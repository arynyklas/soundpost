// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// dcCut is the state of one directed member-to-member link.
type dcCut int

const (
	dcLinkOpen  dcCut = iota
	dcLinkReset       // established connections are reset and new ones are closed at once (a RST/refused link)
	dcLinkDrop        // packets vanish: connections stay open, nothing is delivered either way (an iptables DROP)
)

func (c dcCut) String() string {
	return [...]string{"open", "reset", "drop"}[c]
}

// dcNet is the drill's own peer transport: every member dials every other member THROUGH a loopback
// TCP proxy owned by the drill, each member binding its own source address 127.0.0.<id> so the proxy
// knows which member dialled. Cutting a link needs no host privilege (no iptables, tc or network
// namespace) and leaves both ends running, which is what separates a partition from SIGSTOP. The
// proxy forwards raw bytes; the mTLS session still runs end to end between the two members.
type dcNet struct {
	mu      sync.Mutex
	state   map[[2]uint64]dcCut // [dialer, target]
	proxies []*dcProxy

	dropped, resets, refused atomic.Int64
}

// dcLinkCounters is what the cut links did; a partition that dropped, reset and refused nothing never happened.
type dcLinkCounters struct{ Dropped, Resets, Refused int64 }

func (n *dcNet) Counters() dcLinkCounters {
	return dcLinkCounters{n.dropped.Load(), n.resets.Load(), n.refused.Load()}
}

type dcProxy struct {
	net    *dcNet
	ln     net.Listener
	target string
	to     uint64

	mu    sync.Mutex
	conns map[*dcPipe]struct{}
	done  chan struct{}
}

// dcPipe is one proxied connection.
type dcPipe struct {
	from    uint64
	client  net.Conn
	server  net.Conn
	tainted bool // bytes were discarded: the stream cannot be resumed after the link heals
}

func newDCNet() *dcNet { return &dcNet{state: map[[2]uint64]dcCut{}} }

// listen starts the proxy that fronts member `to` (whose real peer listener is target) and returns
// the address the other members must dial.
func (n *dcNet) listen(to uint64, target string) (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	p := &dcProxy{net: n, ln: ln, target: target, to: to, conns: map[*dcPipe]struct{}{}, done: make(chan struct{})}
	n.mu.Lock()
	n.proxies = append(n.proxies, p)
	n.mu.Unlock()
	go p.accept()
	return ln.Addr().String(), nil
}

func (n *dcNet) mode(from, to uint64) dcCut {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.state[[2]uint64{from, to}]
}

// set changes one directed link and applies it to the connections already open.
func (n *dcNet) set(from, to uint64, mode dcCut) {
	n.mu.Lock()
	n.state[[2]uint64{from, to}] = mode
	proxies := append([]*dcProxy(nil), n.proxies...)
	n.mu.Unlock()
	for _, p := range proxies {
		if p.to == to {
			p.apply(from, mode)
		}
	}
}

// isolate cuts every link between member id and the other members, both directions.
func (n *dcNet) isolate(id uint64, mode dcCut) {
	for _, m := range dcMembers {
		if m.id != id {
			n.set(id, m.id, mode)
			n.set(m.id, id, mode)
		}
	}
}

// heal reopens every link.
func (n *dcNet) heal() {
	for _, a := range dcMembers {
		for _, b := range dcMembers {
			if a.id != b.id {
				n.set(a.id, b.id, dcLinkOpen)
			}
		}
	}
}

func (n *dcNet) close() {
	n.mu.Lock()
	proxies := n.proxies
	n.proxies = nil
	n.mu.Unlock()
	for _, p := range proxies {
		p.close()
	}
}

func (p *dcProxy) close() {
	select {
	case <-p.done:
		return
	default:
		close(p.done)
	}
	_ = p.ln.Close()
	p.mu.Lock()
	for c := range p.conns {
		_ = c.client.Close()
		if c.server != nil {
			_ = c.server.Close()
		}
	}
	p.mu.Unlock()
}

// apply enforces a new link state on established connections of one dialer.
func (p *dcProxy) apply(from uint64, mode dcCut) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		if c.from != from {
			continue
		}
		if mode == dcLinkReset || (mode == dcLinkOpen && c.tainted) {
			if mode == dcLinkReset {
				p.net.resets.Add(1)
			}
			_ = c.client.Close()
			if c.server != nil {
				_ = c.server.Close()
			}
			delete(p.conns, c)
		}
	}
}

func dcDialer(addr net.Addr) uint64 {
	t, ok := addr.(*net.TCPAddr)
	if !ok {
		return 0
	}
	ip := t.IP.To4()
	if ip == nil || ip[0] != 127 || ip[1] != 0 || ip[2] != 0 {
		return 0
	}
	return uint64(ip[3])
}

func (p *dcProxy) accept() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.serve(c)
	}
}

func (p *dcProxy) serve(client net.Conn) {
	pipe := &dcPipe{from: dcDialer(client.RemoteAddr()), client: client}
	switch p.net.mode(pipe.from, p.to) {
	case dcLinkReset:
		p.net.refused.Add(1)
		_ = client.Close()
		return
	case dcLinkDrop:
		// Held open with nothing delivered, like a SYN that is dropped but whose connection state a
		// middlebox keeps: the dialer sees a hang, not a refusal.
		pipe.tainted = true
		p.track(pipe)
		go p.drain(pipe, client)
		return
	}
	server, err := net.DialTimeout("tcp", p.target, 3*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	pipe.server = server
	p.track(pipe)
	go p.pump(pipe, client, server)
	go p.pump(pipe, server, client)
}

func (p *dcProxy) track(c *dcPipe) {
	p.mu.Lock()
	p.conns[c] = struct{}{}
	p.mu.Unlock()
}

func (p *dcProxy) untrack(c *dcPipe) {
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *dcProxy) drain(c *dcPipe, src net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		p.net.dropped.Add(int64(n))
		if err != nil {
			p.untrack(c)
			_ = src.Close()
			return
		}
	}
}

func (p *dcProxy) pump(c *dcPipe, src, dst net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			switch p.net.mode(c.from, p.to) {
			case dcLinkOpen:
				if _, werr := dst.Write(buf[:n]); werr != nil {
					err = werr
				}
			case dcLinkDrop:
				p.net.dropped.Add(int64(n))
				p.mu.Lock()
				c.tainted = true
				p.mu.Unlock()
			case dcLinkReset:
				p.net.resets.Add(1)
				err = errors.New("link reset")
			}
		}
		if err != nil {
			p.untrack(c)
			_ = src.Close()
			_ = dst.Close()
			return
		}
	}
}
