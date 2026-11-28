// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package smokecluster holds the generic plumbing the local multi-node smokes
// share: a private CA with per-node mTLS identities, loopback relays that keep
// every membership address valid while a node is stopped, partitioned or
// replaced, free-port reservation, and an in-process three-voter cluster built
// from appcore.OpenDistributed. It lives beside the smoke harnesses, never in a
// production path.
package smokecluster

import (
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type relayLink struct {
	source, target     uint64
	incoming, outgoing net.Conn
}

// Relays are end-to-end-mTLS opaque TCP relays, one listener per node id.
type Relays struct {
	mu        sync.Mutex
	blocked   map[uint64]bool
	links     map[*relayLink]bool
	ips       map[string]uint64
	listeners map[uint64]net.Listener
	targets   map[uint64]string
	done      bool
}

// PeerSourceIP is the loopback source address node id dials from; the relays
// identify the sending node by it.
func PeerSourceIP(id uint64) string { return "127.0.0." + strconv.FormatUint(id+10, 10) }

// NewRelays opens one relay listener per node id and holds it for the
// life of the scenario. Members dial these relay addresses, never the nodes'
// own listeners, so a node can be killed, partitioned and replaced while every
// address in the membership stays valid. Each node's real listen address is
// attached later with Retarget.
func NewRelays(ids ...uint64) (*Relays, error) {
	r := &Relays{blocked: map[uint64]bool{}, links: map[*relayLink]bool{}, ips: map[string]uint64{}, listeners: map[uint64]net.Listener{}, targets: map[uint64]string{}}
	for _, id := range ids {
		r.ips[PeerSourceIP(id)] = id
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			r.Close()
			return nil, err
		}
		r.listeners[id] = listener
		go r.accept(id, listener)
	}
	return r, nil
}

// Address is the relay listener address members dial for node id.
func (r *Relays) Address(id uint64) string { return r.listeners[id].Addr().String() }

// Addresses lists every relay listener address held open.
func (r *Relays) Addresses() []string {
	out := make([]string, 0, len(r.listeners))
	for _, listener := range r.listeners {
		out = append(out, listener.Addr().String())
	}
	return out
}

// Retarget points a node's relay at the address that node will listen on.
func (r *Relays) Retarget(id uint64, address string) {
	r.mu.Lock()
	r.targets[id] = address
	r.mu.Unlock()
}
func (r *Relays) accept(target uint64, listener net.Listener) {
	for {
		incoming, err := listener.Accept()
		if err != nil {
			return
		}
		host, _, _ := net.SplitHostPort(incoming.RemoteAddr().String())
		r.mu.Lock()
		source := r.ips[host]
		blocked := r.done || source == 0 || r.blocked[source] || r.blocked[target]
		destination := r.targets[target]
		r.mu.Unlock()
		if blocked {
			incoming.Close()
			continue
		}
		outgoing, err := net.DialTimeout("tcp", destination, time.Second)
		if err != nil {
			incoming.Close()
			continue
		}
		link := &relayLink{source: source, target: target, incoming: incoming, outgoing: outgoing}
		r.mu.Lock()
		if r.done || r.blocked[source] || r.blocked[target] {
			r.mu.Unlock()
			incoming.Close()
			outgoing.Close()
			continue
		}
		r.links[link] = true
		r.mu.Unlock()
		go func() {
			defer func() { incoming.Close(); outgoing.Close(); r.mu.Lock(); delete(r.links, link); r.mu.Unlock() }()
			copied := make(chan struct{}, 1)
			go func() { _, _ = io.Copy(outgoing, incoming); copied <- struct{}{} }()
			_, _ = io.Copy(incoming, outgoing)
			outgoing.Close()
			incoming.Close()
			<-copied
		}()
	}
}

// Partition cuts (or restores) every connection to and from node id.
func (r *Relays) Partition(id uint64, blocked bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blocked[id] = blocked
	if blocked {
		for link := range r.links {
			if link.source == id || link.target == id {
				link.incoming.Close()
				link.outgoing.Close()
			}
		}
	}
}

// Close stops every listener and cuts every live link.
func (r *Relays) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	for _, listener := range r.listeners {
		listener.Close()
	}
	for link := range r.links {
		link.incoming.Close()
		link.outgoing.Close()
	}
}

// ReserveAddresses picks n distinct loopback ports. Every listener stays
// bound until all n are chosen, so the addresses cannot repeat one another or
// any relay listener (those are held open for the whole scenario). The caller
// should start the owning process immediately: between this release and that
// process binding, another process on the machine could take the port, which is
// why a node is assigned its address right before it starts rather than at
// scenario start. A node that finds its port taken reports address_in_use.
func ReserveAddresses(n int) ([]string, error) {
	held := make([]net.Listener, 0, n)
	defer func() {
		for _, listener := range held {
			listener.Close()
		}
	}()
	addresses := make([]string, 0, n)
	for range n {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		held = append(held, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	return addresses, nil
}

// AssignPeers gives each node a fresh listen address and points its relay
// at it. targets is the address table the node configurations are built from.
func AssignPeers(relays *Relays, targets map[uint64]string, nodes ...uint64) error {
	addresses, err := ReserveAddresses(len(nodes))
	if err != nil {
		return err
	}
	for i, node := range nodes {
		targets[node] = addresses[i]
		relays.Retarget(node, addresses[i])
	}
	return nil
}
