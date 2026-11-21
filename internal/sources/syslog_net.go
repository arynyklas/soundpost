// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The network syslog receiver (UDP, TCP and TLS). A syslog datagram or stream
// has no replayable position of its own, which the checkpoint discipline needs,
// so the receiver gives it one: every received message is classified AT ONCE
// (framing, tag allowlist, registered template, approved values: exactly the
// rules of a syslog file) and the outcome is kept in a bounded, sequence
// numbered buffer. What stays in memory is the typed record of an approved line,
// or only the drop reason of any other line; the bytes of a message that is not
// exported are zeroed before the receiver reads the next one.
//
// The committed Position of the source is (receiver epoch, last committed
// sequence). Read describes the next range (from, to] of the buffer as the
// pending range; the buffer keeps it, unchanged, until the receipts commit it, so
// a lost acknowledgement rebuilds the same records and batch identifiers. The
// receiver is memory-only (nothing received is written to disk), so what it
// cannot keep is declared, never hidden:
//
//   - a UDP datagram that arrives while the buffer is full is lost: a loss gap
//     `queue_full` with the exact count, positioned in the sequence;
//   - TCP and TLS senders are not dropped: the connection is simply not read
//     while the buffer is full (TCP flow control pushes back on the sender);
//   - messages that were received but not yet committed when the agent stopped,
//     and everything sent while it was down, cannot be replayed. The first read
//     of a new epoch reports one loss gap `shutdown` (count 1, a lower bound)
//     before it continues with the new epoch.

const (
	defaultNetBuffer = 4096
	maxNetBuffer     = 65536
	maxListeners     = 4
	maxConns         = 64
	maxMarkers       = 256
	netIdle          = 10 * time.Minute
	tlsHandshake     = 10 * time.Second
)

const (
	netTCP = "tcp"
	netUDP = "udp"
	netTLS = "tls"
)

// netItem is one entry of the sequence: an approved record, a drop reason, or a
// loss marker (lost > 0).
type netItem struct {
	seq    uint64
	rec    *model.LogRecord
	reason string
	lost   uint64
	at     model.UnixNano
	end    model.UnixNano
}

// SyslogReceiver listens for syslog on the addresses of one source policy.
type SyslogReceiver struct {
	key   string
	p     SourcePolicy
	tpls  []compiledTemplate
	epoch string
	cap   int
	now   func() time.Time

	mu      sync.Mutex
	space   *sync.Cond
	items   []netItem
	next    uint64 // last assigned sequence
	frozen  uint64 // highest sequence ever handed to a read: markers up to it are final
	markers int
	carry   uint64 // overflow that found no room for a marker yet
	carryAt model.UnixNano
	closed  bool
	conns   map[net.Conn]struct{}

	packets []net.PacketConn
	lns     []net.Listener
	addrs   []net.Addr
	wg      sync.WaitGroup
}

var receivers = struct {
	sync.Mutex
	m map[string]*SyslogReceiver
}{m: map[string]*SyslogReceiver{}}

// netKey identifies the policy a receiver was started with: a changed listener,
// template, tag or resource restarts the receiver (a new epoch).
func (p SourcePolicy) netKey() string {
	raw, _ := json.Marshal(struct {
		P   SourcePolicy
		Rev model.Revision
		Res model.Resource
	}{p, p.Revision, p.Resource})
	sum := sha256.Sum256(raw)
	return string(sum[:])
}

func (p SourcePolicy) isNetSyslog() bool {
	return p.Kind == KindSyslog && p.Syslog != nil && len(p.Syslog.Listen) > 0
}

// StartSyslogReceiver binds the listeners of a network syslog policy and keeps
// the receiver for the source: Read finds it by the source name, and starts it
// itself on first use when it was not started earlier. A receiver that already
// runs for an identical policy is returned as it is.
func StartSyslogReceiver(p SourcePolicy) (*SyslogReceiver, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if !p.isNetSyslog() {
		return nil, newError(p.Name, StatusUnknown, ReasonInvalidPolicy)
	}
	return receiverFor(p)
}

// CloseSyslogReceivers stops every network syslog receiver of the process.
func CloseSyslogReceivers() {
	receivers.Lock()
	all := make([]*SyslogReceiver, 0, len(receivers.m))
	for _, r := range receivers.m {
		all = append(all, r)
	}
	receivers.Unlock()
	for _, r := range all {
		r.Close()
	}
}

func receiverFor(p SourcePolicy) (*SyslogReceiver, error) {
	key := p.netKey()
	receivers.Lock()
	defer receivers.Unlock()
	old := receivers.m[p.Name]
	if old != nil && old.key == key && !old.isClosed() {
		return old, nil
	}
	if old != nil {
		delete(receivers.m, p.Name)
		old.shutdown()
	}
	r, err := newReceiver(p, key)
	if err != nil {
		return nil, err
	}
	receivers.m[p.Name] = r
	return r, nil
}

func (r *SyslogReceiver) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func listenFailure(p SourcePolicy, err error) error {
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return newError(p.Name, StatusDenied, ReasonPermission)
	}
	return newError(p.Name, StatusUnknown, ReasonListenFailed)
}

func tlsConfig(l SyslogListen) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(l.CertFile, l.KeyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if l.ClientCAFile != "" {
		pem, err := os.ReadFile(l.ClientCAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no client CA certificate")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func newReceiver(p SourcePolicy, key string) (*SyslogReceiver, error) {
	tpls, err := compileTemplates(p)
	if err != nil {
		return nil, err
	}
	capacity := p.Syslog.BufferRecords
	if capacity == 0 {
		capacity = defaultNetBuffer
	}
	r := &SyslogReceiver{key: key, p: p, tpls: tpls, epoch: model.NewID().String(), cap: capacity, now: p.now, conns: map[net.Conn]struct{}{}}
	r.space = sync.NewCond(&r.mu)
	fail := func(err error) (*SyslogReceiver, error) {
		for _, pc := range r.packets {
			pc.Close()
		}
		for _, ln := range r.lns {
			ln.Close()
		}
		return nil, listenFailure(p, err)
	}
	for _, l := range p.Syslog.Listen {
		switch l.Network {
		case netUDP:
			pc, err := net.ListenPacket("udp", l.Address)
			if err != nil {
				return fail(err)
			}
			r.packets = append(r.packets, pc)
			r.addrs = append(r.addrs, pc.LocalAddr())
		case netTCP, netTLS:
			ln, err := net.Listen("tcp", l.Address)
			if err != nil {
				return fail(err)
			}
			if l.Network == netTLS {
				cfg, err := tlsConfig(l)
				if err != nil {
					ln.Close()
					return fail(err)
				}
				ln = tls.NewListener(ln, cfg)
			}
			r.lns = append(r.lns, ln)
			r.addrs = append(r.addrs, ln.Addr())
		}
	}
	for _, pc := range r.packets {
		r.wg.Add(1)
		go r.servePacket(pc)
	}
	for _, ln := range r.lns {
		r.wg.Add(1)
		go r.serveListener(ln)
	}
	return r, nil
}

// Addrs are the bound addresses, in the order of the policy's listeners
// (useful when a listener asked for port 0).
func (r *SyslogReceiver) Addrs() []net.Addr { return r.addrs }

// Epoch is the identity of this run of the receiver.
func (r *SyslogReceiver) Epoch() string { return r.epoch }

// Close stops the listeners and every connection and waits for the readers.
func (r *SyslogReceiver) Close() {
	r.shutdown()
	receivers.Lock()
	if receivers.m[r.p.Name] == r {
		delete(receivers.m, r.p.Name)
	}
	receivers.Unlock()
}

func (r *SyslogReceiver) shutdown() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	for c := range r.conns {
		c.Close()
	}
	r.space.Broadcast()
	r.mu.Unlock()
	for _, pc := range r.packets {
		pc.Close()
	}
	for _, ln := range r.lns {
		ln.Close()
	}
	r.wg.Wait()
	r.mu.Lock()
	r.items, r.markers = nil, 0
	r.mu.Unlock()
}

// classify applies the syslog file rules to one received message and zeroes its
// bytes. A nil record carries the drop reason.
func (r *SyslogReceiver) classify(line []byte) (*model.LogRecord, string) {
	recs, dropped := classifyEntries(r.p, r.tpls, []entry{{msg: line}}, r.now())
	if len(recs) == 1 {
		return &recs[0], ""
	}
	for reason := range dropped {
		return nil, reason
	}
	return nil, DropBadFrame
}

// offer appends one outcome. A full buffer blocks a stream reader (block) and
// loses a datagram (counted as a loss marker, never silently).
func (r *SyslogReceiver) offer(rec *model.LogRecord, reason string, block bool) {
	at := model.UnixNano(r.now().UnixNano())
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.items) >= r.cap && !r.closed {
		if !block {
			r.overflowLocked(at)
			return
		}
		r.space.Wait()
	}
	if r.closed {
		return
	}
	r.next++
	r.items = append(r.items, netItem{seq: r.next, rec: rec, reason: reason, at: at})
}

// overflowLocked counts one lost datagram. The count lives in a marker that is
// part of the sequence, so a range that was already handed to a read is never
// changed afterwards (a retry rebuilds it byte-identically); a later loss opens
// the next marker.
func (r *SyslogReceiver) overflowLocked(at model.UnixNano) {
	if n := len(r.items); n > 0 {
		if last := &r.items[n-1]; last.lost > 0 && last.seq > r.frozen {
			last.lost++
			last.end = at
			return
		}
	}
	if r.markers < maxMarkers {
		r.next++
		r.items = append(r.items, netItem{seq: r.next, lost: 1, at: at, end: at})
		r.markers++
		return
	}
	if r.carry == 0 {
		r.carryAt = at
	}
	r.carry++
}

// release drops everything the source has committed (sequence <= upTo) and
// frees the readers that wait for room.
func (r *SyslogReceiver) release(upTo uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := sort.Search(len(r.items), func(i int) bool { return r.items[i].seq > upTo })
	if i > 0 {
		for _, it := range r.items[:i] {
			if it.lost > 0 {
				r.markers--
			}
		}
		n := copy(r.items, r.items[i:])
		clear(r.items[n:])
		r.items = r.items[:n]
	}
	if r.carry > 0 && r.markers < maxMarkers {
		r.next++
		r.items = append(r.items, netItem{seq: r.next, lost: r.carry, at: r.carryAt, end: model.UnixNano(r.now().UnixNano())})
		r.markers++
		r.carry = 0
	}
	r.space.Broadcast()
}

// take copies the items after from: up to limit of them, or, to rebuild a
// pending range, exactly those up to and including upTo. Everything it returns
// becomes final (a marker in it is not extended any more).
func (r *SyslogReceiver) take(from, upTo uint64, limit int) []netItem {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := sort.Search(len(r.items), func(i int) bool { return r.items[i].seq > from })
	var out []netItem
	for ; i < len(r.items); i++ {
		it := r.items[i]
		if upTo > 0 && it.seq > upTo || upTo == 0 && len(out) >= limit {
			break
		}
		out = append(out, it)
	}
	if n := len(out); n > 0 && out[n-1].seq > r.frozen {
		r.frozen = out[n-1].seq
	}
	return out
}

// acquireSyslogNet is the acquisition of a network syslog source: the range
// after the committed sequence, or the recorded pending range again.
func acquireSyslogNet(p SourcePolicy, cp Checkpoint, limit int) (acquired, error) {
	acq := acquired{dropped: map[string]uint64{}}
	r, err := receiverFor(p)
	if err != nil {
		return acq, err
	}
	pos := cp.Position
	switched := pos.Started && pos.File != r.epoch
	var from uint64
	if pos.Started && !switched && pos.Offset > 0 {
		from = uint64(pos.Offset)
	}
	if from > 0 {
		r.release(from)
	}
	var upTo uint64
	if pend := cp.Pending; pend != nil && pend.To.Started && pend.To.File == r.epoch && pend.To.Offset > 0 {
		upTo = uint64(pend.To.Offset)
	} else if limit <= 0 {
		limit = p.maxRecords()
	}
	items := r.take(from, upTo, limit)
	last := from
	if switched {
		now := model.UnixNano(r.now().UnixNano())
		start := cp.LastRead
		if start == 0 || start > now {
			start = now
		}
		acq.gaps = append(acq.gaps, Gap{Reason: "shutdown", Count: 1, Start: start, End: now})
	}
	for _, it := range items {
		last = it.seq
		switch {
		case it.lost > 0:
			acq.gaps = append(acq.gaps, Gap{Reason: "queue_full", Count: it.lost, Start: it.at, End: it.end})
			continue
		case it.rec != nil:
			acq.records = append(acq.records, *it.rec)
		default:
			acq.dropped[it.reason]++
		}
		acq.scanned++
	}
	acq.to = Position{Started: true, File: r.epoch, Offset: int64(last)}
	return acq, nil
}

// ---- readers ----

func (r *SyslogReceiver) maxLine() int { return r.p.maxLine() }

func (r *SyslogReceiver) servePacket(pc net.PacketConn) {
	defer r.wg.Done()
	buf := make([]byte, r.maxLine()+1)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			if r.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n > r.maxLine() {
			clear(buf[:n])
			r.offer(nil, DropOversizeLine, false)
			continue
		}
		line := bytes.TrimRight(buf[:n], "\r\n\x00")
		if len(line) == 0 {
			continue
		}
		rec, reason := r.classify(line)
		clear(buf[:n])
		r.offer(rec, reason, false)
	}
}

func (r *SyslogReceiver) serveListener(ln net.Listener) {
	defer r.wg.Done()
	slots := make(chan struct{}, maxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if r.isClosed() || errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close() // too many senders: refuse, never queue
			continue
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			conn.Close()
			return
		}
		r.conns[conn] = struct{}{}
		r.wg.Add(1)
		r.mu.Unlock()
		go func() {
			defer r.wg.Done()
			defer func() { <-slots }()
			r.serveConn(conn)
			r.mu.Lock()
			delete(r.conns, conn)
			r.mu.Unlock()
		}()
	}
}

func (r *SyslogReceiver) serveConn(conn net.Conn) {
	defer conn.Close()
	if tc, ok := conn.(*tls.Conn); ok {
		conn.SetDeadline(time.Now().Add(tlsHandshake))
		if tc.Handshake() != nil {
			return
		}
	}
	br := bufio.NewReaderSize(conn, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(netIdle))
		line, oversize, err := r.readFrame(br)
		switch {
		case oversize:
			r.offer(nil, DropOversizeLine, true)
		case len(line) > 0:
			rec, reason := r.classify(line)
			r.offer(rec, reason, true)
		}
		if err != nil {
			return
		}
	}
}

// readFrame reads one message of a syslog stream: RFC 6587 octet counting
// ("<length> <message>") when the stream starts a message with digits and a
// space, otherwise newline-delimited (non-transparent framing). A message longer
// than max_line_bytes is skipped without being buffered and reported as
// oversize.
func (r *SyslogReceiver) readFrame(br *bufio.Reader) (line []byte, oversize bool, err error) {
	limit := r.maxLine()
	n, used := 0, 0
	for i := 1; i <= 7; i++ {
		b, perr := br.Peek(i)
		if perr != nil {
			break
		}
		c := b[i-1]
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
			continue
		}
		if c == ' ' && i > 1 {
			used = i
		}
		break
	}
	if used > 0 {
		br.Discard(used)
		if n == 0 {
			return nil, false, nil
		}
		if n > limit {
			_, err := io.CopyN(io.Discard, br, int64(n))
			return nil, true, err
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil {
			clear(buf)
			return nil, false, err
		}
		return bytes.TrimRight(buf, "\r\n\x00"), false, nil
	}
	var out []byte
	for {
		chunk, rerr := br.ReadSlice('\n')
		if len(out)+len(chunk) > limit+1 {
			clear(chunk)
			clear(out)
			// over-long line: skip to its newline without buffering
			for errors.Is(rerr, bufio.ErrBufferFull) {
				_, rerr = br.ReadSlice('\n')
			}
			return nil, true, rerr
		}
		out = append(out, chunk...)
		clear(chunk)
		if errors.Is(rerr, bufio.ErrBufferFull) {
			continue
		}
		out = bytes.TrimRight(out, "\r\n\x00")
		if len(out) > limit {
			clear(out)
			return nil, true, rerr
		}
		return out, false, rerr
	}
}
