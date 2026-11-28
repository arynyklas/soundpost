// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// nic is one node's receive link: a byte rate shared by every connection the node accepts, the way a network
// card of a fixed speed is shared by every peer and every request. A Read returns no faster than the rate lets
// the bytes through, so the sender's TCP window (and with it its HTTP/2 flow control) fills and the sender
// is held back exactly as it is by a slow wire. It also counts every byte that came through.
type nic struct {
	mu          sync.Mutex
	next        time.Time
	bytesPerSec float64
	received    atomic.Int64
}

func newNIC(bytesPerSec float64) *nic { return &nic{bytesPerSec: bytesPerSec} }

// take blocks for as long as n more bytes need on the link.
func (c *nic) take(n int) {
	c.received.Add(int64(n))
	c.mu.Lock()
	now := time.Now()
	if c.next.Before(now) {
		c.next = now
	}
	c.next = c.next.Add(time.Duration(float64(n) / c.bytesPerSec * float64(time.Second)))
	wait := c.next.Sub(now)
	c.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}

type throttledListener struct {
	net.Listener
	link *nic
}

func (l throttledListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return throttledConn{Conn: conn, link: l.link}, nil
}

type throttledConn struct {
	net.Conn
	link *nic
}

// Read takes at most 16 KiB at a time so that no single read books the link for long.
func (c throttledConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p[:min(len(p), 16<<10)])
	if n > 0 {
		c.link.take(n)
	}
	return n, err
}

// Replicating over a slow link to slow followers must put on the wire about what it replicates: the committed payload
// once for each follower, and a little overhead. It must not put the same entries on the wire again and again because a
// queue filled, a send timed out or an append was refused: on a link that is already the limit every resend is taken from
// the entries that have not yet arrived, the follower falls further behind, more are resent, and the node stalls (a
// three-node installation on 96 Mbit/s cards, 150 records a second: the leader sent 95 Mbit/s to one follower whose journal
// grew by 3 % of that, and at a third of the intended load the leader's memory grew to 11 GiB).
//
// The three nodes' receive sides share one link of a fixed rate (the cards of the nodes, or the switch between them),
// every node applies every entry slowly, so that a request waits for it as it does for a real disk, and each group is
// written by a burst of concurrent proposers at its leader, as fast as the cluster lets them.
func TestSlowLinkCarriesAboutThePayloadItReplicates(t *testing.T) {
	const (
		groups   = 4
		workers  = 200 // concurrent proposals per group: a burst of appends of one hot group
		payload  = 8 << 10
		linkRate = 24 << 20 // bytes/s the whole network carries
		window   = 8 * time.Second
	)
	defer func(previous time.Duration) { meshTestTick = previous }(meshTestTick)
	meshTestTick = 100 * time.Millisecond
	link := newNIC(linkRate)
	c := newMTLSClusterWith(t, groups, func(node int, l net.Listener) net.Listener {
		return throttledListener{Listener: l, link: link}
	})
	for node := range 3 {
		for _, m := range c.machines[node] {
			m.delay = 4 * time.Millisecond
		}
	}
	for _, g := range c.groups[0] {
		if err := g.Campaign(); err != nil {
			t.Fatal(err)
		}
	}
	// leaderOf is the node that leads group i as far as any node knows, refreshed in the background so that the proposers do
	// not queue on the group locks to ask.
	var leaders [groups]atomic.Int32
	stopLeaders := make(chan struct{})
	defer close(stopLeaders)
	refresh := func() {
		for i := range groups {
			for node := range 3 {
				if l := c.groups[node][i].Status().Leader; l != 0 {
					leaders[i].Store(int32(l))
					break
				}
			}
		}
	}
	go func() {
		for {
			select {
			case <-stopLeaders:
				return
			case <-time.After(50 * time.Millisecond):
				refresh()
			}
		}
	}()
	ready, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for i := range groups {
		for leaders[i].Load() == 0 {
			if ready.Err() != nil {
				t.Fatalf("group %d never elected a leader", i)
			}
			refresh()
			time.Sleep(10 * time.Millisecond)
		}
	}
	base := link.received.Load()
	var committedBytes atomic.Int64
	committed := make([]atomic.Int64, groups)
	deadline := time.Now().Add(window)
	var wg sync.WaitGroup
	for i := range groups {
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				body := make([]byte, payload)
				for time.Now().Before(deadline) {
					_, _ = rand.Read(body)
					node := int(leaders[i].Load()) - 1
					if node < 0 {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
					_, err := c.groups[node][i].Propose(ctx, Entry{ID: model.NewID(), Kind: Data, Payload: body})
					stop()
					if err == nil {
						committedBytes.Add(payload)
						committed[i].Add(1)
					}
				}
			}()
		}
	}
	wg.Wait()
	for node, transport := range c.transports {
		if s, ok := any(transport).(interface{ Stats() map[string]any }); ok {
			if raw, err := json.Marshal(s.Stats()); err == nil {
				t.Logf("node %d transport: %s", node+1, raw)
			}
		}
	}
	for node := range 3 {
		for i, g := range c.groups[node] {
			p := g.Phases()
			t.Logf("node %d group %d: persist %d x %v, apply %d x %v, longest cycle %v, tick at most %v late, term %d", node+1, i, p.PersistN, time.Duration(p.PersistNS/max(p.PersistN, 1)), p.ApplyN, time.Duration(p.ApplyNS/max(p.ApplyN, 1)), g.CycleMax(), g.TickLagMax(), g.Status().Term)
		}
	}
	wire := link.received.Load() - base
	followers := int64(2)
	payloadBytes := committedBytes.Load() * followers
	t.Logf("committed %d entries (%d KiB), wire %d KiB, ratio %.2f", committedBytes.Load()/payload, committedBytes.Load()>>10, wire>>10, float64(wire)/float64(max(payloadBytes, 1)))
	if payloadBytes == 0 {
		t.Fatalf("nothing committed in %v", window)
	}
	// An entry travels as ~1.34x its payload (the encoding of a command) plus a little for the frames.
	if ratio := float64(wire) / float64(payloadBytes); ratio > 1.6 {
		t.Fatalf("the cluster put %d bytes on its link for %d bytes of payload for %d followers (%.1fx): entries are sent again and again", wire, payloadBytes, followers, ratio)
	}
	for i := range committed {
		if committed[i].Load() == 0 {
			t.Fatalf("group %d committed nothing in %v: it stalled", i, window)
		}
	}
}

func flowApp(term, prevIndex, prevTerm, commit uint64, entries ...*pb.Entry) *pb.Message {
	m := &pb.Message{Type: pb.MsgApp.Enum(), From: proto.Uint64(1), To: proto.Uint64(2), Term: proto.Uint64(term), Index: proto.Uint64(prevIndex), LogTerm: proto.Uint64(prevTerm), Commit: proto.Uint64(commit)}
	m.Entries = entries
	return m
}

func flowEntry(index, term uint64, size int) *pb.Entry {
	return &pb.Entry{Type: pb.EntryNormal.Enum(), Index: proto.Uint64(index), Term: proto.Uint64(term), Data: make([]byte, size)}
}

// Appends that continue each other are one message: the entries of the later ones are added, the commit index is the
// highest, and an append that does not continue the message (a gap, another term, a log that disagrees where it starts, a
// message that would pass the size limit) is left alone.
func TestMergeAppContinuesOnlyWhatContinues(t *testing.T) {
	size := func(m *pb.Message) uint64 { return entryBytes(m.GetEntries()) }
	t.Run("contiguous", func(t *testing.T) {
		dst := flowApp(3, 10, 2, 9, flowEntry(11, 3, 100), flowEntry(12, 3, 100))
		sz := size(dst)
		if !mergeApp(dst, flowApp(3, 12, 3, 11, flowEntry(13, 3, 100)), &sz) {
			t.Fatal("a contiguous append was not merged")
		}
		if len(dst.GetEntries()) != 3 || dst.GetEntries()[2].GetIndex() != 13 || dst.GetCommit() != 11 || sz != 300 || dst.GetIndex() != 10 || dst.GetLogTerm() != 2 {
			t.Fatalf("merged %d entries, commit %d, size %d, from %d/%d", len(dst.GetEntries()), dst.GetCommit(), sz, dst.GetIndex(), dst.GetLogTerm())
		}
	})
	t.Run("commit only", func(t *testing.T) {
		dst := flowApp(3, 10, 2, 9, flowEntry(11, 3, 100))
		sz := size(dst)
		if !mergeApp(dst, flowApp(3, 11, 3, 11), &sz) || len(dst.GetEntries()) != 1 || dst.GetCommit() != 11 {
			t.Fatalf("an append that only moves the commit index was not folded in: %d entries, commit %d", len(dst.GetEntries()), dst.GetCommit())
		}
	})
	t.Run("the commit index never goes back", func(t *testing.T) {
		dst := flowApp(3, 10, 2, 11, flowEntry(11, 3, 100))
		sz := size(dst)
		if !mergeApp(dst, flowApp(3, 11, 3, 9, flowEntry(12, 3, 100)), &sz) || dst.GetCommit() != 11 {
			t.Fatalf("commit %d", dst.GetCommit())
		}
	})
	t.Run("overlapping entries are not carried twice", func(t *testing.T) {
		dst := flowApp(3, 10, 2, 9, flowEntry(11, 3, 100), flowEntry(12, 3, 100))
		sz := size(dst)
		if !mergeApp(dst, flowApp(3, 10, 2, 9, flowEntry(11, 3, 100), flowEntry(12, 3, 100), flowEntry(13, 3, 100)), &sz) {
			t.Fatal("an overlapping append was not merged")
		}
		if len(dst.GetEntries()) != 3 || sz != 300 {
			t.Fatalf("%d entries, %d bytes", len(dst.GetEntries()), sz)
		}
	})
	for name, next := range map[string]*pb.Message{
		"a gap":                     flowApp(3, 13, 3, 9, flowEntry(14, 3, 100)),
		"before the message":        flowApp(3, 9, 2, 9, flowEntry(10, 2, 100)),
		"another term":              flowApp(4, 12, 3, 9, flowEntry(13, 4, 100)),
		"a log that disagrees":      flowApp(3, 12, 2, 9, flowEntry(13, 3, 100)),
		"another follower":          func() *pb.Message { m := flowApp(3, 12, 3, 9, flowEntry(13, 3, 100)); m.To = proto.Uint64(3); return m }(),
		"a heartbeat":               {Type: pb.MsgHeartbeat.Enum(), From: proto.Uint64(1), To: proto.Uint64(2), Term: proto.Uint64(3)},
		"more than the size allows": flowApp(3, 12, 3, 9, flowEntry(13, 3, maxAppBytes)),
	} {
		t.Run("not "+name, func(t *testing.T) {
			dst := flowApp(3, 10, 2, 9, flowEntry(11, 3, 100), flowEntry(12, 3, 100))
			sz := size(dst)
			if mergeApp(dst, next, &sz) || len(dst.GetEntries()) != 2 || sz != 200 || dst.GetCommit() != 9 {
				t.Fatalf("merged what does not continue the message: %d entries, size %d, commit %d", len(dst.GetEntries()), sz, dst.GetCommit())
			}
		})
	}
}

// A lane holds a burst of appends as a few messages and refuses to queue entries it already holds. Raft probing a
// follower asks for the same entries on every heartbeat reply until one is acknowledged; each copy is the link's time and
// delays the acknowledgement that would stop them.
func TestLaneHoldsABurstAsFewMessagesAndNoCopies(t *testing.T) {
	transport := &MTLS{}
	lane := newLane()
	group := model.NewID()
	appendOf := func(from, to uint64, term uint64) *pb.Message {
		var entries []*pb.Entry
		for i := from; i <= to; i++ {
			entries = append(entries, flowEntry(i, term, 8<<10))
		}
		return flowApp(term, from-1, term, 1, entries...)
	}
	// 100 proposals of one entry each (11..110), 8 KiB, made while the worker is busy: 800 KiB is four messages of the size
	// limit, not 100.
	for i := uint64(11); i <= 110; i++ {
		if err := transport.enqueueApp(lane, group, appendOf(i, i, 5)); err != nil {
			t.Fatalf("append %d refused: %v", i, err)
		}
	}
	if depth := lane.depth(); depth < 1 || depth > 4 {
		t.Fatalf("a burst of 100 appends of 8 KiB is %d queued messages, want at most 4 (the size limit is %d KiB)", depth, maxAppBytes>>10)
	}
	total := 0
	apps := 0
	for _, item := range lane.items {
		total += len(item.message.GetEntries())
		apps += item.apps
		if item.size > maxAppBytes {
			t.Fatalf("a queued append carries %d bytes of entries, limit %d", item.size, maxAppBytes)
		}
	}
	if total != 100 || apps != 100 {
		t.Fatalf("the queue holds %d entries for %d appends, want 100 and 100", total, apps)
	}
	// Raft probes the follower again with entries 50..110: the lane holds them all.
	before := lane.depth()
	if err := transport.enqueueApp(lane, group, appendOf(50, 110, 5)); err != nil {
		t.Fatal(err)
	}
	if lane.depth() != before || transport.peerStats(2).supersededApps.Load() != 1 {
		t.Fatalf("a probe for entries the lane holds was queued (depth %d -> %d, superseded %d)", before, lane.depth(), transport.peerStats(2).supersededApps.Load())
	}
	// A reply that makes raft go back before what the lane holds is a different request and is queued.
	if err := transport.enqueueApp(lane, group, appendOf(1, 110, 5)); err != nil {
		t.Fatal(err)
	}
	// Another term's entries are never copies of an older term's.
	if err := transport.enqueueApp(lane, group, appendOf(100, 120, 6)); err != nil {
		t.Fatal(err)
	}
	if got := transport.peerStats(2).supersededApps.Load(); got != 1 {
		t.Fatalf("superseded %d appends, want only the probe", got)
	}
	// Once the lane has delivered everything it held (or failed to), the same entries are asked for again and queued:
	// the copy was dropped only because the first was on its way.
	for lane.depth() > 0 {
		out, _ := lane.pop(make(chan struct{}))
		lane.finishApps(out.apps)
	}
	if err := transport.enqueueApp(lane, group, appendOf(50, 110, 5)); err != nil || lane.depth() != 1 {
		t.Fatalf("after a delivery the lane refused the entries again: %v, depth %d", err, lane.depth())
	}
}

// The bytes of messages in flight to a peer are bounded over all the groups, and a closing transport lets waiters go.
func TestByteBudgetBoundsWhatIsInFlight(t *testing.T) {
	b := newByteBudget(100)
	stop := make(chan struct{})
	first, ok := b.acquire(60, stop)
	if !ok {
		t.Fatal("the first acquire failed")
	}
	second, ok := b.acquire(40, stop)
	if !ok {
		t.Fatal("the second acquire failed")
	}
	got := make(chan func(), 1)
	go func() {
		release, _ := b.acquire(30, stop)
		got <- release
	}()
	select {
	case <-got:
		t.Fatal("a third message went out beyond the budget")
	case <-time.After(50 * time.Millisecond):
	}
	first()
	var third func()
	select {
	case third = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter was not let in when bytes were released")
	}
	// A message larger than the whole budget takes all of it and waits for nothing else.
	third()
	second()
	huge, ok := b.acquire(1<<30, stop)
	if !ok {
		t.Fatal("a message larger than the budget never got in")
	}
	waiting := make(chan bool, 1)
	go func() {
		_, ok := b.acquire(1, stop)
		waiting <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	b.wake()
	select {
	case ok := <-waiting:
		if ok {
			t.Fatal("a waiter of a closing transport was let in")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter of a closing transport was not released")
	}
	huge()
}
