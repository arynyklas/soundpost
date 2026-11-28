// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"sync"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// Flow control of the peer transport.
//
// Raft sends an append for every proposal and expects the transport to pipeline them (it lets 32 be unacknowledged
// per follower). The lane of a (peer, group) is one worker that posts one message at a time and waits for the
// follower to step it, persist it and answer, so a lane delivers one request per round trip whatever the requests
// carry. Three things made a slow link or a slow follower a storm:
//
//  1. A burst of proposals queued one append each. A lane that could not deliver them as fast as they were made
//     filled its queue, the next append was refused, and raft was told the peer was unreachable.
//  2. A follower that raft believes unreachable is probed: raft sends the entries after the follower's match
//     index, up to MaxSizePerMsg, again on every heartbeat response until the follower acknowledges one. Every
//     one of those went into the queue behind the previous copy, so the link carried the same unacknowledged
//     entries tens of times over, each copy delaying the acknowledgement that would stop them.
//  3. Nothing bounded the bytes of messages in flight to a peer across the groups: sixty groups each sending a
//     message of megabytes shared one link, every request took longer than its timeout, and each timeout reported
//     the peer unreachable, which made raft send the same entries again.
//
// The lane therefore delivers what it holds in as few requests as raft's own limits allow (coalesceApps), does
// not queue an append whose entries the lane already holds (admitApp), and the bytes of messages in flight to one
// peer are bounded across all the groups (byteBudget), so a message's time on the wire is bounded by that and not by
// how many groups happen to be sending.

// maxAppBytes is raft's MaxSizePerMsg: the entry bytes of one append, and of a merge of several (an entry larger than
// this goes alone).
const maxAppBytes = 256 << 10

// maxInflightBytes is raft's MaxInflightBytes: the entry bytes a leader leaves unacknowledged per follower and group.
const maxInflightBytes = 8 << 20

// flowThreshold is the size of a request from which it is paid for from the peer's byte budget; a small message
// (a vote, an acknowledgement, a heartbeat, an append of a few entries) costs the link nothing worth bounding and
// must not wait for the megabytes of others.
const flowThreshold = 64 << 10

// peerBudgetBytes is the bytes of messages the transport lets be in flight to one peer at once, over all groups.
const peerBudgetBytes = 8 << 20

// byteBudget is a counting semaphore of bytes.
type byteBudget struct {
	mu   sync.Mutex
	cond *sync.Cond
	free int64
	cap  int64
}

func newByteBudget(n int64) *byteBudget {
	b := &byteBudget{free: n, cap: n}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (t *MTLS) budget(peer uint64) *byteBudget {
	if v, ok := t.budgets.Load(peer); ok {
		return v.(*byteBudget)
	}
	v, _ := t.budgets.LoadOrStore(peer, newByteBudget(peerBudgetBytes))
	return v.(*byteBudget)
}

// acquire waits until n bytes (at most the whole budget) are free and takes them; release gives them back. It is
// false when stop closed first (the caller of a closing transport must call wake after closing stop).
func (b *byteBudget) acquire(n int64, stop <-chan struct{}) (release func(), ok bool) {
	n = min(n, b.cap)
	b.mu.Lock()
	defer b.mu.Unlock()
	for b.free < n {
		select {
		case <-stop:
			return nil, false
		default:
		}
		b.cond.Wait()
	}
	select {
	case <-stop:
		return nil, false
	default:
	}
	b.free -= n
	return func() {
		b.mu.Lock()
		b.free += n
		b.cond.Broadcast()
		b.mu.Unlock()
	}, true
}

// wake lets the waiters notice that the transport is closing.
func (b *byteBudget) wake() {
	b.mu.Lock()
	b.cond.Broadcast()
	b.mu.Unlock()
}

func newLane() *laneQueue { return &laneQueue{wake: make(chan struct{}, 1)} }

// pushLocked queues o behind the lane's messages and wakes the worker; false when the lane is full. lane.mu is held.
func (lane *laneQueue) pushLocked(o outbound) bool {
	if len(lane.items) >= laneDepth {
		return false
	}
	lane.items = append(lane.items, o)
	select {
	case lane.wake <- struct{}{}:
	default:
	}
	return true
}

// pop waits for the oldest message of the lane; false when stop closed first.
func (lane *laneQueue) pop(stop <-chan struct{}) (outbound, bool) {
	for {
		lane.mu.Lock()
		if len(lane.items) > 0 {
			o := lane.items[0]
			copy(lane.items, lane.items[1:])
			lane.items[len(lane.items)-1] = outbound{}
			lane.items = lane.items[:len(lane.items)-1]
			lane.mu.Unlock()
			return o, true
		}
		lane.mu.Unlock()
		select {
		case <-stop:
			return outbound{}, false
		case <-lane.wake:
		}
	}
}

// depth is how many messages the lane has queued.
func (lane *laneQueue) depth() int {
	lane.mu.Lock()
	defer lane.mu.Unlock()
	return len(lane.items)
}

// enqueueApp queues the append m on its lane:
//
//   - when the lane already holds every entry m carries (an append queued or in flight that starts at or before m's
//     first entry and reaches its last) m is dropped: that is raft probing a follower again with the entries a
//     request is already carrying, and the copy would only take the link's time. The follower's answer to the first
//     copy moves raft on; if the first copy is lost its delivery fails, the lane forgets it (finishApps) and raft's
//     next probe is not a duplicate;
//   - when the newest queued message is an append that m continues, m is merged into it (mergeApp) and takes no
//     place in the queue: a burst of proposals while a request is in flight becomes one request with their entries,
//     so the queue's depth is bounded by bytes, not by how many proposals were made.
func (t *MTLS) enqueueApp(lane *laneQueue, group model.ID, m *pb.Message) error {
	ents := m.GetEntries()
	first, last := m.GetIndex()+1, m.GetIndex()+uint64(len(ents))
	p := t.peerStats(m.GetTo())
	lane.mu.Lock()
	if lane.apps > 0 && m.GetTerm() != lane.appsTerm {
		lane.apps, lane.appsLow, lane.appsEnd = 0, 0, 0 // a new term: nothing of an older one can stand for these entries
	}
	if len(ents) > 0 && lane.apps > 0 && m.GetIndex() >= lane.appsLow && last <= lane.appsEnd {
		lane.mu.Unlock()
		p.supersededApps.Add(1)
		p.supersededAppBytes.Add(entryBytes(ents))
		return nil
	}
	high := lane.highSent
	if len(ents) > 0 && last > high {
		lane.highSent = last
	}
	merged := false
	if n := len(lane.items); n > 0 {
		if tail := &lane.items[n-1]; tail.message != nil && mergeApp(tail.message, m, &tail.size) {
			tail.apps++
			merged = true
		}
	}
	if !merged && !lane.pushLocked(outbound{group: group, message: m, apps: 1, size: entryBytes(ents)}) {
		lane.mu.Unlock()
		p.queueFull.Add(1)
		return ErrUnavailable
	}
	if lane.apps == 0 {
		lane.appsLow, lane.appsEnd, lane.appsTerm = m.GetIndex(), 0, m.GetTerm()
	}
	lane.apps++
	lane.appsEnd = max(lane.appsEnd, last)
	lane.mu.Unlock()
	if len(ents) > 0 && first <= high { // entries an earlier append of the lane carried: a resend
		n := min(uint64(len(ents)), high-first+1)
		p.resentEntries.Add(n)
		p.resentBytes.Add(entryBytes(ents[:n]))
	}
	return nil
}

// finishApps forgets n appends the lane held: they were delivered, or failed, or were merged into one that was.
func (lane *laneQueue) finishApps(n int) {
	if n == 0 {
		return
	}
	lane.mu.Lock()
	lane.apps -= n
	if lane.apps <= 0 {
		lane.apps, lane.appsLow, lane.appsEnd = 0, 0, 0
	}
	lane.mu.Unlock()
}

// mergeApp appends to dst the entries of next that dst does not already carry and raises dst's commit index to
// next's, when next is an append of the same leader and term that starts inside or at the end of dst and the log
// agrees at its starting point; size is dst's entry bytes. It is false (nothing changed) otherwise, or when the merge
// would pass maxAppBytes.
func mergeApp(dst, next *pb.Message, size *uint64) bool {
	if next.GetType() != pb.MsgApp || next.GetTerm() != dst.GetTerm() || next.GetFrom() != dst.GetFrom() || next.GetTo() != dst.GetTo() {
		return false
	}
	have := dst.GetEntries()
	end := dst.GetIndex() + uint64(len(have))
	at := next.GetIndex()
	if at < dst.GetIndex() || at > end {
		return false
	}
	term := dst.GetLogTerm()
	if at > dst.GetIndex() {
		term = have[at-dst.GetIndex()-1].GetTerm()
	}
	if term != next.GetLogTerm() {
		return false
	}
	extra := next.GetEntries()[min(end-at, uint64(len(next.GetEntries()))):]
	add := entryBytes(extra)
	if len(extra) > 0 && len(have) > 0 && *size+add > maxAppBytes {
		return false
	}
	dst.Entries = append(dst.Entries, extra...)
	*size += add
	if next.GetCommit() > dst.GetCommit() {
		dst.Commit = proto.Uint64(next.GetCommit())
	}
	return true
}
