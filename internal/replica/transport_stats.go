// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"go.etcd.io/raft/v3/tracker"
)

// Replication counters of the mesh transport. Every message a node sends to a peer and every message it
// receives from one is counted by type: how many, how many log entries and bytes of them, and how many of the
// sends failed. A MsgApp that carries entries the sender already sent to that peer on that group (a resend)
// is counted apart, so that "bytes on the wire per byte committed" can be read off a live node. The counters
// are atomics beside the work; Stats reads them.

// statTypes bounds the message types a counter array is indexed by (raft has fewer than 32).
const statTypes = 32

type msgCounter struct {
	n, entries, bytes, failed, failedBytes atomic.Uint64
}

type peerCounters struct {
	sent, recv                     [statTypes]msgCounter
	resentEntries, resentBytes     atomic.Uint64 // MsgApp entries (and their bytes) that an earlier MsgApp to the peer on the group already carried
	rejects                        atomic.Uint64 // MsgAppResp rejects received from the peer
	unreachable                    atomic.Uint64 // times a failed send was reported to raft as an unreachable peer
	supersededApps                 atomic.Uint64 // MsgApp not sent because the same entries were already queued or in flight
	supersededAppBytes             atomic.Uint64
	snapshotsSent, snapshotsFailed atomic.Uint64
	queueFull                      atomic.Uint64 // messages refused because the (peer, group) lane's queue was full
	sendNS, sendMaxNS              atomic.Uint64 // time requests took (sum, longest since start)
	maxMsgBytes                    atomic.Uint64 // the largest message encoding attempted
}

func (t *MTLS) peerStats(peer uint64) *peerCounters {
	if v, ok := t.counters.Load(peer); ok {
		return v.(*peerCounters)
	}
	v, _ := t.counters.LoadOrStore(peer, &peerCounters{})
	return v.(*peerCounters)
}

func typeSlot(m pb.MessageType) int {
	if i := int(m); i >= 0 && i < statTypes {
		return i
	}
	return statTypes - 1
}

func entryBytes(ents []*pb.Entry) (n uint64) {
	for _, e := range ents {
		n += uint64(len(e.GetData()))
	}
	return n
}

// recordSent counts one message the transport tried to deliver; raw is the encoding that went (or would have gone) on the wire.
func (t *MTLS) recordSent(m *pb.Message, raw int, took time.Duration, err error) {
	p := t.peerStats(m.GetTo())
	c := &p.sent[typeSlot(m.GetType())]
	c.n.Add(1)
	c.entries.Add(uint64(len(m.GetEntries())))
	c.bytes.Add(uint64(raw))
	p.sendNS.Add(uint64(took))
	for old := p.sendMaxNS.Load(); uint64(took) > old && !p.sendMaxNS.CompareAndSwap(old, uint64(took)); old = p.sendMaxNS.Load() {
	}
	for old := p.maxMsgBytes.Load(); uint64(raw) > old && !p.maxMsgBytes.CompareAndSwap(old, uint64(raw)); old = p.maxMsgBytes.Load() {
	}
	if m.GetType() == pb.MsgSnap {
		p.snapshotsSent.Add(1)
		if err != nil {
			p.snapshotsFailed.Add(1)
		}
	}
	if err != nil {
		c.failed.Add(1)
		c.failedBytes.Add(uint64(raw))
	}
}

// recordReceived counts one message stepped from peer.
func (t *MTLS) recordReceived(m *pb.Message, raw int) {
	p := t.peerStats(m.GetFrom())
	c := &p.recv[typeSlot(m.GetType())]
	c.n.Add(1)
	c.entries.Add(uint64(len(m.GetEntries())))
	c.bytes.Add(uint64(raw))
	if m.GetType() == pb.MsgAppResp && m.GetReject() {
		p.rejects.Add(1)
	}
}

// recordUnreachable counts a send failure reported to raft.
func (t *MTLS) recordUnreachable(peer uint64) { t.peerStats(peer).unreachable.Add(1) }

// ReplicationProgress is what the leader of a group knows about one follower, summed over groups by Stats.
type followerTotals struct {
	probe, replicate, snapshot int
	inflightFull               int
	inflightMsgs               int
	inflightBytes              uint64
	pendingSnapshots           int
	lag                        uint64 // sum of (leader last index - follower match)
}

// progress sums the follower states this group's leader holds (none when it leads nothing) and reports whether
// this member leads the group. It gives up rather than wait for a group whose lock is held.
func (g *Group) progress(into map[uint64]*followerTotals) (leads bool) {
	if !g.mu.TryLock() {
		return false
	}
	defer g.mu.Unlock()
	if g.failed || g.closed || g.raw.BasicStatus().RaftState != raft.StateLeader {
		return false
	}
	leads = true
	last, _ := g.memory.LastIndex()
	g.raw.WithProgress(func(id uint64, typ raft.ProgressType, pr tracker.Progress) {
		if id == g.id {
			return
		}
		f := into[id]
		if f == nil {
			f = &followerTotals{}
			into[id] = f
		}
		switch pr.State {
		case tracker.StateProbe:
			f.probe++
		case tracker.StateReplicate:
			f.replicate++
		case tracker.StateSnapshot:
			f.snapshot++
			f.pendingSnapshots++
		}
		if pr.Inflights != nil {
			f.inflightMsgs += pr.Inflights.Count()
			if pr.Inflights.Full() {
				f.inflightFull++
			}
		}
		if last > pr.Match {
			f.lag += last - pr.Match
		}
	})
	return leads
}

// Stats is the replication counters of this transport, by peer and message type, with the follower states
// of the groups this node leads. The map is JSON-shaped for a diagnostic endpoint.
func (t *MTLS) Stats() map[string]any {
	totals := map[uint64]*followerTotals{}
	t.mu.RLock()
	groups := make([]*Group, 0, len(t.groups))
	for _, g := range t.groups {
		groups = append(groups, g)
	}
	t.mu.RUnlock()
	led, tried := 0, 0
	for _, g := range groups {
		tried++
		if g.progress(totals) {
			led++
		}
	}
	out := map[string]any{"groups_led": led, "groups_registered": tried}
	var reads, readNS, readMax, rounds, gaveUp uint64
	for _, g := range groups {
		reads += g.phases.readN.Load()
		readNS += g.phases.readNS.Load()
		readMax = max(readMax, g.phases.readMaxNS.Load())
		rounds += g.phases.readRounds.Load()
		gaveUp += g.phases.readGaveUp.Load()
	}
	out["read_calls"], out["read_rounds"], out["read_gave_up"] = reads, rounds, gaveUp
	out["read_wait_ms_total"], out["read_wait_ms_max"] = readNS/1e6, readMax/1e6
	t.counters.Range(func(k, v any) bool {
		p := v.(*peerCounters)
		peer := map[string]any{
			"resent_entries": p.resentEntries.Load(), "resent_bytes": p.resentBytes.Load(), "rejects_received": p.rejects.Load(),
			"unreachable_reports": p.unreachable.Load(), "superseded_apps": p.supersededApps.Load(), "superseded_app_bytes": p.supersededAppBytes.Load(),
			"snapshots_sent": p.snapshotsSent.Load(), "snapshots_failed": p.snapshotsFailed.Load(),
			"queue_full": p.queueFull.Load(), "send_ms_total": p.sendNS.Load() / 1e6, "send_ms_max": p.sendMaxNS.Load() / 1e6, "max_msg_bytes": p.maxMsgBytes.Load(),
		}
		kinds := func(a *[statTypes]msgCounter) map[string]any {
			m := map[string]any{}
			for i := range a {
				c := &a[i]
				if n := c.n.Load(); n > 0 {
					m[pb.MessageType(i).String()] = map[string]uint64{"n": n, "entries": c.entries.Load(), "bytes": c.bytes.Load(), "failed": c.failed.Load(), "failed_bytes": c.failedBytes.Load()}
				}
			}
			return m
		}
		peer["sent"], peer["received"] = kinds(&p.sent), kinds(&p.recv)
		if f := totals[k.(uint64)]; f != nil {
			peer["groups_probe"], peer["groups_replicate"], peer["groups_snapshot"] = f.probe, f.replicate, f.snapshot
			peer["inflight_full"], peer["inflight_msgs"], peer["lag_entries"] = f.inflightFull, f.inflightMsgs, f.lag
		}
		out[strconv.FormatUint(k.(uint64), 10)] = peer
		return true
	})
	// The delivery lanes that hold a backlog or are busy, by what their worker is doing.
	phases := map[string]int{}
	var stuck []string
	t.mu.RLock()
	for key, lane := range t.queues {
		depth := lane.depth()
		phase := lane.phase.Load()
		phases[strconv.Itoa(int(phase))]++
		if depth >= 16 {
			stuck = append(stuck, fmt.Sprintf("peer=%d group=%s depth=%d phase=%d type=%s age_ms=%d", key.peer, key.group, depth, phase, pb.MessageType(lane.curType.Load()), (time.Now().UnixNano()-lane.since.Load())/1e6))
		}
	}
	t.mu.RUnlock()
	out["lane_phases"], out["lanes_backlog"] = phases, stuck
	return out
}

// noteUnreachable counts a send failure that group g reports to raft (a no-op for a transport without counters).
func (g *Group) noteUnreachable(peer uint64) {
	if s, ok := g.transport.(interface{ recordUnreachable(uint64) }); ok {
		s.recordUnreachable(peer)
	}
}
