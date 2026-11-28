// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"slices"
	"time"

	raft "go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/tracker"
)

// Every group is started by one node (the initial leader campaigns for all of them) and a leader keeps its
// leadership for as long as it is healthy, so a node that was up first led 63 of the 65 groups of the three-node
// installation: its card carried the appends of every group to two followers (80-87 Mbit/s of a 96 Mbit/s card) while the
// followers' cards were half idle, and every write of every group waited on that one machine.
//
// Config.LeaderSpread gives each group a preferred leader, a function of the group's seed (the storage engine
// passes the slot) and of the voters, so that the groups of a cluster are shared out evenly by construction (the
// seeds 0..63 over three voters: 22, 21, 21), and the leader of a group that is not its preferred member hands
// leadership over with raft's leadership transfer once it is safe, and never twice in a hurry:
//
//   - the leader has led this term for balance.settled (a fresh election is left alone),
//   - the preferred member has been a healthy follower (replicating, recently active, within balance.lag entries of
//     the log) for the whole of balance.healthy, so a member that is down, restarting, catching up on a snapshot
//     or flapping never gets a group,
//   - balance.cooldown has passed since this leader last tried, and every attempt that did not end with the
//     preferred member leading (it did not win, the transfer was aborted) doubles the wait up to balance.maxCooldown,
//   - the groups stagger by seed, so the transfers of a node that has just come back are spread over seconds,
//   - no membership change is in flight.
//
// A transfer is graceful (the target is up to date and campaigns at once, proposals are refused for a round trip),
// and a preferred leader never gives its leadership away, so the placement converges and does not oscillate: the
// worst a member that keeps failing costs is one transfer per balance.cooldown..maxCooldown for the groups it
// prefers.

// balanceParams are the damping bounds of the placement. Tests replace them.
type balanceParams struct {
	every       time.Duration // a group looks at its placement at most this often
	settled     time.Duration
	healthy     time.Duration
	cooldown    time.Duration
	maxCooldown time.Duration
	lag         uint64 // entries a follower may be behind the log and still be a transfer target
}

var balance = balanceParams{every: time.Second, settled: 10 * time.Second, healthy: 5 * time.Second, cooldown: time.Minute, maxCooldown: 10 * time.Minute, lag: 64}

// balanceState is what one group remembers about its own placement attempts.
type balanceState struct {
	next         time.Time // the next look
	ledTerm      uint64    // the term this member has been leading (0: none)
	ledSince     time.Time // since when
	healthySince time.Time // since when the preferred member has been healthy (zero: not now)
	notBefore    time.Time // no attempt before
	failures     int       // consecutive attempts that did not end with the preferred member leading
	target       uint64    // the member a transfer is running to (0: none)
	deadline     time.Time // when that attempt is judged
}

// preferredLeader is the voter that should lead a group of this seed: voters in ascending order, seed modulo their number.
func preferredLeader(voters []uint64, seed uint64) uint64 {
	if len(voters) < 2 {
		return 0
	}
	sorted := slices.Clone(voters)
	slices.Sort(sorted)
	return sorted[seed%uint64(len(sorted))]
}

// LeaderTransfers is how many leadership transfers the group's placement has started (this member as the leader that
// handed the group over), a transfer that did not take included.
func (g *Group) LeaderTransfers() uint64 { return g.transfers.Load() }

// balanceLocked is called every tick with g.mu held; it hands leadership to the preferred member when all the
// conditions above hold. The caller flushes the Ready it makes.
func (g *Group) balanceLocked() {
	if !g.spread {
		return
	}
	now := time.Now()
	if now.Before(g.bal.next) {
		return
	}
	g.bal.next = now.Add(balance.every)
	status := g.raw.BasicStatus()
	b := &g.bal
	if status.RaftState != raft.StateLeader {
		*b = balanceState{next: b.next}
		return
	}
	if term := status.HardState.GetTerm(); b.ledTerm != term {
		// A new term of a member that was leading: a transfer that was running did not end with the preferred member
		// leading (it lost, or was aborted and this member won again), which counts as a failure; the backoff survives.
		failures, notBefore := b.failures, b.notBefore
		if b.target != 0 {
			failures++
			notBefore = now.Add(min(balance.cooldown<<min(failures, 6), balance.maxCooldown))
		}
		*b = balanceState{next: b.next, ledTerm: term, ledSince: now, failures: failures, notBefore: notBefore}
	}
	if g.conf == nil || len(g.conf.GetVotersOutgoing()) != 0 || len(g.conf.GetLearnersNext()) != 0 {
		return
	}
	preferred := preferredLeader(g.conf.GetVoters(), g.seed)
	if preferred == 0 || preferred == g.id {
		b.healthySince = time.Time{}
		return
	}
	if b.target != 0 {
		if now.Before(b.deadline) {
			return
		}
		b.target = 0
		b.failures++
		b.notBefore = now.Add(min(balance.cooldown<<min(b.failures, 6), balance.maxCooldown))
	}
	if !g.followerHealthyLocked(preferred) {
		b.healthySince = time.Time{}
		return
	}
	if b.healthySince.IsZero() {
		b.healthySince = now
	}
	stagger := time.Duration(g.seed%16) * balance.every / 4
	if now.Sub(b.ledSince) < balance.settled+stagger || now.Sub(b.healthySince) < balance.healthy || now.Before(b.notBefore) {
		return
	}
	g.raw.TransferLeader(preferred)
	g.transfers.Add(1)
	b.target, b.deadline = preferred, now.Add(max(g.leaderWait, time.Second))
	b.notBefore = now.Add(balance.cooldown)
}

// followerHealthyLocked: the leader's own view of a follower says it replicates and is not behind. g.mu is held.
func (g *Group) followerHealthyLocked(id uint64) bool {
	last, _ := g.memory.LastIndex()
	healthy := false
	g.raw.WithProgress(func(peer uint64, kind raft.ProgressType, pr tracker.Progress) {
		if peer == id && kind == raft.ProgressTypePeer && pr.State == tracker.StateReplicate && pr.RecentActive && pr.Match+balance.lag >= last {
			healthy = true
		}
	})
	return healthy
}
