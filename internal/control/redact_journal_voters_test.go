// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	pb "go.etcd.io/raft/v3/raftpb"
)

type voterMsg struct {
	from uint64
	m    *pb.Message
}

// voterMesh is an in-process network between the three control voters: a voter can be cut off,
// and a voter that is not the leader forwards its proposals to the leader.
type voterMesh struct {
	mu      sync.Mutex
	groups  map[uint64]*replica.Group
	queues  map[uint64]chan voterMsg
	blocked map[uint64]bool
	gated   map[uint64]bool
	stash   map[uint64][]voterMsg
	snaps   map[uint64]int // snapshot messages a voter was handed and did not refuse
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	calls   atomic.Int32 // a callMode: how the leader calls of the voters fail
}

func newVoterMesh() *voterMesh {
	return &voterMesh{groups: map[uint64]*replica.Group{}, queues: map[uint64]chan voterMsg{}, blocked: map[uint64]bool{}, gated: map[uint64]bool{}, stash: map[uint64][]voterMsg{}, snaps: map[uint64]int{}, stop: make(chan struct{})}
}
func (m *voterMesh) set(id uint64, g *replica.Group) { m.mu.Lock(); m.groups[id] = g; m.mu.Unlock() }
func (m *voterMesh) cut(id uint64, down bool)        { m.mu.Lock(); m.blocked[id] = down; m.mu.Unlock() }
func (m *voterMesh) close()                          { m.once.Do(func() { close(m.stop) }); m.wg.Wait() }

type voterTransport struct {
	mesh *voterMesh
	node uint64
}

func (t voterTransport) Send(_ model.ID, message *pb.Message) error {
	if message == nil || message.GetFrom() != t.node {
		return replica.ErrInvalid
	}
	to := message.GetTo()
	t.mesh.mu.Lock()
	q := t.mesh.queues[to]
	if q == nil {
		q = make(chan voterMsg, 512)
		t.mesh.queues[to] = q
		t.mesh.wg.Add(1)
		go t.mesh.deliver(to, q)
	}
	t.mesh.mu.Unlock()
	select {
	case <-t.mesh.stop:
		return replica.ErrUnavailable
	case q <- voterMsg{from: t.node, m: message}:
		return nil
	default:
		return replica.ErrUnavailable
	}
}

// ForwardPropose hands a follower's proposal to the leader, as the mTLS transport does. The
// groups are read under mesh.mu but their Status is taken after it is released: a group's run
// loop holds its own lock while it calls Send, which takes mesh.mu, so holding mesh.mu across
// Status inverts that order and can deadlock.
func (t voterTransport) ForwardPropose(ctx context.Context, _ model.ID, entry replica.Entry) (replica.CommittedEntry, error) {
	t.mesh.mu.Lock()
	if t.mesh.blocked[t.node] {
		t.mesh.mu.Unlock()
		return replica.CommittedEntry{}, replica.ErrUnavailable
	}
	groups := make(map[uint64]*replica.Group, len(t.mesh.groups))
	for id, g := range t.mesh.groups {
		groups[id] = g
	}
	t.mesh.mu.Unlock()
	var leader *replica.Group
	for id, g := range groups {
		if st := g.Status(); st.Leader == id && st.ID == id {
			t.mesh.mu.Lock()
			up := !t.mesh.blocked[id]
			t.mesh.mu.Unlock()
			if up {
				leader = g
			}
		}
	}
	if leader == nil {
		return replica.CommittedEntry{}, replica.ErrUnavailable
	}
	return leader.Propose(ctx, entry)
}

// CallLeader hands a call to the leader's handler, as the mTLS transport does (replica.Group.ServeCall is the leader's half).
func (t voterTransport) CallLeader(ctx context.Context, _ model.ID, name string, body []byte) ([]byte, error) {
	t.mesh.mu.Lock()
	if t.mesh.blocked[t.node] {
		t.mesh.mu.Unlock()
		return nil, replica.ErrUnavailable
	}
	groups := make(map[uint64]*replica.Group, len(t.mesh.groups))
	for id, g := range t.mesh.groups {
		groups[id] = g
	}
	t.mesh.mu.Unlock()
	for id, g := range groups {
		if st := g.Status(); st.Leader == id && st.ID == id && id != t.node {
			t.mesh.mu.Lock()
			up := !t.mesh.blocked[id]
			t.mesh.mu.Unlock()
			if up {
				switch callMode(t.mesh.calls.Load()) {
				case callRefused:
					return nil, fmt.Errorf("%w: connection refused", replica.ErrNoLeader) // nothing was sent
				case callAnswerLost:
					// The leader ran the handler and committed what it committed; the connection dropped before the answer came back.
					_, _ = g.ServeCall(ctx, t.node, name, body)
					return nil, fmt.Errorf("%w: connection reset", replica.ErrCallOutcomeUnknown)
				}
				return g.ServeCall(ctx, t.node, name, body)
			}
		}
	}
	return nil, replica.ErrUnavailable
}

func (m *voterMesh) deliver(to uint64, q <-chan voterMsg) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			return
		case in := <-q:
			m.mu.Lock()
			if m.gated[to] && (in.m.GetType() == pb.MsgApp || in.m.GetType() == pb.MsgSnap) {
				m.stash[to] = append(m.stash[to], in)
				m.mu.Unlock()
				continue
			}
			m.mu.Unlock()
			m.step(to, in)
		}
	}
}

// step hands one message to its destination and reports the delivery to the sender.
func (m *voterMesh) step(to uint64, in voterMsg) {
	m.mu.Lock()
	dst, src := m.groups[to], m.groups[in.from]
	down := m.blocked[in.from] || m.blocked[to]
	m.mu.Unlock()
	var err error
	if dst == nil || down {
		err = replica.ErrUnavailable
	} else if stepped := dst.Step(context.Background(), in.m); errors.Is(stepped, replica.ErrUnavailable) {
		err = stepped
	} else if in.m.GetType() == pb.MsgSnap {
		m.mu.Lock()
		m.snaps[to]++
		m.mu.Unlock()
	}
	if src != nil {
		src.ReportDelivery(to, in.m.GetType() == pb.MsgSnap, err)
	}
}

// gateAppends holds back every log append and snapshot message addressed to voter id while on is
// true (its heartbeats, votes and read-index traffic still flow), which makes the voter a connected
// follower that lags in apply: the control group commits without it and it learns of the commit
// only when the gate opens, which delivers what was held back in order.
func (m *voterMesh) gateAppends(id uint64, on bool) {
	m.mu.Lock()
	m.gated[id] = on
	var held []voterMsg
	if !on {
		held, m.stash[id] = m.stash[id], nil
	}
	m.mu.Unlock()
	for _, in := range held {
		m.step(id, in)
	}
}

// controlVoters is three control stores in one control Raft group, each with its own directory,
// opened from the genesis node's seed. fx[id] is the deletion fixture driven against voter id.
type controlVoters struct {
	t      *testing.T
	mesh   *voterMesh
	stores map[uint64]*control.Store
	dirs   map[uint64]string
	fx     map[uint64]*eraseFx
	down   map[uint64]bool // voters a test took out of the group or off the network for good
	// genesis is what every voter was opened from; a voter that joins later is opened from the same.
	genesis voterGenesis
	// beforeRound, when set, runs before each write round of erasedWithVoter3Idle: a test uses it to
	// disturb the group between rounds, as a starved host does on its own.
	beforeRound func(round int)
	// afterLead, when set, runs each time erasedWithVoter3Idle has confirmed voter 1 as the leader and
	// is about to write (stage names the write that follows): a test uses it to move the lead inside a
	// step, which is where a starved host moves it on its own.
	afterLead func(stage string)
	// pinned is the voter that has to lead while a fixture phase runs (0: any voter may).
	pinned uint64
	// retries counts the attempts retryWrite ran again after the lead moved; allowedRetries is the
	// bound checkRetries holds it to (0: maxFixtureRetries).
	retries        atomic.Int64
	allowedRetries int64
}

type voterGenesis struct {
	seed                     []byte
	application, index, term uint64
}

func newControlVoters(t *testing.T) *controlVoters { t.Helper(); return newControlVotersWith(t) }

// newControlVotersWith leaves the retention dispatchers of the voters in ownRetention unbound: a
// test that builds a retention.Service over that voter's store gets them from retention.New.
func newControlVotersWith(t *testing.T, ownRetention ...uint64) *controlVoters {
	t.Helper()
	return newControlVotersCadence(t, replica.Cadence{}, ownRetention...)
}

// newControlVotersCadence opens the voters with the journal cadence the caller chooses (the zero
// value: control's default, DefaultJournalCadence).
func newControlVotersCadence(t *testing.T, cadence replica.Cadence, ownRetention ...uint64) *controlVoters {
	t.Helper()
	return newControlVotersOn(t, nil, cadence, ownRetention...)
}

// voterNetwork is how the fixture's three voters reach each other: the in-process mesh (nil, the
// default) or the production mTLS transport over loopback listeners (newMTLSVoterNetwork).
type voterNetwork interface {
	members() replica.Members
	transport(id uint64) replica.Transport
	// attach is called with each voter's group right after EnableReplication returned it.
	attach(id uint64, g *replica.Group) error
}

// meshNetwork is the in-process network of the fixture's mesh.
type meshNetwork struct{ mesh *voterMesh }

func (n meshNetwork) members() replica.Members {
	members := replica.Members{Revision: 1}
	for id := uint64(1); id <= 3; id++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: id, Address: fmt.Sprintf("https://voter%d.invalid", id), NodeIdentity: fmt.Sprintf("voter-%d", id), FailureDomain: fmt.Sprintf("disk-%d", id)})
	}
	return members
}
func (n meshNetwork) transport(id uint64) replica.Transport {
	return voterTransport{mesh: n.mesh, node: id}
}
func (n meshNetwork) attach(id uint64, g *replica.Group) error {
	n.mesh.set(id, g)
	return nil
}

// forceStatePatchGate opens the state patch gate of a voter store when SOUNDPOST_FORCE_STATE_PATCH=1,
// so that the erasure, attestation and redaction voter suites run with every control command
// proposed as a state patch (a store without a gate proposes whole-state replacements). It is set
// before the store's group starts, and again by restart.
func forceStatePatchGate(s *control.Store) {
	if os.Getenv("SOUNDPOST_FORCE_STATE_PATCH") == "1" {
		s.SetStatePatchGate(func() bool { return true })
	}
}

// answerLayoutQuestion is what appcore wires for a voter of this release: every member runs a binary that
// reads the contracted index layout. An installation bootstrapped by this release carries the born-contracted
// mark from its first command (D72), so the snapshot guard asks the question of the voter it sends to; without
// an answer it fails closed and a lagging voter would never be sent its snapshot.
func answerLayoutQuestion(s *control.Store) {
	s.SetMemberLayoutQuery(func(context.Context, replica.Member) error { return nil })
	s.SetMemberRuleLedgerQuery(func(context.Context, replica.Member) error { return nil }) // and reads the rule facts as records (D108)
}

// newControlVotersOn opens the voters on net (nil: the in-process mesh).
func newControlVotersOn(t *testing.T, net voterNetwork, cadence replica.Cadence, ownRetention ...uint64) *controlVoters {
	t.Helper()
	genesis := newEraseFx(t)
	seed, application, err := genesis.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	position := genesis.store.ReplicaGroup().Status()
	if err = genesis.store.Close(); err != nil {
		t.Fatal(err)
	}
	v := &controlVoters{t: t, mesh: newVoterMesh(), stores: map[uint64]*control.Store{}, dirs: map[uint64]string{}, fx: map[uint64]*eraseFx{}}
	if net == nil {
		net = meshNetwork{v.mesh}
	}
	v.genesis = voterGenesis{seed: seed, application: application, index: position.Applied + 1, term: position.Term + 1}
	t.Cleanup(v.checkRetries)
	t.Cleanup(func() {
		for _, s := range v.stores {
			s.Close()
		}
		v.mesh.close()
	})
	members := net.members()
	for id := uint64(1); id <= 3; id++ {
		v.dirs[id] = t.TempDir()
		store, err := control.OpenSeed(v.dirs[id], seed)
		if err != nil {
			t.Fatal(err)
		}
		v.stores[id] = store
		now := genesis.now
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatal(err)
		}
		binds := []func() error{store.BindRuleEvaluation, store.BindIncidentAction, store.BindConditionApply, store.BindDeliveryOutbox}
		if !slices.Contains(ownRetention, id) { // a retention.Service binds its own dispatchers (retention.New)
			binds = append(binds, store.BindRetention)
		}
		for _, bind := range binds {
			if err = bind(); err != nil {
				t.Fatal(err)
			}
		}
		var installation model.ID
		if err = store.View(genesis.ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
			t.Fatal(err)
		}
		forceStatePatchGate(store)
		answerLayoutQuestion(store)
		group, err := store.EnableReplication(replica.Config{ID: id, Group: installation, Directory: filepath.Join(v.dirs[id], "raft-control"), TickInterval: voterTick(), Members: members, Cadence: cadence,
			Transport: net.transport(id), Seed: seed, Application: application, SeedIndex: position.Applied + 1, SeedTerm: position.Term + 1})
		if err != nil {
			t.Fatal(err)
		}
		if err = net.attach(id, group); err != nil {
			t.Fatal(err)
		}
		v.mesh.set(id, group)
		fence := *genesis.fenceFx
		fence.store, fence.svc, fence.dir = store, svc, v.dirs[id]
		v.fx[id] = &eraseFx{&delFx{fenceFx: &fence, dest: genesis.dest, policy: genesis.policy, subject: genesis.subject}}
		v.fx[id].retry = v.retryWrite
	}
	// leaderIs campaigns (a Campaign that races the group's start is retried, not fatal) and
	// returns only once voter 1 leads and a Fence round has committed under it.
	v.leaderIs(1)
	session, err := v.fx[1].svc.Login(genesis.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.fx[1].cred, err = v.fx[1].svc.Authenticate(genesis.ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	v.leaderIs(1) // the login proposed through the group: lead again before any test proposes
	return v
}

// voterTick is the fixture's Raft tick. The race detector slows every goroutine several times
// over, and a 2-vCPU host (a stock CI runner) running three voters plus the test is starved the
// same way; with the 20 ms tick a delayed heartbeat then expires followers' election timers, the
// lead moves off voter 1 mid-fixture and its leader-bound steps answer stale or unavailable. The
// longer tick on such hosts keeps the fixture's leadership assumptions; the product's timing is
// not changed.
func voterTick() time.Duration {
	if raceEnabled || runtime.NumCPU() <= 2 {
		return 100 * time.Millisecond
	}
	return 20 * time.Millisecond
}

func (v *controlVoters) leaderIs(id uint64) {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last string
	for round := 0; time.Now().Before(deadline); round++ {
		g := v.stores[id].ReplicaGroup()
		if g.Status().Leader == id {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := g.Fence(ctx)
			cancel()
			if err == nil {
				return
			}
		} else if other := v.currentLeader(id); other != 0 {
			// Followers that still hear a live leader refuse a Campaign (check-quorum and
			// pre-vote), so the lead moves back through the leader that holds it.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := v.stores[other].ReplicaGroup().TransferLeadership(ctx, id)
			cancel()
			last = fmt.Sprintf("transfer %d->%d: %v", other, id, err)
		} else if round%10 == 0 {
			_ = g.Campaign() // nobody leads: an election is what is missing
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("voter %d did not become the leader (%s%s)", id, v.leaders(), last)
}

// currentLeader is the reachable voter other than id that leads; 0 when there is none.
func (v *controlVoters) currentLeader(id uint64) uint64 {
	for other, store := range v.stores {
		if other == id || v.down[other] {
			continue
		}
		v.mesh.mu.Lock()
		cut := v.mesh.blocked[other]
		v.mesh.mu.Unlock()
		if st := store.ReplicaGroup().Status(); !cut && st.ID == other && st.Leader == other {
			return other
		}
	}
	return 0
}

func (v *controlVoters) leaders() string {
	var b strings.Builder
	for id := uint64(1); id <= 3; id++ {
		st := v.stores[id].ReplicaGroup().Status()
		fmt.Fprintf(&b, "voter %d leader=%d term=%d; ", id, st.Leader, st.Term)
	}
	return b.String()
}

// led confirms voter 1 as the leader before the write the stage names, then lets a test move the
// lead (afterLead). It is what the fixture runs before each of its writes.
func (v *controlVoters) led(stage string) {
	v.t.Helper()
	v.leaderIs(1)
	if v.afterLead != nil {
		v.afterLead(stage)
	}
}

// retryWrite is the retry of every voter's fixture (fenceFx.write). The fixture's leader-bound writes
// answer unavailable (no voter leads) or with a lease the new leader no longer honours when the
// lead moves while they run. A host that starves the three voters for longer than an election
// timeout moves it between any two steps, which the confirmation before each phase cannot
// prevent; it is the host, not the test, that fails the step. The attempt is run again once the lead
// is settled; any other error is the test's own and is answered at once.
func (v *controlVoters) retryWrite(attempt func() error) error {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		err := attempt()
		if err == nil || !leadMoved(err) || time.Now().After(deadline) {
			return err
		}
		v.retries.Add(1)
		v.settle()
		time.Sleep(20 * time.Millisecond) // a group that failed answers at once: no spinning on it
	}
}

// maxFixtureRetries is the number of retried attempts a whole test may need before the fixture
// reports it. A transient lead move costs one retry per step it lands in; a product whose
// leadership keeps moving without a disturbance retries at every step and would be absorbed
// silently, so more than this many retries in one test fails it. A test that moves the lead on
// purpose raises controlVoters.allowedRetries, never this constant.
const maxFixtureRetries = 10

// checkRetries logs the retries the test needed and fails it when they exceed the bound. It runs
// once, when the test ends.
func (v *controlVoters) checkRetries() {
	n, allowed := v.retries.Load(), v.allowedRetries
	if allowed == 0 {
		allowed = maxFixtureRetries
	}
	v.t.Logf("fixture retries after a lead move: %d (bound %d)", n, allowed)
	if err := retryVerdict(n, allowed); err != nil {
		v.t.Error(err)
	}
}

// retryVerdict is the error checkRetries reports for n retried attempts against a bound.
func retryVerdict(n, allowed int64) error {
	if n > allowed {
		return fmt.Errorf("the fixture retried %d attempts after the lead moved, more than the %d a transient move explains: leadership is unstable", n, allowed)
	}
	return nil
}

// settle waits until the lead is where the running phase needs it: on the voter it pins, or, with
// none pinned, on any reachable voter.
func (v *controlVoters) settle() {
	v.t.Helper()
	if v.pinned != 0 {
		v.leaderIs(v.pinned)
		return
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if v.currentLeader(0) != 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("no voter leads (%s)", v.leaders())
}

// leadMoved reports whether err is what a leader-bound write answers while the lead is moving:
// unavailable, or a lease taken from the leader of one term and sent after the next began.
func leadMoved(err error) bool {
	if errors.Is(err, replica.ErrUnavailable) {
		return true
	}
	var fault *model.Fault
	if !errors.As(err, &fault) {
		return false
	}
	switch fault.Code {
	case model.Unavailable:
		return true
	case model.Stale:
		return fault.SafeDetail == "rule_lease_stale" || fault.SafeDetail == control.ConditionLeaseStale || fault.SafeDetail == control.DeliveryLeaseStale
	}
	return false
}

// revision is the voter's committed revision; ok is false while it cannot serve a read (a voter
// that is catching up knows no leader).
func (v *controlVoters) revision(id uint64) (r model.Revision, ok bool) {
	err := v.stores[id].View(context.Background(), func(st control.State) error { r = st.Revision; return nil })
	return r, err == nil
}

func (v *controlVoters) mustRevision(id uint64) model.Revision {
	v.t.Helper()
	r, ok := v.revision(id)
	if !ok {
		v.t.Fatalf("voter %d cannot serve a read", id)
	}
	return r
}

func (v *controlVoters) await(id uint64, at model.Revision) {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if r, ok := v.revision(id); ok && r >= at {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	r, _ := v.revision(id)
	var status string
	for n := uint64(1); n <= 3; n++ {
		s := v.stores[n].ReplicaGroup().Status()
		status += fmt.Sprintf(" [voter %d leader=%d term=%d commit=%d applied=%d last=%d failed=%v]", n, s.Leader, s.Term, s.Commit, s.Applied, s.LastIndex, s.Failed)
	}
	v.t.Fatalf("voter %d did not reach revision %d (at %d):%s", id, at, r, status)
}

// A voter redacts only its own copy and its receipt is about itself. The leader's pass leaves a
// voter that was cut off during the erasure with no copy of what it never received, and its
// catch-up replays redacted commands to the same state; a voter that has not run the pass still
// holds, and still names, the residue; each one is clean when it runs its own pass.
func TestEachControlVoterRedactsItsOwnCopy(t *testing.T) { eachControlVoterRedactsItsOwnCopy(t, false) }

// The same scenario with every command a state patch: the commands that carry the erased payloads
// are patches of the records they wrote, and the redaction rewrites those records
// (state_patch_redact.go) instead of a whole state. A voter that was cut off and catches up from the
// redacted log applies redacted patches and reaches the leader's state.
func TestEachControlVoterRedactsItsOwnCopyWhenCommandsArePatches(t *testing.T) {
	eachControlVoterRedactsItsOwnCopy(t, true)
}

func eachControlVoterRedactsItsOwnCopy(t *testing.T, patches bool) {
	v := newControlVoters(t)
	if patches {
		for _, s := range v.stores {
			s.SetStatePatchGate(func() bool { return true })
		}
		defer func() {
			var n uint64
			for _, s := range v.stores {
				c, _ := s.StatePatchStatsForTest()
				n += c
			}
			if n < 20 {
				t.Errorf("only %d commands were patches: the scenario did not run on patches", n)
			}
		}()
	}
	const before, during, kept = "CANARYVOTERBEFORE0d2b86a7c41e", "CANARYVOTERDURING0d2b86a7c41e", "CANARYVOTERKEPT51f0aa93c7d"
	leader := v.fx[1]
	leader.seedAll(leader.newSeed(leader.project, before), 50) // on all three voters
	leader.seedAll(leader.newSeed(leader.otherProject, kept), 50)
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	v.mesh.cut(3, true)
	leader.seedAll(leader.newSeed(leader.project, during), 60) // voter 3 never receives these commands
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	v.await(2, v.mustRevision(1))
	if hits := v.fx[3].raftHits(during); len(hits) != 0 {
		t.Fatalf("fixture invalid: the voter that was cut off holds the later payload: %v", hits)
	}
	if hits := v.fx[3].raftHits(before); !contains(hits, "raft-control/ready.wal") {
		t.Fatalf("fixture invalid: the voter that was cut off must hold the earlier payload: %v", hits)
	}
	for _, id := range []uint64{1, 2} {
		if hits := v.fx[id].raftHits(during); !contains(hits, "raft-control/ready.wal") {
			t.Fatalf("fixture invalid: voter %d holds no copy of the erased payload: %v", id, hits)
		}
	}

	// The leader's pass.
	leader.pass()
	for _, canary := range []string{before, during} {
		if hits := leader.raftHits(canary); len(hits) != 0 {
			t.Fatalf("the leader still holds %s after its pass: %v", canary, hits)
		}
	}
	if got := v.stores[1].ResidualStores(); len(got) != 0 {
		t.Fatalf("the leader's receipt after its own pass: %v", got)
	}
	// A voter that applied the deletion and did not run the pass is not covered by the leader's
	// and says so.
	if got := v.stores[2].ResidualStores(); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("voter 2 never ran the pass and must name its journal: %v", got)
	}
	// A voter that was cut off before the erasure has not applied it: it holds the earlier
	// payload but its committed state knows of no erasure, so it names nothing yet. That is
	// the limit of a per-node measurement (it is about what the node has committed), not a
	// statement that the cluster is clean.
	if got := v.stores[3].ResidualStores(); len(got) != 0 {
		t.Fatalf("voter 3 has not applied the erasure: %v", got)
	}
	if hits := v.fx[2].raftHits(during); !contains(hits, "raft-control/ready.wal") {
		t.Fatalf("voter 2 never ran the pass and still holds the payload: %v", hits)
	}

	// The voter that was cut off catches up from the leader, which now sends redacted
	// state: it never stores the original of what it missed and reaches the same state.
	v.mesh.cut(3, false)
	v.await(3, v.mustRevision(1))
	if hits := v.fx[3].raftHits(during); len(hits) != 0 {
		t.Fatalf("the voter that caught up from the redacted leader stored the original: %v", hits)
	}
	if want, got := v.fx[1].canonicalState(), v.fx[3].canonicalState(); want != got {
		t.Fatal("the voter that caught up from redacted commands reached a different state")
	}
	if !v.fx[3].stateHoldsNone(before, during) {
		t.Fatal("the caught-up voter's live state holds an erased payload")
	}
	if got := v.stores[3].ResidualStores(); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("the voter that caught up has not run its own pass and must name its journal: %v", got)
	}

	// Every voter converges when it runs its own pass; the follower's pass commits through the
	// leader, and the voters keep one state.
	for _, id := range []uint64{2, 3} {
		v.fx[id].pass()
	}
	// Neither follower scrubbed its own control.db: voter 2 replayed the erasure and voter 3
	// installed the leader's snapshot, and the leader's replicated scrubbed audit is about the
	// leader's file. Each file still holds what its commits or its install replaced, so each
	// names control_state until the scrub the worker runs before this pass has run on it
	// (scrub_install_voters_test.go pins the bytes).
	for _, id := range []uint64{2, 3} {
		if got := v.stores[id].ResidualStores(); !contains(got, control.ResidualControlState) {
			t.Fatalf("voter %d applied the erasure and never scrubbed its own file: %v", id, got)
		}
		if err := v.stores[id].ScrubErased(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	for id := uint64(1); id <= 3; id++ {
		for _, canary := range []string{before, during} {
			if hits := v.fx[id].raftHits(canary); len(hits) != 0 {
				t.Fatalf("voter %d holds %s after its own pass: %v", id, canary, hits)
			}
		}
		if !v.fx[id].stateHolds(kept) { // the journal no longer keeps the state (compact snapshot, D86): the state does
			t.Fatalf("voter %d lost a payload no deletion covers", id)
		}
	}
	v.await(1, v.mustRevision(2))
	v.await(2, v.mustRevision(1))
	v.await(3, v.mustRevision(1))
	if v.fx[1].canonicalState() != v.fx[2].canonicalState() || v.fx[1].canonicalState() != v.fx[3].canonicalState() {
		t.Fatal("the voters diverged after the passes")
	}
	// A voter's receipt is only as good as its own pass: nothing observes the cluster.
	for id := uint64(1); id <= 3; id++ {
		if got := v.stores[id].ResidualStores(); len(got) != 0 {
			t.Fatalf("voter %d after its own pass: %v", id, got)
		}
	}
}

func (f *eraseFx) stateHoldsNone(canaries ...string) bool {
	f.t.Helper()
	for _, c := range canaries {
		if f.stateHolds(c) {
			return false
		}
	}
	return true
}
