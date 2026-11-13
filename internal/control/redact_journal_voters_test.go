// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pb "go.etcd.io/raft/v3/raftpb"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
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
	stop    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

func newVoterMesh() *voterMesh {
	return &voterMesh{groups: map[uint64]*replica.Group{}, queues: map[uint64]chan voterMsg{}, blocked: map[uint64]bool{}, stop: make(chan struct{})}
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

func (m *voterMesh) deliver(to uint64, q <-chan voterMsg) {
	defer m.wg.Done()
	for {
		select {
		case <-m.stop:
			return
		case in := <-q:
			m.mu.Lock()
			dst, src := m.groups[to], m.groups[in.from]
			down := m.blocked[in.from] || m.blocked[to]
			m.mu.Unlock()
			var err error
			if dst == nil || down {
				err = replica.ErrUnavailable
			} else if stepped := dst.Step(context.Background(), in.m); errors.Is(stepped, replica.ErrUnavailable) {
				err = stepped
			}
			if src != nil {
				src.ReportDelivery(to, in.m.GetType() == pb.MsgSnap, err)
			}
		}
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
}

type voterGenesis struct {
	seed                     []byte
	application, index, term uint64
}

func newControlVoters(t *testing.T) *controlVoters {
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
	v.genesis = voterGenesis{seed: seed, application: application, index: position.Applied + 1, term: position.Term + 1}
	t.Cleanup(func() {
		for _, s := range v.stores {
			s.Close()
		}
		v.mesh.close()
	})
	members := replica.Members{Revision: 1}
	for id := uint64(1); id <= 3; id++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: id, Address: fmt.Sprintf("https://voter%d.invalid", id), NodeIdentity: fmt.Sprintf("voter-%d", id), FailureDomain: fmt.Sprintf("disk-%d", id)})
	}
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
		for _, bind := range []func() error{store.BindRuleEvaluation, store.BindIncidentAction, store.BindConditionApply, store.BindDeliveryOutbox, store.BindRetention} {
			if err = bind(); err != nil {
				t.Fatal(err)
			}
		}
		var installation model.ID
		if err = store.View(genesis.ctx, func(st control.State) error { installation = st.Installation; return nil }); err != nil {
			t.Fatal(err)
		}
		group, err := store.EnableReplication(replica.Config{ID: id, Group: installation, Directory: filepath.Join(v.dirs[id], "raft-control"), TickInterval: 20 * time.Millisecond, Members: members,
			Transport: voterTransport{mesh: v.mesh, node: id}, Seed: seed, Application: application, SeedIndex: position.Applied + 1, SeedTerm: position.Term + 1})
		if err != nil {
			t.Fatal(err)
		}
		v.mesh.set(id, group)
		fence := *genesis.fenceFx
		fence.store, fence.svc, fence.dir = store, svc, v.dirs[id]
		v.fx[id] = &eraseFx{&delFx{fenceFx: &fence, dest: genesis.dest, policy: genesis.policy, subject: genesis.subject}}
	}
	if err = v.stores[1].ReplicaGroup().Campaign(); err != nil {
		t.Fatal(err)
	}
	v.leaderIs(1)
	session, err := v.fx[1].svc.Login(genesis.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	if v.fx[1].cred, err = v.fx[1].svc.Authenticate(genesis.ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	return v
}

func (v *controlVoters) leaderIs(id uint64) {
	v.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for round := 0; time.Now().Before(deadline); round++ {
		g := v.stores[id].ReplicaGroup()
		if g.Status().Leader == id {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, err := g.Fence(ctx)
			cancel()
			if err == nil {
				return
			}
		} else if round%10 == 0 {
			_ = g.Campaign()
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("voter %d did not become the leader", id)
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
func TestEachControlVoterRedactsItsOwnCopy(t *testing.T) {
	v := newControlVoters(t)
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
		if hits := v.fx[id].raftHits(kept); !contains(hits, "raft-control/ready.wal") {
			t.Fatalf("voter %d lost a payload no deletion covers: %v", id, hits)
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
