// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// acceptBarriers is the control store with the barrier check relaxed: these tests drive the data
// plane without a deletion saga, so no control operation exists for the predicate.
type acceptBarriers struct{ *control.Store }

func (acceptBarriers) ValidateReplicatedDeleteBarrier(context.Context, model.DeleteBarrier) error {
	return nil
}

const votersCanary = "VOTERSCANARY9d41c7e03ab55"

// canaryBatch is distinctBatch with the canary in the series name (the reservation binds the
// batch hash, so the name must be set before reserving).
func canaryBatch(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, i int) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, err := a.SourceScope(context.Background(), c, false)
	if err != nil {
		t.Fatal(err)
	}
	src, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(i + 1), Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: fmt.Sprintf("%s_%d", votersCanary, i), Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}}}
	slot, err := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(mustJSON(t, src.Policy)).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 1 << 40}}}
	if n.Reservation, err = store.ReserveAdmission(context.Background(), scope, n); err != nil {
		t.Fatal(err)
	}
	return scope, n
}

// canaryVoters opens three voters led by node 1 and ACKs n canary batches.
func canaryVoters(t *testing.T, n int) *maintenanceFixture {
	t.Helper()
	store, service, credential, descriptor := fixture(t)
	f := &maintenanceFixture{t: t, store: store, service: service, descriptor: descriptor, acks: &ackLog{}}
	f.v = openVotersWith(t, service, acceptBarriers{store})
	f.v.lead(t, func(int) uint64 { return 1 })
	var batches []model.NormalizedBatch
	for i := range n {
		scope, b := canaryBatch(t, store, service, credential, descriptor, i)
		f.scope = scope
		batches = append(batches, b)
	}
	f.ack(batches)
	f.v.converge(t, f.acks.perSlot())
	return f
}

// openVotersWith is openVoters with a caller-chosen replication authority.
func openVotersWith(t *testing.T, service *auth.Service, authority ReplicatedAuthority) *voters {
	t.Helper()
	v := &voters{mesh: newTestMesh(), dirs: map[uint64]string{}, engines: map[uint64]*Engine{}, groups: map[uint64][]*replica.Group{}}
	members := replica.Members{Revision: 1}
	for node := uint64(1); node <= 3; node++ {
		members.Nodes = append(members.Nodes, replica.Member{ID: node, Address: "https://node" + string(rune('0'+node)) + ".invalid", NodeIdentity: "node-" + string(rune('0'+node)), FailureDomain: "disk-" + string(rune('0'+node))})
	}
	var seed ReplicationSeed
	for node := uint64(1); node <= 3; node++ {
		dir := t.TempDir()
		engine, err := Open(dir, service)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { engine.Close() })
		if node == 1 {
			if seed, err = engine.ReplicationSeed(); err != nil {
				t.Fatal(err)
			}
		} else if err = engine.InstallReplicationIdentity(seed.Identity); err != nil {
			t.Fatal(err)
		}
		groups, err := engine.EnableReplication(replica.Config{ID: node, Directory: filepath.Join(dir, "raft"), Transport: meshTransport{mesh: v.mesh, node: node}, Members: members, TickInterval: 20 * time.Millisecond}, &seed, authority)
		if err != nil {
			t.Fatal(err)
		}
		v.mesh.register(node, groups)
		v.dirs[node], v.engines[node], v.groups[node] = dir, engine, groups
	}
	t.Cleanup(v.mesh.close)
	return v
}

func (f *maintenanceFixture) deletionPredicate() model.DeletePredicate {
	return model.DeletePredicate{Operation: model.NewID(), Org: f.descriptor.Org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.descriptor.Project}, Signals: []model.Kind{model.Metric}, Start: 0, End: 1000, Generation: 1}
}

// fencedPredicate records the tombstone of a fresh deletion in every data slot (the saga's
// fencing step), as the saga does through the voter that runs it.
func (f *maintenanceFixture) fencedPredicate() model.DeletePredicate {
	f.t.Helper()
	pred := f.deletionPredicate()
	f.v.lead(f.t, func(int) uint64 { return 1 })
	for slot := range uint16(64) {
		if _, err := f.v.engines[1].RecordDeleteBarrier(context.Background(), slot, pred); err != nil {
			f.t.Fatalf("barrier slot %d: %v (leader per node: %d %d %d)", slot, err, f.v.groups[1][slot].Status().Leader, f.v.groups[2][slot].Status().Leader, f.v.groups[3][slot].Status().Leader)
		}
	}
	f.v.converge(f.t, f.acks.perSlot())
	return pred
}

// voterErase is the retention worker's per-voter sequence for one operation: erase from this
// voter's own stores, cut its own snapshots and journal, mark it, acknowledge it.
func (f *maintenanceFixture) voterErase(node uint64, pred model.DeletePredicate) {
	f.t.Helper()
	e := f.v.engines[node]
	ctx := context.Background()
	// The test mesh cannot forward a proposal, so the voter that proposes must lead (the real
	// transport forwards to the leader).
	f.v.lead(f.t, func(int) uint64 { return node })
	if _, err := e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		f.t.Fatalf("node %d erase: %v", node, err)
	}
	if err := e.CheckpointErasure(ctx, pred); err != nil {
		f.t.Fatalf("node %d checkpoint: %v", node, err)
	}
	if err := f.v.maintain(node); err != nil {
		f.t.Fatalf("node %d maintain: %v", node, err)
	}
	if _, err := e.DropSupersededSnapshots(ctx); err != nil {
		f.t.Fatalf("node %d drop: %v", node, err)
	}
	if err := e.CompactJournals(ctx); err != nil {
		f.t.Fatalf("node %d compact: %v", node, err)
	}
	if err := e.MarkErased([]model.ID{pred.Operation}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *maintenanceFixture) ackErasure(node uint64) {
	f.t.Helper()
	f.v.lead(f.t, func(int) uint64 { return node })
	if err := f.v.engines[node].AckErasure(context.Background()); err != nil {
		f.t.Fatalf("node %d ack: %v", node, err)
	}
}

// waitResidual waits until node's receipt view of op is want (an ack replicates asynchronously
// to the other voters).
func (f *maintenanceFixture) waitResidual(node uint64, op model.ID, want bool) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		got := len(f.v.engines[node].ErasureResidual(op)) > 0
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("node %d: erasure residual named=%v, want %v", node, got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The reported defect: a deletion's physical erasure ran on one voter only, so the other
// voters kept the deleted records live in batches, metrics and the scan index while the receipt
// said done with no residue. Every voter erases its own copy, and the receipt keeps naming the
// data store until every member acknowledged.
func TestEveryVoterErasesItsOwnCopyAndTheReceiptWaitsForAll(t *testing.T) {
	f := canaryVoters(t, 6)
	for node := uint64(1); node <= 3; node++ {
		if applyFileHits(t, f.v.engines[node], votersCanary) == 0 {
			t.Fatalf("fixture invalid: node %d has no canary", node)
		}
	}
	pred := f.fencedPredicate()
	f.voterErase(1, pred)
	f.ackErasure(1)
	for _, node := range []uint64{2, 3} {
		if n := applyFileHits(t, f.v.engines[node], votersCanary); n == 0 {
			t.Fatalf("node %d: expected the live copy before its own erase", node)
		}
		if hits := rawHits(t, f.v.engines[node], votersCanary); len(hits) == 0 {
			t.Fatalf("node %d: no live keys before its own erase", node)
		}
		if got := f.v.engines[node].ErasureResidual(pred.Operation); len(got) == 0 {
			t.Fatalf("node %d answers a receipt with no residue while its own store holds the bytes", node)
		}
	}
	f.waitResidual(1, pred.Operation, true)
	f.voterErase(2, pred)
	f.ackErasure(2)
	f.waitResidual(1, pred.Operation, true) // node 3 has not acknowledged
	f.voterErase(3, pred)
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
		if n := applyFileHits(t, f.v.engines[node], votersCanary); n != 0 {
			t.Fatalf("node %d: %d canary copies in its apply.db after the receipt is clean", node, n)
		}
		if hits := rawHits(t, f.v.engines[node], votersCanary); len(hits) != 0 {
			t.Fatalf("node %d: live keys remain: %v", node, hits)
		}
		if got := f.v.engines[node].ResidualStores(); len(got) != 0 {
			t.Fatalf("node %d residual stores: %v", node, got)
		}
	}
}

// A voter that is stopped while the others erase keeps the residue named in everyone's receipt
// until it returns, erases its own copy and acknowledges.
func TestStoppedVoterKeepsTheResidueNamedUntilItCatchesUp(t *testing.T) {
	f := canaryVoters(t, 6)
	pred := f.fencedPredicate()
	f.v.mesh.partition(3, true)
	f.voterErase(1, pred)
	f.voterErase(2, pred)
	f.ackErasure(1)
	f.ackErasure(2)
	for _, node := range []uint64{1, 2} {
		f.waitResidual(node, pred.Operation, true)
	}
	if applyFileHits(t, f.v.engines[3], votersCanary) == 0 {
		t.Fatal("fixture invalid: node 3 lost the canary without erasing")
	}
	f.v.mesh.partition(3, false)
	f.voterErase(3, pred)
	f.ackErasure(3)
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
		if n := applyFileHits(t, f.v.engines[node], votersCanary); n != 0 {
			t.Fatalf("node %d: %d copies after catch-up", node, n)
		}
	}
}

// The marker and the acknowledgements are durable: a restarted voter neither forgets that it
// erased nor loses the acknowledgements it applied.
func TestEraseMarkerAndAcknowledgementsSurviveRestart(t *testing.T) {
	f := canaryVoters(t, 4)
	pred := f.fencedPredicate()
	for node := uint64(1); node <= 3; node++ {
		f.voterErase(node, pred)
		f.ackErasure(node)
	}
	for node := uint64(1); node <= 3; node++ {
		f.waitResidual(node, pred.Operation, false)
	}
	for node := uint64(1); node <= 3; node++ {
		if err := f.v.engines[node].Close(); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := Open(f.v.dirs[1], f.service)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reopened.ErasedLocally(pred.Operation) {
		t.Fatal("the local erase marker did not survive a restart")
	}
	if n := applyFileHits(t, reopened, votersCanary); n != 0 {
		t.Fatalf("%d canary copies after restart", n)
	}
}

// hasAck reports whether node's own acknowledgement of op stands: attributed, written under its
// current epoch and not withdrawn.
func (f *maintenanceFixture) hasAck(node uint64, op model.ID) bool {
	e := f.v.engines[node]
	id, identity, ok := e.selfMember()
	if !ok {
		f.t.Fatal("no self member")
	}
	return e.db.View(func(tx *bolt.Tx) error {
		if !ackStands(tx.Bucket([]byte("replica_data")), op, id, identity) {
			return errors.New("absent")
		}
		return nil
	}) == nil
}

// A voter does not acknowledge while its own stores still owe something (the journal and
// snapshots cut before the erasure), and does once they are clean.
func TestVoterDoesNotAcknowledgeWhileItsOwnStoresAreDirty(t *testing.T) {
	f := canaryVoters(t, 4)
	pred := f.fencedPredicate()
	e := f.v.engines[1]
	ctx := context.Background()
	f.v.lead(t, func(int) uint64 { return 1 })
	if _, err := e.EraseDeleted(ctx, []model.DeletePredicate{pred}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.MarkErased([]model.ID{pred.Operation}); err != nil {
		t.Fatal(err)
	}
	if len(e.ResidualStores()) == 0 {
		t.Fatal("fixture invalid: the journal and snapshots are still dirty right after the erase")
	}
	if err := e.AckErasure(ctx); err != nil {
		t.Fatal(err)
	}
	if f.hasAck(1, pred.Operation) {
		t.Fatalf("acknowledged while the node's own stores still owe %v", e.ResidualStores())
	}
	f.voterErase(1, pred)
	f.ackErasure(1)
	if !f.hasAck(1, pred.Operation) {
		t.Fatal("did not acknowledge once clean")
	}
}

// An owed scrub of apply.db's free pages is reported by this node's own residual stores, so a
// receipt answered by a voter that installed a snapshot (its file replaced, scrub owed) never
// claims the data store is clean.
func TestResidualStoresNameTheApplyDatabaseWhileAScrubIsOwed(t *testing.T) {
	f := canaryVoters(t, 2)
	e := f.v.engines[1]
	if got := e.ResidualStores(); contains(got, ResidualApplyDB) {
		t.Fatalf("nothing is owed yet: %v", got)
	}
	if err := e.db.Update(e.markScrubPendingTx); err != nil {
		t.Fatal(err)
	}
	if got := e.ResidualStores(); !contains(got, ResidualApplyDB) {
		t.Fatalf("a scrub is owed but the store is not named: %v", got)
	}
	if _, pending, err := e.scrubFreePages(context.Background()); err != nil || pending {
		t.Fatalf("scrub: pending=%v %v", pending, err)
	}
	if got := e.ResidualStores(); contains(got, ResidualApplyDB) {
		t.Fatalf("scrubbed but still named: %v", got)
	}
}
