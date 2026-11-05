// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/replica"
)

// acceptDeleteAuthority stands in for control having committed the deletion
// operation: the storage tests exercise the data plane, not the saga.
type acceptDeleteAuthority struct{ *control.Store }

func (acceptDeleteAuthority) ValidateReplicatedDeleteBarrier(context.Context, model.DeleteBarrier) error {
	return nil
}

type fakeView struct {
	mu    sync.Mutex
	preds []model.DeletePredicate
	err   error
}

func (v *fakeView) set(preds ...model.DeletePredicate) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.preds = preds
}
func (v *fakeView) ActiveDeletions(_ context.Context, org model.ID, _ []model.ID) ([]model.DeletePredicate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err != nil {
		return nil, v.err
	}
	var out []model.DeletePredicate
	for _, p := range v.preds {
		if p.Org == org {
			out = append(out, p)
		}
	}
	return out, nil
}

func enableDeleteSolo(t *testing.T, engine *Engine, raftDirectory string, store *control.Store) (*Engine, error) {
	t.Helper()
	transport := replica.NewLoopback()
	groups, err := engine.EnableReplication(replica.Config{ID: 1, Directory: raftDirectory, Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, acceptDeleteAuthority{store})
	if err != nil {
		engine.Close()
		transport.Close()
		return nil, err
	}
	for _, group := range groups {
		if err = transport.Register(group); err == nil {
			err = group.Campaign()
		}
		if err != nil {
			engine.Close()
			transport.Close()
			return nil, err
		}
	}
	t.Cleanup(func() { engine.Close(); transport.Close() })
	return engine, nil
}

func openDeleteEngine(t *testing.T, dir string, validator Revalidator, store *control.Store) *Engine {
	t.Helper()
	if err := activateTestControl(t, store); err != nil {
		t.Fatal(err)
	}
	engine, err := Open(dir, validator)
	if err != nil {
		t.Fatal(err)
	}
	engine, err = enableDeleteSolo(t, engine, filepath.Join(dir, "raft"), store)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func faultCode(err error) model.Code {
	var fault *model.Fault
	if errors.As(err, &fault) {
		return fault.Code
	}
	return ""
}

// metricBatchAt reserves and normalizes a one-record metric batch whose signal
// time is at.
func metricBatchAt(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, at model.UnixNano) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, e := a.SourceScope(context.Background(), c, false)
	if e != nil {
		t.Fatal(e)
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	policyBytes := mustJSON(t, src.Policy)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policyBytes).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 1000}}}
	n.Reservation, e = store.ReserveAdmission(context.Background(), scope, n)
	if e != nil {
		t.Fatal(e)
	}
	return scope, n
}

func rangeDelete(d model.SourceDescriptor, kinds []model.Kind, start, end model.UnixNano) model.DeletePredicate {
	return model.DeletePredicate{Operation: model.NewID(), Org: d.Org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{d.Project}, Signals: kinds, Start: start, End: end, Generation: 1}
}
func retireProject(d model.SourceDescriptor, project model.ID) model.DeletePredicate {
	return model.DeletePredicate{Operation: model.NewID(), Org: d.Org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}, Generation: 1}
}

func barrierAll(t *testing.T, e *Engine, p model.DeletePredicate) {
	t.Helper()
	for slot := uint16(0); slot < 64; slot++ {
		if _, err := e.RecordDeleteBarrier(context.Background(), slot, p); err != nil {
			t.Fatalf("slot %d: %v", slot, err)
		}
	}
}

func scanTimes(t *testing.T, it RowIterator) map[model.UnixNano]bool {
	t.Helper()
	out := map[model.UnixNano]bool{}
	for {
		page, err := it.Next(context.Background())
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, at := range page.Times {
			out[at] = true
		}
	}
}

func TestDeleteBindDeletionsOnceAndRejectsNil(t *testing.T) {
	store, a, _, _ := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	if err := engine.BindDeletions(nil); faultCode(err) != model.Invalid {
		t.Fatalf("nil view: %v", err)
	}
	if err := engine.BindDeletions(&fakeView{}); err != nil {
		t.Fatal(err)
	}
	if err := engine.BindDeletions(&fakeView{}); faultCode(err) != model.Conflict {
		t.Fatalf("rebind: %v", err)
	}
}

func TestDeleteBarrierIsIdempotentPerSlotAndOperation(t *testing.T) {
	store, a, _, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	ctx := context.Background()
	p := rangeDelete(d, []model.Kind{model.Metric}, 5, 10)
	first, err := engine.RecordDeleteBarrier(ctx, 3, p)
	if err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	before := engine.indexes[3]
	engine.mu.Unlock()
	again, err := engine.RecordDeleteBarrier(ctx, 3, p)
	if err != nil || again != first {
		t.Fatalf("idempotent retry changed the cursor: %v %v %v", err, first, again)
	}
	engine.mu.Lock()
	after := engine.indexes[3]
	engine.mu.Unlock()
	if after != before || uint64(first.Index) != before {
		t.Fatalf("retry proposed a second barrier: %d -> %d (cursor %d)", before, after, first.Index)
	}
	changed := p
	changed.End = 11
	if _, err = engine.RecordDeleteBarrier(ctx, 3, changed); faultCode(err) != model.Conflict {
		t.Fatalf("same operation with another predicate accepted: %v", err)
	}
	if _, err = engine.RecordDeleteBarrier(ctx, 64, p); faultCode(err) != model.Invalid {
		t.Fatalf("slot 64: %v", err)
	}
	bad := p
	bad.Mode = "everything"
	if _, err = engine.RecordDeleteBarrier(ctx, 4, bad); faultCode(err) != model.Invalid {
		t.Fatalf("invalid predicate: %v", err)
	}
	barriers, err := engine.DeleteBarriers(ctx)
	if err != nil || len(barriers) != 1 || barriers[0].Cursor != first || barriers[0].Predicate.Operation != p.Operation {
		t.Fatalf("barriers %v %v", barriers, err)
	}
}

// A write that matches an applied tombstone is refused as a whole; writes the
// predicate does not cover (other time, other project, other signal) stay admitted.
func TestDeleteRangeBarrierRejectsOnlyCoveredWrites(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	ctx := context.Background()
	scopeBefore, before := metricBatchAt(t, store, a, c, d, 7)
	receipt, err := engine.Append(ctx, scopeBefore, before)
	if err != nil {
		t.Fatal(err)
	}
	barrierAll(t, engine, rangeDelete(d, []model.Kind{model.Metric}, 5, 10))
	for _, tc := range []struct {
		at      model.UnixNano
		allowed bool
	}{{4, true}, {5, false}, {9, false}, {10, true}, {11, true}} {
		scope, b := metricBatchAt(t, store, a, c, d, tc.at)
		_, err := engine.Append(ctx, scope, b)
		if tc.allowed && err != nil {
			t.Fatalf("time %d outside [5,10) rejected: %v", tc.at, err)
		}
		if !tc.allowed && faultCode(err) != model.Conflict {
			t.Fatalf("time %d inside [5,10) accepted/err %v", tc.at, err)
		}
	}
	retry, err := engine.Append(ctx, scopeBefore, before)
	if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, receipt)) {
		t.Fatalf("historical receipt lookup broke after the barrier: %v", err)
	}
	// Another signal / another project never matches the predicate.
	other := rangeDelete(d, []model.Kind{model.Log}, 0, 1000)
	elsewhere := retireProject(d, model.NewID())
	otherOrg := retireProject(d, model.NewID())
	otherOrg.Org = model.NewID()
	otherOrg.Mode = model.DeleteRetireOrg
	otherOrg.Projects = nil
	for _, p := range []model.DeletePredicate{other, elsewhere, otherOrg} {
		barrierAll(t, engine, p)
	}
	scope, b := metricBatchAt(t, store, a, c, d, 7777)
	if _, err = engine.Append(ctx, scope, b); err != nil {
		t.Fatalf("unrelated tombstones rejected a write: %v", err)
	}
}

func TestDeleteRetireProjectRejectsEverythingOfThatProjectOnly(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	ctx := context.Background()
	barrierAll(t, engine, retireProject(d, model.NewID()))
	scope, ok := metricBatchAt(t, store, a, c, d, 3)
	if _, err := engine.Append(ctx, scope, ok); err != nil {
		t.Fatalf("another project's retirement rejected this project: %v", err)
	}
	barrierAll(t, engine, retireProject(d, d.Project))
	scope, b := metricBatchAt(t, store, a, c, d, 4)
	if _, err := engine.Append(ctx, scope, b); faultCode(err) != model.Conflict {
		t.Fatalf("retired project accepted a write: %v", err)
	}
	// Retirement is atomic per batch: a retired project never gets even one record.
	engine.mu.Lock()
	rows := 0
	_ = engine.db.View(func(tx *bolt.Tx) error { rows = tx.Bucket([]byte("batches")).Stats().KeyN; return nil })
	engine.mu.Unlock()
	if rows != 1 {
		t.Fatalf("%d batches stored, want only the pre-retirement one", rows)
	}
}

func TestDeleteRetireOrgRejectsAllProjects(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	barrierAll(t, engine, model.DeletePredicate{Operation: model.NewID(), Org: d.Org, Mode: model.DeleteRetireOrg, Generation: 1})
	scope, b := metricBatchAt(t, store, a, c, d, 4)
	if _, err := engine.Append(context.Background(), scope, b); faultCode(err) != model.Conflict {
		t.Fatalf("retired org accepted a write: %v", err)
	}
}

// Replaying the ordered log on a follower or after a snapshot must reject a
// matching batch deterministically (recorded, no ACK) rather than trip the engine.
func TestDeleteApplierRejectsMatchingBatchOrderedAfterBarrier(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	_, late := metricBatchAt(t, store, a, c, d, 7)
	_, outside := metricBatchAt(t, store, a, c, d, 20)
	slot := late.RouteSlot
	// The two batches must share a slot for the ordered check to be observable.
	for outside.RouteSlot != slot {
		_, outside = metricBatchAt(t, store, a, c, d, 20)
	}
	if _, err := engine.RecordDeleteBarrier(context.Background(), slot, rangeDelete(d, []model.Kind{model.Metric}, 5, 10)); err != nil {
		t.Fatal(err)
	}
	machine := &slotMachine{engine: engine, slot: slot}
	apply := func(b model.NormalizedBatch) error {
		engine.mu.Lock()
		logical := engine.indexes[slot] + 1
		var physical, term uint64
		_ = engine.db.View(func(tx *bolt.Tx) error {
			meta := tx.Bucket([]byte("replica_data"))
			physical, term = getUint(meta, metaKey(slot, "physical")), getUint(meta, metaKey(slot, "term"))
			return nil
		})
		engine.mu.Unlock()
		receipt := model.Receipt{Version: 1, BatchID: b.ID, Hash: b.Hash, Cursor: model.Cursor{Group: engine.group(slot), Index: model.Uint64(logical)}, SignalDeadlines: b.Deadlines, DedupUntil: 100, RetainUntil: 100}
		payload, err := json.Marshal(walEntry{Type: "batch", Batch: &b, Receipt: &receipt})
		if err != nil {
			t.Fatal(err)
		}
		reservation := b.Reservation.ID
		return machine.Apply(replica.CommittedEntry{Group: engine.group(slot), Term: term, Index: physical + 1, ApplicationCursor: model.Cursor{Group: engine.group(slot), Index: model.Uint64(logical)}, Entry: replica.Entry{ID: model.NewID(), Kind: replica.Data, Payload: payload, ReservationID: &reservation, ApplicationIndex: logical}})
	}
	if err := apply(late); !errors.Is(err, replica.ErrConflict) {
		t.Fatalf("matching batch ordered after the barrier: %v", err)
	}
	engine.mu.Lock()
	_ = engine.db.View(func(tx *bolt.Tx) error {
		key := batchKey(late.Org, late.Project, late.Source, late.Producer, slot, late.ID)
		if tx.Bucket([]byte("receipts")).Get(key) != nil || tx.Bucket([]byte("batches")).Get(key) != nil {
			t.Error("rejected batch left receipt or data")
		}
		return nil
	})
	engine.mu.Unlock()
	if err := apply(outside); err != nil {
		t.Fatalf("batch outside the predicate rejected at apply: %v", err)
	}
	engine.mu.Lock()
	if engine.failed {
		t.Error("deterministic rejection tripped the engine")
	}
	engine.mu.Unlock()
}

func TestDeleteWriteIsRejectedBeforeProposalWhenControlViewReportsIt(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &fakeView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scopeBefore, before := metricBatchAt(t, store, a, c, d, 7)
	receipt, err := engine.Append(ctx, scopeBefore, before)
	if err != nil {
		t.Fatal(err)
	}
	view.set(rangeDelete(d, []model.Kind{model.Metric}, 5, 10))
	scope, covered := metricBatchAt(t, store, a, c, d, 8)
	engine.mu.Lock()
	indexes := engine.indexes
	engine.mu.Unlock()
	if _, err = engine.Append(ctx, scope, covered); faultCode(err) != model.Conflict {
		t.Fatalf("write covered by a Begun deletion accepted: %v", err)
	}
	engine.mu.Lock()
	moved := engine.indexes != indexes
	engine.mu.Unlock()
	if moved {
		t.Fatal("covered write was proposed")
	}
	scope, free := metricBatchAt(t, store, a, c, d, 50)
	if _, err = engine.Append(ctx, scope, free); err != nil {
		t.Fatalf("uncovered write rejected: %v", err)
	}
	retry, err := engine.Append(ctx, scopeBefore, before)
	if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, receipt)) {
		t.Fatalf("committed receipt not returned after deletion began: %v", err)
	}
	view.mu.Lock()
	view.err = model.Fail(model.Unavailable)
	view.mu.Unlock()
	scope, other := metricBatchAt(t, store, a, c, d, 60)
	if _, err = engine.Append(ctx, scope, other); faultCode(err) != model.Unavailable {
		t.Fatalf("a failing deletion view must fail closed, got %v", err)
	}
}

func TestDeleteScanHidesRowsTheMomentTheViewReportsThem(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &fakeView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, at := range []model.UnixNano{1, 2, 3} {
		scope, b := metricBatchAt(t, store, a, c, d, at)
		if _, err := engine.Append(ctx, scope, b); err != nil {
			t.Fatal(err)
		}
	}
	read := scanScope(t, store, a, d)
	req := ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 100}
	it, err := engine.Scan(ctx, read, req)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	view.set(rangeDelete(d, []model.Kind{model.Metric}, 2, 3))
	got := scanTimes(t, it)
	if got[2] || !got[1] || !got[3] || len(got) != 2 {
		t.Fatalf("iterator opened before the deletion returned %v", got)
	}
	// A new scan applies the same predicate; once the barrier is local the view may forget it.
	barrierAll(t, engine, rangeDelete(d, []model.Kind{model.Metric}, 2, 3))
	view.set()
	fresh, err := engine.Scan(ctx, read, req)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if got = scanTimes(t, fresh); got[2] || len(got) != 2 {
		t.Fatalf("local tombstone does not suppress reads: %v", got)
	}
}

func TestDeleteScanOfRetiredProjectIsNotFoundForOpenAndNewIterators(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &fakeView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, b := metricBatchAt(t, store, a, c, d, 1)
	if _, err := engine.Append(ctx, scope, b); err != nil {
		t.Fatal(err)
	}
	read := scanScope(t, store, a, d)
	req := ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 100}
	open, err := engine.Scan(ctx, read, req)
	if err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	view.set(retireProject(d, d.Project))
	if page, err := open.Next(ctx); faultCode(err) != model.NotFound || page.Len() != 0 {
		t.Fatalf("open iterator of a retired project: %d rows, %v", page.Len(), err)
	}
	if _, err = engine.Scan(ctx, read, req); faultCode(err) != model.NotFound {
		t.Fatalf("new scan of a retired project: %v", err)
	}
}

func TestDeleteSubscribeDoesNotDeliverCoveredRows(t *testing.T) {
	store, a, c, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &fakeView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	read := scanScope(t, store, a, d)
	it, err := engine.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	scope, covered := metricBatchAt(t, store, a, c, d, 8)
	if _, err = engine.Append(ctx, scope, covered); err != nil {
		t.Fatal(err)
	}
	view.set(rangeDelete(d, []model.Kind{model.Metric}, 5, 10))
	quiet, cancel := context.WithTimeout(ctx, 400*time.Millisecond)
	page, err := it.Next(quiet)
	cancel()
	if err == nil && page.Page.Len() > 0 {
		t.Fatalf("live stream delivered a row of a Begun deletion: %v", page.Page.Times)
	}
	if err != nil && faultCode(err) != model.Cancelled {
		t.Fatalf("unexpected stream error %v", err)
	}
	// The stream itself must survive: an uncovered row still arrives.
	it2, err := engine.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric})
	if err != nil {
		t.Fatal(err)
	}
	defer it2.Close()
	scope, free := metricBatchAt(t, store, a, c, d, 50)
	if _, err = engine.Append(ctx, scope, free); err != nil {
		t.Fatal(err)
	}
	wait, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	page, err = it2.Next(wait)
	if err != nil || page.Page.Len() != 1 || page.Page.Times[0] != 50 {
		t.Fatalf("uncovered live row not delivered: %v %v", page.Page.Times, err)
	}
	view.set(retireProject(d, d.Project))
	page, err = it2.Next(wait)
	if err != nil || !page.Revoked || page.Page.Len() != 0 {
		t.Fatalf("retired project must revoke the live stream, got revoked=%v rows=%d err=%v", page.Revoked, page.Page.Len(), err)
	}
}

func TestDeleteBlobWritesAndReadsHonourTombstonesAndView(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, c)
	view := &fakeView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := a.Login(ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := a.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := a.Authorize(ctx, actor, m.Org, []model.ID{m.Project}, auth.ArtifactRead)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := engine.WriteBlob(ctx, scope, m, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.ReadBlobFragment(ctx, reader, receipt, 0); err != nil {
		t.Fatalf("baseline artifact read: %v", err)
	}
	entity := model.DeletePredicate{Operation: model.NewID(), Org: m.Org, Mode: model.DeleteEntity, Projects: []model.ID{m.Project}, Entities: []model.ID{m.Root}, Generation: 1}
	view.set(entity)
	if _, err = engine.ReadBlobFragment(ctx, reader, receipt, 0); faultCode(err) != model.NotFound {
		t.Fatalf("artifact of a Begun deletion released bytes: %v", err)
	}
	second := m
	second.Root = model.NewID()
	second.ReservationID = model.ID{}
	reserved, err := c.ReserveArtifact(ctx, scope, second)
	if err != nil {
		t.Fatal(err)
	}
	second = reserved.Manifest
	other, err := engine.WriteBlob(ctx, scope, second, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("another artifact root must stay writable: %v", err)
	}
	if _, err = engine.ReadBlobFragment(ctx, reader, other, 0); err != nil {
		t.Fatalf("another artifact root must stay readable: %v", err)
	}
	// The same tombstone, now applied locally, rejects new fragments of that root at order time.
	view.set()
	barrierAll(t, engine, entity)
	if _, err = engine.ReadBlobFragment(ctx, reader, receipt, 0); faultCode(err) != model.NotFound {
		t.Fatalf("local tombstone does not hide the artifact: %v", err)
	}
	third := m
	third.Root = m.Root
	engine.mu.Lock()
	slot := model.BlobOwnerSlot(m.Org, m.Project, m.Root)
	rejected := engine.db.View(func(tx *bolt.Tx) error { return validateBlobFence(tx, m, slot) })
	engine.mu.Unlock()
	if faultCode(rejected) != model.Conflict {
		t.Fatalf("ordered artifact fragment of a deleted root not rejected: %v", rejected)
	}
}

func TestDeleteBarrierSurvivesRestartAndSnapshotInstall(t *testing.T) {
	store, a, c, d := fixture(t)
	dir := t.TempDir()
	engine := openDeleteEngine(t, dir, a, store)
	p := rangeDelete(d, []model.Kind{model.Metric}, 5, 10)
	barrierAll(t, engine, p)
	snapshot, err := engine.CreateSnapshots(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	check := func(e *Engine, label string) {
		t.Helper()
		barriers, err := e.DeleteBarriers(context.Background())
		if err != nil || len(barriers) != 64 {
			t.Fatalf("%s: %d barriers, %v", label, len(barriers), err)
		}
		for i, barrier := range barriers {
			if barrier.Predicate.Operation != p.Operation || barrier.Cursor.Group != e.group(uint16(i)) {
				t.Fatalf("%s: barrier %d out of (slot, operation) order", label, i)
			}
		}
		scope, b := metricBatchAt(t, store, a, c, d, 6)
		if _, err = e.Append(context.Background(), scope, b); faultCode(err) != model.Conflict {
			t.Fatalf("%s: covered write accepted: %v", label, err)
		}
	}
	check(engine, "live")
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	check(openDeleteEngine(t, dir, a, store), "restart")
	restored, err := Open(t.TempDir(), a)
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.InstallReplicationIdentity(engine.identity); err != nil {
		t.Fatal(err)
	}
	if err = installEngineSnapshot(t, snapshot)(restored, filepath.Join(restored.dir, "raft")); err != nil {
		t.Fatal(err)
	}
	restored, err = enableDeleteSolo(t, restored, filepath.Join(restored.dir, "raft"), store)
	if err != nil {
		t.Fatal(err)
	}
	check(restored, "snapshot install")
}

func TestDeleteLedgerCarriesBarriersAndGeneration(t *testing.T) {
	store, a, _, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	machine := &slotMachine{engine: engine, slot: 9}
	before, err := machine.DeletionLedger()
	if err != nil {
		t.Fatal(err)
	}
	p := rangeDelete(d, []model.Kind{model.Metric}, 5, 10)
	cursor, err := engine.RecordDeleteBarrier(context.Background(), 9, p)
	if err != nil {
		t.Fatal(err)
	}
	after, err := machine.DeletionLedger()
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation != before.Generation+1 {
		t.Fatalf("ledger generation %d -> %d, want +1 per barrier", before.Generation, after.Generation)
	}
	found := false
	for _, entry := range after.Entries {
		if entry.Kind == "delete_barrier" && entry.Index == uint64(cursor.Index) {
			found = true
		}
	}
	if !found {
		t.Fatal("barrier missing from the deletion ledger")
	}
	if untouched, err := (&slotMachine{engine: engine, slot: 10}).DeletionLedger(); err != nil || untouched.Generation != before.Generation {
		t.Fatalf("barrier of slot 9 changed slot 10's generation: %v %v", untouched.Generation, err)
	}
}

func TestDeleteBackupIsAbortedByDeletionBarrier(t *testing.T) {
	store, a, _, d := fixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	backup, err := engine.BeginBackup(context.Background(), controlCut(t, engine, store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.RecordDeleteBarrier(context.Background(), 5, rangeDelete(d, []model.Kind{model.Metric}, 5, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err = backup.Seal(context.Background(), nil); faultCode(err) != model.Conflict {
		t.Fatalf("backup sealed evidence across a deletion: %v", err)
	}
	// A backup begun after the deletion fence is not disturbed by it.
	fresh, err := engine.BeginBackup(context.Background(), controlCut(t, engine, store))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = engine.RecordDeleteBarrier(context.Background(), 5, rangeDelete(d, []model.Kind{model.Metric}, 5, 10)); err != nil {
		t.Fatal(err)
	}
	fresh.Abort()
}

// restoreWithOldBackup builds a live engine, seals a backup BEFORE the deletion,
// then restores it into an empty engine, leaving the deletion unknown to it.
func TestDeleteRestoreGateRequiresLedgerAndThenSuppresses(t *testing.T) {
	store, a, c, d := fixture(t)
	live := openDeleteEngine(t, t.TempDir(), a, store)
	if err := store.BindAdmissionOwner(live); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope, old := metricBatchAt(t, store, a, c, d, 7)
	if _, err := live.Append(ctx, scope, old); err != nil {
		t.Fatal(err)
	}
	backup, err := live.BeginBackup(ctx, controlCut(t, live, store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ReconcileQuota(sealed.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	// The deletion happens after the backup; the restored node has never heard of it.
	p := rangeDelete(d, []model.Kind{model.Metric}, 5, 10)
	dir := t.TempDir()
	restored, err := Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.InstallReplicationIdentity(sealed.Bundle.Identity); err != nil {
		t.Fatal(err)
	}
	raft := filepath.Join(dir, "raft")
	if err = restored.InstallBackup(ctx, raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, deletionPendingFile)); err != nil {
		t.Fatal("install did not write the durable deletion marker")
	}
	if restored, err = enableDeleteSolo(t, restored, raft, store); err != nil {
		t.Fatal(err)
	}
	if err = restored.CommitQuotaReconciliation(ctx, cert); err != nil {
		t.Fatal(err)
	}
	if restored.RestoreReady() == nil {
		t.Fatal("restored engine ready before the deletion ledger was applied")
	}
	read := scanScope(t, store, a, d)
	req := ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 100}
	if _, err = restored.Scan(ctx, read, req); faultCode(err) != model.Unavailable {
		t.Fatalf("scan served before the ledger: %v", err)
	}
	if _, err = restored.Subscribe(ctx, read, SubscribeRequest{Projects: []model.ID{d.Project}, Signal: model.Metric}); faultCode(err) != model.Unavailable {
		t.Fatalf("subscribe served before the ledger: %v", err)
	}
	scopeNew, fresh := metricBatchAt(t, store, a, c, d, 50)
	if _, err = restored.Append(ctx, scopeNew, fresh); faultCode(err) != model.Unavailable {
		t.Fatalf("append admitted before the ledger: %v", err)
	}
	ledger := replica.Ledger{Version: 1, Generation: 1, Entries: []replica.LedgerEntry{{Index: 1, Kind: "delete_barrier", Hash: p.Digest()}}}
	forged := ledger
	forged.Entries = []replica.LedgerEntry{{Index: 1, Kind: "delete_barrier", Hash: model.HashCanonical([]byte("another predicate"))}}
	if err = restored.ApplyDeletionLedger(ctx, forged, []model.DeletePredicate{p}); err == nil {
		t.Fatal("forged ledger digest accepted")
	}
	if err = restored.ApplyDeletionLedger(ctx, replica.Ledger{Version: 1, Generation: 0, Entries: ledger.Entries}, []model.DeletePredicate{p}); err == nil {
		t.Fatal("ledger generation below its own entry count accepted")
	}
	if restored.RestoreReady() == nil {
		t.Fatal("a refused ledger opened the gate")
	}
	// One unavailable slot leaves the gate closed; a retry completes (idempotent).
	restored.fault = onceAt("tombstone_slot", 5)
	if err = restored.ApplyDeletionLedger(ctx, ledger, []model.DeletePredicate{p}); err == nil {
		t.Fatal("interrupted ledger application reported success")
	}
	restored.fault = nil
	if restored.RestoreReady() == nil {
		t.Fatal("gate opened although a slot was missing")
	}
	if err = restored.ApplyDeletionLedger(ctx, ledger, []model.DeletePredicate{p}); err != nil {
		t.Fatal(err)
	}
	if err = restored.RestoreReady(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, deletionPendingFile)); !os.IsNotExist(err) {
		t.Fatal("deletion marker survived a completed ledger")
	}
	it, err := restored.Scan(ctx, read, req)
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	if got := scanTimes(t, it); len(got) != 0 {
		t.Fatalf("restored engine returned deleted rows %v", got)
	}
	scopeCovered, covered := metricBatchAt(t, store, a, c, d, 6)
	if _, err = restored.Append(ctx, scopeCovered, covered); faultCode(err) != model.Conflict {
		t.Fatalf("restored engine accepted a write the deletion covers: %v", err)
	}
	if _, err = restored.Append(ctx, scopeNew, fresh); err != nil {
		t.Fatalf("restored engine refuses uncovered intake: %v", err)
	}
	// A ledger older than the applied generation is a rollback and is refused.
	if err = restored.ApplyDeletionLedger(ctx, replica.Ledger{Version: 1, Generation: 0}, nil); faultCode(err) != model.Stale {
		t.Fatalf("stale ledger accepted: %v", err)
	}
}

func TestDeleteRestoreGateSurvivesRestart(t *testing.T) {
	store, a, _, d := fixture(t)
	live := openDeleteEngine(t, t.TempDir(), a, store)
	if err := store.BindAdmissionOwner(live); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	backup, err := live.BeginBackup(ctx, controlCut(t, live, store))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	restored, err := Open(dir, a)
	if err != nil {
		t.Fatal(err)
	}
	if err = restored.InstallReplicationIdentity(sealed.Bundle.Identity); err != nil {
		t.Fatal(err)
	}
	if err = restored.InstallBackup(ctx, filepath.Join(dir, "raft"), sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
	}); err != nil {
		t.Fatal(err)
	}
	restored.Close()
	again := openDeleteEngineRestored(t, dir, a, store)
	read := scanScope(t, store, a, d)
	req := ScanRequest{Projects: []model.ID{d.Project}, Signal: model.Metric, End: 100}
	if _, err = again.Scan(ctx, read, req); faultCode(err) != model.Unavailable {
		t.Fatalf("restart forgot the deletion gate: %v", err)
	}
	if err = again.ApplyDeletionLedger(ctx, replica.Ledger{Version: 1}, nil); err != nil {
		t.Fatal(err)
	}
	it, err := again.Scan(ctx, read, req)
	if err != nil {
		t.Fatalf("scan still gated after the ledger: %v", err)
	}
	it.Close()
}

func openDeleteEngineRestored(t *testing.T, dir string, validator Revalidator, store *control.Store) *Engine {
	t.Helper()
	engine, err := Open(dir, validator)
	if err != nil {
		t.Fatal(err)
	}
	engine, err = enableDeleteSolo(t, engine, filepath.Join(dir, "raft"), store)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

// tryAppendTyped is appendTyped without the fatal on rejection.
func tryAppendTyped(t *testing.T, e *Engine, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, row model.Record) error {
	t.Helper()
	ctx := context.Background()
	source, err := a.SourceAuthority(ctx, c, true)
	if err != nil {
		t.Fatal(err)
	}
	service, err := policy.New(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := service.ResolveSource(ctx, c, d.Project, d.Source, source.Policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := policy.Normalize(grant, typedInput(t, d, source.Policy.Revision, row))
	if err != nil {
		t.Fatalf("normalize %s %s: %v", row.Kind, row.ID, err)
	}
	scope, err := grant.Scope()
	if err != nil {
		t.Fatal(err)
	}
	if batch.Reservation, err = store.ReserveAdmission(ctx, scope, batch); err != nil {
		t.Fatal(err)
	}
	_, err = e.Append(ctx, scope, batch)
	return err
}

// An entity tombstone owns the chunks of the named replay/profile only: other
// replays, a profile that happens to share the root, and referencing rows stay.
func TestDeleteEntityBarrierRejectsOnlyNamedChunksAndHidesStoredOnes(t *testing.T) {
	store, a, c, d := typedFixture(t)
	engine := openDeleteEngine(t, t.TempDir(), a, store)
	view := &fakeView{}
	if err := engine.BindDeletions(view); err != nil {
		t.Fatal(err)
	}
	source, err := a.SourceAuthority(context.Background(), c, true)
	if err != nil {
		t.Fatal(err)
	}
	resource := model.Resource{Service: source.Policy.Resources.Services[0], Environment: source.Policy.Resources.Environments[0], Build: source.Policy.Resources.Builds[0], Instance: source.Policy.Resources.Instances[0]}
	rows := typedRows(resource)
	replayRow, profileRow := rows[9], rows[10]
	root := replayRow.Payload.Replay.Replay
	if profileRow.Payload.Profile.Profile != root {
		t.Fatal("fixture no longer shares the replay/profile root")
	}
	sibling := replayRow
	sibling.ID = model.NewID()
	chunk := *replayRow.Payload.Replay
	chunk.Replay = model.NewID()
	sibling.Payload = model.Payload{Replay: &chunk}
	stored := replayRow
	stored.ID = model.NewID()
	storedChunk := *replayRow.Payload.Replay
	storedChunk.Sequence++
	stored.Payload = model.Payload{Replay: &storedChunk}
	if err = tryAppendTyped(t, engine, store, a, c, d, stored); err != nil {
		t.Fatal(err)
	}
	if err = tryAppendTyped(t, engine, store, a, c, d, sibling); err != nil {
		t.Fatal(err)
	}
	read := scanScope(t, store, a, d)
	count := func(kind model.Kind) int {
		it, err := engine.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: kind, End: 100})
		if err != nil {
			t.Fatal(err)
		}
		defer it.Close()
		n := 0
		for {
			page, err := it.Next(context.Background())
			if err == io.EOF {
				return n
			}
			if err != nil {
				t.Fatal(err)
			}
			n += page.Len()
		}
	}
	if count(model.Replay) != 2 {
		t.Fatal("fixture: both replay chunks must be readable")
	}
	entity := model.DeletePredicate{Operation: model.NewID(), Org: d.Org, Mode: model.DeleteEntity, Projects: []model.ID{d.Project}, Signals: []model.Kind{model.Replay}, Entities: []model.ID{root}, Generation: 1}
	view.set(entity)
	if got := count(model.Replay); got != 1 {
		t.Fatalf("%d replay rows readable under an entity deletion, want only the sibling replay", got)
	}
	if err = tryAppendTyped(t, engine, store, a, c, d, replayRow); faultCode(err) != model.Conflict {
		t.Fatalf("chunk of the deleted replay accepted: %v", err)
	}
	if err = tryAppendTyped(t, engine, store, a, c, d, profileRow); err != nil {
		t.Fatalf("a profile outside the entity's signal list was rejected: %v", err)
	}
	if count(model.Profile) != 1 {
		t.Fatal("profile sharing the root was hidden")
	}
	view.set()
	barrierAll(t, engine, entity)
	if got := count(model.Replay); got != 1 {
		t.Fatalf("local entity tombstone: %d replay rows readable", got)
	}
}
