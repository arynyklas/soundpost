// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"sync/atomic"
	"testing"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/replays"
)

// countingAppender counts what reaches the durable appender.
type countingAppender struct {
	inner   ingest.Appender
	appends atomic.Int64
}

func (c *countingAppender) Append(ctx context.Context, s auth.Scope, b model.NormalizedBatch) (model.Receipt, error) {
	c.appends.Add(1)
	return c.inner.Append(ctx, s, b)
}
func (c *countingAppender) LookupReceipt(ctx context.Context, s auth.Scope, q model.ReceiptRequest) (model.Receipt, error) {
	return c.inner.LookupReceipt(ctx, s, q)
}
func (c *countingAppender) ReceiptReplayChunks(ctx context.Context, s auth.Scope, q model.ReceiptRequest, r model.Receipt) ([]model.ReplayChunk, error) {
	return c.inner.(appcore.ReceiptChunkReader).ReceiptReplayChunks(ctx, s, q, r)
}

// countingIndex counts the index reads and writes; skipCheck lets a test model a
// chunk that raced past the pre-check.
type countingIndex struct {
	inner     appcore.ReplayIndex
	checks    atomic.Int64
	records   atomic.Int64
	skipCheck atomic.Bool
}

func (c *countingIndex) CheckIndex(ctx context.Context, s auth.Scope, p model.ID, ch model.ReplayChunk) error {
	c.checks.Add(1)
	if c.skipCheck.Load() {
		return nil
	}
	return c.inner.CheckIndex(ctx, s, p, ch)
}
func (c *countingIndex) RecordScope(ctx context.Context, s auth.Scope, p model.ID, ch model.ReplayChunk, retain model.UnixNano) error {
	c.records.Add(1)
	return c.inner.RecordScope(ctx, s, p, ch, retain)
}

// flakyStore is the control store the replay service records into, failing every
// write while armed: a control store that is unreachable after the append.
type flakyStore struct {
	replays.ReferenceStore
	down atomic.Bool
}

func (f *flakyStore) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	if f.down.Load() {
		return model.Fail(model.Unavailable)
	}
	return f.ReferenceStore.Update(ctx, fn)
}

// decorate replaces the rig's ingest service with the production composition (the
// closed-format gate, the index-recording appender) over the same stores, with the
// given control store behind the replay service and counters at both seams.
func (r *indexRig) decorate(store replays.ReferenceStore) (*countingAppender, *countingIndex) {
	r.t.Helper()
	service, err := replays.New(r.app.Storage, r.app.Auth, store)
	if err != nil {
		r.t.Fatal(err)
	}
	inner := &countingAppender{inner: r.app.Storage}
	index := &countingIndex{inner: service}
	appender, err := appcore.NewReplayIndexingAppender(inner, index)
	if err != nil {
		r.t.Fatal(err)
	}
	p, err := policy.New(r.app.Auth, nil)
	if err != nil {
		r.t.Fatal(err)
	}
	svc, err := ingest.New(r.app.Auth, p, r.app.Control, appender)
	if err != nil {
		r.t.Fatal(err)
	}
	svc.SetReplayGate(replays.ValidateChunk)
	r.override = svc
	return inner, index
}

// The process dies after the durable append and before the index step. The
// sender was not acknowledged. After the restart it retries the SAME batch: the
// retry returns the original receipt, the index now holds the checkpoint exactly
// once, and nothing was appended twice.
func TestReplayIndexConvergesAfterACrashBetweenAppendAndRecord(t *testing.T) {
	rig := newIndexRig(t)
	store := &flakyStore{ReferenceStore: rig.app.Control}
	store.down.Store(true)
	before, _ := rig.decorate(store)

	rec := newReplayRecorder()
	cp := rec.cp()
	batch := rig.replayBatch(cp)
	got, err := rig.admit(batch)
	if codeOf(err) != model.Unavailable || got.BatchID != (model.ID{}) {
		t.Fatalf("a batch whose index step failed was acknowledged: %+v %v", got, err)
	}
	if before.appends.Load() != 1 || rig.storedRows(rec.replay) != 1 {
		t.Fatal("fixture invalid: the batch must be durable before the index step fails")
	}
	if group, pin := rig.indexOf(rec.replay); group != nil || pin.RetainUntil != 0 {
		t.Fatal("fixture invalid: the index must be empty after the failed step")
	}
	charged, reservations := rig.quota()

	rig.restart()
	after, index := rig.decorate(rig.app.Control)
	receipt, err := rig.admit(batch)
	if err != nil {
		t.Fatalf("the retry of the same batch after the restart: %v", err)
	}
	if after.appends.Load() != 1 || index.records.Load() != 1 {
		t.Fatalf("the retry made %d appends and %d records, want one each", after.appends.Load(), index.records.Load())
	}

	// The original receipt: the same batch, the first (and only) entry of its slot,
	// identical to what the historical lookup serves.
	original, err := rig.lookup(batch, receipt.Hash)
	if err != nil || !original.Historical || original.Cursor != receipt.Cursor || original.BatchID != batch.ID || receipt.Cursor.Index != 1 {
		t.Fatalf("retry receipt %+v is not the original %+v (%v)", receipt, original, err)
	}
	if rows := rig.storedRows(rec.replay); rows != 1 {
		t.Fatalf("%d rows stored after the retry, want the one the first attempt appended", rows)
	}
	if bytes, n := rig.quota(); bytes != charged || n != reservations {
		t.Fatalf("the retry charged again: %d bytes in %d reservations, was %d in %d", bytes, n, charged, reservations)
	}
	group, pin := rig.indexOf(rec.replay)
	if group == nil || group.Seq != 1 || len(group.Checkpoints) != 1 || group.Checkpoints[0].Sequence != 1 {
		t.Fatalf("index after the retry: %+v", group)
	}
	if want, _ := replays.ChunkHash(cp); group.Checkpoints[0].Hash != want {
		t.Fatal("the recorded checkpoint is not the stored chunk")
	}
	var deadline model.UnixNano
	for _, d := range receipt.SignalDeadlines {
		if d.Kind == model.Replay {
			deadline = d.RetainUntil
		}
	}
	if deadline == 0 || pin.RetainUntil != deadline {
		t.Fatalf("group deadline %d, receipt replay deadline %d", pin.RetainUntil, deadline)
	}

	// A further retry changes nothing: the index is written once.
	again, err := rig.admit(batch)
	if err != nil || again.Cursor != receipt.Cursor {
		t.Fatalf("second retry: %+v %v", again, err)
	}
	if g, _ := rig.indexOf(rec.replay); g.Seq != 1 || len(g.Checkpoints) != 1 || rig.storedRows(rec.replay) != 1 || after.appends.Load() != 2 {
		t.Fatalf("a repeated retry changed state: index %+v", g)
	}
	if got := rig.reads(rec.replay); got != "checkpoint1" {
		t.Fatalf("the reader sees %q", got)
	}
}

// A chunk that conflicts with a recorded checkpoint is refused before it is
// stored, as a typed Conflict: neither the stored rows nor the index change, and
// the real replay still reads continuous.
func TestAForgedCheckpointIsRefusedBeforeItIsStored(t *testing.T) {
	rig := newIndexRig(t)
	appends, index := rig.decorate(rig.app.Control)
	rec := newReplayRecorder()
	cp, d2, d3 := rec.cp(), rec.delta(), rec.delta()
	for _, c := range []model.ReplayChunk{cp, d2, d3} {
		if _, err := rig.admit(rig.replayBatch(c)); err != nil {
			t.Fatalf("chunk %d: %v", c.Sequence, err)
		}
	}
	const continuous = "checkpoint1 delta2 delta3"
	if rig.storedRows(rec.replay) != 3 || rig.reads(rec.replay) != continuous {
		t.Fatal("fixture invalid")
	}
	group, pin := rig.indexOf(rec.replay)
	appended := appends.appends.Load()

	foreign := cp
	foreign.Session = model.NewID()
	foreignDelta := d2
	foreignDelta.Session = foreign.Session
	for name, c := range map[string]model.ReplayChunk{
		"a different chunk at the recorded checkpoint, same session": forged(cp),
		"the same checkpoint under a foreign session":                foreign,
		"a delta under a foreign session":                            foreignDelta,
	} {
		_, err := rig.admit(rig.replayBatch(c))
		if codeOf(err) != model.Conflict {
			t.Fatalf("%s: %v, want a typed conflict", name, err)
		}
		if appends.appends.Load() != appended {
			t.Fatalf("%s reached the durable appender", name)
		}
		if rig.storedRows(rec.replay) != 3 {
			t.Fatalf("%s was stored", name)
		}
		if g, p := rig.indexOf(rec.replay); g.Seq != group.Seq || len(g.Checkpoints) != 1 || g.Checkpoints[0] != group.Checkpoints[0] || p != pin {
			t.Fatalf("%s changed the index", name)
		}
		if got := rig.reads(rec.replay); got != continuous {
			t.Fatalf("%s: the reader sees %q", name, got)
		}
	}
	// A batch that forges inside itself never reaches storage either.
	if _, err := rig.admit(rig.replayBatch(forged(cp), cp)); codeOf(err) != model.Conflict || appends.appends.Load() != appended {
		t.Fatalf("a batch of two checkpoints at one sequence: %v", err)
	}
	if index.records.Load() != 3 {
		t.Fatalf("the index was written %d times for 3 admitted chunks", index.records.Load())
	}
}

// A forged checkpoint that slips past the pre-check (it raced the real one) is
// stored but can never be pinned: the sender gets the typed Conflict, not a
// receipt, and the reader keeps releasing the real checkpoint. The stored row is
// not an acknowledged row: no acknowledgement was produced for it.
func TestAForgedCheckpointThatRacesPastTheCheckCannotBePinned(t *testing.T) {
	rig := newIndexRig(t)
	_, index := rig.decorate(rig.app.Control)
	rec := newReplayRecorder()
	cp, d2 := rec.cp(), rec.delta()
	for _, c := range []model.ReplayChunk{cp, d2} {
		if _, err := rig.admit(rig.replayBatch(c)); err != nil {
			t.Fatal(err)
		}
	}
	group, pin := rig.indexOf(rec.replay)

	index.skipCheck.Store(true)
	race := rig.replayBatch(forged(cp))
	got, err := rig.admit(race)
	if codeOf(err) != model.Conflict || got.BatchID != (model.ID{}) {
		t.Fatalf("the raced forgery was acknowledged or mistyped: %+v %v", got, err)
	}
	if rig.storedRows(rec.replay) != 3 {
		t.Fatal("fixture invalid: the raced forgery must have reached storage")
	}
	if g, p := rig.indexOf(rec.replay); g.Seq != group.Seq || g.Checkpoints[0] != group.Checkpoints[0] || p != pin {
		t.Fatal("the raced forgery moved the index")
	}
	if got := rig.reads(rec.replay); got != "checkpoint1 delta2" {
		t.Fatalf("the forged duplicate changed what the reader releases: %q", got)
	}

	// Its retry meets the real pre-check and is refused before any further append.
	index.skipCheck.Store(false)
	if _, err = rig.admit(race); codeOf(err) != model.Conflict {
		t.Fatalf("the retry of the raced forgery: %v", err)
	}
	if rig.storedRows(rec.replay) != 3 {
		t.Fatal("the retry stored the forgery again")
	}
}

// A batch with no replay record never touches the index; a chunk the closed-format
// gate refuses is neither recorded nor charged.
func TestReplayIndexIsNotReadForBatchesWithoutReplayRecordsAndNotWrittenForRefusedChunks(t *testing.T) {
	rig := newIndexRig(t)
	appends, index := rig.decorate(rig.app.Control)
	if _, err := rig.admit(rig.metricBatch("replay_index_untouched")); err != nil {
		t.Fatal(err)
	}
	if appends.appends.Load() != 1 || index.checks.Load() != 0 || index.records.Load() != 0 {
		t.Fatalf("a batch without a replay record: %d appends, %d index reads, %d index writes", appends.appends.Load(), index.checks.Load(), index.records.Load())
	}

	charged, reservations := rig.quota()
	revision := rig.revision()
	bad := newReplayRecorder().cp()
	bad.Previous, bad.Checkpoint = model.Hash{1}, model.Hash{1}
	if _, err := rig.admit(rig.replayBatch(bad)); codeOf(err) != model.Invalid {
		t.Fatalf("a first chunk that names a previous hash: %v", err)
	}
	if appends.appends.Load() != 1 || index.checks.Load() != 0 || index.records.Load() != 0 {
		t.Fatalf("a refused chunk reached the appender or the index: %d appends %d reads %d writes", appends.appends.Load(), index.checks.Load(), index.records.Load())
	}
	if bytes, n := rig.quota(); bytes != charged || n != reservations || rig.revision() != revision {
		t.Fatal("a chunk refused by the gate was charged or wrote control state")
	}
	if g, _ := rig.indexOf(bad.Replay); g != nil {
		t.Fatal("a refused chunk was indexed")
	}

	good := newReplayRecorder().cp()
	if _, err := rig.admit(rig.replayBatch(good)); err != nil {
		t.Fatal(err)
	}
	if index.checks.Load() != 1 || index.records.Load() != 1 {
		t.Fatalf("an admitted checkpoint: %d index reads and %d writes, want one each", index.checks.Load(), index.records.Load())
	}
}

// A sender that lost the acknowledgement between the append and the index step asks for the receipt
// instead of resending: the lookup that answers pins the checkpoint it answers for.
func TestReceiptLookupPinsTheCheckpointItAnswersFor(t *testing.T) {
	rig := newIndexRig(t)
	store := &flakyStore{ReferenceStore: rig.app.Control}
	store.down.Store(true)
	before, _ := rig.decorate(store)
	rec := newReplayRecorder()
	cp := rec.cp()
	batch := rig.replayBatch(cp)
	cred, err := rig.app.Auth.AuthenticateSource(rig.ctx, rig.issued, "", false)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := rig.svc().ResolveSource(rig.ctx, cred, batch)
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := policy.Normalize(grant, batch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rig.admit(batch); codeOf(err) != model.Unavailable || before.appends.Load() != 1 {
		t.Fatalf("fixture invalid: the batch must be durable and unacknowledged: %v", err)
	}
	if group, _ := rig.indexOf(rec.replay); group != nil {
		t.Fatal("fixture invalid: the checkpoint is already indexed")
	}

	// The index is unreachable: the lookup does not answer without pinning.
	if _, err = rig.lookup(batch, normalized.Hash); codeOf(err) != model.Unavailable {
		t.Fatalf("a lookup answered although its checkpoint could not be pinned: %v", err)
	}
	store.down.Store(false)
	receipt, err := rig.lookup(batch, normalized.Hash)
	if err != nil || !receipt.Historical || receipt.BatchID != batch.ID {
		t.Fatalf("lookup: %+v %v", receipt, err)
	}
	group, pin := rig.indexOf(rec.replay)
	if group == nil || len(group.Checkpoints) != 1 || group.Checkpoints[0].Sequence != 1 {
		t.Fatalf("the lookup left the checkpoint unpinned: %+v", group)
	}
	if want, _ := replays.ChunkHash(cp); group.Checkpoints[0].Hash != want {
		t.Fatal("the pinned checkpoint is not the stored chunk")
	}
	var deadline model.UnixNano
	for _, d := range receipt.SignalDeadlines {
		if d.Kind == model.Replay {
			deadline = d.RetainUntil
		}
	}
	if deadline == 0 || pin.RetainUntil != deadline {
		t.Fatalf("group deadline %d, receipt replay deadline %d", pin.RetainUntil, deadline)
	}
	if before.appends.Load() != 1 || rig.storedRows(rec.replay) != 1 {
		t.Fatal("the lookup appended")
	}
	// A repeated lookup writes nothing more.
	revision := rig.revision()
	if _, err = rig.lookup(batch, normalized.Hash); err != nil {
		t.Fatal(err)
	}
	if rig.revision() != revision {
		t.Fatal("a repeated lookup wrote control state")
	}
}
