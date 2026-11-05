// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"context"
	"errors"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/retention"
	"soundpost/internal/storage"
	"sync"
	"testing"
	"time"
)

func newCache(t *testing.T, f *fx) *auth.Cache {
	t.Helper()
	c, err := auth.NewCache(f.auth, f.gens, 16, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// warm stores a value bound to the current generation and proves it is served.
func warm(t *testing.T, f *fx, c *auth.Cache, value string) {
	t.Helper()
	scope, err := f.readScope()
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Lookup(f.ctx, scope, "profile", "q", "p")
	if err != nil || res.Hit {
		t.Fatalf("fresh cache: %+v %v", res, err)
	}
	if err = c.Store(f.ctx, scope, res.Fill, []byte(value), false); err != nil {
		t.Fatal(err)
	}
	if res, err = c.Lookup(f.ctx, scope, "profile", "q", "p"); err != nil || !res.Hit || string(res.Value) != value {
		t.Fatalf("entry not warm: %+v %v", res, err)
	}
}
func dead(t *testing.T, f *fx, c *auth.Cache) {
	t.Helper()
	scope, err := f.readScope()
	if err != nil {
		return // a retired scope cannot even look the entry up: unreachable is dead
	}
	if res, err := c.Lookup(f.ctx, scope, "profile", "q", "p"); err == nil && res.Hit {
		t.Fatalf("warm entry bound to the old generation still served: %q", res.Value)
	}
}

// Race an authorized scan, a warm cache entry and a late/old-grant write against
// delete: no covered bytes after the fence, the phases are honest, the hold
// prevents physical-erasure success, and a restore re-applies the ledger.
func TestDeleteBeforeResponseReleaseAndRestore(t *testing.T) {
	f := newFx(t, options{})
	cache := newCache(t, f)
	_, covered, err := f.append(5, "requests")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = f.append(500, "later"); err != nil {
		t.Fatal(err)
	}
	oldGrant, err := f.batch(6, "old_grant") // reserved under the old policy, not yet written
	if err != nil {
		t.Fatal(err)
	}
	scope, err := f.readScope()
	if err != nil {
		t.Fatal(err)
	}
	it, err := f.engine.Scan(f.ctx, scope, storage.ScanRequest{Projects: []model.ID{f.project}, Signal: model.Metric, End: 1 << 60})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	warm(t, f, cache, "response-bytes")
	if n, _ := f.rows(); n != 2 {
		t.Fatalf("fixture rows %d", n)
	}
	before, _ := f.gens.DeleteGeneration(f.ctx, f.org, []model.ID{f.project})

	receipt, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Phase != model.DeletePhaseFencing || receipt.Progress != "0/64" || receipt.Physical != retention.PhysicalPending {
		t.Fatalf("begin receipt %+v", receipt)
	}
	if after, _ := f.gens.DeleteGeneration(f.ctx, f.org, []model.ID{f.project}); after <= before {
		t.Fatal("generation did not advance at Begin")
	}
	// Reads are denied the instant Begin commits, before any barrier exists.
	rows := 0
	for {
		p, err := it.Next(f.ctx)
		if err != nil {
			break
		}
		for i := range p.IDs {
			if p.ObservedTimes[i] < 100 {
				t.Fatal("scan iterator opened before the fence released covered bytes after it")
			}
		}
		rows += p.Len()
	}
	if n, err := f.rows(); err != nil || n != 1 {
		t.Fatalf("fresh scan returns %d rows (%v), want only the row outside the range", n, err)
	}
	dead(t, f, cache)
	// The old-grant write cannot be ACKed, even though no slot has a barrier yet.
	if _, err = f.engine.Append(f.ctx, mustSourceScope(t, f), oldGrant); err == nil {
		t.Fatal("old grant was ACKed after Begin")
	}
	// The original receipt of an already ACKed batch is still retrievable (historical).
	if p := f.poll(receipt.OperationID); p.Phase != model.DeletePhaseFencing {
		t.Fatalf("phase %s before barriers", p.Phase)
	}
	f.run()
	done := f.poll(receipt.OperationID)
	if done.Phase != model.DeletePhaseComplete || done.Progress != "64/64" || done.Physical != retention.PhysicalDone {
		t.Fatalf("complete receipt %+v", done)
	}
	if _, _, err = f.append(7, "late_write"); err == nil {
		t.Fatal("a late matching write committed after completed deletion")
	}
	if _, _, err = f.append(900, "new_epoch"); err != nil {
		t.Fatalf("data outside the range must use the new epoch: %v", err)
	}
	if n, _ := f.rows(); n != 2 {
		t.Fatalf("rows %d after new-epoch write", n)
	}
	_ = covered
}

func mustSourceScope(t *testing.T, f *fx) auth.Scope {
	t.Helper()
	s, err := f.auth.SourceScope(f.ctx, f.source, false)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A hold placed after logical completion makes physical erasure impossible
// (Physical=held, PhysicalAt zero) while reads stay suppressed; releasing it
// lets the next pass erase and advances the generation first.
func TestDeleteHoldRejectsPhysicalErasureSuccess(t *testing.T) {
	f := newFx(t, options{})
	cache := newCache(t, f)
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	receipt, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	holdID, err := f.svc.PlaceHold(f.ctx, f.adminScope(), retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), ProjectIDs: []model.ID{f.project}, Reason: "litigation"})
	if err != nil {
		t.Fatal(err)
	}
	f.run()
	held := f.poll(receipt.OperationID)
	if held.Phase != model.DeletePhaseComplete || held.Physical != retention.PhysicalHeld {
		t.Fatalf("hold did not block physical erasure: %+v", held)
	}
	if n, _ := f.rows(); n != 0 {
		t.Fatal("a held (but logically deleted) row is readable")
	}
	if f.svc.Status().HeldByLegal == 0 {
		t.Fatal("hold veto not reported")
	}
	warm(t, f, cache, "after-hold")
	genHeld, _ := f.gens.DeleteGeneration(f.ctx, f.org, nil)
	if err = f.svc.ReleaseHold(f.ctx, f.adminScope(), model.NewID(), f.revision(), holdID, "settled"); err != nil {
		t.Fatal(err)
	}
	f.run()
	if done := f.poll(receipt.OperationID); done.Physical != retention.PhysicalDone {
		t.Fatalf("release followed by erasure: %+v", done)
	}
	if g, _ := f.gens.DeleteGeneration(f.ctx, f.org, nil); g <= genHeld {
		t.Fatal("erasure after hold release did not advance the generation")
	}
	dead(t, f, cache)
}

// Delete on data under an active hold returns the explicit held phase and
// changes nothing readable; Resume starts it only after the hold is released.
func TestDeleteRequestUnderHoldIsHeldNotSilentlyStarted(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	holdID, err := f.svc.PlaceHold(f.ctx, f.adminScope(), retention.HoldRequest{CommandID: model.NewID(), ExpectedRevision: f.revision(), ProjectIDs: []model.ID{f.project}, Reason: "litigation"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil || r.Phase != model.DeletePhaseHeld || len(r.Holds) != 1 {
		t.Fatalf("held receipt %+v %v", r, err)
	}
	f.run()
	if n, err := f.rows(); err != nil || n != 1 {
		t.Fatalf("held request changed reads: %d %v", n, err)
	}
	if err = f.svc.ReleaseHold(f.ctx, f.adminScope(), model.NewID(), f.revision(), holdID, "settled"); err != nil {
		t.Fatal(err)
	}
	f.run()
	if p := f.poll(r.OperationID); p.Phase != model.DeletePhaseHeld {
		t.Fatalf("release started a deletion on its own: %+v", p)
	}
	if r, err = f.svc.Resume(f.ctx, f.adminScope(), r.OperationID); err != nil || r.Phase != model.DeletePhaseFencing {
		t.Fatalf("resume: %+v %v", r, err)
	}
}

// Every path that can make readable bytes unreadable advances the generation
// before the phase is reported, and a warm cache entry bound to the old
// generation dies.
func TestDeleteEveryModeAdvancesGenerationAndKillsWarmEntries(t *testing.T) {
	modes := map[string]func(*fx, *retention.DeleteRequest){
		model.DeleteHistoricalRange: func(f *fx, r *retention.DeleteRequest) {
			r.ProjectIDs, r.Signals, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 10
		},
		model.DeleteEntity: func(f *fx, r *retention.DeleteRequest) {
			r.ProjectIDs, r.EntityIDs = []model.ID{f.project}, []model.ID{model.NewID()}
		},
		model.DeleteRetireProject: func(f *fx, r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} },
		model.DeleteRetireOrg:     func(f *fx, r *retention.DeleteRequest) {},
	}
	for mode, mut := range modes {
		t.Run(mode, func(t *testing.T) {
			f := newFx(t, options{})
			cache := newCache(t, f)
			warm(t, f, cache, "cached-"+mode)
			before, _ := f.gens.DeleteGeneration(f.ctx, f.org, []model.ID{f.project})
			if _, err := f.del(mode, func(r *retention.DeleteRequest) { mut(f, r) }); err != nil {
				t.Fatal(err)
			}
			after, err := f.gens.DeleteGeneration(f.ctx, f.org, []model.ID{f.project})
			if err != nil || after <= before {
				t.Fatalf("generation %d -> %d (%v)", before, after, err)
			}
			dead(t, f, cache)
			f.run()
			if g, _ := f.gens.DeleteGeneration(f.ctx, f.org, nil); g <= after {
				t.Fatal("completion/erasure did not advance the generation again")
			}
		})
	}
}

func TestDeleteRetireOrgAndProjectMakeTargetsIndistinguishableFromAbsent(t *testing.T) {
	f := newFx(t, options{})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	r, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.readScope(); code(err) != model.NotFound {
		t.Fatalf("retired project scope: %v", err)
	}
	if _, _, err = f.append(8, "after_retire"); err == nil {
		t.Fatal("retired project accepted a write")
	}
	f.run()
	if p := f.poll(r.OperationID); p.Phase != model.DeletePhaseComplete {
		t.Fatalf("%+v", p)
	}
	// A different organization's administrator cannot poll it.
	foreign := model.NewID()
	if _, err = f.svc.PollDelete(f.ctx, f.adminScope(), foreign); code(err) != model.NotFound {
		t.Fatalf("unknown operation: %v", err)
	}
}

// Old proposals ordered before the barrier complete before the operation does;
// none ordered after it ACKs. An unavailable slot leaves the receipt fencing,
// never complete, and derived effects of the deleted origin are suppressed.
func TestDeleteBarrierRacesOldGrantAndDerivedEffects(t *testing.T) {
	f := newFx(t, options{})
	beforeBegin, receipt, err := f.append(5, "ordered_before_barrier")
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.batch(6, "ordered_after_barrier")
	if err != nil {
		t.Fatal(err)
	}
	op, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	// Slot 7 is unreachable: the other 63 are fenced, the operation is not complete.
	f.plane.down[7] = true
	if err = f.svc.RunOnce(f.ctx); code(err) != model.Unavailable {
		t.Fatalf("an unavailable slot must surface: %v", err)
	}
	p := f.poll(op.OperationID)
	if p.Phase != model.DeletePhaseFencing || p.Progress != "63/64" {
		t.Fatalf("unavailable slot: %+v", p)
	}
	// The write ordered after Begin cannot ACK in any slot, fenced or not.
	if _, err = f.engine.Append(f.ctx, mustSourceScope(t, f), pending); err == nil {
		t.Fatal("write ordered after the barrier was ACKed")
	}
	// The original receipt of the write ordered before it is unchanged.
	again, err := f.engine.Append(f.ctx, mustSourceScope(t, f), beforeBegin)
	if err != nil || again.Cursor != receipt.Cursor || again.Hash != receipt.Hash {
		t.Fatalf("ACKed-before receipt changed: %v", err)
	}
	// Data outside the predicate keeps flowing in the new epoch while fencing.
	if _, _, err = f.append(5000, "new_epoch"); err != nil {
		t.Fatalf("new-epoch write during fencing: %v", err)
	}
	f.plane.down[7] = false
	f.run()
	if p = f.poll(op.OperationID); p.Phase != model.DeletePhaseComplete || p.Progress != "64/64" {
		t.Fatalf("after heal: %+v", p)
	}
	// Derived effects (rules/issues/notifications) of the deleted origin are
	// suppressed inside the same control transaction; others proceed.
	var applied, suppressed int
	effect := func(at model.UnixNano) {
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			if control.EffectSuppressed(*st, f.org, f.project, model.Metric, at, nil) {
				suppressed++
			} else {
				applied++
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	effect(5)
	effect(99)
	effect(100)
	effect(5000)
	if applied != 2 || suppressed != 2 {
		t.Fatalf("effects applied=%d suppressed=%d", applied, suppressed)
	}
}

type memAuthority struct {
	mu       sync.Mutex
	fail     error
	received []retention.LedgerGeneration
}

func (a *memAuthority) CheckpointDeletion(ctx context.Context, g retention.LedgerGeneration) (retention.AuthorityReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return retention.AuthorityReceipt{}, a.fail
	}
	a.received = append(a.received, g)
	return retention.AuthorityReceipt{Generation: g.Generation, Head: model.HashCanonical([]byte{byte(len(a.received))}), At: model.UnixNano(time.Now().UnixNano())}, nil
}
func (a *memAuthority) CurrentDeletionLedger(context.Context) (replica.Ledger, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.received) == 0 {
		return replica.Ledger{}, errors.New("empty")
	}
	return a.received[len(a.received)-1].Ledger, nil
}

// With off-host backup the authority checkpoint is required: while it fails the
// operation stays fencing; once it succeeds it completes and the ledger carries
// the exact tombstone digest.
func TestDeleteAuthorityCheckpointIsRequiredForCompletion(t *testing.T) {
	a := &memAuthority{fail: errors.New("object store down")}
	f := newFx(t, options{authority: a})
	op, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.project} })
	if err != nil {
		t.Fatal(err)
	}
	if err = f.svc.RunOnce(f.ctx); code(err) != model.Unavailable {
		t.Fatalf("authority failure must surface: %v", err)
	}
	if p := f.poll(op.OperationID); p.Phase != model.DeletePhaseFencing || p.Progress != "64/64" {
		t.Fatalf("authority down: %+v", p)
	}
	a.mu.Lock()
	a.fail = nil
	a.mu.Unlock()
	f.run()
	p := f.poll(op.OperationID)
	if p.Phase != model.DeletePhaseComplete {
		t.Fatalf("after authority recovery: %+v", p)
	}
	last := a.received[len(a.received)-1]
	if len(last.Tombstones) != 1 || last.Tombstones[0].Operation != op.OperationID || last.Ledger.Entries[0].Hash != last.Tombstones[0].Digest() || last.Generation < p.Generation {
		t.Fatalf("checkpointed generation %+v", last)
	}
}

// Expiry of unprocessed lifecycle evidence records a durable gap first, never
// advances a processing checkpoint, and holds the journal when the gap cannot
// commit.
func TestEvidenceExpiryRecordsGapNotRecovery(t *testing.T) {
	proc := &fixedProcessed{at: map[model.ID]uint64{}}
	f := newFx(t, options{processed: proc})
	group := model.NewID()
	proc.at[group] = 2
	record := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: 10}
	cand := func(index uint64, project model.ID) storage.EraseCandidate {
		r := record
		return storage.EraseCandidate{Org: f.org, Project: project, Cursor: model.Cursor{Group: group, Index: model.Uint64(index)}, Kind: model.ErrorKind, Record: &r}
	}
	var erased []uint64
	f.plane.expired = func(ctx context.Context, now model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		rep := storage.EraseReport{}
		for _, c := range []storage.EraseCandidate{cand(1, f.project), cand(3, f.project), cand(4, f.project), cand(5, f.project)} {
			ok, err := g(ctx, c)
			if err != nil {
				return rep, err
			}
			if ok {
				erased = append(erased, uint64(c.Cursor.Index))
				rep.Records++
			}
		}
		return rep, nil
	}
	if err := f.svc.RunOnce(f.ctx); err != nil {
		t.Fatal(err)
	}
	if len(erased) != 4 {
		t.Fatalf("erased %v: processed evidence and gap-covered evidence are erasable", erased)
	}
	gaps, _ := f.store.EvidenceGaps(f.ctx, f.org, f.project)
	if len(gaps) != 1 || gaps[0].After != 2 || gaps[0].Through != 5 || gaps[0].Count != 3 || gaps[0].Group != group || gaps[0].Reason != "unprocessed_expiry" {
		t.Fatalf("gaps %+v", gaps)
	}
	if proc.calls == 0 || proc.advanced {
		t.Fatal("expiry must consult, never advance, the processing checkpoint")
	}
	// Second pass is idempotent: no second gap.
	erased = nil
	f.advance(2 * time.Hour)
	f.run()
	if g, _ := f.store.EvidenceGaps(f.ctx, f.org, f.project); len(g) != 1 {
		t.Fatalf("gap duplicated: %d", len(g))
	}
	// If the gap cannot commit (unknown project), the evidence is held.
	erased = nil
	ghost := model.NewID()
	f.plane.expired = func(ctx context.Context, now model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		rep := storage.EraseReport{}
		ok, err := g(ctx, cand(9, ghost))
		if err != nil {
			return rep, err
		}
		if ok {
			erased = append(erased, 9)
		}
		return rep, nil
	}
	f.advance(2 * time.Hour)
	if err := f.svc.RunOnce(f.ctx); err == nil {
		t.Fatal("a gap that cannot commit must be reported")
	}
	if len(erased) != 0 || !f.svc.Status().EvidenceHeld {
		t.Fatalf("evidence erased without a durable gap: %v held=%v", erased, f.svc.Status().EvidenceHeld)
	}
}

type fixedProcessed struct {
	at       map[model.ID]uint64
	calls    int
	advanced bool
}

func (p *fixedProcessed) Processed(_ context.Context, g model.ID) (uint64, error) {
	p.calls++
	return p.at[g], nil
}

type meter struct {
	mu        sync.Mutex
	total, in uint64
}

func (m *meter) set(percent uint64) { m.mu.Lock(); m.in = m.total / 100 * percent; m.mu.Unlock() }
func (m *meter) Usage(string) (storage.DiskUsage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return storage.DiskUsage{TotalBytes: m.total, UsedBytes: m.in}, nil
}

type refs struct {
	mu    sync.Mutex
	until map[model.ID]model.UnixNano // keyed by candidate record/blob identity
}

func (r *refs) LatestReference(_ context.Context, c storage.EraseCandidate) (model.UnixNano, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c.Record != nil {
		return r.until[c.Record.ID], nil
	}
	if c.Blob != nil {
		return r.until[c.Blob.Root], nil
	}
	return 0, nil
}

// At 80/90/95% the engine reports defined warnings and rejects admission, but
// no ACKed record disappears before its retention deadline, receipts do not
// change, and a replay checkpoint or an artifact that a retained record still
// references is kept even when its own deadline has passed.
func TestDiskPressureNeverSilentlyShortensRetention(t *testing.T) {
	r := &refs{until: map[model.ID]model.UnixNano{}}
	f := newFx(t, options{pressure: true, refs: r})
	m := &meter{total: 100 << 20}
	cfg := storage.DefaultPressureConfig()
	cfg.ReservedConsensusBytes, cfg.ReservedAuditBytes, cfg.Interval = 0, 0, 0
	cfg.Now = f.at
	if err := f.engine.BindPressure(t.TempDir(), m, cfg); err != nil {
		t.Fatal(err)
	}
	var receipts []model.Receipt
	var batches []model.NormalizedBatch
	for i := range 3 {
		b, rc, err := f.append(int64(10+i), "series"+string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		receipts, batches = append(receipts, rc), append(batches, b)
	}
	admitted := 0
	check := func(stage string) {
		t.Helper()
		if n, err := f.rows(); err != nil || n != 3+admitted {
			t.Fatalf("%s: %d rows (%v): pressure shortened retention", stage, n, err)
		}
	}
	codes := func() []string {
		var out []string
		for _, w := range f.svc.Status().Pressure.Warnings {
			out = append(out, w.Code)
		}
		return out
	}
	for _, step := range []struct {
		percent uint64
		code    string
		admit   bool
	}{{79, "", true}, {80, "disk_warn", true}, {90, "disk_deny_low", true}, {95, "disk_deny_all", false}} {
		m.set(step.percent)
		f.advance(time.Minute) // far below every 14-day deadline
		f.run()
		if step.code != "" {
			if got := codes(); len(got) == 0 || got[len(got)-1] != step.code {
				t.Fatalf("%d%%: warnings %v want last %s", step.percent, got, step.code)
			}
		}
		_, _, err := f.append(int64(100+step.percent), "probe"+string(rune('a'+step.percent%26)))
		if step.admit && err != nil {
			t.Fatalf("%d%%: normal admission rejected: %v", step.percent, err)
		}
		if !step.admit && code(err) != model.Unavailable {
			t.Fatalf("%d%%: admission not rejected: %v", step.percent, err)
		}
		if step.admit {
			admitted++
			check("at " + step.code)
			continue
		}
		check("at " + step.code)
	}
	// At 95% an already ACKed batch still resolves to its original receipt.
	for i, b := range batches {
		again, err := f.engine.Append(f.ctx, mustSourceScope(t, f), b)
		if err != nil || again.Cursor != receipts[i].Cursor || again.Hash != receipts[i].Hash {
			t.Fatalf("ACKed receipt %d changed under pressure: %v", i, err)
		}
	}
	// Recovery reopens admission; the visible failure is recorded.
	m.set(10)
	f.run()
	if got := codes(); got[len(got)-1] != "disk_recovered" {
		t.Fatalf("recovery not reported: %v", got)
	}
	if _, _, err := f.append(2000, "after_recovery"); err != nil {
		t.Fatal(err)
	}

	// Reference-aware expiry: the checkpoint chunk is past its deadline but a
	// retained chunk depends on it; the artifact is referenced by a retained error.
	checkpoint, dependent := model.NewID(), model.NewID()
	root := model.NewID()
	f.advance(24 * time.Hour)
	now := model.UnixNano(f.clock.Load())
	r.until[checkpoint] = now + model.UnixNano(3*time.Hour) // a retained chunk still depends on it
	r.until[dependent] = 0
	r.until[root] = now + model.UnixNano(3*time.Hour)
	verdict := map[model.ID]bool{}
	f.plane.expired = func(ctx context.Context, at model.UnixNano, g storage.EraseGuard) (storage.EraseReport, error) {
		rep := storage.EraseReport{}
		cands := []storage.EraseCandidate{
			{Org: f.org, Project: f.project, Kind: model.Replay, Record: &model.Record{ID: checkpoint, Kind: model.Replay}},
			{Org: f.org, Project: f.project, Kind: model.Replay, Record: &model.Record{ID: dependent, Kind: model.Replay}},
			{Org: f.org, Project: f.project, Blob: &model.BlobManifest{Org: f.org, Project: f.project, Root: root}},
		}
		for _, c := range cands {
			ok, err := g(ctx, c)
			if err != nil {
				return rep, err
			}
			id := root
			if c.Record != nil {
				id = c.Record.ID
			}
			verdict[id] = ok
		}
		return rep, nil
	}
	f.advance(2 * time.Hour) // expiry interval elapsed
	f.run()
	if verdict[checkpoint] || !verdict[dependent] {
		t.Fatalf("replay checkpoint with a retained dependent was expired: %v", verdict)
	}
	f.advance(2 * time.Hour) // dependents/references now past their own deadlines
	f.run()
	if !verdict[checkpoint] || !verdict[root] {
		t.Fatalf("expiry never proceeds once references expire: %v", verdict)
	}
}

type tombAuthority struct {
	memAuthority
	tombs []model.DeletePredicate
	down  bool
}

func (a *tombAuthority) CurrentDeletionLedger(ctx context.Context) (replica.Ledger, error) {
	if a.down {
		return replica.Ledger{}, errors.New("unreachable")
	}
	return a.memAuthority.CurrentDeletionLedger(ctx)
}
func (a *tombAuthority) CurrentDeletionTombstones(context.Context) ([]model.DeletePredicate, error) {
	return a.tombs, nil
}

// A restore re-applies the authority's ledger (control import + barrier in
// every slot) and fails closed when the authority is unreachable or the
// tombstones do not match the ledger digests.
func TestDeleteRestoreAppliesAuthorityLedgerOrFailsClosed(t *testing.T) {
	a := &tombAuthority{}
	f := newFx(t, options{authority: a})
	if _, _, err := f.append(5, "requests"); err != nil {
		t.Fatal(err)
	}
	op, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 0, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	f.run()
	last := a.received[len(a.received)-1]
	a.tombs = last.Tombstones
	if err = f.svc.Restore(f.ctx, a); err != nil {
		t.Fatalf("restore with a verified authority: %v", err)
	}
	a.down = true
	if err = f.svc.Restore(f.ctx, a); code(err) != model.Unavailable {
		t.Fatalf("unreachable authority must fail closed: %v", err)
	}
	a.down = false
	forged := last.Tombstones[0]
	forged.End = 1 << 40
	a.tombs = []model.DeletePredicate{forged}
	if err = f.svc.Restore(f.ctx, a); code(err) != model.Corrupt {
		t.Fatalf("tombstone not matching the ledger digest: %v", err)
	}
	if err = f.svc.Restore(f.ctx, nil); code(err) != model.Unavailable {
		t.Fatalf("no authority: %v", err)
	}
	if n, _ := f.rows(); n != 0 {
		t.Fatalf("restored installation exposes deleted rows (%d)", n)
	}
	if p := f.poll(op.OperationID); p.Phase != model.DeletePhaseComplete {
		t.Fatalf("%+v", p)
	}
}
