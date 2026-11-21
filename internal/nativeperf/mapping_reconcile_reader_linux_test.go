//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"debug/elf"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Reconciliation against a real MappingReader of a real (idle) child process (l4w33 mutation battery A): what the
// helper publishes after a read, and what it does when the read is refused, interrupted or finds the target gone.

type reconcileRig struct {
	source *ProfileSource
	rec    *reconciler
	table  MappingTable
	cmd    *exec.Cmd
}

// idleTarget starts `sleep` and authorizes it the way the capture authorizes a workload (its cgroup, its GNU build ID).
func idleTarget(t *testing.T) (*exec.Cmd, Target, AuthorizedTargets) {
	t.Helper()
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep(1)")
	}
	if path, err = filepath.EvalSymlinks(path); err != nil {
		t.Skip(err)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Skip(err)
	}
	hasBuildID := f.Section(".note.gnu.build-id") != nil
	f.Close()
	if !hasBuildID {
		t.Skip("sleep(1) has no GNU build ID")
	}
	cmd := exec.Command(path, "600")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	exe := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe"
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if got, err := os.Readlink(exe); err == nil && got == path {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the child never executed sleep")
		}
	}
	time.Sleep(200 * time.Millisecond) // the dynamic loader is still mapping libraries right after exec
	target := vaReuseTarget(t, cmd.Process.Pid, path)
	return cmd, target, AuthorizedTargets{targets: []Target{target}, mode: ModeCPU}
}

// reconcileFixture takes the first read of an idle target that the reconciler predicts from.
func reconcileFixture(t *testing.T, interval time.Duration) *reconcileRig {
	t.Helper()
	cmd, target, authorized := idleTarget(t)
	policy := DefaultSymbolPolicy(1)
	policy.MinReadInterval = interval
	reader, err := NewMappingReader(authorized, target, 1, policy)
	if err != nil {
		t.Skipf("the target cannot be read here: %v", err)
	}
	t.Cleanup(func() { reader.Close() })
	table, err := reader.Read(context.Background())
	if err != nil || len(table.entries) == 0 {
		t.Fatalf("first read: %d entries, %v", len(table.entries), err)
	}
	at, err := schedulerNow()
	if err != nil {
		t.Fatal(err)
	}
	rec := &reconciler{reader: reader, process: table.process, model: table.entries, lastAt: at}
	return &reconcileRig{
		source: &ProfileSource{source: plainSource{}, domain: reader.domain, readers: []*MappingReader{reader}, recon: []*reconciler{rec}},
		rec:    rec, table: table, cmd: cmd,
	}
}

// group splits the events of one reconciliation into its rows and its closing confirmation.
func group(t *testing.T, events []SanitizedEvent) (rows []MappingUpdate, confirmation SanitizedEvent) {
	t.Helper()
	if len(events) == 0 {
		t.Fatal("no events")
	}
	last := events[len(events)-1]
	if last.Kind != EventMapping || last.Mapping == nil || !last.Mapping.Snapshot || !last.Mapping.Confirm {
		t.Fatalf("the group is not closed by a confirmation: %+v", last)
	}
	for _, e := range events[:len(events)-1] {
		if e.Kind != EventMapping || e.Mapping == nil || !e.Mapping.Snapshot || e.Mapping.Confirm || e.Time != last.Time || e.Mapping.Since != last.Mapping.Since {
			t.Fatalf("a row that does not belong to the group: %+v (group at %d since %d)", e, last.Time, last.Mapping.Since)
		}
		rows = append(rows, *e.Mapping)
	}
	if last.Mapping.Since >= last.Time {
		t.Fatalf("a read began (%d) no earlier than it ended (%d)", last.Mapping.Since, last.Time)
	}
	return rows, last
}

// A read that matches the prediction is just a confirmation; the prediction becomes the read.
func TestReconcileOfAnUnchangedProcessIsOnlyAConfirmation(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	before := rig.rec.lastAt
	events, err := rig.source.reconcile(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	rows, confirmation := group(t, events)
	if len(rows) != 0 {
		t.Fatalf("an idle process produced rows: %+v", rows)
	}
	if confirmation.Domain != rig.source.domain || confirmation.Mapping.Process != rig.rec.process {
		t.Fatalf("%+v", confirmation)
	}
	if rig.rec.lastAt != confirmation.Time || rig.rec.lastAt <= before {
		t.Fatalf("the reconciler is at %d after a group at %d (it was at %d)", rig.rec.lastAt, confirmation.Time, before)
	}
	if len(rig.rec.pending) != 0 || len(rig.rec.model) != len(rig.table.entries) {
		t.Fatalf("pending %d, model %d entries (read %d)", len(rig.rec.pending), len(rig.rec.model), len(rig.table.entries))
	}
	if rig.source.nextReconcile.IsZero() {
		t.Fatal("the next reconciliation was not scheduled")
	}
}

// The prediction of a read is the previous read plus the announcements between the two reads, in time order; older
// announcements are already part of the previous read and later ones belong to the next prediction.
func TestReconcilePredictsFromTheAnnouncementsBetweenTwoReads(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	owner := rig.table.entries[0]
	same := owner.reason
	other := FrameJITMissing
	if same == other {
		other = FrameUnapproved
	}
	announce := func(at model.MonoNano, start, end uint64, reason FrameReason) timedMapping {
		return timedMapping{at: at, m: MappingUpdate{Process: rig.rec.process, Start: model.Uint64(start), End: model.Uint64(end), Reason: reason}}
	}
	last := rig.rec.lastAt
	const future = model.MonoNano(1 << 62)
	rig.rec.pending = []timedMapping{
		announce(future, 0x5000, 0x6000, FrameJITMissing),
		announce(future, 0x5000, 0x6000, FrameUnapproved), // same instant as the one before: stream order decides
		announce(last-1, 0x1000, 0x2000, FrameJITMissing), // older than the previous read: part of it already
		announce(last+2, owner.start, owner.end, other),   // listed before the earlier one over the same range
		announce(last+1, owner.start, owner.end, same),
		announce(last+3, 0x3000, 0x4000, FrameJITMissing), // predicted, but not there in the read
	}
	time.Sleep(200 * time.Millisecond)
	events, err := rig.source.reconcile(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	rows, confirmation := group(t, events)
	if len(rows) != 2 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	wantReason := same
	if wantReason == "" {
		wantReason = FrameUnapproved
	}
	if rows[0].Start != 0x3000 || rows[0].End != 0x4000 || rows[0].Reason != FrameUnresolved {
		t.Fatalf("the announced range that is no longer mapped: %+v", rows[0])
	}
	if uint64(rows[1].Start) != owner.start || uint64(rows[1].End) != owner.end || rows[1].Reason != wantReason {
		t.Fatalf("the range the later announcement changed (to %q) and the read still holds as %q: %+v", other, wantReason, rows[1])
	}
	if rig.rec.lastAt != confirmation.Time {
		t.Fatalf("lastAt %d, group at %d", rig.rec.lastAt, confirmation.Time)
	}
	if len(rig.rec.pending) != 2 || rig.rec.pending[0].m.Reason != FrameJITMissing || rig.rec.pending[1].m.Reason != FrameUnapproved || rig.rec.pending[0].at != future {
		t.Fatalf("what is kept for the next read: %+v", rig.rec.pending)
	}
	if e, ok := ownerAt(rig.rec.model, 0x5000); !ok || e.reason != FrameUnapproved {
		t.Fatalf("the next prediction holds %+v (%v) over the later announcement's range", e, ok)
	}
	if e, ok := ownerAt(rig.rec.model, 0x3000); ok {
		t.Fatalf("the next prediction holds the range of an announcement older than the read: %+v", e)
	}
	if e, ok := ownerAt(rig.rec.model, owner.start); !ok || e.reason != owner.reason {
		t.Fatalf("the next prediction is not the read: %+v %v", e, ok)
	}
}

// A read the reader refuses for its rate limit is skipped without a group and without an error: the capture goes on
// and the next reconciliation retries.
func TestReconcileSkipsAReadTheReaderRefusesForItsRateLimit(t *testing.T) {
	rig := reconcileFixture(t, 5*time.Second)
	before := rig.rec.lastAt
	events, err := rig.source.reconcile(context.Background(), false)
	if err != nil || len(events) != 0 {
		t.Fatalf("%+v %v", events, err)
	}
	if rig.rec.lastAt != before {
		t.Fatal("a group that was never read moved the reconciler")
	}
	if rig.source.nextReconcile.IsZero() {
		t.Fatal("the next reconciliation was not scheduled")
	}
}

// The final reconciliation of a stopped capture waits out the reader's minimum interval instead of giving up.
func TestReconcileFinalWaitsOutTheReadIntervalAndThenReads(t *testing.T) {
	const interval = 400 * time.Millisecond
	rig := reconcileFixture(t, interval)
	start := time.Now()
	events, err := rig.source.reconcile(context.Background(), true)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if _, confirmation := group(t, events); confirmation.Time == 0 {
		t.Fatal("no confirmation")
	}
	if elapsed < interval-50*time.Millisecond || elapsed > interval+250*time.Millisecond {
		t.Fatalf("the final read ran after %v, want about one interval (%v)", elapsed, interval)
	}
}

// A context that ends while the final reconciliation waits is that context's error.
func TestReconcileFinalStopsWaitingWhenTheContextEnds(t *testing.T) {
	rig := reconcileFixture(t, 3*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	events, err := rig.source.reconcile(ctx, true)
	if !errors.Is(err, context.DeadlineExceeded) || events != nil {
		t.Fatalf("%+v %v", events, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the wait was not interrupted")
	}
}

// A context that has ended is the answer of a reconciliation, never an empty success.
func TestReconcileOfAnEndedContextIsThatContextsError(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	events, err := rig.source.reconcile(ctx, false)
	if !errors.Is(err, context.Canceled) || events != nil {
		t.Fatalf("%+v %v", events, err)
	}
}

// A target that is gone fails the capture with the identity error and retires the readers.
func TestReconcileOfAGoneTargetFailsTheCapture(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	rig.cmd.Process.Kill()
	rig.cmd.Wait()
	time.Sleep(200 * time.Millisecond)
	events, err := rig.source.reconcile(context.Background(), false)
	if !errors.Is(err, ErrTargetIdentity) || events != nil {
		t.Fatalf("%+v %v", events, err)
	}
	if err := rig.rec.reader.Guard(); err == nil {
		t.Fatal("the reader of a failed capture is still valid")
	}
}

// enrich queues, ahead of the item it was given: every announcement the sweep found, then the group that is due, then
// the item. A final proof is preceded by the last group exactly when the acquisition was stopped; a proof that is not
// final and no sample is left alone.
func TestEnrichQueuesAnnouncementsThenTheDueGroupAheadOfTheItem(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	announcement := mapEvent(0, 5, 0x1000, 0x2000, 0, "", FrameJITMissing)
	announcement.Mapping.Process = rig.rec.process
	announcement.Domain = rig.source.domain
	rig.source.source = &sweepingSource{swept: [][]SanitizedEvent{{announcement}, nil}, full: []bool{false, false}}
	sample := sidebandSample(1 << 40)
	rig.source.pending = []AcquisitionItem{sample}
	rig.source.nextReconcile = time.Time{}
	if err := rig.source.enrich(context.Background()); err != nil {
		t.Fatal(err)
	}
	queued := rig.source.pending
	if len(queued) < 3 || queued[len(queued)-1].Event != sample.Event {
		t.Fatalf("%d items queued, the sample must be last", len(queued))
	}
	if first := queued[0].Event; first == nil || first.Kind != EventMapping || first.Mapping.Snapshot || first.Time != 5 {
		t.Fatalf("the announcement is not first: %+v", queued[0].Event)
	}
	if last := queued[len(queued)-2].Event; last == nil || last.Mapping == nil || !last.Mapping.Confirm {
		t.Fatalf("the group does not close right before the sample: %+v", queued[len(queued)-2].Event)
	}
	for _, item := range queued[1 : len(queued)-1] {
		if item.Event == nil || item.Event.Mapping == nil || !item.Event.Mapping.Snapshot {
			t.Fatalf("between the announcement and the sample only the group: %+v", item.Event)
		}
	}
	// the announcement was older than the previous read: it is part of that read already, not of the next prediction
	if len(rig.rec.pending) != 0 {
		t.Fatalf("the prediction kept an announcement older than the read: %+v", rig.rec.pending)
	}

	// not due: the announcements still go first, no group
	time.Sleep(200 * time.Millisecond)
	rig.source.source = &sweepingSource{swept: [][]SanitizedEvent{{announcement}}, full: []bool{false}}
	rig.source.pending = []AcquisitionItem{sample}
	rig.source.nextReconcile = time.Now().Add(time.Hour)
	if err := rig.source.enrich(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rig.source.pending; len(got) != 2 || got[0].Event.Kind != EventMapping || got[1].Event != sample.Event {
		t.Fatalf("a group that is not due was queued: %d items", len(got))
	}
}

func TestEnrichReconcilesBeforeAFinalProofOnlyAfterTheAcquisitionStopped(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	proof := AcquisitionItem{Proof: &AcquisitionProof{Domain: rig.source.domain, CPUs: []uint32{0}, Through: 1 << 40, Final: true}}
	progress := AcquisitionItem{Proof: &AcquisitionProof{Domain: rig.source.domain, CPUs: []uint32{0}, Through: 1 << 40, Progress: true}}
	far := time.Now().Add(time.Hour)

	// stopped acquisition: the final proof is preceded by the last group, whatever the schedule says
	rig.source.nextReconcile = far
	rig.source.finalDue = true
	rig.source.pending = []AcquisitionItem{proof}
	if err := rig.source.enrich(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := rig.source.pending; len(got) < 2 || got[len(got)-1].Proof != proof.Proof || got[len(got)-2].Event == nil || !got[len(got)-2].Event.Mapping.Confirm {
		t.Fatalf("the final proof is not preceded by the last group: %d items", len(got))
	}

	// not stopped (a final proof of something else), or a proof that is not final: nothing is queued
	time.Sleep(200 * time.Millisecond)
	rig.source.finalDue = false
	rig.source.pending = []AcquisitionItem{proof}
	if err := rig.source.enrich(context.Background()); err != nil || len(rig.source.pending) != 1 {
		t.Fatalf("%d items, %v: a final proof without a stop was reconciled", len(rig.source.pending), err)
	}
	rig.source.finalDue = true
	rig.source.pending = []AcquisitionItem{progress}
	if err := rig.source.enrich(context.Background()); err != nil || len(rig.source.pending) != 1 {
		t.Fatalf("%d items, %v: a progress proof was reconciled", len(rig.source.pending), err)
	}
}

// A real acquisition publishes its first read as the first group of its sequence, predicts from it, and ends with the
// context it was started with (never with a bare closed error).
func TestNewProfileAcquisitionOfARealTargetPublishesItsFirstReadAndEndsWithItsOwnerContext(t *testing.T) {
	_, _, authorized := idleTarget(t)
	cfg := DefaultConfig(1)
	lease, err := NewResourceBudget().Reserve(authorized, cfg, Topology{CPUs: 1, FDLimit: 1024, PageBytes: uint64(os.Getpagesize())}, MemoryUsage{})
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source, err := NewProfileAcquisition(ctx, authorized, cfg, lease, DefaultSymbolPolicy(1))
	var capability *CapabilityError
	if errors.As(err, &capability) {
		t.Skipf("native CPU capture is not available here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var events []SanitizedEvent
	for {
		step, stop := context.WithTimeout(ctx, 5*time.Second)
		item, err := source.NextItem(step)
		stop()
		if err != nil || item.Event == nil {
			t.Fatalf("%+v %v", item, err)
		}
		events = append(events, *item.Event)
		if item.Event.Mapping != nil && item.Event.Mapping.Confirm {
			break
		}
	}
	rows, confirmation := group(t, events)
	if len(rows) == 0 {
		t.Fatal("the first read has no rows")
	}
	for i, e := range events {
		if e.Sequence != model.Uint64(i+1) || e.Domain != source.domain {
			t.Fatalf("event %d: sequence %d, domain %+v", i, e.Sequence, e.Domain)
		}
	}
	recon := source.recon[0]
	if recon.lastAt != confirmation.Time || len(recon.model) < len(rows) {
		t.Fatalf("the first prediction: lastAt %d (group at %d), %d entries for %d rows", recon.lastAt, confirmation.Time, len(recon.model), len(rows))
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		step, stop := context.WithTimeout(context.Background(), 300*time.Millisecond)
		_, err := source.NextItem(step)
		stop()
		if errors.Is(err, context.Canceled) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the acquisition did not end with its owner's context: %v", err)
		}
	}
}

type failingSource struct{ err error }

func (f failingSource) Next(context.Context) (SanitizedEvent, error) { return SanitizedEvent{}, f.err }
func (failingSource) Close() error                                   { return nil }

// A source that fails on its own retires the readers (nothing it published afterwards is trusted); the normal end of a
// source and a caller that gave up do not.
func TestFetchRetiresTheReadersOnlyWhenTheSourceFailsOnItsOwn(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for _, c := range []struct {
		name    string
		ctx     context.Context
		err     error
		retired bool
	}{
		{"the source failed", context.Background(), errors.New("ring unreadable"), true},
		{"the source ended", context.Background(), ErrSourceComplete, false},
		{"the caller gave up", ended, context.Canceled, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			rig := reconcileFixture(t, 150*time.Millisecond)
			rig.source.source = failingSource{err: c.err}
			if _, err := rig.source.fetch(c.ctx); !errors.Is(err, c.err) {
				t.Fatalf("%v, want %v", err, c.err)
			}
			if retired := rig.rec.reader.Guard() != nil; retired != c.retired {
				t.Fatalf("readers retired: %v, want %v", retired, c.retired)
			}
		})
	}
}

// enrich fails with the failure of the sweep and with the failure of the reconciliation, and queues nothing then.
func TestEnrichFailsWithTheFailureOfItsSweepOrItsReconciliation(t *testing.T) {
	rig := reconcileFixture(t, 150*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	sample := sidebandSample(1 << 40)
	want := errors.New("ring overwritten")
	rig.source.source = &sweepingSource{sweepFn: func() error { return want }}
	rig.source.pending = []AcquisitionItem{sample}
	if err := rig.source.enrich(context.Background()); !errors.Is(err, want) || len(rig.source.pending) != 1 {
		t.Fatalf("%v, %d queued", err, len(rig.source.pending))
	}
	if err := rig.rec.reader.Guard(); err == nil {
		t.Fatal("a failed sweep left the readers valid")
	}

	rig = reconcileFixture(t, 150*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	rig.source.pending = []AcquisitionItem{sample}
	rig.source.nextReconcile = time.Time{}
	if err := rig.source.enrich(ended); !errors.Is(err, context.Canceled) || len(rig.source.pending) != 1 {
		t.Fatalf("%v, %d queued", err, len(rig.source.pending))
	}
}
