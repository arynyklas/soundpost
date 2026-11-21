// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// normalizedAs is normalized with a chosen producer and observation time: every batch of one
// producer routes to the same slot, so one slot's history grows past several windows.
func normalizedAs(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, producer model.ID, at model.UnixNano) (auth.Scope, model.NormalizedBatch) {
	t.Helper()
	scope, e := a.SourceScope(context.Background(), c, false)
	if e != nil {
		t.Fatal(e)
	}
	src, e := a.SourceAuthority(context.Background(), c, true)
	if e != nil {
		t.Fatal(e)
	}
	b := model.Batch{Version: 1, Project: d.Project, Source: d.Source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: at, Resource: model.Resource{Service: src.Policy.Resources.Services[0], Environment: src.Policy.Resources.Environments[0], Build: src.Policy.Resources.Builds[0], Instance: src.Policy.Resources.Instances[0]}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{}, SampleKind: "float", Value: ptrBits(0x3ff0000000000000), Type: "counter", Unit: "1"}}}}}
	slot, _ := model.OwnerSlot(d.Org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw := mustJSON(t, b)
	policyBytes := mustJSON(t, src.Policy)
	n := model.NormalizedBatch{Batch: b, Org: d.Org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(policyBytes).String(), AdmissionAt: 10, Deadlines: []model.SignalDeadline{{Kind: model.Metric, RetainUntil: 100}}}
	n.Reservation, e = store.ReserveAdmission(context.Background(), scope, n)
	if e != nil {
		t.Fatal(e)
	}
	return scope, n
}

// windowEnv is a replicated engine whose one producer fills a single slot with consumed batches.
type windowEnv struct {
	t        *testing.T
	store    *control.Store
	service  *auth.Service
	cred     auth.SourceCredential
	desc     model.SourceDescriptor
	e        *Engine
	producer model.ID
	slot     uint16
	next     model.UnixNano
}

func newWindowEnv(t *testing.T) *windowEnv {
	t.Helper()
	store, service, cred, desc := fixture(t)
	e, err := openTestEngine(t, t.TempDir(), service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	return &windowEnv{t: t, store: store, service: service, cred: cred, desc: desc, e: e, producer: model.NewID(), next: 1}
}

// add admits and appends n batches and returns the last one.
func (w *windowEnv) add(n int) (auth.Scope, model.NormalizedBatch) {
	w.t.Helper()
	var scope auth.Scope
	var b model.NormalizedBatch
	for range n {
		scope, b = normalizedAs(w.t, w.store, w.service, w.cred, w.desc, w.producer, w.next)
		w.next++
		w.slot = b.RouteSlot
		if _, err := w.e.Append(context.Background(), scope, b); err != nil {
			w.t.Fatal(err)
		}
	}
	return scope, b
}

func sameFileAt(t *testing.T, a, b string) bool {
	t.Helper()
	ia, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	ib, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(ia, ib)
}

// A cut after more history reads and writes only the windows that changed: the sealed windows of
// the previous snapshot are the very same files, and the commands derived into window records
// stay proportional to what was added, not to the history.
func TestIncrementalCutReusesSealedWindows(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(11) // windows 0 and 1 sealed (4 commands each), 3 commands open
	first, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := first.Slots[w.slot]
	w.add(6) // 17: windows 0..3 sealed, 1 open
	before := windowCommandsDerived.Load()
	second, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	derived := windowCommandsDerived.Load() - before
	b := second.Slots[w.slot]
	if b.Manifest.Cursor.Index != 17 {
		t.Fatalf("second cut at %d, want 17", b.Manifest.Cursor.Index)
	}
	for _, n := range []uint64{0, 1} {
		for _, name := range []string{winName(n), evName(n)} {
			if !sameFileAt(t, filepath.Join(a.Dir(), "files", name), filepath.Join(b.Dir(), "files", name)) {
				t.Fatalf("sealed window file %s was copied again instead of reused", name)
			}
		}
	}
	// Windows 2, 3 and the open one hold the 9 commands past the first cut's sealed windows; each
	// is read for its record and once more to write its files. Re-reading all 17 commands for the
	// record, the ledger and the files would be 51.
	if derived > 3*9 {
		t.Fatalf("a cut that added 9 commands derived %d commands (history 17)", derived)
	}
	st, compact, err := compactState(b)
	if err != nil || !compact || len(st.Windows) != 5 || st.Windows[4].Count != 1 {
		t.Fatalf("compact state %+v compact=%v err=%v", st, compact, err)
	}
	// The envelope no longer carries the history.
	state, err := b.MachineState()
	if err != nil || bytes.Contains(state, []byte("requests")) {
		t.Fatalf("the envelope state still holds commands: err=%v", err)
	}
}

// Redaction is the only writer of a sealed command. The next cut must carry the redacted bytes,
// not the window the previous snapshot holds; and the compact state a node cut before the
// redaction must still verify against the redacted commands.
func TestRedactionRewritesASealedWindowInTheNextCut(t *testing.T) {
	x := newEraseEnv(t)
	producer := model.NewID()
	var slot uint16
	for range 9 { // windows 0 and 1 sealed, one command open; every batch carries the canary
		hit := x.appendMixedAs(producer, eraseCanary, bothDeadlines)
		slot = hit.batch.RouteSlot
	}
	ctx := context.Background()
	first, err := x.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	holds := func(s replica.Snapshot) int {
		entries, err := os.ReadDir(filepath.Join(s.Dir(), "files"))
		if err != nil {
			t.Fatal(err)
		}
		hits := 0
		for _, f := range entries {
			if !strings.HasSuffix(f.Name(), ".cmd") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(s.Dir(), "files", f.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if containsAny(raw, canaryForms(eraseCanary)) {
				hits++
			}
		}
		return hits
	}
	if holds(first.Slots[slot]) == 0 {
		t.Fatal("fixture: the first cut does not hold the canary")
	}
	m := &slotMachine{engine: x.e, slot: slot}
	pre, err := m.CompactSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = x.e.EraseDeleted(ctx, []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
		t.Fatal(err)
	}
	if err = m.VerifySnapshot(pre); err != nil {
		t.Fatalf("a compact state cut before the redaction was refused by the node that holds it: %v", err)
	}
	var forged slotSnapshotV2
	if err = json.Unmarshal(pre, &forged); err != nil {
		t.Fatal(err)
	}
	forged.Windows[0].Identity[0] ^= 1
	raw, _ := json.Marshal(forged)
	if err = m.VerifySnapshot(raw); err == nil {
		t.Fatal("a window whose commands differ from the local ones was accepted")
	}
	// A cut at an unchanged index is the snapshot already selected; the later cut is the one that
	// replaces it (docs/privacy/retention.md, "Replication-layer redaction").
	x.appendMixedAs(producer, otherCanary, bothDeadlines)
	second, err := x.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := holds(second.Slots[slot]); n != 0 {
		t.Fatalf("the cut after the erasure still carries the canary in %d places (a stale window was reused)", n)
	}
}

// The window evidence of a bundle follows the number of windows and of reservations control did
// not already hold, not the history; the reconciliation it feeds is the one the full list gives.
func TestBundleEvidenceIsSummarisedPerWindow(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(21) // five sealed windows and one command in the sixth
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	cut := controlCut(t, w.e, w.store)
	backup, err := w.e.BeginBackup(ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	_, late := w.add(2) // created and consumed after C, in the same window as command 21
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle := sealed.Bundle
	if bundle.Version != 2 || bundle.Quota.Version != 2 {
		t.Fatalf("bundle version %d / evidence version %d, want 2", bundle.Version, bundle.Quota.Version)
	}
	if len(bundle.Quota.Windows) != 6 {
		t.Fatalf("%d windows in the evidence, want 6", len(bundle.Quota.Windows))
	}
	detail := 0
	for _, win := range bundle.Quota.Windows {
		if win.Detail {
			detail++
		}
	}
	if detail != 1 || len(bundle.Quota.Consumed) != 3 {
		t.Fatalf("%d detail windows listing %d reservations, want 1 window listing the 3 of window 5", detail, len(bundle.Quota.Consumed))
	}
	cert, err := ReconcileQuota(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Consumed) != 23 || len(cert.AddedAfterCut) != 2 || len(cert.Pending) != 0 || len(cert.Refunded) != 0 {
		t.Fatalf("certificate consumed=%d added=%d pending=%d refunded=%d, want 23/2/0/0", len(cert.Consumed), len(cert.AddedAfterCut), len(cert.Pending), len(cert.Refunded))
	}
	found := false
	for _, id := range cert.AddedAfterCut {
		found = found || id == late.Reservation.ID
	}
	if !found {
		t.Fatal("the reservation admitted after the cut was not rebuilt")
	}
	all, err := bundle.ConsumedEvidence()
	if err != nil || len(all) != 23 {
		t.Fatalf("resolved %d consumed reservations (err %v), want 23", len(all), err)
	}
}

// A bundle whose window table is changed and re-sealed still cannot pass: either control's cut
// disagrees with the window, or the installed snapshot bytes do.
func TestForgedWindowEvidenceIsRefused(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(9)
	if err := w.store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	cut := controlCut(t, w.e, w.store)
	backup, err := w.e.BeginBackup(ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	w.add(2)
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	reseal := func(b BackupBundle) BackupBundle {
		b.Quota.Digest = b.Quota.seal()
		b.Digest = b.seal()
		return b
	}
	clone := func() BackupBundle {
		raw, err := json.Marshal(sealed.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		var b BackupBundle
		if err = json.Unmarshal(raw, &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("a summarised window's digest changed", func(t *testing.T) {
		b := clone()
		for i := range b.Quota.Windows {
			if !b.Quota.Windows[i].Detail {
				b.Quota.Windows[i].Charge[0] ^= 1
				break
			}
		}
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a window digest control's cut does not reproduce was accepted")
		}
	})
	t.Run("a detail flag cleared", func(t *testing.T) {
		b := clone()
		for i := range b.Quota.Windows {
			if b.Quota.Windows[i].Detail {
				b.Quota.Windows[i].Detail = false
			}
		}
		if _, err := ReconcileQuota(reseal(b)); err == nil {
			t.Fatal("a window control's cut does not hold was summarised")
		}
	})
	t.Run("a listed reservation inflated and its window digest recomputed", func(t *testing.T) {
		b := clone()
		late := map[model.ID]bool{}
		for _, id := range ids(sealed.Bundle, cut) {
			late[id] = true
		}
		changed := false
		for i := range b.Quota.Consumed {
			if late[b.Quota.Consumed[i].ID] {
				b.Quota.Consumed[i].Bytes += 1000
				changed = true
			}
		}
		if !changed {
			t.Fatal("fixture: no reservation admitted after the cut in the evidence")
		}
		for i := range b.Quota.Windows {
			if b.Quota.Windows[i].Detail {
				var list []ReservationEvidence
				for _, c := range b.Quota.Consumed {
					if k := (c.Cursor.Index - 1) / model.Uint64(b.Quota.Windows[i].Span); uint64(k) == b.Quota.Windows[i].N {
						list = append(list, c)
					}
				}
				b.Quota.Windows[i].Charge = chargeDigest(list)
			}
		}
		b = reseal(b)
		if _, err := ReconcileQuota(b); err != nil {
			t.Fatalf("fixture: the forged bundle should be self-consistent: %v", err)
		}
		// Nothing but the installed bytes can refute it.
		_, err := openRestoredEngine(t, t.TempDir(), w.service, w.store, b.Identity, func(e *Engine, raft string) error {
			return e.InstallBackup(ctx, raft, b, func(slot uint16) (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
			})
		})
		if err == nil {
			t.Fatal("a bundle whose evidence the installed snapshots do not carry was installed")
		}
	})
	t.Run("a snapshot stream with one flipped byte of a window file", func(t *testing.T) {
		stream := snapshotStream(t, sealed.Snapshots[w.slot])
		var off uint64
		for _, f := range sealed.Snapshots[w.slot].Manifest.Files {
			if f.Name == "files/"+winName(0) {
				break
			}
			off += f.Size
		}
		bad := bytes.Clone(stream)
		bad[off+windowHeader+5] ^= 1
		_, err := openRestoredEngine(t, t.TempDir(), w.service, w.store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
			return e.InstallBackup(ctx, raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
				if slot == w.slot {
					return io.NopCloser(bytes.NewReader(bad)), nil
				}
				return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
			})
		})
		if err == nil {
			t.Fatal("a tampered window file was installed")
		}
	})
	t.Run("a foreign bundle", func(t *testing.T) {
		engine, err := Open(t.TempDir(), w.service)
		if err != nil {
			t.Fatal(err)
		}
		defer engine.Close()
		err = engine.InstallBackup(ctx, filepath.Join(t.TempDir(), "raft"), sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Invalid {
			t.Fatalf("a bundle of another installation: %v (want invalid)", err)
		}
	})
}

// ids are the reservations of the bundle's evidence the cut did not hold.
func ids(b BackupBundle, cut ControlCut) []model.ID {
	var out []model.ID
	for _, c := range b.Quota.Consumed {
		if _, known := cut.Reservations[c.ID.String()]; !known {
			out = append(out, c.ID)
		}
	}
	return out
}

// A restored node installs its compact snapshot from the snapshot directory; the history the
// installed engine then holds is exactly the one that was cut.
func TestCompactSnapshotInstallsFromItsDirectory(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(13)
	cut := controlCut(t, w.e, w.store)
	backup, err := w.e.BeginBackup(ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := backup.Seal(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := openRestoredEngine(t, t.TempDir(), w.service, w.store, sealed.Bundle.Identity, func(e *Engine, raft string) error {
		return e.InstallBackup(ctx, raft, sealed.Bundle, func(slot uint16) (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(snapshotStream(t, sealed.Snapshots[slot]))), nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.indexes[w.slot]; got != 13 {
		t.Fatalf("restored slot applied %d commands, want 13", got)
	}
	for index := uint64(1); index <= 13; index++ {
		var a, b []byte
		w.e.mu.Lock()
		_ = w.e.db.View(func(tx *bolt.Tx) error {
			a = bytes.Clone(tx.Bucket([]byte("replica_commands")).Get(commandKey(w.slot, index)))
			return nil
		})
		w.e.mu.Unlock()
		restored.mu.Lock()
		_ = restored.db.View(func(tx *bolt.Tx) error {
			b = bytes.Clone(tx.Bucket([]byte("replica_commands")).Get(commandKey(w.slot, index)))
			return nil
		})
		restored.mu.Unlock()
		if len(a) == 0 || !bytes.Equal(a, b) {
			t.Fatalf("command %d differs after the install (%d vs %d bytes)", index, len(a), len(b))
		}
	}
	// The restored node cuts its own incremental snapshot at once, from the installed windows.
	if err = restored.CommitQuotaReconciliation(ctx, mustReconcile(t, sealed.Bundle)); err != nil {
		t.Fatal(err)
	}
	if _, err = restored.CreateSnapshots(ctx); err != nil {
		t.Fatalf("cut after install: %v", err)
	}
}

func mustReconcile(t *testing.T, b BackupBundle) QuotaReconciliation {
	t.Helper()
	cert, err := ReconcileQuota(b)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// appendMixedAs is eraseEnv.appendMixed for a chosen producer: every batch of one producer routes
// to the slot its log record routes to, so one slot's history grows.
func (x *eraseEnv) appendMixedAs(producer model.ID, canary string, deadlines []model.SignalDeadline) erased {
	x.t.Helper()
	keepL := x.log()
	want, err := model.OwnerSlot(x.d.Org, x.d.Project, x.d.Source, producer, keepL)
	if err != nil {
		x.t.Fatal(err)
	}
	find := func(prefix string, at model.UnixNano) model.Record {
		for salt := range 1 << 16 {
			r := x.metric(fmt.Sprintf("%s_%d", prefix, salt), at)
			if s, err := model.OwnerSlot(x.d.Org, x.d.Project, x.d.Source, producer, r); err == nil && s == want {
				return r
			}
		}
		x.t.Fatal("no metric name routes to the log slot")
		return model.Record{}
	}
	secret, keepM := find("secret"+canary+model.NewID().String()[:8], 5), find("kept"+model.NewID().String()[:12], 50)
	b, r, scope := x.appendRecords(producer, deadlines, secret, keepM, keepL)
	return erased{batch: b, receipt: r, scope: scope, secret: secret, keepM: keepM, keepL: keepL}
}

// The background full pass re-derives every persisted window record from the commands: a record
// the commands no longer match (bit rot below a verified point, or a writer that forgot to drop
// the record) fails the engine closed.
func TestFullPassCatchesAStaleWindowRecord(t *testing.T) {
	verifyGate = make(chan struct{})
	t.Cleanup(func() { verifyGate = nil })
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(9)
	if _, err := w.e.CreateSnapshots(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.e.VerifyFull(ctx); err != nil {
		t.Fatalf("a clean engine failed the full pass: %v", err)
	}
	w.e.mu.Lock()
	err := w.e.db.Update(func(tx *bolt.Tx) error {
		commands := tx.Bucket([]byte("replica_commands"))
		key := commandKey(w.slot, 2)
		return commands.Put(key, append(bytes.Clone(commands.Get(key)), ' ')) // still valid JSON, no longer the bytes the record hashed
	})
	w.e.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = w.e.VerifyFull(ctx); !isCorruptFault(err) {
		t.Fatalf("the full pass accepted a command its window record does not describe: %v", err)
	}
}

// A different window size makes the old records and files moot, not wrong: the next cut derives
// the windows afresh and the earlier snapshot still reads with the size it names.
func TestChangedWindowSizeRederivesWindows(t *testing.T) {
	w := newWindowEnv(t)
	ctx := context.Background()
	w.add(10)
	first, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old := SetSnapshotWindow(3)
	t.Cleanup(func() { SetSnapshotWindow(old) })
	w.add(3)
	second, err := w.e.CreateSnapshots(ctx)
	if err != nil {
		t.Fatalf("cut with a new window size: %v", err)
	}
	a, _, err := compactState(first.Slots[w.slot])
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := compactState(second.Slots[w.slot])
	if err != nil {
		t.Fatal(err)
	}
	if a.Span != 4 || b.Span != 3 || len(b.Windows) != 5 {
		t.Fatalf("spans %d and %d, %d windows after: want 4, 3 and 5", a.Span, b.Span, len(b.Windows))
	}
	digests, total, err := evidenceDigests(second.Slots[w.slot], 0)
	if err != nil || total != 13 || len(digests) != 13 {
		t.Fatalf("history of the resized snapshot: %d digests of %d commands (%v)", len(digests), total, err)
	}
}
