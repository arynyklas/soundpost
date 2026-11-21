// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestMeasureCutAndBackup measures, at the history sizes named by SOUNDPOST_CUT_N (commands in one
// slot, comma separated; skipped when unset), what a snapshot cut, a backup seal and a journal
// compaction cost and hold. SOUNDPOST_CUT_WINDOW sets the window size (the suite default is 4),
// SOUNDPOST_CUT_RETRY the number of commands a slot's retry table keeps (default slotRetryMax), and
// SOUNDPOST_CUT_COMPACT=1 compacts the journals after each cut the way the retention worker does every
// SnapshotInterval (by default the journal keeps everything since the start). Output: one MEASURE
// line per size, with the sizes of the envelope, the compacted journal and the bundle (its control
// cut and its evidence apart).
func TestMeasureCutAndBackup(t *testing.T) {
	sizes := os.Getenv("SOUNDPOST_CUT_N")
	if sizes == "" {
		t.Skip("set SOUNDPOST_CUT_N=2000,16000 to measure")
	}
	if w, err := strconv.ParseUint(os.Getenv("SOUNDPOST_CUT_WINDOW"), 10, 64); err == nil && w > 0 {
		setMeasureWindow(w)
	}
	if r, err := strconv.Atoi(os.Getenv("SOUNDPOST_CUT_RETRY")); err == nil && r > 0 {
		defer setSlotRetryMax(r)()
	}
	for _, field := range strings.Split(sizes, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil {
			t.Fatal(err)
		}
		t.Run("N"+field, func(t *testing.T) { measureCut(t, n) })
	}
}

func measureNormalized(t *testing.T, store *control.Store, a *auth.Service, c auth.SourceCredential, d model.SourceDescriptor, producer model.ID, at model.UnixNano) (auth.Scope, model.NormalizedBatch) {
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

// peakHeap runs f and reports the highest heap in use it sampled above the heap before it, and
// the bytes it allocated in total.
func peakHeap(f func()) (peak, allocated uint64) {
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	stop, done := make(chan struct{}), make(chan uint64)
	var mu sync.Mutex
	high := base.HeapAlloc
	go func() {
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			mu.Lock()
			if m.HeapAlloc > high {
				high = m.HeapAlloc
			}
			mu.Unlock()
			select {
			case <-stop:
				done <- 0
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	f()
	close(stop)
	<-done
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	mu.Lock()
	defer mu.Unlock()
	if after.HeapAlloc > high {
		high = after.HeapAlloc
	}
	return high - base.HeapAlloc, after.TotalAlloc - base.TotalAlloc
}

func measureCut(t *testing.T, n int) {
	ctx := context.Background()
	store, service, credential, descriptor := fixture(t)
	dir := t.TempDir()
	e, err := openTestEngine(t, dir, service, store)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.BindAdmissionOwner(e); err != nil {
		t.Fatal(err)
	}
	producer := model.NewID()
	var slot uint16
	at := model.UnixNano(1)
	add := func(count int) {
		for range count {
			scope, b := measureNormalized(t, store, service, credential, descriptor, producer, at)
			at++
			slot = b.RouteSlot
			if _, err := e.Append(ctx, scope, b); err != nil {
				t.Fatal(err)
			}
		}
	}
	add(n)
	if err = store.ReconcileAdmissions(ctx); err != nil {
		t.Fatal(err)
	}
	timed := func(f func()) time.Duration {
		start := time.Now()
		f()
		return time.Since(start)
	}
	compactBetween := os.Getenv("SOUNDPOST_CUT_COMPACT") != ""
	var cold, warm time.Duration
	cold = timed(func() {
		if _, err = e.CreateSnapshots(ctx); err != nil {
			t.Fatal(err)
		}
	})
	if compactBetween {
		if err = e.CompactJournals(ctx); err != nil {
			t.Fatal(err)
		}
	}
	add(64)
	warmBase := windowCommandsDerived.Load()
	warm = timed(func() {
		if _, err = e.CreateSnapshots(ctx); err != nil {
			t.Fatal(err)
		}
	})
	warmRead := windowCommandsDerived.Load() - warmBase
	if compactBetween { // the retention worker cuts and compacts every SnapshotInterval; the journal then holds only what came after
		if err = e.CompactJournals(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// SOUNDPOST_CUT_SETTLE=1: the retention worker's settlement pass runs before the control cut is
	// taken (control.SettleAdmissions over the sealed windows the engine offers).
	settleOn := os.Getenv("SOUNDPOST_CUT_SETTLE") != ""
	settledWindows := 0
	if settleOn {
		if err = store.ReconcileAdmissions(ctx); err != nil {
			t.Fatal(err)
		}
		candidates, err := e.SettleCandidates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		rep, err := store.SettleAdmissions(ctx, candidates)
		if err != nil {
			t.Fatal(err)
		}
		settledWindows = rep.Windows
	}
	controlNow := controlState(t, store)
	cut := controlCut(t, e, store)
	backup, err := e.BeginBackup(ctx, cut)
	if err != nil {
		t.Fatal(err)
	}
	add(64)
	var sealed SealedBackup
	var sealTime time.Duration
	sealRead := windowCommandsDerived.Load()
	peak, allocated := peakHeap(func() {
		sealTime = timed(func() {
			if sealed, err = backup.Seal(ctx, nil); err != nil {
				t.Fatal(err)
			}
		})
	})
	sealRead = windowCommandsDerived.Load() - sealRead
	bundle, _ := jsonSize(sealed.Bundle)
	bundleCut, _ := jsonSize(sealed.Bundle.Cut)
	bundleEvidence, _ := jsonSize(sealed.Bundle.Quota)
	var compactTime time.Duration
	compactTime = timed(func() {
		if err = e.CompactJournals(ctx); err != nil {
			t.Fatal(err)
		}
	})
	wal := fileSize(filepath.Join(dir, "raft", "slot-"+strconv.Itoa(int(slot)), "ready.wal"))
	envelope := fileSize(filepath.Join(sealed.Snapshots[slot].Dir(), "envelope.json"))
	records, _, _ := retryShape(t, e, slot)
	windows := (uint64(n) + 128 + snapshotWindow - 1) / snapshotWindow
	controlBytes, _ := jsonSize(controlNow)
	// What one control transition costs on this state: the mean of 16 admissions' reservations.
	reserveTime := timed(func() {
		for range 16 {
			measureNormalized(t, store, service, credential, descriptor, producer, at)
			at++
		}
	}) / 16
	t.Logf("MEASURE history=%d windows=%d compacted=%t settled=%t settled_windows=%d control_rows=%d control_state_bytes=%d reserve_ms=%.2f cut_cold_ms=%.1f cut_incremental_ms=%.1f seal_ms=%.1f compact_ms=%.1f seal_peak_heap_mb=%.1f seal_alloc_mb=%.1f warm_cut_commands_read=%d seal_commands_read=%d bundle_bytes=%d bundle_cut_bytes=%d bundle_evidence_bytes=%d envelope_bytes=%d ready_wal_bytes=%d retry_records=%d",
		n, windows, compactBetween, settleOn, settledWindows, len(controlNow.Reservations), controlBytes, ms(reserveTime), ms(cold), ms(warm), ms(sealTime), ms(compactTime), float64(peak)/(1<<20), float64(allocated)/(1<<20), warmRead, sealRead, bundle, bundleCut, bundleEvidence, envelope, wal, records)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func jsonSize(v any) (int, error) {
	raw, err := json.Marshal(v)
	return len(raw), err
}
