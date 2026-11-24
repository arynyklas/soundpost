// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// addEstate puts n more projects with one source each into the installation, so that the control
// state the admissions run against has the size of an estate (the single-host gate: 100 projects, the
// blob under control/state 1.76 MB) and not that of the fixture.
func (f *fenceFx) addEstate(n int) {
	f.t.Helper()
	for i := range n {
		project := model.NewID()
		f.admin("create_project", f.org, auth.AdminPayload{ID: project, Name: fmt.Sprintf("estate-%04d", i), Reason: "estate"})
		policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 30, MaxSeries: 1000}
		if _, err := f.svc.OnboardSource(f.ctx, f.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: project, Source: model.NewID(), Expires: model.UnixNano(f.now.Add(time.Hour).UnixNano()), Policy: policy, Reason: "estate"}); err != nil {
			f.t.Fatal("estate source:", err)
		}
	}
}

// admitAndFinalize is what one acknowledged request of the intake path asks of control: the
// reservation (ReserveAdmission), the control reads Engine.Append makes before it stores the batch
// (Revalidate, RevalidateSource, ValidateReservation, ActiveDeletions) and the finalize that follows
// the receipt (FinalizeAdmission). The data engine is the one thing missing: its proof of the
// finalization is the owner the fixture binds.
func admitAndFinalize(f *fenceFx, name string, cursor model.Cursor) error {
	src, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		return err
	}
	scope, err := f.svc.SourceScope(f.ctx, src, false)
	if err != nil {
		return err
	}
	authority, err := f.svc.SourceAuthority(f.ctx, src, true)
	if err != nil {
		return err
	}
	v := model.FloatBits(0x3ff0000000000000)
	policy := authority.Policy
	resource := model.Resource{Service: policy.Resources.Services[0], Environment: policy.Resources.Environments[0], Build: policy.Resources.Builds[0], Instance: policy.Resources.Instances[0]}
	point := model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}
	b := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1000, Resource: resource, Payload: point}}}
	slot, _ := model.OwnerSlot(f.org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return err
	}
	canonical, _ := model.CanonicalJSON(policy)
	n := model.NormalizedBatch{Batch: b, Org: f.org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(canonical).String(), AdmissionAt: model.UnixNano(f.now.UnixNano())}
	reservation, err := f.store.ReserveAdmission(f.ctx, scope, n)
	if err != nil {
		return err
	}
	n.Reservation = reservation
	if err = f.svc.Revalidate(f.ctx, scope); err != nil {
		return err
	}
	if err = scope.RevalidateSource(f.ctx, n.Project, n.Source, true); err != nil {
		return err
	}
	if err = scope.ValidateReservation(f.ctx, n); err != nil {
		return err
	}
	if _, err = f.store.ActiveDeletions(f.ctx, n.Org, []model.ID{n.Project}); err != nil {
		return err
	}
	return f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: reservation.ID, Cursor: cursor})
}

// revisionOf is the committed revision, read without the admission books.
func revisionOf(f *fenceFx) (r model.Revision) {
	f.t.Helper()
	if err := f.store.View(control.WithoutBooks(f.ctx), func(st control.State) error { r = st.Revision; return nil }); err != nil {
		f.t.Fatal(err)
	}
	return
}

// writeSetPageBound is the most pages bolt may write to control.db for one serial admission (reserve and
// finalize one after the other).
const writeSetPageBound = 40

// writeWindow is the control.db write counters and commands of a run of admissions.
type writeWindow struct {
	n                  int
	writes, alloc, cmd int64
}

// perAdmission is the pages bolt wrote per admission (the pages its commits allocated, a value that
// spans pages counting for each, and a meta page per commit: bolt's own Write counter counts a
// multi-page value once), the same in KiB, the bolt page writes it counted and the commands.
func (w writeWindow) perAdmission() (pages, kib, writes, commands float64) {
	d := float64(w.n)
	return (float64(w.alloc)/4096 + float64(w.cmd)) / d, (float64(w.alloc) + 4096*float64(w.cmd)) / 1024 / d, float64(w.writes) / d, float64(w.cmd) / d
}

func (w writeWindow) String() string {
	p, k, wr, c := w.perAdmission()
	return fmt.Sprintf("%.1f pages (%.1f KiB; bolt counted %.1f page writes), %.2f commands per admission", p, k, wr, c)
}

// dirtied says which keys of control.db one admission wrote: per bucket the keys that were added,
// changed or removed and the bytes of the values it left, with every key of the small buckets named.
func dirtied(before, after map[string]control.KeyDump) string {
	type tally struct{ keys, bytes int }
	per := map[string]*tally{}
	named := map[string][]string{}
	note := func(key string, size int, what string) {
		bucket, name, _ := strings.Cut(key, "/")
		t := per[bucket]
		if t == nil {
			t = &tally{}
			per[bucket] = t
		}
		t.keys++
		t.bytes += size
		if !strings.HasPrefix(bucket, "adm_") {
			named[bucket] = append(named[bucket], fmt.Sprintf("%s %q %d B", what, name, size))
		}
	}
	for k, a := range after {
		if b, ok := before[k]; !ok {
			note(k, a.Size, "new")
		} else if b != a {
			note(k, a.Size, "changed")
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			note(k, 0, "removed")
		}
	}
	buckets := make([]string, 0, len(per))
	for b := range per {
		buckets = append(buckets, b)
	}
	sort.Strings(buckets)
	var out strings.Builder
	for _, b := range buckets {
		sort.Strings(named[b])
		fmt.Fprintf(&out, "\n    %-16s %2d keys, %6d B of values", b, per[b].keys, per[b].bytes)
		if len(named[b]) != 0 {
			fmt.Fprintf(&out, ": %s", strings.Join(named[b], "; "))
		}
	}
	return out.String()
}

// TestAdmissionWriteSetIsBoundedAndIndependentOfHistory is the red test of the control.db write
// volume of an acknowledged request (07.06 #11, D81): on the single-host gate the server wrote about
// 500 KB per acknowledged request, 100 KB of it to control.db, because every control command rewrote
// the whole blob under control/state (the revision it steps lives in it), the accumulator and the
// seals, and touched a page of every table of the admission ledger. The write set of an admission
// has to be what the admission adds: the pages bolt writes for it are bounded and do not grow with the
// admissions that came before it, nor with the size of the estate. 600 admissions (reserve, the
// reads of the append, finalize) on a real replicated store whose state holds an estate; the first
// 100, the middle 100 and the last 100 are measured.
func TestAdmissionWriteSetIsBoundedAndIndependentOfHistory(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	f.addEstate(120)
	var blob int
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, err := model.CanonicalJSON(st)
		blob = len(raw)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	const total = 600
	windows := []struct {
		name       string
		from, upto int
	}{{"first 100", 0, 100}, {"middle 100", 250, 350}, {"last 100", 500, 600}}
	got := make([]writeWindow, len(windows))
	group := model.NewID()
	var probes []string
	for i := range total {
		probe := i == 50 || i == 300 || i == 590
		var before map[string]control.KeyDump
		if probe {
			var err error
			if before, err = f.store.DumpForTest(); err != nil {
				t.Fatal(err)
			}
		}
		stats, cmdBefore := f.store.BoltWriteStatsForTest(), revisionOf(f)
		if err := admitAndFinalize(f, fmt.Sprintf("writeset_series_%06d", i), model.Cursor{Group: group, Index: model.Uint64(i + 1)}); err != nil {
			t.Fatal("admit:", err)
		}
		after := f.store.BoltWriteStatsForTest()
		for w, win := range windows {
			if i >= win.from && i < win.upto {
				got[w].n++
				got[w].writes += after.Writes - stats.Writes
				got[w].alloc += after.AllocBytes - stats.AllocBytes
				got[w].cmd += int64(revisionOf(f) - cmdBefore)
			}
		}
		if probe {
			dump, err := f.store.DumpForTest()
			if err != nil {
				t.Fatal(err)
			}
			probes = append(probes, fmt.Sprintf("  admission %d dirtied:%s", i, dirtied(before, dump)))
			if before["control/state"] != dump["control/state"] || before["control/state_seal"] != dump["control/state_seal"] {
				t.Errorf("admission %d rewrote the blob under control/state (%d B)", i, dump["control/state"].Size)
			}
		}
	}
	info, err := os.Stat(filepath.Join(f.dir, "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("estate: state %d B (canonical), control.db %d B after %d admissions", blob, info.Size(), total)
	for w, win := range windows {
		t.Logf("%-10s %s", win.name, got[w])
	}
	for _, p := range probes {
		t.Log("\n" + p)
	}
	first, _, _, _ := got[0].perAdmission()
	middle, _, _, _ := got[1].perAdmission()
	last, _, _, _ := got[2].perAdmission()
	// An admission is two commands (reserve, finalize); bolt writes a meta page, the freelist and the
	// page of the root bucket for each, which is six of the pages below before any data page. Before the
	// revision left the blob (state_layout.go) every command rewrote the whole blob: 174 pages per
	// admission here (a state of 312 KB), and 1.76 MB per command at the single-host gate's estate.
	const bound = writeSetPageBound
	for w, win := range windows {
		if p, _, _, _ := got[w].perAdmission(); p > bound {
			t.Errorf("%s: %.1f pages written to control.db per admission, bound %d", win.name, p, bound)
		}
	}
	// The pages of a B+tree path grow with the log of its records (a level more once a table passes the
	// fan-out of its branch pages): a third of the pages over 600 admissions is that, a rewrite of anything
	// that grows with the history is what this catches.
	if last > first*1.5+2 || middle > first*1.5+2 {
		t.Errorf("pages written per admission grew with the history: %.1f (first 100), %.1f (middle), %.1f (last 100)", first, middle, last)
	}
}

// TestConcurrentAdmissionsWriteFewPagesEach is the amortized counterpart: admissions that wait for a
// commit together (admission_group.go) share the pages of it. 32 writers admit (reserve, the reads of the
// append, finalize) against an estate; what control.db is written per admission and what an admission
// costs are logged, and the pages per admission are bounded well below those of a serial admission.
func TestConcurrentAdmissionsWriteFewPagesEach(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	f.addEstate(120)
	if err := admitAndFinalize(f, "concurrent_warmup", model.Cursor{Group: model.NewID(), Index: 1}); err != nil {
		t.Fatal(err)
	}
	const workers, each = 32, 40
	group := model.NewID()
	statsBefore := f.store.BoltWriteStatsForTest()
	patchesBefore, _ := f.store.StatePatchStatsForTest()
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	start := time.Now()
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := admitAndFinalize(f, fmt.Sprintf("concurrent_series_%03d", (w*each+i)%900), model.Cursor{Group: group, Index: model.Uint64(w*each + i + 2)}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(errs)
	for err := range errs {
		t.Fatal("admit:", err)
	}
	after := f.store.BoltWriteStatsForTest()
	patchesAfter, _ := f.store.StatePatchStatsForTest()
	total := workers * each
	win := writeWindow{n: total, writes: after.Writes - statsBefore.Writes, alloc: after.AllocBytes - statsBefore.AllocBytes, cmd: int64(patchesAfter - patchesBefore)}
	pages, _, _, _ := win.perAdmission()
	t.Logf("%d concurrent admissions in %v (%.2f ms each): %s", total, elapsed, float64(elapsed.Microseconds())/1000/float64(total), win)
	if pages > concurrentPageBound {
		t.Errorf("%.1f pages written to control.db per concurrent admission, bound %d", pages, concurrentPageBound)
	}
}

// concurrentPageBound is the most pages bolt may write to control.db for one admission of the writers.
const concurrentPageBound = 8
