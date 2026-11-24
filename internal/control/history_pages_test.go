// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// gateSource is one source of the single-host gate's estate: a project of its own and the credential
// that admits batches for it.
type gateSource struct {
	project, source model.ID
	credential      string
}

// addGateEstate onboards n sources, one in each project of the organization, each allowed a series quota
// that fits the gate (100 projects of 1,000 series: the organization's tier holds 100,000 series).
func (f *fenceFx) addGateEstate(n int) []gateSource {
	f.t.Helper()
	out := make([]gateSource, 0, n)
	for i := range n {
		project := model.NewID()
		f.admin("create_project", f.org, auth.AdminPayload{ID: project, Name: fmt.Sprintf("gate-%04d", i), Reason: "estate"})
		policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{model.NewID()}, Instances: []string{"i"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 40, MaxSeries: 1 << 20}
		source := model.NewID()
		issued, err := f.svc.OnboardSource(f.ctx, f.cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: project, Source: source, Expires: model.UnixNano(f.now.Add(time.Hour).UnixNano()), Policy: policy, Reason: "estate"})
		if err != nil {
			f.t.Fatal("gate source:", err)
		}
		out = append(out, gateSource{project: project, source: source, credential: issued.Credential})
	}
	return out
}

// admitBatch is admitAndFinalize for a batch of one record per name, admitted through the source s: what one
// acknowledged request of the gate asks of control, with a batch that carries many distinct series.
func admitBatch(f *fenceFx, s gateSource, names []string, cursor model.Cursor) error {
	src, err := f.svc.AuthenticateSource(f.ctx, s.credential, "", false)
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
	records := make([]model.Record, len(names))
	for i, name := range names {
		point := model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}
		records[i] = model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1000, Resource: resource, Payload: point}
	}
	b := model.Batch{Version: 1, Project: s.project, Source: s.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: records}
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

// gateShape is the shape of the gate's admissions: sources of the estate, series of each source, series in one batch
// and writers.
type gateShape struct {
	sources, seriesPerSource, seriesPerBatch, workers int
}

// admitConcurrently runs n admissions (reserve, the reads of the append, finalize) through workers writers: each
// admission is a batch of seriesPerBatch distinct series drawn at random from the 1,000 of a random source. It
// returns the control.db write counters of the run: what the commits of the writers share is in it.
func admitConcurrently(t *testing.T, f *fenceFx, estate []gateSource, group model.ID, first, n int, shape gateShape, rng *rand.Rand) writeWindow {
	t.Helper()
	type job struct {
		source int
		names  []string
	}
	jobs := make([]job, n)
	for i := range jobs {
		picked := map[int]bool{}
		names := make([]string, 0, shape.seriesPerBatch)
		for len(names) < shape.seriesPerBatch {
			s := rng.IntN(shape.seriesPerSource)
			if !picked[s] {
				picked[s] = true
				names = append(names, fmt.Sprintf("gate_series_%04d", s))
			}
		}
		jobs[i] = job{source: rng.IntN(len(estate)), names: names}
	}
	before := f.store.BoltWriteStatsForTest()
	overlayBefore := control.OverlayWritesForTest()
	patchesBefore, _ := f.store.StatePatchStatsForTest()
	var wg sync.WaitGroup
	errs := make(chan error, shape.workers)
	next := make(chan int, n)
	for i := range n {
		next <- i
	}
	close(next)
	for range shape.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				if err := admitBatch(f, estate[jobs[i].source], jobs[i].names, model.Cursor{Group: group, Index: model.Uint64(first + i + 1)}); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal("admit:", err)
	}
	after := f.store.BoltWriteStatsForTest()
	patchesAfter, _ := f.store.StatePatchStatsForTest()
	overlay := control.OverlayWritesForTest()
	t.Logf("%d admissions: the overlay wrote %.2f blobs (%.0f B) and %.2f blocks (%.0f B) per commit", n, float64(overlay.Blobs-overlayBefore.Blobs)/float64(patchesAfter-patchesBefore), float64(overlay.BlobBytes-overlayBefore.BlobBytes)/float64(patchesAfter-patchesBefore), float64(overlay.Blocks-overlayBefore.Blocks)/float64(patchesAfter-patchesBefore), float64(overlay.BlockBytes-overlayBefore.BlockBytes)/float64(patchesAfter-patchesBefore))
	return writeWindow{n: n, writes: after.Writes - before.Writes, alloc: after.AllocBytes - before.AllocBytes, cmd: int64(patchesAfter - patchesBefore)}
}

// gatePageBound is the most pages bolt may write to control.db for one admission of the gate's shape (a batch of
// twenty series under three quota tiers, 32 writers, group commit), whatever the ledger holds. The bound is the
// structure's: the log of a commit (a few pages for all the series records of its admissions, compressed), the
// reservation rows and the quota heads of the commit, the blocks the folds of a generation rewrite, once for all the
// admissions of the generation, and what every commit writes whatever it carries (meta pages, the root bucket, the
// accumulator): under 8 pages. Before the ledger kept its series and keys as an overlay with a bounded fold, every
// distinct series of a commit was a leaf of its own: 20 series of 8 admissions of a commit, 100+ pages per commit.
const gatePageBound = 8

// gateGrowthBound is how much the pages of an admission may grow between a ledger that holds 12,000 admissions and one that
// holds 40,000: the history may not cost. Measured over five runs: 6.0 against 6.1, 6.7, 6.7, 6.7 and 6.2 (x1.02 to
// x1.19): what is left is the phase of the fold cycle a window of 3,000 admissions starts in (a window holds a few) and
// the keys table, which only grows while nothing is settled. Before the overlay the same shape cost 32.4 and 41.6 (x1.28).
const gateGrowthBound = 1.3

// TestConcurrentAdmissionsWritePagesThatDoNotGrowWithTheKeysOfTheHistory measures the control.db pages of an admission
// at the gate's shape: 100 sources of 1,000 series each (100,000 series, three quota tiers), a batch of 20 series
// drawn at random from its source, 32 writers admitting at once (group commit). The single-host gate wrote 21 pages
// of control.db per acknowledged request, 3/4 of them random leaves of the series, settled-charge and key tables
// (L2w20Admission27). The window of 3,000 admissions after 12,000 and the one after 40,000 are measured: the pages of
// an admission are few and the same at both. (By 12,000 admissions the ledger holds 91 % of the 100,000 series, by 40,000
// all of them: what a ledger costs grows with the series it holds, a bound of the tables, and not with the admissions
// that came before. At 5,000 admissions, 63 % of the series are charged and the pages of an admission are 4.9 against
// 6.2.)
func TestConcurrentAdmissionsWritePagesThatDoNotGrowWithTheKeysOfTheHistory(t *testing.T) {
	f := newFenceFxPatch(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	shape := gateShape{sources: 100, seriesPerSource: 1000, seriesPerBatch: 20, workers: 32}
	estate := f.addGateEstate(shape.sources)
	const warm, window, history = 12000, 3000, 25000
	rng := rand.New(rand.NewPCG(1, 2))
	group := model.NewID()
	admitConcurrently(t, f, estate, group, 0, warm, shape, rng) // the ramp: the series of the estate are charged for the first time
	fresh := admitConcurrently(t, f, estate, group, warm, window, shape, rng)
	admitConcurrently(t, f, estate, group, warm+window, history, shape, rng)
	aged := admitConcurrently(t, f, estate, group, warm+window+history, window, shape, rng)
	fp, _, _, fc := fresh.perAdmission()
	ap, _, _, ac := aged.perAdmission()
	t.Logf("history %d:   %s", warm, fresh)
	t.Logf("history %d: %s", warm+window+history, aged)
	if ap > gatePageBound {
		t.Errorf("%.1f pages written to control.db per admission after %d admissions of history, bound %d (small history: %.1f)", ap, warm+window+history, gatePageBound, fp)
	}
	if ap > fp*gateGrowthBound {
		t.Errorf("pages per admission grew with the history: %.1f after %d admissions, %.1f after %d (bound x%.2f)", ap, warm+window+history, fp, warm, gateGrowthBound)
	}
	t.Logf("commands per admission: %.2f small history, %.2f large", fc, ac)
}
