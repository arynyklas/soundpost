// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// newFenceFxCompact is newFenceFxPatch for a group whose members all declared the protocol of the compact admission ops (D104).
// SOUNDPOST_TEST_COMPACT_OFF leaves the gate closed: the plain ops of every protocol, the form the red run of the byte test is
// measured in.
func newFenceFxCompact(t *testing.T) *fenceFx {
	f := newFenceFxPatch(t)
	if os.Getenv("SOUNDPOST_TEST_COMPACT_OFF") == "" {
		f.store.SetCompactAdmissionGate(func() bool { return true })
	}
	return f
}

// reserveBatchOf commits one real admission reservation of a batch that holds one point of each of the series named.
func reserveBatchOf(f *fenceFx, names []string) (model.AdmissionReservation, error) {
	none := model.AdmissionReservation{}
	src, err := f.svc.AuthenticateSource(f.ctx, f.sourceCredential, "", false)
	if err != nil {
		return none, err
	}
	scope, err := f.svc.SourceScope(f.ctx, src, false)
	if err != nil {
		return none, err
	}
	authority, err := f.svc.SourceAuthority(f.ctx, src, true)
	if err != nil {
		return none, err
	}
	v := model.FloatBits(0x3ff0000000000000)
	policy := authority.Policy
	resource := model.Resource{Service: policy.Resources.Services[0], Environment: policy.Resources.Environments[0], Build: policy.Resources.Builds[0], Instance: policy.Resources.Instances[0]}
	b := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1}
	for _, name := range names {
		point := model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}
		b.Records = append(b.Records, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1000, Resource: resource, Payload: point})
	}
	slot, _ := model.OwnerSlot(f.org, b.Project, b.Source, b.Producer, b.Records[0])
	b.RouteSlot = slot
	raw, err := model.CanonicalJSON(b)
	if err != nil {
		return none, err
	}
	canonical, _ := model.CanonicalJSON(policy)
	n := model.NormalizedBatch{Batch: b, Org: f.org, Hash: model.HashCanonical(raw), Canonical: raw, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyHash: model.HashCanonical(canonical).String(), AdmissionAt: model.UnixNano(f.now.UnixNano())}
	return f.store.ReserveAdmission(f.ctx, scope, n)
}

// admitBatches reserves and finalizes batches of six series each, from workers goroutines, the way the intake does (one reserve and
// one finalize per batch), and answers the bytes the control commands carried for them.
func admitBatches(t *testing.T, f *fenceFx, workers, each, from int) (batches int, payloadBytes uint64) {
	t.Helper()
	const perBatch, pool = 6, 600 // the source's quota is 1,000 series: later batches meet series that are charged already
	scope := sourceScopeOf(f)
	group := model.NewID()
	_, before := f.store.StatePatchStatsForTest()
	var wg sync.WaitGroup
	errs := make(chan error, workers*each)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				first := (from + w*each + i) * perBatch
				names := make([]string, perBatch)
				for k := range names {
					names[k] = fmt.Sprintf("bytes_series_%04d", (first+k)%pool)
				}
				r, err := reserveBatchOf(f, names)
				if err != nil {
					errs <- err
					return
				}
				if err = f.store.FinalizeAdmission(f.ctx, scope, model.FinalizeAdmission{ReservationID: r.ID, Cursor: model.Cursor{Group: group, Index: model.Uint64(1 + from + w*each + i)}}); err != nil {
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
	_, after := f.store.StatePatchStatsForTest()
	return workers * each, after - before
}

// TestAdmissionPatchBytesPerBatchAreBoundedAndDoNotGrowWithTheState is the red test of the 5,000 records/s ceiling of the cluster
// (admit report, round 3): the control leader's round carried 481 transitions in 1.84 MB, 3.8 KB per transition, and the round
// that moves it to two followers over the link and applies it on three voters is the one thing every batch waits for (3.0 rounds
// a second, the lock held 97 % of the time). A batch makes two transitions, a reserve and a finalize. The bytes the control
// commands carry for one batch (an op for each of the 18 series counts of its three quota tiers, the reservation row, its key,
// and the whole row again for the receipt) have to stay below the budget whatever the books already hold: what a batch costs is
// a function of the batch, as what it costs to apply is (TestAdmissionCostDoesNotGrowWithHistory).
func TestAdmissionPatchBytesPerBatchAreBoundedAndDoNotGrowWithTheState(t *testing.T) {
	const budget = 2000 // bytes per batch: a reservation row of six series (about 1.2 KB), the receipt's cursor, and a round's share of heads and steps (measured 1,450; 6,530 with the plain ops)
	f := newFenceFxCompact(t)
	if err := f.store.BindAdmissionOwner(&reconcileOwner{}); err != nil {
		t.Fatal(err)
	}
	admitBatches(t, f, 4, 4, 0) // one-time costs: the quota heads are written whole once
	const workers, each = 12, 8
	n, early := admitBatches(t, f, workers, each, 10)
	admitBatches(t, f, workers, 40, 100) // history: 480 batches, the series pool is charged by now
	m, late := admitBatches(t, f, workers, each, 700)
	perEarly, perLate := float64(early)/float64(n), float64(late)/float64(m)
	t.Logf("bytes per batch: %.0f on a fresh ledger, %.0f after 480 batches more", perEarly, perLate)
	if perEarly > budget || perLate > budget {
		t.Errorf("a batch costs %.0f bytes of control commands on a fresh ledger and %.0f after a history, budget %d", perEarly, perLate, budget)
	}
	if perLate > 1.25*perEarly+200 {
		t.Errorf("the bytes of a batch grew from %.0f to %.0f with the books", perEarly, perLate)
	}
}
