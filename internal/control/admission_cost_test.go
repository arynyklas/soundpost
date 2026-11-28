// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// intakeSeries is intake for the series name: every distinct name is one more series charged to the three
// quota tiers, so a run of distinct names grows every tier the way a real estate does.
func intakeSeries(f *fenceFx, name string) error {
	_, err := reserveSeries(f, name)
	return err
}

// reserveSeries commits one real admission reservation of a batch holding one point of the series name.
func reserveSeries(f *fenceFx, name string) (model.AdmissionReservation, error) {
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
	point := model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &v, Type: "counter", Unit: "1"}}
	b := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1000, Resource: resource, Payload: point}}}
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

// admissionCost is the mean wall time and the mean bytes allocated of n admissions of series that were
// not admitted before (names start at from).
func admissionCost(t *testing.T, f *fenceFx, from, n int) (time.Duration, uint64) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	for i := range n {
		if err := intakeSeries(f, fmt.Sprintf("history_series_%06d", from+i)); err != nil {
			t.Fatal("admit:", err)
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	return elapsed / time.Duration(n), (after.TotalAlloc - before.TotalAlloc) / uint64(n)
}

// TestAdmissionCostDoesNotGrowWithHistory is the red test of the single-host overload defect (07.06
// #11): every admission decoded and rewrote the whole control state, reservations and per-series quota
// books included, so what one batch cost grew with every batch admitted before it (mean 7.9 ms at 50
// batches, 84 ms at 1,400 in the live measurement). The cost of an admission has to be a function of
// the batch, not of the history: the same number of admissions, measured after a long history of
// batches and series, must cost about what they cost on a fresh installation. The bounds are loose
// (3x time, 2x allocation) because the control state a fresh installation holds is not empty; the
// defect is a factor of 20 and more at this size.
func TestAdmissionCostDoesNotGrowWithHistory(t *testing.T) {
	f := newFenceFxPatch(t)
	const probe, history = 20, 700
	// The first admissions pay one-time costs (cache fills, page allocation): not the baseline.
	admissionCost(t, f, 0, probe)
	earlyTime, earlyAlloc := admissionCost(t, f, probe, probe)
	admissionCost(t, f, 2*probe, history)
	lateTime, lateAlloc := admissionCost(t, f, 2*probe+history, probe)
	t.Logf("after %d admissions: %v and %d B per admission; after %d: %v and %d B", 2*probe, earlyTime, earlyAlloc, 2*probe+history, lateTime, lateAlloc)
	if lateAlloc > 2*earlyAlloc+64<<10 {
		t.Errorf("allocation per admission grew from %d B to %d B with the history of %d admissions", earlyAlloc, lateAlloc, history)
	}
	if lateTime > 3*earlyTime+2*time.Millisecond {
		t.Errorf("time per admission grew from %v to %v with the history of %d admissions", earlyTime, lateTime, history)
	}
}
