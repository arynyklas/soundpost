// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"math"
	"testing"
)

// TestPlanningIsChargedBeforeAnyWork: parsing and planning reserve their
// estimate from the account before the syntax tree exists, so a budget one byte
// below the plan estimate is a typed Quota refusal before a single scan starts.
func TestPlanningIsChargedBeforeAnyWork(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("plancharge", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	st.add(metricRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1))
	e := f.engineWith(st, testLimits(), false)
	req := promReq("up", testEpoch+1, ps[0])
	req.Budget.MemoryBytes = model.Uint64(planCharge(req.Expression) - 1)
	if _, err := e.engine.Execute(f.ctx, scope, req); code(err) != model.Quota || st.scans.Load() != 0 {
		t.Fatalf("a budget below the plan charge must be refused before any scan: %v scans=%d", err, st.scans.Load())
	}
	req.Budget.MemoryBytes = model.Uint64(planCharge(req.Expression))
	if _, err := e.engine.Execute(f.ctx, scope, req); code(err) != model.Quota {
		t.Fatalf("the plan charge alone leaves no room to evaluate: %v", err)
	}
	e.idle(t)
}

// TestPartialExemplarScanIsNeverACompletePage: an exemplar page computed over a
// scan that reported itself partial is a typed refusal, never a page that claims
// to be complete.
func TestPartialExemplarScanIsNeverACompletePage(t *testing.T) {
	d := newDiscovery(t, true)
	d.store.add(exemplarRow(d.project, "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1, model.NewID()))
	d.store.partialPage = 1
	req := ExemplarRequest{Projects: []model.ID{d.project}, Profile: prom310, FeatureSet: baseFeatureSet, Expression: "up", Window: d.window, Limit: 10}
	res, err := d.engine.Exemplars(d.ctx, d.scope, req)
	if err == nil {
		t.Fatalf("an exemplar page over a partial scan succeeded: %+v", res.Freshness)
	}
	d.store.partialPage = 0
	// Nothing partial was cached for the next, healthy request.
	res, err = d.engine.Exemplars(d.ctx, d.scope, req)
	if err != nil || res.Freshness.Cached || res.Freshness.Completeness != CompletenessComplete || len(res.Exemplars) != 1 {
		t.Fatalf("the healthy retry computes a complete page: %v %+v", err, res)
	}
	d.idle(t)
}

// TestEngineReturnsToIdleAfterCancellationAndPanic: a caller cancelling in the
// middle of a scan and a storage layer that panics both leave no charge, slot,
// iterator or leak report behind.
func TestEngineReturnsToIdleAfterCancellationAndPanic(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("idle", 2)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	for _, p := range ps {
		st.add(metricRow(p, "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, 1))
	}
	e := f.engineWith(st, testLimits(), false)
	req := promReq("up", testEpoch+1, ps...)

	cctx, cancel := context.WithCancel(f.ctx)
	st.nextHook = func(context.Context, int) error { cancel(); return nil }
	cancelled := req
	cancelled.AllowPartial = true
	if _, err := e.engine.Execute(cctx, scope, cancelled); err == nil {
		t.Fatal("expected a typed cancellation")
	}
	st.nextHook = nil
	e.idle(t)

	st.nextHook = func(context.Context, int) error { panic("hostile storage") }
	if _, err := e.engine.Execute(f.ctx, scope, req); code(err) != model.Unavailable {
		t.Fatalf("a storage panic is a typed unavailable: %v", err)
	}
	st.nextHook = nil
	e.idle(t)
}

// TestOverBudgetResultIsNotReportedAsALeak: a result that does not fit the
// budget fails typed, returns every byte to the pool and is not counted as an
// accounting violation.
func TestOverBudgetResultIsNotReportedAsALeak(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("overbudget", 2)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	for _, p := range ps {
		for i := range 200 {
			st.add(metricRow(p, "up", model.Labels{{Name: "job", Value: fmt.Sprintf("api%03d", i)}}, testEpoch+int64(i), 1))
		}
	}
	e := f.engineWith(st, testLimits(), false)
	full := promReq("up", testEpoch+1000, ps...)
	res, err := e.engine.Execute(f.ctx, scope, full)
	if err != nil {
		t.Fatal(err)
	}
	peak := int64(res.Projects[0].Stats.PeakMemoryBytes)
	if peak == 0 {
		t.Fatal("the engine measured no peak memory")
	}
	tighter := full
	// Room for the plans but not for both projects' retained results.
	tighter.Budget.MemoryBytes = model.Uint64(2*planCharge(full.Expression) + peak/2)
	if _, err = e.engine.Execute(f.ctx, scope, tighter); code(err) != model.Quota {
		t.Fatalf("a result that does not fit is a typed Quota: %v", err)
	}
	e.idle(t)
}

// TestStaleMarkerNeverEscapesAsAScalar: scalar() of a series whose last sample is
// a stale marker yields an ordinary NaN, never the stale bit pattern, and the
// vector form yields no element.
func TestStaleMarkerNeverEscapesAsAScalar(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("stale", 1)
	scope := f.scope(f.user(org, "alice@example.test", ps, auth.Read), org, ps...)
	st := newStore()
	st.add(metricBitsRow(ps[0], "up", model.Labels{{Name: "job", Value: "api"}}, testEpoch, value.StaleBits))
	e := f.engineWith(st, testLimits(), false)
	res, err := e.engine.Execute(f.ctx, scope, promReq("scalar(last_over_time(up[1m]))", testEpoch+1, ps[0]))
	if err != nil {
		t.Fatal(err)
	}
	bits := uint64(*res.Projects[0].Value.Scalar.Float)
	if bits == uint64(value.StaleBits) || !math.IsNaN(math.Float64frombits(bits)) {
		t.Fatalf("the stale marker escaped as a user scalar: %016x", bits)
	}
	vec, err := e.engine.Execute(f.ctx, scope, promReq("last_over_time(up[1m])", testEpoch+1, ps[0]))
	if err != nil || len(vec.Projects[0].Value.Vector) != 0 {
		t.Fatalf("a stale last sample is the absence of an element: %v %+v", err, vec.Projects[0].Value)
	}
	e.idle(t)
}

// TestDiagnosticsAreTruncatedOnlyWhenSomethingWasOmitted: exactly max distinct
// diagnostics followed only by exact repeats is a complete list, and one more
// distinct diagnostic ends the list with the single truncation warning.
func TestDiagnosticsAreTruncatedOnlyWhenSomethingWasOmitted(t *testing.T) {
	d := func(n int) syntax.Diagnostic {
		return syntax.Diagnostic{Category: "typeWarning", Range: syntax.SourceRange{StartByte: n, EndByte: n + 1}, SafeMessage: "w"}
	}
	for name, tc := range map[string]struct {
		in        []syntax.Diagnostic
		want      int
		truncated bool
	}{
		"exactly max, repeats only":  {[]syntax.Diagnostic{d(1), d(2), d(1), d(2), d(1)}, 2, false},
		"exactly max":                {[]syntax.Diagnostic{d(1), d(2)}, 2, false},
		"one over max":               {[]syntax.Diagnostic{d(1), d(2), d(3)}, 3, true},
		"one over max, then repeats": {[]syntax.Diagnostic{d(1), d(2), d(3), d(1), d(4)}, 3, true},
		"below max":                  {[]syntax.Diagnostic{d(1)}, 1, false},
	} {
		out := normalizeDiagnostics(tc.in, 2)
		if len(out) != tc.want {
			t.Errorf("%s: %d diagnostics, want %d: %+v", name, len(out), tc.want, out)
			continue
		}
		last := out[len(out)-1]
		if got := last.Code == "diagnostics.truncated"; got != tc.truncated {
			t.Errorf("%s: truncation warning = %v, want %v", name, got, tc.truncated)
		}
	}
}
