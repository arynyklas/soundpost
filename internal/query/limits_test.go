// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// series adds n distinct float series `name{i="<k>"}` to a project at testEpoch.
func series(st *tstore, project model.ID, name string, n int) {
	rows := make([]trow, n)
	for i := range rows {
		rows[i] = metricRow(project, name, model.Labels{{Name: "i", Value: strconv.Itoa(i)}}, testEpoch, float64(i))
	}
	st.add(rows...)
}

func oneProject(t *testing.T, limits Limits) (*fx, *env, auth.Scope, model.ID) {
	t.Helper()
	f := newFx(t)
	org, ps := f.newOrg("limits", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	return f, f.engineWith(newStore(), limits, false), scope, ps[0]
}

func TestBudgetIsNotPartialSuccess(t *testing.T) {
	f, e, scope, project := oneProject(t, testLimits())
	series(e.store, project, "m", 5)
	for i := range 5 {
		e.store.add(logRow(t, project, testEpoch+int64(i), "line "+strconv.Itoa(i), model.Labels{{Name: "app", Value: "web"}}))
	}
	all := promReq(`{__name__="m"}`, testEpoch+1, project)

	t.Run("returned count", func(t *testing.T) {
		tight := all
		tight.Budget.MaxReturned = 2
		res, err := e.engine.Execute(f.ctx, scope, tight)
		requireCode(t, err, model.Quota)
		if len(res.Projects) != 0 {
			t.Fatal("a value escaped with the failure")
		}
		exact := all
		exact.Budget.MaxReturned = 5
		res, err = e.engine.Execute(f.ctx, scope, exact)
		if err != nil || len(res.Projects[0].Value.Vector) != 5 || res.Projects[0].Completeness != CompletenessComplete {
			t.Fatalf("exactly at the limit must be a complete answer: %v %+v", err, res)
		}
	})
	t.Run("logs over the returned budget are an error, never a trimmed complete answer", func(t *testing.T) {
		q := logReq(`{app="web"}`, testEpoch, testEpoch+10, project)
		q.Budget.MaxReturned = 3
		_, err := e.engine.Execute(f.ctx, scope, q)
		requireCode(t, err, model.Quota)
		q.Budget.MaxReturned = 5
		res, err := e.engine.Execute(f.ctx, scope, q)
		if err != nil || res.Projects[0].Stats.LogsReturned != 5 {
			t.Fatalf("%v %+v", err, res)
		}
	})
	t.Run("explicit log limit is a page, reported", func(t *testing.T) {
		q := logReq(`{app="web"}`, testEpoch, testEpoch+10, project)
		q.LogLimit = 2
		res, err := e.engine.Execute(f.ctx, scope, q)
		if err != nil {
			t.Fatal(err)
		}
		entries := res.Projects[0].Value.Streams[0].Entries
		if len(entries) != 2 || !res.Projects[0].Stats.LimitReached || entries[0].Line != "line 4" || entries[1].Line != "line 3" {
			t.Fatalf("newest two entries of the complete result, flagged as limited: %+v %+v", entries, res.Projects[0].Stats)
		}
		q.LogLimit, q.LogOrder = 5, "forward"
		res, err = e.engine.Execute(f.ctx, scope, q)
		entries = res.Projects[0].Value.Streams[0].Entries
		if err != nil || len(entries) != 5 || res.Projects[0].Stats.LimitReached || entries[0].Line != "line 0" {
			t.Fatalf("a page exactly the size of the result is not limited: %v %+v", err, res.Projects[0].Stats)
		}
		q.LogLimit = uint64ToModel(uint64(e.engine.limits.MaxReturned) + 1)
		_, err = e.engine.Execute(f.ctx, scope, q)
		requireCode(t, err, model.Invalid)
	})
	t.Run("timeout", func(t *testing.T) {
		e.store.nextHook = func(ctx context.Context, n int) error {
			<-ctx.Done()
			return ctx.Err()
		}
		defer func() { e.store.nextHook = nil }()
		q := all
		q.Budget.TimeoutNS = model.Int64(60 * time.Millisecond)
		started := time.Now()
		res, err := e.engine.Execute(f.ctx, scope, q)
		requireCode(t, err, model.Timeout)
		if len(res.Projects) != 0 || time.Since(started) > 5*time.Second {
			t.Fatalf("a timed-out query returned a value or overran: %v", time.Since(started))
		}
	})
	t.Run("memory", func(t *testing.T) {
		series(e.store, project, "big", 3000)
		big := promReq(`{__name__="big"}`, testEpoch+1, project)
		small := big
		small.Budget.MemoryBytes = 300_000
		res, err := e.engine.Execute(f.ctx, scope, small)
		requireCode(t, err, model.Quota)
		if len(res.Projects) != 0 {
			t.Fatal("a value escaped with the failure")
		}
		res, err = e.engine.Execute(f.ctx, scope, big)
		if err != nil || len(res.Projects[0].Value.Vector) != 3000 {
			t.Fatalf("the default budget answers completely: %v", err)
		}
		if peak := res.Projects[0].Stats.PeakMemoryBytes; peak == 0 || int64(peak) > e.engine.limits.DefaultMemory {
			t.Fatalf("peak %d outside the default budget", peak)
		}
	})
	t.Run("partial scan", func(t *testing.T) {
		e.store.partialPage = 1
		defer func() { e.store.partialPage = 0 }()
		_, err := e.engine.Execute(f.ctx, scope, all)
		requireCode(t, err, model.Unavailable)
		opt := all
		opt.AllowPartial = true
		res, err := e.engine.Execute(f.ctx, scope, opt)
		if err != nil || res.Projects[0].Completeness != CompletenessPartial {
			t.Fatalf("an opted-in partial scan is labelled partial: %v %+v", err, res.Projects[0].Completeness)
		}
	})
	t.Run("stale read cut", func(t *testing.T) {
		group := model.ID{4}
		e.store.marks = []model.Cursor{{Group: group, Index: 5}}
		defer func() { e.store.marks = nil }()
		q := all
		q.MinCursors = []model.Cursor{{Group: group, Index: 9}}
		_, err := e.engine.Execute(f.ctx, scope, q)
		requireCode(t, err, model.Stale)
		q.AllowPartial = true
		res, err := e.engine.Execute(f.ctx, scope, q)
		if err != nil || res.Projects[0].Completeness != CompletenessStale {
			t.Fatalf("a read cut behind the minimum is stale when allowed: %v", err)
		}
		q.MinCursors = []model.Cursor{{Group: group, Index: 5}}
		q.AllowPartial = false
		if res, err = e.engine.Execute(f.ctx, scope, q); err != nil || res.Projects[0].Completeness != CompletenessComplete {
			t.Fatalf("a read cut at the minimum is complete: %v", err)
		}
	})
	e.idle(t)
}

func uint64ToModel(v uint64) model.Uint64 { return model.Uint64(v) }

func TestHostileRequestsAreBoundedAndTyped(t *testing.T) {
	f, e, scope, project := oneProject(t, testLimits())
	other := model.NewID()
	base := promReq("1", testEpoch, project)
	deep := base
	deep.Expression = strings.Repeat("(", 16000) + "1" + strings.Repeat(")", 16000)
	nested := base
	nested.Expression = "sum(" + strings.Repeat("abs(", 2000) + "up" + strings.Repeat(")", 2000) + ")"
	bomb := base
	bomb.Expression = `up{job=~"(a+)+$"}`
	e.store.add(metricRow(project, "up", model.Labels{{Name: "job", Value: strings.Repeat("a", 40) + "!"}}, testEpoch, 1))
	cases := map[string]Request{}
	add := func(name string, mutate func(*Request)) {
		r := base
		r.Projects = []model.ID{project}
		mutate(&r)
		cases[name] = r
	}
	add("empty expression", func(r *Request) { r.Expression = "" })
	add("oversize expression", func(r *Request) { r.Expression = strings.Repeat("1+", e.engine.limits.MaxExpressionBytes) })
	add("invalid utf8", func(r *Request) { r.Expression = "up\xff" })
	add("no projects", func(r *Request) { r.Projects = nil })
	add("duplicate projects", func(r *Request) { r.Projects = []model.ID{project, project} })
	add("zero project", func(r *Request) { r.Projects = []model.ID{project, {}} })
	add("too many projects", func(r *Request) {
		r.Projects = nil
		for range 129 {
			r.Projects = append(r.Projects, model.NewID())
		}
	})
	add("unknown language", func(r *Request) { r.Language = "sql" })
	add("profile of the other language", func(r *Request) { r.Profile = logql352 })
	add("unknown profile", func(r *Request) { r.Profile = "promql-prometheus-9.9.9" })
	add("unregistered feature set", func(r *Request) { r.FeatureSet = "not-registered" })
	add("empty feature set", func(r *Request) { r.FeatureSet = "" })
	add("instant with a range", func(r *Request) { r.Evaluation.Step = 5 })
	add("range without step", func(r *Request) { r.Evaluation = Evaluation{Start: 1, End: 10} })
	add("range ends before it starts", func(r *Request) { r.Evaluation = Evaluation{Start: 10, End: 1, Step: 1} })
	add("range with an instant time", func(r *Request) { r.Evaluation = Evaluation{Time: 5, Start: 1, End: 10, Step: 1} })
	add("negative timeout", func(r *Request) { r.Budget.TimeoutNS = -1 })
	add("timeout above the grant", func(r *Request) { r.Budget.TimeoutNS = model.Int64(time.Hour) })
	add("memory above the grant", func(r *Request) { r.Budget.MemoryBytes = model.Uint64(e.engine.limits.MaxMemory + 1) })
	add("returned above the grant", func(r *Request) { r.Budget.MaxReturned = model.Uint64(e.engine.limits.MaxReturned + 1) })
	add("too many minimum cursors", func(r *Request) {
		for i := 0; i <= e.engine.limits.MaxMinCursors; i++ {
			r.MinCursors = append(r.MinCursors, model.Cursor{Group: model.NewID(), Index: 1})
		}
	})
	add("duplicate minimum cursor groups", func(r *Request) {
		g := model.NewID()
		r.MinCursors = []model.Cursor{{Group: g, Index: 1}, {Group: g, Index: 2}}
	})
	add("log paging on promql", func(r *Request) { r.LogLimit = 1 })
	add("source on a telemetry.read scope", func(r *Request) { r.Source = &other })
	for name, req := range cases {
		res, err := e.engine.Execute(f.ctx, scope, req)
		if err == nil || len(res.Projects) != 0 {
			t.Fatalf("%s: accepted", name)
		}
		if code(err) != model.Invalid && code(err) != model.NotFound {
			t.Fatalf("%s: not a typed rejection: %v", name, err)
		}
	}
	if e.store.scans.Load() != 0 {
		t.Fatal("a malformed request reached the index")
	}
	for name, req := range map[string]Request{"deep parentheses": deep, "deep calls": nested} {
		started := time.Now()
		_, err := e.engine.Execute(f.ctx, scope, req)
		var language *syntax.LanguageError
		if err != nil && !errors.As(err, &language) && code(err) == "" || time.Since(started) > 10*time.Second {
			t.Fatalf("%s: want success or a typed error promptly, got %v after %v", name, err, time.Since(started))
		}
		if name == "deep parentheses" && !errors.As(err, &language) {
			t.Fatalf("%s: 16000 nested parentheses must be a typed language error, got %v", name, err)
		}
	}
	started := time.Now()
	if _, err := e.engine.Execute(f.ctx, scope, bomb); err != nil || time.Since(started) > 10*time.Second {
		t.Fatalf("a pathological regular expression must run in bounded time: %v %v", err, time.Since(started))
	}
	e.idle(t)
}

func TestSchedulerLimitsAndFairness(t *testing.T) {
	l := DefaultLimits()
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg, l.MaxQueueWait = 2, 2, 2, 2, 5*time.Second
	s := newScheduler(l)
	orgA, orgB := model.NewID(), model.NewID()
	pa, pb := model.NewID(), model.NewID()
	bg := context.Background()
	hold := func(org, who model.ID) func() {
		t.Helper()
		r, err := s.Acquire(bg, org, who)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	a1, a2 := hold(orgA, pa), hold(orgA, pa)
	if st := s.state(); st.Active != 2 || st.Queued != 0 {
		t.Fatalf("%+v", st)
	}
	var mu sync.Mutex
	var order []string
	released := map[string]func(){}
	queue := func(name string, org, who model.ID, want int) {
		go func() {
			r, err := s.Acquire(bg, org, who)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			mu.Lock()
			order = append(order, name)
			released[name] = r
			mu.Unlock()
		}()
		for deadline := time.Now().Add(5 * time.Second); s.state().Queued != want; {
			if time.Now().After(deadline) {
				t.Fatalf("%s never queued", name)
			}
			time.Sleep(time.Millisecond)
		}
	}
	queue("A3", orgA, pa, 1)
	queue("A4", orgA, pa, 2)
	queue("B1", orgB, pb, 3)
	if _, err := s.Acquire(bg, orgA, pa); code(err) != model.Quota {
		t.Fatalf("a full per-organization queue is a typed Quota refusal: %v", err)
	}
	granted := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
			mu.Lock()
			n := len(order)
			mu.Unlock()
			if n == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("grants %v", order)
			}
		}
	}
	a1()
	granted(1)
	a2()
	granted(2)
	mu.Lock()
	released["A3"]()
	mu.Unlock()
	granted(3)
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if got[0] != "A3" || got[1] != "B1" || got[2] != "A4" {
		t.Fatalf("an organization with a backlog must not monopolize the workers; grant order %v", got)
	}
	mu.Lock()
	released["B1"]()
	released["A4"]()
	mu.Unlock()
	if st := s.state(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("slots leaked: %+v", st)
	}

	// Waiting ends with typed errors and leaves nothing behind.
	l.MaxQueueWait = 50 * time.Millisecond
	s = newScheduler(l)
	x1, x2 := hold(orgA, pa), hold(orgA, pa)
	if _, err := s.Acquire(bg, orgA, pa); code(err) != model.Timeout {
		t.Fatalf("a wait past the limit is Timeout: %v", err)
	}
	ctx, cancel := context.WithCancel(bg)
	go func() {
		for s.state().Queued == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()
	l2 := l
	l2.MaxQueueWait = 5 * time.Second
	s.maxWait = l2.MaxQueueWait
	if _, err := s.Acquire(ctx, orgA, pa); code(err) != model.Cancelled {
		t.Fatalf("a cancelled wait is Cancelled: %v", err)
	}
	cancelled, stop := context.WithCancel(bg)
	stop()
	if _, err := s.Acquire(cancelled, orgB, pb); code(err) != model.Cancelled {
		t.Fatalf("%v", err)
	}
	x1()
	x2()
	if st := s.state(); st.Active != 0 || st.Queued != 0 {
		t.Fatalf("slots leaked: %+v", st)
	}

	// Per-principal and global ceilings hold even where the organization has room.
	l.MaxConcurrent, l.MaxPerOrg, l.MaxPerPrincipal, l.MaxQueuedPerOrg = 3, 3, 1, 0
	s = newScheduler(l)
	p1 := hold(orgA, pa)
	if _, err := s.Acquire(bg, orgA, pa); code(err) != model.Quota {
		t.Fatalf("a second concurrent query of one principal over the cap: %v", err)
	}
	p2 := hold(orgA, pb)
	p3 := hold(orgB, pa)
	if _, err := s.Acquire(bg, orgB, pb); code(err) != model.Quota {
		t.Fatalf("the global cap: %v", err)
	}
	p1()
	p1() // releasing twice must not free a second slot
	p2()
	p3()
	if st := s.state(); st.Active != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestAggregateMemoryAcrossProjectsAndQueries(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("memory", 4)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	st := newStore()
	for _, p := range ps {
		series(st, p, "m", 600)
	}
	scope := f.scope(alice, org, ps...)

	probe := f.engineWith(st, testLimits(), false)
	res, err := probe.engine.Execute(f.ctx, scope, promReq(`{__name__="m"}`, testEpoch+1, ps[0]))
	if err != nil {
		t.Fatal(err)
	}
	one := int64(res.Projects[0].Stats.PeakMemoryBytes)
	if one < 1<<10 {
		t.Fatalf("implausible single-project peak %d", one)
	}

	// The per-query cap is the aggregate of every project's work: a budget that
	// holds one project does not hold four running at once.
	l := testLimits()
	l.MaxMemory, l.DefaultMemory = 64<<20, 64<<20
	l.GlobalMemory = 256 << 20
	e := f.engineWith(st, l, false)
	four := promReq(`{__name__="m"}`, testEpoch+1, ps...)
	plan := planCharge(four.Expression)
	four.Budget.MemoryBytes = model.Uint64(one + plan + one/4)
	one1 := promReq(`{__name__="m"}`, testEpoch+1, ps[0])
	one1.Budget.MemoryBytes = four.Budget.MemoryBytes
	if _, err = e.engine.Execute(f.ctx, scope, one1); err != nil {
		t.Fatalf("the budget must hold one project: %v", err)
	}
	if _, err = e.engine.Execute(f.ctx, scope, four); code(err) != model.Quota {
		t.Fatalf("four concurrently running projects must share one cap: %v", err)
	}
	if peak := e.engine.Usage().MemoryPeak; peak > int64(four.Budget.MemoryBytes) {
		t.Fatalf("pool peak %d exceeded the query budget %d", peak, four.Budget.MemoryBytes)
	}
	four.Budget.MemoryBytes = model.Uint64(8*one + 4*plan)
	big, err := e.engine.Execute(f.ctx, scope, four)
	if err != nil {
		t.Fatal(err)
	}
	if peak := e.engine.Usage().MemoryPeak; peak < 2*one || peak > int64(four.Budget.MemoryBytes) {
		t.Fatalf("aggregate peak %d should span several projects (one=%d) within the budget %d", peak, one, four.Budget.MemoryBytes)
	}
	for _, pr := range big.Projects {
		if len(pr.Value.Vector) != 600 {
			t.Fatalf("incomplete project result %d", len(pr.Value.Vector))
		}
	}
	e.idle(t)

	// Many concurrent queries share the process-wide pool.
	g := testLimits()
	g.MaxMemory, g.DefaultMemory = 3*one, 3*one
	g.GlobalMemory = 4 * one
	g.MaxConcurrent, g.MaxPerOrg, g.MaxPerPrincipal = 8, 8, 8
	pooled := f.engineWith(st, g, false)
	pooled.store.nextHook = func(ctx context.Context, n int) error { time.Sleep(time.Millisecond); return nil }
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = pooled.engine.Execute(f.ctx, scope, promReq(`{__name__="m"}`, testEpoch+1, ps[i%4]))
		}()
	}
	wg.Wait()
	quota := 0
	for _, err := range results {
		switch code(err) {
		case "":
			if err != nil {
				t.Fatalf("untyped failure %v", err)
			}
		case model.Quota:
			quota++
		default:
			t.Fatalf("unexpected failure %v", err)
		}
	}
	if quota == 0 {
		t.Fatal("eight queries needing 2x the pool all fit: the pool bound did nothing")
	}
	if peak := pooled.engine.Usage().MemoryPeak; peak > g.GlobalMemory {
		t.Fatalf("aggregate working memory %d exceeded the pool %d", peak, g.GlobalMemory)
	}
	pooled.idle(t)
	pooled.store.nextHook = nil
	if _, err = pooled.engine.Execute(f.ctx, scope, promReq(`{__name__="m"}`, testEpoch+1, ps[0])); err != nil {
		t.Fatalf("the pool must recover once the contention is gone: %v", err)
	}
	pooled.idle(t)
}

// The raw-log merge keeps every matched row until it is ordered, so its memory
// is charged to the one query account: a query whose matches do not fit fails
// with Quota rather than allocating past its budget, and an explicit page size
// does not change that bound.
func TestRawLogMergeIsBoundedByTheAccount(t *testing.T) {
	f, e, scope, project := oneProject(t, testLimits())
	line := strings.Repeat("x", 300)
	rows := make([]trow, 4000)
	for i := range rows {
		rows[i] = logRow(t, project, testEpoch+int64(i), line, model.Labels{{Name: "app", Value: "web"}})
	}
	e.store.add(rows...)
	q := logReq(`{app="web"}`, testEpoch, testEpoch+10_000, project)
	q.LogLimit = 10
	q.Budget.MemoryBytes = 600_000
	_, err := e.engine.Execute(f.ctx, scope, q)
	requireCode(t, err, model.Quota)
	if peak := e.engine.Usage().MemoryPeak; peak > 600_000 {
		t.Fatalf("merge allocated %d bytes past its %d byte budget", peak, 600_000)
	}
	e.idle(t)
	q.Budget.MemoryBytes = 0
	res, err := e.engine.Execute(f.ctx, scope, q)
	if err != nil || res.Projects[0].Stats.LogsReturned != 10 || !res.Projects[0].Stats.LimitReached {
		t.Fatalf("with room the page is exact: %v %+v", err, res.Projects[0].Stats)
	}
	if peak := res.Projects[0].Stats.PeakMemoryBytes; peak < 4000*300 {
		t.Fatalf("peak %d does not account the %d bytes the merge actually holds", peak, 4000*300)
	}
	e.idle(t)
}

func TestCancellationReleasesEverything(t *testing.T) {
	f, e, scope, project := oneProject(t, testLimits())
	series(e.store, project, "m", 60)
	e.store.add(logRow(t, project, testEpoch+1, "a", model.Labels{{Name: "app", Value: "web"}}))
	for name, req := range map[string]Request{"metric": promReq(`{__name__="m"}`, testEpoch+1, project), "log": logReq(`{app="web"}`, testEpoch, testEpoch+10, project)} {
		t.Run(name+" cancelled mid scan", func(t *testing.T) {
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			e.store.nextHook = func(_ context.Context, n int) error {
				if n == 1 {
					cancel()
				}
				return nil
			}
			defer func() { e.store.nextHook = nil }()
			res, err := e.engine.Execute(ctx, scope, req)
			requireCode(t, err, model.Cancelled)
			if len(res.Projects) != 0 {
				t.Fatal("cancelled query released a value")
			}
			e.idle(t)
		})
		t.Run(name+" scan fails mid way", func(t *testing.T) {
			e.store.nextHook = func(_ context.Context, n int) error {
				if n == 2 {
					return model.Fail(model.Corrupt)
				}
				return nil
			}
			defer func() { e.store.nextHook = nil }()
			_, err := e.engine.Execute(f.ctx, scope, req)
			if name == "metric" {
				requireCode(t, err, model.Corrupt)
			}
			e.idle(t)
		})
	}
	t.Run("cancelled before admission", func(t *testing.T) {
		ctx, cancel := context.WithCancel(f.ctx)
		cancel()
		_, err := e.engine.Execute(ctx, scope, promReq("1", testEpoch, project))
		requireCode(t, err, model.Cancelled)
		e.idle(t)
	})
	t.Run("deadline of the caller", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(f.ctx, 40*time.Millisecond)
		defer cancel()
		e.store.nextHook = func(ctx context.Context, n int) error {
			<-ctx.Done()
			return ctx.Err()
		}
		defer func() { e.store.nextHook = nil }()
		_, err := e.engine.Execute(ctx, scope, promReq(`{__name__="m"}`, testEpoch+1, project))
		requireCode(t, err, model.Timeout)
		e.idle(t)
	})
}
