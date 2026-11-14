// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/logql"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/promql"
	"github.com/arynyklas/soundpost/internal/query/regexcompat"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// verifyTimeout bounds the final authorization/deletion check that precedes
// every response release.
const verifyTimeout = 5 * time.Second

// Engine executes authorized C06 queries. It holds no per-request state and is
// safe for concurrent use.
type Engine struct {
	scanner  Scanner
	policy   Revalidator
	profiles Registry
	limits   Limits

	sched *scheduler
	pool  *memoryPool

	deletes auth.DeleteGenerations
	tickets Tickets
	cache   ResultCache
	now     func() time.Time

	openIterators atomic.Int64
	leakedBytes   atomic.Int64
	overReleased  atomic.Int64
}

// Option configures optional collaborators.
type Option func(*Engine)

// WithDeleteGenerations lets a running query detect a deletion that commits while
// it computes (checked at the revalidation interval and before release).
func WithDeleteGenerations(d auth.DeleteGenerations) Option { return func(e *Engine) { e.deletes = d } }

// WithTickets enables authenticated pagination cursors.
func WithTickets(t Tickets) Option { return func(e *Engine) { e.tickets = t } }

// WithResultCache enables the visibility-keyed response cache.
func WithResultCache(c ResultCache) Option { return func(e *Engine) { e.cache = c } }

// WithClock replaces the wall clock used for the cache-settle rule.
func WithClock(now func() time.Time) Option { return func(e *Engine) { e.now = now } }

// New builds the engine. The scanner, revalidator and registry are required and
// every limit must be valid; options add cursors, the cache and deletion
// fencing.
func New(scanner Scanner, policy Revalidator, profiles Registry, limits Limits, options ...Option) (*Engine, error) {
	if scanner == nil || policy == nil || profiles == nil || limits.validate() != nil {
		return nil, model.Fail(model.Invalid)
	}
	e := &Engine{scanner: scanner, policy: policy, profiles: profiles, limits: limits, sched: newScheduler(limits), pool: newMemoryPool(limits.GlobalMemory), now: time.Now}
	for _, option := range options {
		option(e)
	}
	return e, nil
}

// Usage is a consistent snapshot of live engine resources. After every query has
// returned all of the byte, iterator and queue counters are zero; LeakedBytes
// and OverReleasedBytes count accounting violations since construction.
type Usage struct {
	ActiveQueries, QueuedQueries int
	MemoryUsed, MemoryPeak       int64
	OpenIterators                int64
	LeakedBytes                  int64
	OverReleasedBytes            int64
}

func (e *Engine) Usage() Usage {
	st := e.sched.state()
	used, peak := e.pool.snapshot()
	return Usage{ActiveQueries: st.Active, QueuedQueries: st.Queued, MemoryUsed: used, MemoryPeak: peak, OpenIterators: e.openIterators.Load(), LeakedBytes: e.leakedBytes.Load(), OverReleasedBytes: e.overReleased.Load()}
}

func ctxFault(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return model.Fail(model.Timeout)
	}
	return model.Fail(model.Cancelled)
}

// normalizeError gives every failure that leaves the service a typed form: a
// *model.Fault, or a *syntax.LanguageError that keeps the language category and
// source range. Raw error text never crosses this boundary. During the compile
// phase an unclassified failure is an invalid expression; at run time it is an
// unavailable dependency.
func normalizeError(err error, compile bool) error {
	if err == nil {
		return nil
	}
	var fault *model.Fault
	var language *syntax.LanguageError
	var pipeline *logql.MetricPipelineError
	var template *logql.TemplateError
	var templateLimit *logql.TemplateLimitError
	switch {
	case errors.As(err, &fault):
		return fault
	case errors.As(err, &language):
		return language
	case errors.Is(err, context.Canceled):
		return model.Fail(model.Cancelled)
	case errors.Is(err, context.DeadlineExceeded):
		return model.Fail(model.Timeout)
	case errors.Is(err, regexcompat.ErrBudget), errors.As(err, &templateLimit):
		return model.Fail(model.Quota)
	case errors.Is(err, regexcompat.ErrScope), errors.Is(err, regexcompat.ErrProfile):
		return model.Fail(model.Invalid)
	case errors.As(err, &pipeline):
		// The category is one of the engine's closed error kinds only when the
		// engine set the label; a record that extracted a label of that name carries
		// arbitrary text, which a static SafeMessage must never repeat.
		message := "metric input contains an __error__ label"
		if pipeline.EngineSet {
			message = "metric input contains pipeline error: " + pipeline.Category
		}
		return &syntax.LanguageError{Code: "metric.pipeline-error", Category: "execution", SafeMessage: message}
	case errors.As(err, &template):
		return &syntax.LanguageError{Code: "template." + template.Phase, Category: "template", SafeMessage: template.SafeMessage()}
	}
	if code, ok := regexcompat.PatternErrorCode(err); ok {
		return &syntax.LanguageError{Code: "regex." + code, Category: "regex", SafeMessage: "invalid regular expression"}
	}
	if compile {
		return &syntax.LanguageError{Code: "plan.invalid", Category: "plan", SafeMessage: "expression cannot be planned"}
	}
	return model.Fail(model.Unavailable)
}

func faultCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// failureOf converts a typed project error into its wire form.
func failureOf(err error) *Failure {
	var language *syntax.LanguageError
	if errors.As(err, &language) {
		return &Failure{Code: language.Code, Category: language.Category, SourceRange: wireRange(language.Range), SafeMessage: language.SafeMessage}
	}
	var f *model.Fault
	if errors.As(err, &f) {
		return &Failure{Code: string(f.Code), SafeMessage: f.SafeDetail}
	}
	return &Failure{Code: string(model.Unavailable), SafeMessage: string(model.Unavailable)}
}

// fatalForOthers reports whether a project's failure ends the whole request even
// when the caller allowed partial results: cancellation, deadlines and every
// authorization or deletion failure are properties of the request, not of one
// project's data.
func fatalForOthers(err error) bool {
	switch faultCode(err) {
	case model.Cancelled, model.Timeout, model.Forbidden, model.NotFound, model.Unauthenticated, model.Stale:
		return true
	}
	return false
}

// normalize validates everything that needs no data or scope lookup, applies the
// budget defaults and returns a request whose projects are ordered by ID.
type normalized struct {
	Request
	timeout  time.Duration
	memory   int64
	returned uint64
	eval     value.Evaluation
}

func (e *Engine) normalize(req Request) (normalized, error) {
	invalid := func() (normalized, error) { return normalized{}, model.Fail(model.Invalid) }
	if !validLanguage(req.Language) || req.Profile == "" || len(req.Profile) > 128 || req.FeatureSet == "" || len(req.FeatureSet) > 128 || !profileMatchesLanguage(req.Language, req.Profile) {
		return invalid()
	}
	if len(req.Expression) == 0 || len(req.Expression) > e.limits.MaxExpressionBytes || !utf8.ValidString(req.Expression) {
		return invalid()
	}
	projects, err := e.checkProjects(req.Projects)
	if err != nil {
		return normalized{}, err
	}
	ev := req.Evaluation
	if ev.Instant {
		if ev.Start != 0 || ev.End != 0 || ev.Step != 0 {
			return invalid()
		}
	} else if ev.Time != 0 || ev.Step <= 0 || ev.End < ev.Start {
		return invalid()
	}
	if len(req.MinCursors) > e.limits.MaxMinCursors {
		return invalid()
	}
	groups := make(map[model.ID]bool, len(req.MinCursors))
	for _, c := range req.MinCursors {
		if c.Group == (model.ID{}) || groups[c.Group] {
			return invalid()
		}
		groups[c.Group] = true
	}
	if req.Source != nil && *req.Source == (model.ID{}) {
		return invalid()
	}
	if req.Language != LanguageLogQL && (req.LogLimit != 0 || req.LogOrder != "") || req.LogOrder != "" && req.LogOrder != "backward" && req.LogOrder != "forward" {
		return invalid()
	}
	timeout, memory, returned, err := e.limits.resolve(req.Budget)
	if err != nil {
		return normalized{}, err
	}
	if uint64(req.LogLimit) > returned {
		return invalid()
	}
	out := normalized{Request: req, timeout: timeout, memory: memory, returned: returned}
	out.Projects = projects
	out.MinCursors = append([]model.Cursor(nil), req.MinCursors...)
	out.eval = value.Evaluation{Instant: ev.Instant, Time: ev.Time, Start: ev.Start, End: ev.End, Step: int64(ev.Step)}
	return out, nil
}

// checkProjects validates and returns the project list ordered by ID bytes.
func (e *Engine) checkProjects(in []model.ID) ([]model.ID, error) {
	if len(in) < 1 || len(in) > e.limits.MaxProjects {
		return nil, model.Fail(model.Invalid)
	}
	out := append([]model.ID(nil), in...)
	sort.Slice(out, func(i, j int) bool { return idLess(out[i], out[j]) })
	for i, id := range out {
		if id == (model.ID{}) || i > 0 && out[i-1] == id {
			return nil, model.Fail(model.Invalid)
		}
	}
	return out, nil
}
func idLess(a, b model.ID) bool { return string(a[:]) < string(b[:]) }

// authorize is the scope gate: it precedes every cache, index, scan, profile and
// parse step. A project the scope does not name is NotFound whether it exists
// or not; named-source rules are the scope's own.
func (e *Engine) authorize(ctx context.Context, scope auth.Scope, projects []model.ID, source *model.ID, logs bool) error {
	switch scope.Permission() {
	case auth.Read:
		if source != nil {
			return model.Fail(model.Invalid)
		}
	case auth.RawRead:
		if !logs || len(projects) != 1 {
			return model.Fail(model.Invalid)
		}
	default:
		return model.Fail(model.Forbidden)
	}
	for _, p := range projects {
		if !scope.AllowsProject(p) {
			return model.Fail(model.NotFound)
		}
	}
	if scope.Permission() == auth.RawRead && (source == nil || !scope.AllowsSource(*source)) {
		return model.Fail(model.NotFound)
	}
	if err := ctx.Err(); err != nil {
		return ctxFault(err)
	}
	return e.policy.Revalidate(ctx, scope)
}

func (e *Engine) resolveProfile(language, id, featureSet string) (profile.Profile, error) {
	p, err := e.profiles.Resolve(id, featureSet)
	if err != nil || p.ID != id || !profileMatchesLanguage(language, p.ID) {
		return profile.Profile{}, model.Fail(model.Invalid)
	}
	return p, nil
}

// session is one admitted unit of work: a scheduler slot, a run context bounded
// by the budget, the shared memory account and the revalidation guard.
type session struct {
	e       *Engine
	scope   auth.Scope
	org     model.ID
	project []model.ID
	gen     uint64

	ctx     context.Context
	cancel  context.CancelCauseFunc
	acct    *queryAccount
	release func()
	stop    func()
	timer   context.CancelFunc
	closeMu sync.Once
	wire    atomic.Int64
}

func (e *Engine) deleteGeneration(ctx context.Context, scope auth.Scope, projects []model.ID) (uint64, error) {
	if e.deletes == nil {
		return 0, nil
	}
	return e.deletes.DeleteGeneration(ctx, scope.OrgID(), projects)
}

// verify is the revalidation every release and every guard tick performs: the
// scope is still valid and no deletion has committed since the work started.
func (e *Engine) verify(ctx context.Context, scope auth.Scope, projects []model.ID, gen uint64) error {
	if err := ctx.Err(); err != nil {
		return ctxFault(err)
	}
	if err := e.policy.Revalidate(ctx, scope); err != nil {
		return err
	}
	if e.deletes == nil {
		return nil
	}
	now, err := e.deletes.DeleteGeneration(ctx, scope.OrgID(), projects)
	if err != nil {
		return err
	}
	if now != gen {
		return model.Fail(model.Stale)
	}
	return nil
}

func (e *Engine) begin(ctx context.Context, scope auth.Scope, projects []model.ID, timeout time.Duration, memory int64) (*session, error) {
	release, err := e.sched.Acquire(ctx, scope.OrgID(), scope.PrincipalID())
	if err != nil {
		return nil, err
	}
	gen, err := e.deleteGeneration(ctx, scope, projects)
	if err != nil {
		release()
		return nil, err
	}
	s := &session{e: e, scope: scope, org: scope.OrgID(), project: projects, gen: gen, release: release, acct: newQueryAccount(e.pool, memory)}
	timed, timer := context.WithTimeout(ctx, timeout)
	s.timer = timer
	s.ctx, s.cancel = context.WithCancelCause(timed)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(e.limits.RevalidateInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-s.ctx.Done():
				return
			case <-t.C:
				if err := e.verify(s.ctx, scope, projects, gen); err != nil && s.ctx.Err() == nil {
					s.acct.fail(normalizeError(err, false))
					s.cancel(err)
					return
				}
			}
		}
	}()
	s.stop = func() { close(done); wg.Wait() }
	return s, nil
}

// finish is the one release point. It stops the guard (once), performs the final
// authorization and deletion check when asked, and frees every charge, iterator
// slot and the scheduler slot. A latched guard failure always wins.
func (s *session) finish(ctx context.Context, verify bool) error {
	var err error
	s.closeMu.Do(func() {
		s.stop()
		err = s.acct.latched()
		if err == nil && verify {
			vctx, cancel := context.WithTimeout(ctx, verifyTimeout)
			err = s.e.verify(vctx, s.scope, s.project, s.gen)
			cancel()
		}
		s.acct.Release(s.wire.Load())
		leaked, over := s.acct.finish()
		s.e.leakedBytes.Add(leaked)
		s.e.overReleased.Add(over)
		s.cancel(nil)
		s.timer()
		s.release()
	})
	return err
}

// chargeHit accounts a cache hit's payload before it is decoded: the cache's
// copy plus the decoded structure are charged at twice the serialized size, to
// the same query account (and process-wide pool) as a cold computation. A
// payload the account cannot hold is reported as not usable so the caller
// recomputes under the same admission; any other refusal is the request's error.
func (s *session) chargeHit(raw []byte) (cost int64, ok bool, err error) {
	cost = 2 * int64(len(raw))
	if err = s.acct.Reserve(cost); err != nil {
		if faultCode(err) == model.Quota {
			return 0, false, nil
		}
		return 0, false, err
	}
	s.wire.Add(cost)
	return cost, true, nil
}

// releaseHit gives back the charge of a hit that was not used.
func (s *session) releaseHit(cost int64) {
	s.acct.Release(cost)
	s.wire.Add(-cost)
}

// lease is the admission of work that scans no project data (Format): the same
// scheduler slot, a deadline of its own and a per-request account on the shared
// pool, released together by close on every path.
type lease struct {
	e       *Engine
	ctx     context.Context
	acct    *queryAccount
	charged int64
	release func()
	cancel  context.CancelFunc
	once    sync.Once
}

func (e *Engine) admit(ctx context.Context, scope auth.Scope, timeout time.Duration, memory int64) (*lease, error) {
	release, err := e.sched.Acquire(ctx, scope.OrgID(), scope.PrincipalID())
	if err != nil {
		return nil, err
	}
	timed, cancel := context.WithTimeout(ctx, timeout)
	return &lease{e: e, ctx: timed, acct: newQueryAccount(e.pool, memory), release: release, cancel: cancel}, nil
}

// charge reserves n bytes before the allocation they stand for.
func (l *lease) charge(n int64) error {
	if err := l.acct.Reserve(n); err != nil {
		return err
	}
	l.charged += n
	return nil
}

// stopped reports the typed fault of an expired or cancelled lease.
func (l *lease) stopped() error {
	if err := l.ctx.Err(); err != nil {
		return ctxFault(err)
	}
	return nil
}

func (l *lease) close() {
	l.once.Do(func() {
		l.acct.Release(l.charged)
		leaked, over := l.acct.finish()
		l.e.leakedBytes.Add(leaked)
		l.e.overReleased.Add(over)
		l.cancel()
		l.release()
	})
}

// run is the state shared by the workers of one Execute.
type run struct {
	e        *Engine
	s        *session
	n        normalized
	prof     profile.Profile
	scope    auth.Scope
	fence    storage.ReadFence
	returned uint64
}

type projectPlan struct {
	prom *promql.Plan
	log  *logql.Plan
	logs bool
}

// compile parses, type-checks and plans the expression for one project, so any
// language error is raised before a scan starts. Plans are per project because
// a LogQL plan owns its query-local regex scope.
func (n normalized) compile(prof profile.Profile) (projectPlan, []syntax.Diagnostic, error) {
	switch n.Language {
	case LanguagePromQL:
		expr, err := promql.Parse(n.Expression, prof)
		if err != nil {
			return projectPlan{}, nil, normalizeError(err, true)
		}
		typed, ds, err := promql.Check(expr, prof)
		if err != nil {
			return projectPlan{}, nil, normalizeError(err, true)
		}
		plan, err := promql.BuildPlan(typed, n.eval, prof)
		if err != nil {
			return projectPlan{}, nil, normalizeError(err, true)
		}
		return projectPlan{prom: &plan}, ds, nil
	default:
		expr, err := logql.Parse(n.Expression, prof)
		if err != nil {
			return projectPlan{}, nil, normalizeError(err, true)
		}
		typed, ds, err := logql.Check(expr, prof)
		if err != nil {
			return projectPlan{}, nil, normalizeError(err, true)
		}
		plan, err := logql.BuildPlan(typed, n.eval, prof)
		if err != nil {
			return projectPlan{}, nil, normalizeError(err, true)
		}
		return projectPlan{log: &plan, logs: typed.Type == logql.TypeLogs}, ds, nil
	}
}

// planCharge is the accounted estimate of one project's syntax tree, typed tree
// and planner/regex-scope state.
func planCharge(expression string) int64 { return int64(len(expression))*64 + 128<<10 }

type outcome struct {
	result ProjectResult
	err    error
}

// Execute evaluates the request independently in every requested project and
// returns one project-keyed result for each, ordered by project ID. The scope
// is checked before anything else; a failure of any project is a typed error
// unless the caller allowed partial results, and then the failed project is
// reported as such and never as data. Cancellation, deadline, authorization
// and deletion failures always fail the whole request.
func (e *Engine) Execute(ctx context.Context, scope auth.Scope, req Request) (Result, error) {
	res, err := e.execute(ctx, scope, req)
	if err != nil {
		return Result{}, normalizeError(err, false)
	}
	return res, nil
}

func (e *Engine) execute(ctx context.Context, scope auth.Scope, req Request) (Result, error) {
	n, err := e.normalize(req)
	if err != nil {
		return Result{}, err
	}
	if err = e.authorize(ctx, scope, n.Projects, n.Source, n.Language == LanguageLogQL); err != nil {
		return Result{}, err
	}
	prof, err := e.resolveProfile(n.Language, n.Profile, n.FeatureSet)
	if err != nil {
		return Result{}, err
	}
	// Admission precedes the cache lookup: a response served from the cache is
	// decoded, charged and released like any other, and a saturated engine refuses
	// it with the same typed fault as a cold query. Authorization above is still
	// the only step ahead of it, so a denied caller never learns the engine's load.
	s, err := e.begin(ctx, scope, n.Projects, n.timeout, n.memory)
	if err != nil {
		return Result{}, err
	}
	released := false
	defer func() {
		if !released {
			_ = s.finish(ctx, false)
		}
	}()
	cached, fill, err := e.lookupQuery(s, scope, prof, n)
	if err != nil {
		if latched := s.acct.latched(); latched != nil {
			return Result{}, latched
		}
		return Result{}, err
	}
	if cached != nil {
		released = true
		if err = s.finish(ctx, true); err != nil {
			return Result{}, err
		}
		return *cached, nil
	}
	rn := &run{e: e, s: s, n: n, prof: prof, scope: scope, fence: storage.ReadFence{Min: n.MinCursors, AllowPartial: n.AllowPartial}, returned: n.returned}

	plans := make([]projectPlan, len(n.Projects))
	var pre []syntax.Diagnostic
	for i := range n.Projects {
		if err = s.acct.Reserve(planCharge(n.Expression)); err != nil {
			return Result{}, err
		}
		s.wire.Add(planCharge(n.Expression))
		var ds []syntax.Diagnostic
		if plans[i], ds, err = n.compile(prof); err != nil {
			return Result{}, err
		}
		if i == 0 {
			pre = ds
		}
	}

	outs := make([]outcome, len(n.Projects))
	sem := make(chan struct{}, e.limits.ProjectParallelism)
	var wg sync.WaitGroup
	var cascade atomic.Bool
	for i := range n.Projects {
		select {
		case sem <- struct{}{}:
		case <-s.ctx.Done():
			outs[i].err = ctxFault(s.ctx.Err())
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					outs[i].err = model.Fail(model.Unavailable)
					cascade.Store(true)
					s.cancel(outs[i].err)
				}
			}()
			outs[i].result, outs[i].err = rn.project(s.ctx, n.Projects[i], plans[i], pre)
			if outs[i].err != nil && (!n.AllowPartial || fatalForOthers(outs[i].err)) {
				cascade.Store(true)
				s.cancel(outs[i].err)
			}
		}(i)
	}
	wg.Wait()
	released = true
	if latched := s.acct.latched(); latched != nil {
		_ = s.finish(ctx, false)
		return Result{}, latched
	}
	fail := e.firstError(ctx, s, outs, cascade.Load(), n.AllowPartial)
	if fail != nil {
		_ = s.finish(ctx, false)
		return Result{}, fail
	}
	var total uint64
	result := Result{Projects: make([]ProjectResult, len(outs))}
	for i := range outs {
		pr := outs[i].result
		if outs[i].err != nil {
			pr = ProjectResult{ProjectID: n.Projects[i], Diagnostics: []Diagnostic{}, Watermarks: []model.Cursor{}, Completeness: CompletenessPartial, Failure: failureOf(outs[i].err)}
		}
		total += uint64(pr.Stats.SamplesReturned) + uint64(pr.Stats.LogsReturned)
		result.Projects[i] = pr
	}
	if total > n.returned {
		_ = s.finish(ctx, false)
		return Result{}, model.Fail(model.Quota)
	}
	if err = s.finish(ctx, true); err != nil {
		return Result{}, err
	}
	e.storeQuery(ctx, scope, fill, n, result)
	return result, nil
}

// firstError picks the request-level error, if any: the first project's (by ID
// order) error that is not merely the cancellation another failure caused.
func (e *Engine) firstError(ctx context.Context, s *session, outs []outcome, cascade, allowPartial bool) error {
	if ctx.Err() != nil {
		return ctxFault(ctx.Err())
	}
	for i := range outs {
		err := outs[i].err
		if err == nil {
			continue
		}
		if cascade && faultCode(err) == model.Cancelled {
			continue
		}
		if !allowPartial || fatalForOthers(err) {
			return err
		}
	}
	if cause := context.Cause(s.ctx); cascade && cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return nil
}

// trackedScanner counts the pages, rows and bytes one project actually reads and
// the iterators the engine has open, and closes every iterator exactly once.
type trackedScanner struct {
	inner Scanner
	open  *atomic.Int64
	stats *scanStats
}
type scanStats struct{ scans, pages, rows, bytes atomic.Uint64 }

func (t *trackedScanner) Scan(ctx context.Context, scope auth.Scope, req storage.ScanRequest) (storage.RowIterator, error) {
	t.stats.scans.Add(1)
	it, err := t.inner.Scan(ctx, scope, req)
	if err != nil {
		return nil, err
	}
	if it == nil {
		return nil, model.Fail(model.Corrupt)
	}
	t.open.Add(1)
	return &trackedRows{inner: it, open: t.open, stats: t.stats}, nil
}

type trackedRows struct {
	inner  storage.RowIterator
	open   *atomic.Int64
	stats  *scanStats
	closed atomic.Bool
}

func (r *trackedRows) Next(ctx context.Context) (storage.Page, error) {
	page, err := r.inner.Next(ctx)
	if err == nil {
		r.stats.pages.Add(1)
		r.stats.rows.Add(uint64(page.Len()))
		r.stats.bytes.Add(page.Bytes)
	}
	return page, err
}
func (r *trackedRows) Watermarks() []model.Cursor { return r.inner.Watermarks() }
func (r *trackedRows) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	r.open.Add(-1)
	return r.inner.Close()
}

// pinnedLogs fixes the one named restricted source of a raw.read scope.
type pinnedLogs struct {
	scan.LogSource
	source model.ID
}

func (p pinnedLogs) Select(ctx context.Context, r scan.LogSelection) (scan.LogIterator, error) {
	r.Source = p.source
	return p.LogSource.Select(ctx, r)
}

// project evaluates one project and converts its value. Everything it reserves
// is released before it returns except the converted value, which stays charged
// until the whole response is released.
func (rn *run) project(ctx context.Context, project model.ID, plan projectPlan, pre []syntax.Diagnostic) (pr ProjectResult, err error) {
	started := time.Now()
	acct := &projectAccount{q: rn.s.acct}
	stats := &scanStats{}
	scanner := &trackedScanner{inner: rn.e.scanner, open: &rn.e.openIterators, stats: stats}
	var res value.Result
	var ds []syntax.Diagnostic
	switch {
	case plan.prom != nil:
		src := scan.NewMetricSource(scanner, rn.scope, project, rn.fence)
		res, ds, err = promql.Evaluate(ctx, *plan.prom, src, acct)
		if err == nil {
			// Evaluate releases its own charges, the returned values included.
			err = acct.Reserve(value.ResultBytes(res))
		}
	default:
		var src scan.LogSource = scan.NewLogSource(scanner, rn.scope, project, rn.fence)
		if rn.n.Source != nil {
			src = pinnedLogs{LogSource: src, source: *rn.n.Source}
		}
		if plan.logs {
			limit, order := rn.returned+1, logql.Backward
			if rn.n.LogLimit > 0 {
				limit = uint64(rn.n.LogLimit) + 1
			}
			if rn.n.LogOrder == "forward" {
				order = logql.Forward
			}
			res, err = logql.EvaluateLogs(ctx, *plan.log, src, order, limit, acct)
		} else {
			res, ds, err = logql.Evaluate(ctx, *plan.log, src, acct)
		}
	}
	if err != nil {
		return ProjectResult{}, normalizeError(err, false)
	}
	limited := false
	retained := value.ResultBytes(res)
	if plan.logs && rn.n.LogLimit > 0 {
		limited = trimLogs(&res, uint64(rn.n.LogLimit))
	}
	defer func() { acct.Release(retained) }()
	wire := retained
	if err = acct.Reserve(wire); err != nil {
		return ProjectResult{}, normalizeError(err, false)
	}
	rn.s.wire.Add(wire)
	v, counts, err := wireValue(res)
	if err != nil {
		return ProjectResult{}, err
	}
	if res.Partial && !rn.n.AllowPartial {
		return ProjectResult{}, model.Fail(model.Unavailable)
	}
	scanned := stats.scans.Load() > 0
	completeness := completenessOf(res, rn.n.MinCursors, scanned)
	if completeness == CompletenessStale && !rn.n.AllowPartial {
		return ProjectResult{}, model.Fail(model.Stale)
	}
	all := append(append([]syntax.Diagnostic(nil), pre...), ds...)
	pr = ProjectResult{
		ProjectID:    project,
		Value:        &v,
		Diagnostics:  normalizeDiagnostics(all, rn.e.limits.MaxDiagnostics),
		Watermarks:   append([]model.Cursor{}, res.Watermarks...),
		Completeness: completeness,
		Stats: Stats{
			ScansStarted: model.Uint64(stats.scans.Load()), PagesRead: model.Uint64(stats.pages.Load()), RowsRead: model.Uint64(stats.rows.Load()), BytesRead: model.Uint64(stats.bytes.Load()),
			SeriesReturned: model.Uint64(counts.series), SamplesReturned: model.Uint64(counts.samples), LogsReturned: model.Uint64(counts.logs),
			PeakMemoryBytes: model.Uint64(acct.peakBytes()), ElapsedNS: model.Int64(time.Since(started)), LimitReached: limited,
		},
	}
	return pr, nil
}

// completenessOf never infers completeness from output rows: partial when any
// input said so; stale when a scan ran and its read cuts do not reach every
// requested minimum cursor.
func completenessOf(r value.Result, min []model.Cursor, scanned bool) string {
	if r.Partial {
		return CompletenessPartial
	}
	if scanned && len(min) > 0 {
		marks := make(map[model.ID]model.Uint64, len(r.Watermarks))
		for _, c := range r.Watermarks {
			marks[c.Group] = c.Index
		}
		for _, c := range min {
			if have, ok := marks[c.Group]; !ok || have < c.Index {
				return CompletenessStale
			}
		}
	}
	return CompletenessComplete
}

// settled reports whether every evaluated time is old enough to cache.
func (e *Engine) settled(ev Evaluation) bool {
	newest := ev.Time
	if !ev.Instant {
		newest = ev.End
	}
	return newest <= model.UnixNano(e.now().Add(-e.limits.CacheSettle).UnixNano())
}

// String is used in cache identity strings only.
func (ev Evaluation) String() string {
	return fmt.Sprintf("%t/%d/%d/%d/%d", ev.Instant, ev.Time, ev.Start, ev.End, ev.Step)
}

func jsonKey(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(raw)
}
