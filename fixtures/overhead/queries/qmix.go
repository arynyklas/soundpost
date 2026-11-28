// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// The interactive mix of the contract, in percent of requests. The weights are the contract's; a draw is made from a seeded RNG per
// worker, so a run's mix is reproducible from the recorded seed.
var mixWeights = []struct {
	Class  string
	Weight int
}{
	{ClassPromInstant, 12}, {ClassPromRange1h, 12}, {ClassPromRange24h, 10}, {ClassPromOrg24h, 8}, {ClassPromTopk, 6},
	{ClassLogLines, 14}, {ClassLogCount24h, 8}, {ClassLogRate6h, 8},
	{ClassTraceView, 12}, {ClassServiceRED, 6}, {ClassGolden, 4},
}

// OverlimitClasses are the classes of the over-limit prober (worker 10), in the order it issues them.
var OverlimitClasses = []string{ClassOverMax, ClassOverMemory, ClassOverTimeout, ClassOverDefault24}

const (
	langProm  = "promql"
	langLog   = "logql"
	langTrace = "trace"
	langRED   = "red"

	pathQuery  = "/api/v1/query"
	pathTraces = "/api/v1/traces/view"
	pathRED    = "/api/v1/services/red"

	hour = int64(time.Hour)
	// settle keeps window ends clear of the freshest data (the product's result cache only caches answers that old; ends are random
	// anyway, this keeps the newest window ends inside data that has been flushed).
	settle = int64(2 * time.Minute)
)

// target is one request ready to send: where, as whom, with which body, and the columns of its queries.csv.gz row that the builder knows.
type target struct {
	Class, Lang, Path string
	Body              []byte
	Org               int
	Projects          int
	WindowS           int64
}

// golden is one query of the fixed set. Its answer over immutable data must hash to the same digest for the whole run.
type golden struct {
	ID      string `json:"id"`
	Slot    *int   `json:"slot,omitempty"` // trace views: the slot of the sampled trace
	Class   string `json:"class"`
	Request string `json:"request"` // a summary: language, expression or route, window and projects
	target  target
}

// builder knows the estate and the preload and turns a class into the exact request body of the product.
type builder struct {
	plan   Plan
	sum    PreloadSummary
	seed   uint64 // the mix seed
	orgs   int
	perOrg int
	tokens []string // org index -> read token
}

func newBuilder(plan Plan, sum PreloadSummary, seed uint64) (*builder, error) {
	c := plan.Config
	if err := c.Check(); err != nil {
		return nil, err
	}
	b := &builder{plan: plan, sum: sum, seed: seed, orgs: c.Orgs, perOrg: c.Projects / c.Orgs, tokens: make([]string, c.Orgs)}
	for _, r := range plan.Readers {
		if r.Org < 0 || r.Org >= c.Orgs {
			return nil, fmt.Errorf("reader for organization %d outside the estate", r.Org)
		}
		b.tokens[r.Org] = r.Token
	}
	for o, t := range b.tokens {
		if t == "" {
			return nil, fmt.Errorf("no read token for organization %d", o)
		}
	}
	if len(sum.TraceSamples) == 0 {
		return nil, fmt.Errorf("preload summary carries no trace sample")
	}
	if sum.EventEndNS <= sum.EventStartNS+24*hour-hour {
		return nil, fmt.Errorf("preload event range %d..%d is shorter than the 24 h the windows need", sum.EventStartNS, sum.EventEndNS)
	}
	if plan.PromProfile == "" || plan.PromFeatureSet == "" || plan.LogProfile == "" || plan.LogFeatureSet == "" {
		return nil, fmt.Errorf("plan names no query profile or feature set")
	}
	return b, nil
}

func (b *builder) orgID(o int) model.ID { return ident(b.plan.Config.Seed, "org", o) }

func (b *builder) projectID(p int) model.ID { return ident(b.plan.Config.Seed, "project", p) }

func (b *builder) orgOf(p int) int { return p / b.perOrg }

// orgProjects are the project ids of organization o.
func (b *builder) orgProjects(o int) []model.ID {
	out := make([]model.ID, b.perOrg)
	for i := range out {
		out[i] = b.projectID(o*b.perOrg + i)
	}
	return out
}

func (b *builder) scope(o int) httpapi.ScopeFields { return httpapi.ScopeFields{Org: b.orgID(o)} }

// promRange and the other body makers are the wire body of POST /api/v1/query: scope fields flattened next to the typed request, a zero
// budget (the product's defaults) unless the class overrides it, and decimal-string numbers.
func (b *builder) queryBody(lang string, o int, projects []model.ID, expr string, ev query.Evaluation, budget query.Budget) httpapi.QueryBody {
	profile, set := b.plan.PromProfile, b.plan.PromFeatureSet
	if lang == query.LanguageLogQL {
		profile, set = b.plan.LogProfile, b.plan.LogFeatureSet
	}
	return httpapi.QueryBody{ScopeFields: b.scope(o), Request: query.Request{
		Language: lang, Profile: profile, FeatureSet: set, Expression: expr, Evaluation: ev, Projects: projects, Budget: budget,
	}}
}

func instantEval(at int64) query.Evaluation {
	return query.Evaluation{Instant: true, Time: model.UnixNano(at)}
}

func rangeEval(start, end int64, step time.Duration) query.Evaluation {
	return query.Evaluation{Start: model.UnixNano(start), End: model.UnixNano(end), Step: model.Int64(step)}
}

func (b *builder) promTarget(class string, o int, projects []model.ID, expr string, ev query.Evaluation, windowS int64) target {
	return target{Class: class, Lang: langProm, Path: pathQuery, Org: o, Projects: len(projects), WindowS: windowS,
		Body: mustJSON(b.queryBody(query.LanguagePromQL, o, projects, expr, ev, query.Budget{}))}
}

func (b *builder) logTarget(class string, o int, projects []model.ID, expr string, ev query.Evaluation, windowS int64, limit uint64) target {
	body := b.queryBody(query.LanguageLogQL, o, projects, expr, ev, query.Budget{})
	if limit > 0 {
		body.LogLimit, body.LogOrder = model.Uint64(limit), "backward"
	}
	return target{Class: class, Lang: langLog, Path: pathQuery, Org: o, Projects: len(projects), WindowS: windowS, Body: mustJSON(body)}
}

func (b *builder) traceTarget(class string, s TraceSample) (target, error) {
	tid, err := model.ParseID(s.Trace)
	if err != nil {
		return target{}, fmt.Errorf("trace sample id %q: %w", s.Trace, err)
	}
	o := b.orgOf(s.Project)
	body := httpapi.TraceBody{ScopeFields: b.scope(o), Project: b.projectID(s.Project), Trace: tid,
		Window: query.TimeRange{Start: model.UnixNano(s.StartNS - int64(time.Minute)), End: model.UnixNano(s.StartNS + 10*int64(time.Minute))}}
	return target{Class: class, Lang: langTrace, Path: pathTraces, Org: o, Projects: 1, WindowS: 660, Body: mustJSON(body)}, nil
}

func (b *builder) serviceID(project int, sample *TraceSample) model.ID {
	if sample != nil && sample.Service != "" {
		if id, err := model.ParseID(sample.Service); err == nil {
			return id
		}
	}
	return ident(b.plan.Config.Seed, "service", project)
}

func (b *builder) redTarget(class string, project int, sample *TraceSample, start, end int64) target {
	o := b.orgOf(project)
	body := httpapi.ServiceREDBody{Org: b.orgID(o), Projects: []model.ID{b.projectID(project)}, Service: b.serviceID(project, sample),
		Window: query.TimeRange{Start: model.UnixNano(start), End: model.UnixNano(end)}}
	return target{Class: class, Lang: langRED, Path: pathRED, Org: o, Projects: 1, WindowS: (end - start) / int64(time.Second), Body: mustJSON(body)}
}

// goldens is the fixed set: seven queries over windows that end at least 30 minutes before the preload's event end, where nothing new
// is ever written (the steady ingest's event time is the wall clock after the preload). Two PromQL, two LogQL, one organization topk,
// one trace view of a TraceSample and one service RED.
func (b *builder) goldens() []golden {
	ge := b.sum.EventEndNS - 30*int64(time.Minute)
	min1 := time.Minute
	pid := func(p int) []model.ID { return []model.ID{b.projectID(p)} }
	var out []golden
	add := func(id, summary string, t target) {
		t.Class = ClassGolden
		out = append(out, golden{ID: id, Class: ClassGolden, Request: summary, target: t})
	}
	add("g_prom_instant", fmt.Sprintf("promql instant project 0 at %d: sum by (route) (rate(app_m0[5m]))", ge-hour),
		b.promTarget(ClassGolden, 0, pid(0), `sum by (route) (rate(app_m0[5m]))`, instantEval(ge-hour), 300))
	add("g_prom_range", fmt.Sprintf("promql range project 5 %d..%d step 60s: sum(rate(app_m1[10m]))", ge-7*hour, ge-6*hour),
		b.promTarget(ClassGolden, 0, pid(5), `sum(rate(app_m1[10m]))`, rangeEval(ge-7*hour, ge-6*hour, time.Minute), 3600))
	add("g_prom_topk", fmt.Sprintf("promql instant organization 1 at %d: topk(5, sum by (route) (increase(app_m2[6h])))", ge-2*hour),
		b.promTarget(ClassGolden, 1, b.orgProjects(1), `topk(5, sum by (route) (increase(app_m2[6h])))`, instantEval(ge-2*hour), 21600))
	add("g_log_lines", fmt.Sprintf("logql project 12 %d..%d forward limit 200: {route=\"r1\"} |= \"retried\"", ge-3*hour, ge-2*hour),
		func() target {
			t := b.logTarget(ClassGolden, 1, pid(12), `{route="r1"} |= "retried"`, rangeEval(ge-3*hour, ge-2*hour, min1), 3600, 200)
			var body httpapi.QueryBody
			must(json.Unmarshal(t.Body, &body), "golden log body")
			body.LogOrder = "forward" // a fixed order: the same first 200 lines every time
			t.Body = mustJSON(body)
			return t
		}())
	add("g_log_count", fmt.Sprintf("logql range organization 2 %d..%d step 600s: sum by (route) (count_over_time({route=~\"r.+\"}[1h]))", ge-5*hour, ge-3*hour),
		b.logTarget(ClassGolden, 2, b.orgProjects(2), `sum by (route) (count_over_time({route=~"r.+"}[1h]))`, rangeEval(ge-5*hour, ge-3*hour, 10*time.Minute), 7200, 0))
	var lost, ok *TraceSample
	for i := range b.sum.TraceSamples {
		s := &b.sum.TraceSamples[i]
		if s.Slot <= LossSlotLast && lost == nil {
			lost = s
		} else if s.Slot > LossSlotLast && ok == nil {
			ok = s
		}
	}
	if lost == nil || ok == nil {
		fatalf("golden trace views: the preload summary needs a trace sample in slots 0..%d and one above", LossSlotLast)
	}
	// the first lies in a closed group during the loss (never complete then), the second in a group that stays open (complete, same
	// digest): the g_ok_ prefix marks it as an isolation proof for the validator
	for _, c := range []struct {
		id string
		s  *TraceSample
	}{{"g_trace_view_lost", lost}, {"g_ok_trace_view", ok}} {
		t, err := b.traceTarget(ClassGolden, *c.s)
		if err != nil {
			fatalf("golden trace view: %v", err)
		}
		slot := int(c.s.Slot)
		add(c.id, fmt.Sprintf("trace_view project %d trace %s slot %d", c.s.Project, c.s.Trace, slot), t)
		out[len(out)-1].Slot = &slot
	}
	s := *lost
	add("g_service_red", fmt.Sprintf("service_red project %d %d..%d", s.Project, ge-4*hour, ge-3*hour),
		b.redTarget(ClassGolden, s.Project, &s, ge-4*hour, ge-3*hour))
	return out
}

// gen is one worker's request generator: a seeded RNG, the counter its request ids derive from and the last evaluation end it used per
// expression key (an end is never repeated back to back, so the product's result cache is not what is measured).
type gen struct {
	b      *builder
	worker int
	rng    *rand.Rand
	n      uint64
	last   map[string]int64
	gold   []golden
}

func (b *builder) newGen(worker int, gold []golden) *gen {
	return &gen{b: b, worker: worker, rng: rand.New(rand.NewPCG(b.seed, uint64(worker)+1)), last: map[string]int64{}, gold: gold}
}

// reqID is the 16 hex characters of the X-Gate-Request header: a pure function of (seed, worker, n), different for every request.
func reqID(seed uint64, worker int, n uint64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("soundpost/overhead/queries/req/%d/%d/%d", seed, worker, n)))
	return hex.EncodeToString(h[:8])
}

// nextReq returns the request id of the next request and advances the counter.
func (g *gen) nextReq() string {
	g.n++
	return reqID(g.b.seed, g.worker, g.n)
}

// draw picks a class by the contract's weights.
func (g *gen) draw() string {
	r := g.rng.IntN(100)
	for _, m := range mixWeights {
		if r < m.Weight {
			return m.Class
		}
		r -= m.Weight
	}
	return mixWeights[len(mixWeights)-1].Class
}

// end draws the end of a window of the given length in the data's own time axis. Short windows may end anywhere from one window after
// the oldest record to just before now; windows of six hours and more end within 30 minutes of the preload end, so they always cover
// the preload for the whole run. The result differs from the last end drawn for key.
func (g *gen) end(key string, window int64, nowNS int64) int64 {
	lo := g.b.sum.EventStartNS + window
	hi := nowNS - settle
	if window >= 6*hour {
		hi = min(hi, g.b.sum.EventEndNS+30*int64(time.Minute))
	}
	if hi <= lo {
		hi = lo + int64(time.Minute)
	}
	var e int64
	for range 8 {
		e = lo + g.rng.Int64N(hi-lo)
		if e != g.last[key] {
			break
		}
	}
	g.last[key] = e
	return e
}

func (g *gen) project() int { return g.rng.IntN(g.b.plan.Config.Projects) }
func (g *gen) org() int     { return g.rng.IntN(g.b.orgs) }

func (g *gen) counter() int { return g.rng.IntN(MetricNames / 2) } // app_m0..app_m4 are the counters

// build makes the request of a class at wall time nowNS (unix ns). It panics on ClassGolden: a golden is taken from the fixed set.
func (g *gen) build(class string, nowNS int64) target {
	b := g.b
	switch class {
	case ClassPromInstant:
		p := g.project()
		m := g.counter()
		key := fmt.Sprintf("%s/%d/%d", class, p, m)
		return b.promTarget(class, b.orgOf(p), []model.ID{b.projectID(p)}, fmt.Sprintf(`sum by (route) (rate(app_m%d[5m]))`, m), instantEval(g.end(key, 5*int64(time.Minute), nowNS)), 300)
	case ClassPromRange1h:
		p := g.project()
		m := g.counter()
		e := g.end(fmt.Sprintf("%s/%d/%d", class, p, m), hour, nowNS)
		return b.promTarget(class, b.orgOf(p), []model.ID{b.projectID(p)}, fmt.Sprintf(`sum(rate(app_m%d[10m]))`, m), rangeEval(e-hour, e, 30*time.Second), 3600)
	case ClassPromRange24h:
		p := g.project()
		m := g.counter()
		e := g.end(fmt.Sprintf("%s/%d/%d", class, p, m), 24*hour, nowNS)
		return b.promTarget(class, b.orgOf(p), []model.ID{b.projectID(p)}, fmt.Sprintf(`sum by (route) (rate(app_m%d[5m]))`, m), rangeEval(e-24*hour, e, 5*time.Minute), 86400)
	case ClassPromOrg24h:
		o := g.org()
		m := g.counter()
		e := g.end(fmt.Sprintf("%s/%d/%d", class, o, m), 24*hour, nowNS)
		return b.promTarget(class, o, b.orgProjects(o), fmt.Sprintf(`sum by (route) (rate(app_m%d[5m]))`, m), rangeEval(e-24*hour, e, 10*time.Minute), 86400)
	case ClassPromTopk:
		o := g.org()
		m := g.counter()
		e := g.end(fmt.Sprintf("%s/%d/%d", class, o, m), 6*hour, nowNS)
		return b.promTarget(class, o, b.orgProjects(o), fmt.Sprintf(`topk(5, sum by (route) (increase(app_m%d[6h])))`, m), instantEval(e), 21600)
	case ClassLogLines:
		p := g.project()
		r := g.rng.IntN(b.plan.Config.RoutesPerProject)
		e := g.end(fmt.Sprintf("%s/%d/%d", class, p, r), hour, nowNS)
		return b.logTarget(class, b.orgOf(p), []model.ID{b.projectID(p)}, fmt.Sprintf(`{route="r%d"} |= "retried"`, r), rangeEval(e-hour, e, time.Minute), 3600, 200)
	case ClassLogCount24h:
		o := g.org()
		e := g.end(fmt.Sprintf("%s/%d", class, o), 24*hour, nowNS)
		return b.logTarget(class, o, b.orgProjects(o), `sum by (route) (count_over_time({route=~"r.+"}[1h]))`, rangeEval(e-24*hour, e, 10*time.Minute), 86400, 0)
	case ClassLogRate6h:
		p := g.project()
		r := g.rng.IntN(b.plan.Config.RoutesPerProject)
		e := g.end(fmt.Sprintf("%s/%d/%d", class, p, r), 6*hour, nowNS)
		return b.logTarget(class, b.orgOf(p), []model.ID{b.projectID(p)}, fmt.Sprintf(`sum(rate({route="r%d"}[5m]))`, r), rangeEval(e-6*hour, e, 5*time.Minute), 21600, 0)
	case ClassTraceView:
		t, err := b.traceTarget(class, b.sum.TraceSamples[g.rng.IntN(len(b.sum.TraceSamples))])
		if err != nil {
			fatalf("trace view: %v", err)
		}
		return t
	case ClassServiceRED:
		s := b.sum.TraceSamples[g.rng.IntN(len(b.sum.TraceSamples))]
		w := hour
		if g.rng.IntN(2) == 0 {
			w = 24 * hour
		}
		e := g.end(fmt.Sprintf("%s/%d/%d", class, s.Project, w), w, nowNS)
		return b.redTarget(class, s.Project, &s, e-w, e)
	}
	panic("build: unknown class " + class)
}

// next draws the next interactive request: a class of the mix, or a golden query for the golden class (its id is returned too, "" for
// any other class).
func (g *gen) next(nowNS int64) (target, string) {
	class := g.draw()
	if class == ClassGolden {
		gd := g.gold[g.rng.IntN(len(g.gold))]
		return gd.target, gd.ID
	}
	return g.build(class, nowNS), ""
}

// overlimit builds the over-limit probe of a class for organization o. Each answer must exceed its limit by construction:
//
//	overlimit_returned  max_returned 10 over a 1 h range of every series of the organization: 10 projects x 30 series x 121 points
//	overlimit_memory    memory_bytes 4096 (the product accepts any value up to its ceiling) over a 24 h range of the organization
//	overlimit_timeout   timeout_ns 1 ms (accepted: positive and under the ceiling) over a 24 h range at 15 s of the organization
//	overlimit_default   the product's own defaults (zero budget): every series of the organization at step 1 s for 24 h, 10 x 30 x
//	                    86,401 = 25.9 M samples, five times the default 5 M returned budget (the total over the projects is judged)
func (g *gen) overlimit(class string, o int) target {
	b := g.b
	projects := b.orgProjects(o)
	e := b.sum.EventEndNS - 10*int64(time.Minute) // inside the preload: the data exists for the whole window
	req := func(expr string, ev query.Evaluation, budget query.Budget) target {
		return target{Class: class, Lang: langProm, Path: pathQuery, Org: o, Projects: len(projects), WindowS: int64(ev.End-ev.Start) / int64(time.Second),
			Body: mustJSON(b.queryBody(query.LanguagePromQL, o, projects, expr, ev, budget))}
	}
	switch class {
	case ClassOverMax:
		return req(`{route=~"r.+"}`, rangeEval(e-hour, e, 30*time.Second), query.Budget{MaxReturned: 10})
	case ClassOverMemory:
		return req(`{route=~"r.+"}`, rangeEval(e-24*hour, e, time.Minute), query.Budget{MemoryBytes: 4096})
	case ClassOverTimeout:
		return req(`sum by (route) (rate(app_m0[5m]))`, rangeEval(e-24*hour, e, 15*time.Second), query.Budget{TimeoutNS: model.Int64(time.Millisecond)})
	case ClassOverDefault24:
		return req(`{route=~"r.+"}`, rangeEval(e-24*hour, e, time.Second), query.Budget{})
	}
	panic("overlimit: unknown class " + class)
}
