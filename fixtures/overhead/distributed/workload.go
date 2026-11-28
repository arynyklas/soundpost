// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Config is the workload of design section 13, single-host row: orgs, projects, active metric series, mixed records/s, a fixed
// synthetic seed. Window is the per-source flush window of the modelled SDK (see README.md in this directory).
type Config struct {
	Seed     uint64
	Orgs     int
	Projects int // total projects, spread evenly over the orgs
	Series   int // total active metric series, spread evenly over the projects
	Rate     int // mixed records per second over all projects
	Window   time.Duration
	// Epoch numbers the run on one estate: a second run (the kill -9 run follows the steady run on the same data directory) sends
	// records, traces, runs and batches of its own, not the ones the first run already had acknowledged (the product answers a batch
	// id it holds with other bytes with a conflict). The estate itself (orgs, projects, sources, series, jobs) is the seed's alone.
	Epoch uint64
}

// mixPerMille is the record mix (per thousand records): the kinds the product admits from an SDK source and that the design's
// "mixed records" names. It sums to 1000.
var mixPerMille = []struct {
	Kind model.Kind
	PM   int
}{{model.Metric, 600}, {model.SpanKind, 200}, {model.Log, 120}, {model.ErrorKind, 30}, {model.JobAttempt, 50}}

const (
	spansPerTrace    = 10
	metricNames      = 10
	shardValues      = 10
	jobsPerProject   = 5
	maxRecordsBatch  = 512
	metricUnit       = "1"
	logTemplateID    = "app.event"
	policyCredential = 6 * time.Hour
)

// exactCounts reports the per-project record count of every mix entry for one window, and whether each is a whole number (spans in
// whole traces are not required, job events must pair into runs).
func (c Config) exactCounts() (counts [5]float64, err error) {
	perProject := float64(c.Rate) / float64(c.Projects)
	for i, m := range mixPerMille {
		counts[i] = perProject * c.Window.Seconds() * float64(m.PM) / 1000
		if math.Abs(counts[i]-math.Round(counts[i])) > 1e-9 {
			return counts, fmt.Errorf("window %s gives %.4f %s records per project: pick a window that makes every kind a whole number", c.Window, counts[i], m.Kind)
		}
	}
	if int(math.Round(counts[4]))%2 != 0 {
		return counts, fmt.Errorf("window %s gives an odd number of job events per project: a run is two events", c.Window)
	}
	return counts, nil
}

// Check says whether the configuration can be generated exactly.
func (c Config) Check() error {
	switch {
	case c.Orgs < 1 || c.Projects < c.Orgs || c.Projects%c.Orgs != 0:
		return fmt.Errorf("projects %d must be a positive multiple of orgs %d", c.Projects, c.Orgs)
	case c.Series < c.Projects || c.Series%c.Projects != 0:
		return fmt.Errorf("series %d must be a positive multiple of projects %d", c.Series, c.Projects)
	case c.Series/c.Projects%(metricNames*shardValues) != 0:
		return fmt.Errorf("series per project %d must be a multiple of %d", c.Series/c.Projects, metricNames*shardValues)
	case c.Rate < c.Projects || c.Rate%c.Projects != 0 || c.Window < time.Second:
		return fmt.Errorf("rate %d must be a positive multiple of projects and the window at least 1 s", c.Rate)
	}
	_, err := c.exactCounts()
	return err
}

// SeriesPerProject is the number of distinct metric series each project writes.
func (c Config) SeriesPerProject() int { return c.Series / c.Projects }

// routeValues is the number of "route" label values per project (series = names x shards x routes).
func (c Config) routeValues() int { return c.SeriesPerProject() / (metricNames * shardValues) }

// ident derives a stable identity from the seed and a name: the same seed always yields the same estate.
func ident(seed uint64, parts ...any) model.ID {
	h := sha256.New()
	fmt.Fprintf(h, "soundpost/overhead/single-host/v1/%d", seed)
	for _, p := range parts {
		fmt.Fprintf(h, "/%v", p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

func scalar(s string) model.Scalar {
	var v model.Scalar
	if err := json.Unmarshal([]byte(fmt.Sprintf("%q", s)), &v); err != nil {
		panic(err)
	}
	return v
}

// Project is one source of the estate: identity, signed-policy input and the generator state.
type Project struct {
	Index    int
	OrgIndex int
	Org      model.ID
	Project  model.ID
	Source   model.ID
	Producer model.ID
	Reader   model.ID // the org's read-only user (same for the org's projects)
	Resource model.Resource
	Policy   model.SourcePolicy

	cfg      Config
	domain   model.ClockDomain
	series   []seriesDef
	perm     []int
	vals     []float64
	rng      *rand.Rand
	recSeq   uint64
	cursor   int
	carry    [5]int64 // fractional record counts per mix entry, in thousandths of a record
	runSeq   uint64
	traceSeq uint64
	slotOf   map[model.Kind]func(model.Record) uint16
}

type seriesDef struct {
	name    string
	labels  model.Labels
	counter bool
	slot    uint16
}

// NewProject builds project index p of the estate.
func NewProject(cfg Config, p int) *Project {
	perOrg := cfg.Projects / cfg.Orgs
	pj := &Project{Index: p, OrgIndex: p / perOrg, cfg: cfg}
	pj.Org = ident(cfg.Seed, "org", pj.OrgIndex)
	pj.Project = ident(cfg.Seed, "project", p)
	pj.Source = ident(cfg.Seed, "source", p)
	pj.Producer = ident(cfg.Seed, "producer", p)
	pj.Reader = ident(cfg.Seed, "reader", pj.OrgIndex)
	pj.Resource = model.Resource{Service: ident(cfg.Seed, "service", p), Environment: ident(cfg.Seed, "environment", p), Build: ident(cfg.Seed, "build", p), Instance: "inst-1", Labels: model.Labels{}}
	pj.domain = model.ClockDomain{Host: ident(cfg.Seed, "host", p), Boot: ident(cfg.Seed, "boot", p), Runtime: ident(cfg.Seed, "runtime", p)}
	pj.rng = rand.New(rand.NewPCG(cfg.Seed, uint64(p)+1))
	pj.recSeq, pj.traceSeq, pj.runSeq = cfg.Epoch<<32, cfg.Epoch<<32, cfg.Epoch<<32

	routes := cfg.routeValues()
	labels := map[string][]string{"route": nil, "shard": nil}
	for r := 0; r < routes; r++ {
		labels["route"] = append(labels["route"], fmt.Sprintf("r%d", r))
	}
	for s := 0; s < shardValues; s++ {
		labels["shard"] = append(labels["shard"], fmt.Sprintf("s%d", s))
	}
	codes := []model.Scalar{scalar("started"), scalar("retried"), scalar("completed"), scalar("skipped")}
	units := []model.Scalar{scalar("api"), scalar("worker"), scalar("cron")}
	pj.Policy = model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured",
		Kinds: []model.Kind{model.Metric, model.Log, model.SpanKind, model.ErrorKind, model.JobAttempt},
		Templates: []model.LogTemplate{{ID: logTemplateID, Revision: 1, Line: "event {code} on {unit}", Severity: "info", Fields: []model.TemplateField{
			{Name: "code", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: codes},
			{Name: "unit", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: units}}}},
		Resources:  model.ResourceRegistry{Services: []model.ID{pj.Resource.Service}, Environments: []model.ID{pj.Resource.Environment}, Builds: []model.ID{pj.Resource.Build}, Instances: []string{"inst-1"}},
		Labels:     labels,
		Operations: []string{"request", "http.call", "db.execute", "job.run"}, Dependencies: []string{"api", "postgres"}, Codes: []string{"app.timeout", "app.db_error", "app.bad_input"},
		RetentionDays: map[model.Kind]uint32{model.Metric: 14, model.Log: 14, model.SpanKind: 14, model.ErrorKind: 90, model.JobAttempt: 90},
		MaxBytes:      1 << 30, MaxSeries: model.Uint64(cfg.SeriesPerProject() + cfg.SeriesPerProject()/10),
	}

	n := cfg.SeriesPerProject()
	pj.series = make([]seriesDef, n)
	pj.vals = make([]float64, n)
	for i := range pj.series {
		name, shard, route := i%metricNames, (i/metricNames)%shardValues, i/(metricNames*shardValues)
		def := seriesDef{name: fmt.Sprintf("app_m%d", name), counter: name < metricNames/2,
			labels: model.Labels{{Name: "route", Value: fmt.Sprintf("r%d", route)}, {Name: "shard", Value: fmt.Sprintf("s%d", shard)}}}
		rec := model.Record{Kind: model.Metric, Payload: model.Payload{Metric: &model.MetricPoint{Name: def.name, Labels: def.labels}}}
		slot, err := model.OwnerSlot(pj.Org, pj.Project, pj.Source, pj.Producer, rec)
		if err != nil {
			panic(err)
		}
		def.slot = slot
		pj.series[i] = def
	}
	pj.perm = pj.rng.Perm(n)
	return pj
}

// RecMeta is what the verifier needs about one record of a batch, numbers and identifiers only.
type RecMeta struct {
	Kind byte
	ID   model.ID
	TS   int64
	Aux  [16]byte // metric: series index; span: trace id; error: occurrence id; job: run id; log: unused
}

// Prepared is one encoded batch ready to be sent.
type Prepared struct {
	Project int
	Slot    uint16
	ID      model.ID
	Body    []byte
	Records []RecMeta
}

func kindByte(k model.Kind) byte {
	switch k {
	case model.Metric:
		return 'm'
	case model.SpanKind:
		return 's'
	case model.Log:
		return 'l'
	case model.ErrorKind:
		return 'e'
	case model.JobAttempt:
		return 'j'
	}
	return '?'
}

// counts is how many records of each mix entry window j holds: the cumulative target, so the totals are exact over any prefix
// of windows (no drift), and a span count is rounded to whole traces by the callers.
func (p *Project) windowCounts() [5]int {
	secs := p.cfg.Window.Seconds()
	perProject := float64(p.cfg.Rate) / float64(p.cfg.Projects)
	var out [5]int
	for i, m := range mixPerMille {
		// thousandths of a record per window, accumulated exactly in integers.
		milli := int64(math.Round(perProject * secs * float64(m.PM)))
		p.carry[i] += milli
		out[i] = int(p.carry[i] / 1000)
		p.carry[i] -= int64(out[i]) * 1000
	}
	return out
}

func (p *Project) nextID() model.ID {
	p.recSeq++
	return ident(p.cfg.Seed, "rec", p.Index, p.recSeq)
}

func spread(start time.Time, w time.Duration, i, n int) int64 {
	return start.UnixNano() + int64(float64(w)*(float64(i)+0.5)/float64(n))
}

// Window generates window [start, start+Window) of this project as slot-grouped batches, exactly as the SDK's queue freezes them: one
// batch per route slot (the product requires every record of a batch to belong to the batch's slot), at most 512 records each.
func (p *Project) Window(j int, start time.Time) []Prepared {
	counts := p.windowCounts()
	w := p.cfg.Window
	bySlot := map[uint16][]model.Record{}
	metaOf := map[model.ID]RecMeta{}
	add := func(r model.Record, aux [16]byte) {
		slot, err := model.OwnerSlot(p.Org, p.Project, p.Source, p.Producer, r)
		if err != nil {
			panic(err)
		}
		bySlot[slot] = append(bySlot[slot], r)
		metaOf[r.ID] = RecMeta{Kind: kindByte(r.Kind), ID: r.ID, TS: int64(r.ObservedAt), Aux: aux}
	}

	// metric samples: round-robin over a seeded permutation of the project's series, so every series is written in turn.
	n := counts[0]
	for i := 0; i < n; i++ {
		idx := p.perm[p.cursor%len(p.perm)]
		p.cursor++
		s := p.series[idx]
		typ := "gauge"
		if s.counter {
			p.vals[idx] += float64(1 + p.rng.IntN(5))
			typ = "counter"
		} else {
			p.vals[idx] = math.Round(p.rng.Float64()*1e4) / 100
		}
		v := model.FloatBits(math.Float64bits(p.vals[idx]))
		r := model.Record{ID: p.nextID(), Kind: model.Metric, ObservedAt: model.UnixNano(spread(start, w, i, n)), Resource: p.Resource,
			Payload: model.Payload{Metric: &model.MetricPoint{Name: s.name, Labels: s.labels, SampleKind: "float", Value: &v, Unit: metricUnit, Type: typ}}}
		var aux [16]byte
		binary.BigEndian.PutUint32(aux[:], uint32(idx))
		add(r, aux)
	}

	// spans: traces of up to ten spans each, every span of a trace routes to the trace's slot.
	n = counts[1]
	for done := 0; done < n; {
		size := min(spansPerTrace, n-done)
		trace := ident(p.cfg.Seed, "trace", p.Index, p.traceSeq)
		p.traceSeq++
		root := spanID(p.cfg.Seed, p.Index, trace, 0)
		for k := 0; k < size; k++ {
			ts := spread(start, w, done+k, n)
			id := root
			var parent *model.SpanID
			kind, op, dep := "server", "request", ""
			if k > 0 {
				id = spanID(p.cfg.Seed, p.Index, trace, k)
				parent = &root
				kind, op, dep = "client", "db.execute", "postgres"
				if k%3 == 0 {
					kind, op, dep = "internal", "http.call", "api"
				}
			}
			dur := int64(2e6 + int64(k)*1e6)
			began := model.TraceClock{Wall: model.UnixNano(ts), Mono: model.MonoNano(ts - p.epoch()), Domain: p.domain, Uncertainty: 1000}
			end := model.TraceClock{Wall: model.UnixNano(ts + dur), Mono: model.MonoNano(ts - p.epoch() + dur), Domain: p.domain, Uncertainty: 1000}
			status := "ok"
			if k == size-1 && p.traceSeq%20 == 0 {
				status = "error"
			}
			sp := &model.Span{Trace: trace, ID: id, Parent: parent, Kind: kind, Operation: op, Start: began, End: &end, Status: status, Dependency: dep,
				Links: []model.SpanLink{}, SampleProbability: model.FloatBits(math.Float64bits(1)), SampleDecision: "keep"}
			var aux [16]byte
			copy(aux[:], trace[:])
			add(model.Record{ID: p.nextID(), Kind: model.SpanKind, ObservedAt: model.UnixNano(ts), Resource: p.Resource, Payload: model.Payload{Span: sp}}, aux)
		}
		done += size
	}

	// logs: registered template, allowed field values, one of the allowed stream labels.
	n = counts[2]
	codes, units := []string{"started", "retried", "completed", "skipped"}, []string{"api", "worker", "cron"}
	for i := 0; i < n; i++ {
		ts := model.UnixNano(spread(start, w, i, n))
		code, unit := codes[p.rng.IntN(len(codes))], units[p.rng.IntN(len(units))]
		lg := &model.LogRecord{Timestamp: &ts, Severity: "info", TemplateID: logTemplateID, TemplateRevision: 1,
			Fields:       map[string]model.Scalar{"code": scalar(code), "unit": scalar(unit)},
			Line:         "event " + code + " on " + unit,
			StreamLabels: model.Labels{{Name: "route", Value: fmt.Sprintf("r%d", p.rng.IntN(p.cfg.routeValues()))}},
			Metadata:     map[string]model.Scalar{}, SourceClass: "structured"}
		add(model.Record{ID: p.nextID(), Kind: model.Log, ObservedAt: ts, Resource: p.Resource, Payload: model.Payload{Log: lg}}, [16]byte{})
	}

	// errors: one occurrence per record with a three-frame in-app stack.
	n = counts[3]
	classes := []string{"app.TimeoutError", "app.DatabaseError", "app.InputError"}
	for i := 0; i < n; i++ {
		ts := spread(start, w, i, n)
		code := p.Policy.Codes[p.rng.IntN(len(p.Policy.Codes))]
		occ := ident(p.cfg.Seed, "occurrence", p.Index, p.recSeq+1)
		col := uint32(12)
		frames := []model.Frame{
			{Module: "app/handler", Function: "handleRequest", Artifact: "dist/handler.js", Line: 42, Column: &col, InApp: true},
			{Module: "app/service", Function: "load", Artifact: "dist/service.js", Line: 17, Column: &col, InApp: true},
			{Module: "app/db", Function: "query", Artifact: "dist/db.js", Line: 9, Column: &col, InApp: true}}
		er := &model.ErrorOccurrence{Occurrence: occ, Class: classes[p.rng.IntN(len(classes))], Mechanism: "manual", Frames: frames, Code: &code, Build: p.Resource.Build, Handled: true}
		add(model.Record{ID: p.nextID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(ts), Resource: p.Resource, Payload: model.Payload{Error: er}}, occ)
	}

	// job attempts: a run is two events (started, succeeded) of one attempt; both route to the run's slot.
	runs := counts[4] / 2
	for i := 0; i < runs; i++ {
		ts := spread(start, w, i, max(runs, 1))
		p.runSeq++
		job := ident(p.cfg.Seed, "job", p.Index, int(p.runSeq)%jobsPerProject)
		run, attempt := ident(p.cfg.Seed, "run", p.Index, p.runSeq), ident(p.cfg.Seed, "attempt", p.Index, p.runSeq)
		epoch := ident(p.cfg.Seed, "epoch", p.Index)
		term := model.UnixNano(ts + 5e6)
		for k, state := range []string{"started", "succeeded"} {
			ev := &model.JobAttemptEvent{Job: job, Run: run, Attempt: attempt, Schedule: fmt.Sprintf("schedule-%d", int(p.runSeq)%jobsPerProject), Ordinal: model.Uint64(p.runSeq), Epoch: epoch,
				Sequence: model.Uint64(k + 1), State: state, Observed: model.UnixNano(ts + int64(k)*5e6)}
			if state != "started" {
				ev.Terminal = &term
			}
			add(model.Record{ID: p.nextID(), Kind: model.JobAttempt, ObservedAt: model.UnixNano(ts + int64(k)*5e6), Resource: p.Resource, Payload: model.Payload{Job: ev}}, run)
		}
	}
	if counts[4]%2 == 1 {
		// an odd event count cannot form whole runs; the workload definition keeps the rate exact, so it is a configuration error.
		panic("job event count must be even: choose a window that makes the per-project job rate a whole number of runs")
	}

	slots := make([]int, 0, len(bySlot))
	for s := range bySlot {
		slots = append(slots, int(s))
	}
	sort.Ints(slots)
	var out []Prepared
	for _, s := range slots {
		recs := bySlot[uint16(s)]
		for chunk, from := 0, 0; from < len(recs); chunk, from = chunk+1, from+maxRecordsBatch {
			part := recs[from:min(from+maxRecordsBatch, len(recs))]
			b := model.Batch{Version: 1, Project: p.Project, Source: p.Source, Producer: p.Producer, ID: ident(p.cfg.Seed, "batch", p.Index, j, s, chunk, p.cfg.Epoch), PolicyRevision: 1, RouteSlot: uint16(s), Records: part}
			body, err := json.Marshal(b)
			if err != nil {
				panic(err)
			}
			pr := Prepared{Project: p.Index, Slot: uint16(s), ID: b.ID, Body: body}
			for _, r := range part {
				pr.Records = append(pr.Records, metaOf[r.ID])
			}
			out = append(out, pr)
		}
	}
	return out
}

// epoch is the monotonic-clock origin of this project's span clock domain: a fixed instant before the run.
func (p *Project) epoch() int64 { return 1_700_000_000_000_000_000 }

func spanID(seed uint64, project int, trace model.ID, k int) model.SpanID {
	id := ident(seed, "span", project, trace.String(), k)
	var s model.SpanID
	copy(s[:], id[:8])
	if s == (model.SpanID{}) {
		s[0] = 1
	}
	return s
}
