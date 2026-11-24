// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Two generators share the estate (estate.go):
//
//	Window           the STEADY stream: mixed records at IngestRate, event time = now, one flush window per project (the single-host
//	                 harness's generator, adapted: no shard label, traces that continue across windows)
//	SignalRound      the PRELOAD: signal-pure batches whose records are spread over a stretch of event time
//
// Both are deterministic for the seed and the project: the same Project built twice yields the same bytes, whatever the wall clock says.
// Nothing in a request body depends on WHEN the batch is generated except the event timestamps themselves, and those are fixed-width
// decimal strings, so the byte length of a batch does not depend on the event-time origin either (the calibration relies on this).

const (
	PreloadEpoch = 1 // preload batch, record and trace ids
	SteadyEpoch  = 2 // steady-run ids; disjoint from the preload's

	spansPerTrace   = 10
	jobsPerProject  = 5
	maxRecordsBatch = 512

	// Preload volume per project and step. A step is the finest slice of event time a round is built from.
	LogsPerStep   = 32 // log records per project per step
	TracesPerStep = 2  // whole traces of spansPerTrace spans per project per step

	preloadSampleTraces = 20 // trace samples kept per project over the 24 h

	// monoOrigin is the monotonic-clock origin of the span clock domain: far enough before any run that the span's mono_ns keeps the same
	// number of digits (18) for the next decades, so a batch's byte length does not change with the wall clock.
	monoOrigin = 1_000_000_000_000_000_000

	ControlProjectFirst = 97               // projects 97..99 carry the flip rule and its control series
	ControlEvery        = 30 * time.Second // spacing of one project's ctl_flag samples
	ControlTurn         = 300              // seconds: ctl_flag is 1 in even turns of this length, 0 in odd ones
)

// mixPerMille is the steady record mix (per thousand records): metric 60 %, span 20 %, log 12 %, error 3 %, job attempt 5 %. It sums
// to 1000. The index of an entry is the kind index of Prepared.ByKind.
var mixPerMille = []struct {
	Kind model.Kind
	PM   int
}{{model.Metric, 600}, {model.SpanKind, 200}, {model.Log, 120}, {model.ErrorKind, 30}, {model.JobAttempt, 50}}

// kindNames name the entries of mixPerMille in load-summary.json (records_acked_by_kind).
var kindNames = [5]string{"metric", "span", "log", "error", "job_attempt"}

func kindIndex(k model.Kind) int {
	for i, m := range mixPerMille {
		if m.Kind == k {
			return i
		}
	}
	return -1
}

var (
	logCodes  = []string{"started", "retried", "completed", "skipped"}
	logUnits  = []string{"api", "worker", "cron"}
	logCodeSc = []model.Scalar{scalar("started"), scalar("retried"), scalar("completed"), scalar("skipped")}
	logUnitSc = []model.Scalar{scalar("api"), scalar("worker"), scalar("cron")}
	noMeta    = map[string]model.Scalar{} // shared and never written: the product's structured metadata of every log record here is empty
)

// genState is the generator state of a Project that is not part of the estate.
type genState struct {
	ready   bool
	rng     [3]*rand.Rand // preload: one stream per PreloadSignals entry, so the order the signals are generated in changes nothing
	seq     [3]uint64     // preload: record sequence per signal
	logSlot []int32       // route index -> owner slot of its log stream, -1 = not yet computed
	logLbl  []model.Labels

	// steady: the trace in progress. A trace has spansPerTrace spans; a window that ends mid-trace leaves the rest to the next one.
	openK     int
	openTrace model.ID
	openRoot  model.SpanID
	openSlot  uint16
}

func sigIndex(s Signal) int {
	for i, v := range PreloadSignals {
		if v == s {
			return i
		}
	}
	panic("workload: not a preload signal: " + string(s))
}

func (p *Project) initGen() {
	g := &p.gen
	if g.ready {
		return
	}
	g.ready = true
	for i := range g.rng {
		g.rng[i] = rand.New(rand.NewPCG(p.cfg.Seed^uint64(i+1)<<56, uint64(p.Index)+1))
		g.seq[i] = p.cfg.Epoch << 32
	}
	routes := p.cfg.RoutesPerProject
	g.logSlot = make([]int32, routes)
	g.logLbl = make([]model.Labels, routes)
	for r := range g.logSlot {
		g.logSlot[r] = -1
		g.logLbl[r] = model.Labels{{Name: "route", Value: fmt.Sprintf("r%d", r)}}
	}
}

// A Prepared carries counts only: the gate verifies nothing record by record (the query role compares answers).

// Prepared is one encoded batch ready to be sent.
type Prepared struct {
	Project int
	Slot    uint16
	ID      model.ID
	Body    []byte
	Signal  Signal
	Records int
	ByKind  [5]int // records per mixPerMille entry
	MinTS   int64  // earliest and latest observed_at of the records, unix ns
	MaxTS   int64
	// Samples are the preloaded traces this batch holds whole (spans only): they exist for the query role once the batch is ACKed.
	Samples []TraceSample
}

// slotBucket collects the records of one route slot while a window or round is generated.
type slotBucket struct {
	recs   []model.Record
	traces []traceEnd // spans of a preload round: the end offsets of whole traces in recs; empty = records may be cut anywhere
}

type traceEnd struct {
	end    int
	sample *TraceSample
}

type buckets map[uint16]*slotBucket

func (b buckets) add(slot uint16, r model.Record) *slotBucket {
	bk := b[slot]
	if bk == nil {
		bk = &slotBucket{}
		b[slot] = bk
	}
	bk.recs = append(bk.recs, r)
	return bk
}

// pack freezes the buckets into batches: one batch per route slot and chunk, at most maxRecordsBatch records each, slots ascending. A
// bucket with trace ends is cut only between traces. id names the batch of (slot, chunk).
func (p *Project) pack(b buckets, sig Signal, id func(slot uint16, chunk int) model.ID) []Prepared {
	slots := make([]int, 0, len(b))
	for s := range b {
		slots = append(slots, int(s))
	}
	sort.Ints(slots)
	var out []Prepared
	for _, s := range slots {
		bk := b[uint16(s)]
		for chunk, from := 0, 0; from < len(bk.recs); chunk++ {
			to := min(from+maxRecordsBatch, len(bk.recs))
			if len(bk.traces) > 0 && to < len(bk.recs) {
				// the last whole trace that fits
				i := sort.Search(len(bk.traces), func(i int) bool { return bk.traces[i].end > to }) - 1
				if i < 0 || bk.traces[i].end <= from {
					panic("workload: a trace does not fit one batch")
				}
				to = bk.traces[i].end
			}
			part := bk.recs[from:to]
			bid := id(uint16(s), chunk)
			body, err := json.Marshal(model.Batch{Version: 1, Project: p.Project, Source: p.Source, Producer: p.Producer, ID: bid, PolicyRevision: 1, RouteSlot: uint16(s), Records: part})
			if err != nil {
				panic(err)
			}
			pr := Prepared{Project: p.Index, Slot: uint16(s), ID: bid, Body: body, Signal: sig, Records: len(part), MinTS: math.MaxInt64}
			for i := range part {
				pr.ByKind[kindIndex(part[i].Kind)]++
				ts := int64(part[i].ObservedAt)
				pr.MinTS, pr.MaxTS = min(pr.MinTS, ts), max(pr.MaxTS, ts)
			}
			for _, t := range bk.traces {
				if t.sample != nil && t.end > from && t.end <= to {
					pr.Samples = append(pr.Samples, *t.sample)
				}
			}
			out = append(out, pr)
			from = to
		}
	}
	return out
}

func spanID(seed uint64, project int, trace model.ID, k int) model.SpanID {
	id := ident(seed, "span", project, trace.String(), k)
	var s model.SpanID
	copy(s[:], id[:8])
	if s == (model.SpanID{}) {
		s[0] = 1
	}
	return s
}

func slotOf(p *Project, r model.Record) uint16 {
	slot, err := model.OwnerSlot(p.Org, p.Project, p.Source, p.Producer, r)
	if err != nil {
		panic(err)
	}
	return slot
}

// spanRecord builds span k of one trace (root first). The trace starts at start (unix ns); child k starts k ms later. All spans of a
// trace route to the same slot (the trace id is the owner key). The last span of every 20th trace ends with an error.
func (p *Project) spanRecord(trace model.ID, root model.SpanID, k int, start int64, failed bool, id model.ID) model.Record {
	sid := root
	var parent *model.SpanID
	kind, op, dep := "server", "request", ""
	if k > 0 {
		sid = spanID(p.cfg.Seed, p.Index, trace, k)
		parent = &root
		kind, op, dep = "client", "db.execute", "postgres"
		if k%3 == 0 {
			kind, op, dep = "internal", "http.call", "api"
		}
	}
	ts := start + int64(k)*1_000_000
	dur := int64(2e6 + int64(k)*1e6)
	if k == 0 {
		dur = 30_000_000
	}
	began := model.TraceClock{Wall: model.UnixNano(ts), Mono: model.MonoNano(ts - monoOrigin), Domain: p.domain, Uncertainty: 1000}
	end := model.TraceClock{Wall: model.UnixNano(ts + dur), Mono: model.MonoNano(ts - monoOrigin + dur), Domain: p.domain, Uncertainty: 1000}
	status := "ok"
	if failed && k == spansPerTrace-1 {
		status = "error"
	}
	sp := &model.Span{Trace: trace, ID: sid, Parent: parent, Kind: kind, Operation: op, Start: began, End: &end, Status: status, Dependency: dep,
		Links: []model.SpanLink{}, SampleProbability: model.FloatBits(math.Float64bits(1)), SampleDecision: "keep"}
	return model.Record{ID: id, Kind: model.SpanKind, ObservedAt: model.UnixNano(ts), Resource: p.Resource, Payload: model.Payload{Span: sp}}
}

func (p *Project) logSlotOf(route int) uint16 {
	g := &p.gen
	if g.logSlot[route] < 0 {
		lg := &model.LogRecord{Severity: "info", TemplateID: logTemplateID, TemplateRevision: 1, Fields: map[string]model.Scalar{}, StreamLabels: g.logLbl[route], Metadata: noMeta, SourceClass: "structured"}
		g.logSlot[route] = int32(slotOf(p, model.Record{Kind: model.Log, Resource: p.Resource, Payload: model.Payload{Log: lg}}))
	}
	return uint16(g.logSlot[route])
}

// frac is span*num/den without overflowing int64 for the sizes used here.
func frac(span, num, den int64) int64 { return span/den*num + span%den*num/den }

// stepBounds is the event-time interval [t0, t0+w) of step s when steps steps cover span from eventStart.
func stepBounds(s, steps int, eventStart time.Time, span time.Duration) (t0, w int64) {
	base, sp := eventStart.UnixNano(), span.Nanoseconds()
	a, b := base+frac(sp, int64(s), int64(steps)), base+frac(sp, int64(s)+1, int64(steps))
	return a, b - a
}

// SignalBatches is step `step` of `steps` of the signal-pure preload: it covers [eventStart+step*span/steps, +span/steps) of event time.
func (p *Project) SignalBatches(sig Signal, step, steps int, eventStart time.Time, span time.Duration) []Prepared {
	return p.SignalRound(sig, step, step+1, steps, eventStart, span)
}

// SignalRound is steps [from, to) of `steps` merged before the slot grouping: one batch per route slot and chunk of at most 512 records
// over the whole round. Merging is what keeps the batches few and fat (a metric step alone holds about one record per project and slot,
// so a batch per step would be thousands of one-record requests). Steps must be generated in order for a Project: counters and the
// per-signal random streams advance with them. Per step and project:
//
//	metric  one sample of every series (counters grow by 1..5 per step, gauges are random 0..100)
//	log     LogsPerStep records on the registered template, the route label drawn at random
//	span    TracesPerStep whole traces of spansPerTrace spans
//
// Event times of a step are spread over the step. Batch ids are ident(seed, "batch", project, signal, from, slot, chunk, epoch).
func (p *Project) SignalRound(sig Signal, from, to, steps int, eventStart time.Time, span time.Duration) []Prepared {
	p.initGen()
	si := sigIndex(sig)
	b := buckets{}
	next := func() model.ID {
		p.gen.seq[si]++
		return ident(p.cfg.Seed, "rec", p.Index, string(sig), p.gen.seq[si])
	}
	rng := p.gen.rng[si]
	for s := from; s < to; s++ {
		t0, w := stepBounds(s, steps, eventStart, span)
		switch sig {
		case SignalMetric:
			n := len(p.perm)
			for i, idx := range p.perm {
				sd := &p.series[idx]
				typ := "gauge"
				if sd.counter {
					p.vals[idx] += float64(1 + rng.IntN(5))
					typ = "counter"
				} else {
					p.vals[idx] = math.Round(rng.Float64()*1e4) / 100
				}
				v := model.FloatBits(math.Float64bits(p.vals[idx]))
				ts := t0 + w*int64(2*i+1)/int64(2*n)
				b.add(sd.slot, model.Record{ID: next(), Kind: model.Metric, ObservedAt: model.UnixNano(ts), Resource: p.Resource,
					Payload: model.Payload{Metric: &model.MetricPoint{Name: sd.name, Labels: sd.labels, SampleKind: "float", Value: &v, Unit: metricUnit, Type: typ}}})
			}
		case SignalLog:
			for i := range LogsPerStep {
				ts := model.UnixNano(t0 + w*int64(2*i+1)/int64(2*LogsPerStep))
				ci, ui, route := rng.IntN(len(logCodes)), rng.IntN(len(logUnits)), rng.IntN(p.cfg.RoutesPerProject)
				lg := &model.LogRecord{Timestamp: &ts, Severity: "info", TemplateID: logTemplateID, TemplateRevision: 1,
					Fields:       map[string]model.Scalar{"code": logCodeSc[ci], "unit": logUnitSc[ui]},
					Line:         "event " + logCodes[ci] + " on " + logUnits[ui],
					StreamLabels: p.gen.logLbl[route], Metadata: noMeta, SourceClass: "structured"}
				b.add(p.logSlotOf(route), model.Record{ID: next(), Kind: model.Log, ObservedAt: ts, Resource: p.Resource, Payload: model.Payload{Log: lg}})
			}
		case SignalSpan:
			total := TracesPerStep * steps
			every := max(1, total/preloadSampleTraces)
			for t := range TracesPerStep {
				seq := p.traceSeq - p.cfg.Epoch<<32
				trace := ident(p.cfg.Seed, "trace", p.Index, p.traceSeq)
				p.traceSeq++
				root := spanID(p.cfg.Seed, p.Index, trace, 0)
				start := t0 + w*int64(2*t+1)/int64(2*TracesPerStep)
				failed := p.traceSeq&0xffffffff%20 == 0
				var recs [spansPerTrace]model.Record
				for k := range recs {
					recs[k] = p.spanRecord(trace, root, k, start, failed, next())
				}
				slot := slotOf(p, recs[0])
				var bk *slotBucket
				for k := range recs {
					bk = b.add(slot, recs[k])
				}
				te := traceEnd{end: len(bk.recs)}
				if seq%uint64(every) == 0 {
					te.sample = &TraceSample{Project: p.Index, Trace: trace.String(), Service: p.Resource.Service.String(), StartNS: start, Slot: slot}
				}
				bk.traces = append(bk.traces, te)
			}
		default:
			panic("workload: not a preload signal: " + string(sig))
		}
	}
	return p.pack(b, sig, func(slot uint16, chunk int) model.ID {
		return ident(p.cfg.Seed, "batch", p.Index, string(sig), from, slot, chunk, p.cfg.Epoch)
	})
}

// windowCounts is how many records of each mix entry window j holds for one project: the cumulative target, so the totals are exact
// over any prefix of windows (no drift). rate is the mixed records per second over all projects of the estate. The job entry counts
// RUNS (a run is two events, started and succeeded, and both are emitted together), so a run is never cut: the event total is exact
// whenever the number of windows makes a whole number of runs (at the gate's 10 s window and 100 records/s over 100 projects that is a
// multiple of 4 windows; the other kinds are exact over 5 (log), 10 (error) and 1 windows).
func (p *Project) windowCounts(window time.Duration, rate int) [5]int {
	var out [5]int
	den := int64(p.cfg.Projects) * 1000
	for i, m := range mixPerMille {
		// thousandths of a record per window, accumulated exactly in integers
		milli := (int64(rate)*window.Milliseconds()*int64(m.PM) + den/2) / den
		if i == 4 {
			milli = (milli + 1) / 2
		}
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

// Window generates window [start, start+window) of this project's STEADY stream as slot-grouped batches, exactly as the SDK's queue
// freezes them: one batch per route slot, at most 512 records each. rate is the mixed records per second over all projects. Windows
// must be generated in order (j = 0, 1, 2, ...). Spans form traces of spansPerTrace that continue across windows.
func (p *Project) Window(j int, start time.Time, window time.Duration, rate int) []Prepared {
	p.initGen()
	counts := p.windowCounts(window, rate)
	b := buckets{}
	add := func(r model.Record) { b.add(slotOf(p, r), r) }

	// metric samples: round-robin over a seeded permutation of the project's series, so every series is written in turn.
	n := counts[0]
	for i := range n {
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
		b.add(s.slot, model.Record{ID: p.nextID(), Kind: model.Metric, ObservedAt: model.UnixNano(spread(start, window, i, n)), Resource: p.Resource,
			Payload: model.Payload{Metric: &model.MetricPoint{Name: s.name, Labels: s.labels, SampleKind: "float", Value: &v, Unit: metricUnit, Type: typ}}})
	}

	// spans: a trace is spansPerTrace spans, root first; a window ends wherever its span count does and the trace goes on in the next.
	g := &p.gen
	n = counts[1]
	for i := range n {
		if g.openK == 0 {
			g.openTrace = ident(p.cfg.Seed, "trace", p.Index, p.traceSeq)
			p.traceSeq++
			g.openRoot = spanID(p.cfg.Seed, p.Index, g.openTrace, 0)
		}
		failed := p.traceSeq&0xffffffff%20 == 0
		r := p.spanRecord(g.openTrace, g.openRoot, g.openK, spread(start, window, i, n)-int64(g.openK)*1_000_000, failed, p.nextID())
		if g.openK == 0 {
			g.openSlot = slotOf(p, r)
		}
		b.add(g.openSlot, r)
		g.openK = (g.openK + 1) % spansPerTrace
	}

	// logs: registered template, allowed field values, one of the allowed stream labels.
	n = counts[2]
	for i := range n {
		ts := model.UnixNano(spread(start, window, i, n))
		ci, ui, route := p.rng.IntN(len(logCodes)), p.rng.IntN(len(logUnits)), p.rng.IntN(p.cfg.RoutesPerProject)
		lg := &model.LogRecord{Timestamp: &ts, Severity: "info", TemplateID: logTemplateID, TemplateRevision: 1,
			Fields:       map[string]model.Scalar{"code": logCodeSc[ci], "unit": logUnitSc[ui]},
			Line:         "event " + logCodes[ci] + " on " + logUnits[ui],
			StreamLabels: g.logLbl[route], Metadata: noMeta, SourceClass: "structured"}
		b.add(p.logSlotOf(route), model.Record{ID: p.nextID(), Kind: model.Log, ObservedAt: ts, Resource: p.Resource, Payload: model.Payload{Log: lg}})
	}

	// errors: one occurrence per record with a three-frame in-app stack.
	n = counts[3]
	classes := []string{"app.TimeoutError", "app.DatabaseError", "app.InputError"}
	for i := range n {
		ts := spread(start, window, i, n)
		code := p.Policy.Codes[p.rng.IntN(len(p.Policy.Codes))]
		occ := ident(p.cfg.Seed, "occurrence", p.Index, p.recSeq+1)
		col := uint32(12)
		frames := []model.Frame{
			{Module: "app/handler", Function: "handleRequest", Artifact: "dist/handler.js", Line: 42, Column: &col, InApp: true},
			{Module: "app/service", Function: "load", Artifact: "dist/service.js", Line: 17, Column: &col, InApp: true},
			{Module: "app/db", Function: "query", Artifact: "dist/db.js", Line: 9, Column: &col, InApp: true}}
		er := &model.ErrorOccurrence{Occurrence: occ, Class: classes[p.rng.IntN(len(classes))], Mechanism: "manual", Frames: frames, Code: &code, Build: p.Resource.Build, Handled: true}
		add(model.Record{ID: p.nextID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(ts), Resource: p.Resource, Payload: model.Payload{Error: er}})
	}

	// job attempts: a run is two events (started, succeeded) of one attempt; both route to the run's slot.
	runs := counts[4]
	for i := range runs {
		ts := spread(start, window, i, runs)
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
			add(model.Record{ID: p.nextID(), Kind: model.JobAttempt, ObservedAt: model.UnixNano(ts + int64(k)*5e6), Resource: p.Resource, Payload: model.Payload{Job: ev}})
		}
	}

	return p.pack(b, SignalMixed, func(slot uint16, chunk int) model.ID {
		return ident(p.cfg.Seed, "batch", p.Index, j, slot, chunk, p.cfg.Epoch)
	})
}

// ctlValue is the value of ctl_flag at unix second t: 1 in the even ControlTurn-second turns, 0 in the odd ones.
func ctlValue(unixSec int64) float64 {
	if (unixSec/ControlTurn)%2 == 0 {
		return 1
	}
	return 0
}

// IsControl says whether project p carries a flip rule and therefore a control series.
func IsControl(p int) bool { return p >= ControlProjectFirst }

// ControlBatch is the one-record request carrying ctl_flag{route=r0} sampled at instant at (sample number j of this project): the
// flip rules fire when it is 1 and recover when it is 0. A control request is its own request (signal "control") so that a lost
// slot cannot hide behind a mixed batch.
func (p *Project) ControlBatch(j int, at time.Time) Prepared {
	v := model.FloatBits(math.Float64bits(ctlValue(at.Unix())))
	ts := at.UnixNano()
	rec := model.Record{ID: ident(p.cfg.Seed, "ctl-rec", p.Index, p.cfg.Epoch, j), Kind: model.Metric, ObservedAt: model.UnixNano(ts), Resource: p.Resource,
		Payload: model.Payload{Metric: &model.MetricPoint{Name: ctlMetric, Labels: model.Labels{{Name: "route", Value: "r0"}}, SampleKind: "float", Value: &v, Unit: metricUnit, Type: "gauge"}}}
	slot := slotOf(p, rec)
	bid := ident(p.cfg.Seed, "ctl-batch", p.Index, p.cfg.Epoch, j)
	body, err := json.Marshal(model.Batch{Version: 1, Project: p.Project, Source: p.Source, Producer: p.Producer, ID: bid, PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{rec}})
	if err != nil {
		panic(err)
	}
	pr := Prepared{Project: p.Index, Slot: slot, ID: bid, Body: body, Signal: SignalControl, Records: 1, MinTS: ts, MaxTS: ts}
	pr.ByKind[0] = 1
	return pr
}
