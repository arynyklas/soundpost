// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func decode(t *testing.T, body []byte) model.Batch {
	t.Helper()
	var b model.Batch
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func preCfg() Config {
	c := DefaultConfig()
	c.Epoch = PreloadEpoch
	return c
}

func steadyCfg() Config {
	c := DefaultConfig()
	c.Epoch = SteadyEpoch
	return c
}

var testStart = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// checkBatch asserts what the product requires of a batch: at most 512 records, every record of the batch's slot, the batch belongs to
// the project, and every record passes the product's own validation against the project's policy. It returns the decoded batch.
func checkBatch(t *testing.T, p *Project, pr Prepared) model.Batch {
	t.Helper()
	b := decode(t, pr.Body)
	if len(b.Records) == 0 || len(b.Records) > maxRecordsBatch || len(b.Records) != pr.Records {
		t.Fatalf("batch of %d records (Prepared says %d)", len(b.Records), pr.Records)
	}
	if b.Project != p.Project || b.Source != p.Source || b.Producer != p.Producer || b.ID != pr.ID || b.RouteSlot != pr.Slot || pr.Project != p.Index {
		t.Fatal("batch identity does not match the project")
	}
	var byKind [5]int
	for i := range b.Records {
		r := b.Records[i]
		slot, err := model.OwnerSlot(p.Org, p.Project, p.Source, p.Producer, r)
		if err != nil || slot != pr.Slot {
			t.Fatalf("record %d routes to slot %d (%v), batch is slot %d", i, slot, err, pr.Slot)
		}
		if err := model.ValidateRecord(&r, p.Policy); err != nil {
			t.Fatalf("record %d (%s) does not validate: %v", i, r.Kind, err)
		}
		byKind[kindIndex(r.Kind)]++
		if ts := int64(r.ObservedAt); ts < pr.MinTS || ts > pr.MaxTS {
			t.Fatalf("record time %d outside [%d, %d]", ts, pr.MinTS, pr.MaxTS)
		}
	}
	if byKind != pr.ByKind {
		t.Fatalf("ByKind %v, records say %v", pr.ByKind, byKind)
	}
	return b
}

func kindOf(sig Signal) model.Kind {
	switch sig {
	case SignalMetric:
		return model.Metric
	case SignalLog:
		return model.Log
	}
	return model.SpanKind
}

func TestPreloadBatchesAreSignalPureSingleSlotAndAdmissible(t *testing.T) {
	const steps = 120
	span := SteadyS * time.Second
	for _, pi := range []int{0, 57, 99} {
		for _, sig := range PreloadSignals {
			p := NewProject(preCfg(), pi)
			var batches []Prepared
			for from := 0; from < steps; from += 40 {
				batches = append(batches, p.SignalRound(sig, from, from+40, steps, testStart, span)...)
			}
			recs := 0
			slots := map[uint16]bool{}
			traces := map[model.ID]int{}
			for _, pr := range batches {
				b := checkBatch(t, p, pr)
				if pr.Signal != sig {
					t.Fatalf("batch signal %s, want %s", pr.Signal, sig)
				}
				inBatch := map[model.ID]int{}
				for _, r := range b.Records {
					if r.Kind != kindOf(sig) {
						t.Fatalf("%s batch holds a %s record", sig, r.Kind)
					}
					if sig == SignalSpan {
						inBatch[r.Payload.Span.Trace]++
					}
				}
				for tr, n := range inBatch {
					if n != spansPerTrace {
						t.Fatalf("trace %s is split: %d spans in one batch", tr, n)
					}
					traces[tr] += n
				}
				recs += pr.Records
				slots[pr.Slot] = true
			}
			want := map[Signal]int{SignalMetric: steps * len(p.series), SignalLog: steps * LogsPerStep, SignalSpan: steps * TracesPerStep * spansPerTrace}[sig]
			if recs != want {
				t.Fatalf("project %d %s: %d records, want %d", pi, sig, recs, want)
			}
			if sig == SignalSpan && len(traces) != steps*TracesPerStep {
				t.Fatalf("%d traces, want %d", len(traces), steps*TracesPerStep)
			}
			if len(slots) == 0 || sig == SignalLog && len(slots) > p.cfg.RoutesPerProject {
				t.Fatalf("%s spread over %d slots", sig, len(slots))
			}
		}
	}
}

func TestPreloadIsDeterministicForTheSeedAndIndependentOfTheClock(t *testing.T) {
	span := SteadyS * time.Second
	for _, sig := range PreloadSignals {
		a, b, c := NewProject(preCfg(), 3), NewProject(preCfg(), 3), NewProject(preCfg(), 3)
		later := testStart.Add(400 * 24 * time.Hour) // another origin: same bytes except the timestamps' digits, which are as long
		for from := 0; from < 60; from += 20 {
			x := a.SignalRound(sig, from, from+20, 60, testStart, span)
			y := b.SignalRound(sig, from, from+20, 60, testStart, span)
			z := c.SignalRound(sig, from, from+20, 60, later, span)
			if len(x) != len(y) || len(x) != len(z) || len(x) == 0 {
				t.Fatalf("%s round %d: %d / %d / %d batches", sig, from, len(x), len(y), len(z))
			}
			for i := range x {
				if !bytes.Equal(x[i].Body, y[i].Body) || x[i].ID != y[i].ID {
					t.Fatalf("%s round %d batch %d differs between two builds of the same seed", sig, from, i)
				}
				if len(x[i].Body) != len(z[i].Body) || x[i].ID != z[i].ID {
					t.Fatalf("%s round %d batch %d: byte length depends on the event-time origin (%d vs %d)", sig, from, i, len(x[i].Body), len(z[i].Body))
				}
			}
		}
	}
	other := DefaultConfig()
	other.Seed++
	other.Epoch = PreloadEpoch
	if bytes.Equal(NewProject(preCfg(), 3).SignalRound(SignalLog, 0, 2, 10, testStart, span)[0].Body, NewProject(other, 3).SignalRound(SignalLog, 0, 2, 10, testStart, span)[0].Body) {
		t.Fatal("another seed gave the same bytes")
	}
}

func TestSteadyWindowIsDeterministicForTheSeed(t *testing.T) {
	a, b := NewProject(steadyCfg(), 8), NewProject(steadyCfg(), 8)
	for j := range 40 {
		x := a.Window(j, testStart.Add(time.Duration(j)*steadyWindow), steadyWindow, IngestRate)
		y := b.Window(j, testStart.Add(time.Duration(j)*steadyWindow), steadyWindow, IngestRate)
		if len(x) != len(y) {
			t.Fatalf("window %d: %d vs %d batches", j, len(x), len(y))
		}
		for i := range x {
			if !bytes.Equal(x[i].Body, y[i].Body) {
				t.Fatalf("window %d batch %d differs", j, i)
			}
		}
	}
}

func TestStepBytesAreStable(t *testing.T) {
	span := SteadyS * time.Second
	const steps = 300
	for _, sig := range PreloadSignals {
		p := NewProject(preCfg(), 11)
		var per []int
		for s := 0; s < steps; s += 30 {
			n := 0
			for _, pr := range p.SignalRound(sig, s, s+30, steps, testStart, span) {
				n += len(pr.Body)
			}
			per = append(per, n)
		}
		lo, hi := per[0], per[0]
		for _, n := range per {
			lo, hi = min(lo, n), max(hi, n)
		}
		if float64(hi-lo) > 0.02*float64(hi) {
			t.Fatalf("%s: bytes per 30 steps vary from %d to %d (> 2 %%)", sig, lo, hi)
		}
	}
}

func TestSignalBatchesIsOneStepOfARound(t *testing.T) {
	span := SteadyS * time.Second
	a, b := NewProject(preCfg(), 4), NewProject(preCfg(), 4)
	x := a.SignalBatches(SignalMetric, 0, 100, testStart, span)
	y := b.SignalRound(SignalMetric, 0, 1, 100, testStart, span)
	if len(x) != len(y) || len(x) == 0 || !bytes.Equal(x[0].Body, y[0].Body) {
		t.Fatal("SignalBatches is not the one-step round")
	}
	// one step of one project holds one sample of every series, so its batches are the series grouped by slot
	n := 0
	for _, pr := range x {
		n += pr.Records
	}
	if n != len(a.series) {
		t.Fatalf("a metric step holds %d records, the project has %d series", n, len(a.series))
	}
	// the step covers [start, start+span/steps)
	w := span / 100
	for _, pr := range x {
		if pr.MinTS < testStart.UnixNano() || pr.MaxTS >= testStart.Add(w).UnixNano() {
			t.Fatalf("step 0 record outside its interval: [%d, %d]", pr.MinTS, pr.MaxTS)
		}
	}
}

func TestSteadyMixIsExactOver1000Windows(t *testing.T) {
	cfg := steadyCfg()
	for _, pi := range []int{0, 98} {
		p := NewProject(cfg, pi)
		var total [5]int
		var prefix [5]int
		for j := range 1000 {
			start := testStart.Add(time.Duration(j) * steadyWindow)
			batches := p.Window(j, start, steadyWindow, IngestRate)
			for _, pr := range batches {
				if pr.Signal != SignalMixed {
					t.Fatalf("steady batch signal %s", pr.Signal)
				}
				if pr.MinTS < start.UnixNano() || pr.MaxTS >= start.Add(steadyWindow).UnixNano() {
					t.Fatalf("window %d: record outside [start, start+window)", j)
				}
				for k, n := range pr.ByKind {
					total[k] += n
					prefix[k] += n
				}
				if j%97 == 0 {
					checkBatch(t, p, pr)
				}
			}
			// the totals never drift: within one record (one run = two events for jobs) of the exact cumulative target at every prefix
			for k, m := range mixPerMille {
				exact := float64(j+1) * float64(IngestRate) / float64(cfg.Projects) * steadyWindow.Seconds() * float64(m.PM) / 1000
				slack := 1.0
				if k == 4 {
					slack = 2
				}
				if math.Abs(float64(prefix[k])-exact) > slack {
					t.Fatalf("window %d kind %s: %d records, exact %.2f", j, kindNames[k], prefix[k], exact)
				}
			}
		}
		// 1000 windows of 10 s at 1 record/s/project
		if total != [5]int{6000, 2000, 1200, 300, 500} {
			t.Fatalf("project %d: totals over 1000 windows %v, want [6000 2000 1200 300 500]", pi, total)
		}
	}
}

// Every trace the steady stream finishes has ten spans, a root first, whatever window boundaries it crosses.
func TestSteadyTracesAreWholeAcrossWindows(t *testing.T) {
	p := NewProject(steadyCfg(), 5)
	spans := map[model.ID][]model.Span{}
	for j := range 1000 {
		for _, pr := range p.Window(j, testStart.Add(time.Duration(j)*steadyWindow), steadyWindow, IngestRate) {
			for _, r := range decode(t, pr.Body).Records {
				if r.Kind == model.SpanKind {
					spans[r.Payload.Span.Trace] = append(spans[r.Payload.Span.Trace], *r.Payload.Span)
				}
			}
		}
	}
	whole, errors := 0, 0
	for tr, ss := range spans {
		if len(ss) == spansPerTrace {
			whole++
			roots := 0
			for _, s := range ss {
				if s.Parent == nil {
					roots++
				}
				if s.Status == "error" {
					errors++
				}
			}
			if roots != 1 {
				t.Fatalf("trace %s has %d roots", tr, roots)
			}
		} else if len(ss) > spansPerTrace {
			t.Fatalf("trace %s has %d spans", tr, len(ss))
		}
	}
	if whole != 200 || len(spans) != 200 {
		t.Fatalf("%d whole traces of %d, want 200 of 200", whole, len(spans))
	}
	if errors != 10 {
		t.Fatalf("%d traces ended with an error span, want 1 in 20 of 200 = 10", errors)
	}
}

func TestControlSamplesFollowTheClock(t *testing.T) {
	p := NewProject(steadyCfg(), 98)
	if !IsControl(97) || !IsControl(99) || IsControl(96) {
		t.Fatal("control projects are 97..99")
	}
	base := int64(1_800_000_000) / 600 * 600 // an even 300 s turn starts here
	seen := map[model.ID]bool{}
	for j := range 40 {
		at := time.Unix(base, 0).Add(time.Duration(j) * ControlEvery)
		pr := p.ControlBatch(j, at)
		if pr.Signal != SignalControl || pr.Records != 1 || seen[pr.ID] {
			t.Fatalf("control batch %d: signal %s records %d", j, pr.Signal, pr.Records)
		}
		seen[pr.ID] = true
		b := checkBatch(t, p, pr)
		m := b.Records[0].Payload.Metric
		if m.Name != "ctl_flag" || len(m.Labels) != 1 || m.Labels[0].Name != "route" || m.Labels[0].Value != "r0" {
			t.Fatalf("control series %s %v", m.Name, m.Labels)
		}
		if int64(b.Records[0].ObservedAt) != at.UnixNano() {
			t.Fatal("control sample is not stamped with its own instant")
		}
		got := math.Float64frombits(uint64(*m.Value))
		// samples 0..9 are the first 300 s (value 1), 10..19 the next (0), 20..29 (1), 30..39 (0); the value is a function of the instant
		want := 1.0
		if (j/10)%2 == 1 {
			want = 0
		}
		if got != want || got != ctlValue(at.Unix()) {
			t.Fatalf("sample %d at %d: ctl_flag %v, want %v", j, at.Unix(), got, want)
		}
	}
}

func TestPreloadTraceSamplesSpreadOverTheEventRange(t *testing.T) {
	span := SteadyS * time.Second
	const steps = 600
	p := NewProject(preCfg(), 6)
	var samples []TraceSample
	traces := map[string]bool{}
	for _, pr := range p.SignalRound(SignalSpan, 0, steps, steps, testStart, span) {
		samples = append(samples, pr.Samples...)
		for _, r := range decode(t, pr.Body).Records {
			traces[r.Payload.Span.Trace.String()] = true
		}
	}
	if len(samples) != preloadSampleTraces {
		t.Fatalf("%d samples, want %d", len(samples), preloadSampleTraces)
	}
	lo, hi, low, high := int64(math.MaxInt64), int64(0), 0, 0
	for _, s := range samples {
		if s.Project != 6 || s.Service != p.Resource.Service.String() || !traces[s.Trace] || len(s.Trace) != 32 {
			t.Fatalf("bad sample %+v", s)
		}
		lo, hi = min(lo, s.StartNS), max(hi, s.StartNS)
		if s.Slot < 32 {
			low++
		} else {
			high++
		}
	}
	if low == 0 || high == 0 {
		t.Fatalf("samples sit on one side of slot 32: %d below, %d above", low, high)
	}
	if lo > testStart.Add(span/10).UnixNano() || hi < testStart.Add(span*9/10).UnixNano() {
		t.Fatal("trace samples do not spread over the 24 h")
	}
}

func TestBudgetEndsAtTheFirstBatchBoundaryAtOrAboveTheTarget(t *testing.T) {
	b := newBudget(1000, 4)
	for i := range 4 {
		if !b.acquire(300) {
			t.Fatalf("acquire %d refused", i)
		}
	}
	// 1200 committed: the fifth must wait; a failure frees 300 and lets it through
	got := make(chan bool, 1)
	go func() { got <- b.acquire(300) }()
	select {
	case <-got:
		t.Fatal("a request was started past the target")
	case <-time.After(50 * time.Millisecond):
	}
	b.done(300, false)
	if !<-got {
		t.Fatal("a failed request's bytes were not given back")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); b.done(300, true) }()
	}
	wg.Wait()
	if b.acquire(300) {
		t.Fatal("acquire succeeded with the target ACKed")
	}
	if b.acked != 1200 {
		t.Fatalf("acked %d", b.acked)
	}
}

// TestCalibrationReachesTheTargetOverTwentyFourHours is the dry run of the preload: no network. By default at 64 MiB per signal (fast);
// SOUNDPOST_QUERIES_FULL=1 runs the real 1 GiB.
func TestCalibrationReachesTheTargetOverTwentyFourHours(t *testing.T) {
	target := int64(64 << 20)
	if os.Getenv("SOUNDPOST_QUERIES_FULL") == "1" {
		target = InputBytesPerSignal
	}
	span := SteadyS * time.Second
	for _, sig := range PreloadSignals {
		sp := calibrate(preCfg(), sig, target, testStart.Add(-span), span, 4)
		t.Logf("%s: steps=%d rounds=%d batches=%d records=%d bytes=%d avg %.0f records/batch range %.3f h, %.1f MB/s", sig, sp.Steps, sp.Rounds, sp.Batches, sp.Records, sp.Bytes,
			float64(sp.Records)/float64(sp.Batches), sp.RangeH, sp.MBPerSec)
		if sp.Bytes < target || sp.Bytes > target+max(target/calHiDiv, 2*sp.Bytes/int64(sp.Steps)) {
			t.Fatalf("%s: %d bytes for a target of %d", sig, sp.Bytes, target)
		}
		if math.Abs(sp.RangeH-24) > 0.02*24 {
			t.Fatalf("%s: event range %.3f h, want 24 h +- 2 %%", sig, sp.RangeH)
		}
		if sp.Records/sp.Batches > maxRecordsBatch {
			t.Fatalf("%s: %d records per batch on average", sig, sp.Records/sp.Batches)
		}
		if target == InputBytesPerSignal && sp.Records/sp.Batches < 100 {
			t.Fatalf("%s: only %d records per batch on average, the contract wants few fat batches", sig, sp.Records/sp.Batches)
		}
		// the stream is what the calibration counted: a second pass at the same step count gives the same bytes
		again := dryPass(preCfg(), sig, sp.Steps, sp.Round, testStart.Add(-span), span, 2)
		if again.Bytes != sp.Bytes || again.Batches != sp.Batches {
			t.Fatalf("%s: the dry pass is not repeatable: %d/%d vs %d/%d", sig, again.Bytes, again.Batches, sp.Bytes, sp.Batches)
		}
	}
}
