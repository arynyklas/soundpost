// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Role `ingest`: PRELOADS exactly >= InputBytesPerSignal ACKed request-body bytes per signal (signal by signal, as fast as the server takes
// it), then ingests the steady mixed stream at IngestRate for the whole run. Files (under --out):
//
//	preload/acks.csv.gz       AcksHeader, one line per preload request (signal metric|log|span)
//	preload/summary.json      PreloadSummary
//	ingest/acks.csv.gz        AcksHeader, one line per steady request (signal mixed|control); times since T0
//	ingest/load-summary.json  IngestSummary
//	ingest/net-series.jsonl   link use of this host, every 10 s (the whole role lifetime)
//	ingest/host.json          HostFacts
//
// Status column: the HTTP status of the answer; 0 = transport failure or the 40 s timeout; 520 = HTTP 200 whose body is not the receipt of the
// batch sent (never counted as an ACK); -1 = a steady request the generator shed (more than steadyMaxInFlight in flight; open loop).

const (
	requestTimeout    = 40 * time.Second // TimeoutLatencyUS
	steadyMaxInFlight = 6000
	statusBadReceipt  = 520
	statusShed        = -1
	ingestUserAgent   = "soundpost-overhead-queries"
	ingestPath        = "/ingest/v1/batches" // the product's ingest route (internal/httpapi/ingest.go)

	// calibration: the preload of a signal must end within [target+calLo, target+calHi] bytes of the target, so that the stream the generator
	// holds is the stream the server takes and the last batch is the one that crosses 1 GiB.
	calLoDiv  = 2000 // target/2000 = 0.05 %
	calHiDiv  = 100  // target/100 = 1 %
	calMaxIt  = 10
	calProbe  = 40  // steps of the probe that gives the first bytes-per-step figure
	maxFailed = 200 // consecutive failed preload requests that end the preload (the server is not taking data)
)

// roundSteps is the merge factor of a signal (steps per round, see SignalRound): metrics and logs are merged so that a (project, slot)
// batch holds about 250 records; spans are one round over the whole preload because a project holds only ~120 spans per slot in all.
func roundSteps(sig Signal, steps int) int {
	switch sig {
	case SignalMetric:
		return min(200, steps)
	case SignalLog:
		return min(24, steps)
	}
	return steps
}

// sigPlan is the calibrated shape of the preload of one signal.
type sigPlan struct {
	Signal   Signal  `json:"signal"`
	Steps    int     `json:"steps"`
	Round    int     `json:"round_steps"`
	Rounds   int     `json:"rounds"`
	Batches  int64   `json:"batches"`
	Records  int64   `json:"records"`
	Bytes    int64   `json:"bytes"`
	Passes   int     `json:"passes"`
	Seconds  float64 `json:"generation_seconds"`
	RangeH   float64 `json:"event_range_hours"`
	MBPerSec float64 `json:"generation_mb_per_s"`
}

func mainRounds(steps, round int) [][2]int {
	var out [][2]int
	for from := 0; from < steps; from += round {
		out = append(out, [2]int{from, min(from+round, steps)})
	}
	return out
}

// allRounds are the main rounds and, behind them, extension rounds of at most 2 % more steps: the stream the preload draws on when
// requests fail and the main rounds alone do not reach the target. Extension rounds are generated only when they are needed.
func (sp sigPlan) allRounds() [][2]int {
	out := mainRounds(sp.Steps, sp.Round)
	ext := max(1, sp.Steps/100)
	for from := sp.Steps; from < sp.Steps+sp.Steps/50; from += ext {
		out = append(out, [2]int{from, min(from+ext, sp.Steps+sp.Steps/50)})
	}
	return out
}

// generate builds the batches of rounds for every project, par projects at a time, and calls emit for each one; it stops when emit says so
// or ctx ends. Rounds are barriers: round r+1 starts when every project has handed over round r.
func generate(ctx context.Context, cfg Config, sig Signal, steps int, rounds [][2]int, eventStart time.Time, span time.Duration, par int, emit func(Prepared) bool) {
	projects := make([]*Project, cfg.Projects)
	var bw sync.WaitGroup
	for p := range projects {
		bw.Add(1)
		go func() { defer bw.Done(); projects[p] = NewProject(cfg, p) }()
	}
	bw.Wait()
	sem := make(chan struct{}, par)
	for _, rd := range rounds {
		var wg sync.WaitGroup
		var stop atomic.Bool
		for _, pj := range projects {
			if stop.Load() || ctx.Err() != nil {
				break
			}
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				for _, pr := range pj.SignalRound(sig, rd[0], rd[1], steps, eventStart, span) {
					if ctx.Err() != nil || !emit(pr) {
						stop.Store(true)
						return
					}
				}
			}()
		}
		wg.Wait()
		if stop.Load() || ctx.Err() != nil {
			return
		}
	}
}

// dryPass generates the main rounds of a plan and counts what it would send: no network.
func dryPass(cfg Config, sig Signal, steps, round int, es time.Time, span time.Duration, par int) (sp sigPlan) {
	sp = sigPlan{Signal: sig, Steps: steps, Round: round, Rounds: len(mainRounds(steps, round))}
	var mu sync.Mutex
	minTS, maxTS := int64(math.MaxInt64), int64(0)
	began := time.Now()
	generate(context.Background(), cfg, sig, steps, mainRounds(steps, round), es, span, par, func(pr Prepared) bool {
		mu.Lock()
		sp.Batches++
		sp.Records += int64(pr.Records)
		sp.Bytes += int64(len(pr.Body))
		minTS, maxTS = min(minTS, pr.MinTS), max(maxTS, pr.MaxTS)
		mu.Unlock()
		return true
	})
	sp.Seconds = time.Since(began).Seconds()
	sp.MBPerSec = float64(sp.Bytes) / 1e6 / max(sp.Seconds, 1e-9)
	sp.RangeH = float64(maxTS-minTS) / float64(time.Hour)
	return sp
}

// calibrate finds the number of steps that makes the preload of sig end within [target+target/2000, target+max(target/100, two steps)]
// bytes. The byte length of a batch does not depend on the event-time origin, so the dry passes measure the real stream exactly; the first
// pass is a short probe whose bytes per step (a little high: its batches are small) gives the first guess.
func calibrate(cfg Config, sig Signal, target int64, es time.Time, span time.Duration, par int) sigPlan {
	probe := dryPass(cfg, sig, calProbe, roundSteps(sig, calProbe), es, span, par)
	perStep := float64(probe.Bytes) / calProbe
	steps := int(math.Ceil(float64(target) / perStep * 1.005))
	passes := 1
	lo := target + target/calLoDiv
	for it := 0; it < calMaxIt; it++ {
		sp := dryPass(cfg, sig, steps, roundSteps(sig, steps), es, span, par)
		passes++
		sp.Passes = passes
		fmt.Fprintf(os.Stderr, "queries: calibrate %s: steps=%d bytes=%d (%+.3f %% of target) in %.1f s\n", sig, steps, sp.Bytes, 100*(float64(sp.Bytes)/float64(target)-1), sp.Seconds)
		hi := target + max(target/calHiDiv, 2*sp.Bytes/int64(steps))
		if sp.Bytes >= lo && sp.Bytes <= hi {
			return sp
		}
		next := int(math.Ceil(float64(steps) * float64(target) * 1.004 / float64(sp.Bytes)))
		if next == steps {
			if sp.Bytes < lo {
				next++
			} else {
				next--
			}
		}
		steps = next
	}
	fatalf("calibrate %s: no step count reaches [%d, ...] bytes after %d passes", sig, lo, calMaxIt)
	return sigPlan{}
}

// budget is the closed loop of the preload: at most `workers` requests in flight, and no request is started once the bytes ACKed plus the
// bytes in flight already make the target. The signal therefore ends at the first batch boundary where the ACKed total is >= the target
// and overshoots by less than one batch (< 1 MiB); a failed request gives its bytes back.
type budget struct {
	mu                       sync.Mutex
	cond                     *sync.Cond
	target, committed, acked int64
	inflight, workers        int
}

func newBudget(target int64, workers int) *budget {
	b := &budget{target: target, workers: workers}
	b.cond = sync.NewCond(&b.mu)
	return b
}

// acquire waits for a free worker and bytes still to be committed; false = the target is ACKed, send nothing more.
func (b *budget) acquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if b.acked >= b.target {
			return false
		}
		if b.committed < b.target && b.inflight < b.workers {
			b.committed += n
			b.inflight++
			return true
		}
		b.cond.Wait()
	}
}

func (b *budget) done(n int64, ok bool) {
	b.mu.Lock()
	b.inflight--
	if ok {
		b.acked += n
	} else {
		b.committed -= n
	}
	b.mu.Unlock()
	b.cond.Broadcast()
}

// post sends one batch. status 0 = transport failure; the body of the answer is returned for refusals and receipts.
func post(client *http.Client, addr, cred string, body []byte) (status int, resp []byte) {
	req, err := http.NewRequest(http.MethodPost, "https://"+addr+ingestPath, bytes.NewReader(body))
	if err != nil {
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set("User-Agent", ingestUserAgent)
	r, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	resp, err = io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return 0, nil
	}
	return r.StatusCode, resp
}

// acked says whether an HTTP 200 answer is the receipt of batch id.
func acked(resp []byte, id model.ID) bool {
	var rc model.Receipt
	return model.StrictJSON(resp, &rc) == nil && rc.Version != 0 && rc.BatchID == id
}

func newClient(ca string) *http.Client {
	c := tlsClient(ca, requestTimeout)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func credentials(plan Plan) map[int]string {
	creds := map[int]string{}
	for _, s := range plan.Sources {
		creds[s.Project] = s.Credential
	}
	return creds
}

func ackRow(startUS, schedUS, latUS, lateUS int64, status, project, records, bytes int, sig Signal) string {
	return fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%s", startUS, schedUS, latUS, lateUS, status, project, records, bytes, sig)
}

// sigAcc is what the preload has had ACKed for one signal.
type sigAcc struct {
	PreloadSignal
	minTS, maxTS int64
}

type preloader struct {
	cfg    Config
	plan   Plan
	creds  map[int]string
	client *http.Client
	acks   *gzCSV
	t0     time.Time

	mu        sync.Mutex
	acc       map[Signal]*sigAcc
	slotMask  []uint64 // project -> bit per route slot with an ACKed record
	samples   []TraceSample
	refused   int64
	transport int64
	failRun   atomic.Int64 // consecutive failed requests
	inflight  atomic.Int64
	ackedB    map[Signal]*atomic.Int64
}

func (l *preloader) fail(status int, resp []byte, pr Prepared) {
	l.mu.Lock()
	if status == 0 {
		l.transport++
	} else {
		l.refused++
	}
	n := l.refused + l.transport
	l.mu.Unlock()
	if n <= 5 {
		fmt.Fprintf(os.Stderr, "queries: preload request failed: project %d slot %d status %d: %.300s\n", pr.Project, pr.Slot, status, resp)
	}
	switch status {
	case 0, http.StatusServiceUnavailable, statusBadReceipt:
		if l.failRun.Add(1) >= maxFailed {
			fatalf("preload: %d requests in a row failed (last status %d): the server is not taking data", maxFailed, status)
		}
	default:
		// 4xx: the batch is final-refused (quota, series, credential, conflict). The preload cannot make a clean 1 GiB of it.
		fatalf("preload: project %d slot %d refused with status %d: %s", pr.Project, pr.Slot, status, resp)
	}
}

func (l *preloader) send(pr Prepared, bud *budget, sig Signal) {
	st := time.Now()
	status, resp := post(l.client, l.plan.Addr, l.creds[pr.Project], pr.Body)
	lat := time.Since(st)
	ok := false
	switch {
	case status == http.StatusOK && acked(resp, pr.ID):
		ok = true
	case status == http.StatusOK:
		status = statusBadReceipt
	}
	start := st.Sub(l.t0).Microseconds()
	l.acks.Line(ackRow(start, start, lat.Microseconds(), 0, status, pr.Project, pr.Records, len(pr.Body), sig))
	if !ok {
		l.fail(status, resp, pr)
		bud.done(int64(len(pr.Body)), false)
		return
	}
	l.failRun.Store(0)
	l.ackedB[sig].Add(int64(len(pr.Body)))
	l.mu.Lock()
	a := l.acc[sig]
	a.Batches++
	a.Records += int64(pr.Records)
	a.EncodedBytes += int64(len(pr.Body))
	a.minTS, a.maxTS = min(a.minTS, pr.MinTS), max(a.maxTS, pr.MaxTS)
	l.slotMask[pr.Project] |= 1 << pr.Slot
	l.samples = append(l.samples, pr.Samples...)
	l.mu.Unlock()
	bud.done(int64(len(pr.Body)), true)
}

// runSignal sends the batches of one signal closed loop until the target bytes are ACKed.
func (l *preloader) runSignal(sp sigPlan, es time.Time, span time.Duration, target int64, workers, par int) {
	sig := sp.Signal
	l.mu.Lock()
	l.acc[sig] = &sigAcc{minTS: math.MaxInt64}
	l.ackedB[sig] = new(atomic.Int64)
	l.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan Prepared, 2*workers)
	go func() {
		defer close(ch)
		generate(ctx, l.cfg, sig, sp.Steps, sp.allRounds(), es, span, par, func(pr Prepared) bool {
			select {
			case ch <- pr:
				return true
			case <-ctx.Done():
				return false
			}
		})
	}()
	bud := newBudget(target, workers)
	var wg sync.WaitGroup
	for pr := range ch {
		if !bud.acquire(int64(len(pr.Body))) {
			break
		}
		wg.Add(1)
		l.inflight.Add(1)
		go func() {
			defer wg.Done()
			defer l.inflight.Add(-1)
			l.send(pr, bud, sig)
		}()
	}
	cancel()
	wg.Wait()
	if got := l.ackedB[sig].Load(); got < target {
		fatalf("preload %s: the stream ended with %d of %d bytes ACKed (requests refused %d, transport failures %d)", sig, got, target, l.refused, l.transport)
	}
}

func runPreload(cfg Config, plan Plan, ca, out string, plans []sigPlan, target int64, workers, par int) {
	dir := filepath.Join(out, "preload")
	must(os.MkdirAll(dir, 0o755), "preload dir")
	l := &preloader{cfg: cfg, plan: plan, creds: credentials(plan), client: newClient(ca), acc: map[Signal]*sigAcc{},
		slotMask: make([]uint64, cfg.Projects), ackedB: map[Signal]*atomic.Int64{}}
	l.acks = newGzCSV(filepath.Join(dir, "acks.csv.gz"), AcksHeader)
	prev := onFatal
	onFatal = func() {
		l.acks.Close()
		if prev != nil {
			prev()
		}
	}
	span := SteadyS * time.Second
	start := time.Now()
	l.t0 = start
	es := start.Add(-span) // the 24 h that END where the preload starts
	fmt.Fprintf(os.Stderr, "queries: preload starts, event time %s .. %s, target %d bytes per signal, %d in flight\n", es.UTC().Format(time.RFC3339), start.UTC().Format(time.RFC3339), target, workers)

	stop := make(chan struct{})
	go func() {
		tick := time.NewTicker(60 * time.Second)
		defer tick.Stop()
		var last int64
		lastT := time.Now()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				l.acks.Flush()
				var total int64
				parts := make([]string, 0, 3)
				l.mu.Lock()
				for _, s := range PreloadSignals {
					if c := l.ackedB[s]; c != nil {
						total += c.Load()
						parts = append(parts, fmt.Sprintf("%s=%.0fMiB", s, float64(c.Load())/(1<<20)))
					}
				}
				refused, tr := l.refused, l.transport
				l.mu.Unlock()
				fmt.Fprintf(os.Stderr, "queries: preload t=%4.0fs %.1f MB/s %s inflight=%d refused=%d transport=%d\n", time.Since(start).Seconds(),
					float64(total-last)/1e6/time.Since(lastT).Seconds(), strings.Join(parts, " "), l.inflight.Load(), refused, tr)
				last, lastT = total, time.Now()
			}
		}
	}()
	for _, sp := range plans {
		fmt.Fprintf(os.Stderr, "queries: preload %s: %d steps, %d rounds\n", sp.Signal, sp.Steps, sp.Rounds)
		l.runSignal(sp, es, span, target, workers, par)
	}
	close(stop)
	end := time.Now()

	sum := PreloadSummary{StartUnixMS: start.UnixMilli(), EndUnixMS: end.UnixMilli(), EventStartNS: math.MaxInt64, Signals: map[Signal]PreloadSignal{},
		SlotsByProject: make([][]int, cfg.Projects), Refused: l.refused, Transport: l.transport}
	for _, s := range PreloadSignals {
		a := l.acc[s]
		a.EventStartNS, a.EventEndNS = a.minTS, a.maxTS
		sum.Signals[s] = a.PreloadSignal
		sum.EventStartNS, sum.EventEndNS = min(sum.EventStartNS, a.minTS), max(sum.EventEndNS, a.maxTS)
	}
	for p, m := range l.slotMask {
		slots := []int{}
		for s := 0; s < 64; s++ {
			if m&(1<<s) != 0 {
				slots = append(slots, s)
			}
		}
		sum.SlotsByProject[p] = slots
	}
	sort.Slice(l.samples, func(i, j int) bool {
		a, b := l.samples[i], l.samples[j]
		if a.Project != b.Project {
			return a.Project < b.Project
		}
		return a.StartNS < b.StartNS
	})
	sum.TraceSamples = l.samples
	l.acks.Close()
	onFatal = prev
	raw, err := json.MarshalIndent(sum, "", " ")
	must(err, "preload summary")
	must(os.WriteFile(filepath.Join(dir, "summary.json"), raw, 0o644), "preload summary file")
	for _, s := range PreloadSignals {
		a := sum.Signals[s]
		rng := time.Duration(a.EventEndNS - a.EventStartNS)
		fmt.Fprintf(os.Stderr, "queries: preload %s: %d batches %d records %d bytes, event range %.3f h\n", s, a.Batches, a.Records, a.EncodedBytes, rng.Hours())
		if a.EncodedBytes < target {
			fatalf("preload %s: %d bytes < target %d", s, a.EncodedBytes, target)
		}
		if math.Abs(float64(rng-span)) > 0.02*float64(span) {
			fatalf("preload %s: the event range %.3f h is not 24 h +- 2 %% (see %s)", s, rng.Hours(), filepath.Join(dir, "summary.json"))
		}
	}
}

// IngestSummary is ingest/load-summary.json, the generator's own account of the steady run.
type IngestSummary struct {
	T0UnixMS     int64            `json:"t0_unix_ms"`
	EndUnixMS    int64            `json:"end_unix_ms"`
	DurationS    float64          `json:"duration_s"`
	WarmupS      float64          `json:"warmup_s"`
	Rate         int              `json:"rate"`
	Window       string           `json:"flush_window"`
	Sent         int64            `json:"requests_sent"`
	Acked        int64            `json:"requests_acked"`
	Refused      int64            `json:"requests_refused"`
	RefusedBy    map[string]int64 `json:"refused_by_status"`
	Transport    int64            `json:"requests_transport_failed"`
	Shed         int64            `json:"requests_shed"`
	MaxInFlight  int64            `json:"max_in_flight"`
	RecordsSent  map[string]int64 `json:"records_sent_by_kind"`
	RecordsAcked map[string]int64 `json:"records_acked_by_kind"` // the mixed stream by kind; "control" = the ctl_flag samples
	BytesAcked   int64            `json:"encoded_bytes_acked"`
	LateP99MS    float64          `json:"lateness_p99_ms"`
	RowsFile     string           `json:"rows_file"`
}

const steadyWindow = 10 * time.Second // the modelled SDK's flush window

type steady struct {
	plan   Plan
	client *http.Client
	t0     time.Time
	rows   *gzCSV

	inflight, maxInFl                  atomic.Int64
	sent, ok, refused, transport, shed atomic.Int64
	refusedBy                          sync.Map        // status -> *atomic.Int64
	recSent, recAcked                  [6]atomic.Int64 // mix entries, then control
	bytesAcked                         atomic.Int64
	wg                                 sync.WaitGroup
	lateMu                             sync.Mutex
	late                               []int32 // microseconds, sent requests only
}

func (l *steady) send(pr Prepared, sched time.Time, cred string) {
	defer l.wg.Done()
	if l.inflight.Add(1) > steadyMaxInFlight {
		l.inflight.Add(-1)
		now := time.Now()
		l.shed.Add(1)
		l.rows.Line(ackRow(now.Sub(l.t0).Microseconds(), sched.Sub(l.t0).Microseconds(), 0, now.Sub(sched).Microseconds(), statusShed, pr.Project, pr.Records, len(pr.Body), pr.Signal))
		return
	}
	defer l.inflight.Add(-1)
	if n := l.inflight.Load(); n > l.maxInFl.Load() {
		l.maxInFl.Store(n)
	}
	l.sent.Add(1)
	count := func(c *[6]atomic.Int64) {
		if pr.Signal == SignalControl {
			c[5].Add(int64(pr.Records))
			return
		}
		for i, n := range pr.ByKind {
			c[i].Add(int64(n))
		}
	}
	count(&l.recSent)
	st := time.Now()
	status, resp := post(l.client, l.plan.Addr, cred, pr.Body)
	lat := time.Since(st)
	late := st.Sub(sched).Microseconds()
	switch {
	case status == 0:
		l.transport.Add(1)
	case status != http.StatusOK:
		l.countRefused(status, resp)
	case !acked(resp, pr.ID):
		status = statusBadReceipt
		l.countRefused(status, resp)
	default:
		l.ok.Add(1)
		l.bytesAcked.Add(int64(len(pr.Body)))
		count(&l.recAcked)
	}
	l.lateMu.Lock()
	l.late = append(l.late, int32(min(max(late, 0), math.MaxInt32)))
	l.lateMu.Unlock()
	l.rows.Line(ackRow(st.Sub(l.t0).Microseconds(), sched.Sub(l.t0).Microseconds(), lat.Microseconds(), late, status, pr.Project, pr.Records, len(pr.Body), pr.Signal))
}

// countRefused counts a non-200 answer by status. Refusals of the slots lost to the injected shard loss are expected and never abort.
func (l *steady) countRefused(status int, resp []byte) {
	l.refused.Add(1)
	c, _ := l.refusedBy.LoadOrStore(status, new(atomic.Int64))
	if n := c.(*atomic.Int64).Add(1); n <= 3 {
		fmt.Fprintf(os.Stderr, "queries: steady refusal %d #%d: %.300s\n", status, n, resp)
	}
}

func runSteady(cfg Config, plan Plan, ca, out string, t0 time.Time, warmup, duration time.Duration, rate int) {
	dir := filepath.Join(out, "ingest")
	must(os.MkdirAll(dir, 0o755), "ingest dir")
	cfg.Epoch = SteadyEpoch
	l := &steady{plan: plan, client: newClient(ca), t0: t0}
	l.rows = newGzCSV(filepath.Join(dir, "acks.csv.gz"), AcksHeader)
	creds := credentials(plan)
	projects := make([]*Project, cfg.Projects)
	var bw sync.WaitGroup
	for p := range projects {
		bw.Add(1)
		go func() { defer bw.Done(); projects[p] = NewProject(cfg, p) }()
	}
	bw.Wait()

	total := warmup + duration
	fmt.Fprintf(os.Stderr, "queries: steady starts at %s for %s, %d records/s over %d projects\n", t0.UTC().Format(time.RFC3339), total, rate, cfg.Projects)
	var sched sync.WaitGroup
	for p, pj := range projects {
		sched.Add(1)
		phase := time.Duration(int64(steadyWindow) * int64(p) / int64(cfg.Projects))
		go func() {
			defer sched.Done()
			for j := 0; ; j++ {
				built := t0.Add(phase + time.Duration(j)*steadyWindow)
				if built.Sub(t0) >= total {
					return
				}
				time.Sleep(time.Until(built))
				batches := pj.Window(j, built.Add(-steadyWindow), steadyWindow, rate)
				m := len(batches)
				for k, pr := range batches {
					at := built.Add(time.Duration(int64(steadyWindow) * int64(k) / int64(m)))
					if at.Sub(t0) >= total {
						break
					}
					l.wg.Add(1)
					time.AfterFunc(time.Until(at), func() { l.send(pr, at, creds[pr.Project]) })
				}
			}
		}()
		if IsControl(p) {
			// ctl_flag of the flip rules: one sample every 30 s, the projects offset by 10 s from each other; the value is that of the
			// sample's own instant, so it is a pure function of the clock.
			sched.Add(1)
			off := time.Duration(p-ControlProjectFirst) * 10 * time.Second
			go func() {
				defer sched.Done()
				for j := 0; ; j++ {
					at := t0.Add(off + time.Duration(j)*ControlEvery)
					if at.Sub(t0) >= total {
						return
					}
					time.Sleep(time.Until(at))
					l.wg.Add(1)
					go l.send(pj.ControlBatch(j, at), at, creds[p])
				}
			}()
		}
	}
	doneSched := make(chan struct{})
	go func() { sched.Wait(); close(doneSched) }()
	tick := time.NewTicker(30 * time.Second)
	beat := 0
loop:
	for {
		select {
		case <-tick.C:
			l.rows.Flush()
			beat++
			if beat%2 == 1 {
				continue
			}
			fmt.Fprintf(os.Stderr, "queries: steady t=%5.0fs sent=%d ok=%d refused=%d transport=%d shed=%d inflight=%d\n", time.Since(t0).Seconds(),
				l.sent.Load(), l.ok.Load(), l.refused.Load(), l.transport.Load(), l.shed.Load(), l.inflight.Load())
		case <-doneSched:
			break loop
		}
	}
	tick.Stop()
	time.Sleep(time.Until(t0.Add(total)))
	l.wg.Wait()
	end := time.Now()
	l.rows.Close()

	sum := IngestSummary{T0UnixMS: t0.UnixMilli(), EndUnixMS: end.UnixMilli(), DurationS: duration.Seconds(), WarmupS: warmup.Seconds(), Rate: rate, Window: steadyWindow.String(),
		Sent: l.sent.Load(), Acked: l.ok.Load(), Refused: l.refused.Load(), RefusedBy: map[string]int64{}, Transport: l.transport.Load(), Shed: l.shed.Load(),
		MaxInFlight: l.maxInFl.Load(), RecordsSent: map[string]int64{}, RecordsAcked: map[string]int64{}, BytesAcked: l.bytesAcked.Load(), RowsFile: "acks.csv.gz"}
	l.refusedBy.Range(func(k, v any) bool { sum.RefusedBy[strconv.Itoa(k.(int))] = v.(*atomic.Int64).Load(); return true })
	names := append(kindNames[:], "control")
	for i, n := range names {
		sum.RecordsSent[n], sum.RecordsAcked[n] = l.recSent[i].Load(), l.recAcked[i].Load()
	}
	l.lateMu.Lock()
	late := make([]int64, len(l.late))
	for i, v := range l.late {
		late[i] = int64(v)
	}
	l.lateMu.Unlock()
	sort.Slice(late, func(i, j int) bool { return late[i] < late[j] })
	sum.LateP99MS = float64(percentile(late, 0.99)) / 1000
	raw, err := json.MarshalIndent(sum, "", " ")
	must(err, "load summary")
	must(os.WriteFile(filepath.Join(dir, "load-summary.json"), raw, 0o644), "load summary file")
	fmt.Fprintf(os.Stderr, "queries: steady done: sent=%d ok=%d refused=%d transport=%d shed=%d\n", sum.Sent, sum.Acked, sum.Refused, sum.Transport, sum.Shed)
}

// parseSteps reads "metric,log,span" step counts (what a --dry-run printed) in PreloadSignals order.
func parseSteps(s string) map[Signal]int {
	parts := strings.Split(s, ",")
	if len(parts) != len(PreloadSignals) {
		fatalf("--steps wants %d comma separated step counts (metric,log,span)", len(PreloadSignals))
	}
	out := map[Signal]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 1 {
			fatalf("--steps: bad step count %q", p)
		}
		out[PreloadSignals[i]] = n
	}
	return out
}

func runIngest(args []string) {
	f := flag.NewFlagSet("ingest", flag.ExitOnError)
	planPath := f.String("plan", "", "plan.json written by the server role (--dry-run: optional, the default estate is used without it)")
	ca := f.String("ca", "", "CA certificate of the product")
	out := f.String("out", "", "run directory (preload/ and ingest/ are written below it)")
	preloadOnly := f.Bool("preload-only", false, "preload and stop")
	steadyOnly := f.Bool("steady-only", false, "run the steady stream only (the preload is already in)")
	dry := f.Bool("dry-run", false, "generate the preload and count its bytes only: no network, no files; prints what the run will take")
	t0ms := f.Int64("t0-unix-ms", 0, "steady T0 as unix ms; 0 = 5 s after the preload ended")
	duration := f.Duration("duration", SteadyS*time.Second, "steady duration after T0")
	warmup := f.Duration("warmup", 0, "steady warm-up appended to the duration (same rate; the validator judges from T0)")
	rate := f.Int("rate", IngestRate, "steady mixed records per second over all projects")
	preloadBytes := f.Int64("preload-bytes", InputBytesPerSignal, "encoded bytes of ACKed request bodies to preload per signal")
	workers := f.Int("workers", 32, "preload requests in flight")
	par := f.Int("gen-par", runtime.NumCPU(), "projects the preload generator builds at a time")
	steps := f.String("steps", "", "metric,log,span step counts to use instead of calibrating (the numbers a --dry-run printed)")
	f.Parse(args)

	if *preloadOnly && *steadyOnly {
		fatalf("--preload-only and --steady-only exclude each other")
	}
	if *rate < 1 || *workers < 1 || *par < 1 || *preloadBytes < 1 || *duration < 0 || *warmup < 0 {
		fatalf("--rate, --workers, --gen-par and --preload-bytes must be positive, --duration and --warmup not negative")
	}
	cfg := DefaultConfig()
	var plan Plan
	if *planPath != "" {
		plan = readPlan(*planPath)
		cfg = plan.Config
	} else if !*dry {
		fatalf("--plan is required")
	}
	must(cfg.Check(), "plan config")
	span := SteadyS * time.Second

	// the calibration reference: a fixed origin, the byte length of a batch does not depend on it
	var plans []sigPlan
	if !*steadyOnly {
		pcfg := cfg
		pcfg.Epoch = PreloadEpoch
		ref := time.Now().Add(-span)
		fixed := parseStepsOrNil(*steps)
		for _, sig := range PreloadSignals {
			var sp sigPlan
			if n, ok := fixed[sig]; ok {
				sp = dryPass(pcfg, sig, n, roundSteps(sig, n), ref, span, *par)
				sp.Passes = 1
			} else {
				sp = calibrate(pcfg, sig, *preloadBytes, ref, span, *par)
			}
			plans = append(plans, sp)
		}
		for _, sp := range plans {
			fmt.Printf("%s: steps=%d round_steps=%d rounds=%d batches=%d records=%d bytes=%d (%.4f GiB, %+.3f %% of target) avg_records_per_batch=%.0f avg_batch_bytes=%.0f event_range_h=%.3f passes=%d generation=%.1f MB/s\n",
				sp.Signal, sp.Steps, sp.Round, sp.Rounds, sp.Batches, sp.Records, sp.Bytes, float64(sp.Bytes)/(1<<30), 100*(float64(sp.Bytes)/float64(*preloadBytes)-1),
				float64(sp.Records)/float64(sp.Batches), float64(sp.Bytes)/float64(sp.Batches), sp.RangeH, sp.Passes, sp.MBPerSec)
		}
		fmt.Printf("--steps %d,%d,%d\n", plans[0].Steps, plans[1].Steps, plans[2].Steps)
	}
	if *dry {
		return
	}
	if *ca == "" || *out == "" {
		fatalf("--ca and --out are required")
	}
	must(os.MkdirAll(filepath.Join(*out, "ingest"), 0o755), "ingest dir")
	raw, err := json.MarshalIndent(hostFacts("", runtime.GOMAXPROCS(0)), "", " ")
	must(err, "host facts")
	must(os.WriteFile(filepath.Join(*out, FileIngestHost), raw, 0o644), "host facts file")
	startNetMon(context.Background(), filepath.Join(*out, FileIngestNet), 10*time.Second)

	if !*steadyOnly {
		pcfg := cfg
		pcfg.Epoch = PreloadEpoch
		runPreload(pcfg, plan, *ca, *out, plans, *preloadBytes, *workers, *par)
	}
	if *preloadOnly {
		return
	}
	t0 := time.UnixMilli(*t0ms)
	if *t0ms == 0 {
		t0 = time.Now().Add(5 * time.Second)
	} else if time.Until(t0) < -2*time.Second {
		fatalf("--t0-unix-ms is %s in the past", -time.Until(t0))
	}
	runSteady(cfg, plan, *ca, *out, t0, *warmup, *duration, *rate)
}

func parseStepsOrNil(s string) map[Signal]int {
	if s == "" {
		return nil
	}
	return parseSteps(s)
}
