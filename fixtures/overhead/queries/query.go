// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/query"
)

const (
	clientTimeout  = 40 * time.Second
	probeEvery     = 5 * time.Minute
	probeFirst     = time.Minute
	goldenEvery    = 30 * time.Minute
	proberWorker   = 10
	userAgent      = "soundpost-overhead-queries"
	headerRequest  = "X-Gate-Request"
	headerToken    = "X-Harness-Token"
	controlTimeout = 15 * time.Minute
)

// wireProject is the part of one project's answer the harness reads; the value stays raw (it is only hashed, for a golden).
type wireProject struct {
	Value        json.RawMessage `json:"value"`
	Completeness string          `json:"completeness"`
	Stats        query.Stats     `json:"stats"`
	Failure      json.RawMessage `json:"failure"`
}

// wireView is what trace_view and service_red answers share: a state and, for the RED view, its freshness.
type wireView struct {
	State     string `json:"state"`
	Partial   bool   `json:"partial"`
	Freshness *struct {
		Cached bool `json:"cached"`
	} `json:"freshness"`
}

// row is one line of queries.csv.gz.
type row struct {
	startUS, latencyUS int64
	status, worker     int
	class, lang        string
	projects           int
	windowS            int64
	pages, rows, bytes uint64
	peakMem            uint64
	serverUS           int64
	cached             bool
	completeness       string
	returned           uint64
	limitReached       bool
	code, digest, req  string
	golden             string
}

func b01(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (r row) csv() string {
	clean := func(s string) string { return strings.NewReplacer(",", "_", "\n", " ", "\r", " ").Replace(s) }
	return fmt.Sprintf("%d,%d,%d,%d,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%s,%d,%d,%s,%s,%s,%s",
		r.startUS, r.latencyUS, r.status, r.worker, r.class, r.lang, r.projects, r.windowS, r.pages, r.rows, r.bytes, r.peakMem, r.serverUS,
		b01(r.cached), r.completeness, r.returned, b01(r.limitReached), clean(r.code), r.digest, r.req, r.golden)
}

// completenessRank orders the letters of the column from the best to the worst answer.
var completenessRank = map[string]int{"c": 0, "s": 1, "p": 2, "-": 3}

func letter(c string) string {
	switch c {
	case query.CompletenessComplete:
		return "c"
	case query.CompletenessStale:
		return "s"
	}
	return "p"
}

func worse(a, b string) string {
	if completenessRank[b] > completenessRank[a] {
		return b
	}
	return a
}

// fill derives the columns that depend on the answer: the stats of a query answer summed over its projects, the state of a view, the
// code of a failure and, for a golden, the digest of a complete answer.
func (r *row) fill(t target, status int, body []byte, wantDigest bool) {
	r.completeness = "-"
	if status != http.StatusOK {
		var e struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Code == "" {
			e.Code = fmt.Sprintf("http_%d", status)
		}
		r.code = e.Code
		return
	}
	switch t.Lang {
	case langProm, langLog:
		var res struct {
			Projects []wireProject `json:"projects"`
		}
		if err := json.Unmarshal(body, &res); err != nil {
			r.code = "bad_body"
			return
		}
		worst, complete := "c", true
		values := make([]json.RawMessage, 0, len(res.Projects))
		for _, p := range res.Projects {
			s := p.Stats
			r.pages += uint64(s.PagesRead)
			r.rows += uint64(s.RowsRead)
			r.bytes += uint64(s.BytesRead)
			r.peakMem += uint64(s.PeakMemoryBytes)
			r.returned += uint64(s.SamplesReturned) + uint64(s.LogsReturned)
			r.serverUS = max(r.serverUS, int64(s.ElapsedNS)/1000)
			r.cached = r.cached || s.Cached
			r.limitReached = r.limitReached || s.LimitReached
			worst = worse(worst, letter(p.Completeness))
			if p.Completeness != query.CompletenessComplete || (len(p.Failure) > 0 && string(p.Failure) != "null") {
				complete = false
			}
			values = append(values, p.Value)
		}
		if len(res.Projects) == 0 {
			worst, complete = "p", false
		}
		r.completeness = worst
		if wantDigest && complete {
			d, err := digestValues(values)
			if err != nil {
				r.code = "bad_body"
				return
			}
			r.digest = d
		}
	default:
		var v wireView
		if err := json.Unmarshal(body, &v); err != nil {
			r.code = "bad_body"
			return
		}
		switch httpapi.ViewState(v.State) {
		case httpapi.StateReady, httpapi.StateEmpty:
			r.completeness = "c"
		case httpapi.StateStale:
			r.completeness = "s"
		default:
			r.completeness = "p"
		}
		if v.Partial {
			r.completeness = "p"
		}
		r.cached = v.Freshness != nil && v.Freshness.Cached
		if wantDigest && httpapi.ViewState(v.State) == httpapi.StateReady && !v.Partial {
			d, err := digestView(body)
			if err != nil {
				r.code = "bad_body"
				return
			}
			r.digest = d
		}
	}
}

// goldenRun is one scheduled run of one golden query (the baseline, every 30 minutes, after the loss, after the restart).
type goldenRun struct {
	ID           string `json:"id"`
	Reason       string `json:"reason"`
	Req          string `json:"req"`
	TMS          int64  `json:"t_ms"`
	Status       int    `json:"status"`
	Completeness string `json:"completeness"`
	Digest       string `json:"digest,omitempty"`
}

type goldenJob struct {
	idx    int
	reason string
}

// faultRecord is the harness's account of one control call.
type faultRecord struct {
	AtUnixMS    int64           `json:"at_unix_ms"`
	DoneUnixMS  int64           `json:"done_unix_ms,omitempty"`
	Status      int             `json:"status"`
	Answer      json.RawMessage `json:"answer,omitempty"`
	Error       string          `json:"error,omitempty"`
	ReadyUnixMS int64           `json:"ready_unix_ms,omitempty"` // restart: when /readyz first answered 200 afterwards
}

// QuerySummary is queries/query-summary.json.
type QuerySummary struct {
	T0UnixMS   int64                  `json:"t0_unix_ms"`
	DurationS  int64                  `json:"duration_s"`
	Workers    int                    `json:"workers"`
	Seed       uint64                 `json:"mix_seed"`
	Requests   map[string]int         `json:"requests_by_class"`
	Statuses   map[string]map[int]int `json:"status_counts_by_class"`
	Loss       *faultRecord           `json:"loss,omitempty"`
	LossSlots  string                 `json:"loss_slots"`
	Restart    *faultRecord           `json:"restart,omitempty"`
	GoldenIDs  []string               `json:"golden_ids"`
	GoldenRuns []goldenRun            `json:"golden_runs"`
	Webhook    struct {
		Deliveries   int64 `json:"deliveries"`
		Verified     int64 `json:"verified"`
		BadSignature int64 `json:"bad_signature"`
	} `json:"webhook"`
}

// qrun is the state of a running query role.
type qrun struct {
	plan   Plan
	b      *builder
	client *http.Client
	t0     time.Time
	csv    *gzCSV
	gold   []golden
	jobs   chan goldenJob

	mu      sync.Mutex
	sum     QuerySummary
	hostURL string

	inflight atomic.Int64
	notes    func() int64 // notifications seen so far
	// minute window and running totals of the progress line, under mu
	winMS          []int64
	nonOK          map[string]int
	total, cachedN int
	goldN, goldBad int
	goldRef        map[string]string
}

func newQRun(plan Plan, b *builder, client *http.Client, t0 time.Time, csv *gzCSV, gold []golden, seed uint64, workers int) *qrun {
	q := &qrun{plan: plan, b: b, client: client, t0: t0, csv: csv, gold: gold, jobs: make(chan goldenJob, 4*len(gold)+8), hostURL: "https://" + plan.Addr}
	q.sum = QuerySummary{T0UnixMS: t0.UnixMilli(), Workers: workers, Seed: seed, Requests: map[string]int{}, Statuses: map[string]map[int]int{}}
	q.nonOK, q.goldRef = map[string]int{}, map[string]string{}
	for _, g := range gold {
		q.sum.GoldenIDs = append(q.sum.GoldenIDs, g.ID)
	}
	return q
}

// do sends one request, reads the whole answer, and records one row. A request is never retried. goldID is set for a golden query;
// reason is the scheduled run it belongs to ("" for a draw of the mix).
func (q *qrun) do(worker int, t target, req, goldID, reason string) {
	start := time.Now()
	q.inflight.Add(1)
	defer q.inflight.Add(-1)
	hr, err := http.NewRequest(http.MethodPost, q.hostURL+t.Path, bytes.NewReader(t.Body))
	must(err, "build request")
	hr.Header.Set("Authorization", "Bearer "+q.b.tokens[t.Org])
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set(headerRequest, req)
	hr.Header.Set("User-Agent", userAgent)

	r := row{startUS: start.Sub(q.t0).Microseconds(), worker: worker, class: t.Class, lang: t.Lang, projects: t.Projects, windowS: t.WindowS, req: req, golden: goldID}
	var body []byte
	status := 0
	resp, err := q.client.Do(hr)
	if err == nil {
		status = resp.StatusCode
		body, err = io.ReadAll(resp.Body) // the latency is taken at the end of the body
		resp.Body.Close()
	}
	lat := time.Since(start)
	switch {
	case err != nil:
		status, r.completeness = 0, "-"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			r.code, lat = "timeout", clientTimeout
		} else {
			r.code = "transport"
		}
	default:
		r.fill(t, status, body, goldID != "")
	}
	r.status, r.latencyUS = status, lat.Microseconds()
	q.csv.Line(r.csv())

	q.mu.Lock()
	q.sum.Requests[t.Class]++
	if q.sum.Statuses[t.Class] == nil {
		q.sum.Statuses[t.Class] = map[int]int{}
	}
	q.sum.Statuses[t.Class][status]++
	q.total++
	if status != http.StatusOK {
		q.nonOK[t.Class]++
	}
	if r.cached {
		q.cachedN++
	}
	if !strings.HasPrefix(t.Class, "overlimit_") {
		q.winMS = append(q.winMS, lat.Milliseconds())
	}
	if goldID != "" && r.digest != "" {
		q.goldN++
		if ref, ok := q.goldRef[goldID]; !ok {
			q.goldRef[goldID] = r.digest
		} else if ref != r.digest {
			q.goldBad++
		}
	}
	if goldID != "" && reason != "" {
		q.sum.GoldenRuns = append(q.sum.GoldenRuns, goldenRun{ID: goldID, Reason: reason, Req: req, TMS: start.UnixMilli(), Status: status, Completeness: r.completeness, Digest: r.digest})
	}
	q.mu.Unlock()
}

// trigger queues one run of every golden query for the workers to take ahead of the mix.
func (q *qrun) trigger(ctx context.Context, reason string) {
	for i := range q.gold {
		select {
		case q.jobs <- goldenJob{i, reason}:
		case <-ctx.Done():
			return
		}
	}
}

func (q *qrun) worker(ctx context.Context, id int, wg *sync.WaitGroup) {
	defer wg.Done()
	g := q.b.newGen(id, q.gold)
	for ctx.Err() == nil {
		select {
		case j := <-q.jobs:
			q.do(id, q.gold[j.idx].target, g.nextReq(), q.gold[j.idx].ID, j.reason)
			continue
		default:
		}
		t, gid := g.next(time.Now().UnixNano())
		q.do(id, t, g.nextReq(), gid, "")
	}
}

// prober is worker 10: every five minutes one request of each over-limit class, in turn over the organizations.
func (q *qrun) prober(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	g := q.b.newGen(proberWorker, nil)
	wait := probeFirst
	for tick := 0; ; tick++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = probeEvery
		for _, class := range OverlimitClasses {
			if ctx.Err() != nil {
				return
			}
			q.do(proberWorker, g.overlimit(class, tick%q.b.orgs), g.nextReq(), "", "")
		}
	}
}

// control calls the server role's control endpoint (plain HTTP, the harness token).
func (q *qrun) control(path string) faultRecord {
	rec := faultRecord{AtUnixMS: now()}
	req, err := http.NewRequest(http.MethodPost, "http://"+q.plan.Control+path, nil)
	must(err, "control request")
	req.Header.Set(headerToken, q.plan.ControlToken)
	resp, err := (&http.Client{Timeout: controlTimeout}).Do(req)
	if err == nil {
		var raw []byte
		raw, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		rec.Status = resp.StatusCode
		if json.Valid(raw) {
			rec.Answer = raw
		} else if len(raw) > 0 {
			rec.Error = strings.TrimSpace(string(raw))
		}
	}
	if err != nil {
		rec.Error = err.Error()
	}
	rec.DoneUnixMS = now()
	return rec
}

// awaitReady polls /readyz of the product until it answers 200 or limit passes.
func (q *qrun) awaitReady(ctx context.Context, limit time.Duration) bool {
	c := &http.Client{Timeout: 5 * time.Second, Transport: q.client.Transport}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if resp, err := c.Get(q.hostURL + "/readyz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return true
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func sleepUntil(ctx context.Context, at time.Time) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Until(at)):
		return true
	}
}

// faults runs the shard loss and the restart at their offsets from T0 (an offset of zero never happens) and queues a golden run right
// after each, the restart's once /readyz answers.
func (q *qrun) faults(ctx context.Context, lossAt, restartAt time.Duration, slots string, wg *sync.WaitGroup) {
	defer wg.Done()
	if lossAt > 0 {
		if !sleepUntil(ctx, q.t0.Add(lossAt)) {
			return
		}
		rec := q.control("/fault/close-groups?slots=" + url.QueryEscape(slots))
		q.mu.Lock()
		q.sum.Loss = &rec
		q.mu.Unlock()
		if rec.Status != http.StatusOK {
			fmt.Fprintf(os.Stderr, "queries: shard loss answered %d %s\n", rec.Status, rec.Error)
		}
		q.trigger(ctx, "after_loss")
	}
	if restartAt > 0 {
		if !sleepUntil(ctx, q.t0.Add(restartAt)) {
			return
		}
		rec := q.control("/restart?mode=graceful")
		if rec.Status == http.StatusOK && q.awaitReady(ctx, 10*time.Minute) {
			rec.ReadyUnixMS = now()
		}
		q.mu.Lock()
		q.sum.Restart = &rec
		q.mu.Unlock()
		if rec.ReadyUnixMS != 0 {
			q.trigger(ctx, "after_restart")
		} else {
			fmt.Fprintf(os.Stderr, "queries: restart answered %d %s, no readiness\n", rec.Status, rec.Error)
		}
	}
}

// goldenClock queues a golden run every 30 minutes after T0 (the baseline run is queued before the workers start).
func (q *qrun) goldenClock(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	tick := time.NewTicker(goldenEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			q.trigger(ctx, "periodic")
		}
	}
}

// reporter flushes the CSV every 30 s (so it can be zcat'ed mid-run) and logs one progress line to stderr every 60 s.
func (q *qrun) reporter(ctx context.Context, rcv *webhookReceiver, wg *sync.WaitGroup) {
	defer wg.Done()
	flush := time.NewTicker(30 * time.Second)
	report := time.NewTicker(time.Minute)
	defer flush.Stop()
	defer report.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			q.csv.Flush()
		case <-report.C:
			q.csv.Flush()
			q.mu.Lock()
			win := q.winMS
			q.winMS = nil
			var classes []string
			for c := range q.nonOK {
				classes = append(classes, c)
			}
			sort.Strings(classes)
			var bad []string
			for _, c := range classes {
				bad = append(bad, fmt.Sprintf("%s=%d", c, q.nonOK[c]))
			}
			total, cached, gn, gb := q.total, q.cachedN, q.goldN, q.goldBad
			q.mu.Unlock()
			sort.Slice(win, func(i, j int) bool { return win[i] < win[j] })
			var p50, p95, mx int64
			if len(win) > 0 {
				p50, p95, mx = percentile(win, 0.5), percentile(win, 0.95), win[len(win)-1]
			}
			fmt.Fprintf(os.Stderr, "queries: t=%ds requests=%d non200=[%s] last-minute ms p50=%d p95=%d max=%d inflight=%d cached=%d notifications=%d golden runs=%d mismatches=%d\n",
				int(time.Since(q.t0).Seconds()), total, strings.Join(bad, " "), p50, p95, mx, q.inflight.Load(), cached, rcv.total.Load(), gn, gb)
		}
	}
}

func runQuery(args []string) {
	f := flag.NewFlagSet("query", flag.ExitOnError)
	planPath := f.String("plan", "", "plan.json written by the server role")
	ca := f.String("ca", "", "CA certificate of the product")
	out := f.String("out", "", "run directory (queries/ is written under it)")
	preload := f.String("preload-summary", "", "preload/summary.json written by the ingest role")
	t0ms := f.Int64("t0-unix-ms", 0, "steady T0, unix milliseconds")
	duration := f.Duration("duration", SteadyS*time.Second, "steady run length")
	workers := f.Int("workers", Interactive, "interactive workers")
	lossAt := f.Duration("loss-at", 22*time.Hour+30*time.Minute, "shard loss offset from T0 (0 = never)")
	restartAt := f.Duration("restart-at", 23*time.Hour, "graceful restart offset from T0 (0 = never)")
	lossSlots := f.String("loss-slots", "0-31", "slots the shard loss closes")
	seed := f.Uint64("seed", 1, "seed of the mix RNG")
	f.Parse(args)
	if *planPath == "" || *ca == "" || *out == "" || *preload == "" || *t0ms == 0 {
		fatalf("--plan, --ca, --out, --preload-summary and --t0-unix-ms are required")
	}
	plan := readPlan(*planPath)
	var sum PreloadSummary
	raw, err := os.ReadFile(*preload)
	must(err, "read preload summary")
	must(json.Unmarshal(raw, &sum), "parse preload summary")
	b, err := newBuilder(plan, sum, *seed)
	must(err, "estate")
	gold := b.goldens()

	dir := filepath.Join(*out, "queries")
	must(os.MkdirAll(dir, 0o755), "queries dir")
	// The rules start notifying as soon as the server runs: the receiver is up from the start of this process, before T0.
	rcv, stopHook := startWebhook(plan.Webhook, filepath.Join(*out, FileNotifications))
	writeGoldenFile(filepath.Join(dir, "golden.json"), gold)

	t0 := time.UnixMilli(*t0ms)
	time.Sleep(time.Until(t0))
	netCtx, stopNet := context.WithCancel(context.Background())
	startNetMon(netCtx, filepath.Join(*out, FileQueryNet), 10*time.Second)
	must(os.WriteFile(filepath.Join(*out, FileQueryHost), append(mustJSON(hostFacts("", runtime.GOMAXPROCS(0))), '\n'), 0o644), "write host.json")

	csv := newGzCSV(filepath.Join(*out, FileQueries), QueriesHeader)
	q := newQRun(plan, b, tlsClient(*ca, clientTimeout), t0, csv, gold, *seed, *workers)
	q.sum.DurationS, q.sum.LossSlots = int64(duration.Seconds()), *lossSlots
	q.notes = rcv.total.Load

	ctx, stop := context.WithDeadline(context.Background(), t0.Add(*duration))
	defer stop()
	var wg sync.WaitGroup
	q.trigger(ctx, "baseline") // the baseline runs first: the channel holds the whole set
	wg.Add(1)
	go q.goldenClock(ctx, &wg)
	for w := range *workers {
		wg.Add(1)
		go q.worker(ctx, w, &wg)
	}
	wg.Add(3)
	go q.reporter(ctx, rcv, &wg)
	go q.prober(ctx, &wg)
	go q.faults(ctx, *lossAt, *restartAt, *lossSlots, &wg)
	wg.Wait() // in-flight requests finish (at most the client timeout) and are recorded

	csv.Close()
	stopNet()
	q.mu.Lock()
	q.sum.Webhook.Deliveries, q.sum.Webhook.Verified, q.sum.Webhook.BadSignature = rcv.total.Load(), rcv.verified.Load(), rcv.bad.Load()
	data := append(mustJSON(q.sum), '\n')
	q.mu.Unlock()
	stopHook()
	must(os.WriteFile(filepath.Join(*out, FileQuerySummary), data, 0o644), "write query summary")
}
