// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify/providers"
	"github.com/arynyklas/soundpost/internal/query"
)

func testBuilder(t *testing.T) *builder {
	t.Helper()
	cfg := DefaultConfig()
	plan := Plan{Config: cfg, PromProfile: "promql-prometheus-3.13.5", PromFeatureSet: "default", LogProfile: "logql-loki-3.5.2", LogFeatureSet: "default"}
	for o := 0; o < cfg.Orgs; o++ {
		plan.Readers = append(plan.Readers, PlanReader{Org: o, Token: fmt.Sprintf("token-%d", o)})
	}
	start := int64(1_700_000_000) * int64(time.Second)
	sum := PreloadSummary{EventStartNS: start, EventEndNS: start + 24*hour + int64(time.Minute)}
	sum.TraceSamples = []TraceSample{
		{Project: 7, Trace: ident(cfg.Seed, "trace", 1).String(), Service: ident(cfg.Seed, "service", 7).String(), StartNS: sum.EventEndNS - 3*hour, Slot: 5},
		{Project: 42, Trace: ident(cfg.Seed, "trace", 2).String(), Service: ident(cfg.Seed, "service", 42).String(), StartNS: sum.EventEndNS - 9*hour, Slot: 40},
	}
	b, err := newBuilder(plan, sum, 99)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// strict decodes a body with the product's own request type, refusing unknown members as the route does.
func strict(t *testing.T, body []byte, v any) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("body does not decode: %v\n%s", err, body)
	}
	if err := model.StrictJSON(body, v); err != nil {
		t.Fatalf("product strict decode: %v\n%s", err, body)
	}
}

func checkTarget(t *testing.T, b *builder, tg target) {
	t.Helper()
	switch tg.Path {
	case pathQuery:
		var q httpapi.QueryBody
		strict(t, tg.Body, &q)
		ev := q.Evaluation
		if q.Org != b.orgID(tg.Org) || len(q.Projects) != tg.Projects || q.Expression == "" || q.FeatureSet == "" || q.Profile == "" {
			t.Fatalf("%s: scope or request incomplete: %s", tg.Class, tg.Body)
		}
		if ev.Instant && (ev.Time == 0 || ev.Start != 0 || ev.End != 0 || ev.Step != 0) || !ev.Instant && (ev.Time != 0 || ev.End <= ev.Start || ev.Step <= 0) {
			t.Fatalf("%s: malformed evaluation %+v", tg.Class, ev)
		}
		if !strings.Contains(string(tg.Body), `"time":"`) || !strings.Contains(string(tg.Body), `"timeout_ns":"`) {
			t.Fatalf("%s: numbers are not decimal strings: %s", tg.Class, tg.Body)
		}
		if (q.Language == query.LanguageLogQL) != (tg.Lang == langLog) || !strings.HasPrefix(q.Profile, q.Language+"-") {
			t.Fatalf("%s: language and profile disagree", tg.Class)
		}
		for _, p := range q.Projects {
			ok := false
			for _, own := range b.orgProjects(tg.Org) {
				ok = ok || own == p
			}
			if !ok {
				t.Fatalf("%s: project outside the organization", tg.Class)
			}
		}
	case pathTraces:
		var q httpapi.TraceBody
		strict(t, tg.Body, &q)
		if q.Org != b.orgID(tg.Org) || q.Window.End <= q.Window.Start || q.Trace == (model.ID{}) {
			t.Fatalf("trace body: %s", tg.Body)
		}
	case pathRED:
		var q httpapi.ServiceREDBody
		strict(t, tg.Body, &q)
		w := q.Window
		if q.Org != b.orgID(tg.Org) || len(q.Projects) != 1 || w.End <= w.Start || time.Duration(w.End-w.Start) > httpapi.MaxConsoleListWindow {
			t.Fatalf("red body: %s", tg.Body)
		}
	default:
		t.Fatalf("unknown path %s", tg.Path)
	}
}

func TestBuildersProduceValidBodiesForEveryClass(t *testing.T) {
	b := testBuilder(t)
	now := b.sum.EventEndNS + 3*hour
	g := b.newGen(0, nil)
	for _, m := range mixWeights {
		if m.Class == ClassGolden {
			continue
		}
		for range 50 {
			tg := g.build(m.Class, now)
			if tg.Class != m.Class {
				t.Fatalf("class %s built as %s", m.Class, tg.Class)
			}
			checkTarget(t, b, tg)
		}
	}
	for _, c := range OverlimitClasses {
		tg := g.overlimit(c, 3)
		checkTarget(t, b, tg)
		var q httpapi.QueryBody
		strict(t, tg.Body, &q)
		switch c {
		case ClassOverMax:
			if q.Budget.MaxReturned != 10 {
				t.Fatal("max_returned")
			}
		case ClassOverMemory:
			if q.Budget.MemoryBytes == 0 {
				t.Fatal("memory_bytes")
			}
		case ClassOverTimeout:
			if q.Budget.TimeoutNS != model.Int64(time.Millisecond) {
				t.Fatal("timeout_ns")
			}
		case ClassOverDefault24:
			if q.Budget != (query.Budget{}) || time.Duration(q.Evaluation.Step) != time.Second || q.Evaluation.End-q.Evaluation.Start != model.UnixNano(24*hour) {
				t.Fatal("default budget range must be 24 h at 1 s")
			}
		}
	}
	gold := b.goldens()
	if len(gold) < 6 {
		t.Fatalf("golden set has %d queries", len(gold))
	}
	ids := map[string]bool{}
	for _, gd := range gold {
		if ids[gd.ID] {
			t.Fatalf("duplicate golden id %s", gd.ID)
		}
		ids[gd.ID] = true
		checkTarget(t, b, gd.target)
		if gd.target.Class != ClassGolden {
			t.Fatalf("golden %s class %s", gd.ID, gd.target.Class)
		}
		// immutable data: a golden window ends before the preload's event end
		switch gd.target.Path {
		case pathQuery:
			var q httpapi.QueryBody
			strict(t, gd.target.Body, &q)
			end := int64(q.Evaluation.Time)
			if !q.Evaluation.Instant {
				end = int64(q.Evaluation.End)
			}
			if end >= b.sum.EventEndNS {
				t.Fatalf("golden %s ends after the preload", gd.ID)
			}
		case pathRED:
			var q httpapi.ServiceREDBody
			strict(t, gd.target.Body, &q)
			if int64(q.Window.End) >= b.sum.EventEndNS {
				t.Fatalf("golden %s ends after the preload", gd.ID)
			}
		}
	}
}

func TestMixWeightsMatchTheContract(t *testing.T) {
	b := testBuilder(t)
	want := map[string]int{ClassPromInstant: 12, ClassPromRange1h: 12, ClassPromRange24h: 10, ClassPromOrg24h: 8, ClassPromTopk: 6, ClassLogLines: 14,
		ClassLogCount24h: 8, ClassLogRate6h: 8, ClassTraceView: 12, ClassServiceRED: 6, ClassGolden: 4}
	total := 0
	for _, m := range mixWeights {
		total += m.Weight
		if want[m.Class] != m.Weight {
			t.Fatalf("%s weight %d, contract %d", m.Class, m.Weight, want[m.Class])
		}
	}
	if total != 100 || len(want) != len(mixWeights) {
		t.Fatalf("weights sum to %d over %d classes", total, len(mixWeights))
	}
	g := b.newGen(3, nil)
	const n = 100000
	got := map[string]int{}
	for range n {
		got[g.draw()]++
	}
	for class, w := range want {
		pp := float64(got[class]) / n * 100
		if d := pp - float64(w); d > 0.5 || d < -0.5 {
			t.Errorf("%s drawn %.2f%%, contract %d%%", class, pp, w)
		}
	}
}

func TestEvaluationInstantsAreUnique(t *testing.T) {
	b := testBuilder(t)
	now := b.sum.EventEndNS + 5*hour
	g := b.newGen(1, nil)
	seen := map[string]bool{}
	for range 20000 {
		for _, class := range []string{ClassPromInstant, ClassPromRange1h, ClassPromTopk, ClassLogLines} {
			tg := g.build(class, now)
			var q httpapi.QueryBody
			strict(t, tg.Body, &q)
			key := fmt.Sprintf("%s|%s|%v|%d|%d", q.Expression, q.Projects, q.Evaluation.Instant, q.Evaluation.Time, q.Evaluation.End)
			if seen[key] {
				t.Fatalf("evaluation repeated: %s", key)
			}
			seen[key] = true
			if tg.Class == ClassPromInstant && (int64(q.Evaluation.Time) < b.sum.EventStartNS || int64(q.Evaluation.Time) > now) {
				t.Fatalf("instant outside the data's time axis")
			}
		}
	}
	// the same key never repeats back to back even when the range is a single tick
	g2 := b.newGen(2, nil)
	g2.b = &builder{plan: b.plan, sum: PreloadSummary{EventStartNS: 0, EventEndNS: 24*hour + 1}, seed: 1, orgs: b.orgs, perOrg: b.perOrg, tokens: b.tokens}
	prev := int64(-1)
	for range 1000 {
		e := g2.end("k", hour, 2*hour+settle+5)
		if e == prev {
			t.Fatal("same end twice in a row")
		}
		prev = e
	}
}

func TestRequestIDsAreSeedWorkerCounterFunctions(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	b := testBuilder(t)
	g := b.newGen(4, nil)
	seen := map[string]bool{}
	for range 5000 {
		id := g.nextReq()
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("bad or repeated id %q", id)
		}
		seen[id] = true
	}
	if reqID(99, 4, 1) != reqID(99, 4, 1) || reqID(99, 4, 1) == reqID(99, 5, 1) || reqID(99, 4, 1) == reqID(98, 4, 1) {
		t.Fatal("ids do not derive from (seed, worker, n)")
	}
}

func TestDigestIsStableUnderKeyReordering(t *testing.T) {
	a := []json.RawMessage{json.RawMessage(`{"type":"vector","vector":[{"labels":{"a":"1","b":"2"},"sample":{"float":"0x3ff","n":1.50}}]}`)}
	b := []json.RawMessage{json.RawMessage(` { "vector" : [ { "sample":{"n":1.50,"float":"0x3ff"}, "labels":{"b":"2","a":"1"} } ], "type":"vector" } `)}
	da, err := digestValues(a)
	if err != nil {
		t.Fatal(err)
	}
	db, _ := digestValues(b)
	if da != db {
		t.Fatalf("digest depends on key order: %s %s", da, db)
	}
	c := []json.RawMessage{json.RawMessage(`{"type":"vector","vector":[{"labels":{"a":"1","b":"2"},"sample":{"float":"0x3ff","n":1.51}}]}`)}
	if dc, _ := digestValues(c); dc == da {
		t.Fatal("a different value has the same digest")
	}
	v1, err := digestView([]byte(`{"state":"ready","freshness":{"cached":false,"watermarks":[1]},"rate":{"per_second":2.5}}`))
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := digestView([]byte(`{"rate":{"per_second":2.5},"freshness":{"cached":true,"watermarks":[7,8]},"state":"ready"}`))
	if v1 != v2 {
		t.Fatal("view digest depends on volatile members")
	}
}

func signedRequest(secret string, id string, ts time.Time, body string, sig string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	if sig == "" {
		sig = providers.Sign([]byte(secret), ts.Unix(), id, []byte(body))
	}
	req.Header.Set(providers.HeaderDeliveryID, id)
	req.Header.Set(providers.HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
	req.Header.Set(providers.HeaderSignature, sig)
	return req
}

func TestWebhookReceiverVerifiesAndRecords(t *testing.T) {
	const secret = "0123456789abcdef0123"
	var out bytes.Buffer
	clock := time.Unix(1_800_000_000, 0)
	r := newWebhookReceiver(secret, &out, func() time.Time { return clock })
	body := `{"version":1,"delivery_id":"d1","event_kind":"open","org_id":"o1","entity":{"kind":"condition","id":"c1"},"impact":{"source":"firing","freshness":"fresh"}}`

	do := func(req *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	w := do(signedRequest(secret, "d1", clock, body, ""))
	if w.Code != http.StatusNoContent || w.Header().Get(providers.HeaderReceiptID) == "" {
		t.Fatalf("good delivery answered %d, receipt %q", w.Code, w.Header().Get(providers.HeaderReceiptID))
	}
	w = do(signedRequest(secret, "d1", clock.Add(time.Second), body, "")) // a retry: same id, fresh signature
	if w.Code != http.StatusNoContent {
		t.Fatalf("retry answered %d", w.Code)
	}
	if w = do(signedRequest(secret, "d1", clock, body, "v1=00")); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature answered %d", w.Code)
	}
	if w = do(signedRequest("another-secret-012345", "d1", clock, body, "")); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret answered %d", w.Code)
	}
	if w = do(signedRequest(secret, "d1", clock.Add(-6*time.Minute), body, "")); w.Code != http.StatusUnauthorized {
		t.Fatalf("stale timestamp answered %d", w.Code)
	}
	if w = do(signedRequest(secret, "other", clock, body, "")); w.Code != http.StatusUnauthorized {
		t.Fatalf("body naming another delivery answered %d", w.Code)
	}
	if r.total.Load() != 6 || r.verified.Load() != 2 || r.bad.Load() != 4 {
		t.Fatalf("counts total %d verified %d bad %d", r.total.Load(), r.verified.Load(), r.bad.Load())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 6 {
		t.Fatalf("%d notification lines", len(lines))
	}
	var n0, n1, n2 Notification
	json.Unmarshal([]byte(lines[0]), &n0)
	json.Unmarshal([]byte(lines[1]), &n1)
	json.Unmarshal([]byte(lines[2]), &n2)
	if !n0.SigOK || n0.Attempt != 1 || n0.Kind != "open" || n0.Org != "o1" || n0.Entity != "c1" || n0.Source != "firing" || n0.Freshness != "fresh" || n0.TMS != clock.UnixMilli() {
		t.Fatalf("first line %+v", n0)
	}
	if !n1.SigOK || n1.Attempt != 2 || n2.SigOK || n2.Attempt != 3 {
		t.Fatalf("attempt counting: %+v %+v", n1, n2)
	}
}

// fakeProduct answers the three routes the way the product shapes them, records the headers it saw and turns an over-limit budget into 429.
func fakeProduct(t *testing.T, mu *sync.Mutex, seen *[]http.Header) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*seen = append(*seen, r.Header.Clone())
		mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case pathQuery:
			var q httpapi.QueryBody
			if err := json.Unmarshal(raw, &q); err != nil {
				t.Errorf("fake product: %v", err)
			}
			if q.Budget.MaxReturned != 0 || q.Budget.MemoryBytes != 0 || q.Budget.TimeoutNS != 0 || q.Evaluation.Step == model.Int64(time.Second) {
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"code":"quota","retryable":false,"detail":"budget","request_id":"00000000000000000000000000000000"}`)
				return
			}
			var parts []string
			for _, p := range q.Projects {
				parts = append(parts, fmt.Sprintf(`{"project_id":%q,"value":{"type":"vector","vector":[]},"diagnostics":[],"watermarks":[],"completeness":"complete","stats":{"scans_started":"1","pages_read":"3","rows_read":"40","bytes_read":"5000","series_returned":"0","samples_returned":"2","logs_returned":"1","peak_memory_bytes":"7","elapsed_ns":"2500000","cached":false,"limit_reached":false}}`, p.String()))
			}
			fmt.Fprintf(w, `{"projects":[%s]}`, strings.Join(parts, ","))
		case pathTraces:
			fmt.Fprint(w, `{"state":"ready","partial":false,"path":{"edges":[]}}`)
		case pathRED:
			fmt.Fprint(w, `{"state":"ready","freshness":{"completeness":"complete","watermarks":[],"cached":false},"rate":{"state":"ready"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestWorkerRoundTripsEveryClassAndWritesExactColumns(t *testing.T) {
	var mu sync.Mutex
	var seen []http.Header
	srv := fakeProduct(t, &mu, &seen)
	defer srv.Close()

	b := testBuilder(t)
	path := filepath.Join(t.TempDir(), "queries.csv.gz")
	csv := newGzCSV(path, QueriesHeader)
	gold := b.goldens()
	q := newQRun(b.plan, b, srv.Client(), time.Now().Add(-time.Second), csv, gold, 99, 10)
	q.hostURL = srv.URL

	g := b.newGen(2, gold)
	now := b.sum.EventEndNS + hour
	var want []string
	for _, m := range mixWeights {
		if m.Class == ClassGolden {
			continue
		}
		tg := g.build(m.Class, now)
		q.do(2, tg, g.nextReq(), "", "")
		want = append(want, m.Class)
	}
	for _, gd := range gold {
		q.do(2, gd.target, g.nextReq(), gd.ID, "baseline")
		want = append(want, ClassGolden)
	}
	for _, c := range OverlimitClasses {
		q.do(proberWorker, g.overlimit(c, 1), g.nextReq(), "", "")
		want = append(want, c)
	}
	csv.Close()

	zf, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(zf)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := io.ReadAll(zr)
	lines := strings.Split(strings.TrimSpace(string(all)), "\n")
	cols := len(strings.Split(QueriesHeader, ","))
	if lines[0] != QueriesHeader || len(lines) != 1+len(want) {
		t.Fatalf("header %q, %d lines for %d requests", lines[0], len(lines), len(want))
	}
	digests := 0
	for i, l := range lines[1:] {
		f := strings.Split(l, ",")
		if len(f) != cols {
			t.Fatalf("row %d has %d columns, header %d: %s", i, len(f), cols, l)
		}
		if f[4] != want[i] {
			t.Fatalf("row %d class %s, want %s", i, f[4], want[i])
		}
		wantOver := strings.HasPrefix(want[i], "overlimit_")
		if wantOver && (f[2] != "429" || f[17] != "quota" || f[14] != "-") {
			t.Fatalf("over-limit row: %s", l)
		}
		if !wantOver {
			if f[2] != "200" || f[14] != "c" || f[17] != "" {
				t.Fatalf("row not a complete 200: %s", l)
			}
			if (f[4] == ClassPromInstant || f[4] == ClassLogLines) && (f[8] != strconv.Itoa(3*atoi(f[6])) || f[9] != strconv.Itoa(40*atoi(f[6])) || f[10] != strconv.Itoa(5000*atoi(f[6])) || f[15] != strconv.Itoa(3*atoi(f[6])) || f[12] != "2500") {
				t.Fatalf("stats not summed over projects: %s", l)
			}
		}
		if f[4] == ClassGolden {
			if len(f[18]) != 64 || f[20] == "" {
				t.Fatalf("golden row without digest or id: %s", l)
			}
			digests++
		} else if f[18] != "" || f[20] != "" {
			t.Fatalf("non-golden row with digest or id: %s", l)
		}
		if len(f[19]) != 16 {
			t.Fatalf("request id %q", f[19])
		}
	}
	if digests != len(gold) {
		t.Fatalf("%d digests for %d goldens", digests, len(gold))
	}
	re := regexp.MustCompile(`^[0-9a-f]{16}$`)
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != len(want) {
		t.Fatalf("product saw %d requests, harness sent %d", len(seen), len(want))
	}
	for _, h := range seen {
		if !re.MatchString(h.Get(headerRequest)) || h.Get("User-Agent") != userAgent || !strings.HasPrefix(h.Get("Authorization"), "Bearer token-") || h.Get("Content-Type") != "application/json" {
			t.Fatalf("headers %v", h)
		}
	}
	if q.sum.Requests[ClassGolden] != len(gold) || len(q.sum.GoldenRuns) != len(gold) || q.sum.Statuses[ClassOverMax][429] != 1 {
		t.Fatalf("summary %+v", q.sum)
	}
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
