// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// The synthetic Queries run. A real run holds millions of query rows (10 closed-loop workers); the validator's thresholds are written
// in terms of RATES and TIME-WEIGHTED concurrency (sum of request latencies over the window), never of row counts, so a fixture is
// free in how it is cut. The time-weighted mean in flight is sum(latency)/window: it cannot reach 9.5 with rows that are shorter than
// the gap between them, so the fixture's workers run closed loop with a 50 ms think-free gap and ~1.9 s requests (just under the 2 s
// budget): about 450k rows, generated and parsed in well under a second. The numbers the tests expect are computed here by the plain
// definition, independently of the runner.

const qgT0 = int64(1_800_000_000_000) // steady T0, unix ms

var qgClasses = []string{"promql_instant", "promql_range_1h", "promql_range_24h", "promql_org_24h", "promql_topk", "logql_lines", "logql_count_24h", "logql_rate_6h", "trace_view", "service_red"}
var qgGoldenLang = []string{"promql", "promql", "logql", "logql", "trace", "red"}

type qgFixture struct {
	steadyS     int
	workers     int
	latUS       func(g int) int64 // latency of the g-th interactive request
	latKey      string            // names latUS for the memo: a fixture with another latUS must set another key
	failEvery   int               // every Nth interactive request outside the degraded window answers 500 with a code
	cachedEvery int               // every Nth interactive request is a cache hit (0 = none)
	goldenIDs   int

	lossErrors       bool // loss window requests are explicit 504 errors instead of partial answers
	leakComplete     bool // one uncached, non-golden request of the loss window is labelled complete
	goldenBad        bool // one golden answer of 12 h into the run has another digest
	goldenNoBaseline bool
	noOverlimit      bool
	overlimit200     bool // one over-limit probe is answered 200
	overlimitNoCode  bool // over-limit probes answer 429 without a code
	overlimitInDown  bool // one probe of each class lands in the restart's downtime as a transport failure
	scanDropEvery    int  // every Nth trace_view/service_red request has no scan line

	preloadBytes map[string]int64
	preloadSpanS int
	preloadLate  bool // the preload ends after the steady T0
	badSlots     bool // project 5 has no preloaded record on a lost slot

	rulesPerMin      int
	ruleLeak         bool // a rule evaluation of the loss window is complete
	ruleBadReason    bool // an evaluation of the loss window is unknown with a reason outside the closed set
	flipComplete     bool // flip rules evaluate complete in the loss window (legitimate)
	preBurst         bool // the server link is saturated before the steady T0 (the preload)
	traceComplete    bool // trace_view requests are complete in the loss window (legitimate)
	okGoldenPartial  bool // the g_ok_ goldens are not complete in the loss window
	goldenLeak       bool // a lost-data golden answers complete in the loss window
	notifLeak        bool // a recovery is delivered in the loss window
	noRecoveryBefore bool
	ingestRate       int // records/s actually offered
	noLoss           bool
	noRestart        bool
	incomplete       bool
	orgs, projects   int
	gateInteractive  int
	gateIngest       int
	gateInputBytes   int64
	gateSteadyS      int
	gateRules        int

	scopeCPUs, memMax, swapMax, cgPath string
	gomax                              int
	serverOS                           string
	tmpfs                              bool
	ingestSame, querySame              bool
	ingestKernel                       string
	serverTxMbit                       float64
	pidFlip                            bool
	oom                                bool
	buildTags                          string
}

func qgDefault() qgFixture {
	return qgFixture{steadyS: 86400, workers: 10, latUS: func(int) int64 { return 1_900_000 }, cachedEvery: 100, goldenIDs: 6,
		preloadBytes: map[string]int64{}, preloadSpanS: 86400, rulesPerMin: 100, ingestRate: 100,
		orgs: 10, projects: 100, gateInteractive: 10, gateIngest: 100, gateInputBytes: 1 << 30, gateSteadyS: 86400, gateRules: 100,
		scopeCPUs: "0-7", memMax: "17179869184", swapMax: "0", cgPath: "/sys/fs/cgroup/soundpost-server.scope", gomax: 8, serverOS: "linux",
		ingestKernel: "6.12.74", serverTxMbit: 4, buildTags: "soundpost_faults"}
}

const (
	qgLossAtS    = 81000
	qgRestartAtS = 82800
	qgStopMS     = 3000
	qgReadyMS    = 20000
)

func qgWrite(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func qgGz(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, gzip.BestSpeed)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return out.Bytes()
}

// qgMemo caches the output of a heavy generator for the DEFAULT value of the fixture fields it depends on (key names them): most mutations
// leave the day's queries, rules and series alone and need not pay for them again. A generator whose inputs differ from the default runs
// every time and is not retained.
var qgMemoCache = struct {
	sync.Mutex
	m map[string]any
}{m: map[string]any{}}

func qgMemo[T any](name string, key func(qgFixture) string, fx qgFixture, gen func() T) T {
	k := name + "|" + key(fx)
	if key(fx) != key(qgDefault()) {
		return gen()
	}
	qgMemoCache.Lock()
	defer qgMemoCache.Unlock()
	if v, ok := qgMemoCache.m[k]; ok {
		return v.(T)
	}
	v := gen()
	qgMemoCache.m[k] = v
	return v
}

func qgJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// writeQueriesResult writes a complete synthetic run directory and returns it.
func writeQueriesResult(t *testing.T, fx qgFixture) string {
	t.Helper()
	dir := t.TempDir()
	lossUS := int64(qgLossAtS) * 1_000_000
	restartUS := int64(qgRestartAtS) * 1_000_000
	steadyUS := int64(fx.steadyS) * 1_000_000
	inLoss := func(us int64) bool { return us >= lossUS && us < restartUS }
	inDegraded := func(us int64) bool { return us >= lossUS && us <= restartUS+int64(qgStopMS+qgReadyMS)*1000 }

	// preload
	var pre bytes.Buffer
	pre.WriteString("start_us,sched_us,latency_us,late_us,status,project,records,bytes,signal\n")
	preEnd := qgT0 - 60_000
	preStart := preEnd - 3_600_000
	if fx.preloadLate {
		preEnd = qgT0 + 60_000
	}
	signals := map[string]any{}
	for i, sig := range []string{"metric", "log", "span"} {
		total := int64(1<<30) + 100_000
		if v, ok := fx.preloadBytes[sig]; ok {
			total = v
		}
		var sum, records, batches int64
		n := 0
		emit := func(status int, b int64) {
			fmt.Fprintf(&pre, "%d,%d,%d,0,%d,%d,512,%d,%s\n", int64(i*10_000_000+n*1000), int64(i*10_000_000+n*1000), 5000, status, n%100, b, sig)
			n++
			if status == 200 {
				sum += b
				records += 512
				batches++
			}
		}
		for rest := total; rest > 0; {
			b := min(rest, int64(1<<20))
			emit(200, b)
			rest -= b
			if n == 7 {
				emit(429, 999_999) // a refused request is not ACKed input
			}
		}
		signals[sig] = map[string]any{"batches": batches, "records": records, "encoded_bytes": sum,
			"event_start_ns": (preEnd - int64(fx.preloadSpanS)*1000) * 1_000_000, "event_end_ns": preEnd * 1_000_000}
	}
	qgWrite(t, dir, "preload/acks.csv.gz", qgGz(t, pre.Bytes()))
	slots := make([][]int, 100)
	for p := range slots {
		slots[p] = []int{p % 32, 32 + p%32}
		if fx.badSlots && p == 5 {
			slots[p] = []int{40, 41}
		}
	}
	preSummary := map[string]any{"start_unix_ms": preStart, "end_unix_ms": preEnd, "event_start_ns": (preEnd - int64(fx.preloadSpanS)*1000) * 1_000_000, "event_end_ns": preEnd * 1_000_000,
		"signals": signals, "slots_by_project": slots, "trace_samples": []any{map[string]any{"project": 0, "trace": strings.Repeat("a", 32), "service": "api", "start_ns": 1}}}
	qgWrite(t, dir, "preload/summary.json", qgJSON(t, preSummary))
	resPreload := map[string]any{}
	for k, v := range preSummary {
		if k != "slots_by_project" && k != "trace_samples" {
			resPreload[k] = v
		}
	}

	// ingest: one request a second carrying ingestRate records; refusals after the loss are expected
	type ingOut struct {
		gz                   []byte
		sent, acked, byteSum int64
	}
	ingRes := qgMemo("ingest", func(f qgFixture) string { return fmt.Sprintf("%d|%d", f.steadyS, f.ingestRate) }, fx, func() ingOut {
		var ing bytes.Buffer
		ing.WriteString("start_us,sched_us,latency_us,late_us,status,project,records,bytes,signal\n")
		var ingSent, ingAcked, ingBytes int64
		for s := range fx.steadyS {
			us := int64(s) * 1_000_000
			status := 200
			if inLoss(us) && s%10 == 0 {
				status = 503
			}
			fmt.Fprintf(&ing, "%d,%d,20000,0,%d,%d,%d,20000,mixed\n", us, us, status, s%100, fx.ingestRate)
			ingSent++
			if status == 200 {
				ingAcked++
				ingBytes += 20000
			}
			if s%30 == 0 {
				fmt.Fprintf(&ing, "%d,%d,20000,0,200,%d,3,300,control\n", us+500_000, us+500_000, 97+s%3)
				ingSent++
				ingAcked++
				ingBytes += 300
			}
			if s >= 5 && s < 8 { // shed by the generator: a row of the file, never a request
				fmt.Fprintf(&ing, "%d,%d,0,900,-1,%d,%d,20000,mixed\n", us+250_000, us, s%100, fx.ingestRate)
			}
		}
		return ingOut{gz: qgGz(t, ing.Bytes()), sent: ingSent, acked: ingAcked, byteSum: ingBytes}
	})
	qgWrite(t, dir, "ingest/acks.csv.gz", ingRes.gz)
	ingSent, ingAcked, ingBytes := ingRes.sent, ingRes.acked, ingRes.byteSum

	// queries
	type qOut struct {
		gz, scans []byte
		requests  int64
		byClass   map[string]int64
	}
	qRes := qgMemo("queries", func(f qgFixture) string {
		return fmt.Sprintf("%d|%d|%s|%d|%d|%d|%v|%v|%v|%v|%v|%v|%v|%v|%d|%v|%v|%v", f.steadyS, f.workers, f.latKey, f.failEvery, f.cachedEvery, f.goldenIDs, f.lossErrors, f.leakComplete, f.goldenBad,
			f.goldenNoBaseline, f.noOverlimit, f.overlimit200, f.overlimitNoCode, f.overlimitInDown, f.scanDropEvery, f.traceComplete, f.okGoldenPartial, f.goldenLeak)
	}, fx, func() qOut {
		var q bytes.Buffer
		q.WriteString("start_us,latency_us,status,worker,class,lang,projects,window_s,pages,rows,bytes,peak_mem,server_us,cached,completeness,returned,limit_reached,code,digest,req,golden\n")
		byClass := map[string]int64{}
		var requests int64
		var scans bytes.Buffer
		leaked, bad := false, false
		g := 0
		row := func(start, lat int64, status, worker int, class, lang string, pages, rows, bytesV int64, cached int, comp, code, digest, req, golden string) {
			fmt.Fprintf(&q, "%d,%d,%d,%d,%s,%s,1,3600,%d,%d,%d,1048576,%d,%d,%s,10,0,%s,%s,%s,%s\n", start, lat, status, worker, class, lang, pages, rows, bytesV, lat-1000, cached, comp, code, digest, req, golden)
			byClass[class]++
			requests++
		}
		nScan := 0
		for w := range fx.workers {
			t := int64(w) * 195_000
			for k := 0; t < steadyUS; k++ {
				lat := fx.latUS(g)
				req := fmt.Sprintf("%016x", g+1)
				golden := k%25 == 0 && !(fx.goldenNoBaseline && t < 90_000_000)
				cached := 0
				if fx.cachedEvery > 0 && g%fx.cachedEvery == 7 && !golden {
					cached = 1
				}
				status, comp, code := 200, "c", ""
				if golden {
					id := (w + k/25) % fx.goldenIDs
					digest := fmt.Sprintf("dg%d", id)
					if fx.goldenBad && !bad && id == 0 && t > 12*3600*1_000_000 && !inDegraded(t) {
						digest, bad = "bad", true
					}
					if inLoss(t) && (id >= 2 || fx.okGoldenPartial) {
						status, comp, code, digest = 200, "p", "", ""
						if fx.goldenLeak && id == 2 && !bad {
							comp, digest, bad = "c", "dg2", true
						}
						if fx.lossErrors {
							status, comp, code = 504, "-", "deadline_exceeded"
						}
					}
					row(t, lat, status, w, "golden", qgGoldenLang[id%6], 0, 0, 0, 0, comp, code, digest, req, qgGoldenName(id))
				} else {
					class := qgClasses[g%10]
					lang := map[string]string{"trace_view": "trace", "service_red": "red"}[class]
					if lang == "" {
						lang = "promql"
					}
					pages, rows, bytesV := int64(5+g%7), int64(1000+g%13*100), int64(50_000+g%11*1000)
					if class == "trace_view" || class == "service_red" {
						pages, rows, bytesV = 0, 0, 0
					}
					if fx.failEvery > 0 && g%fx.failEvery == 0 && !inDegraded(t) {
						status, comp, code = 500, "-", "internal"
					}
					if inLoss(t) {
						status, comp = 200, "p"
						if class == "trace_view" && fx.traceComplete {
							comp = "c"
						}
						if fx.lossErrors {
							status, comp, code = 504, "-", "deadline_exceeded"
						} else if fx.leakComplete && !leaked && cached == 0 {
							comp, leaked = "c", true
						}
					}
					row(t, lat, status, w, class, lang, pages, rows, bytesV, cached, comp, code, "", req, "")
					if class == "trace_view" || class == "service_red" {
						nScan++
						if fx.scanDropEvery == 0 || nScan%fx.scanDropEvery != 0 {
							fmt.Fprintf(&scans, `{"req":"%s","route":"%s","pages":%d,"rows":%d,"bytes":%d,"ms":%d}`+"\n", req, class, 2+g%3, 100+g%5, 10_000+g%7*100, lat/1000)
						}
					}
				}
				t += lat + 50_000
				g++
			}
		}
		if !fx.noOverlimit {
			probes := []struct {
				class, code string
				status      int
				lat         int64
			}{{"overlimit_returned", "result_too_large", 429, 300_000}, {"overlimit_memory", "memory_budget_exceeded", 429, 200_000},
				{"overlimit_timeout", "deadline_exceeded", 504, 50_000}, {"overlimit_default", "budget_exceeded", 429, 900_000}}
			first := true
			for i := range 288 {
				for j, p := range probes {
					start := int64(i*300+100+j) * 1_000_000
					status, code := p.status, p.code
					if fx.overlimitNoCode {
						code = ""
					}
					if fx.overlimit200 && first && p.class == "overlimit_memory" {
						status, code, first = 200, "", false
					}
					comp := "-"
					if status == 200 {
						comp = "c"
					}
					row(start, p.lat, status, 10, p.class, "promql", 0, 0, 0, 0, comp, code, "", fmt.Sprintf("%016x", 0xf000000+i*4+j), "")
				}
			}
			if fx.overlimitInDown {
				for j, p := range probes {
					start := restartUS + int64(1+j)*1_000_000
					row(start, 1000, 0, 10, p.class, "promql", 0, 0, 0, 0, "-", "", "", fmt.Sprintf("%016x", 0xe000000+j), "")
				}
			}
		}
		return qOut{gz: qgGz(t, q.Bytes()), scans: scans.Bytes(), requests: requests, byClass: byClass}
	})
	byClass, requests := qRes.byClass, qRes.requests
	qgWrite(t, dir, "queries/queries.csv.gz", qRes.gz)
	qgWrite(t, dir, "server/scans.jsonl", qRes.scans)

	// rules: rulesPerMin evaluations a minute, one per rule, 100 ms apart per rule; q lines for every tenth
	t0ns := qgT0 * 1_000_000
	lossNS, restartNS := (qgT0+int64(qgLossAtS)*1000)*1_000_000, (qgT0+int64(qgRestartAtS)*1000)*1_000_000
	rules := qgMemo("rules", func(f qgFixture) string {
		return fmt.Sprintf("%d|%d|%v|%v|%v", f.steadyS, f.rulesPerMin, f.ruleLeak, f.ruleBadReason, f.flipComplete)
	}, fx, func() []byte {
		var rules bytes.Buffer
		leakedRule, leakedReason := false, false
		for m := range fx.steadyS / 60 {
			for r := range fx.rulesPerMin {
				tn := t0ns + int64(m)*60_000_000_000 + int64(r)*500_000_000
				outcome, reason := "complete", ""
				if tn >= lossNS && tn < restartNS {
					outcome, reason = "unknown", "unavailable"
					if fx.ruleLeak && !leakedRule {
						outcome, reason, leakedRule = "complete", "", true
					} else if fx.ruleBadReason && !leakedReason && r == 3 {
						reason, leakedReason = "nothing_to_see", true
					}
				}
				rid := fmt.Sprintf("%032x", r+1)
				if r >= 97 {
					rid = qgRuleHex(r)
					if fx.flipComplete && tn >= lossNS && tn < restartNS {
						outcome, reason = "complete", ""
					}
				}
				fmt.Fprintf(&rules, `{"k":"e","t_ns":%d,"at_ns":%d,"project":"%032x","rule":"%s","mode":"live","outcome":"%s","reason":"%s","members":1,"ms":3,"kind":"alert"}`+"\n", tn, tn-1_000_000, r+1, rid, outcome, reason)
				if (m*100+r)%10 == 0 {
					fmt.Fprintf(&rules, `{"k":"q","t_ns":%d,"rule":"%s","at_ns":%d,"pages":%d,"rows":%d,"bytes":%d,"peak_mem":1048576,"ok":true}`+"\n", tn-500_000, rid, tn-1_000_000, 4+r%5, 200+r, 8000+r*10)
				}
			}
		}
		for i := range 5 { // the replay after the restart
			tn := restartNS + int64(60+i)*1_000_000_000
			fmt.Fprintf(&rules, `{"k":"e","t_ns":%d,"at_ns":%d,"project":"%032x","rule":"%032x","mode":"backfill","outcome":"complete","reason":"","members":1,"ms":3,"kind":"alert"}`+"\n", tn, tn-60_000_000_000, 1, 1)
		}
		return rules.Bytes()
	})
	qgWrite(t, dir, "server/rules.jsonl", rules)

	// notifications
	var notes bytes.Buffer
	note := func(tms int64, kind, source, fresh string, i int) {
		fmt.Fprintf(&notes, `{"t_ms":%d,"delivery":"d%d","entity":"c%d","org":"o","kind":"%s","source":"%s","freshness":"%s","attempt":1,"sig_ok":true}`+"\n", tms, i, i%7, kind, source, fresh)
	}
	for i := range 30 {
		note(qgT0+int64(i)*600_000, "open", "firing", "fresh", i)
	}
	if !fx.noRecoveryBefore {
		for i := range 8 {
			note(qgT0+int64(i)*300_000+150_000, "recovery", "recovered", "fresh", 100+i)
		}
	}
	for i := range 5 {
		note(qgT0+int64(qgLossAtS)*1000+int64(i)*60_000, "reminder", "unknown", "stale", 200+i)
	}
	if fx.notifLeak {
		note(qgT0+int64(qgLossAtS)*1000+400_000, "recovery", "recovered", "fresh", 300)
	}
	note(qgT0+int64(qgRestartAtS)*1000+300_000, "recovery", "recovered", "fresh", 400)
	qgWrite(t, dir, "queries/notifications.jsonl", notes.Bytes())

	// server monitor, events and net series
	series := qgMemo("series", func(f qgFixture) string { return fmt.Sprintf("%d|%v|%v", f.steadyS, f.pidFlip, f.oom) }, fx, func() []byte {
		var series bytes.Buffer
		pid := 101
		var utime uint64
		for ts := qgT0; ts < qgT0+int64(fx.steadyS)*1000; ts += 10_000 {
			rel := ts - qgT0
			down := rel >= int64(qgRestartAtS)*1000 && rel < int64(qgRestartAtS)*1000+qgStopMS+qgReadyMS
			cur := pid
			if rel >= int64(qgRestartAtS)*1000 {
				cur = 102
				if rel%20_000 == 0 && fx.pidFlip {
					cur = 103
				}
			}
			if down {
				fmt.Fprintf(&series, `{"t_ms":%d,"pid":0}`+"\n", ts)
				continue
			}
			if cur != pid {
				utime = 0
				pid = cur
			}
			utime += 100
			oom := 0
			if fx.oom && rel > 1_000_000 {
				oom = 1
			}
			fmt.Fprintf(&series, `{"t_ms":%d,"pid":%d,"rss_kib":%d,"hwm_kib":%d,"io_write_bytes":%d,"utime_ticks":%d,"stime_ticks":0,"load1":1.5,"data_bytes":%d,"cgroup_oom_kill":%d}`+"\n",
				ts, cur, 4_000_000+rel%50_000, 5_000_000, rel*10, utime, 3_000_000_000+rel*1000, oom)
		}
		return series.Bytes()
	})
	qgWrite(t, dir, "server/server-series.jsonl", series)
	var events bytes.Buffer
	fmt.Fprintf(&events, `{"t_ms":%d,"event":"start","pid_after":101}`+"\n", qgT0-30_000)
	if !fx.noLoss {
		fmt.Fprintf(&events, `{"t_ms":%d,"event":"shard_loss","mode":"slots 0-31","note":"closed 32"}`+"\n", qgT0+int64(qgLossAtS)*1000)
	}
	if !fx.noRestart {
		fmt.Fprintf(&events, `{"t_ms":%d,"event":"restart","mode":"graceful","pid_before":101,"pid_after":102,"exit":"exit status 0","stop_ms":%d,"ready_ms":%d}`+"\n", qgT0+int64(qgRestartAtS)*1000+qgStopMS+qgReadyMS, qgStopMS, qgReadyMS)
	}
	qgWrite(t, dir, "server/events.jsonl", events.Bytes())
	net := func(name string, txMbit float64, burst bool) {
		b := qgMemo("net", func(f qgFixture) string { return fmt.Sprintf("%d|%v|%v", f.steadyS, txMbit, burst) }, fx, func() []byte {
			var b bytes.Buffer
			for ts := qgT0 - 100_000; ts < qgT0+int64(fx.steadyS)*1000+100_000; ts += 10_000 {
				rel := float64(ts - qgT0 + 100_000)
				tx := rel * txMbit * 125
				if burst { // the preload, NIC-bound, before the steady T0
					tx = rel * 95 * 125
					if ts >= qgT0 {
						tx = 100_000*95*125 + (rel-100_000)*txMbit*125
					}
				}
				fmt.Fprintf(&b, `{"t_ms":%d,"iface":"eth0","rx_bytes":%d,"tx_bytes":%d}`+"\n", ts, int64(rel*750), int64(tx))
			}
			return b.Bytes()
		})
		qgWrite(t, dir, name, b)
	}
	net("server/net-series.jsonl", fx.serverTxMbit, fx.preBurst)
	net("ingest/net-series.jsonl", 3, false)
	net("queries/net-series.jsonl", 12, false)

	// hosts
	facts := func(id string, kernel string) map[string]any {
		return map[string]any{"host_id": id, "os": "linux", "arch": "amd64", "kernel": kernel, "logical_cpus": 16, "mem_total_kib": 32 << 20, "gomaxprocs": 8, "cpus_allowed": "0-15",
			"data_dir_filesystem": "ext2/ext3", "block_device_model": "QEMU HARDDISK", "data_dir_on_tmpfs": false}
	}
	server := facts("aaaaaaaaaaaaaaaa", "6.12.74")
	server["os"], server["gomaxprocs"], server["data_dir_on_tmpfs"] = fx.serverOS, fx.gomax, fx.tmpfs
	if fx.cgPath != "" || fx.scopeCPUs != "" {
		server["cgroup_path"], server["cgroup_cpus_effective"], server["cgroup_memory_max"], server["cgroup_memory_swap_max"] = fx.cgPath, fx.scopeCPUs, fx.memMax, fx.swapMax
	}
	ingest, query := facts("bbbbbbbbbbbbbbbb", fx.ingestKernel), facts("cccccccccccccccc", "6.12.74")
	if fx.ingestSame {
		ingest["host_id"] = server["host_id"]
	}
	if fx.querySame {
		query["host_id"] = server["host_id"]
	}
	qgWrite(t, dir, "server/host.json", qgJSON(t, server))
	qgWrite(t, dir, "ingest/host.json", qgJSON(t, ingest))
	qgWrite(t, dir, "queries/host.json", qgJSON(t, query))
	qgWrite(t, dir, "ingest/load-summary.json", qgJSON(t, map[string]any{"t0_unix_ms": qgT0}))
	qgWrite(t, dir, "queries/query-summary.json", qgJSON(t, map[string]any{"t0_unix_ms": qgT0, "workers": fx.workers}))
	build := "source_tree_sha256=" + strings.Repeat("ab", 32) + "\n" + `{"version":"0.0.0-overhead","commit":"none","build_id":"src-0123456789abcdef","platform":"linux/amd64"}` + "\n" + strings.Repeat("cd", 32) + "  /home/x/bin/soundpost\n"
	qgWrite(t, dir, "BUILD.txt", []byte(build))

	files := map[string]string{}
	for _, name := range []string{"BUILD.txt", "server/server-series.jsonl", "server/events.jsonl", "server/host.json", "server/rules.jsonl", "server/scans.jsonl", "server/net-series.jsonl",
		"preload/acks.csv.gz", "preload/summary.json", "ingest/acks.csv.gz", "ingest/load-summary.json", "ingest/net-series.jsonl", "ingest/host.json",
		"queries/queries.csv.gz", "queries/query-summary.json", "queries/notifications.jsonl", "queries/net-series.jsonl", "queries/host.json"} {
		files[name] = shDigest(t, filepath.Join(dir, filepath.FromSlash(name)))
	}
	var goldenIDs []string
	for i := range fx.goldenIDs {
		goldenIDs = append(goldenIDs, qgGoldenName(i))
	}
	lossSlots := make([]int, 32)
	for i := range lossSlots {
		lossSlots[i] = i
	}
	res := map[string]any{"schema": "soundpost-queries-result/1", "harness": "fixtures/overhead/queries", "complete": !fx.incomplete}
	res["gate"] = map[string]any{"orgs": fx.orgs, "projects": fx.projects, "series_per_project": 30, "seed": 20261124, "input_bytes_per_signal": fx.gateInputBytes, "steady_s": fx.gateSteadyS,
		"interactive": fx.gateInteractive, "rules_per_minute": fx.gateRules, "ingest_rate": fx.gateIngest, "loss_at_s": qgLossAtS, "restart_at_s": qgRestartAtS, "loss_slots": lossSlots}
	res["server_host"], res["ingest_host"], res["query_host"] = server, ingest, query
	res["build"] = map[string]any{"source_tree_sha256": strings.Repeat("ab", 32), "soundpost_version_json": `{"version":"0.0.0-overhead","commit":"none","build_id":"src-0123456789abcdef","platform":"linux/amd64"}`,
		"soundpost_sha256": strings.Repeat("cd", 32), "harness_sha256": strings.Repeat("ef", 32), "go": "go version go1.27.3 linux/amd64", "build_tags": fx.buildTags}
	res["file_sha256"] = files
	res["steady"] = map[string]any{"t0_unix_ms": qgT0}
	res["preload"] = resPreload
	res["ingest"] = map[string]any{"requests_sent": ingSent, "requests_acked": ingAcked, "requests_refused": 0, "requests_transport_failed": 0, "requests_shed": 0, "encoded_bytes_acked": ingBytes}
	res["queries"] = map[string]any{"requests": requests, "by_class": byClass, "golden_ids": goldenIDs, "workers": fx.workers}
	res["server_events"] = []any{}
	qgWrite(t, dir, "result.json", qgJSON(t, res))
	return dir
}

func qgSpec() RowSpec {
	return RowSpec{ID: "overhead.queries.gate", Suite: SuiteOverhead, Required: true, Runner: "overhead_queries",
		Subject: &Subject{Family: "soundpost-queries", Version: "design-13", OS: "any", Arch: "any"},
		Params:  map[string]string{"input_bytes": "1073741824", "duration": "86400", "interactive": "10", "rules_per_minute": "100", "ingest_rate": "100", "seed": "20261124"}}
}

func qgRun(t *testing.T, dir string, spec RowSpec) Row {
	t.Helper()
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	reportDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(reportDir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	rc := &runCtx{root: t.TempDir(), reportDir: reportDir, workloads: w, host: hostInfo()}
	t.Setenv(queriesEnv, dir)
	row := runOverheadQueries(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, spec.Required, *spec.Subject
	if err := ValidateRow(row); err != nil {
		t.Fatalf("runner produced an invalid row: %v\n%+v", err, row)
	}
	return row
}

func qgReading(t *testing.T, row Row, name string) float64 {
	t.Helper()
	for _, r := range row.Readings {
		if r.Name == name {
			if r.Availability != AvailAvailable || r.Value == nil {
				t.Fatalf("reading %s is not available: %+v", name, r)
			}
			return *r.Value
		}
	}
	t.Fatalf("row has no reading %s", name)
	return 0
}

func TestQueriesFullRunWithinTheGatePasses(t *testing.T) {
	row := qgRun(t, writeQueriesResult(t, qgDefault()), qgSpec())
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("a full run within the gate must pass: state %s outcome %s reason %q failures %v budgets %+v", row.State, row.Outcome, row.Reason, row.Failures, row.Budgets)
	}
	if b := budgetOf(t, row, "queries_interactive_p95_ms"); b.Limit != 2000 || b.Observed != 1900 || !b.Within {
		t.Errorf("p95 budget %+v", b)
	}
	for _, name := range []string{"queries_false_healthy_answers", "queries_overlimit_unexplained", "queries_golden_mismatches"} {
		if b := budgetOf(t, row, name); b.Limit != 0 || b.Observed != 0 || !b.Within {
			t.Errorf("budget %s: %+v", name, b)
		}
	}
	if row.Build == nil || row.Build.Family != "soundpost-queries" || !strings.Contains(row.Build.ID, "src-0123456789abcdef") || len(row.Evidence) == 0 {
		t.Errorf("row is not bound to the build and the run: %+v", row.Build)
	}
	limits := strings.Join(row.Limits, "\n")
	for _, want := range []string{"soundpost_faults", "virtual", "one run", "loss window", "96 Mbit/s", "harness"} {
		if !strings.Contains(limits, want) {
			t.Errorf("limits do not say %q:\n%s", want, limits)
		}
	}
	// readings recomputed from the raw files
	if v := qgReading(t, row, "rule_evaluations_per_minute_mean"); v < 99.5 || v > 100.5 {
		t.Errorf("rule evaluations per minute %v", v)
	}
	if v := qgReading(t, row, "cached_fraction"); v < 0.008 || v > 0.011 {
		t.Errorf("cached fraction %v", v)
	}
	if v := qgReading(t, row, "interactive_mean_in_flight"); v < 9.7 || v > 9.8 {
		t.Errorf("mean in flight %v", v)
	}
	if v := qgReading(t, row, "interactive_max_in_flight"); v != 10 {
		t.Errorf("max in flight %v", v)
	}
	if v := qgReading(t, row, "scan_bytes_mean.trace_view"); v < 10_000 || v > 11_000 {
		t.Errorf("trace_view bytes come from scans.jsonl: %v", v)
	}
	if v := qgReading(t, row, "scan_pages_mean.promql_instant"); v < 5 || v > 11 {
		t.Errorf("promql pages %v", v)
	}
	if v := qgReading(t, row, "preload_encoded_bytes.metric"); v != float64(1<<30)+100_000 {
		t.Errorf("preload bytes %v", v)
	}
	if v := qgReading(t, row, "recovered_notifications_before_loss"); v != 8 {
		t.Errorf("recoveries before the loss %v", v)
	}
	if v := qgReading(t, row, "overlimit_probes.overlimit_memory"); v != 288 {
		t.Errorf("probes %v", v)
	}
	if v := qgReading(t, row, "link_server_peak_mbit"); v < 3.9 || v > 6.1 {
		t.Errorf("server link peak %v", v)
	}
	if len(row.Series) < 2 || len(row.Series[0].Values) != 24 {
		t.Errorf("per-hour p95 series missing: %+v", row.Series)
	}
}

// Explicit errors in the degraded window count with their measured latency and are never a false healthy answer.
func TestQueriesExplicitErrorsInTheLossWindowAreHonest(t *testing.T) {
	fx := qgDefault()
	fx.lossErrors = true
	row := qgRun(t, writeQueriesResult(t, fx), qgSpec())
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("explicit errors during the loss are the right behaviour: %s %s %q %+v", row.State, row.Outcome, row.Reason, row.Budgets)
	}
}

// An over-limit probe that reaches a server that is being restarted cannot be answered with a resource error; it is not unexplained.
func TestQueriesOverlimitProbeInRestartDowntimeIsNotUnexplained(t *testing.T) {
	fx := qgDefault()
	fx.overlimitInDown = true
	row := qgRun(t, writeQueriesResult(t, fx), qgSpec())
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("%s %s %q %+v", row.State, row.Outcome, row.Reason, row.Budgets)
	}
}

func TestQueriesEachMissedGateNumberIsAMeasuredFailure(t *testing.T) {
	cases := map[string]struct {
		mutate func(*qgFixture)
		budget string
	}{
		"p95 over 2 s": {func(f *qgFixture) {
			f.latKey = "p95"
			f.latUS = func(g int) int64 {
				if g%10 == 0 {
					return 3_000_000
				}
				return 1_900_000
			}
		}, "queries_interactive_p95_ms"},
		"an unexplained 500 on every 10th request counts as the timeout": {func(f *qgFixture) { f.failEvery = 10 }, "queries_interactive_p95_ms"},
		"one over-limit probe answered 200":                              {func(f *qgFixture) { f.overlimit200 = true }, "queries_overlimit_unexplained"},
		"over-limit probes answered 429 without a code":                  {func(f *qgFixture) { f.overlimitNoCode = true }, "queries_overlimit_unexplained"},
		"a complete uncached answer in the loss window":                  {func(f *qgFixture) { f.leakComplete = true }, "queries_false_healthy_answers"},
		"a complete rule evaluation in the loss window":                  {func(f *qgFixture) { f.ruleLeak = true }, "queries_false_healthy_answers"},
		"an unknown evaluation with a reason outside the closed set":     {func(f *qgFixture) { f.ruleBadReason = true }, "queries_false_healthy_answers"},
		"a recovery notification in the loss window":                     {func(f *qgFixture) { f.notifLeak = true }, "queries_false_healthy_answers"},
		"a golden digest that differs":                                   {func(f *qgFixture) { f.goldenBad = true }, "queries_golden_mismatches"},
	}
	for name, c := range cases {
		fx := qgDefault()
		c.mutate(&fx)
		row := qgRun(t, writeQueriesResult(t, fx), qgSpec())
		if row.State != StateExercised || row.Outcome != OutcomeFailed {
			t.Errorf("%s: want a measured failure, got state %s outcome %s reason %q", name, row.State, row.Outcome, row.Reason)
			continue
		}
		if b := budgetOf(t, row, c.budget); b.Within || b.Observed < 1 {
			t.Errorf("%s: budget %s is within: %+v", name, c.budget, b)
		}
		for _, b := range row.Budgets {
			if b.Name != c.budget && !b.Within {
				t.Errorf("%s: unrelated budget %s fails: %+v", name, b.Name, b)
			}
		}
		if len(row.Failures) != 0 {
			t.Errorf("%s: a budget miss carries no failure text: %v", name, row.Failures)
		}
	}
}

func TestQueriesReducedRunIsNeverExercised(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*qgFixture)
		want   string // the check that must be the one that trips
	}{
		{"preload one MB under 1 GiB", func(f *qgFixture) { f.preloadBytes["log"] = 1<<30 - 1_000_000 }, "encoded bytes of log"},
		{"preload 8 MiB over", func(f *qgFixture) { f.preloadBytes["span"] = 1<<30 + 8<<20 }, "encoded bytes of span"},
		{"preload spans 12 h", func(f *qgFixture) { f.preloadSpanS = 12 * 3600 }, "12.0 h"},
		{"preload ends after the steady", func(f *qgFixture) { f.preloadLate = true }, "preload ended after"},
		{"23 h run", func(f *qgFixture) { f.steadyS, f.gateSteadyS = 82800, 82800 }, "weaker"},
		{"the run is 23 h but says 24 h", func(f *qgFixture) { f.steadyS = 82800 }, "steady window"},
		{"9 concurrent workers", func(f *qgFixture) { f.workers = 9 }, "9 interactive workers"},
		{"11 concurrent workers", func(f *qgFixture) { f.workers = 11 }, "11 interactive workers"},
		{"90 rule evaluations a minute", func(f *qgFixture) { f.rulesPerMin = 90 }, "rule evaluations a minute"},
		{"9 CPUs in the scope", func(f *qgFixture) { f.scopeCPUs = "0-8" }, "D90"},
		{"swap allowed", func(f *qgFixture) { f.swapMax = "max" }, "D90"},
		{"no cgroup scope", func(f *qgFixture) { f.cgPath, f.scopeCPUs, f.memMax, f.swapMax = "", "", "", "" }, "D90"},
		{"data directory on tmpfs", func(f *qgFixture) { f.tmpfs = true }, "tmpfs"},
		{"server is not linux", func(f *qgFixture) { f.serverOS = "windows" }, "not linux"},
		{"half the ingest rate", func(f *qgFixture) { f.ingestRate = 50 }, "records/s"},
		{"estate of 5 orgs", func(f *qgFixture) { f.orgs = 5 }, "5 orgs"},
		{"estate of 50 projects", func(f *qgFixture) { f.projects = 50 }, "50 projects"},
		{"gate says 9 interactive", func(f *qgFixture) { f.gateInteractive = 9 }, "weaker"},
		{"gate says 50 rules a minute", func(f *qgFixture) { f.gateRules = 50 }, "weaker"},
		{"gate says 512 MiB of input", func(f *qgFixture) { f.gateInputBytes = 512 << 20 }, "weaker"},
		{"gate says ingest 50", func(f *qgFixture) { f.gateIngest = 50 }, "weaker"},
		{"no shard_loss event", func(f *qgFixture) { f.noLoss = true }, "shard_loss"},
		{"no restart event", func(f *qgFixture) { f.noRestart = true }, "graceful restart"},
		{"the summary says incomplete", func(f *qgFixture) { f.incomplete = true }, "incomplete"},
		{"10 percent cached answers", func(f *qgFixture) { f.cachedEvery = 10 }, "result cache"},
		{"no over-limit probes", func(f *qgFixture) { f.noOverlimit = true }, "explicit-resource-error"},
		{"the link is saturated", func(f *qgFixture) { f.serverTxMbit = 95 }, "link bound the run"},
		{"ingest generator on the server", func(f *qgFixture) { f.ingestSame = true }, "co-located"},
		{"query role on the server", func(f *qgFixture) { f.querySame = true }, "co-located"},
		{"ingest host kernel unknown", func(f *qgFixture) { f.ingestKernel = "" }, "kernel"},
		{"the server pid changes silently", func(f *qgFixture) { f.pidFlip = true }, "outside the recorded restart"},
		{"the cgroup OOM-killed", func(f *qgFixture) { f.oom = true }, "OOM"},
		{"only five golden ids", func(f *qgFixture) { f.goldenIDs = 5 }, "golden query ids"},
		{"no golden baseline", func(f *qgFixture) { f.goldenNoBaseline = true }, "first minute"},
		{"no recovery ever observed", func(f *qgFixture) { f.noRecoveryBefore = true }, "recovery notifications"},
		{"isolation goldens not complete in the loss window", func(f *qgFixture) { f.okGoldenPartial = true }, "isolation"},
	}
	for _, c := range cases {
		fx := qgDefault()
		c.mutate(&fx)
		row := qgRun(t, writeQueriesResult(t, fx), qgSpec())
		if row.State != StateNotExercised || !strings.Contains(row.Reason, "reduced run") || !strings.Contains(row.Reason, c.want) || len(row.Budgets) != 0 {
			t.Errorf("%s: must be not_exercised with 'reduced run' and %q, got state %s reason %q budgets %v", c.name, c.want, row.State, row.Reason, row.Budgets)
		}
	}
}

func TestQueriesInconsistentOrTamperedResultIsRefused(t *testing.T) {
	refused := func(name string, row Row, want string) {
		t.Helper()
		if row.State != StateNotExercised || !strings.Contains(row.Reason, "refused") || !strings.Contains(row.Reason, want) {
			t.Errorf("%s: want refused/%q, got %s %q", name, want, row.State, row.Reason)
		}
	}
	// fixture knobs that make the documents inconsistent
	for name, c := range map[string]struct {
		mutate func(*qgFixture)
		want   string
	}{
		"trace rows that do not join the server's scans": {func(f *qgFixture) { f.scanDropEvery = 10 }, "scans"},
		"a project without a record on a lost slot":      {func(f *qgFixture) { f.badSlots = true }, "slot"},
		"a build without the faults tag":                 {func(f *qgFixture) { f.buildTags = "" }, "soundpost_faults"},
	} {
		fx := qgDefault()
		c.mutate(&fx)
		refused(name, qgRun(t, writeQueriesResult(t, fx), qgSpec()), c.want)
	}

	edit := func(dir string, fn func(doc map[string]any)) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		fn(doc)
		qgWrite(t, dir, "result.json", qgJSON(t, doc))
	}
	dir := writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) { d["schema"] = "soundpost-queries-result/2" })
	refused("another schema", qgRun(t, dir, qgSpec()), "schema")
	dir = writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) { d["harness"] = "fixtures/overhead/singlehost" })
	refused("another harness", qgRun(t, dir, qgSpec()), "harness")
	dir = writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) { d["queries"].(map[string]any)["requests"] = 12 })
	refused("stated request count", qgRun(t, dir, qgSpec()), "recompute")
	dir = writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) {
		d["preload"].(map[string]any)["signals"].(map[string]any)["metric"].(map[string]any)["encoded_bytes"] = 5 << 30
	})
	refused("stated preload bytes", qgRun(t, dir, qgSpec()), "recompute")
	dir = writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) { d["ingest"].(map[string]any)["requests_acked"] = 7 })
	refused("stated ACKs", qgRun(t, dir, qgSpec()), "recompute")
	dir = writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) { d["server_host"].(map[string]any)["host_id"] = "dddddddddddddddd" })
	refused("host facts that differ from host.json", qgRun(t, dir, qgSpec()), "host")
	dir = writeQueriesResult(t, qgDefault())
	edit(dir, func(d map[string]any) { delete(d["file_sha256"].(map[string]any), "server/rules.jsonl") })
	refused("an unbound raw file", qgRun(t, dir, qgSpec()), "digest")

	// raw files replaced after the digests were taken
	for _, name := range []string{"queries/queries.csv.gz", "server/rules.jsonl", "server/scans.jsonl", "queries/notifications.jsonl", "server/events.jsonl", "server/net-series.jsonl", "preload/acks.csv.gz", "ingest/acks.csv.gz", "preload/summary.json", "server/server-series.jsonl", "queries/host.json"} {
		dir := writeQueriesResult(t, qgDefault())
		raw, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		qgWrite(t, dir, name, append(raw, '\n', '\n'))
		refused("tampered "+name, qgRun(t, dir, qgSpec()), "digest")
	}
	// a raw file that is gone
	dir = writeQueriesResult(t, qgDefault())
	if err := os.Remove(filepath.Join(dir, "queries", "notifications.jsonl")); err != nil {
		t.Fatal(err)
	}
	refused("missing raw file", qgRun(t, dir, qgSpec()), "notifications")
}

func TestQueriesWithoutAResultIsNotExercised(t *testing.T) {
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(queriesEnv, "")
	rc := &runCtx{root: t.TempDir(), reportDir: t.TempDir(), workloads: w}
	row := runOverheadQueries(rc, qgSpec())
	if row.State != StateNotExercised || !strings.Contains(row.Reason, queriesEnv) {
		t.Errorf("missing result: %s %q", row.State, row.Reason)
	}
	spec := qgSpec()
	spec.Params["result"] = filepath.Join(t.TempDir(), "absent")
	if row := runOverheadQueries(rc, spec); row.State != StateNotExercised {
		t.Errorf("unreadable result: %s", row.State)
	}
}

func TestQueriesMatrixRowCannotBeWeakened(t *testing.T) {
	for name, mutate := range map[string]func(map[string]string){
		"shorter duration":     func(p map[string]string) { p["duration"] = "3600" },
		"less input":           func(p map[string]string) { p["input_bytes"] = "1048576" },
		"fewer interactive":    func(p map[string]string) { p["interactive"] = "1" },
		"fewer rules a minute": func(p map[string]string) { p["rules_per_minute"] = "10" },
		"lower ingest rate":    func(p map[string]string) { p["ingest_rate"] = "10" },
		"no seed":              func(p map[string]string) { delete(p, "seed") },
	} {
		spec := qgSpec()
		mutate(spec.Params)
		row := qgRun(t, writeQueriesResult(t, qgDefault()), spec)
		if row.State != StateNotExercised || !strings.Contains(row.Reason, "cannot be weakened") && !strings.Contains(row.Reason, "seed") {
			t.Errorf("%s: %s %q", name, row.State, row.Reason)
		}
	}
}

func TestQueriesBudgetsAndMatrixRowMatchDesign(t *testing.T) {
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{"queries_interactive_p95_ms": 2000, "queries_false_healthy_answers": 0, "queries_overlimit_unexplained": 0, "queries_golden_mismatches": 0} {
		b, ok := w.Budgets[name]
		if !ok || b.Limit != want || b.Source == "" || b.Unit == "" {
			t.Errorf("budget %s = %+v, design section 13 says %v", name, b, want)
		}
	}
	design, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "superpowers", "specs", "2026-11-03-soundpost-design.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"24-hour representative scans with fixed 1-GiB encoded input per signal and concurrent ingest; 10 active interactive queries, 100 rules/minute", "p95 interactive <2 s, explicit resource error on limit, no false healthy state; record bytes/pages scanned"} {
		if !strings.Contains(string(design), phrase) {
			t.Errorf("design section 13 no longer says %q: re-derive the Queries gate", phrase)
		}
	}
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Rows {
		if r.ID == "overhead.queries.gate" {
			if r.Runner != "overhead_queries" {
				t.Errorf("the queries row uses runner %q", r.Runner)
			}
			if why, ok := queriesGateParams(r); !ok {
				t.Errorf("the matrix row does not pin the design workload: %s", why)
			}
			if r.Subject == nil || r.Subject.Family != "soundpost-queries" || r.Subject.Version != "design-13" {
				t.Errorf("subject %+v", r.Subject)
			}
			if _, ok := runners[r.Runner]; !ok {
				t.Errorf("runner %q is not registered", r.Runner)
			}
			return
		}
	}
	t.Error("matrix has no overhead.queries.gate row")
}

// The validator and the harness agree on the raw formats they share: the header lines are copied, so they are compared with the source.
func TestQueriesRawHeadersMatchTheHarnessContract(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "fixtures", "overhead", "queries", "contract.go"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"QueriesHeader": queriesHeader, "AcksHeader": queriesAcksHeader} {
		m := regexp.MustCompile(`const ` + name + ` = "([^"]*)"`).FindSubmatch(src)
		if m == nil || string(m[1]) != want {
			t.Errorf("%s in contract.go is %q, the validator reads %q", name, m, want)
		}
	}
	for name, want := range map[string]string{"ResultSchema": queriesResultSchema, "HarnessName": queriesHarness, "InputBytesPerSignal": "1 << 30", "SteadyS": "86400"} {
		m := regexp.MustCompile(`(?m)^\s*` + name + `\s*=\s*(.*?)\s*(//.*)?$`).FindSubmatch(src)
		if m == nil || strings.Trim(string(m[1]), `"`) != want {
			t.Errorf("%s in contract.go is %q, the validator pins %q", name, m, want)
		}
	}
}

// qgGoldenName: the first two golden ids are isolation proofs over unlost data (prefix g_ok_), the rest read lost data.
func qgGoldenName(id int) string {
	if id < 2 {
		return fmt.Sprintf("g_ok_%d", id)
	}
	return fmt.Sprintf("g%d", id)
}

// qgRuleHex is the id of the rule of project p, derived as fixtures/overhead/queries ident(seed, "rule", p) does.
func qgRuleHex(p int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("soundpost/overhead/queries/v1/%d/rule/%d", 20261124, p)))
	return hex.EncodeToString(h[:16])
}

// A trace on an unlost slot, a flip rule whose control series is unlost and a preload that saturated the NIC before T0 are all legitimate.
func TestQueriesLegitimateLossWindowAndPreloadBehaviourPasses(t *testing.T) {
	fx := qgDefault()
	fx.traceComplete, fx.flipComplete, fx.preBurst = true, true, true
	row := qgRun(t, writeQueriesResult(t, fx), qgSpec())
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("%s %s %q %+v", row.State, row.Outcome, row.Reason, row.Budgets)
	}
	if v := qgReading(t, row, "link_server_peak_mbit"); v > 10 {
		t.Errorf("the pre-T0 burst leaked into the steady link figure: %v", v)
	}
	qgReading(t, row, "preload_throughput_mbyte_per_s")
}

func TestQueriesALostDataGoldenThatAnswersCompleteIsFalseHealthy(t *testing.T) {
	fx := qgDefault()
	fx.goldenLeak = true
	row := qgRun(t, writeQueriesResult(t, fx), qgSpec())
	if b := budgetOf(t, row, "queries_false_healthy_answers"); row.Outcome != OutcomeFailed || b.Observed != 1 {
		t.Fatalf("%s %+v", row.Outcome, b)
	}
}
