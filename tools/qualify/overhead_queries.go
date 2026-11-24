// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// The design section 13 Queries gate, pinned in code beside the budgets of workloads.yaml (fixtures/overhead/queries/contract.go has the
// same numbers): a matrix row cannot ask for less.
const (
	queriesFamily         = "soundpost-queries"
	queriesResultSchema   = "soundpost-queries-result/1"
	queriesHarness        = "fixtures/overhead/queries"
	queriesEnv            = "SOUNDPOST_QUERIES_RESULT"
	queriesOrgs           = 10
	queriesProjects       = 100
	queriesSeries         = 30
	queriesInputBytes     = 1 << 30 // ACKed encoded request bytes per signal
	queriesInputSlack     = 4 << 20 // the preload stops at the first batch boundary past the input: an overshoot above this is not "exactly 1 GiB"
	queriesSteadyS        = 86400
	queriesInteractive    = 10
	queriesRulesPerMinute = 100
	queriesIngestRate     = 100
	// a request that was not answered 200 (and is not an explicit error inside the degraded window) counts as the client's own timeout.
	queriesTimeoutUS = 40_000_000
	// the lab links are rate limited to about 96 Mbit/s; a host above 90 % of it over any minute makes the link, not the product, the bound.
	queriesLinkMbit     = 96.0
	queriesLinkFraction = 0.9
	// the preload covers 24 h of event time, to within 2 %.
	queriesPreloadSpanS = 86400
	// structure a run must have for its judgement not to be vacuous.
	queriesMinOverlimit   = 100 // probes per over-limit class (a 24 h run at one per five minutes makes 288)
	queriesMinGoldenIDs   = 6
	queriesMinGoldenRuns  = 40
	queriesMinRecoveries  = 6    // recovery notifications observed before the loss: the control that the observer can see a recovery at all
	queriesMaxCachedShare = 0.02 // above this the result cache, not the scan, was measured
	queriesJoinFraction   = 0.99 // trace_view/service_red rows that must join the server's scan accounting
	queriesMinLossRows    = 100  // interactive requests a loss window must hold to say anything
	queriesMinLossSpanS   = 600

	queriesHeader     = "start_us,latency_us,status,worker,class,lang,projects,window_s,pages,rows,bytes,peak_mem,server_us,cached,completeness,returned,limit_reached,code,digest,req,golden"
	queriesAcksHeader = "start_us,sched_us,latency_us,late_us,status,project,records,bytes,signal"
)

// The interactive classes of the mix (a run must have every one) and the over-limit classes the explicit-error proof needs.
var (
	queriesInteractiveClasses = []string{"promql_instant", "promql_range_1h", "promql_range_24h", "promql_org_24h", "promql_topk", "logql_lines", "logql_count_24h", "logql_rate_6h", "trace_view", "service_red", "golden"}
	queriesOverlimitClasses   = []string{"overlimit_returned", "overlimit_memory", "overlimit_timeout", "overlimit_default"}
	queriesPreloadSignals     = []string{"metric", "log", "span"}
	// the closed reasons a rule evaluation over unreadable data may carry: it is unknown or an error, never complete.
	queriesRuleReasons = map[string]bool{"unavailable": true, "incomplete_result": true, "timeout": true, "stale_input": true, "evidence_gap": true}
	// raw files bound by a digest (server.log is optional: it is bound when the harness lists it).
	queriesRawFiles = []string{"BUILD.txt", "server/server-series.jsonl", "server/events.jsonl", "server/host.json", "server/rules.jsonl", "server/scans.jsonl", "server/net-series.jsonl",
		"preload/acks.csv.gz", "preload/summary.json", "ingest/acks.csv.gz", "ingest/load-summary.json", "ingest/net-series.jsonl", "ingest/host.json",
		"queries/queries.csv.gz", "queries/query-summary.json", "queries/notifications.jsonl", "queries/net-series.jsonl", "queries/host.json"}
)

// queriesResult is the part of the harness's result.json (fixtures/overhead/queries, ResultSchema) the runner validates. Every judged figure
// is recomputed from the raw files the document binds by digest; the document's own figures are only compared with them.
type queriesResult struct {
	Schema   string `json:"schema"`
	Harness  string `json:"harness"`
	Complete bool   `json:"complete"`
	Gate     struct {
		Orgs             int     `json:"orgs"`
		Projects         int     `json:"projects"`
		SeriesPerProject int     `json:"series_per_project"`
		Seed             uint64  `json:"seed"`
		InputBytes       int64   `json:"input_bytes_per_signal"`
		SteadyS          float64 `json:"steady_s"`
		Interactive      int     `json:"interactive"`
		RulesPerMinute   int     `json:"rules_per_minute"`
		IngestRate       int     `json:"ingest_rate"`
		LossAtS          float64 `json:"loss_at_s"`
		RestartAtS       float64 `json:"restart_at_s"`
		LossSlots        []int   `json:"loss_slots"`
	} `json:"gate"`
	Server singleHostFacts `json:"server_host"`
	Ingest singleHostFacts `json:"ingest_host"`
	Query  singleHostFacts `json:"query_host"`
	Build  struct {
		SourceTreeSHA256 string          `json:"source_tree_sha256"`
		VersionJSON      string          `json:"soundpost_version_json"`
		SoundpostSHA256  string          `json:"soundpost_sha256"`
		HarnessSHA256    string          `json:"harness_sha256"`
		Go               string          `json:"go"`
		Tags             json.RawMessage `json:"build_tags"`
	} `json:"build"`
	Files  map[string]string `json:"file_sha256"`
	Steady struct {
		T0UnixMS int64 `json:"t0_unix_ms"`
	} `json:"steady"`
	Preload   qgPreload `json:"preload"`
	IngestRun struct {
		Sent         int64 `json:"requests_sent"`
		Acked        int64 `json:"requests_acked"`
		EncodedBytes int64 `json:"encoded_bytes_acked"`
	} `json:"ingest"`
	Queries struct {
		Requests  int64            `json:"requests"`
		ByClass   map[string]int64 `json:"by_class"`
		GoldenIDs []string         `json:"golden_ids"`
		Workers   int              `json:"workers"`
	} `json:"queries"`
}

// qgPreload is preload/summary.json and the same fields of the result document.
type qgPreload struct {
	StartUnixMS    int64                      `json:"start_unix_ms"`
	EndUnixMS      int64                      `json:"end_unix_ms"`
	EventStartNS   int64                      `json:"event_start_ns"`
	EventEndNS     int64                      `json:"event_end_ns"`
	Signals        map[string]qgPreloadSignal `json:"signals"`
	SlotsByProject [][]int                    `json:"slots_by_project"`
}

type qgPreloadSignal struct {
	Batches      int64 `json:"batches"`
	Records      int64 `json:"records"`
	EncodedBytes int64 `json:"encoded_bytes"`
	EventStartNS int64 `json:"event_start_ns"`
	EventEndNS   int64 `json:"event_end_ns"`
}

type qgEvent struct {
	TMS       int64  `json:"t_ms"`
	Event     string `json:"event"`
	Mode      string `json:"mode"`
	PIDBefore int    `json:"pid_before"`
	PIDAfter  int    `json:"pid_after"`
	Exit      string `json:"exit"`
	StopMS    int64  `json:"stop_ms"`
	ReadyMS   int64  `json:"ready_ms"`
	Note      string `json:"note"`
}

type qgSample struct {
	TMS       int64  `json:"t_ms"`
	PID       int    `json:"pid"`
	RSSKiB    int64  `json:"rss_kib"`
	HWMKiB    int64  `json:"hwm_kib"`
	UTime     uint64 `json:"utime_ticks"`
	STime     uint64 `json:"stime_ticks"`
	DataBytes int64  `json:"data_bytes"`
	OOMKill   uint64 `json:"cgroup_oom_kill"`
}

type qgNet struct {
	TMS int64  `json:"t_ms"`
	RX  uint64 `json:"rx_bytes"`
	TX  uint64 `json:"tx_bytes"`
}

// qgRule is a line of server/rules.jsonl (internal/rules hook): k e = a committed evaluation, k q = the rule's query.
type qgRule struct {
	K       string `json:"k"`
	TNS     int64  `json:"t_ns"`
	Rule    string `json:"rule"`
	Mode    string `json:"mode"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
	Pages   uint64 `json:"pages"`
	Rows    uint64 `json:"rows"`
	Bytes   uint64 `json:"bytes"`
}

type qgScan struct {
	Req   string `json:"req"`
	Route string `json:"route"`
	Pages int64  `json:"pages"`
	Rows  int64  `json:"rows"`
	Bytes int64  `json:"bytes"`
}

type qgNote struct {
	TMS    int64  `json:"t_ms"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
	SigOK  bool   `json:"sig_ok"`
}

// qgAck is one request of an acks file.
type qgAck struct {
	startUS, latencyUS, records, bytes int64
	status                             int
	signal                             uint32
}

// qgRow is one request of queries.csv.gz; strings are interned in the run's tables.
type qgRow struct {
	start, lat, pages, rows, bytes int64
	req                            uint64
	status                         int32
	worker                         int16
	cached                         bool
	comp                           byte
	class, code, golden, digest    uint32
}

// qgNames interns strings: a run has millions of rows and a handful of distinct classes, codes and digests.
type qgNames struct {
	idx  map[string]uint32
	list []string
}

func newQGNames() *qgNames { return &qgNames{idx: map[string]uint32{"": 0}, list: []string{""}} }

func (n *qgNames) id(s string) uint32 {
	if i, ok := n.idx[s]; ok {
		return i
	}
	s = strings.Clone(s)
	i := uint32(len(n.list))
	n.idx[s] = i
	n.list = append(n.list, s)
	return i
}

func (n *qgNames) get(s string) (uint32, bool) { i, ok := n.idx[s]; return i, ok }

// qgData is every raw file of a run, parsed.
type qgData struct {
	rows              []qgRow
	cls, codes, golds *qgNames
	digs, sigs        *qgNames
	preload, ingest   []qgAck
	preSum            qgPreload
	rules             []qgRule
	scans             map[uint64]qgScan
	notes             []qgNote
	events            []qgEvent
	samples           []qgSample
	net               map[string][]qgNet
	hosts             map[string]singleHostFacts
	t0s               map[string]int64
}

func qgScanGz(path, header string, each func(line string) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	if !sc.Scan() || sc.Text() != header {
		return fmt.Errorf("unexpected header")
	}
	for sc.Scan() {
		if err := each(sc.Text()); err != nil {
			return err
		}
	}
	return sc.Err()
}

func qgJSONL[T any](path string) ([]T, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var out []T
	for line := 1; sc.Scan(); line++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
			return nil, fmt.Errorf("line %d is not valid JSON", line)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

func qgReadJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// qgSplit cuts line at commas into exactly len(dst) fields.
func qgSplit(line string, dst []string) bool {
	for i := 0; i < len(dst)-1; i++ {
		j := strings.IndexByte(line, ',')
		if j < 0 {
			return false
		}
		dst[i], line = line[:j], line[j+1:]
	}
	if strings.IndexByte(line, ',') >= 0 {
		return false
	}
	dst[len(dst)-1] = line
	return true
}

func qgReadQueries(path string, d *qgData) error {
	var f [21]string
	return qgScanGz(path, queriesHeader, func(line string) error {
		if !qgSplit(line, f[:]) {
			return fmt.Errorf("bad row %q", line)
		}
		var v [13]int64
		for i, col := range [13]int{0, 1, 2, 3, 8, 9, 10, 11, 12, 15, 16, 7, 6} {
			n, err := strconv.ParseInt(f[col], 10, 64)
			if err != nil {
				return fmt.Errorf("bad row %q", line)
			}
			v[i] = n
		}
		var req uint64
		if f[19] != "" {
			r, err := strconv.ParseUint(f[19], 16, 64)
			if err != nil {
				return fmt.Errorf("bad request id in row %q", line)
			}
			req = r
		}
		var comp byte
		if f[14] != "" {
			comp = f[14][0]
		}
		d.rows = append(d.rows, qgRow{start: v[0], lat: v[1], status: int32(v[2]), worker: int16(v[3]), pages: v[4], rows: v[5], bytes: v[6], req: req,
			cached: f[13] == "1", comp: comp, class: d.cls.id(f[4]), code: d.codes.id(f[17]), digest: d.digs.id(f[18]), golden: d.golds.id(f[20])})
		return nil
	})
}

func qgReadAcks(path string, d *qgData) ([]qgAck, error) {
	var out []qgAck
	var f [9]string
	err := qgScanGz(path, queriesAcksHeader, func(line string) error {
		if !qgSplit(line, f[:]) {
			return fmt.Errorf("bad row %q", line)
		}
		var v [6]int64
		for i, col := range [6]int{0, 2, 4, 6, 7, 5} {
			n, err := strconv.ParseInt(f[col], 10, 64)
			if err != nil {
				return fmt.Errorf("bad row %q", line)
			}
			v[i] = n
		}
		out = append(out, qgAck{startUS: v[0], latencyUS: v[1], status: int(v[2]), records: v[3], bytes: v[4], signal: d.sigs.id(f[8])})
		return nil
	})
	return out, err
}

// qgLoad parses every raw file; why is empty on success.
func qgLoad(dir string) (*qgData, string) {
	p := func(name string) string { return filepath.Join(dir, filepath.FromSlash(name)) }
	d := &qgData{cls: newQGNames(), codes: newQGNames(), golds: newQGNames(), digs: newQGNames(), sigs: newQGNames(),
		scans: map[uint64]qgScan{}, net: map[string][]qgNet{}, hosts: map[string]singleHostFacts{}, t0s: map[string]int64{}}
	var err error
	if err = qgReadQueries(p("queries/queries.csv.gz"), d); err != nil {
		return nil, "queries: " + err.Error()
	}
	if d.preload, err = qgReadAcks(p("preload/acks.csv.gz"), d); err != nil {
		return nil, "preload acks: " + err.Error()
	}
	if d.ingest, err = qgReadAcks(p("ingest/acks.csv.gz"), d); err != nil {
		return nil, "ingest acks: " + err.Error()
	}
	if err = qgReadJSON(p("preload/summary.json"), &d.preSum); err != nil {
		return nil, "preload summary: " + err.Error()
	}
	if d.rules, err = qgJSONL[qgRule](p("server/rules.jsonl")); err != nil {
		return nil, "server rules: " + err.Error()
	}
	scans, err := qgJSONL[qgScan](p("server/scans.jsonl"))
	if err != nil {
		return nil, "server scans: " + err.Error()
	}
	for _, s := range scans {
		req, perr := strconv.ParseUint(s.Req, 16, 64)
		if perr != nil {
			return nil, "server scans: bad request id " + s.Req
		}
		d.scans[req] = s
	}
	if d.notes, err = qgJSONL[qgNote](p("queries/notifications.jsonl")); err != nil {
		return nil, "notifications: " + err.Error()
	}
	if d.events, err = qgJSONL[qgEvent](p("server/events.jsonl")); err != nil {
		return nil, "server events: " + err.Error()
	}
	if d.samples, err = qgJSONL[qgSample](p("server/server-series.jsonl")); err != nil {
		return nil, "server series: " + err.Error()
	}
	for host, name := range map[string]string{"server": "server/net-series.jsonl", "ingest": "ingest/net-series.jsonl", "query": "queries/net-series.jsonl"} {
		if d.net[host], err = qgJSONL[qgNet](p(name)); err != nil {
			return nil, host + " net series: " + err.Error()
		}
	}
	for host, name := range map[string]string{"server": "server/host.json", "ingest": "ingest/host.json", "query": "queries/host.json"} {
		var f singleHostFacts
		if err = qgReadJSON(p(name), &f); err != nil {
			return nil, host + " host facts: " + err.Error()
		}
		d.hosts[host] = f
	}
	for role, name := range map[string]string{"ingest": "ingest/load-summary.json", "query": "queries/query-summary.json"} {
		var s struct {
			T0UnixMS int64 `json:"t0_unix_ms"`
		}
		if err = qgReadJSON(p(name), &s); err != nil {
			return nil, role + " summary: " + err.Error()
		}
		d.t0s[role] = s.T0UnixMS
	}
	sort.SliceStable(d.samples, func(i, j int) bool { return d.samples[i].TMS < d.samples[j].TMS })
	for _, s := range d.net {
		sort.SliceStable(s, func(i, j int) bool { return s[i].TMS < s[j].TMS })
	}
	return d, ""
}

// qgLink returns the mean rate of the whole series and the largest mean rate over any window of at least windowMS, in Mbit/s, for the
// receive and transmit directions. A counter that goes backwards (a reset) contributes nothing.
func qgLink(s []qgNet, windowMS int64) (meanRX, meanTX, peakRX, peakTX float64) {
	if len(s) < 2 {
		return
	}
	rate := func(a, b uint64, ms int64) float64 {
		if b < a || ms <= 0 {
			return 0
		}
		return float64(b-a) * 8 / (float64(ms) / 1000) / 1e6
	}
	first, last := s[0], s[len(s)-1]
	meanRX, meanTX = rate(first.RX, last.RX, last.TMS-first.TMS), rate(first.TX, last.TX, last.TMS-first.TMS)
	j := 0
	for i := range s {
		j = max(j, i+1)
		for j < len(s) && s[j].TMS-s[i].TMS < windowMS {
			j++
		}
		if j >= len(s) {
			break
		}
		peakRX = max(peakRX, rate(s[i].RX, s[j].RX, s[j].TMS-s[i].TMS))
		peakTX = max(peakTX, rate(s[i].TX, s[j].TX, s[j].TMS-s[i].TMS))
	}
	return
}

func qgSort(v []int64) []int64 {
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v
}

// qgStats returns the mean, p50, p95 and max of a slice (it sorts it).
func qgStats(v []int64) (mean, p50, p95, maxV float64) {
	if len(v) == 0 {
		return
	}
	var sum float64
	for _, x := range v {
		sum += float64(x)
	}
	qgSort(v)
	return shRound(sum / float64(len(v))), float64(shPercentile(v, 0.5)), float64(shPercentile(v, 0.95)), float64(v[len(v)-1])
}

// queriesGateParams is what the matrix row pins; the design values themselves are constants above, so a row cannot ask for less.
func queriesGateParams(spec RowSpec) (string, bool) {
	want := map[string]int{"input_bytes": queriesInputBytes, "duration": queriesSteadyS, "interactive": queriesInteractive, "rules_per_minute": queriesRulesPerMinute, "ingest_rate": queriesIngestRate}
	for _, k := range []string{"input_bytes", "duration", "interactive", "rules_per_minute", "ingest_rate"} {
		got, err := strconv.Atoi(spec.Params[k])
		if err != nil || got != want[k] {
			return fmt.Sprintf("matrix row %s pins %s=%q but design section 13 says %d: the row cannot be weakened", spec.ID, k, spec.Params[k], want[k]), false
		}
	}
	if _, err := strconv.ParseUint(spec.Params["seed"], 10, 64); err != nil {
		return fmt.Sprintf("matrix row %s pins no workload seed", spec.ID), false
	}
	return "", true
}

// queriesDir resolves where the harness result lives: the environment variable wins over the row's `result` parameter.
func (rc *runCtx) queriesDir(spec RowSpec) string {
	p := os.Getenv(queriesEnv)
	if p == "" {
		p = spec.Params["result"]
	}
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(rc.root, p)
	}
	return p
}

// qgSlotSet parses "slots 0-31" or "slots 0-3,8" into a set; ok is false for anything else.
func qgSlotSet(mode string) (map[int]bool, bool) {
	list, found := strings.CutPrefix(strings.TrimSpace(mode), "slots ")
	if !found {
		return nil, false
	}
	set := map[int]bool{}
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return nil, false
			}
		}
		for s := a; s <= b; s++ {
			set[s] = true
		}
	}
	return set, true
}

// runOverheadQueries judges design section 13's Queries gate (p95 interactive < 2 s, an explicit resource error on a limit, no false healthy
// state) from the result of a REAL 24-hour run of the load harness (fixtures/overhead/queries): a server on one host in the D90 scope, an
// ingest role preloading 1 GiB of encoded input per signal and then ingesting, a query role driving 10 interactive queries, over-limit probes
// and golden checks, 100 rule evaluations a minute, and one injected shard loss followed by a graceful restart. The day is not re-run here:
// the result is validated (hosts, build, parameters, hashes of the raw files) and every judged number is recomputed from the raw files.
// A reduced run, a result that does not recompute or one that cannot be tied to the gate is never promoted: the row is not exercised and
// says why. A missed gate is a measured failure.
func runOverheadQueries(rc *runCtx, spec RowSpec) Row {
	if why, ok := queriesGateParams(spec); !ok {
		return notExercised(why)
	}
	dir := rc.queriesDir(spec)
	if dir == "" {
		return notExercised("no queries run result: run the procedure of fixtures/overhead/queries (server, ingest and query roles on three hosts, a 1 GiB preload per signal and 24 hours) and point " + queriesEnv + " at its result directory; the day is not run inside qualify")
	}
	for _, b := range []string{"queries_interactive_p95_ms", "queries_false_healthy_answers", "queries_overlimit_unexplained", "queries_golden_mismatches"} {
		if bud, ok := rc.workloads.Budgets[b]; !ok || bud.Source == "" || bud.Unit == "" {
			return notExercised("workloads.yaml does not pin the design section 13 budget " + b)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		return notExercised("queries result not readable: " + err.Error())
	}
	var res queriesResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return notExercised("queries result refused: not a result document: " + err.Error())
	}
	refuse := func(f string, a ...any) Row { return notExercised("queries result refused: " + fmt.Sprintf(f, a...)) }
	reduced := func(f string, a ...any) Row { return notExercised("reduced run: " + fmt.Sprintf(f, a...)) }
	if res.Schema != queriesResultSchema || res.Harness != queriesHarness {
		return refuse("schema %q harness %q", res.Schema, res.Harness)
	}
	if !strings.Contains(string(res.Build.Tags), "soundpost_faults") {
		return refuse("the product under test is not the soundpost_faults build (build tags %s): the shard loss cannot have been injected", string(res.Build.Tags))
	}
	if res.Steady.T0UnixMS == 0 {
		return refuse("the result names no steady start instant")
	}

	// raw files: every one named must hash to what the result says.
	names := append([]string(nil), queriesRawFiles...)
	if _, ok := res.Files["server/server.log"]; ok {
		names = append(names, "server/server.log")
	}
	for _, name := range names {
		want, ok := res.Files[name]
		if !ok {
			return refuse("raw file %s is not bound by a digest", name)
		}
		got, err := shSHA(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || got != want {
			return refuse("raw file %s does not match its digest (tampered, replaced or missing)", name)
		}
	}
	d, why := qgLoad(dir)
	if why != "" {
		return refuse("%s", why)
	}

	// the documents must agree with the raw files.
	t0 := res.Steady.T0UnixMS
	for role, v := range d.t0s {
		if v != 0 && v != t0 {
			return refuse("the %s summary starts the steady run at %d, the result at %d", role, v, t0)
		}
	}
	for host, f := range map[string]singleHostFacts{"server": res.Server, "ingest": res.Ingest, "query": res.Query} {
		if h := d.hosts[host]; h.HostID != f.HostID || h.Kernel != f.Kernel || h.OS != f.OS {
			return refuse("the result's %s host facts differ from the %s host.json", host, host)
		}
	}
	for _, s := range queriesPreloadSignals {
		sum, ok := d.preSum.Signals[s]
		if !ok {
			return refuse("the preload summary has no %s signal", s)
		}
		var bytesV, records, batches int64
		for _, a := range d.preload {
			if a.status == 200 && d.sigs.list[a.signal] == s {
				bytesV += a.bytes
				records += a.records
				batches++
			}
		}
		if sum.EncodedBytes != bytesV || sum.Records != records || sum.Batches != batches {
			return refuse("the preload summary's %s bytes/records/batches (%d/%d/%d) do not recompute from preload/acks.csv.gz (%d/%d/%d)", s, sum.EncodedBytes, sum.Records, sum.Batches, bytesV, records, batches)
		}
		if r := res.Preload.Signals[s]; r.EncodedBytes != bytesV {
			return refuse("the result's preload bytes of %s (%d) do not recompute from preload/acks.csv.gz (%d)", s, r.EncodedBytes, bytesV)
		}
	}
	if res.Preload.StartUnixMS != d.preSum.StartUnixMS || res.Preload.EndUnixMS != d.preSum.EndUnixMS || res.Preload.EventStartNS != d.preSum.EventStartNS || res.Preload.EventEndNS != d.preSum.EventEndNS {
		return refuse("the result's preload times differ from preload/summary.json")
	}
	// a request the generator shed (status -1) was never sent; every other row is a request that went to the server.
	var ingSent, ingAcked, ingBytes int64
	for _, a := range d.ingest {
		if a.status >= 0 {
			ingSent++
		}
		if a.status == 200 {
			ingAcked++
			ingBytes += a.bytes
		}
	}
	if res.IngestRun.Sent != ingSent || res.IngestRun.Acked != ingAcked || res.IngestRun.EncodedBytes != ingBytes {
		return refuse("the ingest request counts do not recompute (%d sent/%d ACKed/%d bytes stated, %d/%d/%d in ingest/acks.csv.gz)", res.IngestRun.Sent, res.IngestRun.Acked, res.IngestRun.EncodedBytes, ingSent, ingAcked, ingBytes)
	}
	byClass := map[string]int64{}
	goldenSeen := map[string]bool{}
	for i := range d.rows {
		r := &d.rows[i]
		byClass[d.cls.list[r.class]]++
		if d.cls.list[r.class] == "golden" {
			goldenSeen[d.golds.list[r.golden]] = true
		}
	}
	statedIDs := map[string]bool{}
	for _, id := range res.Queries.GoldenIDs {
		statedIDs[id] = true
	}
	same := res.Queries.Requests == int64(len(d.rows)) && len(byClass) == len(res.Queries.ByClass) && len(goldenSeen) == len(statedIDs)
	for c, n := range byClass {
		same = same && res.Queries.ByClass[c] == n
	}
	for id := range goldenSeen {
		same = same && statedIDs[id]
	}
	if !same {
		return refuse("the stated query counts (%d requests, %d classes, %d golden ids) do not recompute from queries/queries.csv.gz (%d, %d, %d)", res.Queries.Requests, len(res.Queries.ByClass), len(statedIDs), len(d.rows), len(byClass), len(goldenSeen))
	}
	if len(res.Gate.LossSlots) == 0 {
		return refuse("the result names no lost slot")
	}
	if len(d.preSum.SlotsByProject) < res.Gate.Projects {
		return refuse("the preload summary lists the slots of %d projects, the estate has %d", len(d.preSum.SlotsByProject), res.Gate.Projects)
	}
	lost := map[int]bool{}
	for _, s := range res.Gate.LossSlots {
		lost[s] = true
	}
	for p := range res.Gate.Projects {
		hit := false
		for _, s := range d.preSum.SlotsByProject[p] {
			hit = hit || lost[s]
		}
		if !hit {
			return refuse("project %d holds no preloaded record on a lost slot: a loss of slots %v proves nothing for it (every project must hold data on a lost slot)", p, res.Gate.LossSlots)
		}
	}
	var loss, restart *qgEvent
	for i := range d.events {
		e := &d.events[i]
		if e.Event == "shard_loss" && loss == nil && strings.HasPrefix(e.Note, "closed ") {
			loss = e
		}
		if e.Event == "restart" && e.Mode == "graceful" && restart == nil {
			restart = e
		}
	}
	if loss != nil {
		set, ok := qgSlotSet(loss.Mode)
		if !ok || len(set) != len(lost) {
			return refuse("the shard_loss event names %q, the result lost slots %v", loss.Mode, res.Gate.LossSlots)
		}
		for s := range set {
			if !lost[s] {
				return refuse("the shard_loss event names slot %d, which the result does not list as lost", s)
			}
		}
		if n, err := strconv.Atoi(strings.TrimPrefix(loss.Note, "closed ")); err != nil || n < 1 || !strings.HasPrefix(loss.Note, "closed ") {
			return refuse("the shard_loss event closed no slot (note %q)", loss.Note)
		}
	}

	// rows of the steady window, and the join of trace_view/service_red rows with the server's scan accounting.
	steadyS := res.Gate.SteadyS
	steadyUS := int64(steadyS * 1e6)
	isOver := func(r *qgRow) bool { return strings.HasPrefix(d.cls.list[r.class], "overlimit_") }
	var joinable, joined int
	for i := range d.rows {
		r := &d.rows[i]
		c := d.cls.list[r.class]
		if (c == "trace_view" || c == "service_red") && r.status == 200 {
			joinable++
			if s, ok := d.scans[r.req]; ok && r.req != 0 && s.Route == c {
				joined++
			}
		}
	}
	if joinable > 0 && float64(joined) < queriesJoinFraction*float64(joinable) {
		return refuse("only %d of %d trace_view/service_red answers join the server's scans.jsonl by request id (%.1f %%, at least %.0f %% needed): the bytes and pages scanned of those routes are not attributable", joined, joinable, 100*float64(joined)/float64(joinable), 100*queriesJoinFraction)
	}

	// ---- reduced-run checks: the result is genuine but is not the design workload.
	g := res.Gate
	switch {
	case g.Orgs < queriesOrgs || g.Projects < queriesProjects || g.SeriesPerProject < queriesSeries:
		return reduced("%d orgs, %d projects, %d series per project against the design's %d/%d/%d", g.Orgs, g.Projects, g.SeriesPerProject, queriesOrgs, queriesProjects, queriesSeries)
	case g.InputBytes < queriesInputBytes || g.SteadyS < queriesSteadyS || g.Interactive < queriesInteractive || g.RulesPerMinute < queriesRulesPerMinute || g.IngestRate < queriesIngestRate:
		return reduced("the run's parameters (%d input bytes per signal, %.0f s, %d interactive, %d rules a minute, %d records/s) are weaker than the design's (%d, %d, %d, %d, %d)", g.InputBytes, g.SteadyS, g.Interactive, g.RulesPerMinute, g.IngestRate, queriesInputBytes, queriesSteadyS, queriesInteractive, queriesRulesPerMinute, queriesIngestRate)
	}
	if res.Server.OS != "linux" {
		return reduced("server host is %q, not linux", res.Server.OS)
	}
	scopeCPUs, scopeMem, scopeWhy := shValidateScope(res.Server)
	if scopeWhy != "" {
		return reduced("the server was not measured in the D90 cgroup scope: %s", scopeWhy)
	}
	if res.Server.DataOnTmpfs || res.Server.DataFS == "" {
		return reduced("the product's data directory is on %q (tmpfs or unknown), not a persistent disk", res.Server.DataFS)
	}
	if res.Server.HostID == "" || res.Server.HostID == res.Ingest.HostID || res.Server.HostID == res.Query.HostID {
		return reduced("the ingest or query role ran on the server host (or a host id is unknown): the design measures a loaded server, not a co-located generator")
	}
	if res.Server.CpusAllowed == "" || res.Server.Kernel == "" {
		return refuse("server host facts are incomplete")
	}
	if res.Ingest.Kernel == "" || res.Query.Kernel == "" {
		return reduced("the kernel of the ingest or query host is unknown")
	}
	preBytes := map[string]int64{}
	for _, s := range queriesPreloadSignals {
		for _, a := range d.preload {
			if a.status == 200 && d.sigs.list[a.signal] == s {
				preBytes[s] += a.bytes
			}
		}
		if b := preBytes[s]; b < queriesInputBytes || b > queriesInputBytes+queriesInputSlack {
			return reduced("the preload ACKed %d encoded bytes of %s, the design wants exactly 1 GiB (%d to %d)", b, s, int64(queriesInputBytes), int64(queriesInputBytes+queriesInputSlack))
		}
		ps := d.preSum.Signals[s]
		if span := float64(ps.EventEndNS-ps.EventStartNS) / 1e9; math.Abs(span-queriesPreloadSpanS) > 0.02*queriesPreloadSpanS {
			return reduced("the preloaded %s records span %.1f h of event time, not 24 h", s, span/3600)
		}
	}
	if span := float64(d.preSum.EventEndNS-d.preSum.EventStartNS) / 1e9; math.Abs(span-queriesPreloadSpanS) > 0.02*queriesPreloadSpanS {
		return reduced("the preload spans %.1f h of event time, not 24 h", span/3600)
	}
	if d.preSum.EndUnixMS > t0 {
		return reduced("the preload ended after the steady run started")
	}
	var maxStart int64
	for i := range d.rows {
		maxStart = max(maxStart, d.rows[i].start)
	}
	if float64(maxStart) < (steadyS-60)*1e6 {
		return reduced("the query role ran for %.0f s of the %d s steady window", float64(maxStart)/1e6, queriesSteadyS)
	}
	if !res.Complete {
		return reduced("the harness says the procedure is incomplete (loss injected, restart done, 24 h elapsed, every file present)")
	}
	if loss == nil {
		return reduced("the server events carry no shard_loss: the loss was not injected, so no false healthy state was provoked")
	}
	switch {
	case restart == nil:
		return reduced("the server events carry no graceful restart after the shard loss")
	case restart.Exit != "exit status 0" || restart.PIDBefore == 0 || restart.PIDAfter == restart.PIDBefore:
		return reduced("the graceful restart did not end the server process with exit status 0 and start another (exit %q, pid %d -> %d)", restart.Exit, restart.PIDBefore, restart.PIDAfter)
	}
	lossMS := loss.TMS
	restartStartMS := restart.TMS - restart.StopMS - restart.ReadyMS
	restartEndMS := restart.TMS
	lossUS, restartStartUS, restartEndUS := (lossMS-t0)*1000, (restartStartMS-t0)*1000, (restartEndMS-t0)*1000
	if lossUS <= 0 || lossUS >= steadyUS || restartStartUS-lossUS < queriesMinLossSpanS*1_000_000 {
		return reduced("the loss window [%d s, %d s) is not inside the run or is shorter than %d s", lossUS/1_000_000, restartStartUS/1_000_000, queriesMinLossSpanS)
	}

	// ingest rate: records offered in the steady window (the control samples of the flip rules are not the mixed stream).
	var offered int64
	for _, a := range d.ingest {
		if a.startUS >= 0 && a.startUS < steadyUS && a.status >= 0 && d.sigs.list[a.signal] != "control" {
			offered += a.records
		}
	}
	if rate := float64(offered) / steadyS; rate < 0.98*float64(g.IngestRate) || rate > 1.02*float64(g.IngestRate) {
		return reduced("the ingest role offered %.1f records/s in the steady window, not %d", rate, g.IngestRate)
	}
	if n := len(d.samples); n < int(steadyS/10)*9/10 {
		return reduced("the server monitor sampled %d times in the steady window", n)
	}
	var gapMax int64
	for i := 1; i < len(d.samples); i++ {
		gapMax = max(gapMax, d.samples[i].TMS-d.samples[i-1].TMS)
	}
	if gapMax > 60_000 {
		return reduced("the server monitor has a %d s gap", gapMax/1000)
	}

	// query concurrency: the time-weighted mean of interactive requests in flight, and the largest number at once.
	var starts, ends []int64
	var flight int64
	workers := map[int16]bool{}
	for i := range d.rows {
		r := &d.rows[i]
		if isOver(r) || r.start < 0 || r.start >= steadyUS {
			continue
		}
		workers[r.worker] = true
		starts = append(starts, r.start)
		// a request that ends and the next one that starts in the same microsecond are not concurrent: the log truncates both to whole
		// microseconds, so ends are taken a millisecond early for the maximum (never for the mean).
		ends = append(ends, max(r.start, r.start+r.lat-1000))
		flight += min(r.start+r.lat, steadyUS) - r.start
	}
	qgSort(starts)
	qgSort(ends)
	maxFlight, j := 0, 0
	for i, s := range starts {
		for j < len(ends) && ends[j] <= s {
			j++
		}
		maxFlight = max(maxFlight, i+1-j)
	}
	meanFlight := float64(flight) / float64(steadyUS)
	switch {
	case len(workers) != queriesInteractive:
		return reduced("%d interactive workers issued requests, the design has %d", len(workers), queriesInteractive)
	case meanFlight < 0.95*queriesInteractive || maxFlight > queriesInteractive:
		return reduced("%.2f interactive requests in flight on average (at most %d at once), the design has %d active queries", meanFlight, maxFlight, queriesInteractive)
	}

	// rule evaluations: a minute holds the design's 100, and every ten minutes holds nearly every rule.
	t0ns := t0 * 1_000_000
	steadyNS := int64(steadyS * 1e9)
	minutes := int(steadyS / 60)
	perMinute := make([]int64, minutes)
	buckets := make([]map[string]bool, int(steadyS/600))
	for i := range buckets {
		buckets[i] = map[string]bool{}
	}
	var evals, liveEvals int64
	ruleCounts := map[string]int64{}
	var qPages, qRows, qBytes []int64
	for i := range d.rules {
		r := &d.rules[i]
		if r.TNS < t0ns || r.TNS >= t0ns+steadyNS {
			continue
		}
		switch r.K {
		case "e":
			evals++
			reason := r.Reason
			if reason == "" {
				reason = "none"
			}
			ruleCounts[r.Mode+"."+r.Outcome+"."+reason]++
			if r.Mode == "live" {
				liveEvals++
				perMinute[min((r.TNS-t0ns)/60_000_000_000, int64(minutes-1))]++
				buckets[min((r.TNS-t0ns)/600_000_000_000, int64(len(buckets)-1))][r.Rule] = true
			}
		case "q":
			qPages, qRows, qBytes = append(qPages, int64(r.Pages)), append(qRows, int64(r.Rows)), append(qBytes, int64(r.Bytes))
		}
	}
	perMinuteMean := float64(liveEvals) / float64(minutes)
	minDistinct := math.MaxInt
	for _, b := range buckets {
		minDistinct = min(minDistinct, len(b))
	}
	switch {
	case perMinuteMean < 0.98*queriesRulesPerMinute:
		return reduced("%.1f rule evaluations a minute (live), the design has %d", perMinuteMean, queriesRulesPerMinute)
	case minDistinct < 95:
		return reduced("only %d of %d rules were evaluated in the thinnest ten-minute window", minDistinct, queriesRulesPerMinute)
	}

	// the link: the server host's use of the shared, rate-limited link over any minute.
	linkMean, linkPeak := map[string][2]float64{}, map[string][2]float64{}
	steadyNet := map[string][]qgNet{}
	for host, s := range d.net {
		// only the steady window: the preload is NIC-bound by design and is not part of the steady gate.
		for _, x := range s {
			if x.TMS >= t0 && x.TMS <= t0+int64(steadyS*1000) {
				steadyNet[host] = append(steadyNet[host], x)
			}
		}
		a, b, c, e := qgLink(steadyNet[host], 60_000)
		linkMean[host], linkPeak[host] = [2]float64{a, b}, [2]float64{c, e}
	}
	for _, host := range []string{"server", "ingest", "query"} {
		if n := len(steadyNet[host]); n < int(steadyS/10)*9/10 {
			return reduced("the %s host's network monitor sampled %d times in the steady window", host, n)
		}
		if p := max(linkPeak[host][0], linkPeak[host][1]); p > queriesLinkFraction*queriesLinkMbit {
			return reduced("the link bound the run: the %s host used %.1f Mbit/s over a minute of the steady window, above %.0f %% of the shared link's %.0f Mbit/s", host, p, 100*queriesLinkFraction, queriesLinkMbit)
		}
	}

	// the server process: only the recorded restart may change it, and the scope must not have killed anything.
	var lastPID int
	var oom uint64
	for _, s := range d.samples {
		oom = max(oom, s.OOMKill)
		if s.PID == 0 {
			continue
		}
		if lastPID != 0 && s.PID != lastPID && !(restart.PIDBefore == lastPID && restart.PIDAfter == s.PID) {
			return reduced("the server process changed from %d to %d outside the recorded restart", lastPID, s.PID)
		}
		lastPID = s.PID
	}
	if oom > 0 {
		return reduced("the server's cgroup recorded %d OOM kills", oom)
	}

	// the query mix: every class present, the cache not what was measured, the over-limit proof not vacuous.
	for _, c := range queriesInteractiveClasses {
		if byClass[c] == 0 {
			return reduced("the query mix has no %s request", c)
		}
	}
	var interactive, cached int
	for i := range d.rows {
		r := &d.rows[i]
		if isOver(r) || r.start < 0 || r.start >= steadyUS {
			continue
		}
		interactive++
		if r.cached {
			cached++
		}
	}
	cachedShare := float64(cached) / float64(max(interactive, 1))
	if cachedShare > queriesMaxCachedShare {
		return reduced("%.1f %% of the interactive answers came from the result cache (more than %.0f %%): the cache, not the scan, was measured", 100*cachedShare, 100*queriesMaxCachedShare)
	}
	for _, c := range queriesOverlimitClasses {
		if byClass[c] < queriesMinOverlimit {
			return reduced("%d %s probes, a day holds at least %d: the explicit-resource-error proof is not exercised", byClass[c], c, queriesMinOverlimit)
		}
	}

	// golden queries: the structure that makes "equal answers" a statement.
	type goldenStat struct {
		runs        int
		baseline    bool
		first       int64
		ref         uint32
		hasRef      bool
		mismatches  int
		notComplete int
	}
	golden := map[uint32]*goldenStat{}
	goldenClass, _ := d.cls.get("golden")
	for i := range d.rows {
		r := &d.rows[i]
		if r.class != goldenClass {
			continue
		}
		st := golden[r.golden]
		if st == nil {
			st = &goldenStat{}
			golden[r.golden] = st
		}
		if r.status == 200 && r.comp == 'c' {
			st.runs++
			if r.start < 60_000_000 {
				st.baseline = true
			}
			if !st.hasRef || r.start < st.first {
				st.first, st.ref, st.hasRef = r.start, r.digest, true
			}
		}
	}
	if len(golden) < queriesMinGoldenIDs {
		return reduced("%d golden query ids, the design set has at least %d", len(golden), queriesMinGoldenIDs)
	}
	for id, st := range golden {
		switch {
		case st.runs < queriesMinGoldenRuns:
			return reduced("golden query %s has %d complete answers, at least %d needed to compare", d.golds.list[id], st.runs, queriesMinGoldenRuns)
		case !st.baseline:
			return reduced("golden query %s has no complete answer in the first minute: there is no baseline to compare with", d.golds.list[id])
		}
	}

	// notifications: the observer must be able to see a recovery before a missing one means anything.
	var recBefore, recLoss int
	notesByKey := map[string]int{}
	badSig := 0
	for _, n := range d.notes {
		if !n.SigOK {
			badSig++
			continue
		}
		notesByKey[n.Kind+"."+n.Source]++
		if n.Source == "recovered" {
			switch {
			case n.TMS < lossMS:
				recBefore++
			case n.TMS < restartStartMS:
				recLoss++
			}
		}
	}
	if recBefore < queriesMinRecoveries {
		return reduced("%d recovery notifications before the loss, at least %d expected from the flip rules: an unobserved recovery cannot be told from an absent one", recBefore, queriesMinRecoveries)
	}
	lossRows := 0
	for i := range d.rows {
		r := &d.rows[i]
		if !isOver(r) && r.start >= lossUS && r.start < restartStartUS {
			lossRows++
		}
	}
	if lossRows < queriesMinLossRows {
		return reduced("%d interactive requests in the loss window, at least %d needed", lossRows, queriesMinLossRows)
	}

	// ---- the judgement.
	// 1. strict p95: a request that was not answered 200 counts as the client timeout, unless it is an explicit error (a status and the
	// product's own code) inside the degraded window, which keeps its measured latency.
	eff := func(r *qgRow) int64 {
		if r.status == 200 {
			return r.lat
		}
		if r.status != 0 && d.codes.list[r.code] != "" && r.start >= lossUS && r.start <= restartEndUS {
			return r.lat
		}
		return queriesTimeoutUS
	}
	hours := int(math.Ceil(steadyS / 3600))
	var all, cachedLat []int64
	perHour := make([][]int64, hours)
	perClass := map[uint32][]int64{}
	nonOK := map[string]int{}
	for i := range d.rows {
		r := &d.rows[i]
		if r.status != 200 {
			nonOK[d.cls.list[r.class]]++
		}
		if isOver(r) || r.start < 0 || r.start >= steadyUS {
			continue
		}
		l := eff(r)
		all = append(all, l)
		perClass[r.class] = append(perClass[r.class], l)
		perHour[min(int(r.start/3_600_000_000), hours-1)] = append(perHour[min(int(r.start/3_600_000_000), hours-1)], l)
		if r.cached {
			cachedLat = append(cachedLat, l)
		}
	}
	ms := func(us int64) float64 { return shRound(float64(us) / 1000) }
	p95 := ms(shPercentile(qgSort(all), 0.95))
	hourP95 := make([]float64, hours)
	for h := range perHour {
		hourP95[h] = ms(shPercentile(qgSort(perHour[h]), 0.95))
	}

	// 2. over-limit probes: an explicit resource or deadline error with the product's own code, never an answer.
	overProbes, overUnexplained, overDown := map[string]int{}, 0, 0
	for i := range d.rows {
		r := &d.rows[i]
		if !isOver(r) {
			continue
		}
		overProbes[d.cls.list[r.class]]++
		if r.start >= restartStartUS && r.start <= restartEndUS && (r.status == 0 || r.status == 503) {
			overDown++ // the server was being restarted: nothing could answer it
			continue
		}
		if (r.status != 429 && r.status != 504 && r.status != 413) || d.codes.list[r.code] == "" {
			overUnexplained++
		}
	}

	// 3. false healthy: an answer, a rule evaluation or a recovery that says "fine" over a lost shard.
	var fhAnswers, lossPartial, lossErrors, okRuns int
	for i := range d.rows {
		r := &d.rows[i]
		if isOver(r) || r.start < lossUS || r.start >= restartStartUS {
			continue
		}
		if gid := d.golds.list[r.golden]; strings.HasPrefix(gid, "g_ok_") { // isolation proof: unlost data must still answer, completely and identically
			if st := golden[r.golden]; r.status == 200 && r.comp == 'c' && r.digest != 0 && r.digest == st.ref {
				okRuns++
			}
			continue
		}
		if d.cls.list[r.class] == "trace_view" && r.golden == 0 { // a trace on an unlost slot is legitimately complete
			continue
		}
		switch {
		case r.status == 200 && r.comp == 'c' && !r.cached:
			fhAnswers++
		case r.status == 200:
			lossPartial++
		default:
			lossErrors++
		}
	}
	if okRuns < 3 {
		return reduced("%d isolation (g_ok_) golden answers in the loss window were complete with the baseline digest, at least 3 needed: unlost data was not shown to stay readable", okRuns)
	}
	lossNS, restartStartNS := lossMS*1_000_000, restartStartMS*1_000_000
	flips := map[string]bool{}
	for p := 97; p <= 99; p++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("soundpost/overhead/queries/v1/%d/rule/%d", res.Gate.Seed, p)))
		flips[hex.EncodeToString(h[:16])] = true
	}
	var fhRules, lossEvals int
	for i := range d.rules {
		r := &d.rules[i]
		if r.K != "e" || r.TNS < lossNS || r.TNS >= restartStartNS {
			continue
		}
		lossEvals++
		if flips[r.Rule] { // a flip rule's ctl_flag series may sit on an unlost slot: its evaluation may legitimately be complete
			continue
		}
		switch {
		case r.Outcome == "unknown" || r.Outcome == "error":
			if !queriesRuleReasons[r.Reason] {
				fhRules++
			}
		default: // complete, or a state the product does not have
			fhRules++
		}
	}
	if lossEvals == 0 {
		return reduced("no rule evaluation was committed in the loss window")
	}
	falseHealthy := fhAnswers + fhRules + recLoss

	// 4. golden answers over immutable data are equal for the whole run.
	for i := range d.rows {
		r := &d.rows[i]
		if r.class != goldenClass || r.status != 200 || r.comp != 'c' {
			continue
		}
		if st := golden[r.golden]; r.digest == 0 || r.digest != st.ref {
			st.mismatches++
		}
	}
	var goldenMismatches int
	for _, st := range golden {
		goldenMismatches += st.mismatches
	}

	// readings: bytes, pages and rows scanned per query (scans.jsonl for trace_view/service_red) and the rest of the run.
	scanPages, scanRows, scanBytes := map[string][]int64{}, map[string][]int64{}, map[string][]int64{}
	for i := range d.rows {
		r := &d.rows[i]
		c := d.cls.list[r.class]
		if isOver(r) || c == "golden" || r.status != 200 || r.cached || r.start < 0 || r.start >= steadyUS {
			continue
		}
		if c == "trace_view" || c == "service_red" {
			s := d.scans[r.req]
			scanPages[c], scanRows[c], scanBytes[c] = append(scanPages[c], s.Pages), append(scanRows[c], s.Rows), append(scanBytes[c], s.Bytes)
			continue
		}
		scanPages[c], scanRows[c], scanBytes[c] = append(scanPages[c], r.pages), append(scanRows[c], r.rows), append(scanBytes[c], r.bytes)
	}

	// ---- the row.
	var ver struct {
		BuildID string `json:"build_id"`
	}
	if res.Build.SoundpostSHA256 == "" || res.Build.SourceTreeSHA256 == "" || res.Build.VersionJSON == "" {
		return refuse("the result names no soundpost build")
	}
	if json.Unmarshal([]byte(res.Build.VersionJSON), &ver) != nil || ver.BuildID == "" || ver.BuildID == "unknown" {
		return refuse("the soundpost binary carries no build id")
	}
	build := &Build{Family: queriesFamily, Version: "design-13", OS: "linux", Arch: res.Server.Arch, ID: "soundpost-" + ver.BuildID + "+sha256:" + res.Build.SoundpostSHA256[:16], SHA256: res.Build.SoundpostSHA256, Host: "vm"}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	row := Row{State: StateExercised, Build: build}
	row.Command = &CommandRun{Command: "fixtures/overhead/queries procedure: server (pinned), ingest and query roles on three hosts, 1 GiB preload per signal, 24 h steady with one shard loss and a graceful restart; validated from " + rc.rel(dir), ExitCode: 0, DurationMS: (d.preSum.EndUnixMS - d.preSum.StartUnixMS) + int64(steadyS)*1000}
	row.Evidence = []string{
		"harness result " + rc.writeEvidence("queries-result.json", raw) + " (digest " + digest[:16] + ") with raw files bound by sha256: queries, acks, rules, scans, notifications, server series, events and network series",
		fmt.Sprintf("run digest %s, server host %s kernel %s %d vCPU %d MiB; server scope %s: cpuset.cpus.effective %s (%d CPUs), memory.max %s, memory.swap.max %s, GOMAXPROCS %d; ingest host %s kernel %s, query host %s kernel %s", digest[:12], res.Server.HostID, res.Server.Kernel, res.Server.LogicalCPUs, res.Server.MemTotalKiB/1024, res.Server.CgroupPath, res.Server.CgroupCPUs, scopeCPUs, res.Server.CgroupMemMax, res.Server.CgroupSwapMax, res.Server.Gomaxprocs, res.Ingest.HostID, res.Ingest.Kernel, res.Query.HostID, res.Query.Kernel),
		fmt.Sprintf("soundpost build %s (tags %s) source tree %s", ver.BuildID, strings.Trim(string(res.Build.Tags), `"`), res.Build.SourceTreeSHA256[:16]),
		fmt.Sprintf("workload: %d orgs, %d projects, %d series per project, seed %d; preload %d/%d/%d ACKed encoded bytes (metric/log/span) over %.1f h of event time; steady %.0f s: %d interactive workers (%.2f in flight on average, %d at most), %.1f rule evaluations a minute, %.1f records/s ingested; shard loss of slots %v at %d s, graceful restart at %d s", g.Orgs, g.Projects, g.SeriesPerProject, g.Seed, preBytes["metric"], preBytes["log"], preBytes["span"], float64(d.preSum.EventEndNS-d.preSum.EventStartNS)/3.6e12, steadyS, len(workers), meanFlight, maxFlight, perMinuteMean, float64(offered)/steadyS, g.LossSlots, lossUS/1_000_000, restartStartUS/1_000_000),
	}
	minuteSeries := make([]float64, minutes)
	for i, v := range perMinute {
		minuteSeries[i] = float64(v)
	}
	var rss []float64
	for _, s := range d.samples {
		if s.PID != 0 {
			rss = append(rss, float64(s.RSSKiB))
		}
	}
	row.Series = []Series{
		{Name: "interactive_p95_per_hour", Unit: "ms", Mode: "steady", Values: hourP95},
		{Name: "rule_evaluations_per_minute", Unit: "count", Mode: "steady", Values: minuteSeries},
	}
	if len(rss) > 0 {
		row.Series = append(row.Series, Series{Name: "server_rss", Unit: "KiB", Mode: "steady", Values: rss})
	}
	row.Budgets = []BudgetResult{
		rc.budget("queries_interactive_p95_ms", p95, fmt.Sprintf("nearest-rank p95 of the latency of the %d interactive requests of the %.0f s steady window (every class of the mix and the golden queries; over-limit probes are judged separately), recomputed from queries/queries.csv.gz; a request that was not answered 200 counts as the %d s client timeout, except an explicit error (HTTP status and the product's own code) inside the degraded window [%d s, %d s] which keeps its measured latency", len(all), steadyS, queriesTimeoutUS/1_000_000, lossUS/1_000_000, restartEndUS/1_000_000)),
		rc.budget("queries_false_healthy_answers", float64(falseHealthy), fmt.Sprintf("in the loss window [%d s, %d s) of slots %v (every project holds data on a lost slot): %d complete uncached answers of %d interactive requests, %d rule evaluations that were complete or carried a reason outside the closed set of %d evaluations, %d recovery notifications", lossUS/1_000_000, restartStartUS/1_000_000, g.LossSlots, fhAnswers, lossRows, fhRules, lossEvals, recLoss)),
		rc.budget("queries_overlimit_unexplained", float64(overUnexplained), fmt.Sprintf("over-limit probes (%d, four classes) not answered by an explicit resource or deadline error (HTTP 429, 504 or 413 with the product's code); %d probes that met the restart's downtime are not counted", overProbes["overlimit_returned"]+overProbes["overlimit_memory"]+overProbes["overlimit_timeout"]+overProbes["overlimit_default"], overDown)),
		rc.budget("queries_golden_mismatches", float64(goldenMismatches), fmt.Sprintf("complete answers of the %d golden queries (over data that ends before the preload end) whose digest differs from the first complete answer of the run, which is taken in the first minute", len(golden))),
	}
	row.Outcome = OutcomePassed
	for _, b := range row.Budgets {
		if !b.Within {
			row.Outcome = OutcomeFailed
		}
	}

	var readings []Reading
	add := func(name string, v float64) {
		val := v
		readings = append(readings, Reading{Name: name, Availability: AvailAvailable, Value: &val})
	}
	add("interactive_requests", float64(len(all)))
	add("interactive_mean_in_flight", shRound(meanFlight))
	add("interactive_max_in_flight", float64(maxFlight))
	add("cached_fraction", shRound(cachedShare))
	if len(cachedLat) > 0 {
		add("cached_p95_ms", ms(shPercentile(qgSort(cachedLat), 0.95)))
	}
	for _, c := range queriesInteractiveClasses {
		id, _ := d.cls.get(c)
		v := qgSort(perClass[id])
		add("latency_p50_ms."+c, ms(shPercentile(v, 0.5)))
		add("latency_p95_ms."+c, ms(shPercentile(v, 0.95)))
		add("latency_p99_ms."+c, ms(shPercentile(v, 0.99)))
	}
	for _, c := range append(append([]string(nil), queriesInteractiveClasses...), queriesOverlimitClasses...) {
		add("non_200_answers."+c, float64(nonOK[c]))
	}
	for _, c := range queriesInteractiveClasses {
		if c == "golden" {
			continue
		}
		for _, m := range []struct {
			name string
			vals []int64
		}{{"pages", scanPages[c]}, {"rows", scanRows[c]}, {"bytes", scanBytes[c]}} {
			mean, p50, p95v, maxV := qgStats(m.vals)
			add("scan_"+m.name+"_mean."+c, mean)
			add("scan_"+m.name+"_p50."+c, p50)
			add("scan_"+m.name+"_p95."+c, p95v)
			add("scan_"+m.name+"_max."+c, maxV)
		}
	}
	for _, c := range queriesOverlimitClasses {
		add("overlimit_probes."+c, float64(overProbes[c]))
	}
	add("overlimit_probes_in_restart_downtime", float64(overDown))
	add("loss_window_interactive_requests", float64(lossRows))
	add("loss_window_partial_or_stale_answers", float64(lossPartial))
	add("loss_window_explicit_errors", float64(lossErrors))
	add("loss_window_complete_answers", float64(fhAnswers))
	add("loss_window_rule_evaluations", float64(lossEvals))
	add("loss_window_false_healthy_rule_evaluations", float64(fhRules))
	add("loss_window_recovery_notifications", float64(recLoss))
	add("recovered_notifications_before_loss", float64(recBefore))
	add("notifications_with_bad_signature", float64(badSig))
	for _, k := range qgSortedKeys(notesByKey) {
		add("notifications."+k, float64(notesByKey[k]))
	}
	ids := make([]uint32, 0, len(golden))
	for id := range golden {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return d.golds.list[ids[i]] < d.golds.list[ids[j]] })
	for _, id := range ids {
		add("golden_complete_answers."+d.golds.list[id], float64(golden[id].runs))
	}
	add("rule_evaluations_per_minute_mean", shRound(perMinuteMean))
	minPerMinute := perMinute[0]
	for _, v := range perMinute {
		minPerMinute = min(minPerMinute, v)
	}
	add("rule_evaluations_per_minute_min", float64(minPerMinute))
	add("rule_evaluations_live_fraction", shRound(float64(liveEvals)/float64(max(evals, 1))))
	add("rule_evaluations_thinnest_ten_minutes_distinct_rules", float64(minDistinct))
	for _, k := range qgSortedKeys(ruleCounts) {
		add("rule_evaluations."+k, float64(ruleCounts[k]))
	}
	for _, m := range []struct {
		name string
		vals []int64
	}{{"pages", qPages}, {"rows", qRows}, {"bytes", qBytes}} {
		mean, _, p95v, maxV := qgStats(m.vals)
		add("rule_query_"+m.name+"_mean", mean)
		add("rule_query_"+m.name+"_p95", p95v)
		add("rule_query_"+m.name+"_max", maxV)
	}
	var preRecords, ingRecords int64
	for _, s := range queriesPreloadSignals {
		var rec int64
		for _, a := range d.preload {
			if a.status == 200 && d.sigs.list[a.signal] == s {
				rec += a.records
			}
		}
		preRecords += rec
		add("preload_encoded_bytes."+s, float64(preBytes[s]))
		add("preload_records."+s, float64(rec))
	}
	if dur := float64(d.preSum.EndUnixMS-d.preSum.StartUnixMS) / 1000; dur > 0 {
		add("preload_throughput_mbyte_per_s", shRound(float64(preBytes["metric"]+preBytes["log"]+preBytes["span"])/dur/1e6))
	}
	var before, after [3]int64 // ACKed, refused (an answer other than 200), transport failures
	var shed int64
	for _, a := range d.ingest {
		k := &before
		if a.startUS >= lossUS {
			k = &after
		}
		switch {
		case a.status == 200:
			k[0]++
			ingRecords += a.records
		case a.status < 0: // shed by the generator: never sent
			shed++
		case a.status == 0:
			k[2]++
		default:
			k[1]++
		}
	}
	for i, name := range []string{"acked", "refused", "transport_failed"} {
		add("ingest_requests_"+name+"_before_loss", float64(before[i]))
		add("ingest_requests_"+name+"_after_loss", float64(after[i]))
	}
	add("ingest_requests_shed_by_generator", float64(shed))
	add("ingest_records_per_second", shRound(float64(offered)/steadyS))
	var dataEnd int64
	for _, s := range d.samples {
		if s.DataBytes > 0 {
			dataEnd = s.DataBytes
		}
	}
	if recs := preRecords + ingRecords; recs > 0 && dataEnd > 0 {
		add("data_bytes_per_acked_record", shRound(float64(dataEnd)/float64(recs)))
	}
	for _, host := range []string{"server", "ingest", "query"} {
		m, p := linkMean[host], linkPeak[host]
		add("link_"+host+"_mean_rx_mbit", shRound(m[0]))
		add("link_"+host+"_mean_tx_mbit", shRound(m[1]))
		add("link_"+host+"_peak_rx_mbit", shRound(p[0]))
		add("link_"+host+"_peak_tx_mbit", shRound(p[1]))
		add("link_"+host+"_peak_mbit", shRound(max(p[0], p[1])))
	}
	var rssPeak, hwmPeak int64
	var cpuTicks uint64
	var cpuWallMS int64
	var prev *qgSample
	for i := range d.samples {
		s := &d.samples[i]
		if s.PID == 0 {
			prev = nil
			continue
		}
		rssPeak, hwmPeak = max(rssPeak, s.RSSKiB), max(hwmPeak, s.HWMKiB)
		if prev != nil && prev.PID == s.PID && s.UTime+s.STime >= prev.UTime+prev.STime {
			cpuTicks += s.UTime + s.STime - prev.UTime - prev.STime
			cpuWallMS += s.TMS - prev.TMS
		}
		prev = s
	}
	add("server_rss_peak_kib", float64(rssPeak))
	add("server_hwm_peak_kib", float64(hwmPeak))
	if cpuWallMS > 0 {
		add("server_cpu_busy_percent_of_scope", shRound(float64(cpuTicks)/100/(float64(cpuWallMS)/1000*float64(scopeCPUs))*100)) // USER_HZ = 100
	}
	row.Readings = readings

	row.Loss = fmt.Sprintf("steady window: %d interactive requests, %d not answered 200; loss window [%d s, %d s): %d interactive requests of which %d partial or stale, %d explicit errors, %d complete uncached; %d rule evaluations; ingest before the loss %d ACKed/%d refused, after %d ACKed/%d refused/%d transport failures",
		len(all), func() int {
			n := 0
			for i := range d.rows {
				if r := &d.rows[i]; !isOver(r) && r.status != 200 && r.start >= 0 && r.start < steadyUS {
					n++
				}
			}
			return n
		}(), lossUS/1_000_000, restartStartUS/1_000_000, lossRows, lossPartial, lossErrors, fhAnswers, lossEvals, before[0], before[1], after[0], after[1], after[2])
	row.Limits = []string{
		fmt.Sprintf("host shape is the server's cgroup v2 scope (D90), not the VM totals: scope %s with %d CPUs effective (cpuset %s, GOMAXPROCS %d) and memory.max %d MiB, memory.swap.max %s, on a VM of %d vCPUs / %d MiB; page cache is charged to the scope", res.Server.CgroupPath, scopeCPUs, res.Server.CgroupCPUs, res.Server.Gomaxprocs, scopeMem>>20, res.Server.CgroupSwapMax, res.Server.LogicalCPUs, res.Server.MemTotalKiB/1024),
		fmt.Sprintf("the product under test is the soundpost_faults build (it adds a fault-injection control for the shard loss and observation hooks in internal/rules and internal/httpapi that only write what they see); it is not the release build. All three hosts are virtual machines on a virtual disk (%q); the data directory's filesystem is %s", res.Server.BlockDevice, res.Server.DataFS),
		fmt.Sprintf("the hosts share a lab link rate-limited to about %.0f Mbit/s: a run whose server host used more than %.0f %% of it over any minute is a reduced run; the measured peak over a minute was %.1f Mbit/s (receive %.1f, transmit %.1f)", queriesLinkMbit, 100*queriesLinkFraction, max(linkPeak["server"][0], linkPeak["server"][1]), linkPeak["server"][0], linkPeak["server"][1]),
		"one run of 24 hours on one set of hosts: no repetition, no confidence interval",
		fmt.Sprintf("the loss window [%d s, %d s) is inside the 24 hours and inside every latency and count: nothing is excluded from the p95 except that an explicit error inside the degraded window (the loss until the restart is ready, %d s) keeps its measured latency instead of the timeout; the over-limit probes are judged apart from the p95", lossUS/1_000_000, restartStartUS/1_000_000, restartEndUS/1_000_000),
		fmt.Sprintf("the ingest rate of %d mixed records/s is the harness's own choice, the design names none; the query mix, its weights, the golden queries and the over-limit classes are the harness's constructs; every project holds records on a lost slot by construction (checked from the preload summary), so every uncached complete answer during the loss is judged false healthy", g.IngestRate),
		"preload input is counted as the encoded request bodies of durably ACKed requests (HTTP 200 with a receipt) per signal; event time is spread over 24 h so the scans reach the whole preload",
		"bytes, pages and rows scanned are the product's own Stats of non-cached answers, summed over the projects of a request; for trace_view and service_red they come from the server's scan accounting joined by request id",
	}
	return row
}

func qgSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
