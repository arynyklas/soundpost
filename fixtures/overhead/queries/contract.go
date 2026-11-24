// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Command queries is the load harness of design section 13's Queries row (07.06 criterion 11): 24-hour representative scans over a fixed
// 1 GiB of encoded input per signal (metrics, logs, traces), with concurrent ingest, 10 active interactive queries and 100 rule
// evaluations a minute, against a REAL `soundpost serve` on another host. Roles:
//
//	server     starts the product (cgroup scope of D90), provisions the estate, destinations and rules, answers a control endpoint
//	ingest     preloads exactly 1 GiB per signal, then ingests at a steady rate for the whole run
//	query      drives 10 interactive queries, golden checks, over-limit probes, the webhook receiver, the shard loss and the restart
//	summarize  folds the raw series into result.json, which tools/qualify's overhead_queries runner validates
//
// This file is the contract the roles share: constants, the estate, the plan and the shapes of the raw files. A raw file is documented
// where its writer is; tools/qualify/overhead_queries.go recomputes every judged number from them.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/arynyklas/soundpost/internal/model"
)

// The design section 13 Queries gate, pinned in code. tools/qualify/overhead_queries.go has the same constants; a run cannot ask for less.
const (
	ResultSchema = "soundpost-queries-result/1"
	HarnessName  = "fixtures/overhead/queries"

	InputBytesPerSignal = 1 << 30 // actual encoded request bytes durably ACKed per signal before the steady run starts
	SteadyS             = 86400   // 24 h
	Interactive         = 10      // concurrently active interactive queries
	RulesPerMinute      = 100     // rule evaluations a minute
	IngestRate          = 100     // mixed records/s ingested during the steady run (metric 60 %, span 20 %, log 12 %, job 5 %, error 3 %)
	P95LimitMS          = 2000
	TimeoutLatencyUS    = 40_000_000 // what a request that did not answer 200 counts as in the strict p95: the client's own timeout
)

// The shard loss and the restart of the steady run (seconds after T0), and the replica-group slots the loss closes (0..31 of 64).
const (
	LossAtS      = 81000 // 22 h 30 m
	RestartAtS   = 82800 // 23 h
	LossSlotLast = 31
)

// Signals of a request's records (the `signal` column of an acks file). A steady-run request is "mixed" (every kind of the single-host
// mix), the control samples of the flip rules are "control".
type Signal string

const (
	SignalMetric  Signal = "metric"
	SignalLog     Signal = "log"
	SignalSpan    Signal = "span"
	SignalMixed   Signal = "mixed"
	SignalControl Signal = "control"
)

// PreloadSignals are the three signals the 1 GiB input is counted per, in the order they are preloaded.
var PreloadSignals = []Signal{SignalMetric, SignalLog, SignalSpan}

// Query classes (the `class` column of queries.csv.gz). The first group is the interactive stream; golden runs are part of it (the same 10
// workers issue them) and are judged for exactness; overlimit_* probes are issued by one more goroutine and are judged for an EXPLICIT
// resource error, never for latency.
const (
	ClassPromInstant   = "promql_instant"   // one project, instant, 5 m rate by route
	ClassPromRange1h   = "promql_range_1h"  // one project, 1 h range
	ClassPromRange24h  = "promql_range_24h" // one project, 24 h range
	ClassPromOrg24h    = "promql_org_24h"   // all projects of one organization, 24 h range
	ClassPromTopk      = "promql_topk"      // organization, topk over 6 h
	ClassLogLines      = "logql_lines"      // one project, 1 h, line filter, limited lines
	ClassLogCount24h   = "logql_count_24h"  // organization, 24 h, count_over_time by route
	ClassLogRate6h     = "logql_rate_6h"    // one project, 6 h metric query
	ClassTraceView     = "trace_view"       // POST /api/v1/traces/view of a known trace
	ClassServiceRED    = "service_red"      // POST /api/v1/services/red over 1 h or 24 h
	ClassGolden        = "golden"           // fixed query over the immutable preload; digest compared across the run
	ClassOverMax       = "overlimit_returned"
	ClassOverMemory    = "overlimit_memory"
	ClassOverTimeout   = "overlimit_timeout"
	ClassOverDefault24 = "overlimit_default" // zero budget (the product's defaults) and a result far past them
)

// Rule classes of the 100 rules, one per project (project index p): p%4==0 firing_metric, 1 firing_log, 2 healthy_metric, 3 healthy_heavy,
// except projects 97, 98 and 99 which carry a flip rule. A firing rule's expression always returns a series while its data is readable,
// a healthy rule's never does: after a lost shard an implementation that read "no series" as "healthy" would recover the firing rules.
const (
	RuleFiringMetric  = "firing_metric"
	RuleFiringLog     = "firing_log"
	RuleHealthyMetric = "healthy_metric"
	RuleHealthyHeavy  = "healthy_heavy"
	RuleFlip          = "flip" // `ctl_flag > 0`; the ingest role writes ctl_flag 1 and 0 in 5-minute turns, so it fires and recovers
)

// Files of a run directory (the evidence directory has the same layout; summarize copies them).
const (
	FileResult         = "result.json"
	FileBuild          = "BUILD.txt"
	FileServerSeries   = "server/server-series.jsonl" // monitor: Sample lines every 10 s
	FileServerEvents   = "server/events.jsonl"        // Event lines
	FileServerHost     = "server/host.json"
	FileServerLog      = "server/server.log"
	FileServerRules    = "server/rules.jsonl" // soundpost_faults hook: evaluations and their queries (see RuleLine)
	FileServerScans    = "server/scans.jsonl" // soundpost_faults hook: scan accounting of trace_view and service_red (see ScanLine)
	FileServerNet      = "server/net-series.jsonl"
	FilePreloadAcks    = "preload/acks.csv.gz"
	FilePreloadSummary = "preload/summary.json"
	FileIngestAcks     = "ingest/acks.csv.gz"
	FileIngestSummary  = "ingest/load-summary.json"
	FileIngestNet      = "ingest/net-series.jsonl"
	FileIngestHost     = "ingest/host.json"
	FileQueries        = "queries/queries.csv.gz"
	FileQuerySummary   = "queries/query-summary.json"
	FileNotifications  = "queries/notifications.jsonl"
	FileQueryNet       = "queries/net-series.jsonl"
	FileQueryHost      = "queries/host.json"
)

// AcksHeader is the header of preload/acks.csv.gz and ingest/acks.csv.gz: one line per request, times in microseconds since the file's own
// t0 (preload: its first request; ingest: the steady T0), bytes = the encoded request body, status = HTTP status (0 = transport failure).
const AcksHeader = "start_us,sched_us,latency_us,late_us,status,project,records,bytes,signal"

// QueriesHeader is the header of queries/queries.csv.gz: one line per request of the query role, times since the steady T0.
//
//	start_us, latency_us   request start and latency to the end of the response body
//	status                 HTTP status (0 = transport failure)
//	worker                 0..9 interactive workers, 10 = the over-limit prober
//	class, lang            Class* and promql|logql|trace|red
//	projects, window_s     projects named and the window (range or lookback) in seconds
//	pages, rows, bytes     the product's own Stats of the answer, summed over the projects (0 for trace_view and service_red: the
//	                       server's scans.jsonl carries those, joined by req)
//	peak_mem, server_us    summed peak_memory_bytes and the largest elapsed_ns / 1000 of the projects
//	cached                 1 when any project answered from the result cache
//	completeness           c complete, p partial, s stale, - when the request failed (the worst over the projects)
//	returned               samples + logs returned
//	limit_reached          1 when stats.limit_reached
//	code                   the error code of a non-200 answer (the product's own code string), "" otherwise
//	digest                 golden class only: hex sha256 of the canonical JSON of every project's value, "" otherwise
//	req                    the X-Gate-Request header value (16 hex) the server's hooks key on
//	golden                 golden class only: the id of the fixed golden query (the validator compares digests per id), "" otherwise
const QueriesHeader = "start_us,latency_us,status,worker,class,lang,projects,window_s,pages,rows,bytes,peak_mem,server_us,cached,completeness,returned,limit_reached,code,digest,req,golden"

// Config is the estate: orgs, projects, the metric cardinality and the seed. The estate is the seed's alone.
type Config struct {
	Seed             uint64 `json:"seed"`
	Orgs             int    `json:"orgs"`
	Projects         int    `json:"projects"` // total, spread evenly over the orgs
	RoutesPerProject int    `json:"routes_per_project"`
	// Epoch numbers a run on one estate: batch, record and trace ids of epoch e are disjoint from those of other epochs (the preload is
	// epoch 1, the steady ingest epoch 2).
	Epoch uint64 `json:"epoch"`
}

const (
	MetricNames = 10 // app_m0..app_m9, the first five counters
	LogCodes    = 4
	LogUnits    = 3
)

// SeriesPerProject is MetricNames x RoutesPerProject; label route=r0..r<routes-1>.
func (c Config) SeriesPerProject() int { return MetricNames * c.RoutesPerProject }

// DefaultConfig is the gate estate: 10 organizations, 100 projects, 30 active metric series per project (3,000 in all).
func DefaultConfig() Config {
	return Config{Seed: 20261124, Orgs: 10, Projects: 100, RoutesPerProject: 3, Epoch: 1}
}

// ident derives a stable identity from the seed and a name: the same seed always yields the same estate.
func ident(seed uint64, parts ...any) model.ID {
	h := sha256.New()
	fmt.Fprintf(h, "soundpost/overhead/queries/v1/%d", seed)
	for _, p := range parts {
		fmt.Fprintf(h, "/%v", p)
	}
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

// RuleID is the identity of the rule of project p.
func RuleID(seed uint64, p int) model.ID { return ident(seed, "rule", p) }

// RuleClass is the class of the rule of project p.
func RuleClass(p int) string {
	switch {
	case p >= 97:
		return RuleFlip
	case p%4 == 0:
		return RuleFiringMetric
	case p%4 == 1:
		return RuleFiringLog
	case p%4 == 2:
		return RuleHealthyMetric
	}
	return RuleHealthyHeavy
}

// PlanRule is one provisioned rule.
type PlanRule struct {
	Project         int      `json:"project"`
	Rule            model.ID `json:"rule"`
	Class           string   `json:"class"`
	Language        string   `json:"language"` // promql | logql
	Expression      string   `json:"expression"`
	IntervalSeconds uint32   `json:"interval_seconds"`
}

// PlanSource is the credential of one project's SDK source.
type PlanSource struct {
	Project    int    `json:"project"`
	Credential string `json:"credential"`
}

// PlanReader is the read token of one organization's read-only user (all of the organization's projects).
type PlanReader struct {
	Org   int    `json:"org"`
	Token string `json:"token"`
}

// PlanWebhook is the receiver of the notification destinations: the query role listens on Listen (host:port) with the leaf the server
// role generated (the server's own egress allow-list and CA file name exactly this address and CA), and verifies every delivery's
// signature with Secret.
type PlanWebhook struct {
	URL     string `json:"url"`
	Listen  string `json:"listen"`
	Secret  string `json:"secret"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// Plan is what the ingest and query roles need to reach and address the estate. It carries credentials: it is written 0600 and is never
// part of the evidence.
type Plan struct {
	Config       Config       `json:"config"`
	Addr         string       `json:"addr"`
	Control      string       `json:"control"`
	ControlToken string       `json:"control_token"`
	Sources      []PlanSource `json:"sources"`
	Readers      []PlanReader `json:"readers"`
	Rules        []PlanRule   `json:"rules"`
	Webhook      PlanWebhook  `json:"webhook"`
	// Profiles the rules and queries pin, as the product advertised them.
	PromProfile    string `json:"prom_profile"`
	PromFeatureSet string `json:"prom_feature_set"`
	LogProfile     string `json:"log_profile"`
	LogFeatureSet  string `json:"log_feature_set"`
	StartedAt      int64  `json:"provisioned_unix_ms"`
}

// PreloadSignal is what the preload ACKed for one signal.
type PreloadSignal struct {
	Batches      int64 `json:"batches"`
	Records      int64 `json:"records"`
	EncodedBytes int64 `json:"encoded_bytes"` // sum of the request bodies of the 200 answers: at least InputBytesPerSignal
	EventStartNS int64 `json:"event_start_ns"`
	EventEndNS   int64 `json:"event_end_ns"`
}

// TraceSample is a preloaded trace the query role may read back (trace_view) and its service.
type TraceSample struct {
	Project int    `json:"project"`
	Trace   string `json:"trace"` // 32 hex
	Service string `json:"service"`
	StartNS int64  `json:"start_ns"`
	Slot    uint16 `json:"slot"` // route slot of the trace's spans (every span of a trace routes to the trace's slot)
}

// PreloadSummary is preload/summary.json.
type PreloadSummary struct {
	StartUnixMS    int64                    `json:"start_unix_ms"`
	EndUnixMS      int64                    `json:"end_unix_ms"`
	EventStartNS   int64                    `json:"event_start_ns"` // oldest record of any signal; the preload spans 24 h up to EventEndNS
	EventEndNS     int64                    `json:"event_end_ns"`
	Signals        map[Signal]PreloadSignal `json:"signals"`
	SlotsByProject [][]int                  `json:"slots_by_project"` // project index -> sorted route slots with at least one preloaded record
	TraceSamples   []TraceSample            `json:"trace_samples"`
	Refused        int64                    `json:"requests_refused"`
	Transport      int64                    `json:"requests_transport_failed"`
}

// RuleLine is one line of server/rules.jsonl, written by the soundpost_faults build of the product (internal/rules, SOUNDPOST_FAULT_DIR):
//
//	{"k":"e", ...}  one committed evaluation (after the commit): t_ns wall clock, at_ns grid time, project and rule (32 hex), mode
//	                live|backfill|replay, outcome complete|unknown|error, reason (closed code or ""), blocked (recovery blocked),
//	                members (series present), ms (evaluate + commit), kind alert|recording
//	{"k":"q", ...}  the rule's query: t_ns, rule, at_ns, pages, rows, bytes, peak_mem, ok (the query answered without error)
type RuleLine struct {
	K       string `json:"k"`
	TNS     int64  `json:"t_ns"`
	AtNS    int64  `json:"at_ns"`
	Project string `json:"project"`
	Rule    string `json:"rule"`
	Mode    string `json:"mode,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Blocked bool   `json:"blocked,omitempty"`
	Members int    `json:"members,omitempty"`
	MS      int64  `json:"ms,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Pages   uint64 `json:"pages,omitempty"`
	Rows    uint64 `json:"rows,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`
	PeakMem uint64 `json:"peak_mem,omitempty"`
	OK      bool   `json:"ok,omitempty"`
}

// ScanLine is one line of server/scans.jsonl: the scan of one trace_view or service_red request that carried an X-Gate-Request header.
type ScanLine struct {
	Req     string `json:"req"`
	Route   string `json:"route"` // trace_view | service_red
	Pages   uint64 `json:"pages"`
	Rows    uint64 `json:"rows"`
	Bytes   uint64 `json:"bytes"`
	MS      int64  `json:"ms"`
	Partial bool   `json:"partial"`
}

// Notification is one line of queries/notifications.jsonl: a signature-verified webhook delivery the product made for a condition.
type Notification struct {
	TMS       int64  `json:"t_ms"`
	Delivery  string `json:"delivery"`
	Entity    string `json:"entity"` // the condition id
	Org       string `json:"org"`
	Kind      string `json:"kind"`      // event_kind of the delivery: open, recovery, reminder, current_state, ...
	Source    string `json:"source"`    // impact.source: firing | recovered | unknown
	Freshness string `json:"freshness"` // fresh | stale | unknown
	Attempt   int    `json:"attempt"`   // the receiver's count of deliveries of this delivery id
	SigOK     bool   `json:"sig_ok"`
}

// mustJSON marshals v or panics; it is for values this program built itself.
func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}
