// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Result is result.json (schema soundpost-queries-result/1), the document tools/qualify's overhead_queries runner validates. It names the
// raw files by sha256 and carries the facts no raw file holds (hosts, build, parameters); every judged figure (p95, evaluation counts,
// false healthy answers, over-limit errors, golden equality, link use) the runner recomputes from the raw files.
type Result struct {
	Schema     string            `json:"schema"`
	Harness    string            `json:"harness"`
	Complete   bool              `json:"complete"` // loss injected, restart done, preload of every signal at its input, 24 h of queries, every file present
	Gate       ResultGate        `json:"gate"`
	ServerHost HostFacts         `json:"server_host"`
	IngestHost HostFacts         `json:"ingest_host"`
	QueryHost  HostFacts         `json:"query_host"`
	Build      ResultBuild       `json:"build"`
	Files      map[string]string `json:"file_sha256"`
	Steady     struct {
		T0UnixMS int64 `json:"t0_unix_ms"`
	} `json:"steady"`
	Preload      ResultPreload `json:"preload"`
	Ingest       ResultIngest  `json:"ingest"`
	Queries      ResultQueries `json:"queries"`
	ServerEvents []Event       `json:"server_events"`
}

// ResultGate is the gate's parameters as the run used them.
type ResultGate struct {
	Orgs             int    `json:"orgs"`
	Projects         int    `json:"projects"`
	SeriesPerProject int    `json:"series_per_project"`
	Seed             uint64 `json:"seed"`
	InputBytes       int64  `json:"input_bytes_per_signal"`
	SteadyS          int    `json:"steady_s"`
	Interactive      int    `json:"interactive"`
	RulesPerMinute   int    `json:"rules_per_minute"`
	IngestRate       int    `json:"ingest_rate"`
	LossAtS          int    `json:"loss_at_s"`
	RestartAtS       int    `json:"restart_at_s"`
	LossSlots        []int  `json:"loss_slots"`
}

// ResultBuild is what BUILD.txt (written by the operator's build script) says about the binaries under test.
type ResultBuild struct {
	SourceTreeSHA256 string `json:"source_tree_sha256"`
	VersionJSON      string `json:"soundpost_version_json"`
	SoundpostSHA256  string `json:"soundpost_sha256"`
	HarnessSHA256    string `json:"harness_sha256"`
	Go               string `json:"go"`
	BuildTags        string `json:"build_tags"`
}

// ResultPreload is the PreloadSummary without its per-project route slots (they stay in preload/summary.json).
type ResultPreload struct {
	StartUnixMS  int64                    `json:"start_unix_ms"`
	EndUnixMS    int64                    `json:"end_unix_ms"`
	EventStartNS int64                    `json:"event_start_ns"`
	EventEndNS   int64                    `json:"event_end_ns"`
	Signals      map[Signal]PreloadSignal `json:"signals"`
}

// ResultIngest are the ingest role's own totals of the steady run (ingest/load-summary.json).
type ResultIngest struct {
	Sent         int64            `json:"requests_sent"`
	Acked        int64            `json:"requests_acked"`
	Refused      int64            `json:"requests_refused"`
	Transport    int64            `json:"requests_transport_failed"`
	Shed         int64            `json:"requests_shed"`
	RecordsAcked map[string]int64 `json:"records_acked_by_kind"`
	EncodedBytes int64            `json:"encoded_bytes_acked"`
}

// ResultQueries counts the rows of queries/queries.csv.gz.
type ResultQueries struct {
	Requests  int64            `json:"requests"`
	ByClass   map[string]int64 `json:"by_class"`
	GoldenIDs []string         `json:"golden_ids"`
	Workers   int              `json:"workers"`
}

func sumFileSHA(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func sumReadJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// buildFacts parses BUILD.txt written by the operator's build script: the lines `source_tree_sha256=`, `build_tags=`, the version JSON
// object, `go version ...` and the `sha256sum` lines of the soundpost and queries binaries, in whichever directory they were built.
func (r *Result) buildFacts(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		f := strings.Fields(l)
		switch {
		case strings.HasPrefix(l, "source_tree_sha256="):
			r.Build.SourceTreeSHA256 = strings.TrimPrefix(l, "source_tree_sha256=")
		case strings.HasPrefix(l, "build_tags="):
			r.Build.BuildTags = strings.TrimPrefix(l, "build_tags=")
		case strings.HasPrefix(l, "{"):
			r.Build.VersionJSON = l
		case len(f) == 2 && len(f[0]) == sha256.Size*2 && filepath.Base(f[1]) == "soundpost":
			r.Build.SoundpostSHA256 = f[0]
		case len(f) == 2 && len(f[0]) == sha256.Size*2 && filepath.Base(f[1]) == "queries":
			r.Build.HarnessSHA256 = f[0]
		case strings.HasPrefix(l, "go version"):
			r.Build.Go = l
		}
	}
}

func sumEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []Event{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			return nil, fmt.Errorf("bad event line")
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// queryRows is what summarize takes from queries/queries.csv.gz: the number of rows, the rows per class and the time span of the run.
type queryRows struct {
	Requests        int64
	ByClass         map[string]int64
	FirstUS, LastUS int64
}

// scanQueries streams the gzip CSV (millions of rows over a 24 h run). Its header must be the contract's.
func scanQueries(path string) (queryRows, error) {
	q := queryRows{ByClass: map[string]int64{}}
	f, err := os.Open(path)
	if err != nil {
		return q, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return q, err
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	if !sc.Scan() || sc.Text() != QueriesHeader {
		return q, fmt.Errorf("queries.csv.gz does not start with the contract's header")
	}
	classCol := indexOfColumn(QueriesHeader, "class")
	first := true
	for sc.Scan() {
		cols := strings.Split(sc.Text(), ",")
		if len(cols) <= classCol {
			return q, fmt.Errorf("short row %q", sc.Text())
		}
		start, err := strconv.ParseInt(cols[0], 10, 64)
		if err != nil {
			return q, fmt.Errorf("bad start_us in row %q", sc.Text())
		}
		if first || start < q.FirstUS {
			q.FirstUS = start
		}
		if first || start > q.LastUS {
			q.LastUS = start
		}
		first = false
		q.Requests++
		q.ByClass[cols[classCol]]++
	}
	return q, sc.Err()
}

func indexOfColumn(header, name string) int {
	for i, c := range strings.Split(header, ",") {
		if c == name {
			return i
		}
	}
	panic("no column " + name)
}

// firstInt is the first of the keys a summary file has as a number (a role may name a counter by either of two names).
func firstInt(m map[string]json.RawMessage, keys ...string) int64 {
	for _, k := range keys {
		var n int64
		if raw, ok := m[k]; ok && json.Unmarshal(raw, &n) == nil {
			return n
		}
	}
	return 0
}

// foldIngest reads the ingest role's totals from ingest/load-summary.json: the counters it names as the single-host harness's load summary
// does (requests_sent, requests_acked, requests_refused, requests_transport_failed, requests_shed[_by_generator], records_acked_by_kind,
// encoded_bytes_acked|encoded_bytes_sent, t0_unix_ms) and, when it carries one, the estate's config.
func foldIngest(path string) (in ResultIngest, t0 int64, cfg *Config, ok bool) {
	var m map[string]json.RawMessage
	if sumReadJSON(path, &m) != nil {
		return in, 0, nil, false
	}
	in.Sent, in.Acked, in.Refused, in.Transport = firstInt(m, "requests_sent"), firstInt(m, "requests_acked"), firstInt(m, "requests_refused"), firstInt(m, "requests_transport_failed")
	in.Shed = firstInt(m, "requests_shed", "requests_shed_by_generator")
	in.EncodedBytes = firstInt(m, "encoded_bytes_acked", "encoded_bytes_sent")
	in.RecordsAcked = map[string]int64{}
	if raw, has := m["records_acked_by_kind"]; has {
		json.Unmarshal(raw, &in.RecordsAcked)
	}
	t0 = firstInt(m, "t0_unix_ms")
	var c Config
	if raw, has := m["config"]; has && json.Unmarshal(raw, &c) == nil && c.Seed != 0 && c.Orgs != 0 {
		cfg = &c
	}
	return in, t0, cfg, true
}

// rawFiles are the raw files of a run directory result.json names by sha256 (contract.go).
var rawFiles = []string{FileBuild, FileServerSeries, FileServerEvents, FileServerHost, FileServerLog, FileServerRules, FileServerScans, FileServerNet,
	FilePreloadAcks, FilePreloadSummary, FileIngestAcks, FileIngestSummary, FileIngestNet, FileIngestHost,
	FileQueries, FileQuerySummary, FileNotifications, FileQueryNet, FileQueryHost}

// buildResult folds the raw files of dir into a Result. incomplete lists what keeps `complete` false.
func buildResult(dir string, fallback Config) (res Result, incomplete []string, err error) {
	at := func(name string) string { return filepath.Join(dir, filepath.FromSlash(name)) }
	res.Schema, res.Harness = ResultSchema, HarnessName
	res.Files = map[string]string{}
	for _, name := range rawFiles {
		if h := sumFileSHA(at(name)); h != "" {
			res.Files[name] = h
		} else {
			incomplete = append(incomplete, "missing "+name)
		}
	}
	for name, dst := range map[string]*HostFacts{FileServerHost: &res.ServerHost, FileIngestHost: &res.IngestHost, FileQueryHost: &res.QueryHost} {
		sumReadJSON(at(name), dst)
	}
	res.buildFacts(at(FileBuild))

	in, t0, cfg, ok := foldIngest(at(FileIngestSummary))
	res.Ingest = in
	if cfg == nil {
		cfg = &fallback
	}
	if !ok {
		res.Ingest.RecordsAcked = map[string]int64{}
	}
	var qsum struct {
		T0UnixMS  int64    `json:"t0_unix_ms"`
		GoldenIDs []string `json:"golden_ids"`
	}
	sumReadJSON(at(FileQuerySummary), &qsum)
	if t0 == 0 {
		t0 = qsum.T0UnixMS
	}
	res.Steady.T0UnixMS = t0
	res.Gate = ResultGate{Orgs: cfg.Orgs, Projects: cfg.Projects, SeriesPerProject: cfg.SeriesPerProject(), Seed: cfg.Seed, InputBytes: InputBytesPerSignal, SteadyS: SteadyS,
		Interactive: Interactive, RulesPerMinute: RulesPerMinute, IngestRate: IngestRate, LossAtS: LossAtS, RestartAtS: RestartAtS}
	for n := range LossSlotLast + 1 {
		res.Gate.LossSlots = append(res.Gate.LossSlots, n)
	}

	var pre PreloadSummary
	if err = sumReadJSON(at(FilePreloadSummary), &pre); err == nil {
		res.Preload = ResultPreload{StartUnixMS: pre.StartUnixMS, EndUnixMS: pre.EndUnixMS, EventStartNS: pre.EventStartNS, EventEndNS: pre.EventEndNS, Signals: pre.Signals}
	}
	for _, sig := range PreloadSignals {
		if got := pre.Signals[sig].EncodedBytes; got < InputBytesPerSignal {
			incomplete = append(incomplete, fmt.Sprintf("preload of %s holds %d encoded bytes, the gate needs %d", sig, got, int64(InputBytesPerSignal)))
		}
	}
	if res.Preload.Signals == nil {
		res.Preload.Signals = map[Signal]PreloadSignal{}
	}

	res.Queries = ResultQueries{ByClass: map[string]int64{}, GoldenIDs: qsum.GoldenIDs, Workers: Interactive}
	if res.Queries.GoldenIDs == nil {
		res.Queries.GoldenIDs = []string{}
	}
	if q, qerr := scanQueries(at(FileQueries)); qerr == nil {
		res.Queries.Requests, res.Queries.ByClass = q.Requests, q.ByClass
		if span := q.LastUS - q.FirstUS; span < int64(SteadyS)*1_000_000 {
			incomplete = append(incomplete, fmt.Sprintf("queries span %.0f s, the gate needs %d s", float64(span)/1e6, SteadyS))
		}
	} else if _, statErr := os.Stat(at(FileQueries)); statErr == nil {
		incomplete = append(incomplete, "queries.csv.gz: "+qerr.Error())
	}

	events, eerr := sumEvents(at(FileServerEvents))
	if eerr != nil {
		events = []Event{}
	}
	res.ServerEvents = events
	var lossT, restartT int64
	for _, e := range events {
		if e.Event == "shard_loss" && strings.HasPrefix(e.Note, "closed ") && lossT == 0 {
			lossT = e.TMS
		}
		if e.Event == "restart" && e.Mode == "graceful" && strings.HasSuffix(e.Exit, "status 0") && restartT == 0 {
			restartT = e.TMS
		}
	}
	if lossT == 0 {
		incomplete = append(incomplete, "no shard_loss event")
	}
	if restartT == 0 {
		incomplete = append(incomplete, "no graceful restart event")
	}
	if lossT != 0 && restartT != 0 && restartT < lossT {
		incomplete = append(incomplete, "the restart came before the shard loss")
	}
	res.Complete = len(incomplete) == 0
	return res, incomplete, nil
}

// runSummarize folds the raw files of one complete procedure into result.json. Layout of --dir (contract.go's File* constants):
//
//	BUILD.txt, result.json
//	server/{server-series.jsonl,events.jsonl,host.json,server.log,rules.jsonl,scans.jsonl,net-series.jsonl}
//	preload/{acks.csv.gz,summary.json}
//	ingest/{acks.csv.gz,load-summary.json,net-series.jsonl,host.json}
//	queries/{queries.csv.gz,query-summary.json,notifications.jsonl,net-series.jsonl,host.json}
func runSummarize(args []string) {
	f := flag.NewFlagSet("summarize", flag.ExitOnError)
	dir := f.String("dir", "", "run directory (layout in the command's documentation)")
	def := DefaultConfig()
	seed := f.Uint64("seed", def.Seed, "estate seed when ingest/load-summary.json carries no config")
	orgs := f.Int("orgs", def.Orgs, "organizations (same fallback)")
	projects := f.Int("projects", def.Projects, "projects (same fallback)")
	routes := f.Int("routes", def.RoutesPerProject, "routes per project (same fallback)")
	f.Parse(args)
	if *dir == "" {
		fatalf("--dir is required")
	}
	res, incomplete, err := buildResult(*dir, Config{Seed: *seed, Orgs: *orgs, Projects: *projects, RoutesPerProject: *routes, Epoch: def.Epoch})
	must(err, "summarize")
	raw, err := json.MarshalIndent(res, "", " ")
	must(err, "result")
	must(os.WriteFile(filepath.Join(*dir, FileResult), append(raw, '\n'), 0o644), "result")
	fmt.Fprintf(os.Stderr, "queries: result written %s (complete=%v, %d queries, %d server events, generated %s)\n", filepath.Join(*dir, FileResult), res.Complete, res.Queries.Requests, len(res.ServerEvents), time.Now().UTC().Format(time.RFC3339))
	for _, why := range incomplete {
		fmt.Fprintf(os.Stderr, "queries: incomplete: %s\n", why)
	}
}
