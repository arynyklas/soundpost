// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ResultSchema identifies result.json; tools/qualify's overhead_distributed runner validates exactly this document.
const ResultSchema = "soundpost-distributed-result/1"

// timeoutLatencyUS is what a request that was not ACKed counts as in the strict latency figures: the client's own request budget.
const timeoutLatencyUS = 40_000_000

// failureTailUS is how long after the killed node answered ready again the run still counts as the failure's: the node is catching up with
// what it missed and the leaderships move back.
const failureTailUS = 60_000_000

// Result is the document the qualify runner validates. Every number in it is recomputed by the runner from the raw files it names.
type Result struct {
	Schema   string `json:"schema"`
	Harness  string `json:"harness"`
	Complete bool   `json:"complete"` // the whole procedure ran: the steady hour with the kill, and every shard read back from every member
	Gate     struct {
		Orgs, Projects, Series, Rate int
		Seed                         uint64
		SteadyS, WarmupS             float64
		FlushWindowS                 float64
		Nodes, Shards                int
	} `json:"gate"`
	Nodes      []NodeFacts `json:"nodes"`
	Generators []HostFacts `json:"generators"`
	Build      struct {
		SourceTreeSHA256 string `json:"source_tree_sha256"`
		VersionJSON      string `json:"soundpost_version_json"`
		SoundpostSHA256  string `json:"soundpost_sha256"`
		HarnessSHA256    string `json:"harness_sha256"`
		Go               string `json:"go"`
	} `json:"build"`
	Files map[string]string `json:"file_sha256"`
	Run   struct {
		T0UnixMS       int64            `json:"t0_unix_ms"`
		Sent           int64            `json:"requests_sent"`
		Acked          int64            `json:"requests_acked"`
		Refused        int64            `json:"requests_refused"`
		Transport      int64            `json:"requests_transport_failed"`
		Shed           int64            `json:"requests_shed_by_generator"`
		Retried        int64            `json:"requests_retried"`
		RecordsSent    map[string]int64 `json:"records_sent_by_kind"`
		RecordsAcked   map[string]int64 `json:"records_acked_by_kind"`
		EncodedBytes   int64            `json:"encoded_bytes_sent"`
		MaxInFlight    int64            `json:"max_in_flight"`
		LateP99MS      float64          `json:"generator_lateness_p99_ms"`
		SteadyRequests int64            `json:"steady_requests"`
		SteadyAcked    int64            `json:"steady_acked"`
	} `json:"run"`
	Latency struct {
		P50MS, P95MS, P99MS float64
		StrictP95MS         float64   `json:"strict_p95_ms"`
		PerMinuteP95MS      []float64 `json:"per_minute_p95_ms"`
		PerMinuteStrictP95  []float64 `json:"per_minute_strict_p95_ms"`
		HealthyP95MS        float64   `json:"healthy_p95_ms"`
		HealthyStrictP95MS  float64   `json:"healthy_strict_p95_ms"`
		HealthyRequests     int64     `json:"healthy_requests"`
	} `json:"latency"`
	Failure   FailureFigures `json:"failure"`
	NodeStats []NodeStats    `json:"node_stats"`
	Kill      *KillRecord    `json:"kill"`
	Verify    []VerifyReport `json:"verify"`
}

// FailureFigures are the figures of the killed node's failure window, derived from the rows and the kill record.
type FailureFigures struct {
	Node          uint64  `json:"node"`
	KillAtUS      int64   `json:"kill_at_us"`            // relative to T0, on the generators' clock
	ReadyAtUS     int64   `json:"restart_ready_at_us"`   // the killed node answered ready again
	WindowEndUS   int64   `json:"failure_window_end_us"` // ReadyAtUS + 60 s
	ResumeS       float64 `json:"resume_s"`
	SlotsSeen     int     `json:"slots_seen"`    // distinct route slots of the run
	SlotsResumed  int     `json:"slots_resumed"` // of them, slots with a durable ACK of a request that started after the kill
	RequestsInWin int64   `json:"steady_requests_in_the_failure_window"`
}

// NodeStats are the figures of one node's monitor series over the steady window.
type NodeStats struct {
	Node            uint64  `json:"node"`
	SteadyMaxRSSKiB int64   `json:"steady_max_rss_kib"`
	PeakHWMKiB      int64   `json:"peak_hwm_kib"`
	Samples         int     `json:"steady_samples"`
	SampleGapMaxS   float64 `json:"sample_gap_max_s"`
	OOMKills        uint64  `json:"cgroup_oom_kills"`
	DataBytesStart  int64   `json:"data_bytes_start"`
	DataBytesEnd    int64   `json:"data_bytes_end"`
	FSUsedPctMax    float64 `json:"data_fs_used_percent_max"`
	LinkPeakRxMbit  float64 `json:"link_peak_rx_mbit"` // peak of the 10 s means outside the failure window
	LinkPeakTxMbit  float64 `json:"link_peak_tx_mbit"`
	LinkMeanRxMbit  float64 `json:"link_mean_rx_mbit"`
	LinkMeanTxMbit  float64 `json:"link_mean_tx_mbit"`
	CPUSecs         float64 `json:"scope_cpu_seconds_steady"`
}

func fileSHA(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// buildFacts parses BUILD.txt written by build.sh.
func (r *Result) buildFacts(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(raw), "\n") {
		f := strings.Fields(l)
		switch {
		case strings.HasPrefix(l, "source_tree_sha256="):
			r.Build.SourceTreeSHA256 = strings.TrimPrefix(l, "source_tree_sha256=")
		case strings.HasPrefix(l, "{"):
			r.Build.VersionJSON = l
		case len(f) == 2 && len(f[0]) == sha256.Size*2 && filepath.Base(f[1]) == "soundpost":
			r.Build.SoundpostSHA256 = f[0]
		case len(f) == 2 && len(f[0]) == sha256.Size*2 && filepath.Base(f[1]) == "distributed":
			r.Build.HarnessSHA256 = f[0]
		case strings.HasPrefix(l, "go version"):
			r.Build.Go = l
		}
	}
}

func readSamples(path string) ([]Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var s Sample
		if json.Unmarshal(sc.Bytes(), &s) != nil {
			return nil, fmt.Errorf("bad sample line")
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

func round6(v float64) float64 { return math.Round(v*1e6) / 1e6 }

func ms(us int64) float64 { return round6(float64(us) / 1000) }

// overlaps says whether the request [start, start+latency) touches [lo, hi).
func overlaps(start, latency, lo, hi int64) bool { return start < hi && start+latency > lo }

// failureFigures derives the failure window and the resume time from the kill record and the rows (every row of the run, warm-up
// included): for every route slot, how long after the kill the first request that started after it was durably ACKed; the resume time is
// the worst slot. A slot with no such ACK at all is counted to endUS, the end of the steady window.
func failureFigures(rows []AckRow, t0MS int64, k *KillRecord, endUS int64) FailureFigures {
	var f FailureFigures
	f.Node = k.Node
	f.KillAtUS = (k.SentUnixMS - t0MS) * 1000
	f.ReadyAtUS = (k.AnsweredUnixMS - t0MS) * 1000
	f.WindowEndUS = f.ReadyAtUS + failureTailUS
	first := map[int]int64{} // slot -> earliest completion of an ACKed request that started after the kill
	seen := map[int]bool{}
	for _, r := range rows {
		seen[r.Slot] = true
		if r.StartUS >= f.KillAtUS && r.Status == 200 {
			done := r.StartUS + r.LatencyUS
			if c, ok := first[r.Slot]; !ok || done < c {
				first[r.Slot] = done
			}
		}
	}
	worst := int64(0)
	for slot := range seen {
		done, ok := first[slot]
		if !ok {
			done = endUS
		}
		worst = max(worst, done-f.KillAtUS)
	}
	f.SlotsSeen, f.SlotsResumed = len(seen), len(first)
	f.ResumeS = round6(float64(worst) / 1e6)
	return f
}

type ackFigures struct {
	steadyReq, steadyAcked, healthyReq int64
	p50, p95, p99, strict              float64
	healthyP95, healthyStrict          float64
	perMin, perMinStrict               []float64
	lateP99                            float64
	inWindow                           int64
}

// ackStats computes the latency figures of the steady window [warmup, warmup+steady) (by the start of a request) from the raw rows of
// every shard. The same definitions are re-implemented by the runner. healthy figures leave out every request whose lifetime touches the
// failure window [killAt, windowEnd).
func ackStats(rows []AckRow, warmupS, steadyS float64, killAt, windowEnd int64) ackFigures {
	lo, hi := int64(warmupS*1e6), int64((warmupS+steadyS)*1e6)
	minutes := int(steadyS / 60)
	perMin, perMinStrict := make([][]int64, minutes), make([][]int64, minutes)
	var a ackFigures
	var acked, strict, late, healthyAcked, healthyStrict []int64
	for _, r := range rows {
		if r.StartUS < lo || r.StartUS >= hi {
			continue
		}
		a.steadyReq++
		lat := r.LatencyUS
		if r.Status != 200 {
			lat = timeoutLatencyUS
		} else {
			a.steadyAcked++
			acked = append(acked, r.LatencyUS)
		}
		strict = append(strict, lat)
		late = append(late, r.LateUS)
		if m := int((r.StartUS - lo) / 60_000_000); m >= 0 && m < minutes {
			perMinStrict[m] = append(perMinStrict[m], lat)
			if r.Status == 200 {
				perMin[m] = append(perMin[m], r.LatencyUS)
			}
		}
		if overlaps(r.StartUS, max(r.LatencyUS, 1), killAt, windowEnd) {
			a.inWindow++
			continue
		}
		a.healthyReq++
		healthyStrict = append(healthyStrict, lat)
		if r.Status == 200 {
			healthyAcked = append(healthyAcked, r.LatencyUS)
		}
	}
	for _, v := range [][]int64{acked, strict, late, healthyAcked, healthyStrict} {
		sortInts(v)
	}
	a.p50, a.p95, a.p99, a.strict = ms(percentile(acked, 0.5)), ms(percentile(acked, 0.95)), ms(percentile(acked, 0.99)), ms(percentile(strict, 0.95))
	a.healthyP95, a.healthyStrict = ms(percentile(healthyAcked, 0.95)), ms(percentile(healthyStrict, 0.95))
	a.lateP99 = ms(percentile(late, 0.99))
	for m := 0; m < minutes; m++ {
		sortInts(perMin[m])
		sortInts(perMinStrict[m])
		a.perMin = append(a.perMin, ms(percentile(perMin[m], 0.95)))
		a.perMinStrict = append(a.perMinStrict, ms(percentile(perMinStrict[m], 0.95)))
	}
	return a
}

// nodeStats folds one node's monitor series over the steady window; the link means and peaks leave out the failure window, in which the
// killed node's catch-up and the other two members' retries are the failure's traffic and not the healthy run's.
func nodeStats(node uint64, samples []Sample, t0MS int64, warmupS, steadyS float64, killAtMS, windowEndMS int64) NodeStats {
	st := NodeStats{Node: node}
	loMS, hiMS := t0MS+int64(warmupS*1000), t0MS+int64((warmupS+steadyS)*1000)
	var prev *Sample
	var firstData int64
	var rxSum, txSum, secs float64
	var firstCPU, lastCPU uint64
	for i := range samples {
		s := &samples[i]
		if s.TMS < loMS || s.TMS > hiMS {
			continue
		}
		st.Samples++
		st.SteadyMaxRSSKiB = max(st.SteadyMaxRSSKiB, s.RSSKiB)
		st.PeakHWMKiB = max(st.PeakHWMKiB, s.HWMKiB)
		st.OOMKills = max(st.OOMKills, s.CgOOMKill)
		st.FSUsedPctMax = max(st.FSUsedPctMax, s.FSUsedPct)
		if s.DataBytes > 0 {
			if firstData == 0 {
				firstData = s.DataBytes
			}
			st.DataBytesEnd = s.DataBytes
		}
		if s.CgCPUUsec > 0 {
			if firstCPU == 0 {
				firstCPU = s.CgCPUUsec
			}
			lastCPU = s.CgCPUUsec
		}
		if prev != nil {
			dt := float64(s.TMS-prev.TMS) / 1000
			st.SampleGapMaxS = max(st.SampleGapMaxS, dt)
			if dt > 0 && s.NetRxBytes >= prev.NetRxBytes && s.NetTxBytes >= prev.NetTxBytes && !(s.TMS > killAtMS && prev.TMS < windowEndMS) {
				rx, tx := float64(s.NetRxBytes-prev.NetRxBytes)*8/1e6/dt, float64(s.NetTxBytes-prev.NetTxBytes)*8/1e6/dt
				st.LinkPeakRxMbit, st.LinkPeakTxMbit = max(st.LinkPeakRxMbit, rx), max(st.LinkPeakTxMbit, tx)
				rxSum, txSum, secs = rxSum+rx*dt, txSum+tx*dt, secs+dt
			}
		}
		prev = s
	}
	st.DataBytesStart = firstData
	if secs > 0 {
		st.LinkMeanRxMbit, st.LinkMeanTxMbit = rxSum/secs, txSum/secs
	}
	st.CPUSecs = float64(lastCPU-firstCPU) / 1e6
	for _, p := range []*float64{&st.LinkPeakRxMbit, &st.LinkPeakTxMbit, &st.LinkMeanRxMbit, &st.LinkMeanTxMbit, &st.CPUSecs, &st.FSUsedPctMax} {
		*p = round6(*p)
	}
	return st
}

// runSummarize folds the raw files of one complete procedure into result.json. Layout of --dir:
//
//	steady/g<S>/{acks.csv.gz,load-summary.json,generator.json,ledger.bin}   shard S's run (ledger.bin stays on its generator host)
//	nodes/n<N>/{server-series.jsonl,events.jsonl,host.json}                 node N's monitor
//	verify/n<N>-g<S>.json                                                   shard S's ledger read back from member N
//	BUILD.txt                                                               build.sh output
func runSummarize(args []string) {
	f := flag.NewFlagSet("summarize", flag.ExitOnError)
	dir := f.String("dir", "", "evidence directory (layout in the command's documentation)")
	shards := f.Int("shards", 0, "number of generator shards")
	f.Parse(args)
	if *dir == "" || *shards < 1 {
		fatalf("--dir and --shards are required")
	}
	var res Result
	res.Schema, res.Harness = ResultSchema, "fixtures/overhead/distributed"
	var rows []AckRow
	var loads []LoadSummary
	for s := 0; s < *shards; s++ {
		sd := filepath.Join(*dir, "steady", fmt.Sprintf("g%d", s))
		var ls LoadSummary
		must(readJSON(filepath.Join(sd, "load-summary.json"), &ls), "load summary of shard "+fmt.Sprint(s))
		r, err := readRows(filepath.Join(sd, "acks.csv.gz"))
		must(err, "rows of shard "+fmt.Sprint(s))
		rows = append(rows, r...)
		loads = append(loads, ls)
		var gf HostFacts
		must(readJSON(filepath.Join(sd, "generator.json"), &gf), "generator host facts")
		res.Generators = append(res.Generators, gf)
	}
	l0 := loads[0]
	res.Gate.Orgs, res.Gate.Projects, res.Gate.Series, res.Gate.Rate, res.Gate.Seed = l0.Config.Orgs, l0.Config.Projects, l0.Config.Series, l0.Config.Rate, l0.Config.Seed
	res.Gate.SteadyS, res.Gate.WarmupS, res.Gate.FlushWindowS = l0.DurationS, l0.WarmupS, l0.Config.Window.Seconds()
	res.Gate.Nodes, res.Gate.Shards = 3, *shards
	res.Run.T0UnixMS = l0.T0UnixMS
	res.Run.RecordsSent, res.Run.RecordsAcked = map[string]int64{}, map[string]int64{}
	for _, ls := range loads {
		res.Run.Sent += ls.Sent
		res.Run.Acked += ls.Acked
		res.Run.Refused += ls.Refused
		res.Run.Transport += ls.Transport
		res.Run.Shed += ls.Shed
		res.Run.Retried += ls.Retried
		res.Run.EncodedBytes += ls.EncodedBytes
		res.Run.MaxInFlight = max(res.Run.MaxInFlight, ls.MaxInFlight)
		for k, v := range ls.RecordsSent {
			res.Run.RecordsSent[k] += v
		}
		for k, v := range ls.RecordsAcked {
			res.Run.RecordsAcked[k] += v
		}
		if ls.Kill != nil {
			res.Kill = ls.Kill
		}
	}
	res.buildFacts(filepath.Join(*dir, "BUILD.txt"))

	killAtUS, windowEndUS := int64(math.MaxInt64), int64(math.MaxInt64)
	if res.Kill != nil {
		res.Failure = failureFigures(rows, res.Run.T0UnixMS, res.Kill, int64((res.Gate.WarmupS+res.Gate.SteadyS)*1e6))
		killAtUS, windowEndUS = res.Failure.KillAtUS, res.Failure.WindowEndUS
	}
	a := ackStats(rows, res.Gate.WarmupS, res.Gate.SteadyS, killAtUS, windowEndUS)
	res.Run.SteadyRequests, res.Run.SteadyAcked, res.Run.LateP99MS = a.steadyReq, a.steadyAcked, a.lateP99
	res.Failure.RequestsInWin = a.inWindow
	res.Latency.P50MS, res.Latency.P95MS, res.Latency.P99MS, res.Latency.StrictP95MS = a.p50, a.p95, a.p99, a.strict
	res.Latency.PerMinuteP95MS, res.Latency.PerMinuteStrictP95 = a.perMin, a.perMinStrict
	res.Latency.HealthyP95MS, res.Latency.HealthyStrictP95MS, res.Latency.HealthyRequests = a.healthyP95, a.healthyStrict, a.healthyReq

	files := []string{"BUILD.txt"}
	for s := 0; s < *shards; s++ {
		for _, n := range []string{"acks.csv.gz", "load-summary.json", "generator.json"} {
			files = append(files, fmt.Sprintf("steady/g%d/%s", s, n))
		}
	}
	killMS, endMS := int64(math.MaxInt64), int64(math.MaxInt64)
	if res.Kill != nil {
		killMS, endMS = res.Kill.SentUnixMS, res.Kill.AnsweredUnixMS+failureTailUS/1000
	}
	for n := 1; n <= 3; n++ {
		nd := filepath.Join(*dir, "nodes", fmt.Sprintf("n%d", n))
		var nf NodeFacts
		must(readJSON(filepath.Join(nd, "host.json"), &nf), "node host facts")
		res.Nodes = append(res.Nodes, nf)
		samples, err := readSamples(filepath.Join(nd, "server-series.jsonl"))
		must(err, "node series")
		res.NodeStats = append(res.NodeStats, nodeStats(uint64(n), samples, res.Run.T0UnixMS, res.Gate.WarmupS, res.Gate.SteadyS, killMS, endMS))
		for _, name := range []string{"server-series.jsonl", "events.jsonl", "host.json"} {
			files = append(files, fmt.Sprintf("nodes/n%d/%s", n, name))
		}
	}
	for n := 1; n <= 3; n++ {
		for s := 0; s < *shards; s++ {
			var v VerifyReport
			name := fmt.Sprintf("verify/n%d-g%d.json", n, s)
			if err := readJSON(filepath.Join(*dir, name), &v); err == nil {
				res.Verify = append(res.Verify, v)
				files = append(files, name)
			}
		}
	}
	res.Complete = res.Kill != nil && len(res.Verify) == 3**shards
	res.Files = map[string]string{}
	for _, name := range files {
		if h := fileSHA(filepath.Join(*dir, filepath.FromSlash(name))); h != "" {
			res.Files[name] = h
		}
	}
	raw, _ := json.MarshalIndent(res, "", " ")
	must(os.WriteFile(filepath.Join(*dir, "result.json"), append(raw, '\n'), 0o644), "result")
	sort.Slice(res.Verify, func(i, j int) bool { return res.Verify[i].Node < res.Verify[j].Node })
	fmt.Fprintf(os.Stderr, "distributed: result written %s (healthy strict p95 %.1f ms, p95 %.1f ms, resume %.1f s, complete=%v, generated %s)\n", filepath.Join(*dir, "result.json"), res.Latency.HealthyStrictP95MS, res.Latency.P95MS, res.Failure.ResumeS, res.Complete, time.Now().UTC().Format(time.RFC3339))
}
