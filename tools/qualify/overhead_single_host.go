// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bufio"
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

// The design section 13 single-host gate, pinned in code beside the budgets of workloads.yaml: a matrix row cannot ask for less.
const (
	singleHostFamily   = "soundpost-single-host"
	singleHostOrgs     = 10
	singleHostProjects = 100
	singleHostSeries   = 100_000
	singleHostRate     = 2000
	singleHostSteadyS  = 3600
	singleHostCPUs     = 8
	// D90: the gate's host shape is the server's cgroup v2 scope: exactly 8 effective CPUs, memory.max from 15,000 MiB to 16 GiB (page cache
	// is charged), no swap. The VM's own totals are not the shape.
	singleHostMemFloorBytes = 15_000 << 20
	singleHostMemCeilBytes  = 16 << 30
	// a request that was not durably ACKed counts as this long in the strict p95: the load generator's own client timeout.
	singleHostTimeoutUS = 40_000_000
	// a load generator that starts requests later than this (p99, ms) after their scheduled instant does not hold an open-loop schedule.
	singleHostMaxLateP99MS = 1000.0

	singleHostResultSchema = "soundpost-single-host-result/1"
	singleHostEnv          = "SOUNDPOST_SINGLE_HOST_RESULT"
)

// singleHostResult is the part of the harness's result.json (fixtures/overhead/singlehost, ResultSchema) the runner validates. Every
// number the runner judges is recomputed from the raw files the document names; the document's own figures are only compared.
type singleHostResult struct {
	Schema   string `json:"schema"`
	Harness  string `json:"harness"`
	Complete bool   `json:"complete"`
	Gate     struct {
		Orgs         int     `json:"Orgs"`
		Projects     int     `json:"Projects"`
		Series       int     `json:"Series"`
		Rate         int     `json:"Rate"`
		Seed         uint64  `json:"Seed"`
		SteadyS      float64 `json:"SteadyS"`
		WarmupS      float64 `json:"WarmupS"`
		FlushWindowS float64 `json:"FlushWindowS"`
	} `json:"gate"`
	Server    singleHostFacts `json:"server_host"`
	Generator singleHostFacts `json:"generator_host"`
	Build     struct {
		SourceTreeSHA256 string `json:"source_tree_sha256"`
		VersionJSON      string `json:"soundpost_version_json"`
		SoundpostSHA256  string `json:"soundpost_sha256"`
		HarnessSHA256    string `json:"harness_sha256"`
		Go               string `json:"go"`
	} `json:"build"`
	Files map[string]string `json:"file_sha256"`
	Run   struct {
		Sent           int64            `json:"requests_sent"`
		Acked          int64            `json:"requests_acked"`
		Refused        int64            `json:"requests_refused"`
		Transport      int64            `json:"requests_transport_failed"`
		Shed           int64            `json:"requests_shed_by_generator"`
		RecordsSent    map[string]int64 `json:"records_sent_by_kind"`
		RecordsAcked   map[string]int64 `json:"records_acked_by_kind"`
		EncodedBytes   int64            `json:"encoded_bytes_sent"`
		MaxInFlight    int64            `json:"max_in_flight"`
		LateP99MS      float64          `json:"generator_lateness_p99_ms"`
		SteadyRequests int64            `json:"steady_requests"`
		SteadyAcked    int64            `json:"steady_acked"`
	} `json:"run"`
	Latency struct {
		P50MS          float64   `json:"P50MS"`
		P95MS          float64   `json:"P95MS"`
		P99MS          float64   `json:"P99MS"`
		StrictP95MS    float64   `json:"strict_p95_ms"`
		PerMinuteP95   []float64 `json:"per_minute_p95_ms"`
		PerMinuteStrct []float64 `json:"per_minute_strict_p95_ms"`
	} `json:"latency"`
	RSS struct {
		SteadyMaxRSSKiB int64   `json:"steady_max_rss_kib"`
		PeakHWMKiB      int64   `json:"peak_hwm_kib"`
		Samples         int     `json:"steady_samples"`
		SeriesKiB       []int64 `json:"steady_rss_kib_series"`
	} `json:"rss"`
	Disk struct {
		DataBytesStart int64   `json:"data_bytes_start"`
		DataBytesEnd   int64   `json:"data_bytes_end"`
		IOWriteBytes   uint64  `json:"server_io_write_bytes_steady"`
		BytesPerRecord float64 `json:"BytesPerRecord"`
		CPUBusyPinned  float64 `json:"server_cpu_busy_percent_of_pinned_set"`
		ServerCPUSecs  float64 `json:"server_process_cpu_seconds_steady"`
		LoadMax        float64 `json:"server_host_load1_max"`
		LoadMean       float64 `json:"server_host_load1_mean"`
	} `json:"disk_and_cpu"`
	Events []shEvent    `json:"server_events"`
	Verify []shVerify   `json:"verify"`
	Kill9  *shLoadBrief `json:"kill9_run"`
}

type singleHostFacts struct {
	HostID      string `json:"host_id"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Kernel      string `json:"kernel"`
	LogicalCPUs int    `json:"logical_cpus"`
	MemTotalKiB int64  `json:"mem_total_kib"`
	Gomaxprocs  int    `json:"gomaxprocs"`
	CpusAllowed string `json:"cpus_allowed"`
	DataFS      string `json:"data_dir_filesystem"`
	BlockDevice string `json:"block_device_model"`
	DataOnTmpfs bool   `json:"data_dir_on_tmpfs"`
	// the server's cgroup v2 scope (D90): path and the raw contents of cpuset.cpus.effective, memory.max and memory.swap.max.
	CgroupPath    string `json:"cgroup_path"`
	CgroupCPUs    string `json:"cgroup_cpus_effective"`
	CgroupMemMax  string `json:"cgroup_memory_max"`
	CgroupSwapMax string `json:"cgroup_memory_swap_max"`
}

type shEvent struct {
	TMS       int64  `json:"t_ms"`
	Event     string `json:"event"`
	Mode      string `json:"mode"`
	PIDBefore int    `json:"pid_before"`
	PIDAfter  int    `json:"pid_after"`
	Exit      string `json:"exit"`
	StopMS    int64  `json:"stop_ms"`
	ReadyMS   int64  `json:"ready_ms"`
	Cpus      string `json:"cpus_allowed"`
}

type shKind struct {
	Acked   int64 `json:"acked_records"`
	Checked int64 `json:"checked_records"`
	Found   int64 `json:"found_records"`
	Missing int64 `json:"missing_records"`
}

type shVerify struct {
	Label                string            `json:"label"`
	LedgerBatches        int64             `json:"ledger_batches"`
	LedgerRecords        int64             `json:"ledger_records"`
	ReceiptsChecked      int64             `json:"receipts_checked"`
	ReceiptsMatching     int64             `json:"receipts_matching_the_ack"`
	ReceiptsNotFound     int64             `json:"receipts_not_found"`
	ReceiptsMismatch     int64             `json:"receipts_with_other_hash_or_cursor"`
	ReceiptErrors        int64             `json:"receipt_lookup_errors"`
	MissingAckedBatches  int64             `json:"missing_acked_batches"`
	MissingAckedRecords  int64             `json:"missing_acked_records"`
	Kinds                map[string]shKind `json:"kinds"`
	QueryErrors          []string          `json:"query_errors"`
	TraceSampleEvery     int               `json:"trace_sample_every"`
	RecordsInLostBatches int64             `json:"records_in_batches_without_matching_receipt"`
}

type shLoadBrief struct {
	Acked   int64   `json:"requests_acked"`
	Sent    int64   `json:"requests_sent"`
	Kill9At float64 `json:"kill9_at_s"`
}

// shRow is one request of acks.csv.gz.
type shRow struct {
	startUS, latencyUS, lateUS, records int64
	status                              int
}

// shPercentile is the nearest-rank percentile (p in (0,1]) of a sorted slice, with the harness's tolerance for float rounding.
func shPercentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p*float64(len(sorted)) + 0.999999999)
	rank = min(max(rank, 1), len(sorted))
	return sorted[rank-1]
}

func shSHA(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shReadRows(path string) ([]shRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var rows []shRow
	first := true
	for sc.Scan() {
		if first {
			first = false
			if !strings.HasPrefix(sc.Text(), "start_us,sched_us,latency_us,late_us,status,project,records,bytes") {
				return nil, fmt.Errorf("unexpected rows header")
			}
			continue
		}
		f := strings.Split(sc.Text(), ",")
		if len(f) < 8 {
			return nil, fmt.Errorf("bad row %q", sc.Text())
		}
		var v [8]int64
		for i := range v {
			n, err := strconv.ParseInt(f[i], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("bad row %q", sc.Text())
			}
			v[i] = n
		}
		rows = append(rows, shRow{startUS: v[0], latencyUS: v[2], lateUS: v[3], status: int(v[4]), records: v[6]})
	}
	return rows, sc.Err()
}

type shSample struct {
	TMS     int64   `json:"t_ms"`
	PID     int     `json:"pid"`
	RSSKiB  int64   `json:"rss_kib"`
	HWMKiB  int64   `json:"hwm_kib"`
	DataB   int64   `json:"data_bytes"`
	IOWrite uint64  `json:"io_write_bytes"`
	UTime   uint64  `json:"utime_ticks"`
	STime   uint64  `json:"stime_ticks"`
	Load1   float64 `json:"load1"`
}

func shReadSamples(path string) ([]shSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []shSample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var s shSample
		if err := json.Unmarshal(sc.Bytes(), &s); err != nil {
			return nil, fmt.Errorf("bad sample line")
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// singleHostRecomputed is every figure the runner derives itself from the raw files.
type singleHostRecomputed struct {
	steadyRequests, steadyAcked int64
	offeredRecords              int64
	p50, p95, p99, strict       float64
	perMin, perMinStrict        []float64
	lateP99                     float64
	steadyMaxRSS, peakHWM       int64
	rssSeries                   []int64
	sampleGapMaxS               float64
	samples                     int
}

func shRound(v float64) float64 { return math.Round(v*1e6) / 1e6 }

// shCPUCount counts the CPUs of a cpuset list such as "0-3,8,10-11"; ok is false for anything that is not a well-formed list.
func shCPUCount(list string) (n int, ok bool) {
	list = strings.TrimSpace(list)
	if list == "" {
		return 0, false
	}
	for _, part := range strings.Split(list, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil || a < 0 {
			return 0, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil || b < a {
				return 0, false
			}
		}
		n += b - a + 1
	}
	return n, true
}

// shValidateScope checks the server's cgroup scope against D90 and returns the effective CPU count and the memory.max in bytes; why is
// empty when the scope is the design's host shape.
func shValidateScope(f singleHostFacts) (cpus int, mem int64, why string) {
	if !strings.HasPrefix(f.CgroupPath, "/") || f.CgroupPath == "/" {
		return 0, 0, "no cgroup v2 scope path is recorded (a run on the bare VM is not the gate's host shape)"
	}
	cpus, ok := shCPUCount(f.CgroupCPUs)
	if !ok {
		return 0, 0, fmt.Sprintf("cpuset.cpus.effective %q is not a CPU list", f.CgroupCPUs)
	}
	if cpus != singleHostCPUs {
		return 0, 0, fmt.Sprintf("the scope has %d effective CPUs (cpuset.cpus.effective %s), the design has exactly %d", cpus, f.CgroupCPUs, singleHostCPUs)
	}
	mem, err := strconv.ParseInt(strings.TrimSpace(f.CgroupMemMax), 10, 64)
	if err != nil {
		return 0, 0, fmt.Sprintf("memory.max is %q: the scope has no memory limit", f.CgroupMemMax)
	}
	if mem < singleHostMemFloorBytes || mem > singleHostMemCeilBytes {
		return 0, 0, fmt.Sprintf("memory.max is %d MiB, the design wants 15,000 MiB to 16 GiB", mem>>20)
	}
	if strings.TrimSpace(f.CgroupSwapMax) != "0" {
		return 0, 0, fmt.Sprintf("memory.swap.max is %q: the scope may use swap", f.CgroupSwapMax)
	}
	if f.Gomaxprocs != singleHostCPUs {
		return 0, 0, fmt.Sprintf("GOMAXPROCS is %d, the design has %d", f.Gomaxprocs, singleHostCPUs)
	}
	return cpus, mem, ""
}

// shRecompute derives the steady-window figures from the raw acks and monitor series, with the definitions the harness documents:
// the steady window is [warmup, warmup+steady) of request start times; the ACK latency figures are over durably ACKed requests; the strict
// p95 counts every request that was not ACKed as the client timeout.
func shRecompute(rows []shRow, samples []shSample, t0MS int64, warmupS, steadyS float64) singleHostRecomputed {
	var r singleHostRecomputed
	lo, hi := int64(warmupS*1e6), int64((warmupS+steadyS)*1e6)
	minutes := int(steadyS / 60)
	perMin, perMinStrict := make([][]int64, minutes), make([][]int64, minutes)
	var acked, strict, late []int64
	for _, row := range rows {
		if row.startUS < lo || row.startUS >= hi {
			continue
		}
		r.steadyRequests++
		r.offeredRecords += row.records
		lat := row.latencyUS
		if row.status != 200 {
			lat = singleHostTimeoutUS
		} else {
			r.steadyAcked++
			acked = append(acked, row.latencyUS)
		}
		strict = append(strict, lat)
		late = append(late, row.lateUS)
		if m := int((row.startUS - lo) / 60_000_000); m >= 0 && m < minutes {
			perMinStrict[m] = append(perMinStrict[m], lat)
			if row.status == 200 {
				perMin[m] = append(perMin[m], row.latencyUS)
			}
		}
	}
	sortI := func(v []int64) { sort.Slice(v, func(i, j int) bool { return v[i] < v[j] }) }
	ms := func(us int64) float64 { return shRound(float64(us) / 1000) }
	for _, v := range [][]int64{acked, strict, late} {
		sortI(v)
	}
	r.p50, r.p95, r.p99, r.strict = ms(shPercentile(acked, 0.5)), ms(shPercentile(acked, 0.95)), ms(shPercentile(acked, 0.99)), ms(shPercentile(strict, 0.95))
	r.lateP99 = ms(shPercentile(late, 0.99))
	for m := 0; m < minutes; m++ {
		sortI(perMin[m])
		sortI(perMinStrict[m])
		r.perMin = append(r.perMin, ms(shPercentile(perMin[m], 0.95)))
		r.perMinStrict = append(r.perMinStrict, ms(shPercentile(perMinStrict[m], 0.95)))
	}
	loMS, hiMS := t0MS+int64(warmupS*1000), t0MS+int64((warmupS+steadyS)*1000)
	var prev int64
	for _, s := range samples {
		if s.TMS < loMS || s.TMS > hiMS {
			continue
		}
		r.samples++
		r.rssSeries = append(r.rssSeries, s.RSSKiB)
		r.steadyMaxRSS = max(r.steadyMaxRSS, s.RSSKiB)
		r.peakHWM = max(r.peakHWM, s.HWMKiB)
		if prev != 0 {
			r.sampleGapMaxS = max(r.sampleGapMaxS, float64(s.TMS-prev)/1000)
		}
		prev = s.TMS
	}
	return r
}

func shEqualFloats(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if math.Abs(a[i]-b[i]) > 1e-6 {
			return false
		}
	}
	return true
}

// shGateParams is what the matrix row pins; the design values themselves are constants above, so a row cannot ask for less.
func shGateParams(spec RowSpec) (string, bool) {
	want := map[string]int{"orgs": singleHostOrgs, "projects": singleHostProjects, "series": singleHostSeries, "rate": singleHostRate, "duration": singleHostSteadyS}
	for _, k := range []string{"orgs", "projects", "series", "rate", "duration"} {
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

// singleHostDir resolves where the harness result lives: the environment variable wins over the row's `result` parameter.
func (rc *runCtx) singleHostDir(spec RowSpec) string {
	p := os.Getenv(singleHostEnv)
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

// runOverheadSingleHost judges design section 13's single-host gate (p95 durable ACK < 250 ms, steady RSS < 12 GiB, no loss of ACKed records
// across a process restart) from the result of a REAL one-hour run of the load harness (fixtures/overhead/singlehost) against a real
// `soundpost serve` on another host. The hour is not re-run here: the result is validated (host, build, parameters, hashes of the raw series)
// and every judged number is recomputed from the raw series. A reduced run, a result that does not recompute or one that cannot be tied to
// the gate is never promoted: the row is not exercised and says why. A missed gate is a measured failure.
func runOverheadSingleHost(rc *runCtx, spec RowSpec) Row {
	if why, ok := shGateParams(spec); !ok {
		return notExercised(why)
	}
	dir := rc.singleHostDir(spec)
	if dir == "" {
		return notExercised("no single-host run result: run the procedure of fixtures/overhead/singlehost (server and load generator on two hosts, one hour) and point " + singleHostEnv + " at its result directory; the hour is not run inside qualify")
	}
	for _, b := range []string{"single_host_ack_p95_ms", "single_host_rss_bytes", "single_host_missing_acked_records"} {
		if bud, ok := rc.workloads.Budgets[b]; !ok || bud.Source == "" || bud.Unit == "" {
			return notExercised("workloads.yaml does not pin the design section 13 budget " + b)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "result.json"))
	if err != nil {
		return notExercised("single-host result not readable: " + err.Error())
	}
	var res singleHostResult
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&res); err != nil {
		return notExercised("single-host result refused: not a result document: " + err.Error())
	}
	refuse := func(f string, a ...any) Row {
		return notExercised("single-host result refused: " + fmt.Sprintf(f, a...))
	}
	if res.Schema != singleHostResultSchema || res.Harness != "fixtures/overhead/singlehost" {
		return refuse("schema %q harness %q", res.Schema, res.Harness)
	}

	// raw files: every one named must hash to what the result says.
	for _, name := range []string{"steady/acks.csv.gz", "server/server-series.jsonl", "server/events.jsonl", "server/host.json", "steady/load-summary.json", "BUILD.txt"} {
		want, ok := res.Files[name]
		if !ok {
			return refuse("raw file %s is not bound by a digest", name)
		}
		got, err := shSHA(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || got != want {
			return refuse("raw file %s does not match its digest (tampered or replaced)", name)
		}
	}
	rows, err := shReadRows(filepath.Join(dir, "steady", "acks.csv.gz"))
	if err != nil {
		return refuse("acks: %v", err)
	}
	samples, err := shReadSamples(filepath.Join(dir, "server", "server-series.jsonl"))
	if err != nil {
		return refuse("server series: %v", err)
	}
	var load struct {
		T0UnixMS int64 `json:"t0_unix_ms"`
	}
	loadRaw, _ := os.ReadFile(filepath.Join(dir, "steady", "load-summary.json"))
	if json.Unmarshal(loadRaw, &load) != nil || load.T0UnixMS == 0 {
		return refuse("load summary has no start instant")
	}

	// the figures must recompute from the raw series.
	rec := shRecompute(rows, samples, load.T0UnixMS, res.Gate.WarmupS, res.Gate.SteadyS)
	switch {
	case rec.steadyRequests != res.Run.SteadyRequests || rec.steadyAcked != res.Run.SteadyAcked:
		return refuse("steady request counts do not recompute (%d/%d vs %d/%d)", rec.steadyRequests, rec.steadyAcked, res.Run.SteadyRequests, res.Run.SteadyAcked)
	case math.Abs(rec.p50-res.Latency.P50MS) > 1e-6 || math.Abs(rec.p95-res.Latency.P95MS) > 1e-6 || math.Abs(rec.p99-res.Latency.P99MS) > 1e-6 || math.Abs(rec.strict-res.Latency.StrictP95MS) > 1e-6:
		return refuse("latency percentiles do not recompute (p95 %.3f vs stated %.3f ms)", rec.p95, res.Latency.P95MS)
	case !shEqualFloats(rec.perMin, res.Latency.PerMinuteP95) || !shEqualFloats(rec.perMinStrict, res.Latency.PerMinuteStrct):
		return refuse("the per-minute p95 series does not recompute")
	case rec.steadyMaxRSS != res.RSS.SteadyMaxRSSKiB || rec.peakHWM != res.RSS.PeakHWMKiB || rec.samples != res.RSS.Samples:
		return refuse("RSS figures do not recompute (peak HWM %d vs stated %d KiB)", rec.peakHWM, res.RSS.PeakHWMKiB)
	case math.Abs(rec.lateP99-res.Run.LateP99MS) > 1e-6:
		return refuse("generator lateness does not recompute")
	}
	if res.Run.Acked > res.Run.Sent || res.Run.SteadyAcked > res.Run.SteadyRequests {
		return refuse("more requests ACKed than sent")
	}

	// reduced-run checks: the result is genuine but is not the design workload.
	reduced := func(f string, a ...any) Row { return notExercised("reduced run: " + fmt.Sprintf(f, a...)) }
	g := res.Gate
	switch {
	case g.Orgs != singleHostOrgs || g.Projects != singleHostProjects || g.Series != singleHostSeries || g.Rate != singleHostRate:
		return reduced("%d orgs, %d projects, %d series, %d records/s against the design's %d/%d/%d/%d", g.Orgs, g.Projects, g.Series, g.Rate, singleHostOrgs, singleHostProjects, singleHostSeries, singleHostRate)
	case g.SteadyS < singleHostSteadyS:
		return reduced("steady window %.0f s against the design's %d s (its numbers are kept as evidence and never promoted)", g.SteadyS, singleHostSteadyS)
	case int(g.SteadyS/60) != len(res.Latency.PerMinuteP95):
		return refuse("the per-minute series does not cover the steady window")
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
	if res.Server.HostID == "" || res.Server.HostID == res.Generator.HostID {
		return reduced("the load generator ran on the server host (or its host id is unknown): the design measures a loaded server, not a co-located generator")
	}
	if res.Server.CpusAllowed == "" || res.Server.Kernel == "" || res.Generator.Kernel == "" {
		return refuse("host facts are incomplete")
	}
	if offered := float64(rec.offeredRecords) / g.SteadyS; offered < 0.98*singleHostRate || offered > 1.02*singleHostRate {
		return reduced("the generator offered %.0f records/s in the steady window, not %d", offered, singleHostRate)
	}
	if rec.lateP99 > singleHostMaxLateP99MS {
		return reduced("the generator started requests up to %.0f ms (p99) after their schedule: it did not hold the open-loop rate", rec.lateP99)
	}
	if rec.sampleGapMaxS > 30 || rec.samples < int(g.SteadyS/10)*9/10 {
		return reduced("the server monitor sampled %d times in the steady window (largest gap %.0f s)", rec.samples, rec.sampleGapMaxS)
	}
	if res.Build.SoundpostSHA256 == "" || res.Build.SourceTreeSHA256 == "" || res.Build.VersionJSON == "" {
		return refuse("the result names no soundpost build")
	}
	var ver struct {
		BuildID  string `json:"build_id"`
		Version  string `json:"version"`
		Platform string `json:"platform"`
	}
	if json.Unmarshal([]byte(res.Build.VersionJSON), &ver) != nil || ver.BuildID == "" || ver.BuildID == "unknown" {
		return refuse("the soundpost binary carries no build id")
	}
	if !res.Complete {
		return notExercised("the procedure is incomplete: the restart loss check (graceful restart and kill -9 of the exact server PID, each followed by a read-back) did not both run, so the third gate number is unmeasured")
	}

	// restart proof: the events must show a graceful stop that exited 0 and a SIGKILL of a different PID, each followed by a read-back that
	// covers every ACK known at that point.
	var graceful, kill9 *shEvent
	for i := range res.Events {
		e := &res.Events[i]
		if e.Event == "restart" && e.Mode == "graceful" && graceful == nil {
			graceful = e
		}
		if e.Event == "restart" && e.Mode == "kill9" && kill9 == nil {
			kill9 = e
		}
	}
	switch {
	case graceful == nil || kill9 == nil:
		return refuse("the server events carry no graceful and kill -9 restart")
	case graceful.Exit != "exit status 0" || graceful.PIDBefore == 0 || graceful.PIDAfter == graceful.PIDBefore:
		return refuse("the graceful restart did not end the server process with exit status 0")
	case !strings.Contains(kill9.Exit, "killed") || kill9.PIDBefore == 0 || kill9.PIDAfter == kill9.PIDBefore || kill9.PIDBefore != graceful.PIDAfter:
		return refuse("the kill -9 restart did not kill the process the graceful restart started")
	case len(res.Verify) != 2 || res.Kill9 == nil:
		return refuse("the result carries %d read-back passes, want 2 and the kill -9 run", len(res.Verify))
	}
	steadyAcked := res.Run.Acked
	wantBatches := []int64{steadyAcked, steadyAcked + res.Kill9.Acked}
	var missing, missingBatches, receipts int64
	for i, v := range res.Verify {
		switch {
		case v.LedgerBatches != wantBatches[i] || v.ReceiptsChecked != v.LedgerBatches:
			return refuse("read-back %q covers %d batches (%d receipts looked up), the ACKs known at that point are %d", v.Label, v.LedgerBatches, v.ReceiptsChecked, wantBatches[i])
		case v.ReceiptsMatching+v.ReceiptsNotFound+v.ReceiptsMismatch+v.ReceiptErrors != v.ReceiptsChecked:
			return refuse("read-back %q: receipt outcomes do not add up", v.Label)
		case v.MissingAckedBatches < v.ReceiptsNotFound+v.ReceiptsMismatch+v.ReceiptErrors:
			return refuse("read-back %q: missing batches are fewer than its failed receipt lookups", v.Label)
		}
		missing += v.MissingAckedRecords
		missingBatches += v.MissingAckedBatches
		receipts += v.ReceiptsMatching
	}

	// the judgement
	build := &Build{Family: singleHostFamily, Version: "design-13", OS: "linux", Arch: res.Server.Arch, ID: "soundpost-" + ver.BuildID + "+sha256:" + res.Build.SoundpostSHA256[:16], SHA256: res.Build.SoundpostSHA256, Host: "vm"}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	row := Row{State: StateExercised, Build: build}
	row.Command = &CommandRun{Command: "fixtures/overhead/singlehost procedure: server (pinned) and load generator on two hosts, steady 3600 s, graceful restart + read-back, kill -9 + read-back; validated from " + rc.rel(dir), ExitCode: 0, DurationMS: int64(g.WarmupS+g.SteadyS) * 1000}
	row.Evidence = []string{
		"harness result " + rc.writeEvidence("single-host-result.json", raw) + " (digest " + digest[:16] + ") with raw series acks.csv.gz, server-series.jsonl, events.jsonl bound by sha256",
		fmt.Sprintf("run digest %s, server host %s kernel %s %d vCPU %d MiB; server scope %s: cpuset.cpus.effective %s (%d CPUs), memory.max %s, memory.swap.max %s, GOMAXPROCS %d; generator host %s kernel %s", digest[:12], res.Server.HostID, res.Server.Kernel, res.Server.LogicalCPUs, res.Server.MemTotalKiB/1024, res.Server.CgroupPath, res.Server.CgroupCPUs, scopeCPUs, res.Server.CgroupMemMax, res.Server.CgroupSwapMax, res.Server.Gomaxprocs, res.Generator.HostID, res.Generator.Kernel),
		fmt.Sprintf("soundpost build %s source tree %s", ver.BuildID, res.Build.SourceTreeSHA256[:16]),
		fmt.Sprintf("workload: %d orgs, %d projects, %d active series, seed %d, %.0f s warm-up + %.0f s steady at %d records/s offered (%.0f measured), flush window %.0f s", g.Orgs, g.Projects, g.Series, g.Seed, g.WarmupS, g.SteadyS, g.Rate, float64(rec.offeredRecords)/g.SteadyS, g.FlushWindowS),
	}
	minutes := make([]float64, len(rec.perMin))
	for i := range minutes {
		minutes[i] = float64(i + 1)
	}
	row.Series = []Series{
		{Name: "ack_p95_per_minute", Unit: "ms", Mode: "steady", Values: rec.perMin},
		{Name: "strict_p95_per_minute", Unit: "ms", Mode: "steady", Values: rec.perMinStrict},
		{Name: "server_rss", Unit: "KiB", Mode: "steady", Values: floatsOfInts(rec.rssSeries)},
	}
	if len(rec.rssSeries) == 0 {
		row.Series = row.Series[:2]
	}
	row.Budgets = []BudgetResult{
		rc.budget("single_host_ack_p95_ms", rec.strict, fmt.Sprintf("p95 of durable-ACK latency over every request of the %.0f s steady window, recomputed from %d raw rows; a request that was not durably ACKed counts as the %d s client timeout (ACKed-only p95 %.3f ms)", g.SteadyS, rec.steadyRequests, singleHostTimeoutUS/1_000_000, rec.p95)),
		rc.budget("single_host_rss_bytes", float64(rec.peakHWM)*1024, fmt.Sprintf("peak VmHWM of the server process through the steady window, sampled every 10 s from /proc (max sampled VmRSS %d KiB, %d samples)", rec.steadyMaxRSS, rec.samples)),
		rc.budget("single_host_missing_acked_records", float64(missing), fmt.Sprintf("ACKed records not read back after a graceful restart and after a kill -9 (%d ACKed batches read back by receipt, %d batches without a matching receipt; metrics, logs and sampled traces also read back by record)", receipts, missingBatches)),
	}
	row.Outcome = OutcomePassed
	for _, b := range row.Budgets {
		if !b.Within {
			row.Outcome = OutcomeFailed
		}
	}
	for _, name := range []string{"ack_p50_ms", "ack_p95_ms", "ack_p99_ms", "steady_requests", "steady_acked", "refused_total", "transport_failed_total", "shed_by_generator_total", "max_in_flight", "encoded_bytes_sent", "data_bytes_per_acked_record", "server_cpu_busy_percent_of_pinned_set"} {
		var v float64
		switch name {
		case "ack_p50_ms":
			v = rec.p50
		case "ack_p95_ms":
			v = rec.p95
		case "ack_p99_ms":
			v = rec.p99
		case "steady_requests":
			v = float64(rec.steadyRequests)
		case "steady_acked":
			v = float64(rec.steadyAcked)
		case "refused_total":
			v = float64(res.Run.Refused)
		case "transport_failed_total":
			v = float64(res.Run.Transport)
		case "shed_by_generator_total":
			v = float64(res.Run.Shed)
		case "max_in_flight":
			v = float64(res.Run.MaxInFlight)
		case "encoded_bytes_sent":
			v = float64(res.Run.EncodedBytes)
		case "data_bytes_per_acked_record":
			v = res.Disk.BytesPerRecord
		case "server_cpu_busy_percent_of_pinned_set":
			v = res.Disk.CPUBusyPinned
		}
		val := v
		row.Readings = append(row.Readings, Reading{Name: name, Availability: AvailAvailable, Value: &val})
	}
	row.Loss = fmt.Sprintf("steady window: %d requests, %d durably ACKed, %d refused, %d transport failures, %d shed by the generator; after the graceful restart %d of %d ACKed batches matched their receipt, after kill -9 %d of %d; %d ACKed records missing",
		rec.steadyRequests, rec.steadyAcked, res.Run.Refused, res.Run.Transport, res.Run.Shed, res.Verify[0].ReceiptsMatching, res.Verify[0].ReceiptsChecked, res.Verify[1].ReceiptsMatching, res.Verify[1].ReceiptsChecked, missing)
	row.Limits = []string{
		fmt.Sprintf("host shape is the server's cgroup v2 scope (D90), not the VM totals: scope %s with %d CPUs effective (cpuset %s, GOMAXPROCS %d) and memory.max %d MiB, memory.swap.max %s, on a VM of %d vCPUs / %d MiB; page cache is charged to the scope", res.Server.CgroupPath, scopeCPUs, res.Server.CgroupCPUs, res.Server.Gomaxprocs, scopeMem>>20, res.Server.CgroupSwapMax, res.Server.LogicalCPUs, res.Server.MemTotalKiB/1024),
		fmt.Sprintf("both hosts are virtual machines on a virtual disk (%q); the data directory's filesystem is %s: a physical SSD was not measured and this says nothing about power-loss durability", res.Server.BlockDevice, res.Server.DataFS),
		"one host, one run of one hour: no repetition, no confidence interval",
		fmt.Sprintf("workload shape is the harness's own: one SDK source per project, records grouped per route slot into batches (the product requires one slot per batch) and flushed every %.0f s per source (the SDK's own export cadence is about 100 ms, which makes smaller batches); %.0f batches/s offered on average", g.FlushWindowS, float64(res.Run.Sent)/(g.WarmupS+g.SteadyS)),
		"metric cardinality is 1,000 active series per project (100,000 in all), every series written in turn within about 83 s",
		"the restart checks run after the hour (graceful) and during a separate kill -9 run, not inside the measured hour, so they do not disturb the steady-state p95",
		"errors and job attempts have no read route by record id before background grouping: they are verified through their ACKed batch receipts only; metrics and logs are read back by record, spans by sampled trace",
		"the web UI is not embedded in the soundpost binary used (built without the webembed tag); it is not on the ingest path",
		"RSS is the process's own VmRSS/VmHWM; page cache is not included",
	}
	if rec.lateP99 > 50 {
		row.Limits = append(row.Limits, fmt.Sprintf("the load generator started requests up to %.0f ms (p99) after their scheduled instant; latency is measured from the actual start of each request", rec.lateP99))
	}
	return row
}

func floatsOfInts(in []int64) []float64 {
	out := make([]float64, len(in))
	for i, v := range in {
		out[i] = float64(v)
	}
	return out
}
