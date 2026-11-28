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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ResultSchema identifies result.json; tools/qualify's overhead_single_host runner validates exactly this document.
const ResultSchema = "soundpost-single-host-result/1"

// timeoutLatencyUS is what a request that was not ACKed counts as in the strict latency figure: the client's own timeout.
const timeoutLatencyUS = 40_000_000

// Result is the document the qualify runner validates. Every number in it is recomputed by the runner from the raw files it names.
type Result struct {
	Schema   string `json:"schema"`
	Harness  string `json:"harness"`
	Complete bool   `json:"complete"` // the whole procedure ran: steady run, graceful restart + verify, kill -9 run + restart + verify
	Gate     struct {
		Orgs, Projects, Series, Rate int
		Seed                         uint64
		SteadyS, WarmupS             float64
		FlushWindowS                 float64
	} `json:"gate"`
	Server    HostFacts `json:"server_host"`
	Generator HostFacts `json:"generator_host"`
	Build     struct {
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
	} `json:"latency"`
	RSS struct {
		SteadyMaxRSSKiB int64   `json:"steady_max_rss_kib"`
		PeakHWMKiB      int64   `json:"peak_hwm_kib"`
		Samples         int     `json:"steady_samples"`
		SeriesKiB       []int64 `json:"steady_rss_kib_series"`
	} `json:"rss"`
	Disk struct {
		DataBytesStart  int64  `json:"data_bytes_start"`
		DataBytesEnd    int64  `json:"data_bytes_end"`
		IOWriteBytes    uint64 `json:"server_io_write_bytes_steady"`
		BytesPerRecord  float64
		CPUBusyPinned   float64 `json:"server_cpu_busy_percent_of_pinned_set"`
		ServerCPUSecs   float64 `json:"server_process_cpu_seconds_steady"`
		LoadAverageMax  float64 `json:"server_host_load1_max"`
		LoadAverageMean float64 `json:"server_host_load1_mean"`
	} `json:"disk_and_cpu"`
	Events   []Event        `json:"server_events"`
	Verify   []VerifyReport `json:"verify"`
	Kill9Run *LoadSummary   `json:"kill9_run,omitempty"`
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

// buildFacts parses BUILD.txt written by build.sh. The binaries are the `sha256sum` lines of soundpost and singlehost, in whichever
// directory they were built (bin, or one directory per candidate).
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
		case len(f) == 2 && len(f[0]) == sha256.Size*2 && filepath.Base(f[1]) == "singlehost":
			r.Build.HarnessSHA256 = f[0]
		case strings.HasPrefix(l, "go version"):
			r.Build.Go = l
		}
	}
}

// ackStats computes the latency figures of the steady window from the raw rows. The same definitions are re-implemented by the runner.
func ackStats(rows []AckRow, warmupS, steadyS float64) (res Result, lateP99 float64) {
	lo, hi := int64(warmupS*1e6), int64((warmupS+steadyS)*1e6)
	var acked, strict, late []int64
	minutes := int(steadyS / 60)
	perMin := make([][]int64, minutes)
	perMinStrict := make([][]int64, minutes)
	for _, r := range rows {
		if r.StartUS < lo || r.StartUS >= hi {
			continue
		}
		res.Run.SteadyRequests++
		lat := r.LatencyUS
		if r.Status != 200 {
			lat = timeoutLatencyUS
		} else {
			res.Run.SteadyAcked++
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
	}
	sortI := func(v []int64) { sort.Slice(v, func(i, j int) bool { return v[i] < v[j] }) }
	for _, v := range [][]int64{acked, strict, late} {
		sortI(v)
	}
	ms := func(us int64) float64 { return float64(us) / 1000 }
	res.Latency.P50MS, res.Latency.P95MS, res.Latency.P99MS = ms(percentile(acked, 0.5)), ms(percentile(acked, 0.95)), ms(percentile(acked, 0.99))
	res.Latency.StrictP95MS = ms(percentile(strict, 0.95))
	for m := 0; m < minutes; m++ {
		sortI(perMin[m])
		sortI(perMinStrict[m])
		res.Latency.PerMinuteP95MS = append(res.Latency.PerMinuteP95MS, ms(percentile(perMin[m], 0.95)))
		res.Latency.PerMinuteStrictP95 = append(res.Latency.PerMinuteStrictP95, ms(percentile(perMinStrict[m], 0.95)))
	}
	return res, ms(percentile(late, 0.99))
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

func readEvents(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			return nil, fmt.Errorf("bad event line")
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// runSummarize folds the raw files of one complete procedure into result.json. Layout of --dir:
//
//	steady/{acks.csv.gz,load-summary.json,generator.json,ledger.bin}   the one-hour run (ledger.bin stays on the generator host)
//	kill9/{acks.csv.gz,load-summary.json}                              the run during which the server is killed
//	server/{server-series.jsonl,events.jsonl,host.json}                the server host monitor
//	verify-graceful.json, verify-kill9.json                            the two read-back passes
//	BUILD.txt                                                          build.sh output
func runSummarize(args []string) {
	f := flag.NewFlagSet("summarize", flag.ExitOnError)
	dir := f.String("dir", "", "evidence directory (layout in the command's documentation)")
	f.Parse(args)
	if *dir == "" {
		fatalf("--dir is required")
	}
	var load LoadSummary
	must(readJSON(filepath.Join(*dir, "steady", "load-summary.json"), &load), "steady load summary")
	rows, err := readRows(filepath.Join(*dir, "steady", "acks.csv.gz"))
	must(err, "steady rows")
	res, lateP99 := ackStats(rows, load.WarmupS, load.DurationS)
	res.Schema, res.Harness = ResultSchema, "fixtures/overhead/singlehost"
	res.Gate.Orgs, res.Gate.Projects, res.Gate.Series, res.Gate.Rate, res.Gate.Seed = load.Config.Orgs, load.Config.Projects, load.Config.Series, load.Config.Rate, load.Config.Seed
	res.Gate.SteadyS, res.Gate.WarmupS, res.Gate.FlushWindowS = load.DurationS, load.WarmupS, load.Config.Window.Seconds()
	must(readJSON(filepath.Join(*dir, "server", "host.json"), &res.Server), "server host facts")
	must(readJSON(filepath.Join(*dir, "steady", "generator.json"), &res.Generator), "generator host facts")
	res.buildFacts(filepath.Join(*dir, "BUILD.txt"))
	res.Run.T0UnixMS, res.Run.Sent, res.Run.Acked, res.Run.Refused, res.Run.Transport, res.Run.Shed = load.T0UnixMS, load.Sent, load.Acked, load.Refused, load.Transport, load.Shed
	res.Run.RecordsSent, res.Run.RecordsAcked, res.Run.EncodedBytes, res.Run.MaxInFlight, res.Run.LateP99MS = load.RecordsSent, load.RecordsAcked, load.EncodedBytes, load.MaxInFlight, lateP99

	samples, err := readSamples(filepath.Join(*dir, "server", "server-series.jsonl"))
	must(err, "server series")
	loMS, hiMS := load.T0UnixMS+int64(load.WarmupS*1000), load.T0UnixMS+int64((load.WarmupS+load.DurationS)*1000)
	var firstData, lastData int64
	var firstIO, lastIO, firstU, lastU uint64
	var ticks, pinnedBusy, pinnedTotal float64
	var firstBusy, firstTotal []uint64
	var loadSum float64
	loadN := 0
	for _, s := range samples {
		if s.TMS < loMS || s.TMS > hiMS {
			continue
		}
		res.RSS.Samples++
		res.RSS.SeriesKiB = append(res.RSS.SeriesKiB, s.RSSKiB)
		res.RSS.SteadyMaxRSSKiB = max(res.RSS.SteadyMaxRSSKiB, s.RSSKiB)
		res.RSS.PeakHWMKiB = max(res.RSS.PeakHWMKiB, s.HWMKiB)
		if s.DataBytes > 0 {
			if firstData == 0 {
				firstData = s.DataBytes
			}
			lastData = s.DataBytes
		}
		if firstIO == 0 {
			firstIO, firstU = s.IOWrite, s.UTime+s.STime
			firstBusy, firstTotal = s.CPUBusy, s.CPUTotal
		}
		lastIO, lastU = s.IOWrite, s.UTime+s.STime
		if len(s.CPUBusy) >= 4 && len(firstBusy) >= 4 {
			pinnedBusy, pinnedTotal = 0, 0
			for c := 0; c < 4; c++ {
				pinnedBusy += float64(s.CPUBusy[c] - firstBusy[c])
				pinnedTotal += float64(s.CPUTotal[c] - firstTotal[c])
			}
		}
		res.Disk.LoadAverageMax = max(res.Disk.LoadAverageMax, s.Load1)
		loadSum += s.Load1
		loadN++
		ticks++
	}
	res.Disk.DataBytesStart, res.Disk.DataBytesEnd = firstData, lastData
	if lastIO >= firstIO {
		res.Disk.IOWriteBytes = lastIO - firstIO
	}
	res.Disk.ServerCPUSecs = float64(lastU-firstU) / 100 // USER_HZ = 100
	if pinnedTotal > 0 {
		res.Disk.CPUBusyPinned = 100 * pinnedBusy / pinnedTotal
	}
	if loadN > 0 {
		res.Disk.LoadAverageMean = loadSum / float64(loadN)
	}
	var recs int64
	for _, n := range load.RecordsAcked {
		recs += n
	}
	if recs > 0 {
		res.Disk.BytesPerRecord = float64(res.Disk.DataBytesEnd-res.Disk.DataBytesStart) / float64(recs)
	}
	res.Events, err = readEvents(filepath.Join(*dir, "server", "events.jsonl"))
	must(err, "events")

	for _, name := range []string{"verify-graceful.json", "verify-kill9.json"} {
		var v VerifyReport
		if err := readJSON(filepath.Join(*dir, name), &v); err == nil {
			res.Verify = append(res.Verify, v)
		}
	}
	var k9 LoadSummary
	if err := readJSON(filepath.Join(*dir, "kill9", "load-summary.json"), &k9); err == nil {
		res.Kill9Run = &k9
	}
	graceful, kill9 := false, false
	for _, e := range res.Events {
		graceful = graceful || e.Event == "restart" && e.Mode == "graceful" && strings.HasSuffix(e.Exit, "status 0")
		kill9 = kill9 || e.Event == "restart" && e.Mode == "kill9"
	}
	res.Complete = graceful && kill9 && len(res.Verify) == 2 && res.Kill9Run != nil

	res.Files = map[string]string{}
	for _, name := range []string{"steady/acks.csv.gz", "steady/load-summary.json", "steady/generator.json", "kill9/acks.csv.gz", "kill9/load-summary.json", "server/server-series.jsonl", "server/events.jsonl", "server/host.json", "verify-graceful.json", "verify-kill9.json", "BUILD.txt"} {
		if h := fileSHA(filepath.Join(*dir, name)); h != "" {
			res.Files[name] = h
		}
	}
	raw, _ := json.MarshalIndent(res, "", " ")
	must(os.WriteFile(filepath.Join(*dir, "result.json"), append(raw, '\n'), 0o644), "result")
	fmt.Fprintf(os.Stderr, "singlehost: result written %s (steady p95 %.1f ms, strict p95 %.1f ms, peak HWM %d KiB, complete=%v, generated %s)\n", filepath.Join(*dir, "result.json"), res.Latency.P95MS, res.Latency.StrictP95MS, res.RSS.PeakHWMKiB, res.Complete, time.Now().UTC().Format(time.RFC3339))
	for _, v := range res.Verify {
		fmt.Fprintf(os.Stderr, "singlehost: verify %s: %s\n", v.Label, v.summaryLine())
	}
}
