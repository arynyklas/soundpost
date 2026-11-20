// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// shFixture describes a synthetic single-host result directory. The numbers are computed here by the plain definition (sort, nearest rank),
// independently of the runner's own recomputation.
type shFixture struct {
	steadyS, warmupS int
	latencyUS        func(i int) int64 // latency of the i-th request
	failEvery        int               // every Nth request is not ACKed (transport failure)
	hwmKiB           int64
	missing          int64
	cpus             int
	memKiB           int64
	tmpfs            bool
	sameHost         bool
	rate             int
	skipVerify       bool
}

func defaultFixture() shFixture {
	return shFixture{steadyS: 3600, warmupS: 60, latencyUS: func(i int) int64 { return 40_000 + int64(i%100)*1000 }, hwmKiB: 6 << 20, cpus: 8, memKiB: 15_996 * 1024, rate: 2000}
}

func nearestRank(v []int64, p float64) int64 {
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s) == 0 {
		return 0
	}
	return s[int(math.Ceil(p*float64(len(s))-1e-9))-1]
}

func shDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func shWriteGz(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	f.Close()
}

// writeSingleHostResult writes a complete result directory (raw series, verification passes, events, host facts, result.json).
func writeSingleHostResult(t *testing.T, fx shFixture) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"steady", "kill9", "server"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	const t0 = int64(1_800_000_000_000)
	// one request every 100 ms carrying rate/10 records: the offered load is exactly the rate.
	total := (fx.steadyS + fx.warmupS) * 10
	var rows strings.Builder
	rows.WriteString("start_us,sched_us,latency_us,late_us,status,project,records,bytes,err\n")
	var steadyAll, steadyAcked []int64
	minutes := fx.steadyS / 60
	perMin, perMinStrict := make([][]int64, minutes), make([][]int64, minutes)
	var sent, ackedTotal, steadyReq, steadyAck int64
	for i := 0; i < total; i++ {
		start := int64(i) * 100_000
		lat, status := fx.latencyUS(i), 200
		if fx.failEvery > 0 && i%fx.failEvery == 0 {
			status = 0
		}
		errName := ""
		if status != 200 {
			errName = "transport"
		}
		fmt.Fprintf(&rows, "%d,%d,%d,%d,%d,%d,%d,%d,%s\n", start, start, lat, 0, status, i%100, fx.rate/10, 500, errName)
		sent++
		if status == 200 {
			ackedTotal++
		}
		if start >= int64(fx.warmupS)*1_000_000 && start < int64(fx.warmupS+fx.steadyS)*1_000_000 {
			steadyReq++
			eff := lat
			if status != 200 {
				eff = 40_000_000
			} else {
				steadyAck++
				steadyAcked = append(steadyAcked, lat)
			}
			steadyAll = append(steadyAll, eff)
			m := int((start - int64(fx.warmupS)*1_000_000) / 60_000_000)
			perMinStrict[m] = append(perMinStrict[m], eff)
			if status == 200 {
				perMin[m] = append(perMin[m], lat)
			}
		}
	}
	shWriteGz(t, filepath.Join(dir, "steady", "acks.csv.gz"), rows.String())
	ms := func(us int64) float64 { return float64(us) / 1000 }

	var series strings.Builder
	var samples int64
	var maxRSS, peak int64
	for ts := t0; ts < t0+int64(fx.warmupS+fx.steadyS)*1000; ts += 10_000 {
		rss := fx.hwmKiB - 100_000 + (ts/10_000)%50_000
		hwm := fx.hwmKiB
		fmt.Fprintf(&series, `{"t_ms":%d,"pid":101,"rss_kib":%d,"hwm_kib":%d,"io_write_bytes":%d,"utime_ticks":%d,"stime_ticks":1,"load1":1.5}`+"\n", ts, rss, hwm, (ts-t0)*10, (ts-t0)/10)
		if ts >= t0+int64(fx.warmupS)*1000 && ts <= t0+int64(fx.warmupS+fx.steadyS)*1000 {
			samples++
			maxRSS, peak = max(maxRSS, rss), max(peak, hwm)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "server", "server-series.jsonl"), []byte(series.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	events := `{"t_ms":1,"event":"start","pid_after":100}` + "\n" +
		`{"t_ms":2,"event":"restart","mode":"graceful","pid_before":100,"pid_after":101,"exit":"exit status 0"}` + "\n" +
		`{"t_ms":3,"event":"restart","mode":"kill9","pid_before":101,"pid_after":102,"exit":"signal: killed"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "server", "events.jsonl"), []byte(events), 0o644); err != nil {
		t.Fatal(err)
	}
	serverID, genID := "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
	if fx.sameHost {
		genID = serverID
	}
	facts := func(id string, cpus int, mem int64, tmpfs bool, allowed string) map[string]any {
		return map[string]any{"host_id": id, "os": "linux", "arch": "amd64", "kernel": "6.12.74", "logical_cpus": cpus, "mem_total_kib": mem, "gomaxprocs": 4, "cpus_allowed": allowed, "data_dir_filesystem": "ext2/ext3", "block_device_model": "QEMU HARDDISK", "data_dir_on_tmpfs": tmpfs}
	}
	server := facts(serverID, fx.cpus, fx.memKiB, fx.tmpfs, "0-3")
	gen := facts(genID, 8, fx.memKiB, false, "0-7")
	writeJSON := func(path string, v any) {
		raw, _ := json.MarshalIndent(v, "", " ")
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeJSON(filepath.Join(dir, "server", "host.json"), server)
	writeJSON(filepath.Join(dir, "steady", "load-summary.json"), map[string]any{"t0_unix_ms": t0})
	build := "source_tree_sha256=" + strings.Repeat("ab", 32) + "\n" + `{"version":"0.0.0-overhead","commit":"none","build_id":"src-0123456789abcdef","platform":"linux/amd64"}` + "\n" + strings.Repeat("cd", 32) + "  /home/x/bin/soundpost\n"
	if err := os.WriteFile(filepath.Join(dir, "BUILD.txt"), []byte(build), 0o644); err != nil {
		t.Fatal(err)
	}

	files := map[string]string{}
	for _, name := range []string{"steady/acks.csv.gz", "server/server-series.jsonl", "server/events.jsonl", "server/host.json", "steady/load-summary.json", "BUILD.txt"} {
		files[name] = shDigest(t, filepath.Join(dir, filepath.FromSlash(name)))
	}
	perMinMS, perMinStrictMS := []float64{}, []float64{}
	for m := 0; m < minutes; m++ {
		perMinMS = append(perMinMS, ms(nearestRank(perMin[m], 0.95)))
		perMinStrictMS = append(perMinStrictMS, ms(nearestRank(perMinStrict[m], 0.95)))
	}
	ver := func(label string, batches int64, missing int64) map[string]any {
		return map[string]any{"label": label, "ledger_batches": batches, "receipts_checked": batches, "receipts_not_found": missing, "receipts_matching_the_ack": batches - missing,
			"missing_acked_batches": missing, "missing_acked_records": missing, "kinds": map[string]any{}}
	}
	kill9Acked := int64(500)
	verify := []any{ver("graceful-restart", ackedTotal, 0), ver("kill9-restart", ackedTotal+kill9Acked, fx.missing)}
	if fx.skipVerify {
		verify = nil
	}
	events3 := []any{map[string]any{"event": "start", "pid_after": 100},
		map[string]any{"event": "restart", "mode": "graceful", "pid_before": 100, "pid_after": 101, "exit": "exit status 0"},
		map[string]any{"event": "restart", "mode": "kill9", "pid_before": 101, "pid_after": 102, "exit": "signal: killed"}}
	res := map[string]any{}
	res["schema"], res["harness"], res["complete"] = singleHostResultSchema, "fixtures/overhead/singlehost", !fx.skipVerify
	res["gate"] = map[string]any{"Orgs": 10, "Projects": 100, "Series": 100000, "Rate": fx.rate, "Seed": 20261113, "SteadyS": fx.steadyS, "WarmupS": fx.warmupS, "FlushWindowS": 10}
	res["server_host"], res["generator_host"], res["file_sha256"] = server, gen, files
	res["build"] = map[string]any{"source_tree_sha256": strings.Repeat("ab", 32), "soundpost_version_json": `{"version":"0.0.0-overhead","commit":"none","build_id":"src-0123456789abcdef","platform":"linux/amd64"}`,
		"soundpost_sha256": strings.Repeat("cd", 32), "harness_sha256": strings.Repeat("ef", 32), "go": "go version go1.27.3 linux/amd64"}
	res["run"] = map[string]any{"requests_sent": sent, "requests_acked": ackedTotal, "requests_refused": 0, "requests_transport_failed": sent - ackedTotal, "requests_shed_by_generator": 0,
		"records_sent_by_kind": map[string]any{"metric": 1}, "records_acked_by_kind": map[string]any{"metric": 1}, "encoded_bytes_sent": 1, "max_in_flight": 40,
		"generator_lateness_p99_ms": 0.0, "steady_requests": steadyReq, "steady_acked": steadyAck}
	res["latency"] = map[string]any{"P50MS": ms(nearestRank(steadyAcked, 0.5)), "P95MS": ms(nearestRank(steadyAcked, 0.95)), "P99MS": ms(nearestRank(steadyAcked, 0.99)),
		"strict_p95_ms": ms(nearestRank(steadyAll, 0.95)), "per_minute_p95_ms": perMinMS, "per_minute_strict_p95_ms": perMinStrictMS}
	res["rss"] = map[string]any{"steady_max_rss_kib": maxRSS, "peak_hwm_kib": peak, "steady_samples": samples}
	res["disk_and_cpu"] = map[string]any{"data_bytes_start": 1, "data_bytes_end": 2, "BytesPerRecord": 3.5}
	res["server_events"], res["verify"] = events3, verify
	res["kill9_run"] = map[string]any{"requests_acked": kill9Acked, "requests_sent": kill9Acked, "kill9_at_s": 60}
	writeJSON(filepath.Join(dir, "result.json"), res)
	return dir
}

func shGateSpec() RowSpec {
	return RowSpec{ID: "overhead.single_host.gate", Suite: SuiteOverhead, Required: true, Runner: "overhead_single_host",
		Subject: &Subject{Family: "soundpost-single-host", Version: "design-13", OS: "any", Arch: "any"},
		Params:  map[string]string{"orgs": "10", "projects": "100", "series": "100000", "rate": "2000", "duration": "3600", "seed": "20261113"}}
}

func shRun(t *testing.T, dir string, spec RowSpec) Row {
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
	t.Setenv(singleHostEnv, dir)
	row := runOverheadSingleHost(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, spec.Required, *spec.Subject
	if err := ValidateRow(row); err != nil {
		t.Fatalf("runner produced an invalid row: %v\n%+v", err, row)
	}
	return row
}

func budgetOf(t *testing.T, row Row, name string) BudgetResult {
	t.Helper()
	for _, b := range row.Budgets {
		if b.Name == name {
			return b
		}
	}
	t.Fatalf("row has no budget %s: %+v", name, row.Budgets)
	return BudgetResult{}
}

func TestSingleHostFullRunWithinTheGatePasses(t *testing.T) {
	row := shRun(t, writeSingleHostResult(t, defaultFixture()), shGateSpec())
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("a full run within the gate must pass: state %s outcome %s reason %q failures %v", row.State, row.Outcome, row.Reason, row.Failures)
	}
	if b := budgetOf(t, row, "single_host_ack_p95_ms"); b.Limit != 250 || b.Observed >= 250 || !b.Within {
		t.Errorf("ack budget %+v", b)
	}
	if b := budgetOf(t, row, "single_host_rss_bytes"); b.Limit != 12<<30 || !b.Within || b.Observed != float64(6<<20)*1024 {
		t.Errorf("rss budget %+v", b)
	}
	if b := budgetOf(t, row, "single_host_missing_acked_records"); b.Limit != 0 || b.Observed != 0 || !b.Within {
		t.Errorf("loss budget %+v", b)
	}
	if row.Build == nil || row.Build.Family != "soundpost-single-host" || !strings.Contains(row.Build.ID, "src-0123456789abcdef") || len(row.Evidence) == 0 {
		t.Errorf("row is not bound to the build and the run: %+v", row.Build)
	}
	limits := strings.Join(row.Limits, "\n")
	for _, want := range []string{"pinned to CPUs 0-3", "virtual", "one host"} {
		if !strings.Contains(limits, want) {
			t.Errorf("limits do not say %q: %s", want, limits)
		}
	}
	if len(row.Series) < 3 || len(row.Series[0].Values) != 60 {
		t.Errorf("raw series missing: %d series", len(row.Series))
	}
}

func TestSingleHostEachMissedGateNumberIsAMeasuredFailure(t *testing.T) {
	cases := map[string]struct {
		mutate func(*shFixture)
		budget string
	}{
		"p95 ACK over 250 ms":                {func(f *shFixture) { f.latencyUS = func(i int) int64 { return 300_000 } }, "single_host_ack_p95_ms"},
		"RSS over 12 GiB":                    {func(f *shFixture) { f.hwmKiB = 13 << 20 }, "single_host_rss_bytes"},
		"one ACKed record lost":              {func(f *shFixture) { f.missing = 1 }, "single_host_missing_acked_records"},
		"fast ACKs but 10 percent not ACKed": {func(f *shFixture) { f.failEvery = 10 }, "single_host_ack_p95_ms"},
	}
	for name, c := range cases {
		fx := defaultFixture()
		c.mutate(&fx)
		row := shRun(t, writeSingleHostResult(t, fx), shGateSpec())
		if row.State != StateExercised || row.Outcome != OutcomeFailed {
			t.Errorf("%s: want a measured failure, got state %s outcome %s reason %q", name, row.State, row.Outcome, row.Reason)
			continue
		}
		if b := budgetOf(t, row, c.budget); b.Within {
			t.Errorf("%s: budget %s is within: %+v", name, c.budget, b)
		}
		if len(row.Failures) != 0 {
			t.Errorf("%s: a budget miss carries no failure text (it is derived from the budget): %v", name, row.Failures)
		}
	}
}

func TestSingleHostReducedRunIsNeverExercised(t *testing.T) {
	cases := map[string]func(*shFixture){
		"ten-minute steady window": func(f *shFixture) { f.steadyS = 600 },
		"4 vCPU server host":       func(f *shFixture) { f.cpus = 4 },
		"data directory on tmpfs":  func(f *shFixture) { f.tmpfs = true },
		"generator on server host": func(f *shFixture) { f.sameHost = true },
		"half the record rate":     func(f *shFixture) { f.rate = 1000 },
		"small host memory":        func(f *shFixture) { f.memKiB = 8 << 20 },
	}
	for name, mutate := range cases {
		fx := defaultFixture()
		mutate(&fx)
		row := shRun(t, writeSingleHostResult(t, fx), shGateSpec())
		if row.State != StateNotExercised || !strings.Contains(row.Reason, "reduced run") || len(row.Budgets) != 0 {
			t.Errorf("%s: must be not_exercised with 'reduced run', got state %s reason %q budgets %v", name, row.State, row.Reason, row.Budgets)
		}
	}
}

func TestSingleHostTamperedResultIsRefused(t *testing.T) {
	failing := defaultFixture()
	failing.latencyUS = func(i int) int64 { return 300_000 }

	// the stated p95 is lowered while the raw rows still say 300 ms
	dir := writeSingleHostResult(t, failing)
	raw, _ := os.ReadFile(filepath.Join(dir, "result.json"))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["latency"].(map[string]any)["P95MS"] = 100.0
	doc["latency"].(map[string]any)["strict_p95_ms"] = 100.0
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(filepath.Join(dir, "result.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
	row := shRun(t, dir, shGateSpec())
	if row.State != StateNotExercised || !strings.Contains(row.Reason, "refused") || !strings.Contains(row.Reason, "recompute") {
		t.Errorf("lowered p95: %s %q", row.State, row.Reason)
	}

	// a raw row is edited after the digests were taken
	dir = writeSingleHostResult(t, failing)
	shWriteGz(t, filepath.Join(dir, "steady", "acks.csv.gz"), "start_us,sched_us,latency_us,late_us,status,project,records,bytes,err\n0,0,1000,0,200,0,200,500,\n")
	if row := shRun(t, dir, shGateSpec()); row.State != StateNotExercised || !strings.Contains(row.Reason, "digest") {
		t.Errorf("replaced acks: %s %q", row.State, row.Reason)
	}

	// the RSS series is edited
	dir = writeSingleHostResult(t, defaultFixture())
	if err := os.WriteFile(filepath.Join(dir, "server", "server-series.jsonl"), []byte(`{"t_ms":1800000060000,"rss_kib":1,"hwm_kib":1}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if row := shRun(t, dir, shGateSpec()); row.State != StateNotExercised || !strings.Contains(row.Reason, "digest") {
		t.Errorf("replaced RSS series: %s %q", row.State, row.Reason)
	}

	// the stated number of missing records is not the verification pass's
	dir = writeSingleHostResult(t, defaultFixture())
	raw, _ = os.ReadFile(filepath.Join(dir, "result.json"))
	_ = json.Unmarshal(raw, &doc)
	doc["verify"].([]any)[1].(map[string]any)["receipts_checked"] = 3
	out, _ = json.Marshal(doc)
	_ = os.WriteFile(filepath.Join(dir, "result.json"), out, 0o644)
	if row := shRun(t, dir, shGateSpec()); row.State != StateNotExercised || !strings.Contains(row.Reason, "refused") {
		t.Errorf("read-back that does not cover the ACKs: %s %q", row.State, row.Reason)
	}
}

func TestSingleHostWithoutResultOrRestartCheckIsNotExercised(t *testing.T) {
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(singleHostEnv, "")
	rc := &runCtx{root: t.TempDir(), reportDir: t.TempDir(), workloads: w}
	row := runOverheadSingleHost(rc, shGateSpec())
	if row.State != StateNotExercised || !strings.Contains(row.Reason, singleHostEnv) {
		t.Errorf("missing result: %s %q", row.State, row.Reason)
	}
	missing := shGateSpec()
	missing.Params["result"] = filepath.Join(t.TempDir(), "absent")
	if row := runOverheadSingleHost(rc, missing); row.State != StateNotExercised {
		t.Errorf("unreadable result: %s", row.State)
	}

	fx := defaultFixture()
	fx.skipVerify = true
	row = shRun(t, writeSingleHostResult(t, fx), shGateSpec())
	if row.State != StateNotExercised || !strings.Contains(row.Reason, "incomplete") {
		t.Errorf("no restart check: %s %q", row.State, row.Reason)
	}
}

func TestSingleHostMatrixRowCannotBeWeakened(t *testing.T) {
	for name, mutate := range map[string]func(map[string]string){
		"shorter duration": func(p map[string]string) { p["duration"] = "600" },
		"fewer projects":   func(p map[string]string) { p["projects"] = "10" },
		"lower rate":       func(p map[string]string) { p["rate"] = "200" },
		"fewer series":     func(p map[string]string) { p["series"] = "1000" },
		"no seed":          func(p map[string]string) { delete(p, "seed") },
	} {
		spec := shGateSpec()
		mutate(spec.Params)
		row := shRun(t, writeSingleHostResult(t, defaultFixture()), spec)
		if row.State != StateNotExercised || !strings.Contains(row.Reason, "cannot be weakened") && !strings.Contains(row.Reason, "seed") {
			t.Errorf("%s: %s %q", name, row.State, row.Reason)
		}
	}
}

func TestSingleHostBudgetsMatchDesign(t *testing.T) {
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]float64{"single_host_ack_p95_ms": 250, "single_host_rss_bytes": 12 << 30, "single_host_missing_acked_records": 0} {
		b, ok := w.Budgets[name]
		if !ok || b.Limit != want || b.Source == "" || b.Unit == "" {
			t.Errorf("budget %s = %+v, design section 13 says %v", name, b, want)
		}
	}
	design, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "superpowers", "specs", "2026-11-03-soundpost-design.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{"10 orgs, 100 projects, 100k active metric series, 2k mixed records/s for 1 hour", "p95 durable ACK <250 ms; steady RSS <12 GiB; no loss of ACKed records across process restart"} {
		if !strings.Contains(string(design), phrase) {
			t.Errorf("design section 13 no longer says %q: re-derive the single-host gate", phrase)
		}
	}
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range m.Rows {
		if r.ID == "overhead.single_host.gate" {
			if r.Runner != "overhead_single_host" {
				t.Errorf("the single-host row still uses runner %q", r.Runner)
			}
			if why, ok := shGateParams(r); !ok {
				t.Errorf("the matrix row does not pin the design workload: %s", why)
			}
			return
		}
	}
	t.Error("matrix has no overhead.single_host.gate row")
}
