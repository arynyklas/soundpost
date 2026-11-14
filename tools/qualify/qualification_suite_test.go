// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

func exercisedRow(budgets ...BudgetResult) Row {
	r := Row{
		ID: "overhead.x", Suite: SuiteOverhead, Required: true,
		Subject: Subject{Family: "node", Version: "22", OS: "linux", Arch: "amd64"},
		State:   StateExercised, Outcome: OutcomePassed,
		Build:    &Build{Family: "node", Version: "22.23.4", OS: "linux", Arch: "amd64", ID: "sha256:x"},
		Command:  &CommandRun{Command: "overhead", ExitCode: 0},
		Evidence: []string{"harness"},
		Series:   []Series{{Name: "p95", Unit: "ms", Values: []float64{1, 2}}},
		Budgets:  budgets,
	}
	return r
}

// A row is judged only against its own build: another version, OS or architecture cannot stand in.
func TestQualificationRejectsExtrapolationAcrossRows(t *testing.T) {
	for name, mutate := range map[string]func(*Build){
		"other architecture": func(b *Build) { b.Arch = "arm64" },
		"other os":           func(b *Build) { b.OS = "windows" },
		"other family":       func(b *Build) { b.Family = "bun" },
		"other major":        func(b *Build) { b.Version = "24.11.0" },
		"prefix lookalike":   func(b *Build) { b.Version = "220.1.0" },
	} {
		row := exercisedRow()
		mutate(row.Build)
		if err := ValidateRow(row); !errors.Is(err, ErrExtrapolated) {
			t.Errorf("%s: want ErrExtrapolated, got %v", name, err)
		}
	}
	if err := ValidateRow(exercisedRow()); err != nil {
		t.Fatalf("the row's own build must validate: %v", err)
	}
	// An unsupported row that names a build must also be its own build.
	row := firefoxRow()
	row.Build = &Build{Family: "chrome", Version: "156.0.1.2", OS: "linux", Arch: "amd64", ID: "x"}
	if err := ValidateRow(row); !errors.Is(err, ErrExtrapolated) {
		t.Errorf("an unsupported firefox row observed on chrome must be rejected, got %v", err)
	}
}

func TestQualificationBudgetVerdictFollowsTheNumbers(t *testing.T) {
	over := BudgetResult{Name: "server_p95_latency_percent", Unit: "percent", Limit: 5, Observed: 153, Within: false}
	at := BudgetResult{Name: "server_p95_latency_percent", Unit: "percent", Limit: 5, Observed: 5, Within: true}
	if err := ValidateRow(exercisedRow(at)); err != nil {
		t.Errorf("a value exactly at the limit is within it: %v", err)
	}
	// A missed budget cannot be recorded as passed, and cannot be relabelled within.
	if err := ValidateRow(exercisedRow(over)); err == nil || !strings.Contains(err.Error(), "failed budget") {
		t.Errorf("passed with a missed budget must be rejected, got %v", err)
	}
	lie := over
	lie.Within = true
	if err := ValidateRow(exercisedRow(lie)); !errors.Is(err, ErrBudgetMismatch) {
		t.Errorf("within=true for 153 > 5 must be ErrBudgetMismatch, got %v", err)
	}
	failed := exercisedRow(over)
	failed.Outcome = OutcomeFailed
	if err := ValidateRow(failed); err != nil {
		t.Errorf("a missed budget recorded as failed is valid: %v", err)
	}
	// And the verdict blocks the claim.
	rep := SuiteReport{Suite: SuiteOverhead, Rows: []Row{failed}}
	rep.Verdict()
	if rep.ExitCode != ExitFail || len(rep.Failed) != 1 || !strings.Contains(rep.Failed[0], "153") {
		t.Fatalf("a missed budget must block with the measured number: %+v", rep)
	}
}

func TestQualificationVerdictBlocksUnqualifiedAndVacuous(t *testing.T) {
	notRun := Row{ID: "runtime.node-24", Suite: SuiteRuntime, Required: true, Subject: Subject{Family: "node", Version: "24", OS: "linux", Arch: "amd64"}, State: StateNotExercised, Reason: "no Node 24 build"}
	denied := Row{ID: "runtime.denied", Suite: SuiteRuntime, Required: true, Subject: Subject{Family: "x", Version: "1", OS: "linux", Arch: "amd64"}, State: StateDenied, Reason: "permission_denied",
		Evidence: []string{"observed"}, Readings: []Reading{{Name: "samples", Availability: AvailDenied, Reason: "permission_denied"}}}
	good := exercisedRow()
	for _, row := range []Row{notRun, denied, good} {
		if err := ValidateRow(row); err != nil {
			t.Fatal(err)
		}
	}
	rep := SuiteReport{Rows: []Row{good, notRun, denied}}
	rep.Verdict()
	if rep.ExitCode != ExitUnqualified || len(rep.Unqualified) != 2 {
		t.Fatalf("required rows that are not exercised (including denied) must give exit 10 and be listed: %+v", rep)
	}
	optional := notRun
	optional.Required = false
	rep = SuiteReport{Rows: []Row{good, optional}}
	rep.Verdict()
	if rep.ExitCode != ExitOK {
		t.Fatalf("an optional unexercised row does not block: %+v", rep)
	}
	rep = SuiteReport{Rows: []Row{optional}}
	rep.Verdict()
	if rep.ExitCode != ExitFail {
		t.Fatalf("a matrix without any required row must not pass vacuously: %+v", rep)
	}
	missed := exercisedRow()
	missed.Outcome, missed.Failures = OutcomeFailed, []string{"fixture exited 1"}
	rep = SuiteReport{Rows: []Row{missed, notRun}}
	rep.Verdict()
	if rep.ExitCode != ExitFail {
		t.Fatalf("a measured failure outranks unqualified rows: %+v", rep)
	}
	if !strings.Contains(rep.Summary(), "MEASURED FAILURE") || !strings.Contains(rep.Summary(), "UNQUALIFIED runtime.node-24") {
		t.Fatalf("summary must list both: %s", rep.Summary())
	}
}

func TestQualificationStateRules(t *testing.T) {
	cases := map[string]func(*Row){
		"not_exercised without reason": func(r *Row) {
			r.State, r.Reason, r.Build, r.Command, r.Series, r.Budgets, r.Outcome = StateNotExercised, "", nil, nil, nil, nil, ""
		},
		"not_exercised carrying series": func(r *Row) {
			r.State, r.Reason, r.Build, r.Command, r.Budgets, r.Outcome = StateNotExercised, "absent", nil, nil, nil, ""
		},
		"exercised without build id":         func(r *Row) { r.Build.ID = "" },
		"exercised without evidence":         func(r *Row) { r.Evidence = nil },
		"exercised without outcome":          func(r *Row) { r.Outcome = "" },
		"failed without any reason":          func(r *Row) { r.Outcome = OutcomeFailed },
		"passed with a failure":              func(r *Row) { r.Failures = []string{"x"} },
		"empty series":                       func(r *Row) { r.Series[0].Values = nil },
		"unsupported without observation":    func(r *Row) { *r = firefoxRow(); r.Evidence = nil },
		"unsupported carrying a series":      func(r *Row) { *r = firefoxRow(); r.Series = []Series{{Name: "x", Values: []float64{0}}} },
		"unavailable reading without reason": func(r *Row) { *r = firefoxRow(); r.Readings[0].Reason = "" },
		"unknown state":                      func(r *Row) { r.State = "passed" },
	}
	for name, mutate := range cases {
		row := exercisedRow()
		mutate(&row)
		if err := ValidateRow(row); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

func TestQualificationBudgetsMatchDesign(t *testing.T) {
	root := repoRoot(t)
	w, err := LoadWorkloads(filepath.Join(root, "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{
		"server_p95_latency_percent": 5, "server_cpu_percent": 5, "sdk_queue_bytes": 2 << 20,
		"browser_core_gzip_bytes": 40 << 10, "browser_replay_gzip_bytes": 60 << 10, "browser_recorder_batch_p95_ms": 5,
		"browser_recorder_queue_bytes": 2 << 20, "native_cpu_overhead_percent": 3, "native_memory_bytes": 64 << 20,
	}
	for name, limit := range want {
		if got := w.Budgets[name].Limit; got != limit {
			t.Errorf("budget %s = %v, design section 13 says %v", name, got, limit)
		}
	}
	design, err := os.ReadFile(filepath.Join(root, "docs", "superpowers", "specs", "2026-11-03-soundpost-design.md"))
	if err != nil {
		t.Fatal(err)
	}
	section := string(design)
	section = section[strings.Index(section, "## 13. Operating targets"):]
	section = section[:strings.Index(section, "## 14.")]
	for _, phrase := range []string{"<=5% p95 latency/CPU increase core capture", "<=2 MiB default queue", "core <=40 KiB gzip", "replay separate <=60 KiB gzip", "<=5 ms p95 per mutation batch", "bounded 2-MiB queue", "<=3% CPU overhead per profiled target workload", "bounded 64-MiB acquisition/export memory"} {
		if !strings.Contains(section, phrase) {
			t.Errorf("design section 13 no longer says %q: re-derive the pinned budgets", phrase)
		}
	}
	// A pinned limit of zero or a missing one is refused rather than defaulted.
	bad := filepath.Join(t.TempDir(), "w.yaml")
	raw, _ := os.ReadFile(filepath.Join(root, "qualification", "workloads.yaml"))
	if err := os.WriteFile(bad, []byte(strings.Replace(string(raw), "limit: 5, unit: percent, source: \"design 13 Python/server TS SDK: <=5% CPU", "limit: 0, unit: percent, source: \"design 13 Python/server TS SDK: <=5% CPU", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWorkloads(bad); err == nil {
		t.Error("a zero budget limit must be rejected")
	}
}

func TestQualificationRealMatrixCoversTheRequiredDimensions(t *testing.T) {
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]RowSpec{}
	for _, r := range m.Rows {
		ids[r.ID] = r
	}
	for _, id := range []string{
		"runtime.python-3.12.linux-amd64", "runtime.python-3.13.linux-arm64", "runtime.python-3.14.linux-amd64",
		"runtime.node-22.linux-amd64", "runtime.node-24.linux-arm64", "runtime.bun-1.3.14.linux-amd64", "runtime.bun-1.3.14.linux-arm64",
		"runtime.browser.chrome-142.linux-amd64.replay", "runtime.browser.firefox-144.sample_capability", "runtime.browser.safari-26.sample_capability", "runtime.browser.edge-142.core",
		"runtime.native.linux-6.1.amd64.off_cpu", "runtime.native.linux-6.1.arm64.cpu", "runtime.native.linux-6.6.amd64.off_cpu", "runtime.native.linux-6.6.arm64.runqueue_split",
		"privacy.native.linux-6.6.amd64.no_stack_bytes_config", "overhead.native.linux-6.6.amd64.cpu_loop", "overhead.native.linux-6.1.arm64.blocked_runqueue",
		"overhead.browser.bundle_size", "overhead.sdk.node-22.linux-amd64.http-3hash", "privacy.scanner_controls", "runtime.native.capture_authenticity_controls",
	} {
		spec, ok := ids[id]
		if !ok {
			t.Errorf("matrix has no row %s", id)
		} else if !spec.Required && !strings.Contains(id, "wsl2") {
			t.Errorf("row %s must be required", id)
		}
	}
	// Every WSL2/Windows measurement is optional: it can never qualify a required row.
	for id, spec := range ids {
		if (strings.Contains(id, "wsl2") || strings.Contains(id, "windows") || strings.Contains(id, "chrome-156")) && spec.Required {
			t.Errorf("row %s measures a different build/host and must not be required", id)
		}
	}
	// The kernel/arch cross product is complete: 2 series x 2 architectures x (8 runtime + 5 identity + 2 gaps + 5 privacy + 2 overhead) capabilities.
	native := 0
	for id := range ids {
		if strings.Contains(id, ".native.linux-") {
			native++
		}
	}
	if native != 2*2*(8+5+2+5+2) {
		t.Errorf("native matrix rows = %d, want 88", native)
	}
	if len(m.Builds) == 0 {
		t.Fatal("no builds")
	}
}

// ---- probing: a build is the exact build or it is absent ----

func probeCtx(t *testing.T, spec BuildSpec) *runCtx {
	t.Helper()
	return &runCtx{ctx: context.Background(), root: t.TempDir(), work: t.TempDir(), reportDir: t.TempDir(),
		matrix: Matrix{Builds: map[string]BuildSpec{"b": spec}}, host: hostInfo(), probes: map[string]*probeResult{}, cache: map[string]any{}}
}

func TestQualificationProbeAcceptsOnlyTheNamedBuild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("probe fixture uses /usr/bin/env")
	}
	env, err := os.Stat("/usr/bin/env")
	if err != nil || env.IsDir() {
		t.Skip("no /usr/bin/env")
	}
	base := BuildSpec{Family: "coreutils", Version: "", OS: "linux", Arch: runtime.GOARCH, Candidates: []string{"env"}, VersionArgs: []string{"--version"}, VersionRegex: `\) (\d+\.\d+)`, Absent: "no such coreutils"}
	out := probeCtx(t, base).exec(10e9, "/", nil, "/usr/bin/env", "--version")
	if out.Exit != 0 || !strings.Contains(out.Stdout, "env") {
		t.Skip("env --version unavailable")
	}
	got := regexpFirst(t, `\) (\d+\.\d+)`, out.Stdout)

	ok := base
	ok.Version = got
	if p := probeCtx(t, ok).probe("b"); !p.Found || p.Build.Version != got || p.Build.ID == "" || p.Build.SHA256 == "" {
		t.Fatalf("the named version must be found with its sha256 build id: %+v", p)
	}
	other := base
	other.Version = "99.9"
	if p := probeCtx(t, other).probe("b"); p.Found || !strings.Contains(p.Reason, "no such coreutils") || !strings.Contains(p.Reason, "row needs 99.9") {
		t.Fatalf("a different version must not stand in and must say why: %+v", p)
	}
	wrongArch := ok
	wrongArch.Arch = map[string]string{"amd64": "arm64", "arm64": "amd64"}[runtime.GOARCH]
	if p := probeCtx(t, wrongArch).probe("b"); p.Found || !strings.Contains(p.Reason, "row needs linux/"+wrongArch.Arch) {
		t.Fatalf("an object built for another architecture must not satisfy the row: %+v", p)
	}
	wrongOS := ok
	wrongOS.OS = "windows"
	if p := probeCtx(t, wrongOS).probe("b"); p.Found {
		t.Fatalf("an ELF must not satisfy a windows row: %+v", p)
	}
	// A prefix lookalike is another version.
	prefix := ok
	prefix.Version = got[:1]
	if got[:1] != strings.SplitN(got, ".", 2)[0] || len(strings.SplitN(got, ".", 2)[0]) < 2 {
		if p := probeCtx(t, prefix).probe("b"); p.Found && !versionMatches(p.Build.Version, prefix.Version) {
			t.Fatalf("lookalike prefix accepted: %+v", p)
		}
	}
}

func regexpFirst(t *testing.T, pattern, text string) string {
	t.Helper()
	m := strings.Split(strings.SplitN(text, "\n", 2)[0], ") ")
	if len(m) < 2 {
		t.Skip("unexpected env --version output")
	}
	return strings.Fields(m[1])[0]
}

func TestQualificationVersionMatchesPatchBuildsOnly(t *testing.T) {
	for _, c := range []struct {
		observed, want string
		ok             bool
	}{
		{"3.12.3", "3.12", true}, {"v22.23.4", "22", true}, {"1.3.14", "1.3.14", true}, {"156.0.8078.80", "156", true},
		{"3.120.1", "3.12", false}, {"220.1.0", "22", false}, {"24.11.0", "22", false}, {"1.3.140", "1.3.14", false}, {"3.12.3", "", false},
	} {
		if got := versionMatches(c.observed, c.want); got != c.ok {
			t.Errorf("versionMatches(%q, %q) = %v, want %v", c.observed, c.want, got, c.ok)
		}
	}
}

// ---- RunSuite end to end on a tiny real matrix ----

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const tinyMatrix = `schema: soundpost-qualification-matrix/1
root: .
workloads: workloads.yaml
builds:
  firefox-144-linux-amd64: {family: firefox, version: "144.0.2", os: linux, arch: amd64, env: SOUNDPOST_QUAL_TEST_ABSENT_FIREFOX, candidates: [definitely-not-installed-firefox], absent: "no Firefox 144.0.2 build is installed on this host"}
  python-3.13-linux-arm64: {family: python, version: "3.13", os: linux, arch: arm64, candidates: [python3], absent: "no CPython 3.13 for linux/arm64"}
rows:
  - {id: runtime.browser.firefox.sample, suite: runtime, required: true, runner: build_probe, build: firefox-144-linux-amd64, params: {reason: "no harness"}}
  - {id: runtime.python-3.13.linux-arm64, suite: runtime, required: true, runner: sdk_profile, build: python-3.13-linux-arm64, params: {fixture: "fixtures/sdk/profiles/python.py"}}
  - {id: runtime.optional, suite: runtime, required: false, runner: unmeasured, subject: {family: x, version: "1", os: any, arch: any}, params: {reason: "optional"}}
  - {id: privacy.other, suite: privacy, required: true, runner: unmeasured, subject: {family: x, version: "1", os: any, arch: any}, params: {reason: "other suite"}}
`

func TestQualificationRunSuiteReportsEveryRowAndNeverPromotes(t *testing.T) {
	root := t.TempDir()
	repo := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(repo, "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "workloads.yaml"), string(raw))
	writeFile(t, filepath.Join(root, "matrix.yaml"), tinyMatrix)
	report := filepath.Join(root, "report")
	rep, err := RunSuite(context.Background(), SuiteRuntime, filepath.Join(root, "matrix.yaml"), report)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Rows) != 3 || rep.ExitCode != ExitUnqualified {
		t.Fatalf("3 runtime rows, required ones unexercised => exit 10: %+v", rep)
	}
	for _, row := range rep.Rows {
		if row.State != StateNotExercised || len(row.Series) != 0 || row.Build != nil || row.Reason == "" {
			t.Errorf("an absent build must give a bare not_exercised row with its reason: %+v", row)
		}
	}
	if len(rep.Unqualified) != 2 || !strings.Contains(rep.Unqualified[0], "runtime.browser.firefox.sample") {
		t.Fatalf("unqualified list: %v", rep.Unqualified)
	}
	// The arm64 row is not satisfied by the amd64 python3 that exists here.
	if runtime.GOARCH == "amd64" && !strings.Contains(rep.Rows[1].Reason, "no CPython 3.13 for linux/arm64") {
		t.Errorf("reason must carry the matrix text: %s", rep.Rows[1].Reason)
	}
	data, err := os.ReadFile(filepath.Join(report, "runtime-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSuiteReport(data)
	if err != nil {
		t.Fatalf("the written report must parse and validate: %v", err)
	}
	if back.Suite != SuiteRuntime || back.MatrixSHA == "" || back.Host.OS == "" || back.ExitCode != ExitUnqualified {
		t.Fatalf("report identity missing: %+v", back)
	}
	if strings.Contains(string(data), `"value"`) {
		t.Errorf("a report of unexercised rows must not contain a single measured value")
	}
	if _, err := os.Stat(filepath.Join(report, "privacy-report.json")); err == nil {
		t.Error("only the requested suite may be written")
	}
}

func TestQualificationMatrixErrors(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown build": strings.Replace(tinyMatrix, "build: python-3.13-linux-arm64", "build: nope", 1),
		"unknown field": strings.Replace(tinyMatrix, "workloads: workloads.yaml", "workloads: workloads.yaml\nsurprise: 1", 1),
		"bad schema":    strings.Replace(tinyMatrix, "matrix/1", "matrix/2", 1),
		"duplicate":     tinyMatrix + "  - {id: runtime.optional, suite: runtime, required: false, runner: unmeasured, subject: {family: x, version: \"1\", os: any, arch: any}}\n",
		"no absent":     strings.Replace(tinyMatrix, `, absent: "no CPython 3.13 for linux/arm64"`, "", 1),
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
		writeFile(t, path, body)
		if _, err := LoadMatrix(path); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
}

// ---- overhead: budgets are compared, never adjusted ----

func overheadCtx(t *testing.T) *runCtx {
	t.Helper()
	w, err := LoadWorkloads(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rc := &runCtx{ctx: context.Background(), root: t.TempDir(), work: t.TempDir(), reportDir: t.TempDir(), workloads: w, host: hostInfo(),
		matrix: Matrix{Builds: map[string]BuildSpec{"node": {Family: "node", Version: "22", OS: "linux", Arch: "amd64", Absent: "x"}}},
		probes: map[string]*probeResult{}, cache: map[string]any{}}
	rc.probes["node"] = &probeResult{Found: true, Path: "/x/node", Build: Build{Family: "node", Version: "22.23.4", OS: "linux", Arch: "amd64", ID: "sha256:x"}}
	if err := os.MkdirAll(filepath.Join(rc.reportDir, "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	return rc
}

func httpRow(hashes int, p95Base, p95Cap, cpuBase, cpuCap []float64) sdkHTTPRow {
	return sdkHTTPRow{HandlerHashes: hashes,
		P95: modePair{statBlock{p95Base}, statBlock{p95Cap}}, CPU: modePair{statBlock{cpuBase}, statBlock{cpuCap}},
		ELU: modePair{statBlock{[]float64{70}}, statBlock{[]float64{90}}}, Achieved: modePair{statBlock{[]float64{995}}, statBlock{[]float64{996}}}, Errors: json.RawMessage("0")}
}

func sdkRun(rows ...sdkHTTPRow) *sdkOverheadRun {
	res := &sdkOverhead{}
	res.Rows.HTTP = rows
	return &sdkOverheadRun{Result: res, Raw: []byte(`{}`), Command: "node overhead.mjs"}
}

func runServerRow(t *testing.T, run *sdkOverheadRun, hashes string) Row {
	t.Helper()
	rc := overheadCtx(t)
	rc.cache["sdk-overhead:node"] = run
	spec := RowSpec{ID: "overhead.x", Suite: SuiteOverhead, Build: "node", Params: map[string]string{"handler_hashes": hashes}}
	row := runOverheadSDKServer(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("overhead runner produced an invalid row: %v", err)
	}
	return row
}

func TestQualificationOverheadMissedBudgetIsAMeasuredFailure(t *testing.T) {
	within := runServerRow(t, sdkRun(httpRow(3, []float64{1.0, 1.0}, []float64{1.04, 1.04}, []float64{100, 100}, []float64{104, 104})), "3")
	if within.Outcome != OutcomePassed || len(within.Budgets) != 2 || !within.Budgets[0].Within || !within.Budgets[1].Within {
		t.Fatalf("+4%% on both is within the 5%% budgets: %+v", within)
	}
	if within.Interval == nil || *within.Interval.RequestedUS != 1000 || *within.Interval.ObservedUS < 1004 || *within.Interval.ObservedUS > 1004.1 {
		t.Fatalf("requested/observed request interval missing or wrong: %+v", within.Interval)
	}
	exact := runServerRow(t, sdkRun(httpRow(3, []float64{1.0}, []float64{1.05}, []float64{100}, []float64{105})), "3")
	if exact.Outcome != OutcomePassed {
		t.Errorf("exactly 5%% is within the budget: %+v", exact.Budgets)
	}
	for name, run := range map[string]*sdkOverheadRun{
		"p95 +6%":      sdkRun(httpRow(3, []float64{1.0}, []float64{1.06}, []float64{100}, []float64{101})),
		"cpu +6%":      sdkRun(httpRow(3, []float64{1.0}, []float64{1.01}, []float64{100}, []float64{106})),
		"measured 153": sdkRun(httpRow(3, []float64{1.78}, []float64{4.52}, []float64{107}, []float64{445})),
	} {
		row := runServerRow(t, run, "3")
		if row.Outcome != OutcomeFailed {
			t.Errorf("%s: a missed budget must be a measured failure, got %s", name, row.Outcome)
		}
		rep := SuiteReport{Rows: []Row{row}}
		rep.Verdict()
		if rep.ExitCode != ExitFail {
			t.Errorf("%s: the claim must be blocked, exit %d", name, rep.ExitCode)
		}
	}
	// A baseline that reads zero has no ratio: never reported as a 0 % overhead.
	zero := runServerRow(t, sdkRun(httpRow(3, []float64{1.0}, []float64{1.0}, []float64{0, 0}, []float64{50, 50})), "3")
	if zero.Outcome != OutcomeFailed || len(zero.Budgets) != 0 {
		t.Errorf("a zero CPU baseline is not measurable and must not pass: %+v", zero)
	}
	// A missing handler row, or a failed harness, is a failure and not a pass.
	if row := runServerRow(t, sdkRun(httpRow(3, []float64{1}, []float64{1}, []float64{1}, []float64{1})), "100"); row.Outcome != OutcomeFailed {
		t.Errorf("no handler_hashes=100 row in the result: %+v", row)
	}
	if row := runServerRow(t, &sdkOverheadRun{Failure: "harness exited 1", Command: "node overhead.mjs", Exit: 1}, "3"); row.Outcome != OutcomeFailed || row.State != StateExercised {
		t.Errorf("a failed harness is a failed row: %+v", row)
	}
}

func TestQualificationOverheadQueueAndBundleBudgets(t *testing.T) {
	rc := overheadCtx(t)
	res := &sdkOverhead{}
	res.Rows.Acking.Max, res.Rows.Stalled.Max = 881686, 2<<20+1
	res.Rows.Bundles.Index = sdkBundle{Raw: 133466, Gzip: 46570}
	res.Rows.Bundles.Replay = sdkBundle{Raw: 13920, Gzip: 5882}
	rc.cache["sdk-overhead:node"] = &sdkOverheadRun{Result: res, Raw: []byte(`{}`), Command: "node overhead.mjs"}
	check := func(row Row, spec RowSpec) Row {
		row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
		if err := ValidateRow(row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	q := check(runOverheadSDKQueue(rc, RowSpec{ID: "q", Suite: SuiteOverhead, Build: "node"}), RowSpec{ID: "q", Suite: SuiteOverhead, Build: "node"})
	if q.Outcome != OutcomeFailed || !q.Budgets[0].Within || q.Budgets[1].Within {
		t.Errorf("one byte over 2 MiB on the stalled transport must fail only that budget: %+v", q.Budgets)
	}
	b := check(runOverheadBundle(rc, RowSpec{ID: "b", Suite: SuiteOverhead, Build: "node"}), RowSpec{ID: "b", Suite: SuiteOverhead, Build: "node"})
	if b.Outcome != OutcomeFailed || b.Budgets[0].Within || !b.Budgets[1].Within || b.Budgets[0].Observed != 46570 || b.Budgets[0].Limit != 40960 {
		t.Errorf("46,570 B gzip core is over 40 KiB (measured failure, budget untouched), replay within: %+v", b.Budgets)
	}
}

func TestQualificationNativeOverheadFromRawRuns(t *testing.T) {
	rc := overheadCtx(t)
	rc.host = HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.87.2-microsoft-standard-WSL2", Class: "wsl2"}
	spec := RowSpec{ID: "o", Suite: SuiteOverhead, Runner: "overhead_native", Subject: &Subject{Family: "wsl2-linux-kernel", Version: "6.6", OS: "linux", Arch: "amd64"}, Params: map[string]string{"capability": "cpu_loop"}}
	runs := func(captureNs float64, mem float64) *nativeOverheadRun {
		var rr []nativeOverheadRunRow
		for range 3 {
			rr = append(rr, nativeOverheadRunRow{Mode: "baseline", CPUNsPerIter: 100, Throughput: 1e7},
				nativeOverheadRunRow{Mode: "capture", CPUNsPerIter: captureNs, Throughput: 1e7, Samples: 1900, AchievedHz: 99, GapP50Ms: 10.1, GapP99Ms: 10.2})
		}
		return &nativeOverheadRun{Command: "overhead --hz 99", Report: &nativeOverheadReport{Hz: 99, FullCommand: "full", Fixtures: []nativeOverheadFixture{{Fixture: "cpu", Seconds: 20, Repeats: 3, Reduced: true, Runs: rr, MemoryBytes: mem, HarnessPct: -99}}}}
	}
	ok := func(r *nativeOverheadRun) Row {
		rc.cache["native-overhead"] = r
		row := runOverheadNative(rc, spec)
		row.ID, row.Suite, row.Subject = spec.ID, spec.Suite, rc.subject(spec)
		if err := ValidateRow(row); err != nil {
			t.Fatalf("invalid row: %v", err)
		}
		return row
	}
	good := ok(runs(102, 38<<20))
	if good.Outcome != OutcomePassed || good.Budgets[0].Observed != 2 || !strings.Contains(strings.Join(good.Limits, " "), "REDUCED real run") || !strings.Contains(strings.Join(good.Limits, " "), "full") {
		t.Fatalf("+2%% and 38 MiB pass; the reduction and the full command must be stated: %+v", good)
	}
	if good.Interval == nil || good.Interval.ObservedUS == nil || *good.Interval.ObservedUS < 10101 || *good.Interval.ObservedUS > 10102 {
		t.Fatalf("observed interval = 1e6/achieved Hz: %+v", good.Interval)
	}
	// The harness' own (here wildly wrong) percentage is NOT trusted: the budget is recomputed from the raw runs.
	if over := ok(runs(104, 38<<20)); over.Outcome != OutcomeFailed || over.Budgets[0].Within {
		t.Errorf("+4%% CPU exceeds the 3%% budget: %+v", over.Budgets)
	}
	if over := ok(runs(101, 64<<20+1)); over.Outcome != OutcomeFailed || over.Budgets[1].Within {
		t.Errorf("64 MiB + 1 byte exceeds the memory budget: %+v", over.Budgets)
	}
	if under := ok(runs(103, 64<<20)); under.Outcome != OutcomePassed {
		t.Errorf("exactly 3%% and exactly 64 MiB are within budget: %+v", under.Budgets)
	}
	// The blocked/runqueue overhead row is never measured by the cpu-only runner.
	spec.Params = map[string]string{"capability": "blocked_runqueue"}
	row := runOverheadNative(rc, spec)
	if row.State != StateNotExercised || !strings.Contains(row.Reason, "no committed overhead harness") {
		t.Errorf("blocked_runqueue overhead must be not_exercised: %+v", row)
	}
}

// ---- native gate and row mapping ----

func TestQualificationNativeGateNeverBorrowsAnotherHost(t *testing.T) {
	rc := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.87.2-microsoft-standard-WSL2", Class: "wsl2"}}
	row := func(family, version, arch string) RowSpec {
		return RowSpec{ID: "n", Subject: &Subject{Family: family, Version: version, OS: "linux", Arch: arch}}
	}
	for name, c := range map[string]struct {
		spec RowSpec
		want string
	}{
		"arm64 is not amd64":        {row("linux-kernel", "6.6", "arm64"), "never extrapolated"},
		"6.1 is not 6.6":            {row("linux-kernel", "6.1", "amd64"), "no Linux 6.1 runner"},
		"WSL2 never qualifies 6.6":  {row("linux-kernel", "6.6", "amd64"), "does not implicitly qualify"},
		"functional on other arch":  {row("wsl2-linux-kernel", "6.6", "arm64"), "never extrapolated"},
		"functional on other minor": {row("wsl2-linux-kernel", "6.1", "amd64"), "no Linux 6.1 runner"},
	} {
		if b, why := rc.nativeGate(c.spec); b != nil || !strings.Contains(why, c.want) {
			t.Errorf("%s: want a not-exercised reason containing %q, got build %v reason %q", name, c.want, b, why)
		}
	}
	if b, why := rc.nativeGate(row("wsl2-linux-kernel", "6.6", "amd64")); b == nil || why != "" || b.Host != "wsl2" || b.Family != "wsl2-linux-kernel" {
		t.Errorf("the WSL2 functional row is allowed on this host: %v %q", b, why)
	}
	real := &runCtx{host: HostInfo{OS: "linux", Arch: "arm64", Kernel: "6.1.115", Class: "linux"}}
	if b, why := real.nativeGate(row("linux-kernel", "6.1", "arm64")); b == nil || why != "" {
		t.Errorf("a genuine 6.1 arm64 runner may exercise its own row: %q", why)
	}
	if _, why := real.nativeGate(row("wsl2-linux-kernel", "6.1", "arm64")); why == "" {
		t.Error("functional WSL2 rows are not produced on a genuine Linux runner")
	}
	if _, why := (&runCtx{host: HostInfo{OS: "windows", Arch: "amd64"}}).nativeGate(row("linux-kernel", "6.6", "amd64")); why == "" {
		t.Error("a Windows host cannot exercise native Linux rows")
	}
}

func TestQualificationNativeRowMappingKeepsDeniedAndUnqualifiedDistinct(t *testing.T) {
	rc := &runCtx{workloads: Workloads{}}
	rc.workloads.NativeAcceptance.Duration = "30s"
	run := &nativeRun{Result: &qual.QualificationResult{}, Command: "acceptance", Exit: 10}
	build := &Build{Family: "wsl2-linux-kernel", Version: "6.6.87", OS: "linux", Arch: "amd64", ID: "k"}
	supported := rc.mapQualRow(run, "loss", qual.Supported([]string{"16 explicit loss events"}, map[string]any{"lost_records": 5720.0, "nested": map[string]any{"samples": 6946.0}}), build)
	if supported.State != StateExercised || supported.Outcome != OutcomePassed || len(supported.Series) != 2 {
		t.Fatalf("supported => exercised/passed with its numbers: %+v", supported)
	}
	denied := rc.mapQualRow(run, "cpu", qual.Row{State: qual.StateDenied, Reason: "permission_denied"}, build)
	if denied.State != StateDenied || len(denied.Series) != 0 || denied.Readings[0].Availability != AvailDenied || denied.Readings[0].Value != nil {
		t.Fatalf("denied stays denied, carries no number: %+v", denied)
	}
	for _, st := range []qual.State{qual.StateUnqualified, qual.StateNotRun} {
		row := rc.mapQualRow(run, "off_cpu", qual.Row{State: st, Reason: "scheduler_pid_namespace_not_initial"}, build)
		if row.State != StateNotExercised || row.Reason != "scheduler_pid_namespace_not_initial" || row.Build != nil {
			t.Fatalf("%s => not_exercised with the harness reason: %+v", st, row)
		}
	}
	for _, st := range []qual.State{qual.StateFailed, qual.StateError} {
		row := rc.mapQualRow(run, "cpu", qual.Row{State: st, Reason: "boom"}, build)
		if row.State != StateExercised || row.Outcome != OutcomeFailed || row.Failures[0] != "boom" {
			t.Fatalf("%s => measured failure: %+v", st, row)
		}
	}
}

func TestQualificationPermissionCasesStayDistinct(t *testing.T) {
	rc := &runCtx{}
	run := &nativeRun{Command: "acceptance", Result: &qual.QualificationResult{Permissions: qual.HostPermissions{Cases: []qual.PermissionCase{
		{Name: "foreign", Helper: "uid 65534", Target: "uid 0", Outcome: "refused", ErrorCode: "permission_denied", FDsReleased: true},
		{Name: "same", Helper: "uid 65534", Target: "uid 65534", Outcome: "captured", Samples: 80, FDsReleased: true},
		{Name: "leaky", Helper: "uid 65534", Target: "uid 65534", Outcome: "captured", Samples: 80, FDsReleased: false},
		{Name: "broken", Helper: "uid 65534", Target: "uid 0", Outcome: "fixture_error: x"},
	}}}}
	build := &Build{Family: "wsl2-linux-kernel", Version: "6.6", OS: "linux", Arch: "amd64", ID: "k"}
	if r := rc.permissionRow(run, "foreign", build); r.State != StateDenied || r.Readings[0].Value != nil {
		t.Errorf("permission_denied stays denied: %+v", r)
	}
	if r := rc.permissionRow(run, "same", build); r.State != StateExercised || r.Outcome != OutcomePassed {
		t.Errorf("a same-uid capture with released resources passes: %+v", r)
	}
	for _, name := range []string{"leaky", "broken"} {
		if r := rc.permissionRow(run, name, build); r.Outcome != OutcomeFailed {
			t.Errorf("%s must be a failure: %+v", name, r)
		}
	}
	if r := rc.permissionRow(run, "absent", build); r.State != StateNotExercised {
		t.Errorf("a case the report lacks is not exercised: %+v", r)
	}
}

func TestQualificationNativeControlsRejectStagedAndEmptySamplers(t *testing.T) {
	rc := &runCtx{host: hostInfo()}
	row := runNativeControls(rc, RowSpec{ID: "c", Suite: SuiteRuntime})
	row.ID, row.Suite, row.Subject = "c", SuiteRuntime, Subject{Family: "go", Version: "1.27", OS: "any", Arch: "any"}
	if err := ValidateRow(row); err != nil {
		t.Fatal(err)
	}
	if row.Outcome != OutcomePassed {
		t.Fatalf("every staged/empty/synthetic/no-op control must be rejected and the positive control accepted: %v", row.Failures)
	}
	text := strings.Join(row.Evidence, "\n")
	for _, want := range []string{"staged_acquisition_pending", "successful_empty_session", "noop_sampler", "positive_control"} {
		if !strings.Contains(text, want) {
			t.Errorf("control %s missing from the evidence", want)
		}
	}
}

// ---- browser rows from Playwright results ----

func TestQualificationPlaywrightRowStates(t *testing.T) {
	rc := overheadCtx(t)
	rc.matrix.Builds["chrome"] = BuildSpec{Family: "chrome", Version: "156", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["chrome"] = &probeResult{Found: true, Path: "/x/chrome", Build: Build{Family: "chrome", Version: "156.0.8078.80", OS: "linux", Arch: "amd64", ID: "sha256:c"}}
	rc.cache["pw:/x/chrome:cfg:spec.ts"] = &pwRun{Command: "playwright", Tests: []pwTest{
		{Title: "with the Document-Policy header: genuine samples", Status: "expected", Stdout: `SOUNDPOST_PROFILE_EVIDENCE {"with_header":{"sample_count":30,"requested_us":5000,"achieved_us":10100}}`},
		{Title: "without the Document-Policy header: refusal", Status: "expected"},
		{Title: "Profiler removed (Firefox/Safari emulation)", Status: "expected"},
		{Title: "second concurrent start", Status: "unexpected"},
	}}
	run := func(title, onPass string) Row {
		spec := RowSpec{ID: "b", Suite: SuiteRuntime, Build: "chrome", Params: map[string]string{"config": "cfg", "spec": "spec.ts", "title": title, "on_pass": onPass, "on_pass_reason": "reason", "evidence_key": "with_header"}}
		row := runPlaywrightTest(rc, spec)
		row.ID, row.Suite, row.Subject = spec.ID, spec.Suite, rc.subject(spec)
		if err := ValidateRow(row); err != nil {
			t.Fatalf("%s: %v", title, err)
		}
		return row
	}
	if r := run("with the Document-Policy header", "exercised"); r.State != StateExercised || r.Outcome != OutcomePassed || r.Interval == nil || *r.Interval.ObservedUS != 10100 {
		t.Errorf("supported row: %+v", r)
	}
	if r := run("without the Document-Policy header", "denied"); r.State != StateDenied || len(r.Series) != 0 || r.Readings[0].Value != nil || r.Interval != nil {
		t.Errorf("a passing denial spec is a denied row without numbers: %+v", r)
	}
	if r := run("Profiler removed", "unsupported"); r.State != StateUnsupported || r.Readings[0].Availability != AvailUnsupported {
		t.Errorf("unsupported row: %+v", r)
	}
	if r := run("second concurrent start", "denied"); r.State != StateExercised || r.Outcome != OutcomeFailed {
		t.Errorf("a failing test is a measured failure, never a denial: %+v", r)
	}
	if r := run("no such test", "exercised"); r.Outcome != OutcomeFailed {
		t.Errorf("no matching test must fail, not pass vacuously: %+v", r)
	}
	tests, errs, err := parsePlaywright(`{"suites":[{"title":"a","specs":[{"title":"t1","tests":[{"status":"expected","results":[{"stdout":[{"text":"hello"}]}]}]}],"suites":[{"title":"b","specs":[{"title":"t2","tests":[{"status":"unexpected","results":[]}]}]}]}],"errors":[{"message":"boom"}]}`)
	if err != nil || len(tests) != 2 || tests[0].Stdout != "hello" || tests[1].Status != "unexpected" || len(errs) != 1 {
		t.Errorf("parsePlaywright: %+v %v %v", tests, errs, err)
	}
}

// One spec run per browser build: a pass in one browser must never be read as a pass in another build that shares the spec.
func TestQualificationPlaywrightResultIsNeverSharedAcrossBuilds(t *testing.T) {
	rc := overheadCtx(t)
	rc.matrix.Builds["chrome142"] = BuildSpec{Family: "chrome", Version: "142.0.7444.59", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["chrome142"] = &probeResult{Found: true, Path: "/y/chrome142", Build: Build{Family: "chrome", Version: "142.0.7444.59", OS: "linux", Arch: "amd64", ID: "sha256:d"}}
	rc.cache["pw:/x/chrome156:cfg:spec.ts"] = &pwRun{Command: "playwright", Tests: []pwTest{{Title: "t", Status: "expected"}}}
	row := runPlaywrightTest(rc, RowSpec{ID: "c142", Suite: SuiteRuntime, Build: "chrome142", Params: map[string]string{"config": "cfg", "spec": "spec.ts", "title": "t", "on_pass": "exercised"}})
	if row.State == StateExercised {
		t.Fatalf("Chrome 142 must not take the result recorded for another build: %+v", row)
	}
}

// ---- native privacy rows from the verifier report ----

func verifyCtx(t *testing.T, neg bool, run *verifyRun) (*runCtx, Build) {
	t.Helper()
	rc := overheadCtx(t)
	rc.host = HostInfo{OS: "linux", Arch: "amd64", Kernel: "6.6.87.2-microsoft-standard-WSL2", Class: "wsl2"}
	key := "verify:false"
	if neg {
		key = "verify:true"
	}
	rc.cache[key] = run
	return rc, Build{}
}

func goodVerify() *verifyRun {
	rep := &verifyReport{Stages: map[string]verifyStage{}}
	for _, s := range []string{"owned_sanitized_staging", "acquisition_socket", "exporter_queue", "wire_compressed", "wire_decompressed", "admitted_storage", "profile_read", "profile_export", "diagnostics"} {
		rep.Stages[s] = verifyStage{Buffers: 3, Bytes: 4096}
	}
	rep.CPU.Samples = 85
	rep.Scheduler.Status, rep.Scheduler.Reason = "unsupported", "tracefs_denied"
	rep.Export.QueueObserved, rep.Export.StoragePos, rep.Export.StorageBytes, rep.Export.ReadSamples, rep.Export.Batches = true, true, 9000, 85, 2
	rep.Syscalls = &struct {
		Method   string   `json:"method"`
		Opens    int      `json:"perf_event_open_calls"`
		CPUOpens int      `json:"cpu_event_opens"`
		Ioctls   int      `json:"perf_event_ioctls"`
		Findings []string `json:"findings"`
	}{Method: "strace -f -v", Opens: 12, CPUOpens: 8, Ioctls: 20}
	return &verifyRun{Report: rep, Raw: []byte(`{}`), Exit: 10, Command: "verify"}
}

func TestPrivacyCanaryNativeRowsInspectActualRecordsAndConfig(t *testing.T) {
	spec := func(capability string) RowSpec {
		return RowSpec{ID: "p", Suite: SuitePrivacy, Subject: &Subject{Family: "wsl2-linux-kernel", Version: "6.6", OS: "linux", Arch: "amd64"}, Params: map[string]string{"capability": capability}}
	}
	run := func(v *verifyRun, capability string) Row {
		rc, _ := verifyCtx(t, capability == "negative_control", v)
		s := spec(capability)
		row := runPrivacyNative(rc, s)
		row.ID, row.Suite, row.Subject = s.ID, s.Suite, rc.subject(s)
		if err := ValidateRow(row); err != nil {
			t.Fatalf("%s: %v", capability, err)
		}
		return row
	}
	for _, capability := range []string{"canary_boundaries", "stored_exported_records", "no_stack_bytes_config"} {
		if r := run(goodVerify(), capability); r.Outcome != OutcomePassed {
			t.Errorf("%s: clean real run must pass: %v", capability, r.Failures)
		}
	}
	mutate := func(f func(*verifyRun)) *verifyRun { v := goodVerify(); f(v); return v }
	for name, c := range map[string]struct {
		capability string
		v          *verifyRun
	}{
		"canary crossed a boundary":      {"canary_boundaries", mutate(func(v *verifyRun) { v.Report.Violations = []string{"canary kind=comm"} })},
		"queue never inspected":          {"canary_boundaries", mutate(func(v *verifyRun) { v.Report.Stages["exporter_queue"] = verifyStage{} })},
		"storage never inspected":        {"stored_exported_records", mutate(func(v *verifyRun) { v.Report.Stages["admitted_storage"] = verifyStage{} })},
		"export read nothing":            {"stored_exported_records", mutate(func(v *verifyRun) { v.Report.Export.ReadSamples = 0 })},
		"no storage positive control":    {"stored_exported_records", mutate(func(v *verifyRun) { v.Report.Export.StoragePos = false })},
		"no real capture samples":        {"canary_boundaries", mutate(func(v *verifyRun) { v.Report.CPU.Samples = 0 })},
		"stack config finding":           {"no_stack_bytes_config", mutate(func(v *verifyRun) { v.Report.Syscalls.Findings = []string{"sample_type STACK_USER"} })},
		"config audit without any open":  {"no_stack_bytes_config", mutate(func(v *verifyRun) { v.Report.Syscalls.Opens = 0 })},
		"config not audited from strace": {"no_stack_bytes_config", mutate(func(v *verifyRun) { v.Report.Syscalls = nil })},
		"verifier exit 1":                {"canary_boundaries", mutate(func(v *verifyRun) { v.Exit = 1 })},
		"verifier failures":              {"canary_boundaries", mutate(func(v *verifyRun) { v.Report.Failures = []string{"x"} })},
	} {
		if r := run(c.v, c.capability); r.Outcome != OutcomeFailed || r.State != StateExercised {
			t.Errorf("%s: must be a measured failure, got %+v", name, r)
		}
	}
	// The permanent contaminated-sanitizer control must exit 4 and report the violation.
	if r := run(&verifyRun{Exit: 4, Command: "verify --negative-control", Report: &verifyReport{Violations: []string{"canary kind=comm"}}}, "negative_control"); r.Outcome != OutcomePassed {
		t.Errorf("negative control exiting 4 with a violation passes: %+v", r)
	}
	if r := run(&verifyRun{Exit: 0, Command: "verify --negative-control", Report: goodVerify().Report}, "negative_control"); r.Outcome != OutcomeFailed {
		t.Errorf("a contaminated sanitizer that is NOT flagged means the detector is blind: %+v", r)
	}
	if r := run(&verifyRun{Exit: 4, Command: "verify --negative-control", Report: &verifyReport{}}, "negative_control"); r.Outcome != OutcomeFailed {
		t.Errorf("exit 4 without any recorded violation is not evidence: %+v", r)
	}
	if r := run(&verifyRun{Exit: 0, Command: "verify --negative-control", Report: &verifyReport{Violations: []string{"canary kind=comm"}}}, "negative_control"); r.Outcome != OutcomeFailed || !strings.Contains(r.Failures[0], "exited 0, want 4") {
		t.Errorf("violations in the report do not excuse a wrong exit code: the contaminated run must EXIT 4: %+v", r)
	}
	if r := run(&verifyRun{Exit: 1, Command: "verify --negative-control", Report: &verifyReport{Violations: []string{"canary kind=comm"}}}, "negative_control"); r.Outcome != OutcomeFailed {
		t.Errorf("exit 1 is a verifier failure, not the canary exit: %+v", r)
	}
	// Scheduler privacy is not exercised when the scheduler cannot be acquired.
	if r := run(goodVerify(), "scheduler_canaries"); r.State != StateNotExercised || !strings.Contains(r.Reason, "tracefs_denied") {
		t.Errorf("scheduler canaries: %+v", r)
	}
}

func TestPrivacyCanaryScannerControlsRunOnRealCanaries(t *testing.T) {
	rc := &runCtx{root: repoRoot(t), host: hostInfo()}
	row := runPrivacyScannerControls(rc, RowSpec{})
	row.ID, row.Suite, row.Subject = "privacy.scanner_controls", SuitePrivacy, Subject{Family: "go", Version: "1.27", OS: "any", Arch: "any"}
	if err := ValidateRow(row); err != nil {
		t.Fatal(err)
	}
	if row.Outcome != OutcomePassed {
		t.Fatalf("scanner controls: %v", row.Failures)
	}
	canaries, err := LoadRecorderCanaries(filepath.Join(repoRoot(t), "fixtures", "sdk", "replay", "canaries.html"))
	if err != nil || len(canaries) < 20 {
		t.Fatalf("the 03.07 recorder canaries must load: %d %v", len(canaries), err)
	}
	var total float64
	for _, s := range row.Series {
		if s.Name == "controls_total" {
			total = s.Values[0]
		}
	}
	if total < float64(len(canaries)*5) {
		t.Errorf("every canary must be run through every control: %v controls for %d canaries", total, len(canaries))
	}
	// A broken scanner (one that accepts the contamination) is detected by the controls themselves.
	for _, c := range NegativeControls(PrivacyCase{Canaries: []string{"CANARY_X_9"}, NativeNotApplicable: true,
		Surfaces: []Surface{{Name: SurfaceNetwork, Data: []byte("a")}, {Name: SurfaceRecorderQueue, Data: []byte("a")}, {Name: SurfaceExportQueue, Data: []byte("a")}, {Name: SurfaceStoredRecords, Data: []byte("a")}}}, "CANARY_Y_9") {
		if !c.Rejected && !strings.HasPrefix(c.Name, "native_config") {
			t.Errorf("control %s accepted contamination", c.Name)
		}
	}
}

// A scanner that accepts contamination, or rejects everything, is caught by the controls themselves.
func TestPrivacyCanaryBrokenScannerFailsTheControls(t *testing.T) {
	rc := &runCtx{root: repoRoot(t), host: hostInfo()}
	acceptAll := func(PrivacyCase) PrivacyVerdict { return PrivacyVerdict{Pass: true} }
	rejectAll := func(PrivacyCase) PrivacyVerdict { return PrivacyVerdict{Pass: false, Problems: []string{"always"}} }
	for name, inspect := range map[string]Inspector{"accept everything": acceptAll, "reject everything": rejectAll} {
		row := rc.scannerControlsRow(inspect)
		if row.Outcome != OutcomeFailed || len(row.Failures) == 0 {
			t.Errorf("%s: a broken scanner must fail its own controls: %+v", name, row)
		}
	}
	for _, c := range NegativeControlsWith(acceptAll, PrivacyCase{Canaries: []string{"CANARY_X_9"}, NativeNotApplicable: true}, "CANARY_Y_9") {
		if c.Rejected {
			t.Errorf("control %s reports rejection from a scanner that rejects nothing", c.Name)
		}
	}
	// A scanner that rejects for the wrong reason (a problem unrelated to the contaminated surface) is not credited.
	wrongReason := func(PrivacyCase) PrivacyVerdict { return PrivacyVerdict{Pass: false, Problems: []string{"unrelated"}} }
	for _, c := range NegativeControlsWith(wrongReason, PrivacyCase{Canaries: []string{"CANARY_X_9"}, NativeNotApplicable: true}, "CANARY_Y_9") {
		if c.Rejected {
			t.Errorf("control %s credited a rejection for the wrong reason", c.Name)
		}
	}
}

func TestQualificationNativeControlsFailWhenAControlMisbehaves(t *testing.T) {
	rc := &runCtx{host: hostInfo()}
	good := qual.RunNegativeControls()
	if r := rc.nativeControlsRow(good); r.Outcome != OutcomePassed {
		t.Fatalf("real controls: %v", r.Failures)
	}
	bad := append([]qual.NegativeControl(nil), good...)
	bad[0].Behaved = false
	if r := rc.nativeControlsRow(bad); r.Outcome != OutcomeFailed || !strings.Contains(r.Failures[0], bad[0].Name) {
		t.Errorf("a staged-sampler control that was accepted must fail the row: %+v", r)
	}
	if r := rc.nativeControlsRow(good[1:]); r.Outcome != OutcomeFailed || !strings.Contains(strings.Join(r.Failures, ";"), "required control missing") {
		t.Errorf("a missing required control must fail the row: %+v", r)
	}
	if r := rc.nativeControlsRow(nil); r.Outcome != OutcomeFailed {
		t.Errorf("no controls at all must fail: %+v", r)
	}
}

func TestPrivacyCanaryGzipOnTheWireStillCarriesTheSecret(t *testing.T) {
	const secret = "CANARY_TEXTAREA_VALUE_WWWWWWWWWWWWW"
	if bytes.Contains(canaryEncodings(secret)["gzip"], []byte(secret)) {
		t.Fatal("fixture invalid: the gzip bytes expose the secret raw")
	}
	c := PrivacyCase{Canaries: []string{secret}, NativeNotApplicable: true,
		Surfaces: []Surface{{Name: SurfaceNetwork, Data: canaryEncodings(secret)["gzip"]}, {Name: SurfaceRecorderQueue, Data: []byte("x")}, {Name: SurfaceExportQueue, Data: []byte("x")}, {Name: SurfaceStoredRecords, Data: []byte("x")}}}
	v := InspectPrivacy(c)
	if v.Pass || len(v.Findings) == 0 || v.Findings[0].Surface != SurfaceNetwork {
		t.Fatalf("a secret inside a gzip body on the network must be found: %+v", v)
	}
	// No canary and no detector means nothing was inspected: that is a failure, not a clean pass.
	if v := InspectPrivacy(PrivacyCase{NativeNotApplicable: true, Surfaces: c.Surfaces}); v.Pass {
		t.Error("inspecting with no canary must not pass")
	}
}
