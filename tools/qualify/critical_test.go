// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// criticalCtx is a run context whose committed critical command and product binary are replaced by a shell script: the runner under
// test is the qualification code (argument mapping, prerequisite refusals, verdict), not the command it drives.
func criticalCtx(t *testing.T, script string) (*runCtx, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the critical-path runner is Unix only")
	}
	rc := overheadCtx(t)
	tool := filepath.Join(t.TempDir(), "critical")
	body := "#!/bin/sh\nout=\nfor a in \"$@\"; do if [ \"$prev\" = --out ]; then out=$a; fi; prev=$a; done\necho \"$@\" > \"" + tool + ".args\"\n" + script
	if err := os.WriteFile(tool, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	rc.cache["tool:critical"] = [2]string{tool, ""}
	rc.cache["tool:soundpost-critical"] = [2]string{"/x/soundpost", ""}
	venv := t.TempDir()
	if err := os.WriteFile(filepath.Join(venv, "pyvenv.cfg"), []byte("home = /usr\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The pinned interpreter inside the venv reports no missing integration module unless a test says otherwise.
	if err := os.MkdirAll(filepath.Join(venv, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venv, "bin", "python"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rc.matrix.Builds["bun"] = BuildSpec{Family: "bun", Version: "1.3.14", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.matrix.Builds["py"] = BuildSpec{Family: "python", Version: "3.13", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["bun"] = &probeResult{Found: true, Path: "/x/bun", Build: Build{Family: "bun", Version: "1.3.14", OS: "linux", Arch: "amd64", ID: "sha256:b"}}
	rc.probes["py"] = &probeResult{Found: true, Path: filepath.Join(venv, "bin", "python"), Build: Build{Family: "python", Version: "3.13.5", OS: "linux", Arch: "amd64", ID: "sha256:p"}}
	return rc, tool
}

func runCritical(t *testing.T, rc *runCtx, build, mode string) Row {
	t.Helper()
	spec := RowSpec{ID: "runtime.critical.x", Suite: SuiteRuntime, Build: build, Params: map[string]string{"mode": mode}}
	row := runSDKCriticalPath(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("critical-path runner produced an invalid row: %v", err)
	}
	return row
}

const okRows = `printf '%s' '{"rows":[{"fixture":"fixtures/sdk/bun/gateway.ts","exit_code":0}]}' > "$out"` + "\n"

func TestCriticalPathPassesOnlyOnWhatTheCommandObserved(t *testing.T) {
	rc, tool := criticalCtx(t, okRows)
	row := runCritical(t, rc, "bun", "gateway")
	if row.Outcome != OutcomePassed || row.State != StateExercised || len(row.Series) != 1 || row.Series[0].Values[0] != 1 {
		t.Fatalf("a command that exited 0 with one verified row is a pass: %+v", row)
	}
	args, _ := os.ReadFile(tool + ".args")
	for _, want := range []string{"--mode gateway", "--bun /x/bun", "--binary /x/soundpost", "--root " + rc.root} {
		if !strings.Contains(string(args), want) {
			t.Errorf("the command must be told %q: %s", want, args)
		}
	}
	for name, script := range map[string]string{
		"a failing exit":            "echo 'read-back found 0 server spans' >&2\nexit 3\n",
		"a row that reports a fail": `printf '%s' '{"rows":[{"fixture":"f","exit_code":1}]}' > "$out"` + "\n",
		"a failing exit after rows": `printf '%s' '{"rows":[{"fixture":"f","exit_code":0}]}' > "$out"` + "\necho 'gateway close exit 1' >&2\nexit 3\n",
		"no rows":                   `printf '%s' '{"rows":[]}' > "$out"` + "\n",
		"no result file":            "exit 0\n",
	} {
		rc, _ := criticalCtx(t, script)
		row := runCritical(t, rc, "bun", "gateway")
		if row.Outcome != OutcomeFailed || row.State != StateExercised || len(row.Failures) == 0 {
			t.Errorf("%s must be a measured failure, got %+v", name, row)
		}
		rep := SuiteReport{Rows: []Row{row}}
		rep.Verdict()
		if rep.ExitCode != ExitFail {
			t.Errorf("%s must block the claim, exit %d", name, rep.ExitCode)
		}
	}
}

func TestCriticalPathNeverRunsWithoutItsPrerequisites(t *testing.T) {
	marker := func(tool string) bool { _, err := os.Stat(tool + ".args"); return err == nil }
	// The database paths need Docker and the pinned PostgreSQL image; their absence is the stated reason, and the command is not run.
	rc, tool := criticalCtx(t, okRows)
	old := criticalPGPresent
	defer func() { criticalPGPresent = old }()
	criticalPGPresent = func(*runCtx) string { return "this host has no docker on PATH" }
	if row := runCritical(t, rc, "py", "python"); row.State != StateNotExercised || !strings.Contains(row.Reason, "docker") || marker(tool) {
		t.Errorf("no PostgreSQL: not exercised, command not run: %+v", row)
	}
	// Without the database requirement (jobs) the command runs with the pinned interpreter's own virtual environment.
	if row := runCritical(t, rc, "py", "jobs"); row.Outcome != OutcomePassed || !marker(tool) {
		t.Errorf("python jobs do not need PostgreSQL: %+v", row)
	}
	args, _ := os.ReadFile(tool + ".args")
	if !strings.Contains(string(args), "--python 3.13="+filepath.Dir(filepath.Dir(rc.probes["py"].Path))) {
		t.Errorf("the pinned Python's venv and label must reach the command: %s", args)
	}
	criticalPGPresent = func(*runCtx) string { return "" }
	if row := runCritical(t, rc, "py", "python"); row.Outcome != OutcomePassed {
		t.Errorf("with PostgreSQL present the python path runs: %+v", row)
	}
	// A bare system interpreter (no pyvenv.cfg) is not a qualified runner for the SDK integration dependencies.
	rc2, tool2 := criticalCtx(t, okRows)
	rc2.probes["py"].Path = "/usr/bin/python3"
	if row := runCritical(t, rc2, "py", "jobs"); row.State != StateNotExercised || !strings.Contains(row.Reason, "virtual environment") || marker(tool2) {
		t.Errorf("a bare interpreter must not run the Python critical path: %+v", row)
	}
	// A mode that belongs to another runner is refused, not silently run with the wrong interpreter.
	rc3, tool3 := criticalCtx(t, okRows)
	if row := runCritical(t, rc3, "py", "gateway"); row.State != StateNotExercised || marker(tool3) {
		t.Errorf("gateway under Python must be refused: %+v", row)
	}
	if row := runCritical(t, rc3, "bun", "nonsense"); row.State != StateNotExercised {
		t.Errorf("an unknown mode must be refused: %+v", row)
	}
	// An absent pinned runner is the probe's own reason.
	rc3.probes["bun"] = &probeResult{Reason: "no Bun 1.3.14 linux/amd64 build was found"}
	if row := runCritical(t, rc3, "bun", "gateway"); row.State != StateNotExercised || !strings.Contains(row.Reason, "no Bun") || marker(tool3) {
		t.Errorf("absent runner: %+v", row)
	}
}

// 03.06-C9: the Python jobs rows failed on the real-kernel VMs because the qualification virtual environments held the development
// lock, not the integration lock, so the fixture died on `import celery` and the row was reported as a failure of the SDK. A venv
// that lacks what the committed command imports is a missing prerequisite (stated, with the lock to install), never a pass or a fail.
func TestPythonCriticalPathNeverRunsInAVenvWithoutTheIntegrationLock(t *testing.T) {
	marker := func(tool string) bool { _, err := os.Stat(tool + ".args"); return err == nil }
	missing := func(rc *runCtx, modules string) {
		python := rc.probes["py"].Path
		body := "#!/bin/sh\necho " + modules + "\n"
		if err := os.WriteFile(python, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	rc, tool := criticalCtx(t, okRows)
	missing(rc, "celery kombu")
	row := runCritical(t, rc, "py", "jobs")
	if row.State != StateNotExercised || !strings.Contains(row.Reason, "celery") || !strings.Contains(row.Reason, "requirements-integrations.lock") || marker(tool) {
		t.Fatalf("a venv without Celery must be not exercised with the lock named, command not run: %+v", row)
	}
	old := criticalPGPresent
	defer func() { criticalPGPresent = old }()
	criticalPGPresent = func(*runCtx) string { return "" }
	rc2, tool2 := criticalCtx(t, okRows)
	missing(rc2, "psycopg")
	if row := runCritical(t, rc2, "py", "python"); row.State != StateNotExercised || !strings.Contains(row.Reason, "psycopg") || marker(tool2) {
		t.Fatalf("a venv without the HTTP/DB integration modules must be not exercised: %+v", row)
	}
	// An interpreter that cannot even run the probe is reported as such, not as missing modules.
	rc3, tool3 := criticalCtx(t, okRows)
	if err := os.WriteFile(rc3.probes["py"].Path, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if row := runCritical(t, rc3, "py", "jobs"); row.State != StateNotExercised || !strings.Contains(row.Reason, "could not be probed") || marker(tool3) {
		t.Fatalf("a broken interpreter must be not exercised: %+v", row)
	}
	// The pinned Bun has no Python lock to check.
	rc4, _ := criticalCtx(t, okRows)
	if row := runCritical(t, rc4, "bun", "jobs"); row.Outcome != OutcomePassed {
		t.Fatalf("bun jobs: %+v", row)
	}
}

// The database paths name the PostgreSQL 16 image by its manifest digest, the same pin fixtures/sdk/compose.yaml carries. A bare id
// prefix (92620daddcd9) is the digest only on a containerd image store; on a classic overlay2 daemon (Docker 26 on the second host)
// the pulled pin has image id 67d1da22... and `docker image inspect 92620daddcd9` finds nothing, so the rows were never exercised there.
// Every place that defaults the image must carry the same digest reference.
func TestCriticalPostgresImageIsTheCommittedDigestPin(t *testing.T) {
	compose, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "sdk", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var pin string
	for _, line := range strings.Split(string(compose), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "image: postgres@sha256:"); ok {
			pin = "postgres@sha256:" + strings.TrimSpace(rest)
		}
	}
	if len(pin) != len("postgres@sha256:")+64 {
		t.Fatalf("fixtures/sdk/compose.yaml carries no full postgres digest pin: %q", pin)
	}
	if criticalPGImage != pin {
		t.Errorf("criticalPGImage = %q, want the committed pin %q (a bare id prefix does not resolve on a classic image store)", criticalPGImage, pin)
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "sdk", "critical", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"pg-image", "`+pin+`"`) {
		t.Errorf("fixtures/sdk/critical/main.go: the --pg-image default is not the committed digest pin %s", pin)
	}
	// The journeys smoke has no default of its own: an empty --pg-image leaves the digest examples/reference/compose.yaml names, which must be
	// this pin, and the smoke's own flag must not carry a short id again.
	refCompose, err := os.ReadFile(filepath.Join("..", "..", "examples", "reference", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(refCompose), "${REFERENCE_PG_IMAGE:-"+pin+"}") {
		t.Errorf("examples/reference/compose.yaml: the PostgreSQL image default is not the committed digest pin %s", pin)
	}
	journeys, err := os.ReadFile(filepath.Join("..", "smoke", "journeys.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(journeys), "92620daddcd9\"") {
		t.Error("tools/smoke/journeys.go carries the short id 92620daddcd9 again")
	}
}

// 03.09-C11: a Node row's critical path runs under THAT Node. The browser path (real browser to an Express backend to a dependency and
// PostgreSQL 16) used to be reachable only through a browser row with a Node 22 backend, and the Node job-attempt journey through no row,
// so Node 24 had neither. A Node row names its own interpreter as the backend (--node) and the browser or the bundler as its needs.
func TestCriticalPathNodeRowsRunTheBrowserAndJobPathsUnderTheirOwnNode(t *testing.T) {
	old := criticalPGPresent
	defer func() { criticalPGPresent = old }()
	criticalPGPresent = func(*runCtx) string { return "" }
	rc, tool := criticalCtx(t, okRows)
	rc.matrix.Builds["chrome"] = BuildSpec{Family: "chrome", Version: "142.0.7444.59", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["chrome"] = &probeResult{Found: true, Path: "/x/chrome", Build: Build{Family: "chrome", Version: "142.0.7444.59", OS: "linux", Arch: "amd64", ID: "sha256:c"}}
	run := func(rc *runCtx, spec RowSpec) Row {
		t.Helper()
		row := runSDKCriticalPath(rc, spec)
		row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
		if err := ValidateRow(row); err != nil {
			t.Fatalf("critical-path runner produced an invalid row: %v", err)
		}
		return row
	}
	browser := RowSpec{ID: "runtime.critical.node-24.linux-amd64.http_db_errors", Suite: SuiteRuntime, Build: "node", Needs: []string{"chrome", "bun"}, Params: map[string]string{"mode": "browser", "target": "Chrome"}}
	if row := run(rc, browser); row.Outcome != OutcomePassed {
		t.Fatalf("a Node row's browser path runs: %+v", row)
	}
	args, _ := os.ReadFile(tool + ".args")
	for _, want := range []string{"--mode browser", "--browsers Chrome=/x/chrome", "--node /x/node", "--bun /x/bun"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("the Node row's backend is its own Node and the browser is its need: want %q in %s", want, args)
		}
	}
	jobs := RowSpec{ID: "runtime.critical.node-24.linux-amd64.jobs", Suite: SuiteRuntime, Build: "node", Needs: []string{"bun"}, Params: map[string]string{"mode": "jobs"}}
	if row := run(rc, jobs); row.Outcome != OutcomePassed {
		t.Fatalf("a Node row's job-attempt path runs: %+v", row)
	}
	args, _ = os.ReadFile(tool + ".args")
	for _, want := range []string{"--mode jobs", "--node /x/node", "--bun /x/bun"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("the Node job path runs the Node SDK under the row's Node, bundled by the pinned Bun: want %q in %s", want, args)
		}
	}
	// The existing shape (a browser row with a Node and a Bun in its needs) is unchanged.
	legacy := RowSpec{ID: "runtime.browser.chrome-142.linux-amd64.core", Suite: SuiteRuntime, Build: "chrome", Needs: []string{"node", "bun"}, Params: map[string]string{"mode": "browser", "target": "Chrome"}}
	if row := run(rc, legacy); row.Outcome != OutcomePassed {
		t.Fatalf("a browser row with a Node backend need runs: %+v", row)
	}
	args, _ = os.ReadFile(tool + ".args")
	if !strings.Contains(string(args), "--browsers Chrome=/x/chrome") || !strings.Contains(string(args), "--node /x/node") {
		t.Errorf("browser row arguments: %s", args)
	}
	// Without its Bun a Node row names what is missing and runs nothing.
	rc2, tool2 := criticalCtx(t, okRows)
	rc2.probes["bun"] = &probeResult{Reason: "no Bun 1.3.14 linux/amd64 build was found"}
	if row := run(rc2, jobs); row.State != StateNotExercised || !strings.Contains(row.Reason, "no Bun") {
		t.Errorf("a Node job row without Bun: %+v", row)
	}
	if _, err := os.Stat(tool2 + ".args"); err == nil {
		t.Error("the command must not run without the Bun that bundles the Node SDK")
	}
}
