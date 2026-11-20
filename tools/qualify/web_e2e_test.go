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

// webE2ECtx is a run context whose harness (web/e2e-harness/h.sh) is a shell script: the runner under test is the qualification
// code (how it drives the harness, what it requires of the report, what it refuses to call a pass), not the harness it drives.
func webE2ECtx(t *testing.T, harness string) *runCtx {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the web e2e runner drives a Linux harness")
	}
	rc := overheadCtx(t)
	dir := filepath.Join(rc.root, "web", "e2e-harness")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "h.sh"), []byte(harness), 0o755); err != nil {
		t.Fatal(err)
	}
	rc.matrix.Builds["chrome"] = BuildSpec{Family: "chrome", Version: "142.0.7444.59", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.matrix.Builds["bun"] = BuildSpec{Family: "bun", Version: "1.3.14", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["chrome"] = &probeResult{Found: true, Path: "/x/chrome", Build: Build{Family: "chrome", Version: "142.0.7444.59", OS: "linux", Arch: "amd64", ID: "sha256:c"}}
	rc.probes["bun"] = &probeResult{Found: true, Path: "/x/bun", Build: Build{Family: "bun", Version: "1.3.14", OS: "linux", Arch: "amd64", ID: "sha256:b"}}
	rc.probes["bun-1.3.14-linux-amd64"] = rc.probes["bun"]
	return rc
}

func runWebE2ERow(t *testing.T, rc *runCtx) Row {
	t.Helper()
	spec := RowSpec{ID: "runtime.critical.replay.real_backend", Suite: SuiteRuntime, Required: true, Build: "chrome", Needs: []string{"node", "bun"},
		Params: map[string]string{"spec": "e2e/replay-profile.spec.ts", "grep": "real browser SDK recorder|real recorder", "min_tests": "2"}}
	row := runWebE2E(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatalf("web e2e runner produced an invalid row: %v", err)
	}
	return row
}

// report is the Playwright JSON report a fake harness writes where the runner asked for it.
func report(titles map[string]string) string {
	var specs []string
	for title, status := range titles {
		specs = append(specs, `{"title":`+quote(title)+`,"tests":[{"status":"`+status+`","results":[]}]}`)
	}
	return `{"suites":[{"title":"e2e/replay-profile.spec.ts","specs":[` + strings.Join(specs, ",") + `]}],"errors":[]}`
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

const harnessHeader = "#!/bin/sh\necho \"$*\" >> \"$0.calls\"\nenv | grep -E '^(E2E_|CHROME=|SOUNDPOST_BUN=|PLAYWRIGHT_JSON_OUTPUT_NAME=)' | sort > \"$0.env.$1\"\n"

func TestWebE2EPassesOnlyOnWhatTheHarnessObserved(t *testing.T) {
	good := report(map[string]string{
		"a replay recorded by the real browser SDK recorder in a real page is delivered": "expected",
		"a replay of the real recorder is gone for a reader who lacks replay.read":       "expected",
	})
	rc := webE2ECtx(t, harnessHeader+`case "$1" in prep) echo prep-ok;; run) cat > "$PLAYWRIGHT_JSON_OUTPUT_NAME" <<'EOF'
`+good+`
EOF
;; esac
`)
	row := runWebE2ERow(t, rc)
	if row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("two matched passing tests through a real harness run are a pass: %+v", row)
	}
	calls, _ := os.ReadFile(filepath.Join(rc.root, "web", "e2e-harness", "h.sh.calls"))
	for _, want := range []string{"prep", "run pw oidc --reporter=json e2e/replay-profile.spec.ts -g real browser SDK recorder|real recorder"} {
		if !strings.Contains(string(calls), want) {
			t.Errorf("the harness must be called with %q, got:\n%s", want, calls)
		}
	}
	env, _ := os.ReadFile(filepath.Join(rc.root, "web", "e2e-harness", "h.sh.env.run"))
	for _, want := range []string{"CHROME=/x/chrome", "SOUNDPOST_BUN=/x/bun", "E2E_P=qual-", "E2E_PORT=", "E2E_OIDC_PORT="} {
		if !strings.Contains(string(env), want) {
			t.Errorf("the run must see %q (the pinned browser, the pinned bundler, a private port pair), got:\n%s", want, env)
		}
	}
	if row.Build == nil || row.Build.Family != "chrome" || len(row.Series) == 0 {
		t.Errorf("the row names the pinned browser and carries the counts: %+v", row)
	}
}

func TestWebE2ENeverPassesWithoutAMatchingPassingReport(t *testing.T) {
	one := report(map[string]string{"a replay recorded by the real browser SDK recorder in a real page": "expected"})
	failing := report(map[string]string{
		"a replay recorded by the real browser SDK recorder in a real page": "expected",
		"a replay of the real recorder is gone for a reader":                "unexpected",
	})
	skipped := report(map[string]string{
		"a replay recorded by the real browser SDK recorder in a real page": "expected",
		"a replay of the real recorder is gone for a reader":                "skipped",
	})
	green := report(map[string]string{"a replay recorded by the real browser SDK recorder": "expected", "a replay of the real recorder": "expected"})
	write := func(json string) string { return `printf '%s' '` + json + `' > "$PLAYWRIGHT_JSON_OUTPUT_NAME"` }
	for _, c := range []struct{ name, script, want string }{
		{"a failing test", `case "$1" in prep) echo prep-ok;; run) ` + write(failing) + `; exit 1;; esac`, "finished unexpected"},
		{"a skipped test", `case "$1" in prep) echo prep-ok;; run) ` + write(skipped) + `;; esac`, "finished skipped"},
		{"fewer matched tests than the row needs", `case "$1" in prep) echo prep-ok;; run) ` + write(one) + `;; esac`, "at least 2"},
		{"a clean exit with no report", `case "$1" in prep) echo prep-ok;; run) exit 0;; esac`, "no report"},
		{"a failing exit with a green report", `case "$1" in prep) echo prep-ok;; run) ` + write(green) + `; exit 1;; esac`, "exited 1"},
	} {
		name := c.name
		rc := webE2ECtx(t, harnessHeader+c.script+"\n")
		row := runWebE2ERow(t, rc)
		if row.State != StateExercised || row.Outcome != OutcomeFailed || !strings.Contains(strings.Join(row.Failures, " "), c.want) {
			t.Errorf("%s must be a measured failure naming %q: %+v", name, c.want, row)
		}
	}
}

func TestWebE2EReportsAHarnessItCouldNotPrepareAsNotExercised(t *testing.T) {
	rc := webE2ECtx(t, harnessHeader+`case "$1" in prep) echo "the real native capture failed: perf_event_paranoid" >&2; exit 1;; esac`+"\n")
	row := runWebE2ERow(t, rc)
	if row.State != StateNotExercised || !strings.Contains(row.Reason, "perf_event_paranoid") {
		t.Fatalf("a harness that cannot prepare never ran a test: not exercised, with the harness's own reason: %+v", row)
	}
	if _, err := os.Stat(filepath.Join(rc.root, "web", "e2e-harness", "h.sh.env.run")); err == nil {
		t.Error("no test run may follow a failed prepare")
	}
}

func TestWebE2EWithoutItsHarnessOrBrowserIsNotExercised(t *testing.T) {
	rc := webE2ECtx(t, "#!/bin/sh\nexit 0\n")
	if err := os.Remove(filepath.Join(rc.root, "web", "e2e-harness", "h.sh")); err != nil {
		t.Fatal(err)
	}
	if row := runWebE2ERow(t, rc); row.State != StateNotExercised || !strings.Contains(row.Reason, "h.sh") {
		t.Errorf("no harness: %+v", row)
	}
	rc = webE2ECtx(t, "#!/bin/sh\nexit 0\n")
	rc.probes["chrome"] = &probeResult{Reason: "no Chrome 142 here"}
	if row := runWebE2ERow(t, rc); row.State != StateNotExercised || !strings.Contains(row.Reason, "no Chrome 142 here") {
		t.Errorf("no pinned browser: %+v", row)
	}
}

// 03.09-C6: the Node, Bun and Python SDK profile records are proven through the same harness. A runtime row names the runtime as its build and
// the pinned Chrome (which only drives the product console) among its needs; the runtime reaches the harness through the variable its
// driver reads, and the harness is prepared once however many rows use it.
func TestWebE2ERuntimeRowsHandTheirRuntimeToTheHarnessAndPrepareOnce(t *testing.T) {
	one := pwReportJSON(map[string]string{"a profile produced by the real SDK is delivered": "expected"})
	rc := webE2ECtx(t, harnessHeader+`case "$1" in prep) echo prep-ok;; run) printf '%s' '`+one+`' > "$PLAYWRIGHT_JSON_OUTPUT_NAME";; esac`+"\n")
	for key, b := range map[string]Build{
		"node24": {Family: "node", Version: "24.11.0", OS: "linux", Arch: "amd64", ID: "sha256:n"},
		"py313":  {Family: "python", Version: "3.13.18", OS: "linux", Arch: "amd64", ID: "sha256:p"},
	} {
		rc.matrix.Builds[key] = BuildSpec{Family: b.Family, Version: b.Version, OS: "linux", Arch: "amd64", Absent: "x"}
		rc.probes[key] = &probeResult{Found: true, Path: "/x/" + key + "/bin/" + b.Family, Build: b}
	}
	row := func(key, grep string) Row {
		t.Helper()
		spec := RowSpec{ID: "runtime.profile." + key, Suite: SuiteRuntime, Required: true, Build: key, Needs: []string{"chrome", "bun"},
			Params: map[string]string{"spec": "e2e/replay-profile.spec.ts", "grep": grep, "min_tests": "1"}}
		r := runWebE2E(rc, spec)
		r.ID, r.Suite, r.Required, r.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
		if err := ValidateRow(r); err != nil {
			t.Fatalf("invalid row: %v", err)
		}
		return r
	}
	envOf := func() string {
		raw, _ := os.ReadFile(filepath.Join(rc.root, "web", "e2e-harness", "h.sh.env.run"))
		return string(raw)
	}
	if r := row("node24", "real Node SDK"); r.Outcome != OutcomePassed || r.Build.Family != "node" || r.Build.Version != "24.11.0" {
		t.Fatalf("a Node row is the Node build: %+v", r)
	}
	if env := envOf(); !strings.Contains(env, "E2E_NODE=/x/node24/bin/node") || !strings.Contains(env, "CHROME=/x/chrome") {
		t.Errorf("the Node row hands its Node to the driver and drives the console in the pinned Chrome:\n%s", env)
	}
	if r := row("py313", "real Python SDK"); r.Outcome != OutcomePassed || r.Build.Family != "python" {
		t.Fatalf("a Python row is the Python build: %+v", r)
	}
	if env := envOf(); !strings.Contains(env, "E2E_PYTHON=/x/py313/bin/python") || strings.Contains(env, "E2E_NODE=") {
		t.Errorf("the Python row hands its interpreter to the driver and no other runtime:\n%s", env)
	}
	calls, _ := os.ReadFile(filepath.Join(rc.root, "web", "e2e-harness", "h.sh.calls"))
	if n := strings.Count(string(calls), "prep\n"); n != 1 {
		t.Errorf("the harness is prepared once per suite, got %d prepares:\n%s", n, calls)
	}
	// A runtime row without a Chrome in its needs has no browser for the console: not exercised, nothing run.
	spec := RowSpec{ID: "runtime.profile.node24", Suite: SuiteRuntime, Build: "node24", Needs: []string{"bun"}, Params: map[string]string{"spec": "e2e/x.spec.ts", "grep": "x", "min_tests": "1"}}
	if r := runWebE2E(rc, spec); r.State != StateNotExercised || !strings.Contains(r.Reason, "Chrome") {
		t.Errorf("no console browser: %+v", r)
	}
}
