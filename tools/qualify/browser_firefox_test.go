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

// pwCtx is a run context whose Playwright driver ("node") is a shell script that records the environment it was given and prints a
// Playwright JSON report: the code under test is how a browser build is handed to the committed configs, not Playwright itself.
func pwCtx(t *testing.T, titles map[string]string) (*runCtx, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the Playwright rows run on Linux hosts")
	}
	rc := overheadCtx(t)
	for _, dir := range []string{filepath.Join("web", "node_modules", "@playwright", "test"), filepath.Join("fixtures", "sdk", "firefox")} {
		if err := os.MkdirAll(filepath.Join(rc.root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join("web", "node_modules", "@playwright", "test", "cli.js"), filepath.Join("fixtures", "sdk", "firefox", "firefox-bidi")} {
		if err := os.WriteFile(filepath.Join(rc.root, f), []byte("#!/bin/sh\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	envFile := filepath.Join(t.TempDir(), "env")
	node := filepath.Join(t.TempDir(), "node")
	script := "#!/bin/sh\nenv | grep -E '^(SOUNDPOST_CHROME|SOUNDPOST_FIREFOX|SOUNDPOST_BUN)=' | sort > " + envFile + "\nprintf '%s' '" + pwReportJSON(titles) + "'\n"
	if err := os.WriteFile(node, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	rc.matrix.Builds["node-22-linux-amd64"] = BuildSpec{Family: "node", Version: "22", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["node-22-linux-amd64"] = &probeResult{Found: true, Path: node, Build: Build{Family: "node", Version: "22.21.1", OS: "linux", Arch: "amd64", ID: "sha256:n"}}
	rc.matrix.Builds["bun-1.3.14-linux-amd64"] = BuildSpec{Family: "bun", Version: "1.3.14", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["bun-1.3.14-linux-amd64"] = &probeResult{Found: true, Path: "/x/bun", Build: Build{Family: "bun", Version: "1.3.14", OS: "linux", Arch: "amd64", ID: "sha256:b"}}
	return rc, envFile
}

func pwReportJSON(titles map[string]string) string {
	var specs []string
	for title, status := range titles {
		specs = append(specs, `{"title":"`+title+`","tests":[{"status":"`+status+`","results":[]}]}`)
	}
	return `{"suites":[{"title":"x","specs":[` + strings.Join(specs, ",") + `]}],"errors":[]}`
}

// The committed configs read both variables and a set SOUNDPOST_FIREFOX makes them run ONLY the Firefox project. The operator's shell may
// export both (a host that holds Chrome and Firefox does), so the row's own browser is handed over and the other variable is emptied: a
// Chromium row is never a Firefox run, and a Firefox row is never a Chromium run.
func TestPlaywrightRowsHandTheBuildToTheConfigByItsFamily(t *testing.T) {
	for _, c := range []struct {
		family, path, want, notWant string
	}{
		{"chrome", "/x/chrome", "SOUNDPOST_CHROME=/x/chrome", "SOUNDPOST_FIREFOX=/"},
		{"edge", "/x/msedge", "SOUNDPOST_CHROME=/x/msedge", "SOUNDPOST_FIREFOX=/"},
		{"firefox", "/x/firefox", "SOUNDPOST_FIREFOX=/x/firefox", "SOUNDPOST_CHROME=/"},
	} {
		t.Setenv("SOUNDPOST_CHROME", "/leaked/chrome")
		t.Setenv("SOUNDPOST_FIREFOX", "/leaked/firefox")
		rc, envFile := pwCtx(t, map[string]string{"Profiler removed": "expected"})
		rc.matrix.Builds["b"] = BuildSpec{Family: c.family, Version: "1", OS: "linux", Arch: "amd64", Absent: "x"}
		rc.probes["b"] = &probeResult{Found: true, Path: c.path, Build: Build{Family: c.family, Version: "1.0", OS: "linux", Arch: "amd64", ID: "sha256:z"}}
		spec := RowSpec{ID: "runtime.browser.x", Suite: SuiteRuntime, Required: true, Build: "b", Params: map[string]string{"config": "fixtures/sdk/profiles/playwright.config.ts", "spec": "browser.spec.ts", "title": "Profiler removed", "on_pass": "exercised"}}
		row := runPlaywrightTest(rc, spec)
		if row.State != StateExercised || row.Outcome != OutcomePassed {
			t.Fatalf("%s: %+v", c.family, row)
		}
		env, _ := os.ReadFile(envFile)
		if !strings.Contains(string(env), c.want) || strings.Contains(string(env), c.notWant) {
			t.Errorf("%s: the config must see %q and not %q, got:\n%s", c.family, c.want, c.notWant, env)
		}
		if c.family == "firefox" {
			// Playwright spawns the launcher by path: it must be executable whatever mode the checkout carried.
			st, err := os.Stat(filepath.Join(rc.root, "fixtures", "sdk", "firefox", "firefox-bidi"))
			if err != nil || st.Mode().Perm()&0o111 == 0 {
				t.Errorf("the Firefox launcher must be executable: %v %v", st, err)
			}
		}
	}
}

// A Firefox profile row EXERCISES the feature detection of a browser that has no JS Self-Profiling API: the harness ran, the assertions of the
// absence rows held (unsupported, zero samples, the page keeps running), and the observed capability is an `unsupported` reading with its
// reason and no number. A required row that came out `unsupported` as its own state could never qualify (an unqualified required row blocks
// the claim), so the capability lives in the reading; the rows that need the Chromium API are skipped by the spec itself and are not matched.
func TestFirefoxSampleCapabilityIsExercisedAndReadsUnsupportedNeverZero(t *testing.T) {
	rc, _ := pwCtx(t, map[string]string{"Profiler removed: unsupported, zero samples, the page keeps running": "expected", "with the Document-Policy header: genuine samples": "skipped"})
	rc.matrix.Builds["ff"] = BuildSpec{Family: "firefox", Version: "144.0.2", OS: "linux", Arch: "amd64", Absent: "x"}
	rc.probes["ff"] = &probeResult{Found: true, Path: "/x/firefox", Build: Build{Family: "firefox", Version: "144.0.2", OS: "linux", Arch: "amd64", ID: "sha256:f"}}
	spec := RowSpec{ID: "runtime.browser.firefox-144.sample_capability", Suite: SuiteRuntime, Required: true, Build: "ff", Params: map[string]string{
		"config": "fixtures/sdk/profiles/playwright.config.ts", "spec": "browser.spec.ts", "title": "Profiler removed", "on_pass": "exercised",
		"observed_unsupported": "js_self_profiling_unavailable: stock Firefox exposes no Profiler constructor"}}
	row := runPlaywrightTest(rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, rc.subject(spec)
	if err := ValidateRow(row); err != nil {
		t.Fatal(err)
	}
	if row.State != StateExercised || row.Outcome != OutcomePassed || len(row.Readings) != 1 {
		t.Fatalf("the detection ran and held: an exercised, passed row with one reading: %+v", row)
	}
	if rd := row.Readings[0]; rd.Availability != AvailUnsupported || rd.Value != nil || !strings.Contains(rd.Reason, "js_self_profiling_unavailable") {
		t.Errorf("the capability reads unsupported with its reason and no number: %+v", rd)
	}
	// The absence rows failing is a measured failure, never an unsupported capability.
	rc2, _ := pwCtx(t, map[string]string{"Profiler removed: unsupported, zero samples, the page keeps running": "unexpected"})
	rc2.matrix.Builds["ff"], rc2.probes["ff"] = rc.matrix.Builds["ff"], rc.probes["ff"]
	if r := runPlaywrightTest(rc2, spec); r.State != StateExercised || r.Outcome != OutcomeFailed || len(r.Readings) != 0 {
		t.Errorf("a failing absence row is a measured failure: %+v", r)
	}
}
