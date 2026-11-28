// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// webE2EPrepared is what the harness prints when `h.sh prep` finished: the dependencies are installed, the product and the console are built
// and the native profile fixture was captured for real (the harness never substitutes a synthetic profile).
const webE2EPrepared = "prep-ok"

// freePorts returns n distinct free loopback TCP ports. The harness of another run (or another lane) may hold its default ports, so a
// qualification run never takes them.
func freePorts(n int) ([]int, error) {
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	ports := make([]int, 0, n)
	for range n {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		listeners = append(listeners, l)
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}

// webHarness is the prepared end-to-end harness of one RunSuite: prepared once (it installs the workspace, builds the product and the console
// and captures a real native profile), then every row starts its own fresh server through it.
type webHarness struct {
	script string
	env    []string
	report string
	why    string // set when the harness could not be prepared: no row ran a test
}

// webE2E prepares the harness once per RunSuite. node is the Node whose directory heads PATH for the build steps of `prep` (tsc, vite).
func (rc *runCtx) webE2E(bun, node string) *webHarness {
	if v, ok := rc.cache["webe2e"]; ok {
		return v.(*webHarness)
	}
	h := &webHarness{script: filepath.Join(rc.root, "web", "e2e-harness", "h.sh"), report: filepath.Join(rc.work, "e2e-report.json")}
	rc.cache["webe2e"] = h
	if _, err := os.Stat(h.script); err != nil {
		h.why = "web/e2e-harness/h.sh is not in this checkout"
		return h
	}
	ports, err := freePorts(2)
	if err != nil {
		h.why = "no free loopback port for the harness: " + err.Error()
		return h
	}
	id := fmt.Sprintf("qual-%d", os.Getpid())
	h.env = []string{
		"E2E_P=" + id, "E2E_PORT=" + strconv.Itoa(ports[0]), "E2E_OIDC_PORT=" + strconv.Itoa(ports[1]), "E2E_OUT=" + filepath.Join(rc.work, "e2e-out"),
		"SOUNDPOST_BIN=" + filepath.Join(rc.work, "soundpost-e2e"), "SOUNDPOST_BUN=" + bun, "PLAYWRIGHT_JSON_OUTPUT_NAME=" + h.report, "CI=1",
	}
	if node != "" {
		h.env = append(h.env, "PATH="+filepath.Dir(node)+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	rc.cleanups = append(rc.cleanups, func() { _ = os.RemoveAll(filepath.Join(os.TempDir(), id+"-"+strconv.Itoa(ports[0]))) })
	prep := rc.exec(45*time.Minute, rc.root, h.env, "sh", h.script, "prep")
	if prep.Exit != 0 || prep.Err != nil || !strings.Contains(prep.Stdout, webE2EPrepared) {
		why := tail(rc.rel(prep.Stderr), 400)
		if why == "" {
			why = tail(rc.rel(prep.Stdout), 400)
		}
		h.why = fmt.Sprintf("the web e2e harness could not prepare (exit %d), so no test ran: %s", prep.Exit, why)
	}
	return h
}

// runtimeEnv are the variables through which the harness's SDK-profile drivers take the runtime of a row (web/e2e/replay-profile.spec.ts).
var runtimeEnv = map[string]string{"node": "E2E_NODE", "bun": "E2E_BUN", "python": "E2E_PYTHON"}

// runWebE2E runs named tests of the committed web end-to-end suite (web/e2e, harness web/e2e-harness/h.sh): a REAL `soundpost serve` over
// HTTPS with a private CA, a real SDK (the browser SDK in the pinned browser, or the Node, Bun or Python SDK of the row's runtime) delivering
// by its own transport, and the product's own console reading what was delivered. The row's build is the pinned browser or the pinned runtime
// (then the browser is the Chrome of its needs, which only drives the console). The row is exercised only by what Playwright reported:
// every matched test passed and at least min_tests matched. A harness that cannot prepare (a dependency, the real native capture the suite
// needs) never ran a test and is reported as not exercised with its own words; a failing test is a measured failure.
func runWebE2E(rc *runCtx, spec RowSpec) Row {
	p := rc.probe(spec.Build)
	if !p.Found {
		return notExercised(p.Reason)
	}
	if why := rc.needsMissing(spec); why != "" {
		return notExercised(why)
	}
	if runtime.GOOS != "linux" {
		return notExercised("the web e2e harness (web/e2e-harness/h.sh) runs on Linux hosts only")
	}
	specFile, grep := spec.Params["spec"], spec.Params["grep"]
	minTests, _ := strconv.Atoi(spec.Params["min_tests"])
	if specFile == "" || grep == "" || minTests < 1 {
		return notExercised(fmt.Sprintf("the matrix row names no spec, title pattern or minimum test count (%q, %q, %q)", specFile, grep, spec.Params["min_tests"]))
	}
	needs := map[string]*probeResult{}
	for _, n := range spec.Needs {
		needs[rc.probe(n).Build.Family] = rc.probe(n)
	}
	browser, runtimeBuild := p, (*probeResult)(nil)
	if fam := p.Build.Family; fam != "chrome" && fam != "edge" {
		browser, runtimeBuild = needs["chrome"], p
		if browser == nil {
			return notExercised("a row of a runtime drives the product console in the pinned Chrome, and this row's needs name none")
		}
	}
	bun, why := rc.bunForBundling()
	if why != "" {
		return notExercised(why)
	}
	node := ""
	if runtimeBuild != nil && runtimeBuild.Build.Family == "node" {
		node = runtimeBuild.Path
	} else if nb := needs["node"]; nb != nil {
		node = nb.Path
	}
	h := rc.webE2E(bun, node)
	if h.why != "" {
		return notExercised(h.why)
	}
	env := append([]string{"CHROME=" + browser.Path}, h.env...)
	if runtimeBuild != nil {
		name, ok := runtimeEnv[runtimeBuild.Build.Family]
		if !ok {
			return notExercised("the web e2e harness has no driver for a " + runtimeBuild.Build.Family + " runtime")
		}
		env = append(env, name+"="+runtimeBuild.Path)
	}
	_ = os.Remove(h.report)
	args := []string{h.script, "run", "pw", "oidc", "--reporter=json", specFile, "-g", grep}
	res := rc.exec(60*time.Minute, rc.root, env, "sh", args...)
	row := Row{State: StateExercised, Build: &p.Build, Command: &CommandRun{
		Command: "web/e2e-harness/h.sh run pw oidc --reporter=json " + specFile + " -g " + grep, ExitCode: res.Exit, DurationMS: res.Duration.Milliseconds()}}
	var failures []string
	if res.Exit != 0 || res.Err != nil {
		failures = append(failures, fmt.Sprintf("the harness run exited %d: %s", res.Exit, tail(rc.rel(res.Stderr+"\n"+res.Stdout), 300)))
	}
	var tests []pwTest
	raw, readErr := os.ReadFile(h.report)
	if readErr != nil {
		failures = append(failures, "the run left no report: "+readErr.Error())
	} else if parsed, errs, perr := parsePlaywright(string(raw)); perr != nil {
		failures = append(failures, "the report is not a Playwright JSON report: "+perr.Error())
	} else {
		tests = parsed
		for _, e := range errs {
			failures = append(failures, "playwright reported an error: "+e)
		}
	}
	passed := 0
	summary := make([]map[string]string, 0, len(tests))
	for _, t := range tests {
		summary = append(summary, map[string]string{"title": t.Title, "status": t.Status})
		if t.Status == "expected" {
			passed++
		} else {
			failures = append(failures, fmt.Sprintf("test %q finished %s", t.Title, t.Status))
		}
	}
	if len(tests) < minTests {
		failures = append(failures, fmt.Sprintf("the run matched %d test(s) of %s for %q, the row needs at least %d", len(tests), specFile, grep, minTests))
	}
	if blob, err := json.MarshalIndent(map[string]any{"spec": specFile, "grep": grep, "tests": summary}, "", " "); err == nil {
		row.Evidence = append(row.Evidence, rc.writeEvidence(spec.ID+".json", append(blob, '\n')))
	}
	row.Evidence = append(row.Evidence, fmt.Sprintf("%d/%d Playwright tests of %s passed against a real soundpost serve, read through the product console in real %s %s", passed, len(tests), specFile, browser.Build.Family, browser.Build.Version))
	row.Series = []Series{{Name: "tests_passed", Unit: "count", Values: []float64{float64(passed)}}, {Name: "tests_matched", Unit: "count", Values: []float64{float64(len(tests))}}}
	row.Limits = []string{
		fmt.Sprintf("this row is the %s %s build only; the product's own console reads what the SDK delivered; the OIDC fixture and the private CA are the harness's, not production identity", p.Build.Family, p.Build.Version),
		"headless Linux build only; no headed run",
	}
	if len(failures) > 0 {
		row.Outcome, row.Failures = OutcomeFailed, failures
		return row
	}
	row.Outcome = OutcomePassed
	return row
}
