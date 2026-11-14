// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// pwTest is one Playwright test result.
type pwTest struct {
	Title  string
	Status string // expected | unexpected | skipped | flaky
	Stdout string
}

// pwRun is one Playwright invocation, shared by every row that reads it.
type pwRun struct {
	Exit     int
	Duration time.Duration
	Tests    []pwTest
	Errors   []string
	Command  string
}

type pwNode struct {
	Title  string   `json:"title"`
	Specs  []pwSpec `json:"specs"`
	Suites []pwNode `json:"suites"`
}

type pwSpec struct {
	Title string `json:"title"`
	Tests []struct {
		Status  string `json:"status"`
		Results []struct {
			Stdout []struct {
				Text string `json:"text"`
			} `json:"stdout"`
		} `json:"results"`
	} `json:"tests"`
}

type pwReport struct {
	Suites []pwNode `json:"suites"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (n pwNode) collect(out *[]pwTest) {
	for _, s := range n.Specs {
		for _, t := range s.Tests {
			var stdout strings.Builder
			for _, r := range t.Results {
				for _, o := range r.Stdout {
					stdout.WriteString(o.Text)
				}
			}
			*out = append(*out, pwTest{Title: s.Title, Status: t.Status, Stdout: stdout.String()})
		}
	}
	for _, c := range n.Suites {
		c.collect(out)
	}
}

// parsePlaywright decodes `playwright test --reporter=json` output.
func parsePlaywright(stdout string) (tests []pwTest, errs []string, err error) {
	var rep pwReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		return nil, nil, err
	}
	for _, s := range rep.Suites {
		s.collect(&tests)
	}
	for _, e := range rep.Errors {
		errs = append(errs, tail(e.Message, 300))
	}
	return tests, errs, nil
}

// bunForBundling prepares the Bun that the committed browser specs invoke to
// bundle the SDK. A Linux Bun is used directly; a Windows Bun (the only one
// installed on a WSL host) is wrapped by a shim that translates the absolute
// WSL paths in its ARGUMENTS. The shim cannot translate paths inside generated
// entry files, so a spec that writes absolute paths into source text still
// fails honestly.
func (rc *runCtx) bunForBundling() (string, string) {
	if p := rc.probe("bun-1.3.14-linux-amd64"); p.Found {
		return p.Path, ""
	}
	p := rc.probe("bun-1.3.14-windows-amd64")
	if !p.Found {
		return "", "no Bun 1.3.14 build runnable here to bundle the SDK for the browser spec (" + p.Reason + ")"
	}
	shim := filepath.Join(rc.work, "bun-shim")
	script := "#!/bin/sh\n# translate absolute WSL paths in ARGUMENTS for the Windows Bun\nfor a; do\n  case \"$a\" in\n    /mnt/*|/tmp/*) set -- \"$@\" \"$(wslpath -w \"$a\")\";;\n    *) set -- \"$@\" \"$a\";;\n  esac\n  shift\ndone\nexec '" + p.Path + "' \"$@\"\n"
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		return "", "cannot write the Bun path shim: " + err.Error()
	}
	return shim, ""
}

// playwright runs one spec file once per RunSuite and caches the result.
func (rc *runCtx) playwright(config, specFile, chromePath string) (*pwRun, string) {
	key := "pw:" + chromePath + ":" + config + ":" + specFile
	if v, ok := rc.cache[key]; ok {
		return v.(*pwRun), ""
	}
	node := rc.probe("node-22-linux-amd64")
	if !node.Found {
		return nil, "Playwright needs a Linux Node 22 to drive Chrome (" + node.Reason + ")"
	}
	cli := filepath.Join(rc.root, "web", "node_modules", "@playwright", "test", "cli.js")
	if _, err := os.Stat(cli); err != nil {
		return nil, "Playwright (web/node_modules/@playwright/test) is not installed in this checkout"
	}
	bun, why := rc.bunForBundling()
	if why != "" {
		return nil, why
	}
	home := filepath.Join(rc.work, "home")
	_ = os.MkdirAll(home, 0o755)
	env := []string{"HOME=" + home, "SOUNDPOST_BUN=" + bun, "SOUNDPOST_CHROME=" + chromePath, "NODE_PATH=" + filepath.Join(rc.root, "web", "node_modules")}
	args := []string{cli, "test", "-c", filepath.Join(rc.root, filepath.FromSlash(config)), "--reporter=json", specFile}
	res := rc.exec(10*time.Minute, filepath.Join(rc.root, "web"), env, node.Path, args...)
	run := &pwRun{Exit: res.Exit, Duration: res.Duration, Command: fmt.Sprintf("node playwright test -c %s --reporter=json %s", config, specFile)}
	tests, errs, err := parsePlaywright(res.Stdout)
	if err != nil {
		run.Errors = append(run.Errors, "no parseable Playwright report: "+tail(rc.rel(res.Stderr), 300))
	}
	run.Tests, run.Errors = tests, append(run.Errors, errs...)
	rc.cache[key] = run
	return run, ""
}

// runPlaywrightTest turns the Playwright results of one committed spec into a
// row. When the named tests pass the row takes the state the spec exists to
// prove (params on_pass: exercised, denied or unsupported); any failing test is
// a measured failure of an exercised row.
func runPlaywrightTest(rc *runCtx, spec RowSpec) Row {
	p := rc.probe(spec.Build)
	if !p.Found {
		return notExercised(p.Reason)
	}
	run, why := rc.playwright(spec.Params["config"], spec.Params["spec"], p.Path)
	if why != "" {
		return notExercised(why)
	}
	prefix := spec.Params["title"]
	var matched []pwTest
	for _, t := range run.Tests {
		if prefix == "" || strings.HasPrefix(t.Title, prefix) {
			matched = append(matched, t)
		}
	}
	row := Row{Build: &p.Build, Command: &CommandRun{Command: run.Command, ExitCode: run.Exit, DurationMS: run.Duration.Milliseconds()}}
	var failures []string
	passed := 0
	for _, t := range matched {
		if t.Status == "expected" {
			passed++
		} else {
			failures = append(failures, fmt.Sprintf("test %q finished %s", t.Title, t.Status))
		}
	}
	if len(matched) == 0 {
		failures = append(failures, "no matching test ran: "+strings.Join(run.Errors, "; "))
	}
	row.Series = []Series{{Name: "tests_passed", Unit: "count", Values: []float64{float64(passed)}}, {Name: "tests_matched", Unit: "count", Values: []float64{float64(len(matched))}}}
	row.Evidence = []string{fmt.Sprintf("%d/%d Playwright tests passed in real %s %s (%s)", passed, len(matched), p.Build.Family, p.Build.Version, spec.Params["spec"])}
	if key := spec.Params["evidence_key"]; key != "" {
		var series []Series
		var iv IntervalReport
		var loss []string
		for _, t := range matched {
			if obj := evidenceObject(t.Stdout, "SOUNDPOST_PROFILE_EVIDENCE"); obj != nil {
				if sub, ok := obj[key]; ok {
					harvest("", sub, &series, &iv, &loss)
					raw, _ := json.Marshal(sub)
					row.Evidence = append(row.Evidence, rc.writeEvidence(spec.ID+".json", raw))
				}
			}
		}
		row.Series = append(row.Series, series...)
		if iv.RequestedUS != nil {
			row.Interval = &iv
		}
		row.Loss = strings.Join(loss, "; ")
	}
	row.Limits = []string{fmt.Sprintf("this row is the %s %s build only; every other browser or version is its own row", p.Build.Family, p.Build.Version), "headless Linux build only; no headed run"}
	if len(failures) > 0 {
		row.State, row.Outcome, row.Failures = StateExercised, OutcomeFailed, failures
		return row
	}
	switch on := spec.Params["on_pass"]; on {
	case "denied", "unsupported":
		row.State = State(on)
		row.Reason = spec.Params["on_pass_reason"]
		avail := AvailDenied
		if on == "unsupported" {
			avail = AvailUnsupported
		}
		row.Readings = []Reading{{Name: "profile_samples", Unit: "samples", Availability: avail, Reason: spec.Params["on_pass_reason"]}}
		row.Series, row.Interval, row.Loss = nil, nil, ""
	default:
		row.State, row.Outcome = StateExercised, OutcomePassed
	}
	return row
}

// evidenceObject extracts the JSON object a spec printed after a marker word.
func evidenceObject(stdout, marker string) map[string]any {
	for _, line := range strings.Split(stdout, "\n") {
		if i := strings.Index(line, marker); i >= 0 {
			var m map[string]any
			if json.Unmarshal([]byte(strings.TrimSpace(line[i+len(marker):])), &m) == nil {
				return m
			}
		}
	}
	return nil
}

// runBuildProbe is a row for a build that no committed harness can drive: when
// the build is absent the row says so; when it is present the row still says
// that nothing drives it, so presence alone never becomes a pass.
func runBuildProbe(rc *runCtx, spec RowSpec) Row {
	p := rc.probe(spec.Build)
	if !p.Found {
		return notExercised(p.Reason)
	}
	return notExercised(fmt.Sprintf("build %s %s is present but no committed harness exercises this row: %s", p.Build.Family, p.Build.Version, spec.Params["reason"]))
}
