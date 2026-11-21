//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

const k66 = "6.6.99-0606099-generic"

const testManifest = `{"rows":[
 {"kernel_series":"6.1 LTS","arch":"amd64","kernel_build":"6.1.0-54-amd64 (Debian)","kernel_config":{"sha256":"sha-6.1.0-54-amd64"},"state":"not_run"},
 {"kernel_series":"6.1 LTS","arch":"arm64","kernel_build":"6.1.0-54-arm64 (Debian)","kernel_config":{"sha256":"sha-6.1.0-54-arm64"},"state":"not_run"},
 {"kernel_series":"6.6 LTS","arch":"amd64","kernel_build":"6.6.99-0606099-generic (mainline)","kernel_config":{"sha256":"sha-6.6.99-0606099-generic"},"state":"not_run"},
 {"kernel_series":"6.6 LTS","arch":"arm64","kernel_build":"6.6.99-0606099-generic (mainline)","kernel_config":{"sha256":"sha-6.6.99-0606099-generic"},"state":"not_run"},
 {"kernel_series":"6.6","arch":"amd64","kernel_build":"6.6.87.2-microsoft-standard-WSL2","state":"not_run"}],
 "advertised_fixtures":["cpu"]}`

func write(t *testing.T, name string, v any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	var data []byte
	if s, ok := v.(string); ok {
		data = []byte(s)
	} else {
		data, _ = json.Marshal(v)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func supportedResult(kernel, arch string) *qual.QualificationResult {
	r := &qual.QualificationResult{KernelBuild: kernel, KernelConfig: qual.KernelConfig{SHA256: "sha-" + kernel}, HostID: "host-1", Arch: arch, TargetBuild: qual.TargetBuild{BuildID: "aa", SHA256: "bb"}, RuntimeBuild: map[string]qual.RuntimeBuild{}, NegativeControls: qual.RunNegativeControls()}
	for _, row := range r.Rows() {
		*row = qual.Supported([]string{"measured"}, nil)
	}
	for _, name := range []string{"python", "node", "bun"} {
		b := qual.RuntimeBuild{Runtime: name, Version: "1", Arch: arch, BuildID: "cc"}
		r.RuntimeBuild[name] = b
		r.Runtimes = append(r.Runtimes, qual.RuntimeColumn{Runtime: name, Arch: arch, Build: b, Engine: qual.Supported([]string{"e"}, nil), Native: qual.Supported([]string{"n"}, nil), Wait: qual.Supported([]string{"w"}, nil)})
	}
	return r
}

func gate(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestRequireAllCannotPassVacuously(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	code, _, stderr := gate(t, "--manifest", m, "--require-all")
	if code != qual.ExitUnexercised {
		t.Fatalf("no results: exit %d, want %d", code, qual.ExitUnexercised)
	}
	for _, want := range []string{"matrix kernel 6.1 LTS amd64", "matrix kernel 6.1 LTS arm64", "matrix kernel 6.6 LTS amd64", "matrix kernel 6.6 LTS arm64"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("unqualified list lacks %q:\n%s", want, stderr)
		}
	}
}

func TestRequireAllFailsOnUnsupportedRowsAndListsThemExactly(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult(k66, "amd64")
	r.OffCPU = qual.Unqualified("tracefs_denied", nil)
	r.RunqueueSplit = qual.Unqualified("tracefs_denied", nil)
	res := write(t, "acceptance.json", r)
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitUnexercised {
		t.Fatalf("exit %d, want %d\n%s", code, qual.ExitUnexercised, stderr)
	}
	for _, want := range []string{k66 + "/amd64 off_cpu: unqualified (tracefs_denied)", k66 + "/amd64 runqueue_split: unqualified (tracefs_denied)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, k66+"/amd64 cpu:") {
		t.Error("a supported row was listed as unqualified")
	}
}

func TestAmd64ResultNeverQualifiesArm64OrAnotherSeries(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	res := write(t, "acceptance.json", supportedResult(k66, "amd64"))
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitUnexercised {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(stderr, "matrix kernel 6.6 LTS amd64") {
		t.Errorf("the fully supported 6.6 amd64 result did not qualify its own row:\n%s", stderr)
	}
	for _, want := range []string{"matrix kernel 6.6 LTS arm64", "matrix kernel 6.1 LTS amd64", "matrix kernel 6.1 LTS arm64"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("%q was qualified by an unrelated result:\n%s", want, stderr)
		}
	}
}

func TestAllRowsSupportedOnFullMatrixPasses(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	var files []string
	for _, k := range []struct{ kernel, arch string }{{"6.1.0-54-amd64", "amd64"}, {"6.1.0-54-arm64", "arm64"}, {k66, "amd64"}, {k66, "arm64"}} {
		files = append(files, write(t, k.kernel+k.arch+".json", supportedResult(k.kernel, k.arch)))
	}
	code, _, stderr := gate(t, "--manifest", m, "--results", strings.Join(files, ","), "--require-all")
	if code != qual.ExitOK {
		t.Fatalf("a complete supported matrix exited %d:\n%s", code, stderr)
	}
}

func TestSupportedRowWithoutEvidenceIsInvalidNotQualified(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult(k66, "amd64")
	r.CPU = qual.Row{State: qual.StateSupported}
	res := write(t, "acceptance.json", r)
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitFail || !strings.Contains(stderr, "supported but not exercised") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestResultWithoutNegativeControlsIsRejected(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult(k66, "amd64")
	r.NegativeControls = nil
	res := write(t, "acceptance.json", r)
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitFail || !strings.Contains(stderr, "negative control staged_acquisition_pending_session was not run") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	r = supportedResult(k66, "amd64")
	r.NegativeControls[2].Behaved = false // the empty-session control was accepted
	res = write(t, "acceptance2.json", r)
	if code, _, _ := gate(t, "--manifest", m, "--results", res, "--require-all"); code != qual.ExitFail {
		t.Fatalf("a result whose empty-session control was accepted passed: exit %d", code)
	}
}

func TestReportOnlyWritesReportAndExitsZero(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult(k66, "amd64")
	r.OffCPU = qual.Unqualified("tracefs_denied", nil)
	res := write(t, "acceptance.json", r)
	out := filepath.Join(t.TempDir(), "report.json")
	code, _, _ := gate(t, "--manifest", m, "--results", res, "--report-only", "--out", out)
	if code != qual.ExitOK {
		t.Fatalf("report-only exit %d", code)
	}
	var c combined
	data, err := os.ReadFile(out)
	if err != nil || json.Unmarshal(data, &c) != nil || c.ExitCode != qual.ExitUnexercised || len(c.Unqualified) == 0 {
		t.Fatalf("machine report missing or does not record the gate verdict: %v %+v", err, c)
	}
	if code, _, _ := gate(t, "--manifest", m, "--require-all", "--report-only"); code != qual.ExitUsage {
		t.Fatalf("exclusive flags accepted: %d", code)
	}
}

// overheadFor builds a sealed overhead report bound to supportedResult's host and kernel pin. A not-full run measured fewer seconds and repeats.
func overheadFor(kernel, arch string, full bool, overhead float64, memory uint64) overheadReport {
	f := overheadFixture{Fixture: "cpu", Seconds: 120, Repeats: 5, OverheadPct: overhead, MemoryBytes: memory, CPUBudgetOK: overhead <= 3, MemoryBudgetOK: memory <= 64<<20}
	if !full {
		f.Seconds, f.Repeats, f.Reduced = 20, 3, true
	}
	if !f.CPUBudgetOK {
		f.Failures = []string{"over budget"}
	}
	return sealed(overheadReport{KernelBuild: kernel, Arch: arch, HostID: "host-1", KernelConfigSHA: "sha-" + kernel, Command: "overhead --hz 99", FullRun: full, Fixtures: []overheadFixture{f}})
}

func sealed(o overheadReport) overheadReport {
	o.RunDigest = overheadDigest(o)
	return o
}

func TestOverheadBudgetsAreMeasuredNeverAdjusted(t *testing.T) {
	cases := []struct {
		name     string
		o        overheadReport
		want     qual.State
		memState qual.State
	}{
		{"full run within budget", overheadFor("k", "amd64", true, 1.2, 30<<20), qual.StateSupported, qual.StateSupported},
		{"exactly at the cpu budget", overheadFor("k", "amd64", true, 3.0, 30<<20), qual.StateSupported, qual.StateSupported},
		{"over the cpu budget", overheadFor("k", "amd64", true, 3.01, 30<<20), qual.StateFailed, qual.StateSupported},
		{"over the memory budget", overheadFor("k", "amd64", true, 1.0, 64<<20+1), qual.StateFailed, qual.StateFailed},
		{"reduced run is not promoted", overheadFor("k", "amd64", false, 0.5, 30<<20), qual.StateUnqualified, qual.StateSupported},
	}
	for _, tc := range cases {
		r := supportedResult("k", "amd64")
		mergeOverhead(r, tc.o, []string{"cpu"})
		if r.Overhead.State != tc.want || r.Memory.State != tc.memState {
			t.Errorf("%s: overhead %s memory %s, want %s/%s (%s)", tc.name, r.Overhead.State, r.Memory.State, tc.want, tc.memState, r.Overhead.Reason)
		}
		if err := r.Overhead.Validate("overhead"); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	r := supportedResult("k", "amd64")
	mergeOverhead(r, sealed(overheadReport{FullRun: true, HostID: "host-1", KernelConfigSHA: "sha-k", KernelBuild: "k", Arch: "amd64"}), []string{"cpu"})
	if r.Overhead.State == qual.StateSupported {
		t.Error("an advertised fixture without a result was reported as supported")
	}
}

func TestOverheadOfAnotherKernelOrArchIsNotMerged(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult(k66, "amd64")
	r.Overhead = qual.Row{State: qual.StateNotRun, Reason: "not measured here"}
	res := write(t, "acceptance.json", r)
	oh := write(t, "overhead.json", overheadFor(k66, "arm64", true, 0.1, 1<<20))
	_, _, stderr := gate(t, "--manifest", m, "--results", res+","+oh, "--require-all")
	if !strings.Contains(stderr, k66+"/amd64 overhead: not_run") {
		t.Errorf("an arm64 overhead report changed the amd64 result:\n%s", stderr)
	}
}

// 04.09 review: the merge used to trust the report's own full_run_executed.
func TestFullRunIsDerivedFromTheMeasuredFixturesNotTheSelfReportedFlag(t *testing.T) {
	o := overheadFor("k", "amd64", false, 0.5, 30<<20) // measured 20 s x 3
	o.FullRun = true                                   // the report claims the approved run
	o = sealed(o)
	r := supportedResult("k", "amd64")
	if problem := mergeOverhead(r, o, []string{"cpu"}); problem != "" {
		t.Fatalf("a bound report was refused: %s", problem)
	}
	if r.Overhead.State == qual.StateSupported {
		t.Fatalf("a 20 s x 3 run claiming full_run_executed was promoted: %+v", r.Overhead)
	}
	o = overheadFor("k", "amd64", true, 0.5, 30<<20) // measured 120 s x 5
	o.FullRun = false                                // a stale/hand-edited flag cannot demote or promote: the fixtures decide
	o = sealed(o)
	r = supportedResult("k", "amd64")
	if problem := mergeOverhead(r, o, []string{"cpu"}); problem != "" || r.Overhead.State != qual.StateSupported {
		t.Fatalf("a measured full run was not promoted: %q %+v", problem, r.Overhead)
	}
	o = overheadFor("k", "amd64", true, 0.5, 30<<20)
	o.Fixtures[0].Reduced = true // the fixture itself says reduced
	o = sealed(o)
	r = supportedResult("k", "amd64")
	mergeOverhead(r, o, []string{"cpu"})
	if r.Overhead.State == qual.StateSupported {
		t.Error("a fixture marked reduced was promoted")
	}
}

// 04.09 review: a report used to be matched to a result by kernel release and arch only.
func TestOverheadIsBoundToHostKernelPinAndRunDigest(t *testing.T) {
	fresh := func() (*qual.QualificationResult, overheadReport) {
		return supportedResult("k", "amd64"), overheadFor("k", "amd64", true, 0.5, 30<<20)
	}
	r, o := fresh()
	if problem := mergeOverhead(r, o, []string{"cpu"}); problem != "" || r.Overhead.State != qual.StateSupported {
		t.Fatalf("the bound report was not merged: %q %+v", problem, r.Overhead)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*overheadReport)
	}{
		{"another host", func(o *overheadReport) { o.HostID = "host-2"; *o = sealed(*o) }},
		{"no host identity", func(o *overheadReport) { o.HostID = ""; *o = sealed(*o) }},
		{"another kernel build pin", func(o *overheadReport) { o.KernelConfigSHA = "sha-other"; *o = sealed(*o) }},
		{"no kernel build pin", func(o *overheadReport) { o.KernelConfigSHA = ""; *o = sealed(*o) }},
		{"edited after the run", func(o *overheadReport) { o.Fixtures[0].OverheadPct = 0.1 }},
		{"no run digest", func(o *overheadReport) { o.RunDigest = "" }},
		{"digest of another run", func(o *overheadReport) { o.Command = "overhead --other" }},
	} {
		name, mutate := tc.name, tc.mutate
		r, o := fresh()
		before := r.Overhead
		mutate(&o)
		problem := mergeOverhead(r, o, []string{"cpu"})
		if problem == "" {
			t.Errorf("%s: an unbound overhead report was merged (%+v)", name, r.Overhead)
		}
		if r.Overhead.State != before.State || r.Overhead.Reason != before.Reason {
			t.Errorf("%s: the result was modified by a report that is not bound to it", name)
		}
	}
}

func TestStaleOverheadForTheSameKernelFailsTheGateLoudly(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult(k66, "amd64")
	r.Overhead = qual.Row{State: qual.StateNotRun, Reason: "not measured here"}
	res := write(t, "acceptance.json", r)
	stale := overheadFor(k66, "amd64", true, 0.1, 1<<20)
	stale.HostID = "another-host"
	oh := write(t, "overhead.json", sealed(stale))
	code, _, stderr := gate(t, "--manifest", m, "--results", res+","+oh, "--require-all")
	if code != qual.ExitFail || !strings.Contains(stderr, "overhead report not bound") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, k66+"/amd64 overhead: not_run") {
		t.Errorf("the stale report changed the result:\n%s", stderr)
	}
}
