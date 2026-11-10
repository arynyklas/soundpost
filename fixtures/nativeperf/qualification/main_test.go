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

	"soundpost/fixtures/nativeperf/qual"
)

const testManifest = `{"rows":[
 {"kernel_series":"6.1 LTS","arch":"amd64","state":"not_run"},
 {"kernel_series":"6.1 LTS","arch":"arm64","state":"not_run"},
 {"kernel_series":"6.6 LTS","arch":"amd64","state":"not_run"},
 {"kernel_series":"6.6 LTS","arch":"arm64","state":"not_run"},
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
	r := &qual.QualificationResult{KernelBuild: kernel, Arch: arch, TargetBuild: qual.TargetBuild{BuildID: "aa", SHA256: "bb"}, RuntimeBuild: map[string]qual.RuntimeBuild{}, NegativeControls: qual.RunNegativeControls()}
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
	r := supportedResult("6.6.99-test", "amd64")
	r.OffCPU = qual.Unqualified("tracefs_denied", nil)
	r.RunqueueSplit = qual.Unqualified("tracefs_denied", nil)
	res := write(t, "acceptance.json", r)
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitUnexercised {
		t.Fatalf("exit %d, want %d\n%s", code, qual.ExitUnexercised, stderr)
	}
	for _, want := range []string{"6.6.99-test/amd64 off_cpu: unqualified (tracefs_denied)", "6.6.99-test/amd64 runqueue_split: unqualified (tracefs_denied)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "6.6.99-test/amd64 cpu:") {
		t.Error("a supported row was listed as unqualified")
	}
}

func TestAmd64ResultNeverQualifiesArm64OrAnotherSeries(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	res := write(t, "acceptance.json", supportedResult("6.6.99-test", "amd64"))
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
	for _, k := range []struct{ kernel, arch string }{{"6.1.10-x", "amd64"}, {"6.1.10-x", "arm64"}, {"6.6.1-x", "amd64"}, {"6.6.1-x", "arm64"}} {
		files = append(files, write(t, k.kernel+k.arch+".json", supportedResult(k.kernel, k.arch)))
	}
	code, _, stderr := gate(t, "--manifest", m, "--results", strings.Join(files, ","), "--require-all")
	if code != qual.ExitOK {
		t.Fatalf("a complete supported matrix exited %d:\n%s", code, stderr)
	}
}

func TestSupportedRowWithoutEvidenceIsInvalidNotQualified(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult("6.6.99-test", "amd64")
	r.CPU = qual.Row{State: qual.StateSupported}
	res := write(t, "acceptance.json", r)
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitFail || !strings.Contains(stderr, "supported but not exercised") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
}

func TestResultWithoutNegativeControlsIsRejected(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult("6.6.99-test", "amd64")
	r.NegativeControls = nil
	res := write(t, "acceptance.json", r)
	code, _, stderr := gate(t, "--manifest", m, "--results", res, "--require-all")
	if code != qual.ExitFail || !strings.Contains(stderr, "negative control staged_acquisition_pending_session was not run") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	r = supportedResult("6.6.99-test", "amd64")
	r.NegativeControls[2].Behaved = false // the empty-session control was accepted
	res = write(t, "acceptance2.json", r)
	if code, _, _ := gate(t, "--manifest", m, "--results", res, "--require-all"); code != qual.ExitFail {
		t.Fatalf("a result whose empty-session control was accepted passed: exit %d", code)
	}
}

func TestReportOnlyWritesReportAndExitsZero(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult("6.6.99-test", "amd64")
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

func overheadFor(kernel, arch string, full bool, overhead float64, memory uint64) overheadReport {
	f := overheadFixture{Fixture: "cpu", Seconds: 120, Repeats: 5, OverheadPct: overhead, MemoryBytes: memory, CPUBudgetOK: overhead <= 3, MemoryBudgetOK: memory <= 64<<20}
	if !f.CPUBudgetOK {
		f.Failures = []string{"over budget"}
	}
	return overheadReport{KernelBuild: kernel, Arch: arch, FullRun: full, Fixtures: []overheadFixture{f}}
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
	mergeOverhead(r, overheadReport{FullRun: true}, []string{"cpu"})
	if r.Overhead.State == qual.StateSupported {
		t.Error("an advertised fixture without a result was reported as supported")
	}
}

func TestOverheadOfAnotherKernelOrArchIsNotMerged(t *testing.T) {
	m := write(t, "manifest.json", testManifest)
	r := supportedResult("6.6.99-test", "amd64")
	r.Overhead = qual.Row{State: qual.StateNotRun, Reason: "not measured here"}
	res := write(t, "acceptance.json", r)
	oh := write(t, "overhead.json", overheadFor("6.6.99-test", "arm64", true, 0.1, 1<<20))
	_, _, stderr := gate(t, "--manifest", m, "--results", res+","+oh, "--require-all")
	if !strings.Contains(stderr, "6.6.99-test/amd64 overhead: not_run") {
		t.Errorf("an arm64 overhead report changed the amd64 result:\n%s", stderr)
	}
}
