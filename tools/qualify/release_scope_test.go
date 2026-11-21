// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

const scopeMatrix = `schema: soundpost-qualification-matrix/1
root: .
workloads: workloads.yaml
release_platforms: [linux/amd64]
release_scope_decision: D10
builds:
  firefox-144-linux-amd64: {family: firefox, version: "144.0.2", os: linux, arch: amd64, env: SOUNDPOST_QUAL_TEST_ABSENT_FIREFOX, candidates: [definitely-not-installed-firefox], absent: "no Firefox 144.0.2 build is installed on this host"}
  python-3.13-linux-arm64: {family: python, version: "3.13", os: linux, arch: arm64, candidates: [python3], absent: "no CPython 3.13 for linux/arm64"}
  safari-26-macos-arm64: {family: safari, version: "26.0.1", os: macos, arch: arm64, absent: "Safari exists only on Apple platforms"}
  node-22-windows-amd64: {family: node, version: "22", os: windows, arch: amd64, absent: "no node on windows"}
rows:
  - {id: runtime.amd64.missing, suite: runtime, required: true, runner: scope_sentinel, build: firefox-144-linux-amd64}
  - {id: runtime.arm64, suite: runtime, required: true, runner: scope_sentinel, build: python-3.13-linux-arm64}
  - {id: runtime.safari, suite: runtime, required: true, runner: scope_sentinel, build: safari-26-macos-arm64}
  - {id: runtime.windows, suite: runtime, required: false, runner: scope_sentinel, build: node-22-windows-amd64}
  - {id: runtime.any, suite: runtime, required: true, runner: scope_sentinel, subject: {family: go, version: "1.27", os: any, arch: any}}
native:
  - {suite: runtime, runner: scope_sentinel, kernels: ["6.6"], arches: [amd64, arm64], capabilities: [cpu]}
`

var sentinelCalls []string

func init() {
	runners["scope_sentinel"] = func(rc *runCtx, spec RowSpec) Row {
		sentinelCalls = append(sentinelCalls, spec.ID)
		return notExercised("sentinel: no harness")
	}
}

func runScope(t *testing.T, body string) SuiteReport {
	t.Helper()
	root := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, "workloads.yaml"), string(raw))
	writeFile(t, filepath.Join(root, "matrix.yaml"), body)
	sentinelCalls = nil
	rep, err := RunSuite(context.Background(), SuiteRuntime, filepath.Join(root, "matrix.yaml"), filepath.Join(root, "report"))
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func rowByID(t *testing.T, rep SuiteReport, id string) Row {
	t.Helper()
	for _, r := range rep.Rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row %s", id)
	return Row{}
}

func TestReleaseScopeArm64RowIsOutOfScopeAndNeverProbed(t *testing.T) {
	rep := runScope(t, scopeMatrix)
	for _, id := range []string{"runtime.arm64", "runtime.safari", "runtime.windows", "runtime.native.linux-6.6.arm64.cpu"} {
		r := rowByID(t, rep, id)
		if r.State != StateOutOfReleaseScope || r.Build != nil || r.Command != nil || r.Outcome != "" {
			t.Errorf("%s must be a bare out_of_release_scope row: %+v", id, r)
		}
		if !strings.Contains(r.Reason, "D10") {
			t.Errorf("%s reason must cite D10: %q", id, r.Reason)
		}
	}
	for _, c := range sentinelCalls {
		if strings.Contains(c, "arm64") || c == "runtime.safari" || c == "runtime.windows" {
			t.Errorf("runner ran for out-of-scope row %s", c)
		}
	}
	// os/arch "any" and linux/amd64 rows stay in scope.
	for _, id := range []string{"runtime.any", "runtime.amd64.missing", "runtime.native.linux-6.6.amd64.cpu"} {
		if r := rowByID(t, rep, id); r.State != StateNotExercised {
			t.Errorf("%s must stay in scope: %+v", id, r)
		}
	}
}

func TestReleaseScopeMissingAmd64BuildStillBlocksAndOutOfScopeNeverCounts(t *testing.T) {
	rep := runScope(t, scopeMatrix)
	if rep.ExitCode != ExitUnqualified {
		t.Fatalf("a missing linux/amd64 build must still give exit %d, got %d", ExitUnqualified, rep.ExitCode)
	}
	joined := strings.Join(rep.Unqualified, "\n")
	if !strings.Contains(joined, "runtime.amd64.missing") || strings.Contains(joined, "arm64") || strings.Contains(joined, "safari") {
		t.Fatalf("unqualified must hold the amd64 row only: %v", rep.Unqualified)
	}
	if len(rep.OutOfScope) != 4 {
		t.Fatalf("4 out-of-scope rows listed separately: %v", rep.OutOfScope)
	}
	// With only out-of-scope required rows left unqualified, they never affect the exit code.
	only := strings.NewReplacer("  - {id: runtime.amd64.missing, suite: runtime, required: true, runner: scope_sentinel, build: firefox-144-linux-amd64}\n", "",
		"  - {id: runtime.any, suite: runtime, required: true, runner: scope_sentinel, subject: {family: go, version: \"1.27\", os: any, arch: any}}\n", "").Replace(scopeMatrix)
	only = strings.Replace(only, "capabilities: [cpu]}", "capabilities: [cpu]}\n  - {suite: runtime, runner: scope_sentinel, kernels: [\"6.6\"], arches: [amd64], capabilities: [off_cpu]}", 1)
	rep = runScope(t, only)
	for _, r := range rep.Rows {
		if r.State == StateExercised {
			t.Errorf("nothing was exercised: %+v", r)
		}
	}
	if len(rep.Unqualified) != 2 {
		t.Fatalf("only the two native amd64 rows block: %v", rep.Unqualified)
	}
}

func TestReleaseScopeTextReportListsOutOfScopeSeparately(t *testing.T) {
	rep := runScope(t, scopeMatrix)
	text := rep.Summary()
	if !strings.Contains(text, "out_of_release_scope 4") {
		t.Errorf("counts must include out_of_release_scope: %s", text)
	}
	for _, id := range []string{"runtime.arm64", "runtime.safari", "runtime.windows"} {
		if !strings.Contains(text, "OUT OF RELEASE SCOPE "+id) {
			t.Errorf("%s must be listed as out of scope: %s", id, text)
		}
		if strings.Contains(text, "UNQUALIFIED "+id) {
			t.Errorf("%s must not be unqualified: %s", id, text)
		}
	}
}

func TestReleaseScopeAddingLinuxArm64ReEnablesTheRowsUnchanged(t *testing.T) {
	rep := runScope(t, strings.Replace(scopeMatrix, "[linux/amd64]", "[linux/amd64, linux/arm64]", 1))
	for _, id := range []string{"runtime.arm64", "runtime.native.linux-6.6.arm64.cpu"} {
		if r := rowByID(t, rep, id); r.State != StateNotExercised {
			t.Errorf("%s must be an ordinary row again: %+v", id, r)
		}
	}
	if r := rowByID(t, rep, "runtime.safari"); r.State != StateOutOfReleaseScope {
		t.Errorf("macos/arm64 stays out of scope: %+v", r)
	}
	if !strings.Contains(strings.Join(rep.Unqualified, "\n"), "runtime.arm64") {
		t.Errorf("a re-enabled arm64 row blocks when its build is missing: %v", rep.Unqualified)
	}
}

func TestReleaseScopeEvidenceCarriesTheStateAndPlatform(t *testing.T) {
	root := t.TempDir()
	raw, _ := os.ReadFile(filepath.Join(repoRoot(t), "qualification", "workloads.yaml"))
	writeFile(t, filepath.Join(root, "workloads.yaml"), string(raw))
	matrix := filepath.Join(root, "matrix.yaml")
	writeFile(t, matrix, scopeMatrix)
	sentinelCalls = nil
	rep, err := RunSuite(context.Background(), SuiteRuntime, matrix, filepath.Join(root, "report"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := SuiteEvidence(releaseevidence.KindRuntime, matrix, []SuiteReport{rep}, strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range ev.Rows {
		if r.ID == "runtime.arm64" {
			found = true
			if r.Status != releaseevidence.StatusOutOfReleaseScope || r.Platform != "linux/arm64" || !strings.Contains(r.Detail, "D10") {
				t.Errorf("arm64 evidence row: %+v", r)
			}
		}
		if r.Status == releaseevidence.StatusPassed {
			t.Errorf("nothing passed: %+v", r)
		}
	}
	if !found {
		t.Fatal("required out-of-scope row must be exported")
	}
}

func TestReleaseScopeRealMatrix(t *testing.T) {
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.ReleasePlatforms) != 1 || m.ReleasePlatforms[0] != "linux/amd64" || m.ReleaseScopeDecision != "D10" {
		t.Fatalf("release scope: %v %q", m.ReleasePlatforms, m.ReleaseScopeDecision)
	}
	for _, id := range []string{"runtime.browser.safari-26.core", "runtime.python-3.12.linux-arm64", "runtime.native.linux-6.6.arm64.cpu", "runtime.browser.chrome-142.linux-amd64.core"} {
		var spec RowSpec
		for _, r := range m.Rows {
			if r.ID == id {
				spec = r
			}
		}
		rc := &runCtx{matrix: m}
		want := !strings.Contains(id, "amd64")
		if got := m.outOfReleaseScope(rc.subject(spec)); got != want {
			t.Errorf("%s out of scope = %v, want %v", id, got, want)
		}
	}
}
