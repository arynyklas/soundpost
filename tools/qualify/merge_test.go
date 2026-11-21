// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// One run of the runtime suite holds the builds installed on its host; the release needs Node 22 and Node 24 rows, so the suite
// report the gate reads is merged from several runs. Each merged row is bound to the run that observed it (its runtime build, its host,
// the run digest), a run stamped against another source refuses the whole merge, and a rerun replaces exactly the rows it produced.

const mergeSource = evidenceSource

func hostNamed(kernel string) HostInfo {
	return HostInfo{OS: "linux", Arch: "amd64", Kernel: kernel, Class: "linux", NumCPU: 8}
}

// nodeRun is a report of a host on which only Node `version` (22 or 24 family) is installed: its row is exercised, the other Node's is not.
func nodeRun(t *testing.T, version, at string, host HostInfo, mutate func(*SuiteReport)) SuiteReport {
	t.Helper()
	mk := func(id, family string) Row {
		row := suiteRowFixture(id, SuiteRuntime, true, StateExercised, OutcomePassed)
		row.Subject = Subject{Family: "node", Version: family, OS: "linux", Arch: "amd64"}
		if strings.HasPrefix(version, family+".") {
			row.Build = &Build{Family: "node", Version: version, OS: "linux", Arch: "amd64", ID: "sha256:" + version}
			return row
		}
		row = suiteRowFixture(id, SuiteRuntime, true, StateNotExercised, "")
		row.Subject = Subject{Family: "node", Version: family, OS: "linux", Arch: "amd64"}
		row.Reason = "no Node " + family + " build for linux/amd64 is installed on this host"
		return row
	}
	rep := SuiteReport{Suite: SuiteRuntime, Matrix: "qualification/matrix.yaml", MatrixSHA: strings.Repeat("m", 8), RecordedAt: at, Host: host, SourceSHA256: mergeSource,
		Rows: []Row{mk("runtime.node-22.linux-amd64", "22"), mk("runtime.node-24.linux-amd64", "24")}}
	if mutate != nil {
		mutate(&rep)
	}
	return rep
}

func rowOfMerged(t *testing.T, rep SuiteReport, id string) Row {
	t.Helper()
	for _, r := range rep.Rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("merged report has no row %s", id)
	return Row{}
}

func TestMergeRefusesARunOfAnotherSource(t *testing.T) { // (a)
	good := nodeRun(t, "22.21.1", "2026-11-19T10:00:00Z", hostNamed("6.1.0-54"), nil)
	other := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.1.0-54"), func(r *SuiteReport) { r.SourceSHA256 = strings.Repeat("1", 64) })
	merged, err := MergeSuiteReports(mergeSource, good, other)
	if err == nil || !strings.Contains(err.Error(), "source") || len(merged.Rows) != 0 {
		t.Fatalf("a run built against another source was merged: %v %+v", err, merged)
	}
	for name, stamp := range map[string]string{"no stamp": "", "a stamp that is not a digest": "abc"} {
		bad := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.1.0-54"), func(r *SuiteReport) { r.SourceSHA256 = stamp })
		if _, err := MergeSuiteReports(mergeSource, good, bad); err == nil {
			t.Errorf("%s: merged", name)
		}
	}
	if _, err := MergeSuiteReports("not-a-digest", good); err == nil {
		t.Error("the manifest's own stamp must be a digest")
	}
	differentMatrix := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.1.0-54"), func(r *SuiteReport) { r.MatrixSHA = strings.Repeat("z", 8) })
	if _, err := MergeSuiteReports(mergeSource, good, differentMatrix); err == nil || !strings.Contains(err.Error(), "matrix") {
		t.Errorf("runs of different matrices were merged: %v", err)
	}
	otherSuite := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.1.0-54"), func(r *SuiteReport) { r.Suite = SuitePrivacy })
	if _, err := MergeSuiteReports(mergeSource, good, otherSuite); err == nil {
		t.Error("runs of different suites were merged")
	}
}

func TestMergeOfTwoRunsHoldsBothNodeRowsBoundToTheirRun(t *testing.T) { // (b)
	r22 := nodeRun(t, "22.21.1", "2026-11-19T10:00:00Z", hostNamed("6.1.0-54"), nil)
	r24 := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.6.162"), nil)
	// Alone, each run leaves the other Node's required row unqualified: the evidence gate would block.
	for _, rep := range []SuiteReport{r22, r24} {
		rep.Verdict()
		if rep.ExitCode != ExitUnqualified || len(rep.Unqualified) != 1 {
			t.Fatalf("a run with one Node must be unqualified on the other: %+v", rep.Unqualified)
		}
	}
	merged, err := MergeSuiteReports(mergeSource, r22, r24)
	if err != nil {
		t.Fatal(err)
	}
	a, b := rowOfMerged(t, merged, "runtime.node-22.linux-amd64"), rowOfMerged(t, merged, "runtime.node-24.linux-amd64")
	if a.State != StateExercised || a.Build.Version != "22.21.1" || b.State != StateExercised || b.Build.Version != "24.11.0" {
		t.Fatalf("both Node rows must be exercised by their own build: %+v %+v", a, b)
	}
	if a.Run == nil || b.Run == nil || a.Run.Digest == b.Run.Digest || a.Run.HostID == b.Run.HostID {
		t.Fatalf("each row is bound to its own run and host: %+v %+v", a.Run, b.Run)
	}
	if a.Run.Runtime != "node-22.21.1" || b.Run.Runtime != "node-24.11.0" || a.Run.SourceSHA256 != mergeSource || a.Run.Digest != ReportDigest(r22) || b.Run.Digest != ReportDigest(r24) {
		t.Fatalf("binding: %+v %+v", a.Run, b.Run)
	}
	if merged.ExitCode != ExitOK || len(merged.Unqualified) != 0 || len(merged.Runs) != 2 || merged.SourceSHA256 != mergeSource {
		t.Fatalf("both Nodes merged: the suite is qualified, two runs listed: exit %d %v runs %d", merged.ExitCode, merged.Unqualified, len(merged.Runs))
	}
	// The merged report is a valid report the gate's exporter reads as one suite report, rows passed.
	raw, err := json.Marshal(merged)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSuiteReport(raw)
	if err != nil {
		t.Fatalf("the merged report must round-trip through the strict reader: %v", err)
	}
	path, sum := evidenceMatrixFile(t)
	back.MatrixSHA = sum
	back.Rows[0].ID, back.Rows[1].ID = "runtime.pass", "runtime.fail"
	env, err := SuiteEvidence(releaseevidence.KindRuntime, path, []SuiteReport{back}, evidenceCommit)
	if err != nil {
		t.Fatal(err)
	}
	wantStatus(t, env, "runtime.pass", releaseevidence.StatusPassed)
	// The order of the arguments does not decide anything.
	again, err := MergeSuiteReports(mergeSource, r24, r22)
	if err != nil || rowOfMerged(t, again, "runtime.node-22.linux-amd64").Run.Digest != a.Run.Digest {
		t.Fatalf("argument order: %v", err)
	}
}

func TestMergeRerunReplacesOnlyItsRows(t *testing.T) { // (c)
	r22 := nodeRun(t, "22.21.1", "2026-11-19T10:00:00Z", hostNamed("6.1.0-54"), nil)
	r24 := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.6.162"), nil)
	first, err := MergeSuiteReports(mergeSource, r22, r24)
	if err != nil {
		t.Fatal(err)
	}
	before24 := rowOfMerged(t, first, "runtime.node-24.linux-amd64")
	rerun := nodeRun(t, "22.21.1", "2026-11-19T11:00:00Z", hostNamed("6.1.0-54"), func(r *SuiteReport) {
		r.Rows[0].Build.ID = "sha256:rerun"
		r.Rows[0].Evidence = []string{"rerun.json"}
	})
	second, err := MergeSuiteReports(mergeSource, first, rerun)
	if err != nil {
		t.Fatal(err)
	}
	a := rowOfMerged(t, second, "runtime.node-22.linux-amd64")
	if a.Build.ID != "sha256:rerun" || a.Run.Digest != ReportDigest(rerun) {
		t.Fatalf("the rerun's row replaces the old one: %+v", a)
	}
	b, _ := json.Marshal(rowOfMerged(t, second, "runtime.node-24.linux-amd64"))
	want, _ := json.Marshal(before24)
	if string(b) != string(want) {
		t.Fatalf("the Node 24 row was touched by a Node 22 rerun:\n%s\n%s", b, want)
	}
	// A rerun that could not run Node 22 (not_exercised there) never replaces an observation.
	blind := nodeRun(t, "24.11.0", "2026-11-19T12:00:00Z", hostNamed("6.6.162"), nil)
	third, err := MergeSuiteReports(mergeSource, second, blind)
	if err != nil {
		t.Fatal(err)
	}
	if got := rowOfMerged(t, third, "runtime.node-22.linux-amd64"); got.State != StateExercised || got.Run.Digest != ReportDigest(rerun) {
		t.Fatalf("a run that did not observe Node 22 replaced the Node 22 observation: %+v", got)
	}
	// A failing rerun replaces a passing observation: the newest observation is the one on record.
	failing := nodeRun(t, "22.21.1", "2026-11-19T13:00:00Z", hostNamed("6.1.0-54"), func(r *SuiteReport) {
		r.Rows[0].Outcome, r.Rows[0].Failures = OutcomeFailed, []string{"fixture exited 1"}
	})
	fourth, err := MergeSuiteReports(mergeSource, third, failing)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.ExitCode != ExitFail || rowOfMerged(t, fourth, "runtime.node-22.linux-amd64").Outcome != OutcomeFailed {
		t.Fatalf("a failing rerun must show: exit %d", fourth.ExitCode)
	}
	// Merging the same run twice is the same as once.
	twice, err := MergeSuiteReports(mergeSource, r22, r22, r24)
	if err != nil || len(twice.Runs) != 2 {
		t.Fatalf("a run given twice: %v %d", err, len(twice.Runs))
	}
}

func TestMergeKeepsRowsOfOneIdConsistent(t *testing.T) {
	r22 := nodeRun(t, "22.21.1", "2026-11-19T10:00:00Z", hostNamed("6.1.0-54"), nil)
	skewed := nodeRun(t, "24.11.0", "2026-11-19T10:05:00Z", hostNamed("6.6.162"), func(r *SuiteReport) { r.Rows[1].Required = false })
	if _, err := MergeSuiteReports(mergeSource, r22, skewed); err == nil {
		t.Fatal("two runs disagree whether a row is required: refused")
	}
	if _, err := MergeSuiteReports(mergeSource); err == nil {
		t.Fatal("a merge of nothing is refused")
	}
}
