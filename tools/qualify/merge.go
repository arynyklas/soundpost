// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

// Merge of suite reports written by separate runs. One run holds the builds installed on its host (one Node of the two the release
// needs), so the report the evidence gate reads is merged from several runs of the same matrix:
//   - every merged row is bound to the run that observed it: its runtime build, its host and the run digest;
//   - a run stamped against another source than the one the merged report is built for refuses the whole merge;
//   - rows are keyed by id: a row a run observed (exercised, unsupported, denied) beats a row a run could not look at (not_exercised),
//     and among observations the newest run replaces the older one, so a rerun replaces exactly the rows it produced.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// ErrMerge is returned for every refused merge; nothing is merged when it is.
var ErrMerge = errors.New("qualification merge refused")

// RowRun is what a merged row is bound to: the run that observed it.
type RowRun struct {
	Digest       string `json:"digest"`
	Runtime      string `json:"runtime"`
	HostID       string `json:"host_id"`
	RecordedAt   string `json:"recorded_at"`
	SourceSHA256 string `json:"source_sha256"`
}

// RunRecord describes one run a merged report draws rows from.
type RunRecord struct {
	Digest       string   `json:"digest"`
	RecordedAt   string   `json:"recorded_at"`
	SourceSHA256 string   `json:"source_sha256"`
	HostID       string   `json:"host_id"`
	Host         HostInfo `json:"host"`
	Command      string   `json:"command,omitempty"`
}

// HostID identifies a host by the facts the report records about it.
func HostID(h HostInfo) string {
	raw, _ := json.Marshal(h)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

// ReportDigest is the digest of one run: its report with the merge bindings removed, so a report and the same report after being
// merged have one digest.
func ReportDigest(rep SuiteReport) string {
	rep.Runs = nil
	rows := make([]Row, len(rep.Rows))
	for i, r := range rep.Rows {
		r.Run = nil
		rows[i] = r
	}
	rep.Rows = rows
	raw, _ := json.Marshal(rep)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func runtimeOf(r Row) string {
	if r.Build != nil {
		return r.Build.Family + "-" + r.Build.Version
	}
	return r.Subject.Family + "-" + r.Subject.Version
}

// observed says whether the run looked at the row: exercised, unsupported and denied are observations, not_exercised and
// out_of_release_scope are not.
func observed(r Row) bool {
	return r.State == StateExercised || r.State == StateUnsupported || r.State == StateDenied
}

// MergeSuiteReports merges reports of one suite and matrix into one report built for the source digest `source`. The reports are
// runs (or earlier merges); the order of the arguments never decides which observation is newest.
func MergeSuiteReports(source string, reports ...SuiteReport) (SuiteReport, error) {
	refuse := func(format string, args ...any) (SuiteReport, error) {
		return SuiteReport{}, fmt.Errorf("%w: %s", ErrMerge, fmt.Sprintf(format, args...))
	}
	if err := releaseevidence.CheckSource(source); err != nil {
		return refuse("the source stamp of the merged report: %v", err)
	}
	if len(reports) == 0 {
		return refuse("no report to merge")
	}
	type candidate struct {
		row Row
		run RowRun
		seq int
	}
	better := func(c, p candidate) bool {
		switch {
		case observed(c.row) != observed(p.row):
			return observed(c.row)
		case c.run.RecordedAt != p.run.RecordedAt:
			return c.run.RecordedAt > p.run.RecordedAt
		}
		return c.seq > p.seq
	}
	var order []string
	best := map[string]candidate{}
	records := map[string]RunRecord{}
	first, newest := reports[0], reports[0]
	for i, rep := range reports {
		who := fmt.Sprintf("report %d (host %s, recorded %s)", i+1, HostID(rep.Host), rep.RecordedAt)
		switch {
		case rep.Suite != first.Suite:
			return refuse("%s is a %s report, %s is a %s report", who, rep.Suite, "report 1", first.Suite)
		case rep.MatrixSHA == "" || rep.MatrixSHA != first.MatrixSHA:
			return refuse("%s was produced from another matrix than report 1", who)
		case rep.SourceSHA256 != source:
			return refuse("%s carries source stamp %q, the merged report is built for %s: refused, nothing was merged", who, rep.SourceSHA256, source)
		}
		if rep.RecordedAt > newest.RecordedAt {
			newest = rep
		}
		for _, run := range rep.Runs {
			records[run.Digest] = run
		}
		digest, host := ReportDigest(rep), HostID(rep.Host)
		for _, row := range rep.Rows {
			ref := RowRun{Digest: digest, Runtime: runtimeOf(row), HostID: host, RecordedAt: rep.RecordedAt, SourceSHA256: rep.SourceSHA256}
			if row.Run != nil {
				if row.Run.SourceSHA256 != source {
					return refuse("%s: row %s is bound to a run with source stamp %q, the merged report is built for %s", who, row.ID, row.Run.SourceSHA256, source)
				}
				ref = *row.Run
			} else {
				records[digest] = RunRecord{Digest: digest, RecordedAt: rep.RecordedAt, SourceSHA256: rep.SourceSHA256, HostID: host, Host: rep.Host}
			}
			c := candidate{row: row, run: ref, seq: i}
			p, seen := best[row.ID]
			switch {
			case !seen:
				order = append(order, row.ID)
				best[row.ID] = c
			case p.row.Required != row.Required || p.row.Subject != row.Subject:
				return refuse("row %s differs between runs (required %v/%v, subject %+v/%+v)", row.ID, p.row.Required, row.Required, p.row.Subject, row.Subject)
			case better(c, p):
				best[row.ID] = c
			}
		}
	}
	merged := SuiteReport{Suite: first.Suite, Matrix: newest.Matrix, MatrixSHA: first.MatrixSHA, RecordedAt: newest.RecordedAt, Host: newest.Host, SourceSHA256: source, Rows: []Row{}}
	used := map[string]bool{}
	for _, id := range order {
		c := best[id]
		ref := c.run
		c.row.Run = &ref
		merged.Rows = append(merged.Rows, c.row)
		used[ref.Digest] = true
	}
	for digest := range used {
		rec, ok := records[digest]
		if !ok {
			return refuse("a row is bound to run %s, which no report describes", digest)
		}
		merged.Runs = append(merged.Runs, rec)
	}
	sort.Slice(merged.Runs, func(i, j int) bool {
		a, b := merged.Runs[i], merged.Runs[j]
		return a.RecordedAt < b.RecordedAt || a.RecordedAt == b.RecordedAt && a.Digest < b.Digest
	})
	merged.Verdict()
	return merged, nil
}
