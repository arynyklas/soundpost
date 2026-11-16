// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Gaps that the CD-8 redaction of an issue book has to tell apart at the edges of a range (a gap is the
// closed interval [Start,End], the range the half-open [start,end)) and by signal (a gap that names none
// concerns every signal). TestCD8RangeRedactsFreeTextInsideTheRangeOnly keeps clear of every edge.
func TestMutantGapReasonsFollowTheClosedIntervalAgainstTheHalfOpenRange(t *testing.T) {
	f := newTextFx()
	gap := func(n byte, start, end model.UnixNano, signals ...model.Kind) model.EvidenceGap {
		return model.EvidenceGap{ID: model.ID{0xf0, n}, Org: f.org, Project: f.project, Group: model.ID{0x99}, Start: start, End: end, Signals: signals, Reason: "gap: " + textCanary}
	}
	cases := []struct {
		name     string
		gap      model.EvidenceGap
		redacted bool
	}{
		{"ends where the range starts: the closed interval meets it", gap(1, 20, 40, model.ErrorKind), true},
		{"ends just before the range starts", gap(2, 10, 39, model.ErrorKind), false},
		{"starts where the range ends: the half-open range does not hold it", gap(3, 100, 120, model.ErrorKind), false},
		{"starts just before the range ends", gap(4, 99, 130, model.ErrorKind), true},
		{"names no signal: it concerns every signal", gap(5, 50, 60), true},
		{"names the range's signal among others", gap(6, 50, 60, model.Log, model.ErrorKind), true},
		{"names only another signal", gap(7, 50, 60, model.Log), false},
	}
	book := IssueBook{Org: f.org, Project: f.project, Revision: 4}
	for _, c := range cases {
		book.Gaps = append(book.Gaps, c.gap)
	}
	raw, err := json.Marshal(book)
	if err != nil {
		t.Fatal(err)
	}
	f.st.IssueBooks[issueBookKey(f.org, f.project)] = raw
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.ErrorKind}, Start: 40, End: 100}}
	if err = eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	got, _, err := loadIssueBook(f.st, f.org, f.project)
	if err != nil || len(got.Gaps) != len(cases) {
		t.Fatalf("the issue book after the erasure: %d gaps, %v", len(got.Gaps), err)
	}
	for i, c := range cases {
		if redacted := !strings.Contains(got.Gaps[i].Reason, textCanary); redacted != c.redacted {
			t.Errorf("gap %q: redacted=%v, want %v", c.name, redacted, c.redacted)
		}
	}
}

// A redaction of text alone is an erasure: the pages that held the text are free pages, so the erasing
// audit is recorded (a scrub is owed) although no payload was dropped. An empty reason is no text: it is
// neither rewritten nor counted, and a state whose only candidate is empty erases nothing.
func TestMutantRedactedTextAloneIsAnErasureAndAnEmptyReasonIsNot(t *testing.T) {
	org, project := model.ID{0x10}, model.ID{0x11}
	predicate := model.DeletePredicate{Operation: model.ID{0xdd}, Org: org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100}
	for _, c := range []struct {
		name, reason, wantReason string
		audits                   int
	}{
		{"consumer text", "series_conflict:" + textCanary, controlTextErased, 1},
		{"empty reason", "", "", 0},
	} {
		st := &State{Installation: model.ID{0x01}}
		out := RuleOutput{ID: model.ID{0xa1}, Org: org, Project: project, Rule: model.ID{0xb1}, Version: 1, At: 60, Kind: RuleOutputRecording, Signal: model.Metric, Mode: RuleModeLive, Phase: RulePhaseFinalized, Reason: c.reason}
		if err := storeRuleOutput(st, out); err != nil {
			t.Fatal(err)
		}
		op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: predicate}
		if err := eraseControlPayloads(st, &op, 5); err != nil {
			t.Fatal(err)
		}
		got, _, err := loadRuleOutput(st, out.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.Reason != c.wantReason || len(st.Audits) != c.audits {
			t.Errorf("%s: reason %q with %d erasing audits, want %q with %d", c.name, got.Reason, len(st.Audits), c.wantReason, c.audits)
		}
	}
}
