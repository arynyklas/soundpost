// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// CD-8 (decision D6): the free-text fields of control records inside a deleted
// scope are redacted when the deletion begins, completes or is imported, and by
// the late pass of a record committed afterwards. The scope of a record is the
// one the rest of the erasure uses: a retirement covers every record of its
// projects, a range the records whose time and signal it selects, an entity
// deletion what links the entity.

const textCanary = "CANARYFREETEXT-the-outage-was-caused-by-ACME"

type textFx struct {
	st                      *State
	org, project, other     model.ID
	outIn, outOut, outOther model.ID
	rule, otherRule         model.ID
}

func newTextFx() *textFx {
	f := &textFx{st: &State{Installation: model.ID{0x01}}, org: model.ID{0x10}, project: model.ID{0x11}, other: model.ID{0x12},
		outIn: model.ID{0xa1}, outOut: model.ID{0xa2}, outOther: model.ID{0xa3}, rule: model.ID{0xb1}, otherRule: model.ID{0xb2}}
	put := func(id, project, rule model.ID, at model.UnixNano, signal model.Kind, reason string) {
		o := RuleOutput{ID: id, Org: f.org, Project: project, Rule: rule, Version: 1, At: at, Kind: RuleOutputRecording, Signal: signal, Mode: RuleModeLive, Phase: RulePhaseFinalized, Reason: reason}
		if err := storeRuleOutput(f.st, o); err != nil {
			panic(err)
		}
	}
	put(f.outIn, f.project, f.rule, 60, model.Metric, "series_conflict:"+textCanary)    // inside [40,100)
	put(f.outOut, f.project, f.rule, 1000, model.Metric, "series_conflict:"+textCanary) // after the range
	put(f.outOther, f.other, f.otherRule, 60, model.Metric, "series_conflict:"+textCanary)
	book := func(project, rule model.ID, windows ...RuleReplayWindow) {
		for i := range windows {
			windows[i].Operator = model.ID{0xaa}
		}
		if err := storeRuleBook(f.st, ruleKey(f.org, project, rule), RuleBook{Org: f.org, Project: project, Rule: rule, Replays: windows}); err != nil {
			panic(err)
		}
	}
	book(f.project, f.rule,
		RuleReplayWindow{From: 50, To: 70, Reason: "replay: " + textCanary, At: 5},   // inside
		RuleReplayWindow{From: 500, To: 700, Reason: "replay: " + textCanary, At: 5}, // after the range
		RuleReplayWindow{From: 10, To: 40, Reason: "replay: " + textCanary, At: 5},   // [10,40) ends where the range starts: outside
	)
	book(f.other, f.otherRule, RuleReplayWindow{From: 50, To: 70, Reason: "replay: " + textCanary, At: 5})
	f.st.GroupingMigrations = map[string]model.GroupingMigration{
		"in":    {ID: model.ID{0xc1}, Org: f.org, Project: f.project, From: model.ID{0xf1}, To: model.ID{0xf2}, At: 60, Reason: "migrate: " + textCanary},
		"out":   {ID: model.ID{0xc2}, Org: f.org, Project: f.project, From: model.ID{0xf1}, To: model.ID{0xf2}, At: 1000, Reason: "migrate: " + textCanary},
		"other": {ID: model.ID{0xc3}, Org: f.org, Project: f.other, From: model.ID{0xf1}, To: model.ID{0xf2}, At: 60, Reason: "migrate: " + textCanary},
	}
	f.st.Releases = map[string]model.Release{
		"mine":  {ID: model.ID{0xd1}, Org: f.org, Project: f.project, BuildID: model.ID{0xf3}, DisplayLabel: "release " + textCanary, History: []model.ReleaseLabelRevision{{Revision: 1, DisplayLabel: "old " + textCanary}}},
		"other": {ID: model.ID{0xd2}, Org: f.org, Project: f.other, BuildID: model.ID{0xf3}, DisplayLabel: "release " + textCanary, History: []model.ReleaseLabelRevision{{Revision: 1, DisplayLabel: "old " + textCanary}}},
	}
	book2 := IssueBook{Org: f.org, Project: f.project, Revision: 4, Gaps: []model.EvidenceGap{
		{ID: model.ID{0xe1}, Org: f.org, Project: f.project, Group: model.ID{0x99}, Start: 50, End: 70, Signals: []model.Kind{model.ErrorKind}, Reason: "gap: " + textCanary},
		{ID: model.ID{0xe2}, Org: f.org, Project: f.project, Group: model.ID{0x99}, Start: 500, End: 700, Signals: []model.Kind{model.ErrorKind}, Reason: "gap: " + textCanary},
		{ID: model.ID{0xe3}, Org: f.org, Project: f.project, Group: model.ID{0x99}, Start: 50, End: 70, Signals: []model.Kind{model.Log}, Reason: "gap: " + textCanary}, // another signal
	}}
	raw, err := json.Marshal(book2)
	if err != nil {
		panic(err)
	}
	f.st.IssueBooks = map[string]json.RawMessage{issueBookKey(f.org, f.project): raw}
	otherRaw, err := json.Marshal(IssueBook{Org: f.org, Project: f.other, Revision: 4, Gaps: []model.EvidenceGap{{ID: model.ID{0xe4}, Org: f.org, Project: f.other, Group: model.ID{0x99}, Start: 50, End: 70, Signals: []model.Kind{model.ErrorKind}, Reason: "gap: " + textCanary}}})
	if err != nil {
		panic(err)
	}
	f.st.IssueBooks[issueBookKey(f.org, f.other)] = otherRaw
	return f
}

func (f *textFx) holds(t *testing.T) map[string]bool {
	t.Helper()
	got := map[string]bool{}
	has := func(name string, v any) {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		got[name] = strings.Contains(string(raw), textCanary)
	}
	for name, id := range map[string]model.ID{"output in range": f.outIn, "output after range": f.outOut, "output of another project": f.outOther} {
		o, _, err := loadRuleOutput(f.st, id)
		if err != nil {
			t.Fatal(err)
		}
		has(name, o.Reason)
	}
	b, _, _ := loadRuleBook(f.st, ruleKey(f.org, f.project, f.rule))
	for i, w := range b.Replays {
		has("replay "+string(rune('0'+i)), w.Reason)
	}
	ob, _, _ := loadRuleBook(f.st, ruleKey(f.org, f.other, f.otherRule))
	has("replay of another project", ob.Replays[0].Reason)
	for key, m := range f.st.GroupingMigrations {
		has("migration "+key, m.Reason)
	}
	for key, r := range f.st.Releases {
		labels := []string{r.DisplayLabel}
		for _, h := range r.History {
			labels = append(labels, h.DisplayLabel)
		}
		has("release "+key, labels)
	}
	gb, _, _ := loadIssueBook(f.st, f.org, f.project)
	for i, g := range gb.Gaps {
		has("gap "+string(rune('0'+i)), g.Reason)
	}
	og, _, _ := loadIssueBook(f.st, f.org, f.other)
	for _, g := range og.Gaps {
		has("gap of another project", g.Reason)
	}
	return got
}

func TestCD8RetireProjectRedactsFreeTextOfItsProjectOnly(t *testing.T) {
	f := newTextFx()
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	for name, held := range f.holds(t) {
		own := !strings.Contains(name, "another project") && name != "migration other" && name != "release other"
		// The issue book (with its gaps) is dropped whole by a retirement, so the
		// gap texts of the project are gone with it.
		if own && held {
			t.Errorf("%s: free text survives the retirement", name)
		}
		if !own && !held {
			t.Errorf("%s: the text of a project the deletion does not name was redacted", name)
		}
	}
	if n := len(f.st.Audits); n != 1 || f.st.Audits[0].Action != controlErasedAction {
		t.Errorf("a redaction frees pages holding the old text: want one erasing audit (so a scrub is owed), got %+v", f.st.Audits)
	}
}

func TestCD8RetireOrgRedactsFreeTextOfEveryProject(t *testing.T) {
	f := newTextFx()
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteRetireOrg}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	for name, held := range f.holds(t) {
		if held {
			t.Errorf("%s: free text survives the organization's retirement", name)
		}
	}
}

func TestCD8RangeRedactsFreeTextInsideTheRangeOnly(t *testing.T) {
	f := newTextFx()
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric, model.ErrorKind}, Start: 40, End: 100}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{ // true: the text must still be there
		"output in range": false, "output after range": true, "output of another project": true,
		"replay 0": false, "replay 1": true, "replay 2": true, "replay of another project": true,
		"migration in": false, "migration out": true, "migration other": true,
		"release mine": true, "release other": true, // a release is not time-bound: only a retirement redacts its labels
		"gap 0": false, "gap 1": true, "gap 2": true, "gap of another project": true, // gap 2 is of another signal
	}
	for name, held := range f.holds(t) {
		if held != want[name] {
			t.Errorf("%s: text present=%v, want %v", name, held, want[name])
		}
	}
}

func TestCD8EntityDeletionRedactsOnlyTheRulesItErases(t *testing.T) {
	f := newTextFx()
	// The rule of an output of the replay signal is covered; the metric rule is not.
	replay := RuleOutput{ID: model.ID{0xa9}, Org: f.org, Project: f.project, Rule: model.ID{0xb9}, Version: 1, At: 60, Kind: RuleOutputRecording, Signal: model.Replay, Mode: RuleModeLive, Phase: RulePhaseFinalized, Reason: "series_conflict:" + textCanary}
	if err := storeRuleOutput(f.st, replay); err != nil {
		t.Fatal(err)
	}
	if err := storeRuleBook(f.st, ruleKey(f.org, f.project, replay.Rule), RuleBook{Org: f.org, Project: f.project, Rule: replay.Rule, Replays: []RuleReplayWindow{{From: 1, To: 2, Reason: "replay: " + textCanary, Operator: model.ID{0xaa}}}}); err != nil {
		t.Fatal(err)
	}
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{{0xe7}}}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	if o, _, _ := loadRuleOutput(f.st, replay.ID); strings.Contains(o.Reason, textCanary) {
		t.Error("the reason of a covered replay-signal output survives an entity deletion")
	}
	if b, _, _ := loadRuleBook(f.st, ruleKey(f.org, f.project, replay.Rule)); strings.Contains(b.Replays[0].Reason, textCanary) {
		t.Error("the replay reason of the covered rule's book survives an entity deletion")
	}
	for name, held := range f.holds(t) {
		if !held && !strings.Contains(name, "gap") {
			t.Errorf("%s: an entity deletion redacted text of an uncovered record", name)
		}
	}
}

// The redaction is idempotent and a closed system reason is not text a person
// typed: the retired-project reason of a suppressed output stays, and a second
// pass changes and counts nothing.
func TestCD8RedactionIsIdempotentAndKeepsClosedReasons(t *testing.T) {
	f := newTextFx()
	closed := RuleOutput{ID: model.ID{0xa8}, Org: f.org, Project: f.project, Rule: f.rule, Version: 1, At: 60, Kind: RuleOutputRecording, Signal: model.Metric, Mode: RuleModeLive, Phase: RulePhaseSuppress, Reason: ruleRetiredReason}
	if err := storeRuleOutput(f.st, closed); err != nil {
		t.Fatal(err)
	}
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Principal: model.ID{0xaa}, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	if o, _, _ := loadRuleOutput(f.st, closed.ID); o.Reason != ruleRetiredReason {
		t.Errorf("a closed system reason was rewritten: %q", o.Reason)
	}
	before, err := json.Marshal(f.st)
	if err != nil {
		t.Fatal(err)
	}
	audits := len(f.st.Audits)
	op.Phase = model.DeletePhaseComplete
	if err := eraseControlPayloads(f.st, &op, 9); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.st)
	if string(before) != string(after) || len(f.st.Audits) != audits {
		t.Error("a second erasure pass changed the state or added an erasing audit")
	}
}

// An erasure replaces the stored reason of a rule output with controlTextErased. The worker that
// retries the same settle step afterwards still carries its original reason, and the idempotent
// compare (applyRuleOutputArm's same) must call that the same step, not a conflict: for a
// suppression, for a recording output's settled phase and for the late duplicate of an earlier
// step. The tolerance is exactly the redacted token: any other differing reason, receipt or hash
// is still a conflict.
func TestCD8SettleStepRetriedAfterRedactionIsTheSameStepNotAConflict(t *testing.T) {
	f := newTextFx()
	receipt := model.Cursor{Group: model.ID{0x77}, Index: 9}
	hash := model.Hash{0x42}
	otherHash := model.Hash{0x43}
	book := &RuleBook{Org: f.org, Project: f.project, Rule: f.rule}
	put := func(id byte, phase string, kind string, reason string) RuleOutput {
		o := RuleOutput{ID: model.ID{0xc0, id}, Org: f.org, Project: f.project, Rule: f.rule, Version: 1, At: 60, Kind: kind, Signal: model.Metric, Mode: RuleModeLive, Phase: phase, Reason: reason}
		if kind == RuleOutputRecording && phase != RulePhaseSuppress {
			o.Receipt, o.Hash = &receipt, &hash
		}
		if err := storeRuleOutput(f.st, o); err != nil {
			t.Fatal(err)
		}
		return o
	}
	redact := func() {
		op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100}}
		if err := eraseControlPayloads(f.st, &op, 5); err != nil {
			t.Fatal(err)
		}
	}
	suppressed := put(1, RulePhaseSuppress, RuleOutputRecording, "series_conflict:"+textCanary)
	finalized := put(2, RulePhaseFinalized, RuleOutputRecording, "series_conflict:"+textCanary)
	redact()
	for _, o := range []RuleOutput{suppressed, finalized} {
		if got, _, _ := loadRuleOutput(f.st, o.ID); got.Reason != controlTextErased {
			t.Fatalf("fixture invalid: the reason of %v was not redacted: %q", o.ID, got.Reason)
		}
	}
	want := func(name string, u RuleOutputApply, conflict bool) {
		t.Helper()
		u.Project, u.Rule = f.project, f.rule
		effect, err := applyRuleOutputArm(f.st, book, u)
		if conflict {
			var fault *model.Fault
			if err == nil || !errors.As(err, &fault) || fault.Code != model.Conflict {
				t.Errorf("%s: want a conflict, got %v", name, err)
			}
			return
		}
		if err != nil || effect.Phase != "unchanged" {
			t.Errorf("%s: want unchanged, got %+v %v", name, effect, err)
		}
	}
	want("suppress retried with its original reason", RuleOutputApply{Output: suppressed.ID, To: RulePhaseSuppress, Reason: "series_conflict:" + textCanary}, false)
	want("finalized retried with its original reason", RuleOutputApply{Output: finalized.ID, To: RulePhaseFinalized, Receipt: &receipt, Hash: &hash, Reason: "series_conflict:" + textCanary}, false)
	want("late duplicate of the admitted step", RuleOutputApply{Output: finalized.ID, To: RulePhaseAdmitted, Receipt: &receipt, Hash: &hash, Reason: "series_conflict:" + textCanary}, false)
	want("finalized retried with another hash", RuleOutputApply{Output: finalized.ID, To: RulePhaseFinalized, Receipt: &receipt, Hash: &otherHash, Reason: "x"}, true)
	// Not redacted: a different reason is a different step.
	live := put(3, RulePhaseSuppress, RuleOutputRecording, "obsolete_origin")
	want("suppress retried with another reason when nothing was redacted", RuleOutputApply{Output: live.ID, To: RulePhaseSuppress, Reason: "other_reason"}, true)
	liveFinal := put(4, RulePhaseFinalized, RuleOutputRecording, "kept_reason")
	want("finalized retried with another reason when nothing was redacted", RuleOutputApply{Output: liveFinal.ID, To: RulePhaseFinalized, Receipt: &receipt, Hash: &hash, Reason: "other_reason"}, true)
}

// State.EvidenceGaps[].Reason is kept by every range or retirement erasure: the backup
// attestation binds the committed gap to that exact text (backup.GapDigest), so redacting it
// would break the restore proof. The text is capped at 64 bytes (recordGap) and the worker writes a
// closed vocabulary into it; docs/privacy/retention.md records the owner acceptance as a
// decision proposed by lane 1 wave 7. This test pins the behaviour the decision rests on: the
// committed gap fact is untouched and the issue-book copy is redacted.
func TestCD8CommittedEvidenceGapKeepsItsReasonForTheBackupDigest(t *testing.T) {
	f := newTextFx()
	gap := model.EvidenceGap{ID: model.ID{0xe9}, Org: f.org, Project: f.project, Group: model.ID{0x99}, Start: 50, End: 70, Signals: []model.Kind{model.ErrorKind}, Reason: "unprocessed_expiry"}
	f.st.EvidenceGaps = map[string]model.EvidenceGap{gap.ID.String(): gap}
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	if got := f.st.EvidenceGaps[gap.ID.String()]; got.Reason != gap.Reason {
		t.Errorf("the committed gap fact's reason was rewritten to %q: the backup GapDigest would no longer bind it", got.Reason)
	}
}

// A range redacts a grouping migration whose time lies in the half-open [start,end): the one at
// start goes, the one at end is kept.
func TestCD8RangeRedactsAMigrationAtStartAndKeepsOneAtEnd(t *testing.T) {
	f := newTextFx()
	f.st.GroupingMigrations["at start"] = model.GroupingMigration{ID: model.ID{0xc4}, Org: f.org, Project: f.project, From: model.ID{0xf1}, To: model.ID{0xf2}, At: 40, Reason: "migrate: " + textCanary}
	f.st.GroupingMigrations["at end"] = model.GroupingMigration{ID: model.ID{0xc5}, Org: f.org, Project: f.project, From: model.ID{0xf1}, To: model.ID{0xf2}, At: 100, Reason: "migrate: " + textCanary}
	op := model.DeletionOperation{Phase: model.DeletePhaseFencing, Predicate: model.DeletePredicate{Operation: model.ID{0xdd}, Org: f.org, Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.ErrorKind}, Start: 40, End: 100}}
	if err := eraseControlPayloads(f.st, &op, 5); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.st.GroupingMigrations["at start"].Reason, textCanary) {
		t.Error("the migration at the range's start kept its text")
	}
	if !strings.Contains(f.st.GroupingMigrations["at end"].Reason, textCanary) {
		t.Error("the migration at the range's end (outside [start,end)) was redacted")
	}
}
