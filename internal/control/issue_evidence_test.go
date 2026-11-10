// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

const issuesWrite = auth.Permission("issues.write")

type issFx struct {
	*fenceFx
	writer auth.Scope
	group  model.ID
	rel    model.ID
}

func newIssFx(t *testing.T) *issFx {
	t.Helper()
	f := &issFx{fenceFx: newFenceFx(t), group: model.ID{0xe1}, rel: model.ID{0xc0, 1}}
	if err := f.store.BindReleases(); err != nil {
		t.Fatal(err)
	}
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read), string(issuesWrite)}, Reason: "fixture"})
	var err error
	if f.writer, err = f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, issuesWrite); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *issFx) evidence(fp byte, index uint64) model.GroupingEvidence {
	rel := f.rel
	return model.GroupingEvidence{
		OccurrenceID: model.ID{0xd0, fp, byte(index >> 8), byte(index)}, RecordID: model.ID{0xd1, fp, byte(index >> 8), byte(index)},
		Origin: model.Cursor{Group: f.group, Index: model.Uint64(index)}, GroupingVersion: 1, Fingerprint: model.Hash{fp},
		EventTime: model.UnixNano(1000 + index), ArrivalTime: model.UnixNano(2000 + index), ReleaseID: &rel, Ancestry: "known", Ordinal: model.Uint64(index), Freshness: "fresh",
	}
}
func (f *issFx) issueID(fp byte) model.ID { return model.ID{0xb0, fp} }
func (f *issFx) issue(fp byte, revision uint64, evidence ...model.GroupingEvidence) model.GroupingIssue {
	return model.GroupingIssue{ID: f.issueID(fp), Org: f.org, Project: f.project, GroupingVersion: 1, Fingerprint: model.Hash{fp}, Workflow: "open", Revision: model.Revision(revision), Occurrences: evidence}
}
func (f *issFx) record(i model.GroupingIssue) control.IssueRecordChange {
	return control.IssueRecordChange{Issue: i, Explanations: json.RawMessage(`[]`)}
}
func (f *issFx) commitCmd(c control.IssueCommand) control.Command {
	f.t.Helper()
	if c.Operation == "" {
		c.Operation = "commit"
	}
	if c.Project == (model.ID{}) {
		c.Project = f.project
	}
	raw, err := json.Marshal(c)
	if err != nil {
		f.t.Fatal(err)
	}
	id := control.IssueCommandID(raw)
	if c.Command != nil {
		id = *c.Command
	}
	return control.Command{CommandID: id, Kind: string(control.KindApplyIssueEvidence), Payload: raw}
}
func (f *issFx) commit(c control.IssueCommand) (control.Result, error) {
	f.t.Helper()
	return f.store.TransactIssues(f.ctx, f.writer, f.commitCmd(c))
}
func (f *issFx) must(c control.IssueCommand) control.Result {
	f.t.Helper()
	r, err := f.commit(c)
	if err != nil {
		f.t.Fatalf("commit: %v", err)
	}
	return r
}
func (f *issFx) snap() control.IssueSnapshot {
	f.t.Helper()
	s, err := f.store.IssueBook(f.ctx, f.writer, f.project)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}
func (f *issFx) semantic() string {
	f.t.Helper()
	raw, err := json.Marshal(f.snap())
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.NewReplacer(f.org.String(), "ORG", f.project.String(), "PROJECT").Replace(string(raw))
}
func (f *issFx) audits(action string) []model.ControlAudit {
	var out []model.ControlAudit
	_ = f.store.View(f.ctx, func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == action {
				out = append(out, a)
			}
		}
		return nil
	})
	return out
}

// first creates issue 1 with one occurrence at cursor 1.
func (f *issFx) first() control.IssueCommand {
	return control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(1, 1, f.evidence(1, 1)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 1}}
}

func TestIssueCommitStoresSharedIssuesAndBook(t *testing.T) {
	f := newIssFx(t)
	expl := json.RawMessage(`[{"occurrence_id":"` + f.evidence(1, 1).OccurrenceID.String() + `","eligible":false}]`)
	c := f.first()
	c.Records[0].Explanations = expl
	c.Effects = []control.IssueEffect{{ID: model.ID{0xf1}, Kind: "issue_regressed", Issue: f.issueID(1), Occurrence: f.evidence(1, 1).OccurrenceID}}
	res, err := f.commit(c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Phase != "applied" || len(res.AffectedIDs) != 1 || res.AffectedIDs[0] != f.issueID(1) {
		t.Fatalf("result %+v", res)
	}
	s := f.snap()
	if s.Revision != 1 || len(s.Issues) != 1 || s.Issues[0].ID != f.issueID(1) || s.Issues[0].Revision != 1 || len(s.Issues[0].Occurrences) != 1 {
		t.Fatalf("snapshot %+v", s)
	}
	if s.Checkpoints[f.group] != 1 || len(s.Effects) != 1 || s.Effects[0].ID != (model.ID{0xf1}) {
		t.Fatalf("checkpoint/effects %+v", s)
	}
	if string(s.Explanations[f.issueID(1)]) != string(expl) {
		t.Fatalf("explanations %s", s.Explanations[f.issueID(1)])
	}
	// The issue is the shared GroupingIssue record the release evidence reader
	// and the grouping migration use.
	if err = f.store.View(f.ctx, func(st control.State) error {
		gi, ok := st.GroupingIssues[model.ReleaseScopeKey(f.org, f.project, f.issueID(1))]
		if !ok || gi.Revision != 1 || len(st.IssueBooks) != 1 {
			t.Fatalf("shared state: %+v books %d", gi, len(st.IssueBooks))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// An empty project reads as revision 0, not an error.
	if _, err = f.store.IssueBook(f.ctx, f.writer, f.project); err != nil {
		t.Fatal(err)
	}
}

func TestIssueRevisionCompareAndSet(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	second := control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 2}}
	f.must(second)
	loser := control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(3, 1, f.evidence(3, 3)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 3}}
	_, err := f.commit(loser)
	cur, ok := control.IssueConflictRevision(err)
	if code(err) != model.Conflict || !strings.Contains(err.Error(), control.IssueRevisionConflict) || !ok || cur != 2 {
		t.Fatalf("second writer at revision 1: %v (current %d %v)", err, cur, ok)
	}
	if s := f.snap(); s.Revision != 2 || len(s.Issues) != 2 || s.Checkpoints[f.group] != 2 {
		t.Fatalf("a loser changed state: %+v", s)
	}
	if _, ok = control.IssueConflictRevision(model.Fail(model.Conflict)); ok {
		t.Fatal("a conflict without a current revision parsed")
	}
	if _, ok = control.IssueConflictRevision(nil); ok {
		t.Fatal("nil parsed")
	}
}

func TestIssueCommitRetryReturnsOriginalResult(t *testing.T) {
	f := newIssFx(t)
	// An evidence commit (derived command ID) retried after later commits.
	first := f.must(f.first())
	f.must(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 2}})
	again, err := f.commit(f.first())
	if err != nil || again.Revision != first.Revision || again.Cursor != first.Cursor || again.Phase != first.Phase {
		t.Fatalf("retried evidence commit %+v %v, want %+v", again, err, first)
	}
	// A human command with an explicit ID.
	id := model.ID{0xaa, 1}
	audit := model.ControlAudit{ID: id, Principal: f.user, Action: "issues.ignore", Reason: "reviewed", Time: 5, Org: f.org.String(), PolicyEpoch: f.writer.PolicyEpoch(), Targets: []model.ID{f.issueID(1)}, RequestID: id, Outcome: model.AuditAllowed}
	ignored := f.issue(1, 2, f.evidence(1, 1))
	ignored.Workflow = "ignored"
	act := control.IssueCommand{Command: &id, ExpectedRevision: 2, Records: []control.IssueRecordChange{f.record(ignored)}, Audits: []model.ControlAudit{audit}, Action: &control.IssueActionRecord{Fingerprint: model.Hash{7}, Issue: f.issueID(1)}}
	ack := f.must(act)
	f.must(control.IssueCommand{ExpectedRevision: 3, Records: []control.IssueRecordChange{f.record(f.issue(4, 1, f.evidence(4, 3)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 3}})
	before := f.semantic()
	for range 3 {
		retry, err := f.commit(act)
		if err != nil || retry.Revision != ack.Revision || len(retry.AffectedIDs) != 1 {
			t.Fatalf("retry %+v %v", retry, err)
		}
	}
	if f.semantic() != before || len(f.audits("issues.ignore")) != 1 {
		t.Fatalf("a retry changed state or audited twice")
	}
	if s := f.snap(); s.Commands[id].Action == nil || s.Commands[id].Action.Issue != f.issueID(1) {
		t.Fatalf("command record %+v", s.Commands)
	}
	// The same ID with other content never commits and never answers as the original.
	other := act
	other.Records = []control.IssueRecordChange{f.record(func() model.GroupingIssue { i := ignored; i.Workflow = "open"; return i }())}
	if _, err = f.commit(other); code(err) != model.Conflict {
		t.Fatalf("command ID reused with other content: %v", err)
	}
	if f.semantic() != before {
		t.Fatal("a conflicting reuse changed state")
	}
}

// Two stores receive the same commands: one in order, one with early, late and
// duplicated retries interleaved. Both must end in the same state.
func TestIssueDeterministicUnderReorderedRetries(t *testing.T) {
	run := func(order []int) string {
		f := newIssFx(t)
		steps := []control.IssueCommand{
			f.first(),
			{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 2}, Effects: []control.IssueEffect{{ID: model.ID{0xf2}, Kind: "issue_regressed", Issue: f.issueID(2), Occurrence: f.evidence(2, 2).OccurrenceID}}},
			{ExpectedRevision: 2, Records: []control.IssueRecordChange{f.record(f.issue(3, 1, f.evidence(3, 3)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 3}},
		}
		for _, i := range order {
			if _, err := f.commit(steps[i]); err != nil && code(err) != model.Conflict {
				t.Fatal(err)
			}
		}
		return f.semantic()
	}
	ordered := run([]int{0, 1, 2})
	reordered := run([]int{0, 2, 1, 0, 2, 1, 0, 2, 2})
	if ordered != reordered || !strings.Contains(ordered, `"Revision":"3"`) {
		t.Fatalf("state depends on retry order:\n%s\n%s", ordered, reordered)
	}
}

func TestIssueScopeBeforeLookup(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	// A project outside the scope (an org project without a grant) and a missing
	// project answer alike.
	other := f.first()
	other.Project = f.otherProject
	_, errOther := f.commit(other)
	missing := f.first()
	missing.Project = model.NewID()
	_, errMissing := f.commit(missing)
	if code(errOther) != model.NotFound || code(errMissing) != model.NotFound || errOther.Error() != errMissing.Error() {
		t.Fatalf("wrong scope %v vs missing %v", errOther, errMissing)
	}
	if _, err := f.store.IssueBook(f.ctx, f.writer, f.otherProject); code(err) != model.NotFound {
		t.Fatalf("read outside the scope: %v", err)
	}
	if _, err := f.store.IssueBook(f.ctx, f.writer, model.NewID()); code(err) != model.NotFound {
		t.Fatalf("read of a missing project: %v", err)
	}
	// Read-only and org-admin scopes cannot commit.
	read, err := f.readScope(f.project)
	if err != nil {
		t.Fatal(err)
	}
	c := f.commitCmd(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}})
	if _, err = f.store.TransactIssues(f.ctx, read, c); code(err) != model.Forbidden {
		t.Fatalf("read scope committed: %v", err)
	}
	if _, err = f.store.TransactIssues(f.ctx, f.adminScope(), c); code(err) != model.Forbidden {
		t.Fatalf("admin scope committed through the issue path: %v", err)
	}
	c.ExpectedRevision = f.revision()
	if _, err = f.store.Transact(f.ctx, f.adminScope(), c); code(err) != model.Forbidden {
		t.Fatalf("admin scope committed through the generic path: %v", err)
	}
	// Reads: read scope may read, the zero scope may not.
	if _, err = f.store.IssueBook(f.ctx, read, f.project); err != nil {
		t.Fatalf("telemetry.read cannot read: %v", err)
	}
	if _, err = f.store.IssueBook(f.ctx, auth.Scope{}, f.project); err == nil {
		t.Fatal("zero scope read")
	}
	if _, err = f.store.TransactIssues(f.ctx, auth.Scope{}, c); err == nil {
		t.Fatal("zero scope committed")
	}
	// A scope whose grant was revoked after it was minted stops committing in
	// the same transaction that would apply the change.
	// (Every administrative change moves the policy epoch, which already kills
	// older scopes; the grant check is the independent second line, so this
	// revokes the grant without moving the epoch.)
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Orgs[f.org.String()].Grants, f.user.String()+":"+f.project.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}}); code(err) != model.NotFound {
		t.Fatalf("a scope with a revoked grant committed: %v", err)
	}
	if _, err = f.store.IssueBook(f.ctx, f.writer, f.project); code(err) != model.NotFound {
		t.Fatalf("a scope with a revoked grant read: %v", err)
	}
	if _, err = f.store.IssueBook(f.ctx, read, f.project); code(err) != model.NotFound {
		t.Fatalf("a read scope with a revoked grant read: %v", err)
	}
}

func TestIssueActorIsTheSessionAndAuditIsSafe(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	id := model.ID{0xaa, 2}
	mk := func(mutate func(*model.ControlAudit)) control.IssueCommand {
		a := model.ControlAudit{ID: id, Principal: f.user, Action: "issues.ignore", Reason: "reviewed by on-call", Time: 5, Org: f.org.String(), PolicyEpoch: f.writer.PolicyEpoch(), Targets: []model.ID{f.issueID(1)}, RequestID: id, Outcome: model.AuditAllowed}
		mutate(&a)
		i := f.issue(1, 2, f.evidence(1, 1))
		i.Workflow = "ignored"
		return control.IssueCommand{Command: &id, ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(i)}, Audits: []model.ControlAudit{a}, Action: &control.IssueActionRecord{Fingerprint: model.Hash{9}, Issue: f.issueID(1)}}
	}
	for name, mutate := range map[string]func(*model.ControlAudit){
		"forged principal": func(a *model.ControlAudit) { a.Principal = model.ID{0xee} },
		"other org":        func(a *model.ControlAudit) { a.Org = model.ID{0xee}.String() },
		"policy epoch":     func(a *model.ControlAudit) { a.PolicyEpoch++ },
		"denied outcome":   func(a *model.ControlAudit) { a.Outcome = model.AuditDenied },
	} {
		if _, err := f.commit(mk(mutate)); code(err) != model.Forbidden {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*model.ControlAudit){
		"foreign action":  func(a *model.ControlAudit) { a.Action = "incidents.ack" },
		"bare action":     func(a *model.ControlAudit) { a.Action = "ignore" },
		"control chars":   func(a *model.ControlAudit) { a.Reason = "bad\x00reason" },
		"empty reason":    func(a *model.ControlAudit) { a.Reason = "" },
		"overlong reason": func(a *model.ControlAudit) { a.Reason = strings.Repeat("r", 513) },
		"target count": func(a *model.ControlAudit) {
			a.Targets = make([]model.ID, 65)
			for i := range a.Targets {
				a.Targets[i] = model.ID{byte(i + 1)}
			}
		},
	} {
		if _, err := f.commit(mk(mutate)); code(err) != model.Invalid {
			t.Errorf("%s: %v", name, err)
		}
	}
	if s := f.snap(); s.Revision != 1 || len(f.audits("issues.ignore")) != 0 {
		t.Fatal("a rejected command committed")
	}
	f.must(mk(func(*model.ControlAudit) {}))
	a := f.audits("issues.ignore")
	if len(a) != 1 || a[0].Principal != f.user || a[0].ID != id || a[0].Targets[0] != f.issueID(1) || a[0].Outcome != model.AuditAllowed {
		t.Fatalf("audit %+v", a)
	}
}

func TestIssueRejectsMalformedCommands(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	ev2 := f.evidence(1, 2)
	grown := func() model.GroupingIssue { return f.issue(1, 2, f.evidence(1, 1), ev2) }
	newIssue := func(fp byte, idx uint64) control.IssueRecordChange {
		return f.record(f.issue(fp, 1, f.evidence(fp, idx)))
	}
	type tc struct {
		want model.Code
		c    control.IssueCommand
	}
	mut := func(f func(i *model.GroupingIssue)) control.IssueCommand {
		i := grown()
		f(&i)
		return control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: i, Explanations: json.RawMessage(`[]`)}}}
	}
	cases := map[string]tc{
		"empty commit":      {model.Invalid, control.IssueCommand{ExpectedRevision: 1}},
		"skipped revision":  {model.Conflict, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(1, 3, f.evidence(1, 1), ev2))}}},
		"new at revision 2": {model.Conflict, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(5, 2, f.evidence(5, 5)))}}},
		"edited ledger":     {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[0].EventTime++ })},
		"dropped ledger":    {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(1, 2))}}},
		"reordered ledger":  {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(1, 2, ev2, f.evidence(1, 1)))}}},
		"late history edit": {model.Invalid, mut(func(i *model.GroupingIssue) {
			i.LateHistory = []model.GroupingEvidence{f.evidence(1, 9)}
			i.Occurrences = i.Occurrences[:1]
			i.LateHistory[0].Fingerprint = model.Hash{4}
		})},
		"duplicate in issue":    {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].OccurrenceID = i.Occurrences[0].OccurrenceID })},
		"fingerprint mismatch":  {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].Fingerprint = model.Hash{9} })},
		"version mismatch":      {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].GroupingVersion = 2 })},
		"bad ancestry":          {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].Ancestry = "guess" })},
		"known without release": {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].ReleaseID = nil })},
		"zero origin index":     {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].Origin.Index = 0 })},
		"zero event time":       {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].EventTime = 0 })},
		"long freshness":        {model.Invalid, mut(func(i *model.GroupingIssue) { i.Occurrences[1].Freshness = strings.Repeat("f", 33) })},
		"other org":             {model.Invalid, mut(func(i *model.GroupingIssue) { i.Org = model.ID{9} })},
		"other project":         {model.Invalid, mut(func(i *model.GroupingIssue) { i.Project = f.otherProject })},
		"bad workflow":          {model.Invalid, mut(func(i *model.GroupingIssue) { i.Workflow = "bogus" })},
		"resolved no boundary":  {model.Invalid, mut(func(i *model.GroupingIssue) { i.Workflow = "resolved" })},
		"open with boundary":    {model.Invalid, mut(func(i *model.GroupingIssue) { t := model.UnixNano(5); i.ResolutionTime = &t })},
		"occurrence in another issue": {model.Conflict, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(6, 1, func() model.GroupingEvidence {
			e := f.evidence(6, 6)
			e.OccurrenceID = f.evidence(1, 1).OccurrenceID
			return e
		}()))}}},
		"duplicate record":    {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7), newIssue(7, 8)}}},
		"explanations object": {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: f.issue(8, 1, f.evidence(8, 8)), Explanations: json.RawMessage(`{"a":1}`)}}}},
		"too many records": {model.Quota, func() control.IssueCommand {
			c := control.IssueCommand{ExpectedRevision: 1}
			for i := range 65 {
				c.Records = append(c.Records, newIssue(byte(100+i), uint64(100+i)))
			}
			return c
		}()},
		"checkpoint zero index":     {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Checkpoint: &control.IssueCheckpoint{Group: f.group}}},
		"checkpoint regression":     {model.Conflict, control.IssueCommand{ExpectedRevision: 1, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 1}}},
		"effect unknown issue":      {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}, Effects: []control.IssueEffect{{ID: model.ID{0xf3}, Kind: "issue_regressed", Issue: model.ID{0xb0, 99}, Occurrence: f.evidence(7, 7).OccurrenceID}}}},
		"effect foreign occurrence": {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}, Effects: []control.IssueEffect{{ID: model.ID{0xf3}, Kind: "issue_regressed", Issue: f.issueID(7), Occurrence: f.evidence(1, 1).OccurrenceID}}}},
		"effect bad kind":           {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}, Effects: []control.IssueEffect{{ID: model.ID{0xf3}, Kind: "Regressed Now", Issue: f.issueID(7), Occurrence: f.evidence(7, 7).OccurrenceID}}}},
		"duplicate effect":          {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}, Effects: []control.IssueEffect{{ID: model.ID{0xf3}, Kind: "issue_regressed", Issue: f.issueID(7), Occurrence: f.evidence(7, 7).OccurrenceID}, {ID: model.ID{0xf3}, Kind: "issue_regressed", Issue: f.issueID(7), Occurrence: f.evidence(7, 7).OccurrenceID}}}},
		"gap without command":       {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 9}, Gap: &model.EvidenceGap{ID: model.ID{0xa7}, Org: f.org, Project: f.project, Group: f.group, After: 1, Through: 9, Count: 8, Start: 1, End: 2, Reason: "expired"}}},
		"action without command":    {model.Invalid, control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}, Action: &control.IssueActionRecord{Fingerprint: model.Hash{1}, Issue: f.issueID(7)}}},
	}
	names := make([]string, 0, len(cases))
	for n := range cases {
		names = append(names, n)
	}
	sort.Strings(names)
	before := f.semantic()
	for _, name := range names {
		c := cases[name]
		if _, err := f.commit(c.c); code(err) != c.want {
			t.Errorf("%s: got %v, want %s", name, err, c.want)
		}
	}
	// Gap shapes (explicit command ID equal to the gap ID).
	gapCmd := func(mutate func(*model.EvidenceGap, *control.IssueCommand)) control.IssueCommand {
		g := model.EvidenceGap{ID: model.ID{0xa7}, Org: f.org, Project: f.project, Group: f.group, After: 1, Through: 9, Count: 8, Start: 1, End: 2, Reason: "expired before processing"}
		id := g.ID
		c := control.IssueCommand{Command: &id, ExpectedRevision: 1, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 9}, Gap: &g}
		mutate(&g, &c)
		return c
	}
	for name, tcase := range map[string]struct {
		want   model.Code
		mutate func(*model.EvidenceGap, *control.IssueCommand)
	}{
		"gap not at checkpoint":   {model.Conflict, func(g *model.EvidenceGap, c *control.IssueCommand) { g.After = 0 }},
		"gap checkpoint mismatch": {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { c.Checkpoint.Index = 8 }},
		"gap other group":         {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { c.Checkpoint.Group = model.ID{7} }},
		"gap other project":       {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { g.Project = f.otherProject }},
		"gap declared by":         {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { g.DeclaredBy = "worker" }},
		"gap actor":               {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { a := f.user; g.Actor = &a }},
		"gap empty":               {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { g.Through, c.Checkpoint.Index = g.After, g.After }},
		"gap count":               {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { g.Count = 0 }},
		"gap reason":              {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { g.Reason = "" }},
		"gap command mismatch":    {model.Invalid, func(g *model.EvidenceGap, c *control.IssueCommand) { id := model.ID{0xa8}; c.Command = &id }},
	} {
		if _, err := f.commit(gapCmd(tcase.mutate)); code(err) != tcase.want {
			t.Errorf("%s: %v, want %s", name, err, tcase.want)
		}
	}
	if f.semantic() != before {
		t.Fatalf("a rejected command changed state:\n%s\n%s", before, f.semantic())
	}
	// Explanations that are not JSON at all (the DTO cannot marshal one, so the
	// payload is edited).
	garbage := f.commitCmd(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: f.issue(8, 1, f.evidence(8, 8)), Explanations: json.RawMessage(`["GARBAGE"]`)}}})
	garbage.Payload = json.RawMessage(strings.Replace(string(garbage.Payload), `["GARBAGE"]`, `[1,`, 1))
	garbage.CommandID = control.IssueCommandID(garbage.Payload)
	if _, err := f.store.TransactIssues(f.ctx, f.writer, garbage); code(err) != model.Invalid {
		t.Errorf("explanations garbage: %v", err)
	}
	// Strictness: unknown fields, a derived ID that is not the payload's, an
	// explicit ID that is not the declared one.
	good := f.commitCmd(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}})
	forged := good
	forged.CommandID = model.NewID()
	if _, err := f.store.TransactIssues(f.ctx, f.writer, forged); code(err) != model.Invalid {
		t.Errorf("derived ID forged: %v", err)
	}
	surprise := good
	surprise.Payload = json.RawMessage(strings.Replace(string(good.Payload), `"operation"`, `"surprise":1,"operation"`, 1))
	surprise.CommandID = control.IssueCommandID(surprise.Payload)
	if _, err := f.store.TransactIssues(f.ctx, f.writer, surprise); code(err) != model.Invalid {
		t.Errorf("unknown field: %v", err)
	}
	explicit := f.commitCmd(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{newIssue(7, 7)}, Command: &model.ID{0xaa, 7}})
	explicit.CommandID = model.ID{0xaa, 8}
	if _, err := f.store.TransactIssues(f.ctx, f.writer, explicit); code(err) != model.Invalid {
		t.Errorf("explicit ID mismatch: %v", err)
	}
	trailing := good
	trailing.Payload = append(append(json.RawMessage(nil), good.Payload...), []byte(` {}`)...)
	trailing.CommandID = control.IssueCommandID(trailing.Payload)
	if _, err := f.store.TransactIssues(f.ctx, f.writer, trailing); code(err) != model.Invalid {
		t.Errorf("trailing JSON: %v", err)
	}
	wrongKind := good
	wrongKind.Kind = string(control.KindIncidentAction)
	if _, err := f.store.TransactIssues(f.ctx, f.writer, wrongKind); code(err) != model.Invalid {
		t.Errorf("wrong kind: %v", err)
	}
	collect := f.commitCmd(control.IssueCommand{Operation: "collect_retired"})
	if _, err := f.store.TransactIssues(f.ctx, f.writer, collect); code(err) != model.Invalid {
		t.Errorf("collect through the commit path: %v", err)
	}
	if f.semantic() != before {
		t.Fatal("a rejected command changed state")
	}
}

func TestIssueBounds(t *testing.T) {
	f := newIssFx(t)
	// One issue ledger over its bound.
	var big []model.GroupingEvidence
	for i := uint64(1); i <= 1025; i++ {
		big = append(big, f.evidence(1, i))
	}
	if _, err := f.commit(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(1, 1, big...))}}); code(err) != model.Quota {
		t.Fatalf("1025 occurrences in one issue: %v", err)
	}
	if _, err := f.commit(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(1, 1, big[:1024]...))}}); err != nil {
		t.Fatalf("1024 occurrences: %v", err)
	}
	// Oversized explanations.
	huge := json.RawMessage(`["` + strings.Repeat("x", 256<<10) + `"]`)
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: f.issue(2, 1, f.evidence(2, 2000)), Explanations: huge}}}); code(err) != model.Quota {
		t.Fatalf("oversized explanations: %v", err)
	}
	// Per-commit effect and audit counts.
	var effects []control.IssueEffect
	for i := range 33 {
		effects = append(effects, control.IssueEffect{ID: model.ID{0xf0, byte(i + 1)}, Kind: "issue_regressed", Issue: f.issueID(1), Occurrence: f.evidence(1, 1).OccurrenceID})
	}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Effects: effects}); code(err) != model.Quota {
		t.Fatalf("33 effects in a command: %v", err)
	}
	// Total effects: 8 commands of 32 fill 256; the next is refused.
	for c := range 8 {
		var es []control.IssueEffect
		for i := range 32 {
			es = append(es, control.IssueEffect{ID: model.ID{0xf1, byte(c), byte(i)}, Kind: "issue_regressed", Issue: f.issueID(1), Occurrence: f.evidence(1, 1).OccurrenceID})
		}
		f.must(control.IssueCommand{ExpectedRevision: model.Revision(1 + c), Effects: es})
	}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 9, Effects: []control.IssueEffect{{ID: model.ID{0xf2}, Kind: "issue_regressed", Issue: f.issueID(1), Occurrence: f.evidence(1, 1).OccurrenceID}}}); code(err) != model.Quota {
		t.Fatalf("effects beyond the book bound: %v", err)
	}
	if s := f.snap(); len(s.Effects) != 256 || s.Revision != 9 {
		t.Fatalf("book %d effects, revision %d", len(s.Effects), s.Revision)
	}
}

func TestIssueProjectBounds(t *testing.T) {
	f := newIssFx(t)
	rev := 0
	// bulk is the i-th issue: a distinct two-byte fingerprint, ID and occurrence.
	bulk := func(i int, revision uint64, extra ...model.GroupingEvidence) model.GroupingIssue {
		fp := model.Hash{byte(i), byte(i >> 8), 1}
		ev := f.evidence(1, uint64(i))
		ev.Fingerprint, ev.OccurrenceID = fp, model.ID{0xd2, byte(i), byte(i >> 8)}
		for k := range extra {
			extra[k].Fingerprint = fp
		}
		return model.GroupingIssue{ID: model.ID{0xb2, byte(i), byte(i >> 8)}, Org: f.org, Project: f.project, GroupingVersion: 1, Fingerprint: fp, Workflow: "open", Revision: model.Revision(revision), Occurrences: append([]model.GroupingEvidence{ev}, extra...)}
	}
	add := func(from, to int) error {
		var rs []control.IssueRecordChange
		for i := from; i < to; i++ {
			rs = append(rs, f.record(bulk(i, 1)))
		}
		_, err := f.commit(control.IssueCommand{ExpectedRevision: model.Revision(rev), Records: rs})
		if err == nil {
			rev++
		}
		return err
	}
	// 256 issues fit (four commands of 64); the 257th does not.
	for from := 1; from < 257; from += 64 {
		if err := add(from, min(from+64, 257)); err != nil {
			t.Fatalf("issues from %d: %v", from, err)
		}
	}
	if len(f.snap().Issues) != 256 {
		t.Fatalf("%d issues", len(f.snap().Issues))
	}
	rs := []control.IssueRecordChange{f.record(bulk(1000, 1))}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: model.Revision(rev), Records: rs}); code(err) != model.Quota {
		t.Fatalf("257th issue: %v", err)
	}
	// An existing issue can still change at the bound.
	more := f.evidence(1, 301)
	more.OccurrenceID = model.ID{0xd3, 1}
	grown := bulk(1, 2, more)
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: model.Revision(rev), Records: []control.IssueRecordChange{f.record(grown)}}); err != nil {
		t.Fatalf("change at the issue bound: %v", err)
	}
}

func TestIssueProjectByteBound(t *testing.T) {
	f := newIssFx(t)
	blob := json.RawMessage(`["` + strings.Repeat("x", 250<<10) + `"]`)
	rev := 0
	var last error
	for n := 1; n <= 20 && last == nil; n++ {
		_, last = f.commit(control.IssueCommand{ExpectedRevision: model.Revision(rev), Records: []control.IssueRecordChange{{Issue: f.issue(byte(n), 1, f.evidence(byte(n), uint64(n))), Explanations: blob}}})
		if last == nil {
			rev++
		}
	}
	// 250 KiB each against a 4 MiB project bound: the 17th must be refused.
	if code(last) != model.Quota || rev != 16 {
		t.Fatalf("committed %d records, then %v", rev, last)
	}
}

func TestIssueGapCommitAndHealth(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	id := model.ID{0xa7}
	g := model.EvidenceGap{ID: id, Org: f.org, Project: f.project, Group: f.group, After: 1, Through: 9, Count: 8, Start: 1, End: 2, Signals: []model.Kind{model.Log}, Reason: "expired before processing", RecordedAt: 77}
	audit := model.ControlAudit{ID: id, Principal: f.user, Action: "issues.evidence_gap", Reason: g.Reason, Time: 77, Org: f.org.String(), PolicyEpoch: f.writer.PolicyEpoch(), Targets: []model.ID{id}, RequestID: id, Outcome: model.AuditAllowed}
	c := control.IssueCommand{Command: &id, ExpectedRevision: 1, Audits: []model.ControlAudit{audit}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 9}, Gap: &g}
	res := f.must(c)
	s := f.snap()
	if len(s.Gaps) != 1 || s.Gaps[0].ID != id || s.Gaps[0].Through != 9 || s.Checkpoints[f.group] != 9 || s.Revision != 2 || s.Gaps[0].DeclaredBy != "" || s.Gaps[0].Actor != nil {
		t.Fatalf("gap not committed with its checkpoint: %+v", s)
	}
	again, err := f.commit(c)
	if err != nil || again.Revision != res.Revision || len(f.snap().Gaps) != 1 || len(f.audits("issues.evidence_gap")) != 1 {
		t.Fatalf("gap retry: %+v %v", again, err)
	}
	// The same gap ID with other content never commits.
	g2 := g
	g2.Count = 7
	c2 := c
	c2.Gap = &g2
	if _, err = f.commit(c2); code(err) != model.Conflict {
		t.Fatalf("gap ID reuse: %v", err)
	}
	// A second gap that does not start at the checkpoint (9) is a conflict.
	id2 := model.ID{0xa8}
	g3 := model.EvidenceGap{ID: id2, Org: f.org, Project: f.project, Group: f.group, After: 5, Through: 20, Count: 15, Start: 1, End: 2, Reason: "expired"}
	if _, err = f.commit(control.IssueCommand{Command: &id2, ExpectedRevision: 2, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 20}, Gap: &g3}); code(err) != model.Conflict {
		t.Fatalf("gap skipping the checkpoint: %v", err)
	}
	if s = f.snap(); s.Checkpoints[f.group] != 9 || len(s.Gaps) != 1 {
		t.Fatalf("a rejected gap moved state: %+v", s)
	}
}

func TestIssueRetiredProjectDropsPayloads(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	f.must(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 2}, Effects: []control.IssueEffect{{ID: model.ID{0xf1}, Kind: "issue_regressed", Issue: f.issueID(2), Occurrence: f.evidence(2, 2).OccurrenceID}}})
	// Another project's facts must survive the collection.
	foreign := model.GroupingIssue{ID: model.ID{0xb0, 0x77}, Org: f.org, Project: f.otherProject, GroupingVersion: 1, Fingerprint: model.Hash{7}, Workflow: "open", Revision: 1}
	foreignKey := model.ReleaseScopeKey(f.org, f.otherProject, foreign.ID)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.GroupingIssues[foreignKey] = foreign
		st.IssueBooks[f.org.String()+":"+f.otherProject.String()] = json.RawMessage(`{}`)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Not retired: nothing is collected, and nothing is claimed.
	if _, err := f.store.CollectRetiredIssues(f.ctx, f.adminScope(), f.project); code(err) != model.Conflict {
		t.Fatalf("collect of a live project: %v", err)
	}
	if _, _, err := f.del(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{f.project}}); err != nil {
		t.Fatal(err)
	}
	// Retirement denies reads and commits at once.
	if _, err := f.store.IssueBook(f.ctx, f.writer, f.project); err == nil {
		t.Fatal("a retired project's issues stayed readable")
	}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 2, Records: []control.IssueRecordChange{f.record(f.issue(3, 1, f.evidence(3, 3)))}}); err == nil {
		t.Fatal("a retired project accepted evidence")
	}
	if _, err := f.store.CollectRetiredIssues(f.ctx, f.writer, f.project); err == nil {
		t.Fatal("a non-administrator collected")
	}
	// Before collection the payloads are still held; after, none.
	count := func() (issues, books int) {
		_ = f.store.View(f.ctx, func(st control.State) error {
			for _, gi := range st.GroupingIssues {
				if gi.Project == f.project {
					issues++
				}
			}
			for k := range st.IssueBooks {
				if strings.HasPrefix(k, f.org.String()+":"+f.project.String()) {
					books++
				}
			}
			return nil
		})
		return
	}
	if i, b := count(); i != 2 || b != 1 {
		t.Fatalf("before collection: %d issues %d books", i, b)
	}
	ids, err := f.store.CollectRetiredIssues(f.ctx, f.adminScope(), f.project)
	if err != nil || len(ids) != 2 {
		t.Fatalf("collect: %v %v", ids, err)
	}
	if i, b := count(); i != 0 || b != 0 {
		t.Fatalf("after collection: %d issues %d books", i, b)
	}
	again, err := f.store.CollectRetiredIssues(f.ctx, f.adminScope(), f.project)
	if err != nil || len(again) != 0 {
		t.Fatalf("second collect: %v %v", again, err)
	}
	if err = f.store.View(f.ctx, func(st control.State) error {
		if _, ok := st.GroupingIssues[foreignKey]; !ok {
			t.Error("another project's issue was dropped")
		}
		if _, ok := st.IssueBooks[f.org.String()+":"+f.otherProject.String()]; !ok {
			t.Error("another project's book was dropped")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// DropRetiredIssueBooks is the pure hook the retire-time collection calls inside
// the retiring transaction: it touches only the named org and project.
func TestDropRetiredIssueBooksIsScoped(t *testing.T) {
	org, other, p1, p2 := model.ID{1}, model.ID{2}, model.ID{3}, model.ID{4}
	mk := func(o, p model.ID, n byte) model.GroupingIssue {
		return model.GroupingIssue{ID: model.ID{0xb0, n}, Org: o, Project: p, GroupingVersion: 1, Fingerprint: model.Hash{n}, Workflow: "open", Revision: 1}
	}
	st := &control.State{GroupingIssues: map[string]model.GroupingIssue{}, IssueBooks: map[string]json.RawMessage{}}
	for _, in := range []model.GroupingIssue{mk(org, p1, 1), mk(org, p2, 2), mk(other, p1, 3)} {
		st.GroupingIssues[model.ReleaseScopeKey(in.Org, in.Project, in.ID)] = in
	}
	st.IssueBooks[org.String()+":"+p1.String()] = json.RawMessage(`{}`)
	st.IssueBooks[org.String()+":"+p2.String()] = json.RawMessage(`{}`)
	st.IssueBooks[other.String()+":"+p1.String()] = json.RawMessage(`{}`)
	ids, book := control.DropRetiredIssueBooks(st, org, p1)
	if len(ids) != 1 || ids[0] != (model.ID{0xb0, 1}) || !book {
		t.Fatalf("dropped %v %v", ids, book)
	}
	if len(st.GroupingIssues) != 2 || len(st.IssueBooks) != 2 {
		t.Fatalf("scoped drop removed too much: %d issues, %d books", len(st.GroupingIssues), len(st.IssueBooks))
	}
	if _, ok := st.IssueBooks[org.String()+":"+p1.String()]; ok {
		t.Fatal("the retired project's book stayed")
	}
	if again, book := control.DropRetiredIssueBooks(st, org, p1); len(again) != 0 || book {
		t.Fatalf("second drop %v %v", again, book)
	}
	if got, book := control.DropRetiredIssueBooks(&control.State{}, org, p1); len(got) != 0 || book {
		t.Fatalf("empty state %v %v", got, book)
	}
}

// 24 committers race on one project revision; exactly one wins each round and
// every issue lands exactly once.
func TestIssueConcurrentCommitters(t *testing.T) {
	f := newIssFx(t)
	const n = 24
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, conflicts := map[int]model.Revision{}, 0
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fp := byte(i + 1)
			for range 200 {
				s, err := f.store.IssueBook(f.ctx, f.writer, f.project)
				if err != nil {
					t.Error(err)
					return
				}
				c := control.IssueCommand{ExpectedRevision: s.Revision, Records: []control.IssueRecordChange{f.record(f.issue(fp, 1, f.evidence(fp, uint64(i+1))))}, Checkpoint: &control.IssueCheckpoint{Group: model.ID{0xe2, fp}, Index: 1}}
				res, err := f.commit(c)
				if err == nil {
					mu.Lock()
					won[i] = res.Revision
					mu.Unlock()
					return
				}
				if code(err) != model.Conflict {
					t.Error(err)
					return
				}
				mu.Lock()
				conflicts++
				mu.Unlock()
			}
			t.Errorf("committer %d never won", i)
		}()
	}
	wg.Wait()
	s := f.snap()
	if len(won) != n || len(s.Issues) != n || s.Revision != n {
		t.Fatalf("won %d, issues %d, revision %d", len(won), len(s.Issues), s.Revision)
	}
	seen := map[model.Revision]bool{}
	for _, r := range won {
		if seen[r] {
			t.Fatalf("two committers share control revision %d", r)
		}
		seen[r] = true
	}
	for _, in := range s.Issues {
		if in.Revision != 1 || len(in.Occurrences) != 1 {
			t.Fatalf("issue %+v", in)
		}
	}
	t.Logf("%d conflicts lost to retries", conflicts)
}

// 24 goroutines send the very same command: it commits once and every caller
// is given the one original result.
func TestIssueConcurrentSameCommandCommitsOnce(t *testing.T) {
	f := newIssFx(t)
	id := model.ID{0xaa, 3}
	audit := model.ControlAudit{ID: id, Principal: f.user, Action: "issues.resolve", Reason: "reviewed", Time: 5, Org: f.org.String(), PolicyEpoch: f.writer.PolicyEpoch(), Targets: []model.ID{f.issueID(1)}, RequestID: id, Outcome: model.AuditAllowed}
	c := f.first()
	c.Command, c.Audits = &id, []model.ControlAudit{audit}
	cmd := f.commitCmd(c)
	results := make([]control.Result, 24)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := f.store.TransactIssues(f.ctx, f.writer, cmd)
			if err != nil {
				t.Error(err)
			}
			results[i] = r
		}()
	}
	wg.Wait()
	for i := range results {
		if results[i].Revision != results[0].Revision || results[i].Phase != "applied" {
			t.Fatalf("result %d %+v vs %+v", i, results[i], results[0])
		}
	}
	if s := f.snap(); s.Revision != 1 || len(f.audits("issues.resolve")) != 1 {
		t.Fatalf("revision %d, audits %d", s.Revision, len(f.audits("issues.resolve")))
	}
}

func TestIssueStateHoldsNoTelemetryText(t *testing.T) {
	f := newIssFx(t)
	c := f.first()
	f.must(c)
	var raw []byte
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, _ = json.Marshal(struct {
			B map[string]json.RawMessage
			G map[string]model.GroupingIssue
		}{st.IssueBooks, st.GroupingIssues})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Only the closed field names of IDs, hashes, counts, cursors and versions.
	for _, forbidden := range []string{"message", "body", "stack", "title", "attributes"} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Fatalf("issue state has a %q field: %s", forbidden, raw)
		}
	}
	var evidence map[string]json.RawMessage
	var one struct {
		Occurrences []map[string]json.RawMessage
	}
	var gi model.GroupingIssue
	_ = f.store.View(f.ctx, func(st control.State) error {
		gi = st.GroupingIssues[model.ReleaseScopeKey(f.org, f.project, f.issueID(1))]
		return nil
	})
	rawIssue, _ := json.Marshal(gi)
	_ = json.Unmarshal(rawIssue, &one)
	evidence = one.Occurrences[0]
	keys := make([]string, 0, len(evidence))
	for k := range evidence {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "ancestry,arrival_time_ns,event_time_ns,fingerprint,freshness,grouping_version,occurrence_id,ordinal,origin,record_id,release_id"
	if strings.Join(keys, ",") != want {
		t.Fatalf("evidence fields %s", strings.Join(keys, ","))
	}
}

// Issue state, command records and checkpoints survive a control snapshot
// import and a restart; a restarted store still answers a committed command once.
func TestIssueSurvivesRestartAndSnapshotImport(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	open := func() (*control.Store, *auth.Service) {
		store, err := control.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
		if err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
			store.Close()
			t.Fatal(err)
		}
		if err = store.BindReleases(); err != nil {
			store.Close()
			t.Fatal(err)
		}
		return store, svc
	}
	store, svc := open()
	boot, _ := store.BootstrapToken()
	session, err := svc.Bootstrap(ctx, boot, "owner@example.test", "a long test password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := svc.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org, project, group := model.NewID(), model.NewID(), model.ID{0xe1}
	admin := func(kind string, p auth.AdminPayload) {
		var revision model.Revision
		_ = store.View(ctx, func(st control.State) error { revision = st.Revision; return nil })
		raw, _ := json.Marshal(p)
		if _, err := svc.AdminCommand(ctx, cred, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw}); err != nil {
			t.Fatal(kind, err)
		}
	}
	admin("create_org", auth.AdminPayload{Name: "restart", Reason: "fixture"})
	admin("create_project", auth.AdminPayload{ID: project, Name: "p1", Reason: "fixture"})
	admin("membership", auth.AdminPayload{UserID: session.User, Enabled: true, Reason: "fixture"})
	admin("grant", auth.AdminPayload{UserID: session.User, ProjectID: project, Enabled: true, Permissions: []string{string(issuesWrite)}, Reason: "fixture"})
	rel := model.ID{0xc0, 1}
	issue := func(rev uint64, n byte, workflow string) model.GroupingIssue {
		ev := model.GroupingEvidence{OccurrenceID: model.ID{0xd0, n}, RecordID: model.ID{0xd1, n}, Origin: model.Cursor{Group: group, Index: model.Uint64(n)}, GroupingVersion: 1, Fingerprint: model.Hash{1}, EventTime: model.UnixNano(1000 + int64(n)), ArrivalTime: 2000, ReleaseID: &rel, Ancestry: "known", Ordinal: model.Uint64(n), Freshness: "fresh"}
		return model.GroupingIssue{ID: model.ID{0xb0, 1}, Org: org, Project: project, GroupingVersion: 1, Fingerprint: model.Hash{1}, Workflow: workflow, Revision: model.Revision(rev), Occurrences: []model.GroupingEvidence{ev}}
	}
	send := func(store *control.Store, svc *auth.Service, cred auth.Credential, c control.IssueCommand) (control.Result, error) {
		scope, err := svc.Authorize(ctx, cred, org, []model.ID{project}, issuesWrite)
		if err != nil {
			t.Fatal(err)
		}
		c.Operation, c.Project = "commit", project
		raw, _ := json.Marshal(c)
		id := control.IssueCommandID(raw)
		if c.Command != nil {
			id = *c.Command
		}
		return store.TransactIssues(ctx, scope, control.Command{CommandID: id, Kind: string(control.KindApplyIssueEvidence), Payload: raw})
	}
	semantic := func(store *control.Store) string {
		scope, err := svc.Authorize(ctx, cred, org, []model.ID{project}, issuesWrite)
		if err != nil {
			t.Fatal(err)
		}
		s, err := store.IssueBook(ctx, scope, project)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(s)
		return string(raw)
	}
	one := control.IssueCommand{Records: []control.IssueRecordChange{{Issue: issue(1, 1, "open"), Explanations: json.RawMessage(`[]`)}}, Checkpoint: &control.IssueCheckpoint{Group: group, Index: 1}}
	first, err := send(store, svc, cred, one)
	if err != nil {
		t.Fatal(err)
	}
	id := model.ID{0xaa, 9}
	two := control.IssueCommand{Command: &id, ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: issue(2, 1, "ignored"), Explanations: json.RawMessage(`[{"k":1}]`)}}, Action: &control.IssueActionRecord{Fingerprint: model.Hash{3}, Issue: model.ID{0xb0, 1}}}
	second, err := send(store, svc, cred, two)
	if err != nil {
		t.Fatal(err)
	}
	before := semantic(store)
	seed, _, err := store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := control.OpenSeed(filepath.Join(t.TempDir(), "imported"), seed)
	if err != nil {
		t.Fatal(err)
	}
	var rawBooks, rawIssues string
	if err = imported.View(ctx, func(st control.State) error {
		b, _ := json.Marshal(st.IssueBooks)
		i, _ := json.Marshal(st.GroupingIssues)
		rawBooks, rawIssues = string(b), string(i)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	imported.Close()
	var liveBooks, liveIssues string
	if err = store.View(ctx, func(st control.State) error {
		b, _ := json.Marshal(st.IssueBooks)
		i, _ := json.Marshal(st.GroupingIssues)
		liveBooks, liveIssues = string(b), string(i)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if rawBooks != liveBooks || rawIssues != liveIssues || !strings.Contains(rawBooks, "commands") {
		t.Fatalf("snapshot import changed issue state:\n%s\n%s", liveBooks, rawBooks)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, svc = open()
	defer store.Close()
	if cred, err = svc.Authenticate(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if after := semantic(store); after != before {
		t.Fatalf("restart changed issue state:\n%s\n%s", before, after)
	}
	again, err := send(store, svc, cred, two)
	if err != nil || again.Revision != second.Revision {
		t.Fatalf("committed command not recognized after restart: %+v vs %+v (%v)", again, second, err)
	}
	againFirst, err := send(store, svc, cred, one)
	if err != nil || againFirst.Revision != first.Revision {
		t.Fatalf("evidence commit not recognized after restart: %+v vs %+v (%v)", againFirst, first, err)
	}
	stale := control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{{Issue: issue(2, 3, "open"), Explanations: json.RawMessage(`[]`)}}}
	if _, err = send(store, svc, cred, stale); code(err) != model.Conflict {
		t.Fatalf("a stale revision committed after restart: %v", err)
	}
}

// The grouping migration (06.01) and the lifecycle share the issue records: a
// commit that read an issue before a migration cannot overwrite the migrated
// record, and a later commit keeps the migration links.
func TestIssueCommitCannotOverwriteGroupingMigration(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	mig := model.GroupingMigration{ID: model.ID{0xaa, 0x55}, Org: f.org, Project: f.project, From: f.issueID(1), To: model.ID{0xb0, 0x99}, FromRevision: 1, GroupingVersion: 2, Fingerprint: model.Hash{9}, Reason: "regroup", At: 50}
	raw, err := json.Marshal(model.ReleaseCommand{Operation: "grouping_migration", Migration: &mig, At: 50, RequestID: model.ID{1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindApplyIssueEvidence), Payload: raw}); err != nil {
		t.Fatalf("migration: %v", err)
	}
	s := f.snap()
	if len(s.Issues) != 2 || s.Revision != 1 {
		t.Fatalf("migrated state %+v", s)
	}
	// A worker that loaded the issue at revision 1 commits against revision 2 of the record: refused.
	stale := f.issue(1, 2, f.evidence(1, 1), f.evidence(1, 2))
	_, err = f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(stale)}})
	if code(err) != model.Conflict || !strings.Contains(err.Error(), "issue_record_conflict") {
		t.Fatalf("overwrite of a migrated record: %v", err)
	}
	// Reading the record again, the next commit goes through and must keep the link.
	migrated := f.issue(1, 3, f.evidence(1, 1), f.evidence(1, 2))
	if _, err = f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(migrated)}}); code(err) != model.Invalid {
		t.Fatalf("a commit that dropped the migration link: %v", err)
	}
	migrated.MigrationLinks = []model.ID{mig.ID}
	f.must(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(migrated)}})
	if s = f.snap(); s.Revision != 2 || len(s.Issues) != 2 {
		t.Fatalf("state %+v", s)
	}
}

// A second principal with issues.write acts as itself: it cannot replay or
// reuse another principal's command ID, and its audits carry its own ID.
func TestIssueCommandBelongsToItsPrincipal(t *testing.T) {
	f := newIssFx(t)
	second := model.NewID()
	f.admin("create_user", f.org, auth.AdminPayload{ID: second, Email: "second@example.test", Password: "a long test password 2026", Reason: "fixture"})
	f.admin("membership", f.org, auth.AdminPayload{UserID: second, Enabled: true, Reason: "fixture"})
	f.admin("grant", f.org, auth.AdminPayload{UserID: second, ProjectID: f.project, Enabled: true, Permissions: []string{string(issuesWrite)}, Reason: "fixture"})
	login, err := f.svc.Login(f.ctx, "second@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.svc.Authenticate(f.ctx, login.Token)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.svc.Authorize(f.ctx, cred, f.org, []model.ID{f.project}, issuesWrite)
	if err != nil {
		t.Fatal(err)
	}
	// The first writer's scope is older than the grant change (the epoch moved):
	// it must be minted again.
	if f.writer, err = f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, issuesWrite); err != nil {
		t.Fatal(err)
	}
	id := model.ID{0xaa, 5}
	audit := model.ControlAudit{ID: id, Principal: f.user, Action: "issues.ignore", Reason: "mine", Time: 5, Org: f.org.String(), PolicyEpoch: f.writer.PolicyEpoch(), Targets: []model.ID{f.issueID(1)}, RequestID: id, Outcome: model.AuditAllowed}
	ignored := f.issue(1, 2, f.evidence(1, 1))
	ignored.Workflow = "ignored"
	f.must(f.first())
	act := control.IssueCommand{Command: &id, ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(ignored)}, Audits: []model.ControlAudit{audit}, Action: &control.IssueActionRecord{Fingerprint: model.Hash{1}, Issue: f.issueID(1)}}
	f.must(act)
	// The other principal sends the very same command: not its command.
	if _, err = f.store.TransactIssues(f.ctx, other, f.commitCmd(act)); code(err) != model.NotFound {
		t.Fatalf("another principal replayed a command: %v", err)
	}
	// And its own audit cannot name the first principal.
	if _, err = f.store.TransactIssues(f.ctx, other, f.commitCmd(control.IssueCommand{Command: &model.ID{0xaa, 6}, ExpectedRevision: 2, Records: []control.IssueRecordChange{f.record(func() model.GroupingIssue { i := ignored; i.Revision = 3; i.Workflow = "open"; return i }())}, Audits: []model.ControlAudit{{ID: model.ID{0xaa, 6}, Principal: f.user, Action: "issues.unignore", Reason: "x", Time: 5, Org: f.org.String(), PolicyEpoch: other.PolicyEpoch(), Targets: []model.ID{f.issueID(1)}, RequestID: id, Outcome: model.AuditAllowed}}})); code(err) != model.Forbidden {
		t.Fatalf("audit under another principal: %v", err)
	}
	// The other principal acts as itself.
	unignored := ignored
	unignored.Revision, unignored.Workflow = 3, "open"
	mine := model.ID{0xaa, 7}
	a2 := model.ControlAudit{ID: mine, Principal: second, Action: "issues.unignore", Reason: "theirs", Time: 6, Org: f.org.String(), PolicyEpoch: other.PolicyEpoch(), Targets: []model.ID{f.issueID(1)}, RequestID: mine, Outcome: model.AuditAllowed}
	if _, err = f.store.TransactIssues(f.ctx, other, f.commitCmd(control.IssueCommand{Command: &mine, ExpectedRevision: 2, Records: []control.IssueRecordChange{f.record(unignored)}, Audits: []model.ControlAudit{a2}, Action: &control.IssueActionRecord{Fingerprint: model.Hash{2}, Issue: f.issueID(1)}})); err != nil {
		t.Fatal(err)
	}
	if a := f.audits("issues.unignore"); len(a) != 1 || a[0].Principal != second {
		t.Fatalf("audits %+v", a)
	}
}

func TestIssueEffectAndMembershipAndPayloadBounds(t *testing.T) {
	f := newIssFx(t)
	eff := control.IssueEffect{ID: model.ID{0xf1}, Kind: "issue_regressed", Issue: f.issueID(1), Occurrence: f.evidence(1, 1).OccurrenceID}
	c := f.first()
	c.Effects = []control.IssueEffect{eff}
	f.must(c)
	// An effect minted once is never minted again, by a later command either.
	dup := control.IssueCommand{ExpectedRevision: 1, Effects: []control.IssueEffect{eff}}
	if _, err := f.commit(dup); code(err) != model.Invalid {
		t.Fatalf("effect ID reused by a later command: %v", err)
	}
	// A payload over the bound is refused whole, before it is parsed.
	big := json.RawMessage(`["` + strings.Repeat("x", 250<<10) + `"]`)
	huge := control.IssueCommand{ExpectedRevision: 1}
	for i := 1; i <= 17; i++ {
		huge.Records = append(huge.Records, control.IssueRecordChange{Issue: f.issue(byte(100+i), 1, f.evidence(byte(100+i), uint64(100+i))), Explanations: big})
	}
	if _, err := f.commit(huge); code(err) != model.TooLarge {
		t.Fatalf("oversized payload: %v", err)
	}
	// (The dispatcher bounds it too, for a command that arrives through Transact.)
	if _, err := f.store.Transact(f.ctx, f.adminScope(), func() control.Command { c := f.commitCmd(huge); c.ExpectedRevision = f.revision(); return c }()); code(err) != model.TooLarge {
		t.Fatalf("oversized payload through the generic path: %v", err)
	}
	// A principal that is no longer a member stops committing in the transaction
	// that would apply the change (even with the grant record still present and
	// the epoch not yet moved).
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Orgs[f.org.String()].Members, f.user.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}}); code(err) != model.NotFound {
		t.Fatalf("a non-member committed: %v", err)
	}
}

// A scope names its projects: a principal that holds issues.write on two
// projects commits only to the one its scope names.
func TestIssueScopeIsConfinedToItsProjects(t *testing.T) {
	f := newIssFx(t)
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.otherProject, Enabled: true, Permissions: []string{string(issuesWrite)}, Reason: "fixture"})
	narrow, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, issuesWrite)
	if err != nil {
		t.Fatal(err)
	}
	wide, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project, f.otherProject}, issuesWrite)
	if err != nil {
		t.Fatal(err)
	}
	c := f.first()
	c.Project = f.otherProject
	cmd := f.commitCmd(c)
	if _, err = f.store.TransactIssues(f.ctx, narrow, cmd); code(err) != model.NotFound {
		t.Fatalf("a scope committed to a project it does not name: %v", err)
	}
	if _, err = f.store.IssueBook(f.ctx, narrow, f.otherProject); code(err) != model.NotFound {
		t.Fatalf("a scope read a project it does not name: %v", err)
	}
	// The issue records name their own project, so a wide scope still cannot
	// write another project's records through this one.
	if _, err = f.store.TransactIssues(f.ctx, wide, cmd); code(err) != model.Invalid {
		t.Fatalf("issue record of another project: %v", err)
	}
}

func TestIssueLateHistoryAndIdentityAreImmutable(t *testing.T) {
	f := newIssFx(t)
	late := f.evidence(1, 5)
	withLate := f.issue(1, 1, f.evidence(1, 1))
	withLate.LateHistory = []model.GroupingEvidence{late}
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(withLate)}})
	dropped := f.issue(1, 2, f.evidence(1, 1))
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(dropped)}}); code(err) != model.Invalid {
		t.Fatalf("dropped late history: %v", err)
	}
	edited := f.issue(1, 2, f.evidence(1, 1))
	l := late
	l.ArrivalTime++
	edited.LateHistory = []model.GroupingEvidence{l}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(edited)}}); code(err) != model.Invalid {
		t.Fatalf("rewritten late history: %v", err)
	}
	grown := f.issue(1, 2, f.evidence(1, 1))
	grown.LateHistory = []model.GroupingEvidence{late, f.evidence(1, 6)}
	f.must(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(grown)}})
	// An issue's identity (grouping version and fingerprint) never changes, even
	// while it holds no evidence for the ledger checks to trip over.
	f.must(control.IssueCommand{ExpectedRevision: 2, Records: []control.IssueRecordChange{f.record(f.issue(3, 1))}})
	renamed := f.issue(3, 2)
	renamed.Fingerprint = model.Hash{9}
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 3, Records: []control.IssueRecordChange{f.record(renamed)}}); code(err) != model.Invalid {
		t.Fatalf("changed fingerprint: %v", err)
	}
	regrouped := f.issue(3, 2)
	regrouped.GroupingVersion = 2
	if _, err := f.commit(control.IssueCommand{ExpectedRevision: 3, Records: []control.IssueRecordChange{f.record(regrouped)}}); code(err) != model.Invalid {
		t.Fatalf("changed grouping version: %v", err)
	}
}

// Even with the control-wide command memory gone (an imported snapshot of an
// older installation, say), the project's own command record refuses a reused ID.
func TestIssueBookRefusesReusedCommandWithoutControlMemory(t *testing.T) {
	f := newIssFx(t)
	id := model.ID{0xaa, 8}
	c := f.first()
	c.Command = &id
	f.must(c)
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Commands, id.String())
		delete(st.CommandOwners, id.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	again := control.IssueCommand{Command: &id, ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}}
	if _, err := f.commit(again); code(err) != model.Conflict || !strings.Contains(err.Error(), "issue_command_exists") {
		t.Fatalf("reused command ID: %v", err)
	}
	if s := f.snap(); s.Revision != 1 || len(s.Issues) != 1 {
		t.Fatalf("state %+v", s)
	}
}

// A retirement marker alone (before the saga has removed the project from the
// organization) already closes the project's issues, and a raw-read scope is not
// an issue reader.
func TestIssueReadsAreClosedByRetirementMarkerAndRawRead(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read), string(issuesWrite), string(auth.RawRead)}, Reason: "fixture"})
	raw, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, auth.RawRead)
	if err != nil {
		t.Fatal(err)
	}
	if f.writer, err = f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.project}, issuesWrite); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.IssueBook(f.ctx, raw, f.project); code(err) != model.Forbidden {
		t.Fatalf("raw.read read the issues: %v", err)
	}
	if err = f.store.Update(f.ctx, func(st *control.State) error {
		st.RetiredProjects = map[string]model.ID{f.org.String() + ":" + f.project.String(): model.NewID()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.IssueBook(f.ctx, f.writer, f.project); code(err) != model.NotFound {
		t.Fatalf("a retired project's issues stayed readable: %v", err)
	}
	if _, err = f.commit(control.IssueCommand{ExpectedRevision: 1, Records: []control.IssueRecordChange{f.record(f.issue(2, 1, f.evidence(2, 2)))}}); code(err) != model.NotFound {
		t.Fatalf("a retired project accepted evidence: %v", err)
	}
}

// A retry of a committed command answers only a scope that still acts in the
// project: the first result is not a way around a revoked grant.
func TestIssueReplayIsScopedLikeAFirstCommit(t *testing.T) {
	f := newIssFx(t)
	id := model.ID{0xaa, 9}
	c := f.first()
	c.Command = &id
	f.must(c)
	if _, err := f.commit(c); err != nil {
		t.Fatalf("replay before the revocation: %v", err)
	}
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Orgs[f.org.String()].Grants, f.user.String()+":"+f.project.String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(c); code(err) != model.NotFound {
		t.Fatalf("replay by a scope whose grant was revoked: %v", err)
	}
}

// A declared gap is recorded once: with the control-wide command memory gone the
// book still names the reuse, as a gap and not only as a command.
func TestIssueGapIDIsRecordedOnce(t *testing.T) {
	f := newIssFx(t)
	f.must(f.first())
	id := model.ID{0xa7}
	gap := func(count model.Uint64, expected model.Revision) control.IssueCommand {
		g := model.EvidenceGap{ID: id, Org: f.org, Project: f.project, Group: f.group, After: 1, Through: 9, Count: count, Start: 1, End: 2, Reason: "expired before processing"}
		return control.IssueCommand{Command: &id, ExpectedRevision: expected, Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 9}, Gap: &g}
	}
	f.must(gap(8, 1))
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		delete(st.Commands, id.String())
		delete(st.CommandOwners, id.String())
		raw := st.IssueBooks[f.org.String()+":"+f.project.String()]
		var b control.IssueBook
		if err := json.Unmarshal(raw, &b); err != nil {
			return err
		}
		delete(b.Commands, id.String())
		b.Checkpoints[f.group.String()] = 1
		raw, err := json.Marshal(b)
		st.IssueBooks[f.org.String()+":"+f.project.String()] = raw
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.commit(gap(7, 2)); code(err) != model.Conflict || !strings.Contains(err.Error(), "issue_gap_exists") {
		t.Fatalf("a gap ID recorded twice: %v", err)
	}
}
