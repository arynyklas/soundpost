// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// Issue evidence (State.GroupingIssues + State.IssueBooks) is derived from error
// records. These tests commit it through the real TransactIssues path with
// distinct markers (record IDs, origin groups, release IDs, denominator cursor
// groups) and pin what each deletion mode removes from the control state, the
// control snapshot and control.db.

type issEraseFx struct{ *issFx }

func newIssEraseFx(t *testing.T) *issEraseFx { return &issEraseFx{newIssFx(t)} }

// marker is one evidence item's distinct IDs; every ID string is a canary.
type marker struct {
	occurrence, record, group, release, denomGroup model.ID
}

func newMarker(tag byte, n byte) marker {
	return marker{
		occurrence: model.ID{0xA1, tag, n, 1}, record: model.ID{0xA2, tag, n, 2}, group: model.ID{0xA3, tag, n, 3},
		release: model.ID{0xA4, tag, n, 4}, denomGroup: model.ID{0xA5, tag, n, 5},
	}
}
func (m marker) all() []string {
	return []string{m.occurrence.String(), m.record.String(), m.group.String(), m.release.String(), m.denomGroup.String()}
}

func (f *issEraseFx) ev(fp byte, m marker, event int64, index uint64) model.GroupingEvidence {
	rel := m.release
	return model.GroupingEvidence{
		OccurrenceID: m.occurrence, RecordID: m.record, Origin: model.Cursor{Group: m.group, Index: model.Uint64(index)}, GroupingVersion: 1, Fingerprint: model.Hash{fp},
		EventTime: model.UnixNano(event), ArrivalTime: model.UnixNano(event + 5), ReleaseID: &rel, Ancestry: "known", Ordinal: model.Uint64(index), Freshness: "fresh",
		Denominator: &model.GroupingDenominator{Name: "errors", Start: model.UnixNano(event), End: model.UnixNano(event + 1), Count: 7, Complete: true, Cursors: []model.Cursor{{Group: m.denomGroup, Index: 1}}},
	}
}

func explanation(occ model.ID, event int64) string {
	return fmt.Sprintf(`{"occurrence_id":%q,"event_time_ns":%d,"eligible":true,"reason":"after_resolution","ancestry_known":true,"resolution_time_ns":1,"threshold":2,"window_ns":9,"qualifying":1,"reopened":false}`, occ.String(), event)
}

func (f *issEraseFx) saga(req control.DeleteScope) model.ID {
	f.t.Helper()
	id, _, err := f.del(req)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordBarriers(f.ctx, id, cursors(model.DeleteSlots)); err != nil {
		f.t.Fatal(err)
	}
	at := model.UnixNano(f.now.UnixNano())
	if _, err = f.store.CompleteDeletion(f.ctx, id, at, nil); err != nil {
		f.t.Fatal(err)
	}
	if _, err = f.store.RecordPhysicalCleanup(f.ctx, f.org, []model.ID{id}, at); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *issEraseFx) stateHolds(canary string) bool {
	f.t.Helper()
	held := false
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, err := json.Marshal(st)
		held = eraseDeep(raw, []byte(canary), 3)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
	return held
}

func (f *issEraseFx) snapshotHolds(canary string) bool {
	f.t.Helper()
	raw, _, err := f.store.ReplicationSeed()
	if err != nil {
		f.t.Fatal(err)
	}
	return eraseDeep(raw, []byte(canary), 3)
}

// gone asserts the canary is absent from the state, the snapshot and control.db.
func (f *issEraseFx) gone(canary string) {
	f.t.Helper()
	if f.stateHolds(canary) {
		f.t.Errorf("%s is still in the control state", canary)
	}
	if f.snapshotHolds(canary) {
		f.t.Errorf("%s is still in the control snapshot", canary)
	}
	if hits := controlDBHits(f.t, f.dir, canary); len(hits) != 0 {
		f.t.Errorf("%s is still in %v", canary, hits)
	}
}

func (f *issEraseFx) kept(canary string) {
	f.t.Helper()
	if !f.stateHolds(canary) || !f.snapshotHolds(canary) {
		f.t.Errorf("%s was erased but is not covered", canary)
	}
}

// rangeSeed: issue A wholly inside [50,300), B partially, C outside.
type rangeSeed struct {
	aIn1, aIn2          marker
	bIn, bOut, bLateIn  marker
	bLateOut            marker
	cOut                marker
	effA, effBIn, effBO model.ID
}

func (f *issEraseFx) seedRange() rangeSeed {
	f.t.Helper()
	s := rangeSeed{aIn1: newMarker(1, 1), aIn2: newMarker(1, 2), bIn: newMarker(2, 1), bOut: newMarker(2, 2), bLateIn: newMarker(2, 3), bLateOut: newMarker(2, 4), cOut: newMarker(3, 1),
		effA: model.ID{0xEE, 1}, effBIn: model.ID{0xEE, 2}, effBO: model.ID{0xEE, 3}}
	a := f.issue(1, 1, f.ev(1, s.aIn1, 100, 1), f.ev(1, s.aIn2, 200, 2))
	b := f.issue(2, 1, f.ev(2, s.bIn, 120, 3), f.ev(2, s.bOut, 1000, 4))
	b.LateHistory = []model.GroupingEvidence{f.ev(2, s.bLateIn, 150, 5), f.ev(2, s.bLateOut, 2000, 6)}
	b.ObservedReleases = []model.ID{s.bIn.release, s.bOut.release}
	c := f.issue(3, 1, f.ev(3, s.cOut, 1500, 7))
	expl := func(parts ...string) json.RawMessage { return json.RawMessage("[" + strings.Join(parts, ",") + "]") }
	f.must(control.IssueCommand{
		Records: []control.IssueRecordChange{
			{Issue: a, Explanations: expl(explanation(s.aIn1.occurrence, 100))},
			{Issue: b, Explanations: expl(explanation(s.bIn.occurrence, 120), explanation(s.bOut.occurrence, 1000))},
			{Issue: c, Explanations: expl(explanation(s.cOut.occurrence, 1500))},
		},
		Effects: []control.IssueEffect{
			{ID: s.effA, Kind: "regression", Issue: a.ID, Occurrence: s.aIn1.occurrence},
			{ID: s.effBIn, Kind: "regression", Issue: b.ID, Occurrence: s.bIn.occurrence},
			{ID: s.effBO, Kind: "regression", Issue: b.ID, Occurrence: s.bOut.occurrence},
		},
		Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: 9},
	})
	return s
}

func errorRange() control.DeleteScope {
	return control.DeleteScope{Mode: model.DeleteHistoricalRange, Signals: []model.Kind{model.ErrorKind}, Start: 50, End: 300}
}

func TestHistoricalRangeErasesIssueEvidenceInRange(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedRange()
	before := f.snap()
	for _, m := range []marker{s.aIn1, s.aIn2, s.bIn, s.bLateIn, s.bOut, s.bLateOut, s.cOut} {
		for _, c := range m.all() {
			if !f.stateHolds(c) {
				t.Fatalf("fixture: %s not in state", c)
			}
		}
	}
	if hits := eraseFileHits(t, f.dir, s.aIn1.record.String()); !contains(hits, "control.db") {
		t.Fatalf("fixture: control.db lacks the marker: %v", hits)
	}

	req := errorRange()
	req.Projects = []model.ID{f.project}
	f.saga(req)

	for _, m := range []marker{s.aIn1, s.aIn2, s.bIn, s.bLateIn} {
		for _, c := range m.all() {
			f.gone(c)
		}
	}
	// What is outside the range stays, including its cursors and releases.
	for _, m := range []marker{s.bOut, s.bLateOut, s.cOut} {
		for _, c := range m.all() {
			f.kept(c)
		}
	}
	after := f.snap()
	if len(after.Issues) != 2 {
		t.Fatalf("issues after: %d, want B and C", len(after.Issues))
	}
	byID := map[model.ID]model.GroupingIssue{}
	for _, gi := range after.Issues {
		byID[gi.ID] = gi
	}
	if _, found := byID[f.issueID(1)]; found {
		t.Fatal("an issue whose evidence is wholly inside the range survived")
	}
	b := byID[f.issueID(2)]
	if len(b.Occurrences) != 1 || b.Occurrences[0].OccurrenceID != s.bOut.occurrence || len(b.LateHistory) != 1 || b.LateHistory[0].OccurrenceID != s.bLateOut.occurrence {
		t.Fatalf("partially covered issue kept the wrong evidence: %+v", b)
	}
	if !reflect.DeepEqual(b.ObservedReleases, []model.ID{s.bOut.release}) {
		t.Errorf("observed releases not re-derived from the survivors: %v", b.ObservedReleases)
	}
	if b.Revision != 2 || byID[f.issueID(3)].Revision != 1 {
		t.Errorf("revisions: B=%d C=%d, want 2 and 1", b.Revision, byID[f.issueID(3)].Revision)
	}
	if after.Revision <= before.Revision {
		t.Errorf("book revision did not advance: %d -> %d", before.Revision, after.Revision)
	}
	if _, found := after.Explanations[f.issueID(1)]; found {
		t.Error("the erased issue kept its explanations")
	}
	if got := string(after.Explanations[f.issueID(2)]); strings.Contains(got, s.bIn.occurrence.String()) || !strings.Contains(got, s.bOut.occurrence.String()) {
		t.Errorf("explanations of B: %s", got)
	}
	if got := string(after.Explanations[f.issueID(3)]); !strings.Contains(got, s.cOut.occurrence.String()) {
		t.Errorf("explanations of the uncovered issue were touched: %s", got)
	}
	if len(after.Effects) != 1 || after.Effects[0].ID != s.effBO {
		t.Errorf("effects: %+v", after.Effects)
	}
	if after.Checkpoints[f.group] != 9 {
		t.Errorf("checkpoint lost: %v", after.Checkpoints)
	}
	// A stale committer (it read the book before the deletion) conflicts.
	stale := f.issue(3, 2, f.ev(3, s.cOut, 1500, 7), f.ev(3, newMarker(3, 9), 1600, 8))
	_, err := f.commit(control.IssueCommand{ExpectedRevision: before.Revision, Records: []control.IssueRecordChange{f.record(stale)}})
	if rev, ok := control.IssueConflictRevision(err); !ok || rev != after.Revision {
		t.Fatalf("a stale committer must conflict with the new revision: %v", err)
	}
	// A current committer extends the surviving issue.
	if _, err = f.commit(control.IssueCommand{ExpectedRevision: after.Revision, Records: []control.IssueRecordChange{f.record(stale)}}); err != nil {
		t.Fatalf("committing on the post-erasure revision: %v", err)
	}
}

func TestHistoricalRangeOfAnotherSignalKeepsIssueEvidence(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedRange()
	req := errorRange()
	req.Signals = []model.Kind{model.Metric}
	req.Projects = []model.ID{f.project}
	f.saga(req)
	for _, c := range s.aIn1.all() {
		f.kept(c)
	}
	if got := len(f.snap().Issues); got != 3 {
		t.Fatalf("a range of another signal erased issues: %d left", got)
	}
}

func TestHistoricalRangeDropsOverlappingDenominatorsOfSurvivors(t *testing.T) {
	f := newIssEraseFx(t)
	m1, m2 := newMarker(7, 1), newMarker(7, 2)
	// m2 is outside the range but its window straddles the range end.
	e2 := f.ev(4, m2, 1000, 2)
	e2.Denominator.Start, e2.Denominator.End = 250, 2000
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(4, 1, f.ev(4, m1, 100, 1), e2))}})
	req := errorRange()
	req.Projects = []model.ID{f.project}
	f.saga(req)
	f.gone(m1.denomGroup.String())
	f.gone(m2.denomGroup.String()) // measured partly over deleted telemetry
	f.kept(m2.record.String())
	if gi := f.snap().Issues[0]; gi.Occurrences[0].Denominator != nil || gi.Revision != 2 {
		t.Fatalf("survivor: %+v", gi)
	}
}

func TestRetireErasesIssueBooksOfCoveredProjectsOnly(t *testing.T) {
	for _, mode := range []string{model.DeleteRetireProject, model.DeleteRetireOrg} {
		t.Run(mode, func(t *testing.T) {
			f := newIssEraseFx(t)
			s := f.seedRange()
			f.admin("grant", f.org, auth.AdminPayload{UserID: f.user, ProjectID: f.otherProject, Enabled: true, Permissions: []string{string(auth.Read), string(issuesWrite)}, Reason: "fixture"})
			other, err := f.svc.Authorize(f.ctx, f.cred, f.org, []model.ID{f.otherProject}, issuesWrite)
			if err != nil {
				t.Fatal(err)
			}
			om := newMarker(9, 1)
			oi := f.issue(5, 1, f.ev(5, om, 100, 1))
			oi.Project = f.otherProject
			c := control.IssueCommand{Operation: "commit", Project: f.otherProject, Records: []control.IssueRecordChange{f.record(oi)}}
			raw, _ := json.Marshal(c)
			if _, err = f.store.TransactIssues(f.ctx, other, control.Command{CommandID: control.IssueCommandID(raw), Kind: string(control.KindApplyIssueEvidence), Payload: raw}); err != nil {
				t.Fatal(err)
			}
			req := control.DeleteScope{Mode: mode}
			if mode == model.DeleteRetireProject {
				req.Projects = []model.ID{f.project}
			}
			f.saga(req)
			for _, m := range []marker{s.aIn1, s.bIn, s.bOut, s.bLateOut, s.cOut} {
				for _, cn := range m.all() {
					f.gone(cn)
				}
			}
			for _, cn := range om.all() {
				if mode == model.DeleteRetireOrg {
					f.gone(cn)
				} else {
					f.kept(cn)
				}
			}
			if err = f.store.View(f.ctx, func(st control.State) error {
				for key, gi := range st.GroupingIssues {
					if gi.Project == f.project || mode == model.DeleteRetireOrg {
						t.Errorf("issue %s of a retired project is left", key)
					}
				}
				if _, ok := st.IssueBooks[f.org.String()+":"+f.project.String()]; ok {
					t.Error("book of the retired project is left")
				}
				if _, ok := st.RetiredProjects[f.org.String()+":"+f.project.String()]; !ok {
					t.Error("the retirement marker must stay")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(f.audits("delete.control_erased")) != 1 {
				t.Errorf("erasing audits: %d", len(f.audits("delete.control_erased")))
			}
		})
	}
}

func TestEntityDeletionErasesOnlyIssueEvidenceLinkingTheEntity(t *testing.T) {
	f := newIssEraseFx(t)
	linked, cursorOnly := newMarker(6, 1), newMarker(6, 2)
	entity := model.ID{0xE7, 7}
	le := f.ev(6, linked, 100, 1)
	le.BuildID = &entity // the only ID link evidence can hold to a root
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{
		{Issue: f.issue(6, 1, le), Explanations: json.RawMessage("[" + explanation(linked.occurrence, 100) + "]")},
		f.record(f.issue(7, 1, f.ev(7, cursorOnly, 100, 2))),
	}})
	f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{entity}, Signals: []model.Kind{model.Replay}})
	for _, c := range linked.all() {
		f.gone(c)
	}
	for _, c := range cursorOnly.all() {
		f.kept(c) // names a data-group position, never an entity: unattributable, kept like incidents
	}
	if got := f.snap(); len(got.Issues) != 1 || got.Issues[0].ID != f.issueID(7) || len(got.Explanations) != 0 {
		t.Fatalf("after: %+v", got)
	}
}

func TestIssueErasureIsDeterministicIdempotentAndSurvivesRestart(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedRange()
	req := errorRange()
	req.Projects = []model.ID{f.project}
	f.saga(req)
	var want string
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, e := model.CanonicalJSON(st)
		want = string(raw)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if n := len(f.audits("delete.control_erased")); n != 1 {
		t.Fatalf("erasing audits: %d, want 1 (completion must be a no-op)", n)
	}
	// A second deletion that covers nothing new erases nothing and changes no revision.
	rev := f.snap().Revision
	f.saga(req)
	if got := f.snap().Revision; got != rev {
		t.Errorf("an idempotent pass advanced the book revision: %d -> %d", rev, got)
	}
	if n := len(f.audits("delete.control_erased")); n != 1 {
		t.Errorf("a pass that erased nothing wrote an audit: %d", n)
	}
	if err := f.store.View(f.ctx, func(st control.State) error {
		raw, e := model.CanonicalJSON(st)
		want = string(raw)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	seed, _, err := f.store.ReplicationSeed()
	if err != nil {
		t.Fatal(err)
	}
	seeded, err := control.OpenSeed(t.TempDir(), seed)
	if err != nil {
		t.Fatal(err)
	}
	defer seeded.Close()
	var got string
	if err = seeded.View(f.ctx, func(st control.State) error {
		raw, e := model.CanonicalJSON(st)
		got = string(raw)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range s.aIn1.all() {
		if strings.Contains(got, c) {
			t.Fatalf("a snapshot-seeded replica holds %s", c)
		}
	}
	if !strings.Contains(got, s.cOut.record.String()) {
		t.Fatal("a snapshot-seeded replica lost uncovered evidence")
	}
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := control.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = auth.NewService(auth.AuthDependencies{Control: reopened}); err != nil {
		t.Fatal(err)
	}
	if err = reopened.EnableSingle(f.ctx, filepath.Join(f.dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	if err = reopened.View(f.ctx, func(st control.State) error {
		raw, _ := model.CanonicalJSON(st)
		if string(raw) != want {
			t.Error("a restart changed the erased state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRedactControlCommandErasesIssueEvidence(t *testing.T) {
	f := newIssEraseFx(t)
	s := f.seedRange()
	var original []byte
	if err := f.store.View(f.ctx, func(st control.State) error {
		var err error
		original, err = json.Marshal(struct {
			Expected model.Revision     `json:"expected"`
			State    model.ControlState `json:"state"`
			Keys     map[string][]byte  `json:"keys"`
		}{st.Revision, st, map[string][]byte{}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	req := errorRange()
	req.Projects = []model.ID{f.project}
	f.saga(req)
	replacement, changed, err := f.store.RedactControlCommand(original)
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	for _, c := range append(s.aIn1.all(), s.bIn.all()...) {
		if eraseDeep(replacement, []byte(c), 3) {
			t.Fatalf("the replacement still carries %s", c)
		}
	}
	if !eraseDeep(replacement, []byte(s.cOut.record.String()), 3) {
		t.Fatal("the replacement lost uncovered evidence")
	}
	again, changed, err := f.store.RedactControlCommand(replacement)
	if err != nil || changed || string(again) != string(replacement) {
		t.Fatalf("not idempotent: changed=%v err=%v", changed, err)
	}
}

// Every ID link evidence can hold to a replay/profile root attributes it.
func TestEntityDeletionAttributesEveryIDLink(t *testing.T) {
	links := map[string]func(e *model.GroupingEvidence, id model.ID){
		"record":     func(e *model.GroupingEvidence, id model.ID) { e.RecordID = id },
		"occurrence": func(e *model.GroupingEvidence, id model.ID) { e.OccurrenceID = id },
		"build":      func(e *model.GroupingEvidence, id model.ID) { e.BuildID = &id },
		"release":    func(e *model.GroupingEvidence, id model.ID) { e.ReleaseID = &id },
		"epoch":      func(e *model.GroupingEvidence, id model.ID) { e.ProducerEpoch = &id },
	}
	for name, link := range links {
		t.Run(name, func(t *testing.T) {
			f := newIssEraseFx(t)
			m := newMarker(8, 1)
			entity := model.ID{0xE8, 1}
			e := f.ev(8, m, 100, 1)
			link(&e, entity)
			f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(8, 1, e))}})
			f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{entity}})
			if got := f.snap(); len(got.Issues) != 0 {
				t.Fatalf("evidence linking %s survived: %+v", name, got.Issues)
			}
		})
	}
}

// An explanation that cannot be read (no occurrence to attribute it by) is
// dropped whole, never kept, when its issue loses evidence.
func TestUnattributableExplanationsAreDropped(t *testing.T) {
	f := newIssEraseFx(t)
	in, out := newMarker(5, 1), newMarker(5, 2)
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{
		{Issue: f.issue(5, 1, f.ev(5, in, 100, 1), f.ev(5, out, 1000, 2)), Explanations: json.RawMessage(`[{"reason":"no occurrence"},` + explanation(out.occurrence, 1000) + `]`)},
	}})
	req := errorRange()
	req.Projects = []model.ID{f.project}
	f.saga(req)
	got := string(f.snap().Explanations[f.issueID(5)])
	if strings.Contains(got, "no occurrence") || !strings.Contains(got, out.occurrence.String()) {
		t.Fatalf("explanations after: %s", got)
	}

	g := newIssEraseFx(t)
	g.must(control.IssueCommand{Records: []control.IssueRecordChange{
		{Issue: g.issue(5, 1, g.ev(5, in, 100, 1), g.ev(5, out, 1000, 2)), Explanations: json.RawMessage(`[5]`)},
	}})
	g.saga(req2(g))
	if _, found := g.snap().Explanations[g.issueID(5)]; found {
		t.Fatal("an unreadable explanation list was kept")
	}
}

func req2(f *issEraseFx) control.DeleteScope {
	r := errorRange()
	r.Projects = []model.ID{f.project}
	return r
}

// A surviving denominator whose window straddles the range start is dropped too.
func TestRangeDropsDenominatorStraddlingTheStart(t *testing.T) {
	f := newIssEraseFx(t)
	m := newMarker(4, 1)
	e := f.ev(4, m, 10, 1)
	e.Denominator.Start, e.Denominator.End = 10, 60
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(4, 1, e))}})
	f.saga(req2(f))
	if gi := f.snap().Issues[0]; gi.Occurrences[0].Denominator != nil {
		t.Fatalf("denominator measured partly over deleted telemetry survived: %+v", gi.Occurrences[0].Denominator)
	}
	f.gone(m.denomGroup.String())
}

// The range is half-open: evidence at Start is erased, evidence at End is kept.
func TestRangeBoundariesAreHalfOpen(t *testing.T) {
	f := newIssEraseFx(t)
	atStart, atEnd := newMarker(3, 1), newMarker(3, 2)
	f.must(control.IssueCommand{Records: []control.IssueRecordChange{f.record(f.issue(3, 1, f.ev(3, atStart, 50, 1), f.ev(3, atEnd, 300, 2)))}})
	f.saga(req2(f))
	for _, c := range atStart.all() {
		f.gone(c)
	}
	for _, c := range atEnd.all() {
		f.kept(c)
	}
}
