// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The bounded-state rules (bounded_rules.go) wait for the whole replica group: until the gate says
// every member declared the protocol, the previous rule applies, byte for byte what a release
// without the rules writes; then the rules engage. A Store without a gate applies them (every test
// of the rules themselves).

func TestAStoreWithoutAGateAppliesTheBoundedRules(t *testing.T) {
	f := newIssFx(t)
	if !f.store.BoundedRules() {
		t.Fatal("no gate: the bounded rules must apply")
	}
	f.store.SetBoundedRulesGate(func() bool { return false })
	if f.store.BoundedRules() {
		t.Fatal("a closed gate must keep the previous rules")
	}
	f.store.SetBoundedRulesGate(nil)
	if !f.store.BoundedRules() {
		t.Fatal("removing the gate must restore the default")
	}
}

// issueGap is the i-th gap of one data group, declared at the checkpoint the (i-1)-th advanced to.
func (f *issFx) issueGap(i int) control.IssueCommand {
	after := uint64(1 + i)
	id := model.ID{0xa7, 2, byte(i >> 8), byte(i)}
	g := model.EvidenceGap{ID: id, Org: f.org, Project: f.project, Group: f.group, After: model.Uint64(after), Through: model.Uint64(after + 1), Count: 1,
		Start: model.UnixNano(100 + i), End: model.UnixNano(100 + i), Signals: []model.Kind{model.Log}, Reason: "expired before processing", RecordedAt: model.UnixNano(1000 + i)}
	return control.IssueCommand{Command: &id, ExpectedRevision: model.Revision(1 + i), Checkpoint: &control.IssueCheckpoint{Group: f.group, Index: model.Uint64(after + 1)}, Gap: &g}
}

// R01-2 across an upgrade: with the gate closed the 129th gap of a group is the Quota the release
// before refused it with and nothing was written; once the gate opens it coalesces.
func TestIssueGapListRefusesAtItsBoundUntilTheBoundedRulesApply(t *testing.T) {
	f := newIssFx(t)
	var engaged atomic.Bool
	f.store.SetBoundedRulesGate(engaged.Load)
	f.must(f.first())
	for i := range 128 {
		f.must(f.issueGap(i))
	}
	before := f.semantic()
	if _, err := f.commit(f.issueGap(128)); code(err) != model.Quota {
		t.Fatalf("gap 129 with the gate closed: %v, want the previous rule's quota", err)
	}
	if f.semantic() != before {
		t.Fatal("a refused gap changed the book")
	}
	for _, g := range f.snap().Gaps {
		if g.Merged != 0 {
			t.Fatalf("a gap carries merged=%d before the rules engaged", g.Merged)
		}
	}
	engaged.Store(true)
	f.must(f.issueGap(128))
	s := f.snap()
	var lost, merged model.Uint64
	for _, g := range s.Gaps {
		lost += g.Count
		merged += model.Uint64(g.Merged)
	}
	if len(s.Gaps) != 128 || lost != 129 || merged != 1 {
		t.Fatalf("after the gate opened: %d gaps, %d lost (want 129), %d merged (want 1)", len(s.Gaps), lost, merged)
	}
}

// R01-2 across an upgrade, commands: the 1025th record is a Quota with the gate closed, no record
// carries a book revision (the release before did not write one), and the oldest is evicted once the
// gate opens.
func TestIssueCommandRecordsRefuseAtTheirBoundUntilTheBoundedRulesApply(t *testing.T) {
	f := newIssFx(t)
	var engaged atomic.Bool
	f.store.SetBoundedRulesGate(engaged.Load)
	f.must(f.first())
	idOf := func(i int) model.ID { return model.ID{0xc8, byte(i >> 8), byte(i)} }
	cmd := func(i int) control.IssueCommand {
		id := idOf(i)
		return control.IssueCommand{Command: &id, ExpectedRevision: model.Revision(1 + i), Records: []control.IssueRecordChange{f.record(f.issue(1, uint64(2+i), f.evidence(1, 1)))},
			Action: &control.IssueActionRecord{Fingerprint: model.Hash{byte(i)}, Issue: f.issueID(1)}}
	}
	const bound = 1024
	for i := range bound {
		f.must(cmd(i))
	}
	s := f.snap()
	if len(s.Commands) != bound {
		t.Fatalf("%d command records, want %d", len(s.Commands), bound)
	}
	for id, entry := range s.Commands {
		if entry.Rev != 0 {
			t.Fatalf("command %s carries rev=%d before the rules engaged", id, entry.Rev)
		}
	}
	if _, err := f.commit(cmd(bound)); code(err) != model.Quota {
		t.Fatalf("command 1025 with the gate closed: %v, want the previous rule's quota", err)
	}
	engaged.Store(true)
	f.must(cmd(bound))
	s = f.snap()
	if _, ok := s.Commands[idOf(bound)]; !ok || len(s.Commands) != bound {
		t.Fatalf("after the gate opened: %d records, the newest present=%v", len(s.Commands), ok)
	}
}

// seedIncidents stores n resolved incidents (resolved long ago) of the fixture's project.
func (f *incFx) seedIncidents(n int, resolvedAt model.UnixNano) {
	f.t.Helper()
	if err := f.store.Update(f.ctx, func(st *control.State) error {
		st.IncidentBooks = map[string]json.RawMessage{}
		for i := range n {
			id := model.ID{0xb1, byte(i >> 8), byte(i)}
			resolved, _ := json.Marshal(resolvedAt) // a UnixNano is a quoted decimal on the wire
			state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","status":"resolved","resolved_at":%s}`, id.String(), f.org.String(), f.project.String(), resolved))
			raw, err := json.Marshal(control.IncidentRecord{Org: f.org, Project: f.project, ID: id, Version: 1, Digest: digest(state), State: state})
			if err != nil {
				return err
			}
			st.IncidentBooks[f.org.String()+":"+f.project.String()+":"+id.String()] = raw
		}
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
}

// R01-4 across an upgrade: with the gate closed a pruned incident is removed (the previous rule: the
// producer's key goes with it), once it opens the next one leaves a stub.
func TestIncidentPruningRemovesTheRecordUntilTheBoundedRulesApply(t *testing.T) {
	f := newIncFx(t)
	var engaged atomic.Bool
	f.store.SetBoundedRulesGate(engaged.Load)
	const day = model.UnixNano(24 * time.Hour)
	now := model.UnixNano(1_700_000_000_000_000_000)
	id := func(n int) model.ID { return model.ID{0xb1, byte(n >> 8), byte(n)} }
	f.seedIncidents(1024, now-120*day)
	open := func(n int) error {
		st := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","status":"open"}`, id(n).String(), f.org.String(), f.project.String()))
		_, err := f.send(model.NewID(), control.IncidentCommand{Project: f.project, Incident: id(n), Action: "open", Origin: "human", Actor: f.user, At: now, ExpectedVersion: 0, NewVersion: 1, State: st, Digest: digest(st)})
		return err
	}
	if err := open(1024); err != nil {
		t.Fatalf("a new incident at the cap must prune an expired one: %v", err)
	}
	if _, found, err := f.store.Incident(f.ctx, f.adminScope(), f.project, id(0)); err != nil || found {
		t.Fatalf("with the gate closed the pruned incident must be removed (the previous rule): found=%v err=%v", found, err)
	}
	// The flaw of the previous rule, which the stub exists to remove: the key is free again.
	if err := open(0); err != nil {
		t.Fatalf("with the gate closed the producer's key is free again: %v", err)
	}
	engaged.Store(true)
	if err := open(1025); err != nil {
		t.Fatalf("a new incident at the cap must prune an expired one: %v", err)
	}
	rec, found, err := f.store.Incident(f.ctx, f.adminScope(), f.project, id(2))
	if err != nil || !found || !rec.Erased() || rec.Version != 1 {
		t.Fatalf("once the gate opened a pruned incident must stay as a stub: found=%v erased=%v err=%v", found, rec.Erased(), err)
	}
}

// R01-5 across an upgrade: with the gate closed a creation past the byte budget collects nothing (the
// previous rule had no byte budget); once it opens the budget is enforced by collection.
func TestConditionByteBudgetWaitsForTheBoundedRules(t *testing.T) {
	f := newCondFx(t)
	var engaged atomic.Bool
	f.store.SetBoundedRulesGate(engaged.Load)
	const day = model.UnixNano(24 * time.Hour)
	now := model.UnixNano(1_700_000_000_000_000_000)
	pad := strings.Repeat("x", 30<<10)
	idOf := func(i int) model.ID { return model.ID{0xd0, byte(i >> 8), byte(i)} }
	const seeded = 320 // about 9.6 MB, past the 8 MiB budget and inside one control entry
	seed := func() {
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			st.ConditionBooks = map[string]json.RawMessage{}
			for i := range seeded {
				id := idOf(i)
				at := int64(now-200*day) + int64(i)
				state := json.RawMessage(fmt.Sprintf(`{"condition_id":%q,"org_id":%q,"project_id":%q,"version":"1","phase":"recovered","event_ns":"%d","arrived_ns":"%d","fresh_ns":"%d","pad":%q}`,
					id.String(), f.org.String(), f.project.String(), at, at, at, pad))
				raw, err := json.Marshal(control.ConditionRecord{Org: f.org, Project: f.project, ID: id, Version: 1, State: state})
				if err != nil {
					return err
				}
				st.ConditionBooks[f.org.String()+":"+f.project.String()+":"+id.String()] = raw
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	erased := func() int {
		recs, err := f.store.Conditions(f.ctx, f.adminScope(), f.project)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range recs {
			if r.Erased() {
				n++
			}
		}
		return n
	}
	lease := f.lease()
	create := func(id model.ID) error {
		state := condState(f.org, f.project, id, 1, "new")
		_, err := f.send(model.NewID(), control.ConditionCommand{Project: f.project, Condition: id, Lease: &lease, ExpectedVersion: 0, NewVersion: 1, At: now, State: state, Digest: digest(state)})
		return err
	}
	seed()
	if err := create(model.ID{0xe1}); err != nil {
		t.Fatalf("with the gate closed the previous rule has no byte budget: %v", err)
	}
	if n := erased(); n != 0 {
		t.Fatalf("with the gate closed %d conditions were collected", n)
	}
	engaged.Store(true)
	seed()
	if err := create(model.ID{0xe2}); err != nil {
		t.Fatalf("once the gate opened a creation over the budget must collect: %v", err)
	}
	if n := erased(); n == 0 {
		t.Fatal("once the gate opened nothing was collected")
	}
}

// groupGate is the gate of a three-member group as the application builds it: every member declared
// the protocol. A member of the release before the rules (old) has no gate at all and applies the
// previous rules whatever the others declared; modelling it by a gate that is always closed is the
// same behaviour, since that is the code path it runs.
type groupGate struct{ declared [4]atomic.Bool }

func (g *groupGate) all() bool {
	return g.declared[1].Load() && g.declared[2].Load() && g.declared[3].Load()
}

// A group that mixes a member of the release before the rules with members that have them never
// applies the new rule on any member, whichever member proposes, and every member holds the same
// state; the rules engage on every member together once the last one declared.
func TestAMixedVersionGroupAppliesOneRuleAndConvergesOnOneState(t *testing.T) {
	v := newControlVoters(t)
	gate := &groupGate{}
	gate.declared[1].Store(true)
	gate.declared[2].Store(true) // voters 1 and 2 run the new binary and declared; voter 3 is the old one
	var upgraded atomic.Bool
	for id := uint64(1); id <= 3; id++ {
		if err := v.stores[id].BindReleases(); err != nil {
			t.Fatal(err)
		}
		switch id {
		case 3:
			v.stores[id].SetBoundedRulesGate(func() bool { return upgraded.Load() && gate.all() })
		default:
			v.stores[id].SetBoundedRulesGate(gate.all)
		}
	}
	fx := map[uint64]*issFx{}
	for id := uint64(1); id <= 3; id++ {
		fx[id] = &issFx{fenceFx: v.fx[id].fenceFx, group: model.ID{0xe1}, rel: model.ID{0xc0, 1}}
	}
	v.leaderIs(1)
	fx[1].admin("grant", fx[1].org, auth.AdminPayload{UserID: fx[1].user, ProjectID: fx[1].project, Enabled: true, Permissions: []string{string(auth.Read), string(issuesWrite)}, Reason: "fixture"})
	for id := uint64(1); id <= 3; id++ {
		session, err := v.fx[id].svc.Login(v.fx[id].ctx, "owner@example.test", "a long test password 2026", "")
		if err != nil {
			t.Fatal(err)
		}
		if fx[id].cred, err = v.fx[id].svc.Authenticate(v.fx[id].ctx, session.Token); err != nil {
			t.Fatal(err)
		}
		if fx[id].writer, err = v.fx[id].svc.Authorize(v.fx[id].ctx, fx[id].cred, fx[id].org, []model.ID{fx[id].project}, issuesWrite); err != nil {
			t.Fatal(err)
		}
	}
	v.leaderIs(1)
	books := func() [4][]byte {
		var out [4][]byte
		rev := v.mustRevision(1)
		for id := uint64(1); id <= 3; id++ {
			v.await(id, rev)
			if err := v.stores[id].View(fx[id].ctx, func(st control.State) error {
				out[id] = bytes.Clone(st.IssueBooks[fx[id].org.String()+":"+fx[id].project.String()])
				return nil
			}); err != nil {
				t.Fatalf("voter %d: %v", id, err)
			}
		}
		return out
	}
	converged := func(when string) []byte {
		t.Helper()
		b := books()
		if !bytes.Equal(b[1], b[2]) || !bytes.Equal(b[2], b[3]) {
			t.Fatalf("%s: the members hold different issue books", when)
		}
		return b[1]
	}
	// The new binary proposes the first gaps; the old one proposes the next ones. The book fills to its
	// bound whichever member proposed.
	if _, err := fx[1].commit(fx[1].first()); err != nil {
		t.Fatal(err)
	}
	for i := range 128 {
		if _, err := fx[1+uint64(i%3)].commit(fx[1].issueGap(i)); err != nil {
			t.Fatalf("gap %d: %v", i, err)
		}
	}
	converged("128 gaps")
	// Mixed: the 129th gap is refused by the new members exactly as by the old one.
	for _, proposer := range []uint64{1, 2, 3} {
		if _, err := fx[proposer].commit(fx[1].issueGap(128)); code(err) != model.Quota {
			t.Fatalf("voter %d proposed gap 129 in a mixed group: %v, want the previous rule's quota", proposer, err)
		}
	}
	mixed := converged("after the refused gaps")
	if bytes.Contains(mixed, []byte(`"merged"`)) {
		t.Fatal("a member wrote the new rule's merged mark into a mixed group")
	}
	// The old member is upgraded and declares: every member now applies the rule.
	upgraded.Store(true)
	gate.declared[3].Store(true)
	if _, err := fx[3].commit(fx[1].issueGap(128)); err != nil {
		t.Fatalf("gap 129 once every member declared: %v", err)
	}
	if _, err := fx[1].commit(fx[1].issueGap(129)); err != nil {
		t.Fatalf("gap 130 once every member declared: %v", err)
	}
	after := converged("after the rules engaged")
	if !bytes.Contains(after, []byte(`"merged"`)) || bytes.Equal(after, mixed) {
		t.Fatal("the rules did not engage on every member after the last declaration")
	}
}
