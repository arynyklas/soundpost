// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// D49: the audit delta command (audit_delta.go). These tests drive the machine directly
// (replicatedControl.Apply) the way mutant_rejected_internal_test.go does, and the store's
// AppendAudit through its real group.

func (f *installFx) deltaPayload(expected model.Revision, at int64, rows ...model.ControlAudit) []byte {
	f.t.Helper()
	raw, err := json.Marshal(auditDeltaCommand{AuditDelta: auditDelta{Installation: f.state().Installation, Expected: expected, At: at, Audits: rows}})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

// deltaEntry is a committed audit delta for the machine of f at the next replica index, expecting
// revision expected, with the application slot cursor.
func (f *installFx) deltaEntry(expected, cursor model.Revision, at int64, rows ...model.ControlAudit) replica.CommittedEntry {
	f.t.Helper()
	physical, err := f.s.appliedIndex()
	if err != nil {
		f.t.Fatal(err)
	}
	g := f.s.ReplicaGroup().Status()
	return replica.CommittedEntry{
		Group: g.Group, Term: g.Term, Index: physical + 1,
		ApplicationCursor: model.Cursor{Group: g.Group, Index: model.Uint64(cursor)},
		Entry:             replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: f.deltaPayload(expected, at, rows...)},
	}
}

func randomAudit(r *rand.Rand, f *installFx) model.ControlAudit {
	a := model.ControlAudit{ID: model.NewID(), Principal: model.ID{byte(r.IntN(250) + 1)}, Action: fmt.Sprintf("export.chunk.%d", r.IntN(5)), Reason: "elevated response released", Time: r.Int64N(1 << 50), Outcome: model.AuditAllowed}
	if r.IntN(2) == 0 {
		a.Org = f.org.String()
		a.PolicyEpoch = uint64(r.IntN(9))
	}
	for range r.IntN(4) {
		a.Targets = append(a.Targets, model.NewID())
	}
	if r.IntN(3) == 0 {
		a.RequestID = model.NewID()
	}
	return a
}

// A commit through the delta command leaves exactly the state the whole-state commit of the same
// rows leaves (the fallback AppendAudit takes while the gate is closed): same revisions, same
// AuthorityRevision, same revision clock, same audit log, over random rows and a clock that moves
// by random steps (so the revision clock stamps and prunes). Two stores run the same sequence, one
// per path; only the installation id differs.
func TestAuditDeltaApplyEqualsReplacementApply(t *testing.T) {
	whole, delta := newInstallFx(t), newInstallFx(t)
	whole.s.SetAuditDeltaGate(func() bool { return false })
	delta.s.SetAuditDeltaGate(func() bool { return true })
	r := rand.New(rand.NewPCG(49, 49))
	now := int64(2_000)
	clock := func() time.Time { return time.Unix(0, now) }
	whole.s.SetClock(clock)
	delta.s.SetClock(clock)
	// Both stores start from the same state: same stamps (the fixtures were built by the same steps).
	for _, f := range []*installFx{whole, delta} {
		if err := f.s.Update(f.ctx, func(st *State) error {
			st.RevisionClock = []model.RevisionStamp{{Revision: 1, At: 1_000}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	if a, b := whole.state().Revision, delta.state().Revision; a != b {
		t.Fatalf("fixtures disagree on the revision: %d vs %d", a, b)
	}
	check := func(model.ReadOnlyControl) error { return nil }
	for i := range 60 {
		now += int64(r.IntN(3)) * int64(time.Minute) * int64(r.IntN(40)+1)
		row := randomAudit(r, whole)
		if err := whole.s.AppendAudit(whole.ctx, check, row); err != nil {
			t.Fatalf("whole-state commit %d: %v", i, err)
		}
		if err := delta.s.AppendAudit(delta.ctx, check, row); err != nil {
			t.Fatalf("delta commit %d: %v", i, err)
		}
		a, b := whole.state(), delta.state()
		a.Installation, b.Installation = model.ID{0x49}, model.ID{0x49} // what differs between the two fixtures:
		b.BootstrapHash = a.BootstrapHash                               // random per store
		if whole.canonical(a) != delta.canonical(b) {
			var ma, mb map[string]json.RawMessage
			_ = json.Unmarshal([]byte(whole.canonical(a)), &ma)
			_ = json.Unmarshal([]byte(delta.canonical(b)), &mb)
			var differing []string
			for k := range ma {
				if string(ma[k]) != string(mb[k]) {
					differing = append(differing, k+": "+string(ma[k])[:min(len(ma[k]), 120)]+" | "+string(mb[k])[:min(len(mb[k]), 120)])
				}
			}
			t.Fatalf("commit %d: the delta left a state that differs from the whole-state commit in %v", i, differing)
		}
		if a.AuthorityRevision != b.AuthorityRevision {
			t.Fatalf("commit %d: authority %d vs %d", i, a.AuthorityRevision, b.AuthorityRevision)
		}
	}
	if n, _ := delta.s.AuditDeltaStatsForTest(); n != 60 {
		t.Fatalf("the delta store proposed %d delta commands, want 60", n)
	}
	if n, _ := whole.s.AuditDeltaStatsForTest(); n != 0 {
		t.Fatalf("the store with the gate closed proposed %d delta commands, want 0", n)
	}
	if a := delta.state(); a.AuthorityRevision == a.Revision {
		t.Fatalf("the audit deltas moved AuthorityRevision to %d", a.AuthorityRevision)
	}
}

// A delta that expects an older (or a newer) revision is rejected exactly like a stale
// replacement: nothing is replaced, the rejection is recorded and a replay answers it again.
func TestAuditDeltaWithAStaleExpectedRevisionIsRejected(t *testing.T) {
	f := newInstallFx(t)
	before := f.canonical(f.state())
	rev := f.state().Revision
	for _, expected := range []model.Revision{rev - 1, rev + 1} {
		c := f.deltaEntry(expected, rev, 5, f.audit("export.chunk", 5))
		if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("a delta expecting %d at revision %d answered %v, want replica.ErrConflict", expected, rev, err)
		}
		if got := f.canonical(f.state()); got != before {
			t.Fatalf("a rejected delta changed the state:\n got  %.300s\n want %.300s", got, before)
		}
		if got := f.mutantMeta("rejected:" + c.Entry.ID.String()); len(got) != 1 || got[0] != 1 {
			t.Fatalf("the rejection left no marker: %v", got)
		}
		if err := f.s.repl.Apply(c); !errors.Is(err, replica.ErrConflict) {
			t.Fatalf("a replay of the rejected delta answered %v, want the same conflict", err)
		}
	}
}

// The group may hand the machine an applied delta again (a restart replays what the machine had
// applied): the same command changes nothing; a different one at the same index is corrupt.
func TestAuditDeltaReplayIsVerifiedNotReapplied(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	row := f.audit("export.chunk", 7)
	c := f.deltaEntry(rev, rev+1, 7, row)
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatal(err)
	}
	after := f.state()
	if after.Revision != rev+1 || after.AuthorityRevision == after.Revision || len(after.Audits) == 0 || after.Audits[len(after.Audits)-1].ID != row.ID {
		t.Fatalf("applied delta left revision %d (was %d), authority %d, %d audit rows", after.Revision, rev, after.AuthorityRevision, len(after.Audits))
	}
	if err := f.s.repl.Apply(c); err != nil {
		t.Fatalf("a replay of the applied delta answered %v", err)
	}
	if got := f.canonical(f.state()); got != f.canonical(after) {
		t.Fatal("a replay of the applied delta changed the state")
	}
	forged := c
	forged.Entry.Payload = f.deltaPayload(rev, 7, f.audit("export.chunk", 7))
	if err := f.s.repl.Apply(forged); mutantCode(err) != model.Corrupt {
		t.Fatalf("a different delta at an applied revision answered %v, want corrupt", err)
	}
	// The same replay, with the rows right but for another installation, is corrupt too.
	foreign := c
	rawForeign, _ := json.Marshal(auditDeltaCommand{AuditDelta: auditDelta{Installation: model.ID{0x77}, Expected: rev, At: 7, Audits: []model.ControlAudit{row}}})
	foreign.Entry.Payload = rawForeign
	if err := f.s.repl.Apply(foreign); mutantCode(err) != model.Corrupt {
		t.Fatalf("a replay of a delta of another installation answered %v, want corrupt", err)
	}
	// A delta of another installation is corrupt, not a conflict.
	other := f.deltaEntry(f.state().Revision, f.state().Revision+1, 8, f.audit("export.chunk", 8))
	raw, _ := json.Marshal(auditDeltaCommand{AuditDelta: auditDelta{Installation: model.ID{0x77}, Expected: f.state().Revision, At: 8, Audits: []model.ControlAudit{f.audit("x", 1)}}})
	other.Entry.Payload = raw
	if err := f.s.repl.Apply(other); mutantCode(err) != model.Corrupt {
		t.Fatalf("a delta of another installation answered %v, want corrupt", err)
	}
}

// A delta carrying an erasing audit owes this file a scrub, like a replacement that adds one.
func TestAuditDeltaWithAnErasingRowOwesAScrub(t *testing.T) {
	f := newInstallFx(t)
	if f.owesState() {
		t.Fatal("fixture already owes a scrub")
	}
	owedBefore := f.local()
	rev := f.state().Revision
	if err := f.s.repl.Apply(f.deltaEntry(rev, rev+1, 9, f.audit(controlErasedAction, 9))); err != nil {
		t.Fatal(err)
	}
	if !f.owesState() || f.local() == owedBefore {
		t.Fatalf("an erasing audit applied through a delta owes no scrub: %+v (was %+v)", f.local(), owedBefore)
	}
	f2 := newInstallFx(t)
	owedBefore = f2.local()
	rev = f2.state().Revision
	if err := f2.s.repl.Apply(f2.deltaEntry(rev, rev+1, 9, f2.audit("export.chunk", 9))); err != nil {
		t.Fatal(err)
	}
	if f2.owesState() || f2.local() != owedBefore {
		t.Fatalf("an ordinary audit row owes a scrub: %+v (was %+v)", f2.local(), owedBefore)
	}
}

// The payload decoder tells the two shapes apart and refuses everything else.
func TestControlPayloadDecoderIsStrict(t *testing.T) {
	f := newInstallFx(t)
	st := f.state()
	row, _ := json.Marshal(f.audit("export.chunk", 1))
	good := func(rows string, extra string) string {
		return `{"audit_delta":{"installation":"` + st.Installation.String() + `","expected":"3","at":1,"audits":[` + rows + `]` + extra + `}}`
	}
	replacement, _ := json.Marshal(controlReplacement{Expected: st.Revision - 1, State: st, Keys: map[string][]byte{}})
	if c, err := decodeControlCommand(replacement); err != nil || c.replacement == nil || c.delta != nil {
		t.Fatalf("a legacy whole-state payload did not decode as a replacement: %v", err)
	}
	if c, err := decodeControlCommand([]byte(good(string(row), ""))); err != nil || c.delta == nil || c.replacement != nil || len(c.delta.Audits) != 1 {
		t.Fatalf("a delta payload did not decode as a delta: %v", err)
	}
	many := strings.TrimSuffix(strings.Repeat(string(row)+",", maxAuditDeltaRows+1), ",")
	for name, payload := range map[string]string{
		"empty":                  ``,
		"not an object":          `[]`,
		"no rows":                good("", ""),
		"too many rows":          good(many, ""),
		"unknown member":         good(string(row), `,"state":{}`),
		"unknown row member":     good(strings.TrimSuffix(string(row), "}")+`,"future_field":7}`, ""),
		"delta not first member": `{"keys":{},"audit_delta":{"installation":"` + st.Installation.String() + `","expected":"3","at":1,"audits":[` + string(row) + `]}}`,
		"unknown outer member":   `{"audit_delta":{"installation":"` + st.Installation.String() + `","expected":"3","at":1,"audits":[` + string(row) + `]},"keys":{}}`,
		"delta then replacement": `{"audit_delta":{"installation":"` + st.Installation.String() + `","expected":"3","at":1,"audits":[` + string(row) + `]},"expected":"3","state":{},"keys":{}}`,
		"replacement with delta": `{"expected":"3","state":{},"keys":{},"audit_delta":{}}`,
		"duplicate key":          `{"audit_delta":{},"audit_delta":{}}`,
		"trailing data":          good(string(row), "") + `{}`,
		"maximal expected":       strings.Replace(good(string(row), ""), `"expected":"3"`, `"expected":"18446744073709551615"`, 1),
	} {
		if c, err := decodeControlCommand([]byte(payload)); err == nil {
			t.Errorf("%s: decoded (replacement %v, delta %v), want a refusal", name, c.replacement != nil, c.delta != nil)
		}
	}
}

// A deletion's journal redaction leaves a delta as it is (it carries no book a deletion erases) and
// still redacts the whole-state commands around it.
func TestJournalRedactionLeavesAnAuditDeltaUntouched(t *testing.T) {
	f := newInstallFx(t)
	rev := f.state().Revision
	current := f.state()
	current.Deletions = f.finishedDeletion()
	payload := f.deltaPayload(rev, 3, f.audit("export.chunk", 3))
	got, changed, err := redactControlPayload(current, payload)
	if err != nil || changed || string(got) != string(payload) {
		t.Fatalf("redaction of an audit delta: changed %v, err %v", changed, err)
	}
	// The same rule still redacts a whole-state command that carries the payload.
	whole, _ := json.Marshal(controlReplacement{Expected: rev - 1, State: f.state(), Keys: map[string][]byte{}})
	if _, changed, err = redactControlPayload(current, whole); err != nil || !changed {
		t.Fatalf("redaction of a whole-state command: changed %v, err %v", changed, err)
	}
}

// The gate: closed or absent, AppendAudit commits the whole-state path (no delta proposed); open, it
// proposes the delta. The delta is a few hundred bytes whatever the state size.
func TestAppendAuditProposesTheDeltaOnlyWhenTheGateIsOpen(t *testing.T) {
	f := newInstallFx(t)
	check := func(model.ReadOnlyControl) error { return nil }
	var open bool
	f.s.SetAuditDeltaGate(func() bool { return open })
	rev := f.state().Revision
	if err := f.s.AppendAudit(f.ctx, check, f.audit("export.chunk", 1)); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.s.AuditDeltaStatsForTest(); n != 0 || f.state().Revision != rev+1 {
		t.Fatalf("gate closed: %d deltas proposed, revision %d -> %d (want 0 deltas, one revision)", n, rev, f.state().Revision)
	}
	open = true
	if err := f.s.AppendAudit(f.ctx, check, f.audit("export.chunk", 2)); err != nil {
		t.Fatal(err)
	}
	n, bytes := f.s.AuditDeltaStatsForTest()
	if n != 1 || f.state().Revision != rev+2 {
		t.Fatalf("gate open: %d deltas proposed, revision %d -> %d", n, rev, f.state().Revision)
	}
	whole, _ := json.Marshal(controlReplacement{Expected: rev, State: f.state(), Keys: map[string][]byte{}})
	if bytes > 1024 || bytes*4 > uint64(len(whole)) {
		t.Fatalf("a delta payload is %d bytes, the whole-state payload %d: not small", bytes, len(whole))
	}
	f.s.SetAuditDeltaGate(nil)
	if f.s.AuditDelta() {
		t.Fatal("a store without a gate must not propose deltas: the delta is a wire format older peers cannot decode")
	}
	before := f.state().Revision
	if err := f.s.AppendAudit(f.ctx, check, f.audit("export.chunk", 4)); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.s.AuditDeltaStatsForTest(); n != 1 || f.state().Revision != before+1 {
		t.Fatalf("a store without a gate proposed %d deltas in total (want the 1 of the open gate)", n)
	}
	// The check runs on the state the commit decides on; a refusal commits nothing on either path.
	refuse := errors.New("scope no longer valid")
	for _, gate := range []bool{false, true} {
		g := gate
		f.s.SetAuditDeltaGate(func() bool { return g })
		rev = f.state().Revision
		if err := f.s.AppendAudit(f.ctx, func(model.ReadOnlyControl) error { return refuse }, f.audit("export.chunk", 3)); !errors.Is(err, refuse) {
			t.Fatalf("gate %v: a refused check answered %v", g, err)
		}
		if f.state().Revision != rev {
			t.Fatalf("gate %v: a refused check committed", g)
		}
	}
}

// AppendAudit's delta path does not go through guardAttestations (the replacement path does, so a
// transition that touches another voter's attestation record is forbidden). That is sound only
// because the delta's transition cannot touch one: it changes the audit log, the revision and the
// revision clock and nothing else. This pins it, over a state that holds another voter's
// attestation record, so a future change that lets applyAuditDelta write elsewhere fails here.
func TestAuditDeltaTouchesOnlyTheAuditLogTheRevisionAndItsClock(t *testing.T) {
	f := newInstallFx(t)
	st := f.state()
	if st.OIDC == nil {
		st.OIDC = map[string]json.RawMessage{}
	}
	st.OIDC["control_attest:9"] = json.RawMessage(`{"node":9,"identity":"voter-9","journal":{"erasures":1,"applied":1}}`)
	before := st
	before.Audits = slices.Clone(st.Audits)
	before.RevisionClock = slices.Clone(st.RevisionClock)
	after := st
	after.Audits = slices.Clone(st.Audits)
	after.RevisionClock = slices.Clone(st.RevisionClock)
	applyAuditDelta(&after, auditDelta{Installation: st.Installation, Expected: st.Revision, At: 1 << 40, Audits: []model.ControlAudit{f.audit("export.chunk", 1), f.audit(controlErasedAction, 2)}})
	var a, b map[string]json.RawMessage
	if err := json.Unmarshal([]byte(f.canonical(before)), &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(f.canonical(after)), &b); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"Audits": true, "Revision": true, "revision_clock": true}
	for key := range a {
		if !allowed[key] && string(a[key]) != string(b[key]) {
			t.Errorf("the audit delta changed %q", key)
		}
	}
	for key := range b {
		if _, ok := a[key]; !ok && !allowed[key] {
			t.Errorf("the audit delta added %q", key)
		}
	}
	if string(a["Audits"]) == string(b["Audits"]) || string(a["Revision"]) == string(b["Revision"]) {
		t.Fatal("fixture invalid: the delta changed neither the audit log nor the revision")
	}
}
