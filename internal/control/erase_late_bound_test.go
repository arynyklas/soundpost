// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// The late re-erasure (eraseLateEffect) screens an effect that a worker read
// before the barrier and commits after its deletion completed. It must never
// reach state that is not derived from the deleted range: a project that once
// had a range deletion keeps working, and what it commits from data after the
// range stays readable. (09.06 review C-1.)

const controlErasedAudit = "delete.control_erased"

// Data AFTER the range's end: the new incident, condition, rule evaluation and
// delivery commit in a project with a completed [40,100) metric deletion, and
// stay, readable, with no erasing audit and no scrub owed.
func TestEffectOfDataAfterACompletedRangeIsKept(t *testing.T) {
	for _, c := range lateCases {
		t.Run(c.name, func(t *testing.T) {
			f := newEraseFx(t)
			f.commitRule(f.newSeed(f.project, "CANARYBEFOREBOUND7c41e90d2b"), 60, model.Metric)
			f.saga(f.lateRange())
			if err := f.store.ScrubErased(f.ctx); err != nil {
				t.Fatal(err)
			}
			erasing, scrubbed := f.auditCount(controlErasedAudit), f.auditCount("delete.control_scrubbed")

			const after = "CANARYAFTERRANGE3b9d41e07c5a82"
			c.commit(f, f.newSeed(f.project, after), 1000) // a later evidence time than End
			if !f.stateHolds(after) {
				t.Fatal("an effect derived from data after the range's end was erased in the transition that committed it")
			}
			if n := f.auditCount(controlErasedAudit); n != erasing {
				t.Fatalf("a late pass that erased nothing appended %d erasing audit(s)", n-erasing)
			}
			if err := f.store.ScrubErased(f.ctx); err != nil {
				t.Fatal(err)
			}
			if n := f.auditCount("delete.control_scrubbed"); n != scrubbed {
				t.Fatalf("a late pass that erased nothing re-owed the control.db scrub (%d new scrub audit(s))", n-scrubbed)
			}
			if got := f.store.ResidualStores(); len(got) != 1 || got[0] != control.ResidualControlJournal {
				t.Fatalf("residual stores %v, want only %s", got, control.ResidualControlJournal)
			}
		})
	}
}

// The same project, one late effect inside the range and one after it: only the
// first goes, in its own apply, and the second is untouched by it.
func TestLateEffectInRangeGoesAndTheOneAfterItStays(t *testing.T) {
	for _, c := range lateCases {
		t.Run(c.name, func(t *testing.T) {
			f := newEraseFx(t)
			f.saga(f.lateRange())
			const covered, after = "CANARYCOVERED9a1c0e5d77f3b2", "CANARYAFTER2e8f60b1c4d95a73"
			c.commit(f, f.newSeed(f.project, after), 1000)
			c.commit(f, f.newSeed(f.project, covered), 60)
			if f.stateHolds(covered) {
				t.Fatal("an in-range late effect was not erased")
			}
			if !f.stateHolds(after) {
				t.Fatal("erasing the in-range late effect took the one after the range with it")
			}
			// A later, unrelated commit changes neither.
			c.commit(f, f.newSeed(f.project, "CANARYUNRELATED6d0a93e5b1c7f2"), 1000)
			if f.stateHolds(covered) || !f.stateHolds(after) {
				t.Fatal("a later commit changed what the range covers")
			}
		})
	}
}

// A range that starts at zero ("everything older than T") is the common
// retention shape; a duration or an unset time in a state must not make every
// later state of the project look in-range.
func TestOpenEndedRangeKeepsLaterStates(t *testing.T) {
	f := newEraseFx(t)
	req := f.lateRange()
	req.Start, req.End = 0, 100
	f.saga(req)
	const after = "CANARYAFTERZERO5c3e80a1d9f246"
	f.commitIncident(f.newSeed(f.project, after), 1000)
	f.commitCondition(f.newSeed(f.project, after), 1000)
	if !f.stateHolds(after) {
		t.Fatal("a state after an open-ended range was erased")
	}
}

// A job updated from data after a completed range keeps its state, and one that
// names evidence inside the range loses it.
func TestJobUpdateOfDataAfterACompletedRangeIsKept(t *testing.T) {
	f := newJobFx(t)
	sagaOf(f.fenceFx, control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.Metric}, Start: 40, End: 100})
	const after, covered = "CANARYJOBAFTER1f6a08c2e5b937", "CANARYJOBCOVERED7e2d90b4a1c685"
	u := f.upd(f.job(1), 0, 1)
	u.State = f.state(f.job(1), 1, map[string]any{"latest_schedule_key": after, "current_health": map[string]any{"status": "unknown", "as_of_ns": model.Int64(1000)}})
	f.must(1, u)
	if snap, ok := f.book(f.job(1)); !ok || snap.Erased || snap.Version != 1 {
		t.Fatalf("a job updated from data after the range must keep its state: %+v %v", snap, ok)
	}
	late := f.upd(f.job(2), 0, 2)
	late.State = f.state(f.job(2), 1, map[string]any{"latest_schedule_key": covered, "current_health": map[string]any{"status": "unknown", "as_of_ns": model.Int64(1000)},
		"attempts": map[string]any{"a": map[string]any{"observed_ns": model.Int64(60)}}})
	f.must(2, late)
	if snap, ok := f.book(f.job(2)); !ok || !snap.Erased || snap.Version != 1 {
		t.Fatalf("a job that names evidence inside the range must read as erased at its version: %+v %v", snap, ok)
	}
	if snap, ok := f.book(f.job(1)); !ok || snap.Erased {
		t.Fatalf("erasing the covered job took the other: %+v %v", snap, ok)
	}
}

// The redaction of a retained control command uses the rule the live apply used
// for it: a command committed while the deletion was fencing carried a state the
// completion erased by the begin/complete rule, one committed after it was
// screened by the late rule, so redacting it must not drop what that kept.
func TestRedactControlCommandFollowsTheRuleOfItsOwnCommit(t *testing.T) {
	f := newEraseFx(t)
	id := f.begin(f.lateRange())
	const fencing, after = "CANARYFENCINGRED4e7a1c93d05b", "CANARYAFTERRED8b2f60d1e39a7"
	f.commitIncidentSpan(f.newSeed(f.project, fencing), 10, 1000) // window spans the range, no time inside: the begin rule covers it, the late rule does not
	retained := func() []byte {
		var raw []byte
		if err := f.store.View(f.ctx, func(st control.State) error {
			var err error
			raw, err = json.Marshal(struct {
				Expected model.Revision     `json:"expected"`
				State    model.ControlState `json:"state"`
				Keys     map[string][]byte  `json:"keys"`
			}{st.Revision, st, map[string][]byte{}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	whileFencing := retained()
	f.complete(id)
	f.commitIncidentSpan(f.newSeed(f.project, after), 10, 1000)
	afterCompletion := retained()

	replacement, changed, err := f.store.RedactControlCommand(whileFencing)
	if err != nil || !changed || bytes.Contains(replacement, []byte(fencing)) {
		t.Fatalf("a command committed while fencing must lose the state the completion erased: changed=%v err=%v", changed, err)
	}
	if replacement, changed, err = f.store.RedactControlCommand(afterCompletion); err != nil || changed || !bytes.Contains(replacement, []byte(after)) {
		t.Fatalf("a command committed after completion must keep the state the late rule kept: changed=%v err=%v", changed, err)
	}
}

// An entity deletion covers no opaque state, so after one has completed no
// incident or condition commit is erased and none adds an erasing audit, at any
// evidence time.
func TestLateCommitAfterAnEntityDeletionErasesNothing(t *testing.T) {
	f := newEraseFx(t)
	f.saga(control.DeleteScope{Mode: model.DeleteEntity, Projects: []model.ID{f.project}, Entities: []model.ID{model.NewID()}})
	erasing := f.auditCount(controlErasedAudit)
	const kept = "CANARYENTITYLATE6a41f9c27d3e05"
	for _, at := range []int64{10, 60, 1000} {
		f.commitIncident(f.newSeed(f.project, kept), at)
		f.commitCondition(f.newSeed(f.project, kept), at)
	}
	if !f.stateHolds(kept) {
		t.Fatal("an entity deletion erased an incident or condition committed after it")
	}
	if n := f.auditCount(controlErasedAudit); n != erasing {
		t.Fatalf("%d spurious erasing audit(s)", n-erasing)
	}
}

// The begin/complete rule is exact in time (CD-9): a state committed while the
// deletion is still fencing is erased when it completes when its recorded window
// intersects the range, and kept when its evidence all lies after the range's
// end. A state with no window at all is erased and counted as over-erased.
func TestCompletionKeepsAStateCommittedWhileFencingOutsideTheRange(t *testing.T) {
	f := newEraseFx(t)
	id := f.begin(f.lateRange())
	const outside, inside, spanning, bare = "CANARYFENCINGOUT2c8e5a1f7d4b90", "CANARYFENCINGIN9d3e6b2a05c817", "CANARYFENCINGSPAN4b1f7a8e2c6d30", "CANARYFENCINGBARE8a5c1e9d37b402"
	f.commitIncident(f.newSeed(f.project, outside), 1000)
	f.commitIncident(f.newSeed(f.project, inside), 60)
	f.commitIncidentSpan(f.newSeed(f.project, spanning), 10, 1000)
	f.commitIncidentState(f.newSeed(f.project, bare), `"labels":{"host":"a"}`)
	for _, c := range []string{outside, inside, spanning, bare} {
		if !f.stateHolds(c) {
			t.Fatal("a fencing deletion erased at the effect: completion owns that")
		}
	}
	f.complete(id)
	if !f.stateHolds(outside) {
		t.Fatal("completion erased a state whose evidence is all after the range's end")
	}
	for _, gone := range []string{inside, spanning, bare} {
		if f.stateHolds(gone) {
			t.Fatalf("completion kept %s", gone)
		}
	}
	op, _, err := f.store.DeletionOperation(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if want := []model.OverErased{{Book: model.OverErasedIncident, Count: 1}}; !reflect.DeepEqual(op.OverErased, want) {
		t.Fatalf("over-erased = %+v, want %+v (only the state with no window)", op.OverErased, want)
	}
}

// commitIncidentState commits an incident whose state is the seed's header and
// canary plus the given extra members, which name the times the case needs.
func (f *eraseFx) commitIncidentState(s eraseSeed, extra string) {
	f.t.Helper()
	state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1","evidence":%q,%s}`, s.inc.String(), f.org.String(), s.project.String(), s.canary, extra))
	c := control.IncidentCommand{Project: s.project, Incident: s.inc, Action: "open", Origin: "human", Actor: f.user, At: 100, NewVersion: 1, State: state, Digest: digest(state)}
	if _, err := f.store.Transact(f.ctx, f.adminScope(), f.cmd(control.KindIncidentAction, model.NewID(), c)); err != nil {
		f.t.Fatal(err)
	}
}

// commitIncidentSpan commits an incident that names an old evidence time and a
// newer one (a timeline that spans the range) and nothing in between.
func (f *eraseFx) commitIncidentSpan(s eraseSeed, from, to int64) {
	f.t.Helper()
	f.commitIncidentState(s, fmt.Sprintf(`"first_at":"%d","at":"%d"`, from, to))
}
