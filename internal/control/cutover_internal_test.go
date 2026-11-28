// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

var (
	icOrg, icProject, icOther = model.ID{0x10}, model.ID{0x11}, model.ID{0x12}
	icOld, icNew              = model.ID{0x21}, model.ID{0x22}
)

func icRecord(project model.ID, phase string, revision model.Revision, ack *model.ID) CutoverRecord {
	return CutoverRecord{Org: icOrg, Project: project, ID: model.ID{0x31}, Old: icOld, New: icNew, Revision: revision, Phase: phase, RestoreAck: ack, EnteredAt: 5,
		Frontier: []CutoverFrontier{{Source: model.ID{0x41}, Version: 1, Cursor: model.Cursor{Group: model.ID{0x42}, Index: 9}}},
		Steps: []CutoverStep{
			{Command: model.ID{0x51}, Principal: model.ID{0x52}, From: "", To: CutoverShadow, Revision: 1, At: 1, Reason: "OPERATOR-TEXT-1"},
			{Command: model.ID{0x53}, Principal: model.ID{0x52}, From: CutoverShadow, To: CutoverQuiescingOld, Revision: 2, At: 2, Reason: "OPERATOR-TEXT-2",
				Payload: json.RawMessage(`{"cutover":"EVIDENCE-PAYLOAD"}`), Evidence: &model.Hash{7}},
		}}
}

func icState(t *testing.T, recs ...CutoverRecord) *State {
	t.Helper()
	st := &State{}
	for _, r := range recs {
		if err := storeCutover(st, cutoverKey(r.Org, r.Project), r); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// The restore marker is the real quarantine's: the pinned key and shape are read
// back from what auth.QuarantineRestoredState wrote, so a rename there fails here
// instead of silently opening the claim gate.
func TestRestoreMarkerIsTheRealQuarantineStash(t *testing.T) {
	st := &State{}
	if _, present := restoreOf(st); present {
		t.Fatal("a state that was never restored reports a restore")
	}
	at := time.Unix(1_800_000_123, 456)
	gen := model.NewID()
	if _, err := auth.QuarantineRestoredState(st, auth.RestoreInput{Generation: gen, Backup: model.NewID(), BootstrapHash: "h", SealedBearerKey: "s", At: at}); err != nil {
		t.Fatal(err)
	}
	m, present := restoreOf(st)
	if !present || m.Generation != gen || m.At != at.UnixNano() {
		t.Fatalf("the committed quarantine reads back as %+v (present %v), want generation %s at %d", m, present, gen, at.UnixNano())
	}
	// Discarding the stash (the next generation's restore does) removes the marker.
	if !auth.DiscardRestoreStash(st) {
		t.Fatal("no stash to discard")
	}
	if _, present = restoreOf(st); present {
		t.Fatal("a discarded stash is still a restore")
	}
}

// What the committed state says about sending, for every combination of cutover
// phase and restore state.
func TestCutoverGateOfCommittedState(t *testing.T) {
	gen1, gen2 := model.ID{0x61}, model.ID{0x62}
	stash := func(g model.ID) json.RawMessage {
		raw, _ := json.Marshal(restoreMarker{Generation: g, At: 3})
		return raw
	}
	cases := []struct {
		name      string
		rec       *CutoverRecord
		stash     json.RawMessage
		wantBlock string
		wantRev   model.Revision
	}{
		{name: "nothing configured", wantBlock: ""},
		{name: "shadow", rec: new(icRecord(icProject, CutoverShadow, 1, nil)), wantBlock: DeliveryCodeShadow, wantRev: 1},
		{name: "quiescing_old", rec: new(icRecord(icProject, CutoverQuiescingOld, 2, nil)), wantBlock: DeliveryCodeShadow, wantRev: 2},
		{name: "barrier_verified", rec: new(icRecord(icProject, CutoverBarrierVerified, 3, nil)), wantBlock: DeliveryCodeShadow, wantRev: 3},
		{name: "new_active", rec: new(icRecord(icProject, CutoverNewActive, 4, nil)), wantBlock: "", wantRev: 4},
		{name: "rollback_quiescing", rec: new(icRecord(icProject, CutoverRollbackQuiescing, 5, nil)), wantBlock: DeliveryCodeShadow, wantRev: 5},
		{name: "old_active", rec: new(icRecord(icProject, CutoverOldActive, 6, nil)), wantBlock: DeliveryCodeShadow, wantRev: 6},
		{name: "a restore and no record", stash: stash(gen1), wantBlock: DeliveryCodeRestorePending},
		{name: "a restore the cutover did not acknowledge", rec: new(icRecord(icProject, CutoverNewActive, 4, nil)), stash: stash(gen1), wantBlock: DeliveryCodeRestorePending, wantRev: 4},
		{name: "a restore of another generation", rec: new(icRecord(icProject, CutoverNewActive, 4, &gen1)), stash: stash(gen2), wantBlock: DeliveryCodeRestorePending, wantRev: 4},
		{name: "the acknowledged restore", rec: new(icRecord(icProject, CutoverNewActive, 4, &gen1)), stash: stash(gen1), wantBlock: "", wantRev: 4},
		{name: "an acknowledged restore in another phase", rec: new(icRecord(icProject, CutoverOldActive, 6, &gen1)), stash: stash(gen1), wantBlock: DeliveryCodeShadow, wantRev: 6},
		{name: "an unreadable stash", rec: new(icRecord(icProject, CutoverNewActive, 4, &gen1)), stash: json.RawMessage(`{"generation":"not an id"}`), wantBlock: DeliveryCodeRestorePending, wantRev: 4},
		{name: "an unreadable stash is never acknowledged by a zero generation", stash: json.RawMessage(`garbage`), wantBlock: DeliveryCodeRestorePending},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &State{}
			if tc.rec != nil {
				st = icState(t, *tc.rec)
			}
			if tc.stash != nil {
				st.OIDC = map[string]json.RawMessage{restoreQuarantineKey: tc.stash}
			}
			g, err := cutoverGateOf(st, icOrg, icProject)
			if err != nil || g.block != tc.wantBlock || g.revision != tc.wantRev {
				t.Fatalf("gate %+v (%v), want block %q revision %d", g, err, tc.wantBlock, tc.wantRev)
			}
			// The read side agrees: a delivery of the project is revoked exactly when
			// the claim is blocked.
			r := DeliveryRecord{Org: icOrg, Project: icProject, Phase: DeliveryPending}
			v := deliveryGate(st, g, err, &r)
			if blocked := v.phase == DeliveryCancelled && v.code == DeliveryReasonRevoked; blocked != (tc.wantBlock != "") {
				t.Fatalf("hold verdict %+v for block %q", v, tc.wantBlock)
			}
		})
	}
	// Another project of the same organization has its own record.
	st := icState(t, icRecord(icProject, CutoverShadow, 1, nil))
	if g, err := cutoverGateOf(st, icOrg, icOther); err != nil || g.block != "" || g.revision != 0 {
		t.Fatalf("a project without a record is gated by another project's: %+v %v", g, err)
	}
	if g, err := cutoverGateOf(st, model.ID{0x99}, icProject); err != nil || g.block != "" {
		t.Fatalf("another organization is gated by this one's: %+v %v", g, err)
	}
}

// A cutover record that cannot be read never opens anything: the claim fails, the
// read side pauses, and the revision helper reports none rather than guessing.
func TestCutoverCorruptRecordFailsClosed(t *testing.T) {
	st := &State{CutoverBooks: map[string]json.RawMessage{cutoverKey(icOrg, icProject): json.RawMessage(`{"revision":`)}}
	gate, gerr := cutoverGateOf(st, icOrg, icProject)
	if gerr == nil {
		t.Fatal("a corrupt record was read as a gate")
	}
	r := DeliveryRecord{Org: icOrg, Project: icProject, Phase: DeliveryPending}
	if v := deliveryGate(st, gate, gerr, &r); !v.pause {
		t.Fatalf("a corrupt record did not pause the delivery: %+v", v)
	}
	if CutoverRevision(*st, icOrg, icProject) != 0 {
		t.Fatal("a corrupt record has a revision")
	}
	if _, _, err := loadCutover(st, cutoverKey(icOrg, icProject)); err == nil {
		t.Fatal("a corrupt record loaded")
	}
}

// ---------------------------------------------------------------------------
// Erasure.

func retire(mode string, projects ...model.ID) model.DeletePredicate {
	return model.DeletePredicate{Operation: model.ID{0xdd, 1}, Org: icOrg, Mode: mode, Projects: projects}
}

func TestEraseCutoverBooksDropsOperatorTextAndEvidenceOnRetirement(t *testing.T) {
	for name, p := range map[string]model.DeletePredicate{
		"retire project": retire(model.DeleteRetireProject, icProject),
		"retire org":     retire(model.DeleteRetireOrg),
	} {
		t.Run(name, func(t *testing.T) {
			st := icState(t, icRecord(icProject, CutoverNewActive, 4, nil))
			if name == "retire project" {
				if err := storeCutover(st, cutoverKey(icOrg, icOther), icRecord(icOther, CutoverShadow, 1, nil)); err != nil {
					t.Fatal(err)
				}
			}
			before, _, _ := loadCutover(st, cutoverKey(icOrg, icProject))
			wantDropped := 1
			if name == "retire org" {
				wantDropped = 1
				if err := storeCutover(st, cutoverKey(icOrg, icOther), icRecord(icOther, CutoverShadow, 1, nil)); err != nil {
					t.Fatal(err)
				}
				wantDropped = 2
			}
			dropped, err := eraseCutoverBooks(st, p, 99)
			if err != nil || dropped != wantDropped {
				t.Fatalf("dropped %d: %v", dropped, err)
			}
			rec, _, _ := loadCutover(st, cutoverKey(icOrg, icProject))
			raw := string(st.CutoverBooks[cutoverKey(icOrg, icProject)])
			if strings.Contains(raw, "OPERATOR-TEXT") || strings.Contains(raw, "EVIDENCE-PAYLOAD") {
				t.Fatalf("operator text or evidence survived: %s", raw)
			}
			// Identity, revision, phase, epoch, frontier and the per-step audit survive.
			if rec.Erased == nil || *rec.Erased != p.Operation || rec.ID != before.ID || rec.Old != before.Old || rec.New != before.New || rec.Revision != 4 || rec.Phase != CutoverNewActive ||
				rec.EnteredAt != before.EnteredAt || len(rec.Frontier) != 1 || len(rec.Steps) != 2 {
				t.Fatalf("the erased record: %+v", rec)
			}
			for i, s := range rec.Steps {
				b := before.Steps[i]
				if s.Reason != "" || s.Payload != nil || s.Command != b.Command || s.Principal != b.Principal || s.To != b.To || s.From != b.From || s.Revision != b.Revision || s.At != b.At || s.Digest != b.Digest || (s.Evidence == nil) != (b.Evidence == nil) {
					t.Fatalf("step %d after the erasure: %+v", i, s)
				}
			}
			otherRaw := string(st.CutoverBooks[cutoverKey(icOrg, icOther)])
			if name == "retire project" && !strings.Contains(otherRaw, "OPERATOR-TEXT") {
				t.Fatalf("another project's record was erased: %s", otherRaw)
			}
			if name == "retire org" && strings.Contains(otherRaw, "OPERATOR-TEXT") {
				t.Fatalf("an organization retirement left a project's record: %s", otherRaw)
			}
			// Idempotent: a retired record is never covered again.
			again := p
			again.Operation = model.ID{0xdd, 2}
			if n, err := eraseCutoverBooks(st, again, 100); err != nil || n != 0 {
				t.Fatalf("second erasure dropped %d: %v", n, err)
			}
			if rec2, _, _ := loadCutover(st, cutoverKey(icOrg, icProject)); *rec2.Erased != p.Operation {
				t.Fatal("a second operation re-marked an erased record")
			}
		})
	}
}

// A retirement of another organization, a historical range and an entity deletion
// cover nothing: the record holds no telemetry.
func TestEraseCutoverBooksCoversOnlyRetirements(t *testing.T) {
	for name, p := range map[string]model.DeletePredicate{
		"another organization": {Operation: model.ID{0xdd, 1}, Org: model.ID{0x99}, Mode: model.DeleteRetireOrg},
		"another project":      retire(model.DeleteRetireProject, icOther),
		"a historical range":   {Operation: model.ID{0xdd, 1}, Org: icOrg, Mode: model.DeleteHistoricalRange, Projects: []model.ID{icProject}, Start: 0, End: 1 << 60},
		"an entity deletion":   {Operation: model.ID{0xdd, 1}, Org: icOrg, Mode: model.DeleteEntity, Projects: []model.ID{icProject}, Entities: []model.ID{{0x77}}},
	} {
		t.Run(name, func(t *testing.T) {
			st := icState(t, icRecord(icProject, CutoverNewActive, 4, nil))
			before, _ := json.Marshal(st.CutoverBooks)
			if n, err := eraseCutoverBooks(st, p, 5); err != nil || n != 0 {
				t.Fatalf("dropped %d: %v", n, err)
			}
			if after, _ := json.Marshal(st.CutoverBooks); string(after) != string(before) {
				t.Fatal("the books changed")
			}
		})
	}
}

func TestEraseCutoverBooksIsDeterministicAndRefusesCorruption(t *testing.T) {
	run := func() string {
		st := icState(t, icRecord(icProject, CutoverNewActive, 4, nil), icRecord(icOther, CutoverShadow, 1, nil))
		if _, err := eraseCutoverBooks(st, retire(model.DeleteRetireOrg), 77); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(st.CutoverBooks)
		return string(raw)
	}
	if a, b := run(), run(); a != b {
		t.Fatal("the erasure is not deterministic")
	}
	st := icState(t, icRecord(icProject, CutoverShadow, 1, nil))
	st.CutoverBooks["bad"] = json.RawMessage(`{`)
	if _, err := eraseCutoverBooks(st, retire(model.DeleteRetireOrg), 5); err == nil {
		t.Fatal("a corrupt record was skipped")
	}
}
