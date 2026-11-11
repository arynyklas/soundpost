// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"soundpost/internal/model"
)

// The redaction must never change the command that establishes the current state: the machine
// compares a replayed command of the current revision with the state it holds. A deletion only
// removes what the state no longer has, so a current state that still holds a covered payload
// is refused (the pass fails and the receipt keeps naming the journal) instead of rewriting the
// head under it. An older command, and a stale command that was rejected, are redacted.
func TestRedactorNeverRewritesTheCommandThatIsTheCurrentState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	org, project, operation, incident := model.ID{0x10}, model.ID{0x11}, model.ID{0xdd}, model.ID{0xa1}
	const canary = "CANARYGUARD7c41e90d2b86a"
	record, err := json.Marshal(IncidentRecord{Org: org, Project: project, ID: incident, Version: 1, Digest: model.Hash{7},
		State: json.RawMessage(`{"incident_id":"` + incident.String() + `","org_id":"` + org.String() + `","project_id":"` + project.String() + `","version":"1","evidence":"` + canary + `","at":"5"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Update(ctx, func(st *State) error {
		st.IncidentBooks = map[string]json.RawMessage{org.String() + ":" + project.String() + ":" + incident.String(): record}
		st.Deletions = map[string]model.DeletionOperation{operation.String(): {
			Predicate: model.DeletePredicate{Operation: operation, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}, Generation: 1},
			Phase:     model.DeletePhaseComplete, Principal: model.ID{0xbb}, CompletedAt: 10}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	current, err := s.localState()
	if err != nil {
		t.Fatal(err)
	}
	commandOf := func(st State) []byte {
		raw, err := json.Marshal(controlReplacement{Expected: st.Revision - 1, State: st, Keys: map[string][]byte{}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if !strings.Contains(string(commandOf(current)), canary) {
		t.Fatal("fixture invalid: the current state does not hold the covered payload")
	}

	r := &controlRedactor{s: s}
	if _, changed, err := r.redact(commandOf(current)); err == nil || changed {
		t.Fatalf("the command that is the current state was redacted: changed=%v err=%v", changed, err)
	}
	// An older command (its revision is not the current one) is redacted.
	older := current
	older.Revision = current.Revision - 1
	replacement, changed, err := r.redact(commandOf(older))
	if err != nil || !changed || strings.Contains(string(replacement), canary) {
		t.Fatalf("an older command: changed=%v err=%v", changed, err)
	}
	// A stale command rejected at the current revision carries a different state: redacted.
	stale := current
	stale.Users = nil
	stale.Orgs = nil
	if replacement, changed, err = r.redact(commandOf(stale)); err != nil || !changed || strings.Contains(string(replacement), canary) {
		t.Fatalf("a stale command at the current revision: changed=%v err=%v", changed, err)
	}
	// A deletion that is still fencing erases nothing from retained commands.
	op := current.Deletions[operation.String()]
	op.Phase = model.DeletePhaseFencing
	current.Deletions[operation.String()] = op
	fencing := &controlRedactor{s: s}
	fencing.loaded, fencing.live, fencing.rules = true, current, current
	fencing.rules.Deletions = map[string]model.DeletionOperation{}
	if _, changed, err = fencing.redact(commandOf(older)); err != nil || changed {
		t.Fatalf("a fencing deletion redacted a retained command: changed=%v err=%v", changed, err)
	}
}

// The retained commands are redacted at once, but the journal head and the snapshots that were
// cut before are sealed: until a later cut replaces them the receipt keeps naming the journal,
// however complete the redaction itself was. Only the whole pass (redaction, a cut past it,
// DropSuperseded, compaction) clears it.
func TestReceiptNamesTheJournalUntilTheCutReplacesTheSealedCopies(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.EnableSingle(ctx, filepath.Join(dir, "raft-control")); err != nil {
		t.Fatal(err)
	}
	org, project, operation, incident := model.ID{0x10}, model.ID{0x11}, model.ID{0xdd}, model.ID{0xa1}
	record, err := json.Marshal(IncidentRecord{Org: org, Project: project, ID: incident, Version: 1, Digest: model.Hash{7},
		State: json.RawMessage(`{"incident_id":"` + incident.String() + `","org_id":"` + org.String() + `","project_id":"` + project.String() + `","version":"1","evidence":"CANARYSEALED7c41e90d","at":"5"}`)})
	if err != nil {
		t.Fatal(err)
	}
	key := org.String() + ":" + project.String() + ":" + incident.String()
	if err = s.Update(ctx, func(st *State) error {
		st.IncidentBooks = map[string]json.RawMessage{key: record}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	group := s.ReplicaGroup()
	cut, err := group.ReadIndex(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = group.CreateSnapshot(ctx, cut); err != nil {
		t.Fatal(err)
	}
	// The deletion committed and the live state no longer has the payload.
	if err = s.Update(ctx, func(st *State) error {
		delete(st.IncidentBooks, key)
		st.Deletions = map[string]model.DeletionOperation{operation.String(): {
			Predicate: model.DeletePredicate{Operation: operation, Org: org, Mode: model.DeleteRetireProject, Projects: []model.ID{project}, Generation: 1},
			Phase:     model.DeletePhaseComplete, Principal: model.ID{0xbb}, CompletedAt: 10}}
		st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: model.ID{0xbb}, Action: controlErasedAction, Time: 10, Org: org.String(), Targets: []model.ID{operation}, Outcome: model.AuditAllowed})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	named := func() bool {
		for _, name := range s.ResidualStores() {
			if name == ResidualControlJournal {
				return true
			}
		}
		return false
	}
	if !named() {
		t.Fatal("an erasure committed and no pass ran: the journal must be named")
	}
	redactor := &controlRedactor{s: s}
	res, err := group.RedactMachineCommands(ctx, 1, redactor.redact)
	if err != nil || res.Redacted == 0 {
		t.Fatalf("redaction %+v %v", res, err)
	}
	if !named() {
		t.Fatal("the commands were redacted but the sealed snapshot and journal head still carry the payload: the journal must stay named")
	}
	if err = s.RedactRetainedControlCommands(ctx); err != nil {
		t.Fatal(err)
	}
	if named() {
		t.Fatalf("the whole pass completed and the store still names %v", s.ResidualStores())
	}
}
