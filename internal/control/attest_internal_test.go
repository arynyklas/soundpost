// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

func attestMembers(ids ...uint64) replica.Members {
	m := replica.Members{Revision: 1}
	for _, id := range ids {
		m.Nodes = append(m.Nodes, replica.Member{ID: id, Address: fmt.Sprintf("https://n%d.invalid", id), NodeIdentity: fmt.Sprintf("node-%d", id), FailureDomain: fmt.Sprintf("d%d", id)})
	}
	return m
}

func attestRecord(t *testing.T, node uint64, identity string, journal, state uint64) json.RawMessage {
	t.Helper()
	a := residueAttestation{Node: node, Identity: identity}
	if journal != 0 {
		a.Journal = &attestedFact{Erasures: journal, Applied: 7}
	}
	if state != 0 {
		a.State = &attestedFact{Erasures: state, Applied: 7}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// The cluster rule, from the committed state and the committed configuration alone.
func TestClusterUnattestedRules(t *testing.T) {
	const erasures = 3
	ok := func(node uint64) json.RawMessage {
		return attestRecord(t, node, fmt.Sprintf("node-%d", node), erasures, erasures)
	}
	cases := []struct {
		name                   string
		records                map[string]json.RawMessage
		members                replica.Members
		wantJournal, wantState bool
	}{
		{name: "every voter attested", records: map[string]json.RawMessage{attestKey(1): ok(1), attestKey(2): ok(2), attestKey(3): ok(3)}, members: attestMembers(1, 2, 3)},
		{name: "one of three has not attested", records: map[string]json.RawMessage{attestKey(1): ok(1), attestKey(2): ok(2)}, members: attestMembers(1, 2, 3), wantJournal: true, wantState: true},
		{name: "any voter is not every voter", records: map[string]json.RawMessage{attestKey(2): ok(2)}, members: attestMembers(1, 2, 3), wantJournal: true, wantState: true},
		{name: "no attestation at all", members: attestMembers(1, 2, 3), wantJournal: true, wantState: true},
		{name: "unknown configuration", records: map[string]json.RawMessage{attestKey(1): ok(1)}, wantJournal: true, wantState: true},
		{name: "a voter that left does not count (its record is stale)", records: map[string]json.RawMessage{attestKey(1): ok(1), attestKey(2): ok(2), attestKey(3): attestRecord(t, 3, "node-3", 1, 1)}, members: attestMembers(1, 2)},
		{name: "a voter that left does not count (no record)", records: map[string]json.RawMessage{attestKey(1): ok(1), attestKey(2): ok(2)}, members: attestMembers(1, 2)},
		{name: "a voter that joined after the erasure must attest", records: map[string]json.RawMessage{attestKey(1): ok(1), attestKey(2): ok(2), attestKey(3): ok(3)}, members: attestMembers(1, 2, 3, 4), wantJournal: true, wantState: true},
		{name: "a replacement that attested counts", records: map[string]json.RawMessage{attestKey(1): ok(1), attestKey(2): ok(2), attestKey(4): ok(4)}, members: attestMembers(1, 2, 4)},
		{name: "a later erasure supersedes every attestation", records: map[string]json.RawMessage{attestKey(1): attestRecord(t, 1, "node-1", erasures-1, erasures-1), attestKey(2): ok(2)}, members: attestMembers(1, 2), wantJournal: true, wantState: true},
		{name: "a fact for more erasures than exist is not a fact", records: map[string]json.RawMessage{attestKey(1): attestRecord(t, 1, "node-1", erasures+1, erasures+1)}, members: attestMembers(1), wantJournal: true, wantState: true},
		{name: "the journal alone", records: map[string]json.RawMessage{attestKey(1): attestRecord(t, 1, "node-1", erasures, 0)}, members: attestMembers(1), wantState: true},
		{name: "the scrub alone", records: map[string]json.RawMessage{attestKey(1): attestRecord(t, 1, "node-1", 0, erasures)}, members: attestMembers(1), wantJournal: true},
		{name: "a record of another node under this key", records: map[string]json.RawMessage{attestKey(1): ok(2)}, members: attestMembers(1), wantJournal: true, wantState: true},
		{name: "a record of a node replaced under the same id", records: map[string]json.RawMessage{attestKey(1): attestRecord(t, 1, "someone-else", erasures, erasures)}, members: attestMembers(1), wantJournal: true, wantState: true},
		{name: "an unknown field is not a closed DTO", records: map[string]json.RawMessage{attestKey(1): json.RawMessage(fmt.Sprintf(`{"node":1,"identity":"node-1","journal":{"erasures":%d,"applied":7},"state":{"erasures":%d,"applied":7},"extra":1}`, erasures, erasures))}, members: attestMembers(1), wantJournal: true, wantState: true},
		{name: "a fact without an applied index", records: map[string]json.RawMessage{attestKey(1): json.RawMessage(fmt.Sprintf(`{"node":1,"identity":"node-1","journal":{"erasures":%d,"applied":0},"state":{"erasures":%d,"applied":0}}`, erasures, erasures))}, members: attestMembers(1), wantJournal: true, wantState: true},
		{name: "garbage", records: map[string]json.RawMessage{attestKey(1): json.RawMessage(`[1]`)}, members: attestMembers(1), wantJournal: true, wantState: true},
		{name: "a learner counts (it holds the same files)", records: map[string]json.RawMessage{attestKey(1): ok(1)}, members: replica.Members{Revision: 1, Nodes: append(attestMembers(1).Nodes, replica.Member{ID: 9, NodeIdentity: "node-9", Learner: true})}, wantJournal: true, wantState: true},
	}
	for _, c := range cases {
		st := State{OIDC: c.records}
		journal, state := clusterUnattested(st, c.members, erasures)
		if journal != c.wantJournal || state != c.wantState {
			t.Errorf("%s: unattested journal=%v state=%v, want journal=%v state=%v", c.name, journal, state, c.wantJournal, c.wantState)
		}
	}
}

// guardAttestations lets a writer other than the attestation writer delete a record or leave
// one alone, never add or change one.
func TestGuardAttestationsRefusesForgeryOnly(t *testing.T) {
	key := attestKey(3)
	raw := json.RawMessage(`{"node":3}`)
	other := json.RawMessage(`{"node":3,"identity":"x"}`)
	forbidden := func(err error) bool {
		var fault *model.Fault
		return errors.As(err, &fault) && fault.Code == model.Forbidden
	}
	run := func(initial map[string]json.RawMessage, fn func(*State)) error {
		st := &State{OIDC: initial}
		return guardAttestations(func(st *State) error { fn(st); return nil })(st)
	}
	if err := run(nil, func(st *State) { st.OIDC = map[string]json.RawMessage{key: raw} }); !forbidden(err) {
		t.Fatalf("adding a record: %v", err)
	}
	if err := run(map[string]json.RawMessage{key: raw}, func(st *State) { st.OIDC[key] = other }); !forbidden(err) {
		t.Fatalf("changing a record: %v", err)
	}
	if err := run(map[string]json.RawMessage{key: raw}, func(st *State) { st.OIDC[attestKey(4)] = raw }); !forbidden(err) {
		t.Fatalf("adding a record beside one: %v", err)
	}
	if err := run(map[string]json.RawMessage{key: raw}, func(st *State) { delete(st.OIDC, key) }); err != nil {
		t.Fatalf("deleting a record is refused: %v", err)
	}
	if err := run(map[string]json.RawMessage{key: raw}, func(st *State) { st.OIDC["unrelated:x"] = other }); err != nil {
		t.Fatalf("an unrelated record beside an attestation is refused: %v", err)
	}
	// The error of the wrapped writer is its own.
	boom := errors.New("boom")
	if err := guardAttestations(func(*State) error { return boom })(&State{}); !errors.Is(err, boom) {
		t.Fatalf("the writer's own error was replaced: %v", err)
	}
}

// The attestation writer is on the non-authority allowlist, and its mask hides exactly its own
// records: a change to anything else would still bump AuthorityRevision.
func TestAttestationWriterIsNonAuthorityAndMaskedExactly(t *testing.T) {
	if _, keeps := nonAuthorityWriters[writerAttestControl]; !keeps {
		t.Fatal("writerAttestControl is not on the non-authority allowlist")
	}
	id := model.NewID()
	base := State{Installation: id, OIDC: map[string]json.RawMessage{"elevation:x": json.RawMessage(`{}`)}}
	with := State{Installation: id, OIDC: map[string]json.RawMessage{"elevation:x": json.RawMessage(`{}`), attestKey(1): json.RawMessage(`{"node":1}`)}}
	changed := State{Installation: id, OIDC: map[string]json.RawMessage{"elevation:x": json.RawMessage(`{"a":1}`)}}
	a, err := stateWithoutAttestations(&base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := stateWithoutAttestations(&with)
	if err != nil {
		t.Fatal(err)
	}
	c, err := stateWithoutAttestations(&changed)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("the mask does not hide an attestation record")
	}
	if string(a) == string(c) {
		t.Fatal("the mask hides a record that is not an attestation")
	}
	if len(with.OIDC) != 2 {
		t.Fatal("the mask mutated the state it encoded")
	}
}
