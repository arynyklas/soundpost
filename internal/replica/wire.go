// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"encoding/json"
	"soundpost/internal/model"
)

// The Go consensus primitive uses uint64. JSON boundaries decode through the
// owned canonical decimal scalar, rejecting numeric JSON and noncanonical forms.
type entryWire struct {
	ID            model.ID            `json:"id"`
	Kind          Kind                `json:"kind"`
	Payload       []byte              `json:"payload"`
	ReservationID *model.ID           `json:"reservation_id,omitempty"`
	Application   model.Uint64        `json:"application_index"`
	CommitSet     *CommitSetWatermark `json:"commit_set,omitempty"`
	Original      *model.Hash         `json:"original,omitempty"`
	Proposer      *Proposer           `json:"proposer,omitempty"`
}

func (w entryWire) entry() Entry {
	return Entry{ID: w.ID, Kind: w.Kind, Payload: w.Payload, ReservationID: w.ReservationID, ApplicationIndex: uint64(w.Application), CommitSet: w.CommitSet, Original: w.Original, Proposer: w.Proposer}
}

func (p *Proposer) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Node     model.Uint64 `json:"node"`
		Identity string       `json:"node_identity"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*p = Proposer{Node: uint64(wire.Node), Identity: wire.Identity}
	return nil
}

func (e *Entry) UnmarshalJSON(raw []byte) error {
	var wire entryWire
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*e = wire.entry()
	return nil
}

// decodeEntry is model.StrictJSON(data, &Entry) with one validation and one decode of data:
// Entry.UnmarshalJSON would validate and decode the same bytes again from inside the outer decode.
func decodeEntry(data []byte) (Entry, error) {
	var wire entryWire
	if model.StrictJSON(data, &wire) != nil {
		return Entry{}, ErrInvalid
	}
	return wire.entry(), nil
}

func (c *CommittedEntry) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Group       model.ID     `json:"group"`
		Term        model.Uint64 `json:"term"`
		Index       model.Uint64 `json:"index"`
		Application model.Cursor `json:"application_cursor"`
		Entry       Entry        `json:"entry"`
		Outcome     string       `json:"outcome,omitempty"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*c = CommittedEntry{Group: wire.Group, Term: uint64(wire.Term), Index: uint64(wire.Index), ApplicationCursor: wire.Application, Entry: wire.Entry, Outcome: wire.Outcome}
	return nil
}
func (f *FenceToken) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Group    model.ID       `json:"group"`
		Term     model.Uint64   `json:"term"`
		Revision model.Revision `json:"revision"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*f = FenceToken{Group: wire.Group, Term: uint64(wire.Term), Revision: wire.Revision}
	return nil
}
func (m *Member) UnmarshalJSON(raw []byte) error {
	var wire struct {
		ID       model.Uint64 `json:"id"`
		Address  string       `json:"address"`
		Identity string       `json:"node_identity"`
		Domain   string       `json:"failure_domain"`
		Learner  bool         `json:"learner,omitempty"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*m = Member{ID: uint64(wire.ID), Address: wire.Address, NodeIdentity: wire.Identity, FailureDomain: wire.Domain, Learner: wire.Learner}
	return nil
}
func (w *CommitSetWatermark) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Group       model.ID     `json:"group"`
		Term        model.Uint64 `json:"term"`
		Commit      model.Uint64 `json:"physical_commit"`
		Last        model.Uint64 `json:"physical_last"`
		Application model.Uint64 `json:"application_applied"`
		Reservation model.ID     `json:"reservation"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*w = CommitSetWatermark{Group: wire.Group, Term: uint64(wire.Term), PhysicalCommit: uint64(wire.Commit), PhysicalLast: uint64(wire.Last), ApplicationApplied: uint64(wire.Application), Reservation: wire.Reservation}
	return nil
}
func (r *readyRecord) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Group    model.ID     `json:"group"`
		Node     model.Uint64 `json:"node"`
		Members  Members      `json:"members"`
		Hard     []byte       `json:"hard,omitempty"`
		Snapshot []byte       `json:"snapshot,omitempty"`
		Entries  [][]byte     `json:"entries,omitempty"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*r = readyRecord{Group: wire.Group, Node: uint64(wire.Node), Members: wire.Members, Hard: wire.Hard, Snapshot: wire.Snapshot, Entries: wire.Entries}
	return nil
}
func (s *snapshotEnvelope) UnmarshalJSON(raw []byte) error {
	var wire struct {
		Application model.Uint64     `json:"application"`
		State       []byte           `json:"state"`
		Completed   []CommittedEntry `json:"completed"`
		Members     Members          `json:"members"`
		Retiring    []Member         `json:"retiring,omitempty"`
	}
	if model.StrictJSON(raw, &wire) != nil {
		return ErrInvalid
	}
	*s = snapshotEnvelope{Application: uint64(wire.Application), State: wire.State, Completed: wire.Completed, Members: wire.Members, Retiring: wire.Retiring}
	return nil
}

var _ json.Unmarshaler = (*Entry)(nil)
