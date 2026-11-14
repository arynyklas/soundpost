// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"bytes"
	"context"
	"encoding/json"
	"unicode"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Control is the consumer-owned view of the C05 control authority the lifecycle
// ledger needs; *control.Store implements it. The control handler is installed
// by control.Store.BindReleases (it routes the lifecycle arms of
// KindApplyIssueEvidence), which composition already runs.
type Control interface {
	TransactIssues(ctx context.Context, scope auth.Scope, cmd control.Command) (control.Result, error)
	IssueBook(ctx context.Context, scope auth.Scope, project model.ID) (control.IssueSnapshot, error)
}

// ControlStore is the durable Store over the control group: one project's issues
// are the shared grouping issue records, everything else lives in the project's
// issue book, and every Commit is one control transaction.
type ControlStore struct{ c Control }

var _ Store = (*ControlStore)(nil)

func NewControlStore(c Control) (*ControlStore, error) {
	if c == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &ControlStore{c: c}, nil
}

// storedExplanation is the closed JSON form of an Explanation. The evidence
// release is a pointer because an occurrence without a release has none (a zero
// ID has no JSON form). It carries IDs, times, counts and the stable decision
// reason, never evidence text.
type storedExplanation struct {
	OccurrenceID    model.ID       `json:"occurrence_id"`
	EvidenceRelease *model.ID      `json:"evidence_release,omitempty"`
	EventTime       model.UnixNano `json:"event_time_ns"`
	Eligible        bool           `json:"eligible"`
	Reason          string         `json:"reason"`
	Frontier        []model.ID     `json:"frontier,omitempty"`
	AncestryKnown   bool           `json:"ancestry_known"`
	ResolutionTime  model.UnixNano `json:"resolution_time_ns"`
	Threshold       uint32         `json:"threshold"`
	Window          model.UnixNano `json:"window_ns"`
	Qualifying      int            `json:"qualifying"`
	Reopened        bool           `json:"reopened"`
}

const maxExplanationReason = 256

func encodeExplanations(list []Explanation) (json.RawMessage, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]storedExplanation, len(list))
	for i, x := range list {
		if len(x.Decision.Reason) > maxExplanationReason || !utf8.ValidString(x.Decision.Reason) || x.OccurrenceID == (model.ID{}) {
			return nil, model.Fail(model.Invalid)
		}
		for _, r := range x.Decision.Reason {
			if unicode.IsControl(r) {
				return nil, model.Fail(model.Invalid)
			}
		}
		s := storedExplanation{OccurrenceID: x.OccurrenceID, EventTime: x.EventTime, Eligible: x.Decision.Eligible, Reason: x.Decision.Reason,
			Frontier: append([]model.ID(nil), x.Decision.Frontier...), AncestryKnown: x.Decision.AncestryKnown, ResolutionTime: x.ResolutionTime,
			Threshold: x.Threshold, Window: x.Window, Qualifying: x.Qualifying, Reopened: x.Reopened}
		if x.EvidenceRelease != (model.ID{}) {
			release := x.EvidenceRelease
			s.EvidenceRelease = &release
		}
		out[i] = s
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	return raw, nil
}

func decodeExplanations(raw json.RawMessage) ([]Explanation, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var stored []storedExplanation
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&stored) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	out := make([]Explanation, len(stored))
	for i, s := range stored {
		x := Explanation{OccurrenceID: s.OccurrenceID, EventTime: s.EventTime, ResolutionTime: s.ResolutionTime, Threshold: s.Threshold, Window: s.Window, Qualifying: s.Qualifying, Reopened: s.Reopened,
			Decision: RegressionDecision{Eligible: s.Eligible, Reason: s.Reason, Frontier: append([]model.ID(nil), s.Frontier...), AncestryKnown: s.AncestryKnown}}
		if s.EvidenceRelease != nil {
			x.EvidenceRelease = *s.EvidenceRelease
		}
		out[i] = x
	}
	return out, nil
}

// Load returns the project's committed state as a private snapshot. The
// occurrence index is derived from the immutable ledgers, so it can never
// disagree with them.
func (s *ControlStore) Load(ctx context.Context, scope auth.Scope, project model.ID) (State, error) {
	snap, err := s.c.IssueBook(ctx, scope, project)
	if err != nil {
		return State{}, err
	}
	out := State{Revision: snap.Revision, Issues: make(map[model.ID]Record, len(snap.Issues)), Occurrences: map[model.ID]model.ID{}, Checkpoints: snap.Checkpoints, Commands: map[model.ID]CommandRecord{}, Gaps: snap.Gaps}
	if out.Checkpoints == nil {
		out.Checkpoints = map[model.ID]model.Uint64{}
	}
	for _, gi := range snap.Issues {
		explanations, err := decodeExplanations(snap.Explanations[gi.ID])
		if err != nil {
			return State{}, err
		}
		out.Issues[gi.ID] = Record{Issue: gi, Explanations: explanations}
		for _, list := range [][]Evidence{gi.Occurrences, gi.LateHistory} {
			for _, e := range list {
				if _, dup := out.Occurrences[e.OccurrenceID]; dup {
					return State{}, model.Fail(model.Corrupt)
				}
				out.Occurrences[e.OccurrenceID] = gi.ID
			}
		}
	}
	for id, entry := range snap.Commands {
		if entry.Action != nil {
			out.Commands[id] = CommandRecord{Fingerprint: entry.Action.Fingerprint, IssueID: entry.Action.Issue}
		}
	}
	return out, nil
}

// Commit applies every part of c as one control transaction, with the project
// revision as the compare-and-set token. A lost race is the control fault with
// code Conflict whose detail carries the current revision (ConflictRevision). A
// commit with a command ID is exactly-once: retried, it returns nil and changes
// nothing; the same ID with other content is a Conflict. A commit without one
// (evidence applied through a cursor) is identified by its content, so an
// identical retry is likewise recognized after the ledger has moved on.
func (s *ControlStore) Commit(ctx context.Context, scope auth.Scope, project model.ID, c Commit) error {
	payload := control.IssueCommand{Operation: "commit", Project: project, ExpectedRevision: c.ExpectedRevision, Audits: c.Audits}
	held := map[model.ID]map[model.ID]bool{}
	for _, r := range c.Records {
		explanations, err := encodeExplanations(r.Explanations)
		if err != nil {
			return err
		}
		payload.Records = append(payload.Records, control.IssueRecordChange{Issue: r.Issue, Explanations: explanations})
		ledger := map[model.ID]bool{}
		for _, list := range [][]Evidence{r.Issue.Occurrences, r.Issue.LateHistory} {
			for _, e := range list {
				ledger[e.OccurrenceID] = true
			}
		}
		held[r.Issue.ID] = ledger
	}
	// The occurrence index is derived on read; a claim the issue's own ledger does
	// not back is a caller bug that must not be silently dropped.
	for occurrence, issue := range c.Occurrences {
		if !held[issue][occurrence] {
			return model.Fail(model.Invalid)
		}
	}
	for _, e := range c.Effects {
		payload.Effects = append(payload.Effects, control.IssueEffect{ID: e.ID, Kind: e.Kind, Issue: e.IssueID, Occurrence: e.OccurrenceID})
	}
	if c.Checkpoint != nil {
		payload.Checkpoint = &control.IssueCheckpoint{Group: c.Checkpoint.Group, Index: c.Checkpoint.Index}
	}
	if c.Command != nil {
		if c.CommandID == (model.ID{}) {
			return model.Fail(model.Invalid)
		}
		payload.Action = &control.IssueActionRecord{Fingerprint: model.Hash(c.Command.Fingerprint), Issue: c.Command.IssueID}
	}
	if c.Gap != nil {
		gap := *c.Gap
		gap.Signals = append([]model.Kind(nil), c.Gap.Signals...)
		payload.Gap = &gap
	}
	if c.CommandID != (model.ID{}) {
		id := c.CommandID
		payload.Command = &id
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	id := control.IssueCommandID(raw)
	if payload.Command != nil {
		id = *payload.Command
	}
	_, err = s.c.TransactIssues(ctx, scope, control.Command{CommandID: id, Kind: string(control.KindApplyIssueEvidence), Payload: raw})
	return err
}

// ConflictRevision returns the current project revision carried by a Commit that
// lost a revision race, so a caller can tell a stale revision from another
// conflict (a reused command ID, a regressing checkpoint).
func ConflictRevision(err error) (model.Revision, bool) { return control.IssueConflictRevision(err) }
