// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Lifecycle effect intents (an issue regressed, ...) are committed with the
// change that caused them and stay in the project's issue book until a consumer
// has acted on them and acknowledges them. The book holds a bounded number of
// them, so a consumer that never acknowledges would eventually wedge the commits
// that mint new ones: acknowledging is part of the contract, not housekeeping.

// MaxEffectAck is the most effect intents one acknowledgement names.
const MaxEffectAck = 32

// PendingEffects returns the project's unacknowledged effect intents, oldest
// first. The scope must be admitted to the project's issue lifecycle.
func (s *ControlStore) PendingEffects(ctx context.Context, scope auth.Scope, project model.ID) ([]Effect, error) {
	snap, err := s.c.IssueBook(ctx, scope, project)
	if err != nil {
		return nil, err
	}
	out := make([]Effect, len(snap.Effects))
	for i, e := range snap.Effects {
		out[i] = Effect{ID: e.ID, Kind: e.Kind, IssueID: e.Issue, OccurrenceID: e.Occurrence}
	}
	return out, nil
}

// AckEffects acknowledges consumed effect intents in one control transaction:
// they leave the book. It is idempotent: an intent that is already gone is
// skipped, and the same acknowledgement retried changes nothing. It never
// touches issues, ledgers, checkpoints or the project revision, so it commutes
// with evidence commits and cannot lose a race against one.
func (s *ControlStore) AckEffects(ctx context.Context, scope auth.Scope, project model.ID, effects []model.ID) error {
	if len(effects) == 0 || len(effects) > MaxEffectAck {
		return model.Fail(model.Invalid)
	}
	raw, err := json.Marshal(control.IssueAck{Operation: control.IssueOpAck, Project: project, Ack: effects})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	_, err = s.c.TransactIssues(ctx, scope, control.Command{CommandID: control.IssueCommandID(raw), Kind: string(control.KindApplyIssueEvidence), Payload: raw})
	return err
}
