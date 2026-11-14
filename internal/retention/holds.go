// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// HoldRequest places a legal hold. An active hold blocks Begin (receipt phase
// held) and makes physical-erasure success impossible for the data it covers.
type HoldRequest struct {
	CommandID        model.ID       `json:"command_id"`
	ExpectedRevision model.Revision `json:"expected_revision"`
	ProjectIDs       []model.ID     `json:"project_ids,omitempty"`
	Signals          []model.Kind   `json:"signals,omitempty"`
	Start            model.UnixNano `json:"start_ns,omitempty"`
	End              model.UnixNano `json:"end_ns,omitempty"`
	EntityIDs        []model.ID     `json:"entity_ids,omitempty"`
	Reason           string         `json:"reason"`
}

// PlaceHold records a hold; its ID is the command ID.
func (s *Service) PlaceHold(ctx context.Context, scope auth.Scope, r HoldRequest) (model.ID, error) {
	payload, err := json.Marshal(control.PolicyChange{Kind: "hold_place", Hold: &control.PlaceHold{Projects: r.ProjectIDs, Signals: r.Signals, Start: r.Start, End: r.End, Entities: r.EntityIDs, Reason: r.Reason, At: s.now()}})
	if err != nil {
		return model.ID{}, model.Fail(model.Invalid)
	}
	_, err = s.cfg.Control.Transact(ctx, scope, control.Command{CommandID: r.CommandID, ExpectedRevision: r.ExpectedRevision, Kind: string(control.KindPolicyChange), Payload: payload})
	return r.CommandID, err
}

// ReleaseHold releases a hold. Held deletions are not started implicitly (use
// Resume); blocked physical erasure proceeds on the next worker pass, which
// advances the delete generation before it erases.
func (s *Service) ReleaseHold(ctx context.Context, scope auth.Scope, command model.ID, expected model.Revision, hold model.ID, reason string) error {
	payload, err := json.Marshal(control.PolicyChange{Kind: "hold_release", Release: &control.ReleaseHold{Hold: hold, Reason: reason, At: s.now()}})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	_, err = s.cfg.Control.Transact(ctx, scope, control.Command{CommandID: command, ExpectedRevision: expected, Kind: string(control.KindPolicyChange), Payload: payload})
	return err
}
