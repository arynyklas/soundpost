// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
)

// Audit wire timestamps and epochs never use JSON-number roundtrips. Correlation
// and outcome are stored boundary observations, never synthesized by encoding.
type auditWire struct {
	ID          ID           `json:"id"`
	Principal   ID           `json:"principal"`
	Action      string       `json:"action"`
	Reason      string       `json:"reason"`
	Time        UnixNano     `json:"time_ns"`
	Org         string       `json:"org"`
	RequestID   *ID          `json:"request_id,omitempty"`
	Outcome     AuditOutcome `json:"outcome"`
	PolicyEpoch Uint64       `json:"policy_epoch"`
	Targets     []ID         `json:"targets"`
}

func (a ControlAudit) MarshalJSON() ([]byte, error) {
	var requestID *ID
	if a.RequestID != (ID{}) {
		id := a.RequestID
		requestID = &id
	}
	return json.Marshal(auditWire{a.ID, a.Principal, a.Action, a.Reason, UnixNano(a.Time), a.Org, requestID, a.Outcome, Uint64(a.PolicyEpoch), a.Targets})
}
func (a *ControlAudit) UnmarshalJSON(raw []byte) error {
	var wire auditWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	*a = ControlAudit{ID: wire.ID, Principal: wire.Principal, Action: wire.Action, Reason: wire.Reason, Time: int64(wire.Time), Org: wire.Org, PolicyEpoch: uint64(wire.PolicyEpoch), Targets: wire.Targets, Outcome: wire.Outcome}
	if wire.RequestID != nil {
		a.RequestID = *wire.RequestID
	}
	return nil
}
