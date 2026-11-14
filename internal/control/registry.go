// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// Handler performs deterministic leaf-state transitions only: all random IDs,
// timestamps and network observations must already be present in Command.
// Registration is per authority; missing feature handlers fail unsupported.
type Handler func(auth.Scope, *State, Command) (Effect, error)
type Effect struct {
	AffectedIDs []model.ID
	Phase       string
}

func (k CommandKind) Valid() bool {
	switch k {
	case KindCreateOrg, KindGrant, KindPolicyChange, KindBeginFence, KindCompleteFence, KindReserveAdmission, KindFinalizeAdmission, KindApplyIssueEvidence, KindApplyCondition, KindApplyRuleEvaluation, KindIncidentAction, KindClaimDelivery, KindCompleteDelivery, KindDeleteScope, KindAudit, KindRegisterRelease, KindUpdateJob, KindRecordEvidenceGap:
		return true
	}
	return false
}
func (s *Store) RegisterHandler(kind CommandKind, handler Handler) error {
	if !kind.Valid() || kind == KindAudit || handler == nil {
		return model.Fail(model.Invalid)
	}
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	if s.handlers == nil {
		s.handlers = map[CommandKind]Handler{}
	}
	if _, exists := s.handlers[kind]; exists {
		return model.Fail(model.Conflict)
	}
	s.handlers[kind] = handler
	return nil
}
func (s *Store) handler(kind CommandKind) Handler {
	s.registryMu.RLock()
	defer s.registryMu.RUnlock()
	return s.handlers[kind]
}
