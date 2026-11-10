// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"errors"
	"soundpost/internal/model"
	"time"
)

// Service validates, indexes and reads replay chunks. It owns no durable state
// of its own: chunks live in the record store, the immutable checkpoint index
// and retention groups in the replicated control state.
type Service struct {
	scanner    ReplayScanner
	authorizer ScopeAuthorizer
	control    ReferenceStore
	now        func() time.Time
}

// New requires all three dependencies.
func New(scanner ReplayScanner, authorizer ScopeAuthorizer, control ReferenceStore) (*Service, error) {
	if scanner == nil || authorizer == nil || control == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{scanner: scanner, authorizer: authorizer, control: control, now: time.Now}, nil
}

func faultCode(err error) model.Code {
	var f *model.Fault
	if errors.As(err, &f) {
		return f.Code
	}
	return ""
}

// transient is a failure that says nothing about authorization or existence.
func transient(err error) bool {
	switch faultCode(err) {
	case model.Unavailable, model.Timeout, model.Cancelled:
		return true
	}
	return errors.Is(err, errContextDone)
}
