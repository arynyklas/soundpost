// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/replays"
	"soundpost/internal/storage"
)

// NewReplayService binds the replay chain validator and authorized reader over
// the record engine, the auth service and the replicated control state. It keeps
// no state of its own: chunks live in storage, the immutable checkpoint index and
// retention groups in control settings. Admission must call its Validate before
// durable append and Record after it, and retention must consult it as a
// References source (see docs/protocol/replay-v1.md).
func NewReplayService(engine *storage.Engine, authorizer *auth.Service, store *control.Store) (*replays.Service, error) {
	return replays.New(engine, authorizer, store)
}
