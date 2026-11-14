// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/replays"
	"github.com/arynyklas/soundpost/internal/storage"
)

// NewReplayService binds the replay chain validator and authorized reader over
// the record engine, the auth service and the replicated control state. It keeps
// no state of its own: chunks live in storage, the immutable checkpoint index and
// retention groups in control settings. Admission runs the stateless closed-format
// check (ValidateChunk, installed on ingest as its replay gate) before the durable
// append, and NewReplayIndexingAppender runs CheckIndex before and RecordScope after
// it; retention consults the service as a References source (see
// docs/protocol/replay-v1.md).
func NewReplayService(engine *storage.Engine, authorizer *auth.Service, store *control.Store) (*replays.Service, error) {
	return replays.New(engine, authorizer, store)
}
