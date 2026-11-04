// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/releases"
	"time"
)

// NewReleaseService binds deterministic handlers on the same control Store used
// by auth/ingest. Reopening the app installs fresh per-store handlers over the
// durable leaf state; no feature state lives in this adapter.
func NewReleaseService(store *control.Store, authorizer *auth.Service) (*releases.Service, error) {
	if e := store.BindReleases(); e != nil {
		return nil, e
	}
	return releases.New(store, authorizer, releaseActionClock{})
}

type releaseActionClock struct{}

func (releaseActionClock) Now() model.UnixNano {
	return model.UnixNano(time.Now().UnixNano())
}
