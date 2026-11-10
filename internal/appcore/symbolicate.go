// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
)

// NewSymbolicator composes the real protected artifact reader with explicitly
// selected operator sandbox configuration and the retention service's delete
// generation, which every warm map entry is bound to. No shared App field or
// route is introduced, and no source credential is promoted to read authority.
func (a *App) NewSymbolicator(config symbolicate.Config) (*symbolicate.Service, error) {
	if a == nil || a.Artifacts == nil || a.Retention == nil {
		return nil, model.Fail(model.Unavailable)
	}
	return symbolicate.New(a.Artifacts, a.Retention, config)
}
