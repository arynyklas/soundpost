// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/storage"
	"net/http"
)

func NewArtifactService(store *control.Store, authorizer *auth.Service, engine *storage.Engine) (*artifacts.Service, error) {
	return artifacts.New(engine, store, authorizer)
}
func (a *App) RegisterArtifactRoutes(mux *http.ServeMux) {
	httpapi.RegisterArtifactRoutes(mux, a.Auth, a.Artifacts)
}
