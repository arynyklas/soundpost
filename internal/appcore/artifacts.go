// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"net/http"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/storage"
)

func NewArtifactService(store *control.Store, authorizer *auth.Service, engine *storage.Engine) (*artifacts.Service, error) {
	return artifacts.New(engine, store, authorizer)
}
func (a *App) RegisterArtifactRoutes(mux *http.ServeMux) {
	httpapi.RegisterArtifactRoutes(mux, a.Auth, a.Artifacts)
}
