// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/httpapi"
)

// registerEntityConsole mounts the console routes that live with the incident service
// (docs/operations/console-api.md): the related-incident proposals of section 8. The Markdown copy
// routes are mounted by the GitLab group's own register function, not here.
func (a *App) registerEntityConsole(mux *http.ServeMux, _ ConsoleConfig) {
	httpapi.RegisterRelatedRoutes(mux, a.Auth, httpapi.NewRelated(a.Control))
}
