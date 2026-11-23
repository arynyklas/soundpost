// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/httpapi"
)

// registerListsConsole mounts the console lists of docs/operations/console-api.md section 5 that read stored
// records: error issues (control state, titles through the storage scan under the caller's telemetry.read),
// replays and profiles (chunk metadata through the storage scan, behind their own grants).
//
//	POST /api/v1/issues/list    POST /api/v1/replays/list    POST /api/v1/profiles/list
func (a *App) registerListsConsole(mux *http.ServeMux, cfg ConsoleConfig) {
	lists := httpapi.ConsoleListsConfig{State: a.Control, Scanner: a.Storage, Titles: httpapi.NewStorageErrorSource(a.Storage), Tickets: a.Cache}
	// The regressed filter reads the stored evaluations through the issue lifecycle; without it the filter says it is not available.
	if svc, err := a.NewIssueActions(releaseActionClock{}); err == nil {
		lists.Regressions = svc
	}
	httpapi.RegisterConsoleListRoutes(mux, a.Auth, httpapi.NewConsoleLists(lists))
}

// registerREDConsole mounts POST /api/v1/services/red (section 6): rate, errors and duration of one service
// computed from its stored spans through the storage scan.
func (a *App) registerREDConsole(mux *http.ServeMux, cfg ConsoleConfig) {
	httpapi.RegisterServiceREDRoute(mux, a.Auth, httpapi.NewServiceRED(a.Storage))
}
