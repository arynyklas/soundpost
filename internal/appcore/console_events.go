// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"net/http"

	"github.com/arynyklas/soundpost/internal/httpapi"
)

// registerEventsConsole mounts POST /api/v1/events/webhooks: the organization
// administrator's list, save, test and deliveries of event webhook endpoints
// (docs/operations/console-api.md section 9). The events themselves are produced by
// EventProducer under the leader lease and delivered by the notification outbox.
func (a *App) registerEventsConsole(mux *http.ServeMux, _ ConsoleConfig) {
	webhooks, err := httpapi.NewEventWebhooks(a.Auth, a.Control, a.Control, systemWorkerClock{})
	if err != nil {
		panic("appcore: event webhook routes need the control store and the authority")
	}
	httpapi.RegisterEventWebhookRoutes(mux, a.Auth, webhooks)
}
