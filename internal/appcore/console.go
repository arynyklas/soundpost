// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"crypto/x509"
	"net/http"
	"net/netip"
)

// ConsoleConfig is the node's own environment of the console API
// (docs/operations/console-api.md).
type ConsoleConfig struct {
	// PublicOrigin is the https origin console links are built from; empty means the
	// node cannot state a link (the answers say public_origin_not_configured).
	PublicOrigin string
	// EgressAllow are the private prefixes an administrator allowed for outbound
	// requests (the notification delivery's --notify-egress-allow); the GitLab
	// integration follows the same egress rules as every webhook.
	EgressAllow []netip.Prefix
	// RootCAs are extra trust roots for outbound TLS (the system roots when nil).
	RootCAs *x509.CertPool
}

// RegisterConsole mounts the console API routes of docs/operations/console-api.md next
// to the routes of Register. It is a separate method (not part of Register) so the
// serving command passes the node's environment. Each group lives in its own file and
// is called from here.
func (a *App) RegisterConsole(mux *http.ServeMux, cfg ConsoleConfig) {
	a.registerEntityConsole(mux, cfg)    // related incidents
	a.registerDirectoryConsole(mux, cfg) // display names
	a.registerDeployConsole(mux, cfg)    // deploy markers, release list
	a.registerListsConsole(mux, cfg)     // issue, replay and profile lists
	a.registerREDConsole(mux, cfg)       // service RED metrics
	a.registerEventsConsole(mux, cfg)    // event webhook endpoints
	a.registerGitLabConsole(mux, cfg)    // markdown copy, GitLab settings and create
	_ = cfg
	_ = mux
	_ = a
}
