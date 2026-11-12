// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
)

// ScrapeTargetState is one target's health as the route consumes it. The serve
// command builds it from sources.ScrapeTargetStatus (httpapi cannot import
// sources: appcore imports httpapi and sources' tests import appcore). Health,
// Reason and Coverage are the closed vocabularies of package sources.
type ScrapeTargetState struct {
	Alias         string
	Project       model.ID
	LastAttempt   time.Time
	Cycles        uint64
	Health        string
	HTTPStatus    int
	Reason        string
	Coverage      string
	Samples       uint64
	StaleMarkers  uint64
	AdmitFailures uint64
}

// ScrapeStatusSource is what the route reads: in production an adapter over the
// node's *sources.ScrapeHost. It is read-only.
type ScrapeStatusSource interface {
	ScrapeTargets() []ScrapeTargetState
}

// ScrapeTargetView is one target as the route answers it. Every field is an
// operator alias, a count, a time or a member of a closed vocabulary: no URL,
// secret reference or secret, header, response body or transport error text,
// and no project or source identifier, is in it or in anything it is built from.
type ScrapeTargetView struct {
	Alias         string     `json:"alias"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	Cycles        uint64     `json:"cycles"`
	// Health is the typed outcome of the last fetch (sources.ScrapeStatus);
	// empty before any fetch completed.
	Health     string `json:"health"`
	HTTPStatus int    `json:"http_status,omitempty"`
	// Reason is the typed reason the last cycle did not complete
	// (sources.ScrapeReason); empty when it scraped and admitted.
	Reason        string `json:"reason"`
	Coverage      string `json:"coverage"`
	Samples       uint64 `json:"samples"`
	StaleMarkers  uint64 `json:"stale_markers"`
	AdmitFailures uint64 `json:"admit_failures"`
}

// ScrapeTargetsView is the body of GET /api/v1/admin/scrape/targets.
type ScrapeTargetsView struct {
	Targets []ScrapeTargetView `json:"targets"`
}

// RegisterScrapeStatusRoutes serves GET /api/v1/admin/scrape/targets?org=ID: the
// health of the scrape targets that admit into projects of that organization.
// Only an administrator of that organization may read it; any other caller
// (member, administrator of another organization, absent or malformed
// organization) gets the same not-found, answered before the host is read.
func RegisterScrapeStatusRoutes(mux *http.ServeMux, authority *auth.Service, directory Directory, host ScrapeStatusSource) {
	mux.HandleFunc("GET /api/v1/admin/scrape/targets", func(w http.ResponseWriter, r *http.Request) {
		credential, err := readCredential(authority, r)
		if err != nil {
			reply(w, nil, err)
			return
		}
		q := r.URL.Query()
		if !onlyKeys(q, "org") {
			reply(w, nil, model.Fail(model.Invalid))
			return
		}
		org, err := model.ParseID(q.Get("org"))
		if err != nil {
			reply(w, nil, model.Fail(model.NotFound))
			return
		}
		scope, err := authority.Authorize(r.Context(), credential, org, nil, auth.OrgAdmin)
		if err != nil {
			reply(w, nil, err)
			return
		}
		var projects map[string]string
		err = directory.View(r.Context(), func(st control.State) error {
			o, ok := st.Orgs[org.String()]
			if !ok {
				return model.Fail(model.NotFound)
			}
			projects = o.Projects
			return nil
		})
		if err != nil {
			reply(w, nil, err)
			return
		}
		out := ScrapeTargetsView{Targets: []ScrapeTargetView{}}
		for _, t := range host.ScrapeTargets() {
			if _, ok := projects[t.Project.String()]; !ok {
				continue
			}
			v := ScrapeTargetView{
				Alias: t.Alias, Cycles: t.Cycles, Health: t.Health, HTTPStatus: t.HTTPStatus, Reason: t.Reason,
				Coverage: t.Coverage, Samples: t.Samples, StaleMarkers: t.StaleMarkers, AdmitFailures: t.AdmitFailures,
			}
			if !t.LastAttempt.IsZero() {
				at := t.LastAttempt.UTC()
				v.LastAttemptAt = &at
			}
			out.Targets = append(out.Targets, v)
		}
		// The org admin's authority must still hold after the read.
		if err := authority.Revalidate(r.Context(), scope); err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, out, nil)
	})
}
