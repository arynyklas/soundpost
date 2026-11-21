// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"net/http"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
)

// ProfileSetView is one registered feature set of a pinned profile: its
// identifier and exactly the features it enables.
type ProfileSetView struct {
	ID      string   `json:"id"`
	Enabled []string `json:"enabled"`
}

// ProfileRegistryEntry is one accepted pinned query profile as the browser
// selects it.
type ProfileRegistryEntry struct {
	ID       string `json:"id"`
	Language string `json:"language"`
	// Features is every feature any registered set of the profile enables, sorted.
	Features    []string         `json:"features"`
	FeatureSets []ProfileSetView `json:"feature_sets"`
}

// ProfileRegistryResponse is the GET /api/v1/query/profiles body.
type ProfileRegistryResponse struct {
	Profiles []ProfileRegistryEntry `json:"profiles"`
}

// registerProfiles serves GET /api/v1/query/profiles: the pinned C06 profile and
// feature-set registry the engine itself resolves requests against, so the
// console never carries a copy that can drift. It holds no tenant data and
// names no project, so any authenticated principal may read it; an
// unauthenticated caller gets the usual 401.
func registerProfiles(mux *http.ServeMux, authority *auth.Service, service QueryService) {
	mux.HandleFunc("GET /api/v1/query/profiles", func(w http.ResponseWriter, r *http.Request) {
		if _, err := readCredential(authority, r); err != nil {
			reply(w, nil, err)
			return
		}
		reply(w, profileRegistry(service), nil)
	})
}

// profileRegistry builds the response from the engine's registry.
func profileRegistry(service QueryService) ProfileRegistryResponse {
	out := ProfileRegistryResponse{Profiles: []ProfileRegistryEntry{}}
	for _, p := range service.Profiles() {
		entry := ProfileRegistryEntry{ID: p.ID, Language: strings.SplitN(p.ID, "-", 2)[0], Features: []string{}, FeatureSets: make([]ProfileSetView, 0, len(p.FeatureSets))}
		seen := map[string]bool{}
		for _, set := range p.FeatureSets {
			entry.FeatureSets = append(entry.FeatureSets, ProfileSetView{ID: set.ID, Enabled: append([]string{}, set.Enabled...)})
			for _, f := range set.Enabled {
				if !seen[f] {
					seen[f] = true
					entry.Features = append(entry.Features, f)
				}
			}
		}
		sort.Strings(entry.Features)
		out.Profiles = append(out.Profiles, entry)
	}
	return out
}
