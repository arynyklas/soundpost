// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

func (e *queryEnv) get(who person, path string) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.server.URL+path, nil)
	if who.Session.Token != "" {
		req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	}
	req.Header.Set("Origin", e.server.URL)
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// TestProfileRegistryRouteServesExactlyTheCommittedRegistry: the console reads
// the pinned profile and feature-set registry from the server. The expected
// values come from the committed profiles/query/*.json files themselves (read
// here, not from the engine), so a registry that dropped a set, reordered the
// sets, invented a feature, listed an unaccepted profile or leaked profile
// configuration fails. An unauthenticated caller learns nothing.
func TestProfileRegistryRouteServesExactlyTheCommittedRegistry(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	project := model.NewID()
	org := e.org("profiles org", project)
	// A member with no grant at all: the registry holds no tenant data.
	nobody := e.user(org, "nobody@example.test")

	status, raw := e.get(nobody, "/api/v1/query/profiles")
	if status != 200 {
		t.Fatalf("registry read: %d %s", status, raw)
	}
	var got httpapi.ProfileRegistryResponse
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}

	files, err := filepath.Glob("../../profiles/query/*.json")
	if err != nil || len(files) < 3 {
		t.Fatalf("committed profiles: %v %v", files, err)
	}
	sort.Strings(files)
	if len(got.Profiles) != len(files) {
		t.Fatalf("%d profiles served, %d committed", len(got.Profiles), len(files))
	}
	for i, file := range files {
		committed, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var want struct {
			ID          string `json:"id"`
			FeatureSets []struct {
				ID      string   `json:"id"`
				Enabled []string `json:"enabled"`
			} `json:"feature_sets"`
		}
		if err := json.Unmarshal(committed, &want); err != nil {
			t.Fatal(err)
		}
		p := got.Profiles[i]
		if p.ID != want.ID {
			t.Fatalf("profile %d is %s, want %s (ordered by identifier)", i, p.ID, want.ID)
		}
		if wantLanguage := strings.SplitN(want.ID, "-", 2)[0]; p.Language != wantLanguage {
			t.Fatalf("%s language %q, want %q", p.ID, p.Language, wantLanguage)
		}
		if len(p.FeatureSets) != len(want.FeatureSets) {
			t.Fatalf("%s serves %d feature sets, %d committed", p.ID, len(p.FeatureSets), len(want.FeatureSets))
		}
		union := map[string]bool{}
		for j, set := range want.FeatureSets {
			served := p.FeatureSets[j]
			if served.ID != set.ID || !reflect.DeepEqual(append([]string{}, served.Enabled...), append([]string{}, set.Enabled...)) {
				t.Fatalf("%s set %d: %+v, committed %+v", p.ID, j, served, set)
			}
			for _, f := range set.Enabled {
				union[f] = true
			}
		}
		var features []string
		for f := range union {
			features = append(features, f)
		}
		sort.Strings(features)
		if features == nil {
			features = []string{}
		}
		if !reflect.DeepEqual(p.Features, features) {
			t.Fatalf("%s features %v, want the sorted union %v", p.ID, p.Features, features)
		}
	}
	for _, leak := range []string{`"configuration"`, `"commit"`, `"obligations"`, `"manifest_version"`} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("registry body carries %s", leak)
		}
	}

	// No credential: the same typed refusal as every protected read, and no registry bytes.
	status, raw = e.get(person{}, "/api/v1/query/profiles")
	if status != 401 || strings.Contains(string(raw), "promql-prometheus") {
		t.Fatalf("unauthenticated read: %d %s", status, raw)
	}
}
