// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestCapabilitiesRevealNoMetadataOutsideCallerScope: GET /api/v1/capabilities
// answers for the one project the caller's grant covers and for nothing else.
// A project of the same organization the caller may not read, a project of
// another organization and a project that does not exist deny with the same
// bytes, and no body ever carries another project's source, service,
// environment or build identifiers, or any count of hidden sources.
func TestCapabilitiesRevealNoMetadataOutsideCallerScope(t *testing.T) {
	e := newIsoEnv(t)
	mine, theirs, absent := model.NewID(), model.NewID(), model.NewID()
	org := e.org("capabilities org", mine, theirs)
	otherProject := model.NewID()
	other := e.org("other capabilities org", otherProject)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, mine, true, auth.Read)
	ownIDs := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	hiddenIDs := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	foreignIDs := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	own := e.source(org, mine, ownIDs, []model.Kind{model.Metric})
	hiddenA := e.source(org, theirs, hiddenIDs, []model.Kind{model.Metric, model.Log})
	hiddenB := e.source(org, theirs, hiddenIDs, []model.Kind{model.Metric})
	foreign := e.source(other, otherProject, foreignIDs, []model.Kind{model.Metric})

	call := func(org, project model.ID) (int, []byte) {
		status, raw, _ := e.call(alice, "GET", "/api/v1/capabilities?org="+org.String()+"&project="+project.String(), nil)
		return status, raw
	}
	status, raw := call(org, mine)
	var caps struct {
		Sources []auth.VisibleSource `json:"sources"`
	}
	if status != 200 || json.Unmarshal(raw, &caps) != nil || len(caps.Sources) != 1 || caps.Sources[0].ID != own.ID || caps.Sources[0].Project != mine {
		t.Fatalf("own project: %d %s", status, raw)
	}
	for name, id := range map[string]model.ID{"hidden source": hiddenA.ID, "second hidden source": hiddenB.ID, "foreign source": foreign.ID, "hidden project": theirs, "foreign org": other, "foreign project": otherProject,
		"hidden service": hiddenIDs.Service, "hidden environment": hiddenIDs.Environment, "hidden build": hiddenIDs.Build, "foreign service": foreignIDs.Service, "foreign environment": foreignIDs.Environment, "foreign build": foreignIDs.Build} {
		if bytes.Contains(raw, []byte(id.String())) {
			t.Fatalf("own-project capabilities carry the %s identifier: %s", name, raw)
		}
	}
	for _, key := range []string{`"services"`, `"environments"`, `"builds"`, `"dependencies"`, `"resources"`, `"count"`, `"total"`} {
		if bytes.Contains(raw, []byte(key)) {
			t.Fatalf("capabilities carry resource metadata %s: %s", key, raw)
		}
	}

	// Every project outside the grant denies identically, whatever it holds.
	want := ""
	for name, c := range map[string]struct{ org, project model.ID }{
		"unreadable project of my organization":  {org, theirs},
		"project of another organization":        {other, otherProject},
		"my project in another organization":     {other, mine},
		"another organization's project in mine": {org, otherProject},
		"nonexistent project":                    {org, absent},
	} {
		status, raw := call(c.org, c.project)
		if status != 404 {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		got := denial(t, status, raw)
		if want == "" {
			want = got
		} else if got != want {
			t.Fatalf("%s is distinguishable from the other denials: %q vs %q", name, got, want)
		}
	}
}
