// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// A served node commits the definition an author posted over
// POST /api/v1/jobs/definitions to control state, and the node's JobCatalogue
// (what the observer stage reads) lists it to the runner's read scope with the
// definition as saved; a retired job is listed as retired and a project the
// runner is not scoped to lists nothing.
func TestServedNodeJobCatalogueSavesOverTheRouteAndListsToTheRunner(t *testing.T) {
	n := newWorkerNode(t)
	n.command("grant", auth.AdminPayload{UserID: n.user, ProjectID: n.project, Permissions: []string{string(auth.Read), string(auth.PolicyWrite)}, Enabled: true})
	session, err := n.app.Auth.Login(n.ctx, "workers@example.test", "worker wiring password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(httpapi.NewServer("", n.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterPolicyRoutes(mux, n.app.Auth, n.app.Policies)
	}).Handler)
	t.Cleanup(srv.Close)
	post := func(body httpapi.JobDefinitionRequest) (int, []byte) {
		t.Helper()
		fields := map[string]any{"org": body.Org, "project_id": body.Project, "operation": body.Operation}
		if body.CommandID != (model.ID{}) {
			fields["command_id"] = body.CommandID
		}
		if body.JobID != (model.ID{}) {
			fields["job_id"] = body.JobID
		}
		if body.ExpectedRevision != nil {
			fields["expected_revision"] = body.ExpectedRevision
		}
		if body.Reason != "" {
			fields["reason"] = body.Reason
		}
		if body.Definition != nil {
			fields["definition"] = body.Definition
		}
		raw, _ := json.Marshal(fields)
		req, _ := http.NewRequest("POST", srv.URL+"/api/v1/jobs/definitions", bytes.NewReader(raw))
		req.Header.Set("Cookie", "__Host-soundpost="+session.Token)
		req.Header.Set("X-CSRF-Token", session.CSRF)
		req.Header.Set("Origin", srv.URL)
		req.Header.Set("Content-Type", "application/json")
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, out
	}
	catalogue, err := n.app.JobCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := n.app.Auth.AuthorizeSystem(n.ctx, n.org, []model.ID{n.project}, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := catalogue.List(n.ctx, runner, n.project); err != nil || len(got) != 0 {
		t.Fatalf("an empty catalogue lists %+v %v", got, err)
	}

	job, effective := model.NewID(), model.UnixNano(time.Now().Add(-time.Hour).UnixNano())
	expected := model.Uint64(0)
	def := jobs.Definition{Revision: 1, EffectiveFrom: effective, Schedule: &jobs.Schedule{Cron: "*/5 * * * *", Timezone: "UTC"}, Grace: jobs.Duration(2 * time.Minute)}
	status, raw := post(httpapi.JobDefinitionRequest{Org: n.org, Project: n.project, Operation: httpapi.JobDefinitionSave, CommandID: model.NewID(), JobID: job, ExpectedRevision: &expected, Reason: "served e2e", Definition: &def})
	if status != http.StatusOK {
		t.Fatalf("save over the route: %d %s", status, raw)
	}
	got, err := catalogue.List(n.ctx, runner, n.project)
	if err != nil || len(got) != 1 || got[0].Job != job || got[0].Retired || got[0].Revision != 1 || got[0].Definition.Revision != 1 ||
		got[0].Definition.EffectiveFrom != effective || got[0].Definition.Schedule == nil || got[0].Definition.Schedule.Cron != "*/5 * * * *" || got[0].Definition.Grace != jobs.Duration(2*time.Minute) {
		t.Fatalf("the runner lists %+v %v", got, err)
	}
	var list httpapi.JobDefinitionListAnswer
	status, raw = post(httpapi.JobDefinitionRequest{Org: n.org, Project: n.project, Operation: httpapi.JobDefinitionList})
	if err = json.Unmarshal(raw, &list); err != nil || status != http.StatusOK || !list.CanAuthor || len(list.Jobs) != 1 || list.Jobs[0].JobID != job {
		t.Fatalf("list over the route: %d %v %s", status, err, raw)
	}

	one := model.Uint64(1)
	status, raw = post(httpapi.JobDefinitionRequest{Org: n.org, Project: n.project, Operation: httpapi.JobDefinitionRetire, CommandID: model.NewID(), JobID: job, ExpectedRevision: &one, Reason: "served e2e retire"})
	if status != http.StatusOK {
		t.Fatalf("retire over the route: %d %s", status, raw)
	}
	if got, err = catalogue.List(n.ctx, runner, n.project); err != nil || len(got) != 1 || !got[0].Retired || got[0].Definition.Revision != 1 {
		t.Fatalf("the runner lists after the retirement %+v %v", got, err)
	}

	// The runner is never an author: it holds the read scope the catalogue lists to.
	if _, err = catalogue.Save(n.ctx, runner, jobs.SaveCommand{CommandID: model.NewID(), Project: n.project, Job: model.NewID(), Definition: jobs.Definition{Revision: 1, EffectiveFrom: effective}, Reason: "runner"}); err == nil {
		t.Fatal("the runner saved a definition")
	}
	other := model.NewID()
	n.addProject(other)
	if got, err = catalogue.List(n.ctx, runner, other); err == nil {
		t.Fatalf("the runner listed a project it is not scoped to: %+v", got)
	}
}
