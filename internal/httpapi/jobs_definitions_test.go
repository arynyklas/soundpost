// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
)

// jobDefEnv serves POST /api/v1/jobs/definitions over the real control store and auth.
type jobDefEnv struct {
	*isoEnv
	srv *httptest.Server
}

func newJobDefEnv(t *testing.T) *jobDefEnv {
	t.Helper()
	e := &jobDefEnv{isoEnv: newIsoEnv(t)}
	policies, err := httpapi.NewPolicies(e.app.Control)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", e.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterPolicyRoutes(mux, e.app.Auth, policies)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

// jobDefWire is a request as a client sends it: only the fields the request
// sets (a zero model.ID has no wire form at all).
func jobDefWire(b httpapi.JobDefinitionRequest) map[string]any {
	fields := map[string]any{"org": b.Org, "project_id": b.Project, "operation": b.Operation}
	if b.CommandID != (model.ID{}) {
		fields["command_id"] = b.CommandID
	}
	if b.JobID != (model.ID{}) {
		fields["job_id"] = b.JobID
	}
	if b.ExpectedRevision != nil {
		fields["expected_revision"] = b.ExpectedRevision
	}
	if b.Reason != "" {
		fields["reason"] = b.Reason
	}
	if b.Definition != nil {
		fields["definition"] = b.Definition
	}
	return fields
}

func (e *jobDefEnv) post(who person, body any) (int, []byte) {
	e.t.Helper()
	if b, isReq := body.(httpapi.JobDefinitionRequest); isReq {
		body = jobDefWire(b)
	}
	raw, ok := body.([]byte)
	if !ok {
		raw, _ = json.Marshal(body)
	}
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/jobs/definitions", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (e *jobDefEnv) audits(org model.ID) int {
	e.t.Helper()
	n := 0
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "jobs.") && a.Org == org.String() {
				n++
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *jobDefEnv) definitions(org model.ID) int {
	e.t.Helper()
	n := 0
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for k := range st.JobDefinitions {
			if strings.HasPrefix(k, org.String()+":") {
				n++
			}
		}
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func jobDefSaveBody(org, project, command, job model.ID, expected uint64, def jobs.Definition) httpapi.JobDefinitionRequest {
	rev := model.Uint64(expected)
	return httpapi.JobDefinitionRequest{Org: org, Project: project, Operation: httpapi.JobDefinitionSave, CommandID: command, JobID: job, ExpectedRevision: &rev, Reason: "author the schedule", Definition: &def}
}

func jobDefRetireBody(org, project, command, job model.ID, expected uint64) httpapi.JobDefinitionRequest {
	rev := model.Uint64(expected)
	return httpapi.JobDefinitionRequest{Org: org, Project: project, Operation: httpapi.JobDefinitionRetire, CommandID: command, JobID: job, ExpectedRevision: &rev, Reason: "stop the schedule"}
}

func jobDefListBody(org, project model.ID) httpapi.JobDefinitionRequest {
	return httpapi.JobDefinitionRequest{Org: org, Project: project, Operation: httpapi.JobDefinitionList}
}

func jobDef(revision uint64, effective int64, cron string) jobs.Definition {
	return jobs.Definition{Revision: model.Uint64(revision), EffectiveFrom: model.UnixNano(effective), Schedule: &jobs.Schedule{Cron: cron, Timezone: "UTC"}}
}

type jobDefParties struct {
	org, project          model.ID
	writer, reader, wOnly person
	outsider              person
}

func (e *jobDefEnv) parties(name string) jobDefParties {
	p := jobDefParties{org: model.ID{}, project: model.NewID()}
	p.org = e.org(name, p.project)
	p.writer = e.user(p.org, name+"-writer@example.test")
	e.grant(p.org, p.writer, p.project, true, auth.Read, auth.PolicyWrite)
	p.reader = e.user(p.org, name+"-reader@example.test")
	e.grant(p.org, p.reader, p.project, true, auth.Read)
	p.wOnly = e.user(p.org, name+"-wonly@example.test")
	e.grant(p.org, p.wOnly, p.project, true, auth.PolicyWrite)
	other := model.NewID()
	otherOrg := e.org(name+" other", other)
	p.outsider = e.user(otherOrg, name+"-outsider@example.test")
	e.grant(otherOrg, p.outsider, other, true, auth.Read, auth.PolicyWrite)
	return p
}

// The route: a policy.write member saves a definition (catalogue revision 1,
// definition revision 1), the next one from the revision it read, a stale author
// loses, a replay of the latest command commits once, a schedule that does not
// parse is refused and leaves nothing, a retirement keeps the record and a save
// brings it back; the list shows each job with both revisions, and every commit
// is audited with the reason, never the schedule.
func TestJobDefinitionRouteSaveListRetire(t *testing.T) {
	e := newJobDefEnv(t)
	p := e.parties("jobdef route")
	job, first := model.NewID(), model.NewID()
	eff := time.Now().Add(-time.Hour).UnixNano()

	status, raw := e.post(p.writer, jobDefSaveBody(p.org, p.project, first, job, 0, jobDef(1, eff, "CANARYSCHED */5 * * * *")))
	if status != http.StatusBadRequest {
		t.Fatalf("a schedule that does not parse: %d %s", status, raw)
	}
	if e.definitions(p.org) != 0 || e.audits(p.org) != 0 {
		t.Fatal("a refused save left a record or an audit")
	}
	status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, first, job, 0, jobDef(1, eff, "*/5 * * * *")))
	var saved httpapi.JobDefinitionWriteAnswer
	if err := json.Unmarshal(raw, &saved); err != nil || status != http.StatusOK {
		t.Fatalf("create: %d %v %s", status, err, raw)
	}
	if v := saved.Job; saved.State != httpapi.ActionCommitted || v.JobID != job || v.Revision != 1 || v.Retired || v.Definition.Revision != 1 || v.Definition.Schedule == nil || v.Definition.Schedule.Cron != "*/5 * * * *" || v.Definition.Grace == 0 {
		t.Fatalf("created view: %+v", saved)
	}
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 0, jobDef(1, eff, "*/6 * * * *"))); status != http.StatusConflict {
		t.Fatalf("create over an existing job: %d %s", status, raw)
	}
	var second httpapi.JobDefinitionWriteAnswer
	status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 1, jobDef(2, eff+1, "*/10 * * * *")))
	if err := json.Unmarshal(raw, &second); err != nil || status != http.StatusOK || second.Job.Revision != 2 || second.Job.Definition.Revision != 2 || second.Job.Definition.Schedule.Cron != "*/10 * * * *" {
		t.Fatalf("update: %d %v %s", status, err, raw)
	}
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 1, jobDef(3, eff+2, "*/7 * * * *"))); status != http.StatusConflict {
		t.Fatalf("stale revision: %d %s", status, raw)
	}
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 2, jobDef(2, eff+2, "*/7 * * * *"))); status != http.StatusBadRequest {
		t.Fatalf("a repeated definition revision: %d %s", status, raw)
	}
	latest := model.NewID()
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, latest, job, 2, jobDef(3, eff+2, "*/7 * * * *"))); status != http.StatusOK {
		t.Fatalf("third save: %d %s", status, raw)
	}
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, latest, job, 2, jobDef(3, eff+2, "*/7 * * * *"))); status != http.StatusOK {
		t.Fatalf("replay of the latest command: %d %s", status, raw)
	}
	if e.audits(p.org) != 3 {
		t.Fatalf("audits after three saves and their refusals: %d", e.audits(p.org))
	}

	retireCmd := model.NewID()
	var retired httpapi.JobDefinitionWriteAnswer
	status, raw = e.post(p.writer, jobDefRetireBody(p.org, p.project, retireCmd, job, 3))
	if err := json.Unmarshal(raw, &retired); err != nil || status != http.StatusOK || !retired.Job.Retired || retired.Job.Revision != 4 || retired.Job.Definition.Revision != 3 {
		t.Fatalf("retire: %d %v %s", status, err, raw)
	}
	if status, raw = e.post(p.writer, jobDefRetireBody(p.org, p.project, model.NewID(), job, 4)); status != http.StatusOK {
		t.Fatalf("a second retirement: %d %s", status, raw)
	}
	if status, raw = e.post(p.writer, jobDefRetireBody(p.org, p.project, model.NewID(), model.NewID(), 0)); status != http.StatusNotFound {
		t.Fatalf("a retirement of an unknown job: %d %s", status, raw)
	}

	var list httpapi.JobDefinitionListAnswer
	status, raw = e.post(p.reader, jobDefListBody(p.org, p.project))
	if err := json.Unmarshal(raw, &list); err != nil || status != http.StatusOK || list.CanAuthor || len(list.Jobs) != 1 || list.Jobs[0].JobID != job || !list.Jobs[0].Retired || list.Jobs[0].Revision != 4 {
		t.Fatalf("a reader's list: %d %v %s", status, err, raw)
	}
	list = httpapi.JobDefinitionListAnswer{}
	status, raw = e.post(p.writer, jobDefListBody(p.org, p.project))
	if err := json.Unmarshal(raw, &list); err != nil || status != http.StatusOK || !list.CanAuthor || len(list.Jobs) != 1 {
		t.Fatalf("a writer's list: %d %v %s", status, err, raw)
	}
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 3, jobDef(4, eff+3, "*/8 * * * *"))); status != http.StatusConflict {
		t.Fatalf("a save from before the retirement: %d %s", status, raw)
	}
	if status, raw = e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 4, jobDef(4, eff+3, "*/8 * * * *"))); status != http.StatusOK {
		t.Fatalf("the save that brings it back: %d %s", status, raw)
	}
	if e.audits(p.org) != 5 {
		t.Fatalf("audits %d", e.audits(p.org))
	}
	if err := e.app.Control.View(e.ctx, func(st model.ControlState) error {
		for _, a := range st.Audits {
			if strings.HasPrefix(a.Action, "jobs.") && (strings.Contains(a.Reason, "*/") || a.Principal != p.writer.ID) {
				t.Errorf("an audit carries the schedule or the wrong actor: %+v", a)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Who may do what: a policy.write member of the project saves and retires; a
// member with only telemetry.read lists and is told it may not author; policy.write
// without read lists nothing; another project's and another organization's
// members see the same not-found an absent project gives; and nothing is
// committed by a refused request.
func TestJobDefinitionRouteScopes(t *testing.T) {
	e := newJobDefEnv(t)
	p := e.parties("jobdef scopes")
	job := model.NewID()
	eff := time.Now().Add(-time.Hour).UnixNano()
	if status, raw := e.post(p.writer, jobDefSaveBody(p.org, p.project, model.NewID(), job, 0, jobDef(1, eff, "* * * * *"))); status != http.StatusOK {
		t.Fatalf("seed: %d %s", status, raw)
	}
	before := e.audits(p.org)
	if status, raw := e.post(p.writer, jobDefListBody(p.org, model.NewID())); status != http.StatusNotFound {
		t.Fatalf("an absent project: %d %s", status, raw)
	}
	for name, who := range map[string]person{"policy.write without read": p.wOnly, "another org": p.outsider} {
		if status, raw := e.post(who, jobDefListBody(p.org, p.project)); status != http.StatusNotFound {
			t.Errorf("%s listed: %d %s", name, status, raw)
		}
	}
	for name, body := range map[string]httpapi.JobDefinitionRequest{
		"save":   jobDefSaveBody(p.org, p.project, model.NewID(), job, 1, jobDef(2, eff+1, "* * * * *")),
		"retire": jobDefRetireBody(p.org, p.project, model.NewID(), job, 1),
	} {
		for who, member := range map[string]person{"reader": p.reader, "another org": p.outsider} {
			if status, raw := e.post(member, body); status != http.StatusNotFound {
				t.Errorf("%s by %s: %d %s", name, who, status, raw)
			}
		}
	}
	if status, raw := e.post(p.wOnly, jobDefSaveBody(p.org, p.project, model.NewID(), job, 1, jobDef(2, eff+1, "* * * * *"))); status != http.StatusOK {
		t.Errorf("a save by a policy.write member without read: %d %s", status, raw)
	}
	if status, raw := e.post(p.wOnly, jobDefRetireBody(p.org, p.project, model.NewID(), job, 2)); status != http.StatusOK {
		t.Errorf("a retirement by a policy.write member without read: %d %s", status, raw)
	}
	// Someone else's project under my organization: a guessed project and a guessed org.
	if status, raw := e.post(p.writer, jobDefSaveBody(p.org, model.NewID(), model.NewID(), job, 0, jobDef(1, eff, "* * * * *"))); status != http.StatusNotFound {
		t.Errorf("a guessed project: %d %s", status, raw)
	}
	if status, raw := e.post(p.writer, jobDefSaveBody(model.NewID(), p.project, model.NewID(), job, 0, jobDef(1, eff, "* * * * *"))); status != http.StatusNotFound {
		t.Errorf("a guessed organization: %d %s", status, raw)
	}
	if e.audits(p.org) != before+2 {
		t.Fatalf("audits %d, want %d: a refused request committed", e.audits(p.org), before+2)
	}
}

// The body is closed: an unknown field (top level or inside the definition), a
// list that carries write fields, a write that misses one, and an unknown
// operation are refused before anything is looked up or committed.
func TestJobDefinitionRouteBodyIsClosed(t *testing.T) {
	e := newJobDefEnv(t)
	p := e.parties("jobdef closed")
	job, command := model.NewID(), model.NewID()
	eff := time.Now().Add(-time.Hour).UnixNano()
	good := func() map[string]any {
		raw, _ := json.Marshal(jobDefSaveBody(p.org, p.project, command, job, 0, jobDef(1, eff, "* * * * *")))
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	with := func(edit func(m map[string]any)) map[string]any {
		m := good()
		edit(m)
		return m
	}
	for name, body := range map[string]any{
		"unknown field":      with(func(m map[string]any) { m["principal"] = p.outsider.ID.String() }),
		"unknown definition": with(func(m map[string]any) { m["definition"].(map[string]any)["cron"] = "* * * * *" }),
		"no command":         with(func(m map[string]any) { delete(m, "command_id") }),
		"no job":             with(func(m map[string]any) { delete(m, "job_id") }),
		"no expected":        with(func(m map[string]any) { delete(m, "expected_revision") }),
		"no reason":          with(func(m map[string]any) { delete(m, "reason") }),
		"no definition":      with(func(m map[string]any) { delete(m, "definition") }),
		"no org":             with(func(m map[string]any) { delete(m, "org") }),
		"no project":         with(func(m map[string]any) { delete(m, "project_id") }),
		"unknown operation":  with(func(m map[string]any) { m["operation"] = "replay" }),
		"list with a write":  with(func(m map[string]any) { m["operation"] = "list" }),
		"retire with a body": with(func(m map[string]any) { m["operation"] = "retire" }),
		"not json":           []byte(`{"org":`),
	} {
		if status, raw := e.post(p.writer, body); status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, status, raw)
		}
	}
	if e.definitions(p.org) != 0 || e.audits(p.org) != 0 {
		t.Fatal("a refused request committed")
	}
	if status, raw := e.post(p.writer, good()); status != http.StatusOK {
		t.Fatalf("the unedited body: %d %s", status, raw)
	}
}
