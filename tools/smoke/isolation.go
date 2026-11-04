// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/exports"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"time"
)

type isoPerson struct {
	id      model.ID
	session auth.Session
}
type isoSource struct {
	id, org, project model.ID
	credential       string
}
type isoRow struct {
	Actor   string `json:"actor"`
	Target  string `json:"target"`
	Surface string `json:"surface"`
	Status  int    `json:"status"`
	Outcome string `json:"outcome"`
}

// RunIsolation drives a real appcore (real control, storage, auth, ingest) over
// HTTPS with real logged-in identities and checks the secondary-surface denial
// matrix: capabilities and exports across orgs, projects (grant and team) and
// named restricted sources. Every unauthorized request must be byte-identical
// to a request for a guessed nonexistent target, and no response may carry
// another scope's marker. Registered as: case "isolation": return RunIsolation(os.Args[2:]).
func RunIsolation(args []string) (result error) {
	stage := "isolation_flags"
	defer func() { result = annotateSmokeFailure("isolation", stage, model.ID{}, result) }()
	flags := flag.NewFlagSet("isolation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	artifact := flags.String("artifact-dir", "", "sanitized artifacts")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *artifact == "" {
		return errors.New("artifact directory required")
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	stage = "isolation_open"
	dir, err := os.MkdirTemp("", "soundpost-isolation-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	app, err := appcore.Open(dir)
	if err != nil {
		return err
	}
	defer app.Close()
	ctx := context.Background()
	stage = "isolation_https"
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()
	call := func(who isoPerson, method, path string, body any) (int, []byte, error) {
		var reader io.Reader
		if body != nil {
			raw, err := json.Marshal(body)
			if err != nil {
				return 0, nil, err
			}
			reader = bytes.NewReader(raw)
		}
		req, err := http.NewRequest(method, server.URL+path, reader)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Cookie", "__Host-soundpost="+who.session.Token)
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", who.session.CSRF)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
		return resp.StatusCode, raw, err
	}
	stage = "isolation_identities"
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	owner, err := app.Auth.Bootstrap(ctx, boot, "isolation-smoke-owner@example.test", "isolation smoke owner password 2026")
	if err != nil {
		return err
	}
	actor, err := app.Auth.Authenticate(ctx, owner.Token)
	if err != nil {
		return err
	}
	command := func(org model.ID, kind string, p auth.AdminPayload) error {
		var revision model.Revision
		if err := app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		p.Reason = "isolation smoke"
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw})
		return err
	}
	orgA, orgB := model.NewID(), model.NewID()
	p1, p2, pb := model.NewID(), model.NewID(), model.NewID()
	for _, step := range []struct {
		org  model.ID
		kind string
		p    auth.AdminPayload
	}{{orgA, "create_org", auth.AdminPayload{Name: "isolation A"}}, {orgA, "create_project", auth.AdminPayload{ID: p1, Name: "one"}}, {orgA, "create_project", auth.AdminPayload{ID: p2, Name: "two"}}, {orgB, "create_org", auth.AdminPayload{Name: "isolation B"}}, {orgB, "create_project", auth.AdminPayload{ID: pb, Name: "b"}}} {
		if err = command(step.org, step.kind, step.p); err != nil {
			return err
		}
	}
	person := func(org model.ID, email string) (isoPerson, error) {
		id := model.NewID()
		password := "isolation smoke reader password"
		if err := command(org, "create_user", auth.AdminPayload{ID: id, Email: email, Password: password}); err != nil {
			return isoPerson{}, err
		}
		if err := command(org, "membership", auth.AdminPayload{UserID: id, Enabled: true}); err != nil {
			return isoPerson{}, err
		}
		login, err := app.Auth.Login(ctx, email, password, "")
		return isoPerson{id: id, session: login}, err
	}
	var alice, bob, carol, dave, rawOne, rawTwo isoPerson
	for _, c := range []struct {
		out   *isoPerson
		org   model.ID
		email string
	}{{&alice, orgA, "iso-alice@example.test"}, {&bob, orgA, "iso-bob@example.test"}, {&carol, orgA, "iso-carol@example.test"}, {&dave, orgB, "iso-dave@example.test"}, {&rawOne, orgA, "iso-raw-one@example.test"}, {&rawTwo, orgA, "iso-raw-two@example.test"}} {
		if *c.out, err = person(c.org, c.email); err != nil {
			return err
		}
	}
	grant := func(org model.ID, who isoPerson, project model.ID, permission auth.Permission) error {
		return command(org, "grant", auth.AdminPayload{UserID: who.id, ProjectID: project, Enabled: true, Permissions: []string{string(permission)}})
	}
	team, err := json.Marshal(model.ControlTeam{Members: []model.ID{bob.id}, Projects: []model.ID{p2}, Permissions: []string{string(auth.Read)}, Enabled: true})
	if err != nil {
		return err
	}
	for _, err = range []error{grant(orgA, alice, p1, auth.Read), command(orgA, "team", auth.AdminPayload{ID: model.NewID(), Config: team}), grant(orgB, dave, pb, auth.Read), grant(orgA, rawOne, p1, auth.RawRead), grant(orgA, rawTwo, p1, auth.RawRead)} {
		if err != nil {
			return err
		}
	}
	stage = "isolation_seed"
	ids := struct{ service, environment, build model.ID }{model.NewID(), model.NewID(), model.NewID()}
	registry := model.ResourceRegistry{Services: []model.ID{ids.service}, Environments: []model.ID{ids.environment}, Builds: []model.ID{ids.build}, Instances: []string{"opaque-instance"}}
	resource := model.Resource{Service: ids.service, Environment: ids.environment, Build: ids.build, Instance: "opaque-instance", Labels: model.Labels{}}
	onboard := func(org, project model.ID, policy model.SourcePolicy, cfg auth.SourcePolicyConfig) (isoSource, error) {
		source := model.NewID()
		policy.Resources = registry
		raw, err := json.Marshal(cfg)
		if err != nil {
			return isoSource{}, err
		}
		if err = command(org, "source_policy", auth.AdminPayload{ID: source, Config: raw}); err != nil {
			return isoSource{}, err
		}
		issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "isolation smoke"})
		return isoSource{id: source, org: org, project: project, credential: issued.Credential}, err
	}
	structured := func(org, project model.ID) (isoSource, error) {
		return onboard(org, project, model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, RetentionDays: map[model.Kind]uint32{model.Metric: 7}, MaxBytes: 1 << 20, MaxSeries: 100}, auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
	}
	rawPolicy := func() model.SourcePolicy {
		ownerID := owner.User
		return model.SourcePolicy{Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log}, Templates: []model.LogTemplate{{ID: "raw", Revision: 1, Line: "{msg}", Severity: "error", Fields: []model.TemplateField{{Name: "msg", Type: "string", MaxBytes: 64, Sensitivity: "restricted_raw"}}}}, RetentionDays: map[model.Kind]uint32{model.Log: 7}, MaxBytes: 1 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(30 * time.Minute).UnixNano()), RawOwner: &ownerID, RawRationale: "isolation smoke", RawMaxBytes: 128}
	}
	raw := func(project model.ID, reader isoPerson) (isoSource, error) {
		return onboard(orgA, project, rawPolicy(), auth.SourcePolicyConfig{ProjectID: project, Restricted: true, Readers: []model.ID{reader.id}, Enabled: true})
	}
	sa1, err := structured(orgA, p1)
	if err != nil {
		return err
	}
	sa2, err := structured(orgA, p2)
	if err != nil {
		return err
	}
	sb, err := structured(orgB, pb)
	if err != nil {
		return err
	}
	rs1, err := raw(p1, rawOne)
	if err != nil {
		return err
	}
	rs2, err := raw(p1, rawTwo)
	if err != nil {
		return err
	}
	ingest := func(s isoSource, record model.Record) error {
		batch := model.Batch{Version: 1, Project: s.project, Source: s.id, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
		if batch.RouteSlot, err = model.OwnerSlot(s.org, s.project, s.id, batch.Producer, record); err != nil {
			return err
		}
		body, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		req, err := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+s.credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		reply, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return requireSmokeResponse("isolation_ingest", resp.StatusCode, 200, reply, nil)
	}
	value := model.FloatBits(math.Float64bits(1))
	for _, s := range []struct {
		src  isoSource
		n    int
		name string
	}{{sa1, 2, "iso_marker_one_total"}, {sa2, 3, "iso_marker_two_total"}, {sb, 4, "iso_marker_b_total"}} {
		for j := range s.n {
			if err = ingest(s.src, model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(j + 1), Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: s.name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}); err != nil {
				return err
			}
		}
	}
	for _, s := range []struct {
		src  isoSource
		text string
	}{{rs1, "iso-raw-marker-one"}, {rs2, "iso-raw-marker-two"}} {
		var msg model.Scalar
		if err = json.Unmarshal([]byte(`"`+s.text+`"`), &msg); err != nil {
			return err
		}
		ts := model.UnixNano(5)
		if err = ingest(s.src, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: 5, Resource: resource, Payload: model.Payload{Log: &model.LogRecord{Timestamp: &ts, Severity: "error", TemplateID: "raw", TemplateRevision: 1, Fields: map[string]model.Scalar{"msg": msg}, Line: s.text, StreamLabels: model.Labels{}, Metadata: map[string]model.Scalar{}, SourceClass: "restricted_raw"}}}); err != nil {
			return err
		}
	}
	stage = "isolation_matrix"
	var matrix []isoRow
	fail := func(name string) error { return &smokeFailure{Stage: "isolation_" + name, Code: "isolation_violation"} }
	denial := func(status int, body []byte) (string, error) {
		var f model.Fault
		if json.Unmarshal(body, &f) != nil || f.Code == "" {
			return "", fail("unsafe_fault")
		}
		return fmt.Sprintf("%d/%s/%s", status, f.Code, f.SafeDetail), nil
	}
	record := func(who, target, surface string, status int, outcome string) {
		matrix = append(matrix, isoRow{who, target, surface, status, outcome})
	}
	markers := []string{"iso_marker_one_total", "iso_marker_two_total", "iso_marker_b_total", "iso-raw-marker-one", "iso-raw-marker-two"}
	surfaces := func(who isoPerson, org, project model.ID, permission string, source model.ID) (map[string][2]any, error) {
		out := map[string][2]any{}
		capPath := "/api/v1/capabilities?org=" + org.String() + "&project=" + project.String() + "&permission=" + permission
		if source != (model.ID{}) {
			capPath += "&source=" + source.String()
		}
		status, body, err := call(who, "GET", capPath, nil)
		if err != nil {
			return nil, err
		}
		out["capabilities"] = [2]any{status, body}
		signal := model.Metric
		if permission == "raw.read" {
			signal = model.Log
		}
		create := httpapi.ExportRequest{Operation: "create", Org: org, Project: project, Permission: permission, Source: httpapi.OptionalID(source), Signal: signal, Start: 0, End: model.Int64(math.MaxInt64)}
		if status, body, err = call(who, "POST", "/api/v1/exports", create); err != nil {
			return nil, err
		}
		out["export_create"] = [2]any{status, body}
		probe := httpapi.ExportRequest{Operation: "status", Org: org, Project: project, Permission: permission, Source: httpapi.OptionalID(source), ID: httpapi.OptionalID(model.NewID())}
		if status, body, err = call(who, "POST", "/api/v1/exports", probe); err != nil {
			return nil, err
		}
		out["export_status"] = [2]any{status, body}
		probe.Operation, probe.Ticket = "download", "forged"
		if status, body, err = call(who, "POST", "/api/v1/exports", probe); err != nil {
			return nil, err
		}
		out["export_download"] = [2]any{status, body}
		return out, nil
	}
	// The guessed-ID baseline is what every unauthorized request must equal.
	baseline, err := surfaces(carol, model.NewID(), model.NewID(), "", model.ID{})
	if err != nil {
		return err
	}
	want := map[string]string{}
	for surface, r := range baseline {
		if want[surface], err = denial(r[0].(int), r[1].([]byte)); err != nil {
			return err
		}
	}
	denied := []struct {
		who        string
		person     isoPerson
		org, pj    model.ID
		permission string
		source     model.ID
		target     string
	}{
		{"dave(orgB)", dave, orgA, p1, "", model.ID{}, "orgA/P1"},
		{"dave(orgB)", dave, orgB, p1, "", model.ID{}, "orgB/foreign-project"},
		{"alice(P1 grant)", alice, orgB, pb, "", model.ID{}, "orgB/PB"},
		{"alice(P1 grant)", alice, orgA, p2, "", model.ID{}, "orgA/P2"},
		{"bob(P2 team)", bob, orgA, p1, "", model.ID{}, "orgA/P1"},
		{"carol(no grant)", carol, orgA, p1, "", model.ID{}, "orgA/P1"},
		{"alice(read only)", alice, orgA, p1, "raw.read", rs1.id, "orgA/P1 raw one"},
		{"raw-two", rawTwo, orgA, p1, "raw.read", rs1.id, "orgA/P1 raw one"},
		{"raw-one", rawOne, orgA, p1, "raw.read", rs2.id, "orgA/P1 raw two"},
		{"raw-one", rawOne, orgA, p1, "raw.read", model.NewID(), "orgA/P1 guessed raw"},
	}
	for _, d := range denied {
		got, err := surfaces(d.person, d.org, d.pj, d.permission, d.source)
		if err != nil {
			return err
		}
		for surface, r := range got {
			status, body := r[0].(int), r[1].([]byte)
			text, err := denial(status, body)
			if err != nil {
				return err
			}
			for _, marker := range markers {
				if bytes.Contains(body, []byte(marker)) {
					return fail("marker_leak")
				}
			}
			if text != want[surface] {
				return fail(surface + "_distinguishable")
			}
			record(d.who, d.target, surface, status, "indistinguishable_from_guess")
		}
	}
	stage = "isolation_allowed"
	// Authorized callers see exactly their own marker and nobody else's.
	allowed := []struct {
		who        string
		person     isoPerson
		org, pj    model.ID
		permission string
		source     model.ID
		own        string
		count      int
	}{
		{"alice(P1 grant)", alice, orgA, p1, "", model.ID{}, "iso_marker_one_total", 2},
		{"bob(P2 team)", bob, orgA, p2, "", model.ID{}, "iso_marker_two_total", 3},
		{"dave(orgB)", dave, orgB, pb, "", model.ID{}, "iso_marker_b_total", 4},
		{"raw-one", rawOne, orgA, p1, "raw.read", rs1.id, "iso-raw-marker-one", 1},
		{"raw-two", rawTwo, orgA, p1, "raw.read", rs2.id, "iso-raw-marker-two", 1},
	}
	for _, a := range allowed {
		signal := model.Metric
		if a.permission == "raw.read" {
			signal = model.Log
		}
		status, body, err := call(a.person, "POST", "/api/v1/exports", httpapi.ExportRequest{Operation: "create", Org: a.org, Project: a.pj, Permission: a.permission, Source: httpapi.OptionalID(a.source), Signal: signal, Start: 0, End: model.Int64(math.MaxInt64)})
		if err = requireSmokeResponse("isolation_export_create", status, http.StatusAccepted, body, err); err != nil {
			return err
		}
		var grant exports.Grant
		if err = json.Unmarshal(body, &grant); err != nil {
			return err
		}
		complete := false
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline) && !complete; time.Sleep(25 * time.Millisecond) {
			status, body, err = call(a.person, "POST", "/api/v1/exports", httpapi.ExportRequest{Operation: "status", Org: a.org, Project: a.pj, Permission: a.permission, Source: httpapi.OptionalID(a.source), ID: httpapi.OptionalID(grant.Operation.ID)})
			if err = requireSmokeResponse("isolation_export_status", status, 200, body, err); err != nil {
				return err
			}
			var op exports.Operation
			if err = json.Unmarshal(body, &op); err != nil {
				return err
			}
			if op.Phase == "failed" {
				return fail("own_export_failed")
			}
			complete = op.Phase == "complete"
		}
		if !complete {
			return fail("own_export_pending")
		}
		status, body, err = call(a.person, "POST", "/api/v1/exports", httpapi.ExportRequest{Operation: "download", Org: a.org, Project: a.pj, Permission: a.permission, Source: httpapi.OptionalID(a.source), ID: httpapi.OptionalID(grant.Operation.ID), Ticket: grant.Ticket})
		if err = requireSmokeResponse("isolation_export_download", status, 200, body, err); err != nil {
			return err
		}
		// Rows, not substrings: one log row legitimately carries its marker in both
		// fields.msg and line.
		rows := 0
		for _, line := range bytes.Split(body, []byte("\n")) {
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			rows++
			if !bytes.Contains(line, []byte(a.own)) {
				return fail("own_export_foreign_row")
			}
		}
		if rows != a.count {
			return fail("own_export_rows")
		}
		for _, marker := range markers {
			if marker != a.own && bytes.Contains(body, []byte(marker)) {
				return fail("export_marker_leak")
			}
		}
		record(a.who, a.pj.String()[:8], "export_own_rows", status, "only_own_scope")
	}
	stage = "isolation_artifact"
	evidence := struct {
		Version       int
		Matrix        []isoRow
		Qualification string
	}{1, matrix, "real appcore over HTTPS with real sessions; capabilities and exports only; investigation/workflow handlers belong to plan05"}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*artifact, "isolation.json"), data, 0600)
}
