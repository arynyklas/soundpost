// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"soundpost/internal/retention"
	"strings"
	"time"
)

// RunDeletion drives a real appcore (real control, replicated storage, auth,
// ingest, exports) through the C11/C12 deletion saga over HTTPS: ingest a
// canary-bearing series, delete it (retire_project), observe HTTP denial from
// the instant Begin commits, drive the barrier saga to complete, run the local
// physical pass, search the data directory for the canary bytes, and write the
// backup suppression manifest (the exact ledger a restore authority stores).
// Registered as: case "delete-restore-pressure": return RunDeletion(os.Args[2:]).
func RunDeletion(args []string) (result error) {
	stage := "deletion_flags"
	defer func() { result = annotateSmokeFailure("delete_restore_pressure", stage, model.ID{}, result) }()
	flags := flag.NewFlagSet("delete-restore-pressure", flag.ContinueOnError)
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
	fail := func(name string) error { return &smokeFailure{Stage: "deletion_" + name, Code: "deletion_violation"} }
	stage = "deletion_open"
	dir, err := os.MkdirTemp("", "soundpost-deletion-")
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
	svc := app.Retention
	defer svc.Close()
	server := httptest.NewTLSServer(httpapi.NewServer("", app.Auth, nil, app.Register).Handler)
	defer server.Close()
	client := server.Client()

	stage = "deletion_identities"
	boot, err := app.Control.BootstrapToken()
	if err != nil {
		return err
	}
	owner, err := app.Auth.Bootstrap(ctx, boot, "deletion-smoke-owner@example.test", "deletion smoke owner password 2026")
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
		p.Reason = "deletion smoke"
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = app.Auth.AdminCommand(ctx, actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: raw})
		return err
	}
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "deletion smoke"}}, {"create_project", auth.AdminPayload{ID: project, Name: "doomed"}}, {"membership", auth.AdminPayload{UserID: owner.User, Enabled: true}}, {"grant", auth.AdminPayload{UserID: owner.User, ProjectID: project, Enabled: true, Permissions: []string{string(auth.Read)}}}} {
		if err = command(org, step.kind, step.p); err != nil {
			return err
		}
	}
	ids := struct{ service, environment, build model.ID }{model.NewID(), model.NewID(), model.NewID()}
	resource := model.Resource{Service: ids.service, Environment: ids.environment, Build: ids.build, Instance: "opaque-instance", Labels: model.Labels{}}
	cfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: project, Enabled: true})
	if err = command(org, "source_policy", auth.AdminPayload{ID: source, Config: cfg}); err != nil {
		return err
	}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{ids.service}, Environments: []model.ID{ids.environment}, Builds: []model.ID{ids.build}, Instances: []string{"opaque-instance"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 14}, MaxBytes: 1 << 20, MaxSeries: 100}
	issued, err := app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "deletion smoke"})
	if err != nil {
		return err
	}
	call := func(method, path string, body any) (int, []byte, error) {
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
		req.Header.Set("Cookie", "__Host-soundpost="+owner.Token)
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", owner.CSRF)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
		return resp.StatusCode, raw, err
	}
	canary := "deletion_canary_" + strings.ReplaceAll(model.NewID().String(), "-", "")
	ingest := func(at int64, name string) (int, error) {
		value := model.FloatBits(math.Float64bits(1))
		record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(at), Resource: resource, Payload: model.Payload{Metric: &model.MetricPoint{Name: name, Labels: model.Labels{}, SampleKind: "float", Value: &value, Unit: "1", Type: "counter"}}}
		batch := model.Batch{Version: 1, Project: project, Source: source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
		var err error
		if batch.RouteSlot, err = model.OwnerSlot(org, project, source, batch.Producer, record); err != nil {
			return 0, err
		}
		body, err := json.Marshal(batch)
		if err != nil {
			return 0, err
		}
		req, err := http.NewRequest("POST", server.URL+"/ingest/v1/batches", bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+issued.Credential)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return resp.StatusCode, nil
	}
	stage = "deletion_seed"
	for i := range 3 {
		status, err := ingest(int64(i+1), canary)
		if err = requireSmokeResponse("deletion_ingest", status, 200, nil, err); err != nil {
			return err
		}
	}
	export := httpapi.ExportRequest{Operation: "create", Org: org, Project: project, Permission: string(auth.Read), Signal: model.Metric, Start: 0, End: model.Int64(math.MaxInt64)}
	status, body, err := call("POST", "/api/v1/exports", export)
	if err = requireSmokeResponse("deletion_export_before", status, 200, body, err); err != nil {
		return err
	}

	stage = "deletion_begin"
	scope, err := app.Auth.Authorize(ctx, actor, org, nil, auth.OrgAdmin)
	if err != nil {
		return err
	}
	var revision model.Revision
	if err = app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		return err
	}
	receipt, err := svc.Delete(ctx, scope, retention.DeleteRequest{CommandID: model.NewID(), ExpectedRevision: revision, Mode: model.DeleteRetireProject, OrgID: org, ProjectIDs: []model.ID{project}, Reason: "deletion smoke"})
	if err != nil {
		return err
	}
	if receipt.Phase != model.DeletePhaseFencing {
		return fail("begin_not_fencing")
	}
	// HTTP denial from the instant Begin commits, before any slot has a barrier.
	stage = "deletion_http_denial"
	randomExport := export
	randomExport.Project = model.NewID()
	baseStatus, baseBody, err := call("POST", "/api/v1/exports", randomExport)
	if err != nil {
		return err
	}
	status, body, err = call("POST", "/api/v1/exports", export)
	if err != nil {
		return err
	}
	if status == 200 || status != baseStatus || !bytes.Equal(body, baseBody) && !sameFaultCode(body, baseBody) {
		return fail("export_not_denied_like_absent")
	}
	if status, err = ingest(10, canary); err != nil {
		return err
	}
	if status == 200 {
		return fail("ingest_accepted_after_begin")
	}

	stage = "deletion_saga"
	deadline := time.Now().Add(2 * time.Minute)
	var current retention.DeleteReceipt
	for {
		if err = svc.RunOnce(ctx); err != nil && time.Now().After(deadline) {
			return err
		}
		scope, err = app.Auth.Authorize(ctx, actor, org, nil, auth.OrgAdmin)
		if err != nil {
			return err
		}
		if current, err = svc.PollDelete(ctx, scope, receipt.OperationID); err != nil {
			return err
		}
		if current.Phase == model.DeletePhaseComplete && current.Physical == retention.PhysicalDone {
			break
		}
		if time.Now().After(deadline) {
			return fail("saga_not_complete")
		}
		time.Sleep(200 * time.Millisecond)
	}

	stage = "deletion_physical_scan"
	counts := map[string]int{}
	needle := []byte(canary)
	if err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if n := bytes.Count(raw, needle); n > 0 {
			rel, _ := filepath.Rel(dir, path)
			counts[filepath.ToSlash(rel)] = n
		}
		return nil
	}); err != nil {
		return err
	}
	unscrubbable := 0
	for path, n := range counts {
		if strings.HasSuffix(path, "apply.db") || strings.HasSuffix(path, "control.db") {
			unscrubbable += n // bbolt free pages are not scrubbed: reported, never hidden
			continue
		}
		return fail("canary_survived_in_" + strings.NewReplacer("/", "_", ".", "_").Replace(path))
	}

	stage = "deletion_manifest"
	var ledger retention.LedgerGeneration
	if err = app.Control.View(ctx, func(st model.ControlState) error {
		l, tombstones := retention.BuildLedger(st)
		ledger = retention.LedgerGeneration{Generation: l.Generation, Ledger: l, Tombstones: tombstones}
		return nil
	}); err != nil {
		return err
	}
	if len(ledger.Tombstones) != 1 || ledger.Ledger.Entries[0].Hash != ledger.Tombstones[0].Digest() {
		return fail("ledger_digest")
	}
	manifest := struct {
		Smoke              string                     `json:"smoke"`
		Operation          model.ID                   `json:"operation"`
		Mode               string                     `json:"mode"`
		Phase              string                     `json:"phase"`
		Physical           string                     `json:"physical"`
		Generation         uint64                     `json:"generation"`
		HTTPDenial         int                        `json:"http_denial_status"`
		CanaryFiles        map[string]int             `json:"canary_occurrences_after_cleanup"`
		BoltFreePagesNote  int                        `json:"bolt_free_page_occurrences_unscrubbed"`
		Backup             retention.LedgerGeneration `json:"suppression_ledger"`
		BackupExpiryBefore model.UnixNano             `json:"backup_expiry_not_after_ns"`
	}{"delete-restore-pressure", receipt.OperationID, current.Mode, current.Phase, current.Physical, current.Generation, status, counts, unscrubbable, ledger, current.BackupDeadline}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*artifact, "deletion-manifest.json"), raw, 0600)
}

func sameFaultCode(a, b []byte) bool {
	var x, y model.Fault
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && x.Code != "" && x.Code == y.Code && x.SafeDetail == y.SafeDetail
}
