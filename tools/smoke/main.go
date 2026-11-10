// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "smoke failed:", e)
		os.Exit(1)
	}
}
func run() (err error) {
	smoke, stage := "bootstrap_scope", "dispatch"
	runID := model.NewID()
	defer func() { err = annotateSmokeFailure(smoke, stage, runID, err) }()
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "quorum-node-loss":
			smoke, stage = "quorum_node_loss", "quorum_dispatch"
			return runQuorumNodeLoss(os.Args[2:])
		case "quorum-child":
			smoke, stage = "quorum_child", "quorum_child_start"
			return runQuorumChild(os.Args[2:])
		case "artifact-upload":
			smoke, stage = "artifact_upload", "artifact_dispatch"
			return runArtifactUpload(os.Args[2:])
		case "artifact-upload-child":
			smoke, stage = "artifact_upload_child", "artifact_child"
			return runArtifactUploadChild(os.Args[2:])
		case "storage-roundtrip":
			smoke, stage = "storage_roundtrip", "storage_dispatch"
			return runStorageRoundtrip(os.Args[2:])
		case "durable-child":
			smoke, stage = "durable_child", "child_start"
			return runDurableChild(os.Args[2:])
		case "durable-restart":
			smoke, stage = "durable_restart", "durable_dispatch"
			return runDurable(os.Args[2:], os.Args[1])
		case "privacy-admission":
			smoke, stage = "privacy_admission", "privacy_dispatch"
			return runDurable(os.Args[2:], os.Args[1])
		case "isolation":
			smoke, stage = "isolation", "isolation_dispatch"
			return RunIsolation(os.Args[2:])
		case "snapshot-repair":
			smoke, stage = "snapshot_repair", "repair_dispatch"
			return RunSnapshotRepair(os.Args[2:])
		case "snapshot-repair-child":
			smoke, stage = "snapshot_repair_child", "repair_child_start"
			return RunSnapshotRepairChild(os.Args[2:])
		case "delete-restore-pressure":
			smoke, stage = "delete_restore_pressure", "deletion_dispatch"
			return RunDeletion(os.Args[2:])
		case "artifact-policy":
			smoke, stage = "artifact_policy", "artifact_policy_dispatch"
			return RunArtifactPolicy(os.Args[2:])
		case "backup-restore":
			smoke, stage = "backup_restore", "backup_dispatch"
			return RunBackupRestore(os.Args[2:])
		case "install-single":
			smoke, stage = "install_single", "install_dispatch"
			return RunInstallSingle(os.Args[2:])
		case "install-distributed":
			smoke, stage = "install_distributed", "install_dispatch"
			return RunInstallDistributed(os.Args[2:])
		case "host-collection":
			smoke, stage = "host_collection", "host_collection_dispatch"
			return RunHostCollection(os.Args[2:])
		case "evidence":
			smoke, stage = "evidence", "evidence_dispatch"
			return RunEvidence(os.Args[2:])
		case "journeys":
			smoke, stage = "journeys", "journeys_dispatch"
			return RunJourneys(os.Args[2:])
		case "backup-restore-child":
			smoke, stage = "backup_restore_child", "backup_child_start"
			return RunBackupRestoreChild(os.Args[2:])
		}
	}
	if len(os.Args) >= 2 && os.Args[1] == "source-map" {
		smoke, stage = "source_map", "source_map_dispatch"
		return runSourceMap(os.Args[2:])
	}
	if len(os.Args) < 2 || os.Args[1] != "bootstrap-scope" {
		return fmt.Errorf("expected bootstrap-scope")
	}
	f := flag.NewFlagSet("bootstrap-scope", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	stage = "bootstrap_flags"
	artifact := f.String("artifact-dir", "", "sanitized artifact directory")
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *artifact == "" {
		return fmt.Errorf("artifact directory required")
	}
	stage = "artifact_directory"
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	stage = "fixture_directory"
	dir, err := os.MkdirTemp("", "soundpost-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	stage = "control_open"
	store, err := control.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	stage = "auth_new"
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		return err
	}
	stage = "control_activate"
	if err = store.EnableSingle(context.Background(), filepath.Join(dir, "raft-control")); err != nil {
		return err
	}
	stage = "https_start"
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	adminClient := client
	statuses := map[string]int{}
	expected := map[string]int{}
	call := func(name, path string, v any, csrf string, want int) ([]byte, error) {
		stage = "http_" + name + "_encode"
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		stage = "http_" + name + "_request"
		req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		stage = "http_" + name + "_send"
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		statuses[name] = response.StatusCode
		expected[name] = want
		if response.StatusCode != want {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 65536))
			return nil, httpSmokeFailure(name, response.StatusCode, want, body)
		}
		stage = "http_" + name + "_body"
		return io.ReadAll(response.Body)
	}
	stage = "bootstrap_token_read"
	bootstrap, err := store.BootstrapToken()
	if err != nil {
		return err
	}
	q := map[string]string{"Token": bootstrap, "Email": "smoke@example.test", "Password": "smoke bootstrap password 2026"}
	raw, err := call("bootstrap", "/api/v1/bootstrap", q, "", 200)
	if err != nil {
		return err
	}
	stage = "bootstrap_session_decode"
	var session auth.Session
	if err = json.Unmarshal(raw, &session); err != nil {
		return err
	}
	adminSession := session
	if _, err = call("bootstrap_replay", "/api/v1/bootstrap", q, "", 401); err != nil {
		return err
	}
	ctx := context.Background()
	command := func(name, kind string, org model.ID, p auth.AdminPayload) error {
		stage = "command_" + name + "_revision"
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		p.Reason = "bootstrap-scope smoke"
		stage = "command_" + name + "_encode"
		payload, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = call(name, "/api/v1/admin/commands", auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: org, Kind: kind, Payload: payload}, session.CSRF, 200)
		return err
	}
	orgs := []model.ID{model.NewID(), model.NewID()}
	projects := []model.ID{model.NewID(), model.NewID()}
	reader := model.NewID()
	for i := range 2 {
		if err = command(fmt.Sprintf("create_org_%d", i), "create_org", orgs[i], auth.AdminPayload{Name: "generic"}); err != nil {
			return err
		}
		if err = command(fmt.Sprintf("create_project_%d", i), "create_project", orgs[i], auth.AdminPayload{ID: projects[i], Name: "generic"}); err != nil {
			return err
		}
		if i == 0 {
			if err = command("create_reader", "create_user", orgs[0], auth.AdminPayload{ID: reader, Email: "reader@example.test", Password: "smoke reader password 2026"}); err != nil {
				return err
			}
		}
		if err = command(fmt.Sprintf("membership_%d", i), "membership", orgs[i], auth.AdminPayload{UserID: reader, Enabled: true}); err != nil {
			return err
		}
	}
	if err = command("grant_first_project", "grant", orgs[0], auth.AdminPayload{UserID: reader, ProjectID: projects[0], Enabled: true, Permissions: []string{"telemetry.read"}}); err != nil {
		return err
	}
	readerClientValue := *server.Client()
	readerClient := &readerClientValue
	readerClient.Jar, _ = cookiejar.New(nil)
	client = readerClient
	raw, err = call("reader_login", "/api/v1/login", map[string]string{"Email": "reader@example.test", "Password": "smoke reader password 2026"}, "", 200)
	if err != nil {
		return err
	}
	stage = "reader_session_decode"
	if err = json.Unmarshal(raw, &session); err != nil {
		return err
	}
	readerSession := session
	probe := func(name string, org, project model.ID, want int) error {
		_, err := call(name, "/api/v1/control/authorize", map[string]any{"org_id": org, "project_ids": []model.ID{project}, "permission": "telemetry.read"}, session.CSRF, want)
		return err
	}
	if err = probe("granted_project", orgs[0], projects[0], 200); err != nil {
		return err
	}
	if err = probe("membership_without_grant", orgs[1], projects[1], 404); err != nil {
		return err
	}
	if err = probe("foreign_project", orgs[0], projects[1], 404); err != nil {
		return err
	}
	client = adminClient
	session = adminSession
	if err = command("revoke_first_project", "grant", orgs[0], auth.AdminPayload{UserID: reader, ProjectID: projects[0], Enabled: false}); err != nil {
		return err
	}
	raw, err = call("elevation", "/api/v1/elevation", map[string]any{"Reason": "smoke audit ordering", "Orgs": []model.ID{orgs[0]}}, session.CSRF, 200)
	if err != nil {
		return err
	}
	stage = "elevation_decode"
	var elevated struct {
		ID model.ID `json:"id"`
	}
	if err = json.Unmarshal(raw, &elevated); err != nil {
		return err
	}
	stage = "elevation_origin"
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		return err
	}
	adminCookie := ""
	for _, cookie := range client.Jar.Cookies(serverURL) {
		if cookie.Name == "__Host-soundpost" {
			adminCookie = cookie.Value
		}
	}
	stage = "elevation_authenticate"
	credential, err := service.Authenticate(ctx, adminCookie)
	if err != nil {
		return err
	}
	stage = "elevation_resolve"
	handle, err := service.ResolveElevation(ctx, credential, elevated.ID)
	if err != nil {
		return err
	}
	stage = "elevation_scope"
	if _, err = service.ElevatedScope(ctx, handle, orgs[0], []model.ID{projects[0]}, auth.Read); err != nil {
		return err
	}
	stage = "elevation_audit_read"
	auditOrdered := false
	if err = store.View(ctx, func(st control.State) error {
		n := len(st.Audits)
		auditOrdered = n >= 2 && st.Audits[n-2].Action == "elevate" && st.Audits[n-1].Action == "elevated_read"
		return nil
	}); err != nil {
		return err
	}
	stage = "elevation_audit_order"
	if !auditOrdered {
		return fmt.Errorf("durable audit ordering absent")
	}
	client = readerClient
	session = readerSession
	if err = probe("revoked_project", orgs[0], projects[0], 404); err != nil {
		return err
	}
	if _, err = call("csrf_denied", "/api/v1/admin/read", auth.AdminReadRequest{OrgID: orgs[0], Kind: "organization"}, "invalid", 403); err != nil {
		return err
	}
	stage = "artifact_encode"
	report := struct {
		Statuses     map[string]int `json:"statuses"`
		Expected     map[string]int `json:"expected"`
		AuditOrdered bool           `json:"audit_ordered"`
		RunID        model.ID       `json:"run_id"`
	}{statuses, expected, auditOrdered, runID}
	artifactJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	stage = "artifact_write"
	return os.WriteFile(filepath.Join(*artifact, "bootstrap-scope.json"), artifactJSON, 0600)
}
