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
		if len(os.Args) >= 2 && os.Args[1] == "source-map" {
			fmt.Fprintln(os.Stderr, "source-map smoke failed:", e)
		} else {
			fmt.Fprintln(os.Stderr, "bootstrap-scope smoke failed")
		}
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) >= 2 && os.Args[1] == "source-map" {
		return runSourceMap(os.Args[2:])
	}
	if len(os.Args) < 2 || os.Args[1] != "bootstrap-scope" {
		return fmt.Errorf("expected bootstrap-scope")
	}
	f := flag.NewFlagSet("bootstrap-scope", flag.ContinueOnError)
	artifact := f.String("artifact-dir", "", "sanitized artifact directory")
	if err := f.Parse(os.Args[2:]); err != nil {
		return err
	}
	if *artifact == "" {
		return fmt.Errorf("artifact directory required")
	}
	if err := os.MkdirAll(*artifact, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "soundpost-smoke-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	store, err := control.Open(dir)
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		return err
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", service, nil).Handler)
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	adminClient := client
	statuses := map[string]int{}
	expected := map[string]int{}
	call := func(name, path string, v any, csrf string, want int) ([]byte, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Origin", server.URL)
		req.Header.Set("X-CSRF-Token", csrf)
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		statuses[name] = response.StatusCode
		expected[name] = want
		if response.StatusCode != want {
			return nil, fmt.Errorf("unexpected status for %s", name)
		}
		return io.ReadAll(response.Body)
	}
	bootstrap, err := store.BootstrapToken()
	if err != nil {
		return err
	}
	q := map[string]string{"Token": bootstrap, "Email": "smoke@example.test", "Password": "smoke bootstrap password 2026"}
	raw, err := call("bootstrap", "/api/v1/bootstrap", q, "", 200)
	if err != nil {
		return err
	}
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
		var revision model.Revision
		if err := store.View(ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
			return err
		}
		p.Reason = "bootstrap-scope smoke"
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
	var elevated struct {
		ID model.ID `json:"id"`
	}
	if err = json.Unmarshal(raw, &elevated); err != nil {
		return err
	}
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
	credential, err := service.Authenticate(ctx, adminCookie)
	if err != nil {
		return err
	}
	handle, err := service.ResolveElevation(ctx, credential, elevated.ID)
	if err != nil {
		return err
	}
	if _, err = service.ElevatedScope(ctx, handle, orgs[0], []model.ID{projects[0]}, auth.Read); err != nil {
		return err
	}
	auditOrdered := false
	if err = store.View(ctx, func(st control.State) error {
		n := len(st.Audits)
		auditOrdered = n >= 2 && st.Audits[n-2].Action == "elevate" && st.Audits[n-1].Action == "elevated_read"
		return nil
	}); err != nil {
		return err
	}
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
	report := struct {
		Statuses     map[string]int `json:"statuses"`
		Expected     map[string]int `json:"expected"`
		AuditOrdered bool           `json:"audit_ordered"`
	}{statuses, expected, auditOrdered}
	artifactJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(*artifact, "bootstrap-scope.json"), artifactJSON, 0600)
}
