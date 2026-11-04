// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"testing"
	"time"
)

func TestArtifactProtectedHTTPUploadAndClosedReads(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	principal := f.scope(t, auth.ArtifactWrite).PrincipalID()
	writeToken, e := f.app.Auth.IssueServerToken(ctx, actor, f.org, principal, []model.ID{f.project}, []auth.Permission{auth.ArtifactWrite}, time.Now().Add(time.Hour).Unix(), "artifact HTTP fixture")
	if e != nil {
		t.Fatal(e)
	}
	readToken, e := f.app.Auth.IssueServerToken(ctx, actor, f.org, principal, []model.ID{f.project}, []auth.Permission{auth.ArtifactRead}, time.Now().Add(time.Hour).Unix(), "artifact read fixture")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", f.app.Auth, nil, f.app.Register).Handler)
	defer server.Close()
	client := server.Client()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA","sourcesContent":["SECRET"]}`)
	m := f.manifest(raw)
	request := func(token, contentType string, body []byte) (int, []byte) {
		t.Helper()
		r, e := http.NewRequest("POST", server.URL+"/api/v1/artifacts", bytes.NewReader(body))
		if e != nil {
			t.Fatal(e)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", contentType)
		response, e := client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		data, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, data
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormField("manifest")
	encoded, _ := json.Marshal(m)
	part.Write(encoded)
	part, _ = writer.CreateFormFile("file", "../../unused.map")
	part.Write(raw)
	writer.Close()
	status, receipt := request(writeToken.Token, writer.FormDataContentType(), body.Bytes())
	if status != 200 {
		t.Fatalf("upload status %d: %s", status, receipt)
	}
	var artifact model.ArtifactReferenceIntent
	if model.StrictJSON(receipt, &artifact) != nil {
		t.Fatal("invalid committed receipt")
	}
	query, _ := json.Marshal(httpapi.ArtifactReadRequest{Operation: "read", Org: f.org, Project: f.project, ID: artifact.ID})
	status, download := request(readToken.Token, "application/json", query)
	if status != 200 || model.HashCanonical(download) != artifact.Map.Hash || bytes.Contains(download, []byte("SECRET")) {
		t.Fatal("protected map read", status)
	}
	if status, _ = request(writeToken.Token, "application/json", query); status != 404 {
		t.Fatal("write-only token read", status)
	}
	for _, bad := range []string{`{"operation":"upload"}`, `{"operation":"read","unexpected":true}`, `{"operation":"sources"}`} {
		if status, _ = request(readToken.Token, "application/json", []byte(bad)); status != 400 {
			t.Fatal("open read DTO", status)
		}
	}
	// Actual source credentials are accepted only by the source-ingest authority,
	// never by this user/server artifact route, even when write-only elsewhere.
	source := model.NewID()
	onboarded, e := f.app.Auth.OnboardSource(ctx, actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric}, Resources: model.ResourceRegistry{Services: []model.ID{model.NewID()}, Environments: []model.ID{model.NewID()}, Builds: []model.ID{f.build}, Instances: []string{"http-fixture"}}, RetentionDays: map[model.Kind]uint32{model.Metric: 30}, MaxBytes: 1 << 30, MaxSeries: 100}, Reason: "source bearer isolation fixture"})
	if e != nil {
		t.Fatal(e)
	}
	if status, _ = request(onboarded.Credential, "application/json", query); status != 401 {
		t.Fatal("source bearer gained artifact read", status)
	}
	if status, _ = request(onboarded.Credential, writer.FormDataContentType(), body.Bytes()); status != 401 {
		t.Fatal("source bearer promoted to private artifact writer", status)
	}
}
