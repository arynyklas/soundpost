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
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/httpapi"
	"soundpost/internal/model"
	"testing"
	"time"
)

// A truncated file part is malformed input, not an over-cap upload.
func TestArtifactHTTPTruncatedPartIsNotTooLarge(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	actor, e := f.app.Auth.Authenticate(ctx, f.token)
	if e != nil {
		t.Fatal(e)
	}
	token, e := f.app.Auth.IssueServerToken(ctx, actor, f.org, f.scope(t, auth.ArtifactWrite).PrincipalID(), []model.ID{f.project}, []auth.Permission{auth.ArtifactWrite}, time.Now().Add(time.Hour).Unix(), "status fixture")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(httpapi.NewServer("", f.app.Auth, nil, f.app.Register).Handler)
	defer server.Close()
	raw := []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`)
	post := func(m artifacts.Manifest, file []byte) model.Code {
		t.Helper()
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		p, _ := w.CreateFormField("manifest")
		enc, _ := json.Marshal(m)
		p.Write(enc)
		p, _ = w.CreateFormFile("file", "x")
		p.Write(file)
		w.Close()
		r, _ := http.NewRequest("POST", server.URL+"/api/v1/artifacts", &body)
		r.Header.Set("Authorization", "Bearer "+token.Token)
		r.Header.Set("Content-Type", w.FormDataContentType())
		resp, err := server.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		var fault model.Fault
		if resp.StatusCode == 200 || model.StrictJSON(data, &fault) != nil {
			t.Fatalf("unexpected status %d: %s", resp.StatusCode, data)
		}
		return fault.Code
	}
	short := f.manifest(raw)
	short.Size = model.Uint64(len(raw) + 10)
	if c := post(short, raw); c != model.Invalid {
		t.Fatalf("truncated part reported as %v", c)
	}
	long := f.manifest(raw)
	long.Size = model.Uint64(len(raw) - 1)
	if c := post(long, raw); c != model.TooLarge {
		t.Fatalf("over-cap part reported as %v", c)
	}
}
