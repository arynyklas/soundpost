// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"os"
	"path/filepath"
	"testing"
)

// The provisioner must produce what artifact-upload consumes: a valid source_content manifest, a map
// whose retained part spans several fragments, working uploader/reader credentials for the artifact's
// organization, and a credential that is live in a different organization only.
func TestArtifactProvisionProducesAUsableFixture(t *testing.T) {
	base := t.TempDir()
	// runArtifactProvision prints the path; capture it from the directory instead.
	if e := runArtifactProvision([]string{"--base-dir", base}); e != nil {
		t.Fatal(e)
	}
	runs, _ := filepath.Glob(filepath.Join(base, "run-*", "config.json"))
	if len(runs) != 1 {
		t.Fatalf("want one fixture config, got %v", runs)
	}
	c, m, e := readArtifactSmokeConfig(runs[0])
	if e != nil {
		t.Fatal(e)
	}
	if !m.SourceContent {
		t.Fatal("manifest must declare source_content")
	}
	raw, e := os.ReadFile(c.MapFile)
	if e != nil {
		t.Fatal(e)
	}
	if model.HashCanonical(raw) != m.MapSHA256 || uint64(len(raw)) != uint64(m.Size) {
		t.Fatal("manifest does not describe the map file")
	}
	var parsed map[string]json.RawMessage
	if e = json.Unmarshal(raw, &parsed); e != nil {
		t.Fatal(e)
	}
	delete(parsed, "sourcesContent")
	stripped, _ := json.Marshal(parsed)
	if min := 2*model.ArtifactFragmentLimit + 1; len(stripped) < min {
		t.Fatalf("retained map %d bytes, need at least %d for three fragments", len(stripped), min)
	}
	if !bytes.Contains(raw, []byte("sourcesContent")) {
		t.Fatal("fixture map has no sourcesContent for the explicit sources read")
	}
	app, e := appcore.Open(c.StateDir)
	if e != nil {
		t.Fatal(e)
	}
	defer app.Close()
	ctx := context.Background()
	tok := func(path string) auth.Credential {
		s, e := artifactSmokeToken(path)
		if e != nil {
			t.Fatal(e)
		}
		a, e := app.Auth.Authenticate(ctx, s)
		if e != nil {
			t.Fatal(e)
		}
		return a
	}
	if _, e = app.Auth.Authorize(ctx, tok(c.UploaderTokenFile), m.Org, []model.ID{m.Project}, auth.ArtifactWrite); e != nil {
		t.Fatalf("uploader: %v", e)
	}
	if _, e = app.Auth.Authorize(ctx, tok(c.ReaderTokenFile), m.Org, []model.ID{m.Project}, auth.ArtifactRead); e != nil {
		t.Fatalf("reader: %v", e)
	}
	denied := tok(c.DeniedTokenFile)
	if _, e = app.Auth.Authorize(ctx, denied, m.Org, []model.ID{m.Project}, auth.ArtifactRead); e == nil {
		t.Fatal("the other-org credential reads this org's artifacts")
	}
	if c.DeniedOrg == m.Org {
		t.Fatal("denied credential must belong to a different organization")
	}
	if _, e = app.Auth.Authorize(ctx, denied, c.DeniedOrg, []model.ID{c.DeniedProject}, auth.ArtifactRead); e != nil {
		t.Fatalf("other-org credential is not live in its own org: %v", e)
	}
	// The fixture must be uploadable by the real service: a source_content artifact is private, so the source policy, the source-reader grant and raw.read on the token all have to line up.
	service, e := artifacts.New(app.Storage, app.Control, app.Auth)
	if e != nil {
		t.Fatal(e)
	}
	writeScope, e := app.Auth.Authorize(ctx, tok(c.UploaderTokenFile), m.Org, []model.ID{m.Project}, auth.ArtifactWrite)
	if e != nil {
		t.Fatal(e)
	}
	input, e := os.Open(c.MapFile)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	put, e := service.Put(ctx, writeScope, m, input)
	if e != nil {
		t.Fatalf("the provisioned fixture is not uploadable: %v", e)
	}
	if err := requireMultiFragment(put.Map, 2*model.ArtifactFragmentLimit+1); err != nil {
		t.Fatal(err)
	}
}
