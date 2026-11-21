// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// runArtifactUpload re-executes os.Executable() as `artifact-upload-child`; under `go test` that is the
// test binary, so it must behave like the smoke binary for that one subcommand.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "artifact-upload-child" {
		if e := runArtifactUploadChild(os.Args[2:]); e != nil {
			os.Stderr.WriteString("artifact-upload-child: " + e.Error() + "\n")
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// provisionArtifactFixture runs the provisioner into base and returns the config path it created.
func provisionArtifactFixture(t *testing.T, base string) string {
	t.Helper()
	before, _ := filepath.Glob(filepath.Join(base, "run-*", "config.json"))
	seen := map[string]bool{}
	for _, p := range before {
		seen[p] = true
	}
	if e := runArtifactProvision([]string{"--base-dir", base}); e != nil {
		t.Fatal(e)
	}
	after, _ := filepath.Glob(filepath.Join(base, "run-*", "config.json"))
	var fresh []string
	for _, p := range after {
		if !seen[p] {
			fresh = append(fresh, p)
		}
	}
	if len(fresh) != 1 {
		t.Fatalf("a provisioner run must create exactly one new fixture config, got %v", fresh)
	}
	return fresh[0]
}

func inside(dir, path string) bool {
	rel, e := filepath.Rel(dir, path)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// 10.18#1: the provisioner is run-time disposable. Every run owns a fresh directory below --base-dir
// (a second run never reuses or disturbs the first), every path in its configuration lies inside that
// directory, a full upload smoke over it leaves nothing outside it (not even in the temp directory),
// and removing the directory leaves no residue.
func TestArtifactProvisionRunIsDisposable(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	base := filepath.Join(t.TempDir(), "fixtures")
	first := provisionArtifactFixture(t, base)
	second := provisionArtifactFixture(t, base)
	if filepath.Dir(first) == filepath.Dir(second) {
		t.Fatal("two provisioner runs share one directory")
	}
	for _, cfgPath := range []string{first, second} {
		run := filepath.Dir(cfgPath)
		c, _, e := readArtifactSmokeConfig(cfgPath)
		if e != nil {
			t.Fatal(e)
		}
		for _, p := range []string{c.StateDir, c.ManifestFile, c.MapFile, c.UploaderTokenFile, c.ReaderTokenFile, c.DeniedTokenFile} {
			if !inside(run, p) {
				t.Fatalf("configuration path %q escapes its disposable run directory %q", p, run)
			}
		}
	}
	c1, _, _ := readArtifactSmokeConfig(first)
	c2, _, _ := readArtifactSmokeConfig(second)
	if c1.StateDir == c2.StateDir {
		t.Fatal("two runs share one state directory")
	}
	entries, e := os.ReadDir(base)
	if e != nil || len(entries) != 2 {
		t.Fatalf("base directory must hold exactly the two run directories, got %v (%v)", entries, e)
	}
	// A real upload smoke over the first run mutates only that run (and cleans its own temp directory).
	if e = runArtifactUpload([]string{"--fixture-config", first, "--artifact-dir", filepath.Join(t.TempDir(), "out")}); e != nil {
		t.Fatalf("artifact-upload over a freshly provisioned fixture: %v", e)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Fatalf("the smoke left residue in the temp directory: %v", left)
	}
	if e = os.RemoveAll(filepath.Dir(first)); e != nil {
		t.Fatal(e)
	}
	// The sibling run is untouched by the first run's upload and removal, and is still usable.
	if _, _, e = readArtifactSmokeConfig(second); e != nil {
		t.Fatalf("removing one run damaged another: %v", e)
	}
	if e = os.RemoveAll(filepath.Dir(second)); e != nil {
		t.Fatal(e)
	}
	if entries, _ = os.ReadDir(base); len(entries) != 0 {
		t.Fatalf("residue after removing every run: %v", entries)
	}
}

func readArtifactUploadReport(t *testing.T, dir string) map[string]json.RawMessage {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(dir, "artifact-upload.json"))
	if e != nil {
		t.Fatal(e)
	}
	var report map[string]json.RawMessage
	if e = json.Unmarshal(raw, &report); e != nil {
		t.Fatal(e)
	}
	return report
}

// 10.18#6 and #7: a real artifact-upload run (killed child, resume over HTTP) over the provisioned
// fixture performs the explicit `sources` read of a source_content manifest, and a live artifact-read
// token of another organization is denied for this organization's map and sources.
func TestArtifactUploadRealRunReadsSourcesAndDeniesOtherOrg(t *testing.T) {
	fixture := provisionArtifactFixture(t, t.TempDir())
	_, m, e := readArtifactSmokeConfig(fixture)
	if e != nil {
		t.Fatal(e)
	}
	if !m.SourceContent {
		t.Fatal("provisioned manifest must declare source_content")
	}
	out := t.TempDir()
	if e = runArtifactUpload([]string{"--fixture-config", fixture, "--artifact-dir", out, "--require-source-content"}); e != nil {
		t.Fatalf("real artifact-upload run: %v", e)
	}
	report := readArtifactUploadReport(t, out)
	for _, name := range []string{"sources_read", "other_org_denied", "other_org_credential_live", "killed_after_bytes", "orphan_denied", "same_cursors"} {
		var v bool
		if e = json.Unmarshal(report[name], &v); e != nil || !v {
			t.Fatalf("report %s = %s, want true", name, report[name])
		}
	}
	var status int
	if e = json.Unmarshal(report["other_org_sources_status"], &status); e != nil || status != 401 && status != 403 && status != 404 {
		t.Fatalf("other_org_sources_status = %s, want a refusal", report["other_org_sources_status"])
	}
	var retained uint64
	if e = json.Unmarshal(report["retained_bytes"], &retained); e != nil || retained < 2*model.ArtifactFragmentLimit+1 {
		t.Fatalf("retained_bytes = %s, want a multi-fragment map", report["retained_bytes"])
	}
}

// 10.18#6: --require-source-content refuses a manifest without source_content instead of passing
// without an explicit sources read.
func TestArtifactUploadRequireSourceContentRefusesAManifestWithoutIt(t *testing.T) {
	fixture := provisionArtifactFixture(t, t.TempDir())
	_, m, e := readArtifactSmokeConfig(fixture)
	if e != nil {
		t.Fatal(e)
	}
	m.SourceContent = false
	raw, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	c, _, _ := readArtifactSmokeConfig(fixture)
	if e = os.WriteFile(c.ManifestFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	e = runArtifactUpload([]string{"--fixture-config", fixture, "--artifact-dir", t.TempDir(), "--require-source-content"})
	if e == nil || !strings.Contains(e.Error(), "source_content") {
		t.Fatalf("want a source_content refusal, got %v", e)
	}
}
