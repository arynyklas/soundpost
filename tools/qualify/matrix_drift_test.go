// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package qualify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/releaseevidence"
)

// qualification/matrix.yaml is hand-maintained (07.06-W8): no generator is committed, and the
// native section is the only expanded part (LoadMatrix). These tests are its drift guard: what a
// hand edit can silently break is the link between a build, the rows that exercise it and the ids
// the reports and the release gate quote.

func TestMatrixDeclaresItselfHandMaintained(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "HAND-MAINTAINED: there is no generator") {
		t.Fatal("matrix.yaml must say that it is hand-maintained and has no generator, so nobody looks for one")
	}
}

// A build key names its platform; a key that disagrees with the build it points at is a copy-paste
// drift that would make an arm64 row probe an amd64 binary (or the reverse).
func TestMatrixBuildKeysAgreeWithTheirBuilds(t *testing.T) {
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for key, b := range m.Builds {
		if !strings.HasPrefix(key, b.Family+"-") || !strings.HasSuffix(key, "-"+b.OS+"-"+b.Arch) {
			t.Errorf("build key %q disagrees with its family/os/arch %s/%s/%s", key, b.Family, b.OS, b.Arch)
			continue
		}
		middle := strings.TrimSuffix(strings.TrimPrefix(key, b.Family+"-"), "-"+b.OS+"-"+b.Arch)
		if middle == "" || !strings.HasPrefix(b.Version, middle) {
			t.Errorf("build key %q does not carry the version %q", key, b.Version)
		}
	}
}

// Every SDK runtime row's id is its build key with the platform separated by a dot, so a report
// line, the evidence envelope and the matrix agree on which build a row is.
func TestMatrixSDKProfileRowIDsEncodeTheirBuild(t *testing.T) {
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, r := range m.Rows {
		if r.Runner != "sdk_profile" {
			continue
		}
		b := m.Builds[r.Build]
		want := "runtime." + strings.TrimSuffix(r.Build, "-"+b.OS+"-"+b.Arch) + "." + b.OS + "-" + b.Arch
		if r.ID != want {
			t.Errorf("row %s runs build %s: its id must be %s", r.ID, r.Build, want)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no sdk_profile row: the guard is vacuous")
	}
}

// A build that is in release scope and that no row exercises or needs is dead weight today and a
// silent gap tomorrow: either a row names it or the build is removed.
func TestMatrixEveryInScopeBuildIsUsedByARow(t *testing.T) {
	m, err := LoadMatrix(filepath.Join(repoRoot(t), "qualification", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{}
	for _, r := range m.Rows {
		used[r.Build] = true
		for _, n := range r.Needs {
			used[n] = true
		}
	}
	for key, b := range m.Builds {
		if releaseevidence.InReleasePlatforms(m.ReleasePlatforms, b.OS+"/"+b.Arch) && !used[key] {
			t.Errorf("build %s is in release scope and no row names it", key)
		}
	}
}
