// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceDataDirRestoresContentAndModes(t *testing.T) {
	backup, live := t.TempDir(), t.TempDir()
	os.MkdirAll(filepath.Join(backup, "raft"), 0o700)
	os.WriteFile(filepath.Join(backup, "control.db"), []byte("old"), 0o600)
	os.WriteFile(filepath.Join(backup, "raft", "log"), []byte("entries"), 0o600)
	os.WriteFile(filepath.Join(live, "control.db"), []byte("new"), 0o600)
	os.WriteFile(filepath.Join(live, "extra.db"), []byte("written by the new build"), 0o600)
	if err := replaceDataDir(live, backup); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(live, "control.db")); string(b) != "old" {
		t.Fatalf("control.db %q", b)
	}
	if _, err := os.Stat(filepath.Join(live, "extra.db")); err == nil {
		t.Fatal("a file the new build wrote survived the rollback")
	}
	if info, err := os.Stat(filepath.Join(live, "raft", "log")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("raft/log: %v %v", info, err)
	}
}

func TestUntarGzRefusesMembersOutsideThePackageDirectory(t *testing.T) {
	for _, name := range []string{"other/file", "package/../../escape"} {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		tw.WriteHeader(&tar.Header{Name: name, Size: 1, Mode: 0o644, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
		tw.Close()
		gz.Close()
		p := filepath.Join(t.TempDir(), "x.tgz")
		os.WriteFile(p, buf.Bytes(), 0o644)
		if err := untarGz(p, t.TempDir()); err == nil || !strings.Contains(err.Error(), "unexpected member") {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
}

func TestRunUpgradeRollbackRefusesMissingReleases(t *testing.T) {
	if err := RunUpgradeRollback([]string{"--artifact-dir", t.TempDir()}); err == nil {
		t.Fatal("missing releases must be refused")
	}
}

// The produced-artifact tests need release directories made by `go run ./build release` (two different
// versions) and, for the matrix, `go run ./build artifacts`; they are skipped without them.
func TestUpgradeRollbackOfProducedBinaries(t *testing.T) {
	oldRel, newRel := os.Getenv("SOUNDPOST_UPGRADE_OLD_RELEASE"), os.Getenv("SOUNDPOST_UPGRADE_NEW_RELEASE")
	if oldRel == "" || newRel == "" {
		t.Skip("set SOUNDPOST_UPGRADE_OLD_RELEASE and SOUNDPOST_UPGRADE_NEW_RELEASE to release directories")
	}
	dir := t.TempDir()
	if err := RunUpgradeRollback([]string{"--artifact-dir", dir, "--old-release", oldRel, "--new-release", newRel}); err != nil {
		t.Fatal(err)
	}
	if out := os.Getenv("SOUNDPOST_UPGRADE_REPORT"); out != "" {
		raw, _ := os.ReadFile(filepath.Join(dir, "upgrade-rollback.json"))
		os.WriteFile(out, raw, 0o644)
	}
}

func TestFreshInstallMatrixOfProducedArtifacts(t *testing.T) {
	rel, art := os.Getenv("SOUNDPOST_MATRIX_RELEASE"), os.Getenv("SOUNDPOST_MATRIX_ARTIFACTS")
	if rel == "" || art == "" {
		t.Skip("set SOUNDPOST_MATRIX_RELEASE and SOUNDPOST_MATRIX_ARTIFACTS")
	}
	dir := t.TempDir()
	err := RunFreshInstallMatrix([]string{"--artifact-dir", dir, "--release", rel, "--artifacts", art, "--root", "../.."})
	if out := os.Getenv("SOUNDPOST_MATRIX_REPORT"); out != "" {
		raw, _ := os.ReadFile(filepath.Join(dir, "fresh-install-matrix.json"))
		os.WriteFile(out, raw, 0o644)
	}
	if err != nil {
		t.Fatal(err)
	}
}
