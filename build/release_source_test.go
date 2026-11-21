// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The gate must not trust the digest release.json recorded: a file under --root changed after
// `build release` makes the recomputed digest differ, so the gate blocks even though release.json
// and every envelope stamp still agree with each other.
func TestGateRefusesATreeThatDiffersFromTheReleaseSourceDigest(t *testing.T) {
	f := newFixture(t)
	if m, _ := Release(context.Background(), testCommit, f.reports()); strings.Contains(strings.Join(m.Blocking, "\n"), "source:") {
		t.Fatalf("the unmodified tree blocks on source: %v", m.Blocking)
	}
	write(t, filepath.Join(f.root, "internal", "a", "a.go"), "package a // edited after release\n")
	m, err := Release(context.Background(), testCommit, f.reports())
	if err == nil || m.Ready {
		t.Fatal("a modified source file passed the gate")
	}
	var found bool
	for _, b := range m.Blocking {
		found = found || (strings.HasPrefix(b, "source: the tree under --root has source digest") && strings.Contains(b, testSource))
	}
	if !found {
		t.Fatalf("modified file not reported as a source digest mismatch: %v", m.Blocking)
	}
}

func gitTree(t *testing.T) (root, head string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root = t.TempDir()
	writeFixtureSources(root)
	for _, args := range [][]string{
		{"init", "-q"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"},
		{"config", "commit.gpgsign", "false"}, {"add", "-A"}, {"commit", "-q", "-m", "base"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return root, strings.TrimSpace(string(out))
}

func TestReleaseDerivesTheCommitFromHeadAndRefusesADifferentOne(t *testing.T) {
	root, head := gitTree(t)
	if got, err := releaseCommit(root, ""); err != nil || got != head {
		t.Fatalf("derived %q %v, want HEAD %s", got, err, head)
	}
	if got, err := releaseCommit(root, head); err != nil || got != head {
		t.Fatalf("explicit HEAD: %q %v", got, err)
	}
	if got, err := releaseCommit(root, testCommit); err == nil || !strings.Contains(err.Error(), "is not HEAD") {
		t.Fatalf("a typed commit that is not HEAD was accepted: %q %v", got, err)
	}
}

func TestReleaseRefusesADirtyDigestedSet(t *testing.T) {
	for name, mutate := range map[string]func(root string){
		"modified source":   func(root string) { write(t, filepath.Join(root, "internal", "a", "a.go"), "package a // dirty\n") },
		"untracked source":  func(root string) { write(t, filepath.Join(root, "cmd", "soundpost", "new.go"), "package main\n") },
		"modified go.mod":   func(root string) { write(t, filepath.Join(root, "go.mod"), "module x\n") },
		"untracked profile": func(root string) { write(t, filepath.Join(root, "profiles", "query", "q.json"), "{}\n") },
	} {
		t.Run(name, func(t *testing.T) {
			root, _ := gitTree(t)
			mutate(root)
			got, err := releaseCommit(root, "")
			if err == nil || !strings.Contains(err.Error(), "dirty tree") {
				t.Fatalf("dirty tree released: %q %v", got, err)
			}
		})
	}
	root, head := gitTree(t)
	write(t, filepath.Join(root, "internal", "a", "a_test.go"), "package a\n")
	write(t, filepath.Join(root, "docs", "note.md"), "outside the digested set\n")
	if got, err := releaseCommit(root, ""); err != nil || got != head {
		t.Fatalf("files outside the digest blocked a release: %q %v", got, err)
	}
}

func TestReleaseWithoutGitRecordsUnknownNeverATypedCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	writeFixtureSources(root)
	if got, err := releaseCommit(root, ""); err != nil || got != "unknown" {
		t.Fatalf("no git: %q %v", got, err)
	}
	if got, err := releaseCommit(root, testCommit); err == nil {
		t.Fatalf("a typed commit was recorded without git: %q", got)
	}
}
