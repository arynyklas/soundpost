// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A member upgraded from a chart that used the volume root as its data directory would start with
// a fresh control state in the old engine directory (the new data/) while its control.db and raft/
// sit one level up. serve refuses that, before it creates or changes anything, and only for the one
// layout that has this history.
func TestServeRefusesADataDirectoryOnTheOldVolumeRootLayout(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, root string)
		dir  string // relative to the volume root
		want bool   // refused
	}{
		{"a fresh volume", func(t *testing.T, root string) {}, "data", false},
		{"the volume root holds control.db", func(t *testing.T, root string) { mustWrite(t, filepath.Join(root, "control.db")) }, "data", true},
		{"the volume root holds raft/", func(t *testing.T, root string) { mustWrite(t, filepath.Join(root, "raft", "control", "ready.wal")) }, "data", true},
		{"the old layout as the previous chart left it: control.db, raft/ and the engine's data/ at the volume root", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "control.db"))
			mustWrite(t, filepath.Join(root, "raft", "control", "ready.wal"))
			mustWrite(t, filepath.Join(root, "data", "apply.db"))
		}, "data", true},
		{"a stale copy beside a data/ that already holds the member", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "control.db"))
			mustWrite(t, filepath.Join(root, "data", "control.db"))
		}, "data", true},
		{"after the move: only data/ holds the member's files", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "data", "control.db"))
			mustWrite(t, filepath.Join(root, "data", "raft", "control", "ready.wal"))
		}, "data", false},
		{"unrelated files at the volume root", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "lost+found", "x"))
		}, "data", false},
		{"a data directory not named data is not judged", func(t *testing.T, root string) { mustWrite(t, filepath.Join(root, "control.db")) }, "state", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			tc.set(t, root)
			dir := filepath.Join(root, tc.dir)
			_, absent := os.Stat(dir)
			err := preparePrivate(dir, "")
			if tc.want {
				if !errors.Is(err, errLegacyVolumeLayout) {
					t.Fatalf("preparePrivate = %v, want errLegacyVolumeLayout", err)
				}
				if absent != nil {
					if _, statErr := os.Stat(dir); !os.IsNotExist(statErr) {
						t.Fatalf("the refusal created the data directory (%v)", statErr)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("preparePrivate = %v, want it admitted", err)
			}
		})
	}
}

// A relative --data-dir is judged by the directory it names, not by its spelling: "data", "." run
// from inside data/, and "../data" from a sibling all name the same directory.
func TestServeJudgesARelativeDataDirectoryByItsVolume(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "control.db"))
	mustWrite(t, filepath.Join(root, "data", "apply.db"))
	mustWrite(t, filepath.Join(root, "sibling", "x"))
	for _, tc := range []struct {
		from, dir string
		want      bool
	}{
		{".", "data", true},
		{"data", ".", true},
		{"sibling", "../data", true},
		{".", "./state", false},
	} {
		t.Run(tc.from+" "+tc.dir, func(t *testing.T) {
			t.Chdir(filepath.Join(root, tc.from))
			err := refuseLegacyVolumeLayout(tc.dir)
			if tc.want != errors.Is(err, errLegacyVolumeLayout) || (!tc.want && err != nil) {
				t.Fatalf("refuseLegacyVolumeLayout(%q) from %q = %v, want refused=%v", tc.dir, tc.from, err, tc.want)
			}
		})
	}
}

// The refusal is what the operator sees: a typed code, no path, exit 1, nothing created. The
// process is bounded: a serve that does not refuse would run forever, and the test must say so
// instead of hanging.
func TestServePrintsTheTypedLegacyVolumeLayoutRefusal(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "control.db"))
	data := filepath.Join(root, "data")
	cmd, lines, stderr := serveChild(t, "--mode=single", "--data-dir", data, "--listen", "127.0.0.1:0")
	defer cmd.Process.Kill()
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		for range lines {
		}
	}()
	select {
	case <-exited:
	case <-time.After(60 * time.Second):
		t.Fatalf("serve did not refuse the old volume-root layout and kept running; stderr:\n%s", stderr.String())
	}
	var exit *exec.ExitError
	if err := cmd.Wait(); !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("serve exited with %v, want exit code 1 (stderr %q)", err, stderr.String())
	}
	out := stderr.String()
	if !strings.Contains(out, "legacy_volume_layout") || !strings.Contains(out, "docs/operations/upgrade.md") {
		t.Fatalf("stderr %q is not the typed refusal", out)
	}
	if strings.Contains(out, root) || strings.Contains(out, "startup or service failed") {
		t.Fatalf("stderr %q names a path or is the generic line", out)
	}
	if _, err := os.Stat(data); !os.IsNotExist(err) {
		t.Fatalf("serve created %s before refusing (%v)", data, err)
	}
}

// The guard judges a directory named data on the volume root. The chart must keep passing exactly
// such a directory, or the guard would silently stop covering it.
func TestChartDataDirIsWhatTheLegacyVolumeLayoutGuardJudges(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "helm", "soundpost", "templates", "statefulset.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	mount := regexp.MustCompile(`name: data, mountPath: (\S+)\}`).FindStringSubmatch(string(raw))
	flag := regexp.MustCompile(`- --data-dir=(\S+)`).FindStringSubmatch(string(raw))
	if mount == nil || flag == nil || !strings.HasPrefix(flag[1], mount[1]+"/") {
		t.Fatalf("data mount %v or --data-dir flag %v not found, or the flag is not inside the mount", mount, flag)
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "control.db"))
	dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(flag[1], mount[1]+"/")))
	if err = refuseLegacyVolumeLayout(dir); !errors.Is(err, errLegacyVolumeLayout) {
		t.Fatalf("the chart's --data-dir=%s on a volume mounted at %s is not covered by the guard: %v", flag[1], mount[1], err)
	}
}

// documentedLayoutMove is the shell block of docs/operations/upgrade.md that moves an old volume
// root into data/, with its volume root replaced by volume.
func documentedLayoutMove(t *testing.T, volume string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "operations", "upgrade.md"))
	if err != nil {
		t.Fatal(err)
	}
	const open = "```sh\ncd /var/lib/soundpost"
	text := string(raw)
	start := strings.Index(text, open)
	if start < 0 {
		t.Fatal("the documented volume-root move is not in docs/operations/upgrade.md")
	}
	block := text[start+len("```sh\n"):]
	end := strings.Index(block, "\n```")
	if end < 0 {
		t.Fatal("the documented volume-root move has no closing fence")
	}
	return strings.Replace(block[:end], "cd /var/lib/soundpost", "cd '"+volume+"'", 1)
}

// The move the upgrade guide documents, run on a directory a real node wrote at the volume root
// (what the previous chart left on each member's claim), yields the layout the chart now uses:
// the guard sees the old layout before and not after, and the member opens its own state from
// data/ (same installation), not a fresh one.
func TestTheDocumentedMoveTurnsTheOldVolumeRootIntoTheNewLayout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	volume := filepath.Join(t.TempDir(), "volume")
	old, err := appcore.Open(volume)
	if err != nil {
		t.Fatal(err)
	}
	var installation model.ID
	err = old.Control.View(context.Background(), func(st control.State) error { installation = st.Installation; return nil })
	old.Close()
	if err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(volume, "data")
	if err = refuseLegacyVolumeLayout(data); !errors.Is(err, errLegacyVolumeLayout) {
		t.Fatalf("a directory a node wrote at the volume root is not recognised as the old layout: %v", err)
	}
	if out, runErr := exec.Command("sh", "-ec", documentedLayoutMove(t, volume)).CombinedOutput(); runErr != nil {
		t.Fatalf("the documented move failed: %v\n%s", runErr, out)
	}
	entries, err := os.ReadDir(volume)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "data" {
		t.Fatalf("after the move the volume root holds %d entries, want only data/", len(entries))
	}
	if err = preparePrivate(data, ""); err != nil {
		t.Fatalf("the moved layout is refused: %v", err)
	}
	moved, err := appcore.Open(data)
	if err != nil {
		t.Fatalf("the member does not open from data/ after the move: %v", err)
	}
	defer moved.Close()
	var after model.ID
	if err = moved.Control.View(context.Background(), func(st control.State) error { after = st.Installation; return nil }); err != nil {
		t.Fatal(err)
	}
	if after != installation {
		t.Fatalf("the moved member is installation %s, want its own %s (a fresh state was created)", after, installation)
	}
}
