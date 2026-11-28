//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// ociTestEnv selects the real-runtime sweep test. There is exactly one way to not
// run it: set it to `skip:<reason>` (the reason is logged). Unset or anything else
// is a failure, never a silent pass: `run` needs SOUNDPOST_SYMBOLICATE_TEST_CONFIG
// to name a private OCI config (mode "oci", the operator's runtime and pinned image).
const ociTestEnv = "SOUNDPOST_SYMBOLICATE_TEST_OCI"

func realOCIConfig(t *testing.T) Config {
	t.Helper()
	v := os.Getenv(ociTestEnv)
	if reason, ok := strings.CutPrefix(v, "skip:"); ok && strings.TrimSpace(reason) != "" {
		t.Skipf("real OCI runtime test skipped explicitly: %s", reason)
	}
	if v != "run" {
		t.Fatalf("real OCI runtime test is not configured: set %s=run and SOUNDPOST_SYMBOLICATE_TEST_CONFIG=<private oci config>, or %s=skip:<reason>", ociTestEnv, ociTestEnv)
	}
	name := os.Getenv("SOUNDPOST_SYMBOLICATE_TEST_CONFIG")
	if name == "" {
		t.Fatalf("%s=run needs SOUNDPOST_SYMBOLICATE_TEST_CONFIG", ociTestEnv)
	}
	b, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	var c Config
	if json.Unmarshal(b, &c) != nil || c.Mode != "oci" {
		t.Fatalf("%s=run needs a config with mode \"oci\"", ociTestEnv)
	}
	return c
}

// sweepRow is the one `ps` row of the named container, in the exact format
// SweepOCI itself reads.
func sweepRow(t *testing.T, c Config, name string) []string {
	t.Helper()
	out, e := exec.Command(c.OCIRuntime, "ps", "-a", "--no-trunc", "--filter", "name="+name, "--format", "{{.ID}}|{{.Names}}|{{.State}}|{{.CreatedAt}}|{{.Image}}").Output()
	if e != nil {
		t.Fatalf("ps: %v", e)
	}
	var rows [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.SplitN(l, "|", 5); len(f) == 5 && f[1] == name {
			rows = append(rows, f)
		}
	}
	if len(rows) == 0 {
		return nil
	}
	if len(rows) != 1 {
		t.Fatalf("container %s listed %d times", name, len(rows))
	}
	return rows[0]
}

// sweepScenario creates a real `created`-state worker container (never started),
// proves a young one survives SweepOCI, ages it with ageIt, and proves SweepOCI
// then removes exactly it by ID.
func sweepScenario(t *testing.T, c Config, ageIt func(name string)) {
	t.Helper()
	name := "soundpost-symbolicate-" + model.NewID().String()
	if out, e := exec.Command(c.OCIRuntime, "create", "--name", name, c.OCIImage).CombinedOutput(); e != nil {
		t.Fatalf("create: %v: %s", e, out)
	}
	t.Cleanup(func() { exec.Command(c.OCIRuntime, "rm", "--force", name).Run() })
	row := sweepRow(t, c, name)
	if row == nil || row[2] != "created" || row[4] != c.OCIImage {
		t.Fatalf("not a created-state container of the pinned image: %q", row)
	}
	id := row[0]
	for _, r := range SweepOCI(context.Background(), c).Removed {
		if r == id {
			t.Fatalf("a container younger than %s was swept", sweepMinAge)
		}
	}
	if sweepRow(t, c, name) == nil {
		t.Fatal("young container vanished")
	}
	ageIt(name)
	removed := SweepOCI(context.Background(), c).Removed
	found := false
	for _, r := range removed {
		found = found || r == id
	}
	if !found {
		t.Fatalf("aged created-state container %s not removed; sweep removed %q", id, removed)
	}
	if sweepRow(t, c, name) != nil {
		t.Fatal("container still listed after the sweep")
	}
}

// The real runtime: needs a container runtime and the pinned image, and waits out
// the real 30 s minimum age.
func TestActualSweepOCIRemovesAgedCreatedContainer(t *testing.T) {
	c := realOCIConfig(t)
	sweepScenario(t, c, func(string) { time.Sleep(sweepMinAge + 3*time.Second) })
}

// The same scenario against a stateful stand-in runtime that keeps containers as
// files and backdates one on request. This proves the scenario and SweepOCI's age,
// state and ID handling; it is not evidence about a real daemon.
func TestSweepOCIScenarioAgainstStatefulRuntime(t *testing.T) {
	dir := t.TempDir()
	image := "sha256:" + strings.Repeat("c", 64)
	if e := os.Mkdir(filepath.Join(dir, "c"), 0o700); e != nil {
		t.Fatal(e)
	}
	script := `#!/bin/sh
D='` + dir + `'
echo "$@" >> "$D/argv.log"
case "$1" in
create) n="$3"; date +%s > "$D/c/$n"; echo "id-$n"; exit 0;;
ps)
  want=""
  for a in "$@"; do case "$a" in name=*) want="${a#name=}";; esac; done
  for f in "$D"/c/*; do
    [ -e "$f" ] || continue
    n="$(basename "$f")"
    case "$n" in *"$want"*) ;; *) continue;; esac
    echo "id-$n|$n|created|$(date -d "@$(cat "$f")" '+%Y-%m-%d %H:%M:%S %z %Z')|` + image + `"
  done
  exit 0;;
rm)
  n="$(echo "$@" | sed 's/^rm //; s/^--force //; s/^id-//')"
  if [ -e "$D/c/$n" ]; then rm -f "$D/c/$n"; exit 0; fi
  exit 1;;
esac
exit 2
`
	rt := filepath.Join(dir, "runtime")
	if e := os.WriteFile(rt, []byte(script), 0o700); e != nil {
		t.Fatal(e)
	}
	c := Config{Mode: "oci", OCIRuntime: rt, OCIImage: image, WorkerSHA256: model.HashCanonical([]byte("x"))}
	sweepScenario(t, c, func(name string) {
		old := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
		if e := os.WriteFile(filepath.Join(dir, "c", name), []byte(old), 0o600); e != nil {
			t.Fatal(e)
		}
	})
}

// workerContainers lists the names of every worker container (any state) of the
// runtime.
func workerContainers(t *testing.T, c Config) map[string]bool {
	t.Helper()
	out, e := exec.Command(c.OCIRuntime, "ps", "-a", "--no-trunc", "--filter", "name=soundpost-symbolicate-", "--format", "{{.Names}}").Output()
	if e != nil {
		t.Fatalf("ps: %v", e)
	}
	names := map[string]bool{}
	for _, l := range strings.Fields(string(out)) {
		names[l] = true
	}
	return names
}

// OCI symbolication through the real runtime and the pinned image (the launcher
// is the current one, not a stand-in): every position of the batch resolves to
// its own line, within the parent's wall bound, and the run leaves no container.
func TestActualOCISymbolicationResolvesABatchAndLeavesNoContainer(t *testing.T) {
	c := realOCIConfig(t)
	before := workerContainers(t, c)
	s, err := New(&unusedReader{}, unusedGenerations{}, c)
	if err != nil {
		t.Fatal(err)
	}
	lines := []uint32{1, 5, 7, 12}
	start := time.Now()
	got := s.run(context.Background(), batchInput(lineMap(20), lines...))
	t.Logf("real OCI batch of %d positions answered in %s", len(lines), time.Since(start))
	if len(got) != len(lines) {
		t.Fatalf("%d answers for %d positions: %+v", len(got), len(lines), got)
	}
	for i, l := range lines {
		if got[i].Reason != Resolved || got[i].Position == nil || got[i].Position.Line != l || got[i].Position.Source != "a.ts" {
			t.Fatalf("position %d (line %d): %+v", i, l, got[i])
		}
	}
	removeRetries.Wait()
	for name := range workerContainers(t, c) {
		if !before[name] {
			t.Errorf("worker container %s left behind", name)
		}
	}
}
