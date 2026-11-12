//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
)

// fakeDocker is an absolute-path OCIRuntime script that records its argv and
// models just enough of a runtime: `run --name N` registers container N (at once,
// or 0.6 s later like a daemon still working on a request whose client died,
// or never), `rm --force N` removes it or fails when it is absent.
type fakeDocker struct {
	dir    string
	config Config
}

func newFakeDocker(t *testing.T, mode string) *fakeDocker {
	t.Helper()
	d := &fakeDocker{dir: t.TempDir()}
	hash := model.HashCanonical([]byte("fake worker"))
	image := "sha256:" + strings.Repeat("a", 64)
	must := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(d.dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must("mode", []byte(mode))
	must("label", []byte(hash.String()+"\n"))
	must("hello", append([]byte{'R'}, hash[:]...))
	if err := os.Mkdir(filepath.Join(d.dir, "containers"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
D='` + d.dir + `'
echo "$@" >> "$D/argv.log"
case "$1" in
image) cat "$D/label"; exit 0;;
inspect) echo false; exit 0;;
ps) cat "$D/ps.txt"; exit 0;;
rm)
  if [ "$2" = "--force" ]; then n="$3"; else n="$2"; fi
  if [ -e "$D/containers/$n" ]; then rm -f "$D/containers/$n"; exit 0; fi
  exit 1;;
run)
  n="$3"
  case "$(cat "$D/mode")" in
  late) ( sleep 0.6; touch "$D/containers/$n" ) >/dev/null 2>&1 & exec sleep 30;;
  now) touch "$D/containers/$n"; exec sleep 30;;
  fail) exit 125;;
  ok)
    touch "$D/containers/$n"
    dd bs=1 count=1 of=/dev/null 2>/dev/null
    cat "$D/hello"
    cat >/dev/null
    echo '{"reason":"unmapped"}'
    exit 0;;
  esac;;
esac
exit 2
`
	name := filepath.Join(d.dir, "docker")
	if err := os.WriteFile(name, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	d.config = Config{Mode: "oci", OCIRuntime: name, OCIImage: image, WorkerSHA256: hash}
	return d
}

func (d *fakeDocker) argv() []string {
	b, _ := os.ReadFile(filepath.Join(d.dir, "argv.log"))
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

// runName is the container name of the (single) `run` the fake saw.
func (d *fakeDocker) runName(t *testing.T) string {
	t.Helper()
	for _, l := range d.argv() {
		f := strings.Fields(l)
		if len(f) > 3 && f[0] == "run" && f[1] == "--name" {
			return f[2]
		}
	}
	t.Fatalf("no run command recorded: %q", d.argv())
	return ""
}

func (d *fakeDocker) live() []string {
	es, _ := os.ReadDir(filepath.Join(d.dir, "containers"))
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func fastRetries(t *testing.T) {
	t.Helper()
	pe, pb := removeRetryEvery, removeRetryBudget
	removeRetryEvery, removeRetryBudget = 50*time.Millisecond, 2*time.Second
	t.Cleanup(func() { removeRetryEvery, removeRetryBudget = pe, pb })
}

func (d *fakeDocker) service(t *testing.T) *Service {
	t.Helper()
	s, err := New(&unusedReader{}, unusedGenerations{}, d.config)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// assertRemoved waits for any background retries, then requires that the exact
// `rm --force <name>` ran and that no container is left.
func (d *fakeDocker) assertRemoved(t *testing.T) {
	t.Helper()
	removeRetries.Wait()
	name := d.runName(t)
	found := false
	for _, l := range d.argv() {
		if l == "rm --force "+name {
			found = true
		}
	}
	if !found {
		t.Fatalf("`rm --force %s` never ran: %q", name, d.argv())
	}
	if left := d.live(); len(left) != 0 {
		t.Fatalf("container leaked: %v (argv %q)", left, d.argv())
	}
}

func TestOCIContainerIsRemovedOnEveryExit(t *testing.T) {
	fastRetries(t)
	in := workerInput{Version: 1, Line: 1, Column: 0, Map: []byte("{}"), MapHash: model.HashCanonical([]byte("{}"))}
	t.Run("normal success", func(t *testing.T) {
		d := newFakeDocker(t, "ok")
		if got := d.service(t).run(context.Background(), in); got.Reason != Unmapped {
			t.Fatalf("fake worker answer: %+v", got)
		}
		d.assertRemoved(t)
	})
	t.Run("start-time failure of the run command", func(t *testing.T) {
		d := newFakeDocker(t, "fail")
		if got := d.service(t).run(context.Background(), in); got.Reason == Resolved {
			t.Fatalf("answer %+v", got)
		}
		removeRetries.Wait()
		name := d.runName(t)
		saw := false
		for _, l := range d.argv() {
			saw = saw || l == "rm --force "+name
		}
		if !saw {
			t.Fatalf("no remove attempted after a failed run: %q", d.argv())
		}
	})
	t.Run("request deadline expires mid-run, container exists", func(t *testing.T) {
		d := newFakeDocker(t, "now")
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		start := time.Now()
		if got := d.service(t).run(ctx, in); got.Reason != Deadline && got.Reason != SandboxUnavailable {
			t.Fatalf("answer %+v", got)
		}
		if took := time.Since(start); took > 4*time.Second {
			t.Fatalf("run held %s past an expired request", took)
		}
		// run (and so the service slot it is called under) returns only after the
		// client was killed, reaped AND the container removed: no wait for retries.
		if left := d.live(); len(left) != 0 {
			t.Fatalf("run returned before the container was removed: %v", left)
		}
		d.assertRemoved(t)
	})
	t.Run("run timed out before the daemon created the container", func(t *testing.T) {
		d := newFakeDocker(t, "late")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		d.service(t).run(ctx, in)
		// The first remove finds nothing; the container appears 0.6 s after the
		// client died. It must still end up removed.
		time.Sleep(900 * time.Millisecond)
		d.assertRemoved(t)
	})
	t.Run("probe launch, client killed before the daemon created it", func(t *testing.T) {
		d := newFakeDocker(t, "late")
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		if r := Probe(ctx, d.config, ProbeFile); r.Reason == Resolved {
			t.Fatalf("probe %+v", r)
		}
		time.Sleep(900 * time.Millisecond)
		d.assertRemoved(t)
	})
}

func TestSweepRemovesOnlyExactMatchingContainersByID(t *testing.T) {
	d := newFakeDocker(t, "ok")
	old := time.Now().Add(-time.Hour).Format("2006-01-02 15:04:05 -0700 MST")
	young := time.Now().Add(-time.Second).Format("2006-01-02 15:04:05 -0700 MST")
	hex := strings.Repeat("ab", 16)
	rows := []string{
		"id-exited|soundpost-symbolicate-" + hex + "|exited|" + old + "|" + d.config.OCIImage,
		"id-created|soundpost-symbolicate-" + hex + "|created|" + old + "|" + d.config.OCIImage,
		"id-running|soundpost-symbolicate-" + hex + "|running|" + old + "|" + d.config.OCIImage,
		"id-young|soundpost-symbolicate-" + hex + "|created|" + young + "|" + d.config.OCIImage,
		"id-otherimage|soundpost-symbolicate-" + hex + "|exited|" + old + "|sha256:" + strings.Repeat("b", 64),
		"id-prefix|other-soundpost-symbolicate-" + hex + "|exited|" + old + "|" + d.config.OCIImage,
		"id-shortname|soundpost-symbolicate-abc|exited|" + old + "|" + d.config.OCIImage,
		"id-suffix|soundpost-symbolicate-" + hex + "-x|exited|" + old + "|" + d.config.OCIImage,
		"id-other|someone-elses-db|exited|" + old + "|" + d.config.OCIImage,
		"id-baddate|soundpost-symbolicate-" + hex + "|exited|yesterday|" + d.config.OCIImage,
	}
	if err := os.WriteFile(filepath.Join(d.dir, "ps.txt"), []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	SweepOCI(context.Background(), d.config)
	var rms []string
	for _, l := range d.argv() {
		if strings.HasPrefix(l, "rm ") {
			rms = append(rms, l)
		}
	}
	// the fake removes only containers it knows, so success is judged by argv
	want := []string{"rm id-exited", "rm id-created"}
	if strings.Join(rms, ",") != strings.Join(want, ",") {
		t.Fatalf("removed %q, want exactly %q (argv %q)", rms, want, d.argv())
	}
	ps := d.argv()[0]
	if !strings.Contains(ps, "ps -a --no-trunc --filter ancestor="+d.config.OCIImage+" --filter name=soundpost-symbolicate-") || strings.Contains(strings.Join(d.argv(), "\n"), "prune") || strings.Contains(strings.Join(d.argv(), "\n"), "--force") {
		t.Fatalf("unexpected runtime invocations: %q", d.argv())
	}
	if got := SweepOCI(context.Background(), Config{Mode: "native"}); got != nil {
		t.Fatal("native mode swept")
	}
}
