//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// stagedGroup is a nativeGroup over a plain directory with a release pipe, as
// stage() leaves it, so attach's write and read-back of cgroup.procs can be driven
// without a delegated cgroup.
func stagedGroup(t *testing.T) *nativeGroup {
	t.Helper()
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	g := &nativeGroup{path: t.TempDir(), releaseR: r, releaseW: w}
	t.Cleanup(func() { r.Close(); w.Close() })
	return g
}

// released reports whether the release byte reached the staging process's end.
func released(t *testing.T, g *nativeGroup) bool {
	t.Helper()
	g.releaseR.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	var b [1]byte
	n, _ := g.releaseR.Read(b[:])
	return n == 1
}

// Fault injection: the kernel accepts the write to cgroup.procs but the process is
// not listed afterwards (a migration that silently did not happen, or happened to
// another group). The read-back must refuse and the worker must stay blocked; with
// the read-back removed the worker would be released outside the limited group.
func TestAttachRefusesAndWithholdsReleaseWhenReadBackDoesNotListThePid(t *testing.T) {
	g := stagedGroup(t)
	// A write to /dev/null always succeeds and reads back empty.
	if e := os.Symlink(os.DevNull, filepath.Join(g.path, "cgroup.procs")); e != nil {
		t.Fatal(e)
	}
	if e := g.attach(os.Getpid()); e == nil {
		t.Fatal("attach succeeded although the pid is not in the group's cgroup.procs")
	}
	if released(t, g) {
		t.Fatal("the staged worker was released although the migration was not verified")
	}
	if g.releaseW == nil {
		t.Fatal("the release end was consumed by a refused attach")
	}
}

// A group that lists only other pids (or a pid that merely starts with ours) is not
// membership.
func TestMemberRequiresTheExactPid(t *testing.T) {
	g := stagedGroup(t)
	pid := 4242
	for _, listing := range []string{"", "1\n2\n", "424\n42420\n", strconv.Itoa(pid) + "7\n"} {
		if e := os.WriteFile(filepath.Join(g.path, "cgroup.procs"), []byte(listing), 0o600); e != nil {
			t.Fatal(e)
		}
		if g.member(pid) == nil {
			t.Fatalf("pid %d accepted from listing %q", pid, listing)
		}
	}
	if e := os.WriteFile(filepath.Join(g.path, "cgroup.procs"), []byte("1\n4242\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := g.member(pid); e != nil {
		t.Fatalf("listed pid refused: %v", e)
	}
}

// The success path: written, read back, then exactly one release byte.
func TestAttachReleasesOnlyAfterTheReadBackConfirms(t *testing.T) {
	g := stagedGroup(t)
	if e := g.attach(os.Getpid()); e != nil {
		t.Fatal(e)
	}
	if !released(t, g) {
		t.Fatal("a verified worker was not released")
	}
	if g.releaseW != nil {
		t.Fatal("the release end stayed open after the release")
	}
}
