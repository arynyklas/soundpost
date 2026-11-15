//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func TestTargetIdentity(t *testing.T) {
	target, e := ResolveLocalTarget(os.Getpid())
	if e != nil {
		t.Fatal(e)
	}
	target.ProcessStart++
	if h, e := openCheckedTarget(target); e == nil {
		h.Close()
		t.Fatal("stale identity accepted")
	}
	target.ProcessStart--
	target.PIDNamespace++
	if h, e := openCheckedTarget(target); e == nil {
		h.Close()
		t.Fatal("foreign namespace accepted")
	}
}
func TestTargetIdentityRejectsCgroupTraversal(t *testing.T) {
	for _, b := range []string{"0::/../escape\n", "0::/a/../../escape\n", "not-a-cgroup"} {
		if _, e := cgroupIdentity([]byte(b)); e == nil {
			t.Fatal("accepted traversal")
		}
	}
}

// targetFixture is a real child process started from a private copy of a system ELF, with the checked identity the helper
// would be authorized for (build ID of the copy, the child's own cgroup inode).
type targetFixture struct {
	pid    int
	exe    string
	target Target
}

func startTargetFixture(t *testing.T, source string) targetFixture {
	t.Helper()
	data, e := os.ReadFile(source)
	if e != nil {
		t.Skipf("NOT run: %v", e)
	}
	exe := filepath.Join(t.TempDir(), "target")
	if e = os.WriteFile(exe, data, 0o700); e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(exe, "60")
	if e = cmd.Start(); e != nil {
		t.Skipf("NOT run: cannot start %s: %v", source, e)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	target, e := ResolveLocalTarget(cmd.Process.Pid)
	if e != nil {
		t.Skipf("NOT run: target identity unavailable: %v", e)
	}
	cg, e := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup")
	if e != nil {
		t.Fatal(e)
	}
	inode, e := cgroupIdentity(cg)
	if e != nil {
		t.Skipf("NOT run: cgroup v2 identity unavailable: %v", e)
	}
	target.CgroupID = model.Uint64(inode)
	target.AllowedBuildIDs = []string{fileBuildID(t, exe)}
	return targetFixture{pid: cmd.Process.Pid, exe: exe, target: target}
}

func fileBuildID(t *testing.T, path string) string {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Skipf("NOT run: %v", e)
	}
	defer f.Close()
	id, e := executableBuildID(f)
	if e != nil {
		t.Skipf("NOT run: %s has no GNU build ID: %v", path, e)
	}
	return id
}

// The executable is checked through the kernel's /proc/<pid>/exe link: a target that swaps its own on-disk path for a symlink to
// another ELF (the file it was started from, or a path it controls) can neither redirect the checked executable nor launder
// the build-ID check; the handle keeps pointing at the inode the process really runs.
func TestTargetExePathSwapToSymlinkIsRefused(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	other := "/usr/bin/true"
	otherID := fileBuildID(t, other)
	if otherID == fx.target.AllowedBuildIDs[0] {
		t.Skip("NOT run: the two system binaries share a build ID")
	}
	h, e := openCheckedTarget(fx.target)
	if e != nil {
		t.Fatalf("unswapped target refused: %v", e)
	}
	var running syscall.Stat_t
	if e = syscall.Fstat(int(h.exe.Fd()), &running); e != nil {
		t.Fatal(e)
	}
	h.Close()
	// Swap: the executable's path now resolves to a different ELF through a symlink.
	if e = os.Rename(fx.exe, fx.exe+".moved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(other, fx.exe); e != nil {
		t.Fatal(e)
	}
	var swapped syscall.Stat_t
	if e = syscall.Stat(fx.exe, &swapped); e != nil {
		t.Fatal(e)
	}
	if swapped.Ino == running.Ino && swapped.Dev == running.Dev {
		t.Fatal("test setup: swapped path still names the running inode")
	}
	// Authorized for the swapped-in binary only: the running process is not it, so the check refuses.
	forged := fx.target
	forged.AllowedBuildIDs = []string{otherID}
	if h, e = openCheckedTarget(forged); e == nil {
		h.Close()
		t.Fatal("path swap laundered the build-ID check")
	} else if !errors.Is(e, ErrTargetIdentity) {
		t.Fatalf("refused with %v, want the target identity error", e)
	}
	// Authorized for what actually runs: still accepted, and the handle names the running inode, not the swapped one.
	h, e = openCheckedTarget(fx.target)
	if e != nil {
		t.Fatalf("swap broke the genuine target: %v", e)
	}
	defer h.Close()
	var checked syscall.Stat_t
	if e = syscall.Fstat(int(h.exe.Fd()), &checked); e != nil {
		t.Fatal(e)
	}
	if checked.Ino != running.Ino || checked.Dev != running.Dev {
		t.Fatal("checked executable followed the swapped path")
	}
}

// /proc metadata is read relative to a directory FD with O_NOFOLLOW: a symlink in the place of `cgroup` (or any metadata file) is
// refused instead of followed to a file the target or another user chose.
func TestProcMetadataSymlinkSwapIsRefused(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "real"), []byte("0::/real\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(filepath.Join(dir, "real"), filepath.Join(dir, "cgroup")); e != nil {
		t.Fatal(e)
	}
	fd, e := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer syscall.Close(fd)
	if b, e := readProcMetadata(fd, "cgroup"); e == nil {
		t.Fatalf("followed a symlink: %q", b)
	}
	if b, e := readProcMetadata(fd, "real"); e != nil || string(b) != "0::/real\n" {
		t.Fatalf("regular metadata file unreadable: %q %v", b, e)
	}
	// The same through a swap after a first successful read.
	if e = os.Remove(filepath.Join(dir, "real")); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "elsewhere"), []byte("0::/elsewhere\n"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(dir, "real")); e != nil {
		t.Fatal(e)
	}
	if _, e = readProcMetadata(fd, "real"); e == nil {
		t.Fatal("followed a symlink swapped in after a successful read")
	}
}
