//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// A helper without the privilege to inspect another user's process must report a
// genuine permission denial. Task 04.09 measured the engine answering such a
// target with generation_changed (the closed code for a PID-reuse/generation
// change) because identity resolution folded EACCES into ErrInvalid and
// openCheckedTarget folded every failure into ErrTargetIdentity.

const permissionProbeEnv = "SOUNDPOST_PERMISSION_PROBE_TARGET"

// TestPermissionProbeChild runs in the unprivileged child process only.
func TestPermissionProbeChild(t *testing.T) {
	raw := os.Getenv(permissionProbeEnv)
	if raw == "" {
		t.Skip("child-only test")
	}
	var target Target
	if err := json.Unmarshal([]byte(raw), &target); err != nil {
		t.Fatal(err)
	}
	target.AllowedBuildIDs = []string{"00"}
	_, resolveErr := ResolveLocalTarget(int(target.TGID))
	h, openErr := openCheckedTarget(target)
	if h != nil {
		h.Close()
	}
	for name, err := range map[string]error{"ResolveLocalTarget": resolveErr, "openCheckedTarget": openErr} {
		var capability *CapabilityError
		if !errors.As(err, &capability) || capability.Status != Denied || capability.Reason != ReasonPermission {
			t.Errorf("%s of a target owned by another user returned %v, want denied/permission_denied", name, err)
		}
		if errors.Is(err, ErrTargetIdentity) {
			t.Errorf("%s reported a permission denial as a target identity (generation) failure", name)
		}
	}
}

func TestUnprivilegedProcessSeesAForeignTargetAsPermissionDenied(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to start a target and drop privileges in a child")
	}
	sleeper := exec.Command("sleep", "60")
	if err := sleeper.Start(); err != nil {
		t.Skip("cannot start a target: " + err.Error())
	}
	defer func() { sleeper.Process.Kill(); sleeper.Wait() }()
	target, err := ResolveLocalTarget(sleeper.Process.Pid)
	if err != nil {
		t.Skip("target identity unreadable even as root: " + err.Error())
	}
	self, err := os.Executable()
	if err != nil {
		t.Skip("executable path unavailable")
	}
	dir, err := os.MkdirTemp("", "soundpost-permission-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(dir, "nativeperf.test")
	bin, err := os.ReadFile(self)
	if err != nil || os.WriteFile(copyPath, bin, 0o755) != nil {
		t.Skip("cannot stage the test binary for the unprivileged child")
	}
	raw, _ := json.Marshal(target)
	child := exec.Command(copyPath, "-test.run=^TestPermissionProbeChild$", "-test.v")
	child.Env = append(os.Environ(), permissionProbeEnv+"="+string(raw))
	child.Dir = dir
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := child.CombinedOutput()
	text := string(out)
	if err != nil || !strings.Contains(text, "--- PASS: TestPermissionProbeChild") {
		t.Fatalf("unprivileged child (uid 65534, target pid %s owned by root): %v\n%s", strconv.Itoa(sleeper.Process.Pid), err, text)
	}
}
