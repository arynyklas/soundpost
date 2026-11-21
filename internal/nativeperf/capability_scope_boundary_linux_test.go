//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Pins for the scope Probe reports (l4w33 mutation battery C).

// A probe that fails before it reached the scheduler path still reports the scope of the path it did not open.
func TestProbeFailuresBeforeTheSchedulerPathStayTargetOnly(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	caps, err := Probe(ended, nil)
	if !errors.Is(err, context.Canceled) || caps.AcquisitionScope != model.AcquisitionScopeTargetOnly {
		t.Fatalf("an ended context: scope %q, %v", caps.AcquisitionScope, err)
	}
	caps, err = Probe(context.Background(), nil)
	if err == nil || caps.AcquisitionScope != model.AcquisitionScopeTargetOnly {
		t.Fatalf("no targets: scope %q, %v", caps.AcquisitionScope, err)
	}
	if e := caps.Validate(); e != nil {
		t.Fatalf("%v", e)
	}
}

const probeScopeChildEnv = "L4W33_PROBE_SCOPE_CHILD"

// probeScopeHolds is the whole contract: system-wide exactly where the scheduler read opened. It returns the status
// the probe saw so a caller knows which side of it was exercised.
func probeScopeHolds(t *testing.T) Status {
	t.Helper()
	target, e := ResolveLocalTarget(os.Getpid())
	if e != nil {
		t.Skip("local target unresolved")
	}
	caps, _ := Probe(context.Background(), []Target{target})
	want := model.AcquisitionScopeTargetOnly
	if caps.OffCPU == Supported {
		want = model.AcquisitionScopeSystemWideScheduler
	}
	if caps.AcquisitionScope != want {
		t.Fatalf("scope %q with off_cpu %s, want %q", caps.AcquisitionScope, caps.OffCPU, want)
	}
	if e := caps.Validate(); e != nil {
		t.Fatalf("probe evidence invalid: %v", e)
	}
	return caps.OffCPU
}

// TestProbeScopeChild is the body the unprivileged re-execution of the next test runs; it does nothing otherwise.
func TestProbeScopeChild(t *testing.T) {
	if os.Getenv(probeScopeChildEnv) == "" {
		t.Skip("helper of TestProbeScopeIsTargetOnlyWhereTheSchedulerReadIsRefused")
	}
	t.Logf("PROBE_SCOPE off_cpu=%s", probeScopeHolds(t))
}

// Where the scheduler read is refused (denied, unsupported or failed, not only absent) the scope is target-only. A
// privileged host cannot see that from itself, so the probe runs once more as an unprivileged user.
func TestProbeScopeIsTargetOnlyWhereTheSchedulerReadIsRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Logf("off_cpu %s (this process is the unprivileged one)", probeScopeHolds(t))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	dir, err := os.MkdirTemp("", "probe-scope")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err = os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src, err := os.Open(exe)
	if err != nil {
		t.Skip(err)
	}
	defer src.Close()
	child := filepath.Join(dir, "nativeperf.test")
	dst, err := os.OpenFile(child, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	if err = dst.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(child, "-test.run=^TestProbeScopeChild$", "-test.v", "-test.count=1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), probeScopeChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the unprivileged probe failed: %v\n%s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "SKIP") && !strings.Contains(text, "PROBE_SCOPE") {
		t.Skipf("the unprivileged probe could not run here:\n%s", text)
	}
	if !strings.Contains(text, "PROBE_SCOPE off_cpu=") {
		t.Fatalf("the unprivileged probe reported nothing:\n%s", text)
	}
	t.Log(strings.TrimSpace(text[strings.Index(text, "PROBE_SCOPE"):]))
}
