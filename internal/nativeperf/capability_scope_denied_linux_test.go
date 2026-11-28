//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The scope Probe reports where the scheduler read is DENIED (not merely unsupported) - l4w33 mutation battery C026.
//
// Root inside a user namespace that maps an unprivileged host user is the one place the Denied branch is reachable
// without a host that refuses perf to its own root: the CPU events still open (the process owns itself and
// perf_event_paranoid allows it), the scheduler tracepoints are system-wide and tracefs refuses the namespace's root.
// The probe must then report the target-only scope: the system-wide scheduler read was never opened.

const probeDeniedChildEnv = "L4W33_PROBE_DENIED_CHILD"

// TestProbeDeniedChild is the body the user-namespace re-execution of the next test runs; it does nothing otherwise.
func TestProbeDeniedChild(t *testing.T) {
	if os.Getenv(probeDeniedChildEnv) == "" {
		t.Skip("helper of TestProbeScopeIsTargetOnlyWhereTheSchedulerReadIsDeniedInAUserNamespace")
	}
	target, e := ResolveLocalTarget(os.Getpid())
	if e != nil {
		t.Skipf("local target unresolved: %v", e)
	}
	caps, err := Probe(context.Background(), []Target{target})
	t.Logf("PROBE_DENIED cpu=%s off_cpu=%s scope=%s err=%v", caps.CPU, caps.OffCPU, caps.AcquisitionScope, err)
	if caps.OffCPU == Supported {
		t.Fatalf("the scheduler read opened inside the namespace (off_cpu %s): nothing was refused", caps.OffCPU)
	}
	if caps.AcquisitionScope != model.AcquisitionScopeTargetOnly {
		t.Fatalf("scope %q with off_cpu %s, want %q: a scheduler read that never opened is not a system-wide one", caps.AcquisitionScope, caps.OffCPU, model.AcquisitionScopeTargetOnly)
	}
	if e := caps.Validate(); e != nil {
		t.Fatalf("probe evidence invalid: %v", e)
	}
}

func TestProbeScopeIsTargetOnlyWhereTheSchedulerReadIsDeniedInAUserNamespace(t *testing.T) {
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("SKIPPED: no unshare(1): %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	dir, err := os.MkdirTemp("", "probe-denied")
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
	// unshare maps the calling user to root of the new namespace: a host root would stay root of the host (tracefs is
	// readable to it), so it first becomes nobody
	cmd := exec.Command(unshare, "--user", "--map-root-user", child, "-test.run=^TestProbeDeniedChild$", "-test.v", "-test.count=1")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), probeDeniedChildEnv+"=1")
	if os.Getuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil && !strings.Contains(text, "PROBE_DENIED") {
		t.Skipf("SKIPPED: a user namespace cannot be entered here (%v):\n%s", err, text)
	}
	if err != nil {
		t.Fatalf("the probe inside the user namespace failed: %v\n%s", err, text)
	}
	if !strings.Contains(text, "PROBE_DENIED") {
		t.Skipf("SKIPPED: the probe inside the user namespace reported nothing:\n%s", text)
	}
	report := strings.TrimSpace(text[strings.Index(text, "PROBE_DENIED"):])
	if i := strings.IndexByte(report, '\n'); i >= 0 {
		report = report[:i]
	}
	if !strings.Contains(report, "off_cpu=denied") {
		t.Skipf("SKIPPED: the scheduler read was not DENIED inside the namespace, the branch under test was not reached: %s", report)
	}
	t.Log(report)
}
