// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"regexp"
	"strings"
	"testing"
)

// The native symbolication worker installs its own seccomp filter, which systemd's
// @system-service group forbids (seccomp(2) is in @sandbox); the unit must allow exactly
// that call and must keep the namespace restriction and the allowlist it extends.
func TestServerUnitAllowsWorkerSeccompWithoutLoosening(t *testing.T) {
	u := deployFile(t, "deploy/systemd/soundpost.service")
	for _, required := range []string{"RestrictNamespaces=yes", "SystemCallFilter=@system-service", "SystemCallFilter=seccomp", "SystemCallErrorNumber=EPERM", "NoNewPrivileges=yes", "SystemCallArchitectures=native"} {
		if !hasLine(u, required) {
			t.Fatalf("server unit lacks %q", required)
		}
	}
	for _, line := range directives(u) {
		if strings.HasPrefix(line, "SystemCallFilter=") && line != "SystemCallFilter=@system-service" && line != "SystemCallFilter=seccomp" {
			t.Fatalf("unexpected syscall allowance: %q", line)
		}
		if strings.HasPrefix(line, "RestrictNamespaces=") && line != "RestrictNamespaces=yes" {
			t.Fatalf("namespace restriction loosened: %q", line)
		}
	}
}

// The credential comment must describe what systemd really does (a 0440 root:root file with
// an ACL for the service user), not promise a mode the key never has.
func TestServerUnitCredentialCommentIsTruthful(t *testing.T) {
	u := deployFile(t, "deploy/systemd/soundpost.service")
	if strings.Contains(u, "0400") {
		t.Fatal("the unit promises a 0400 credential file; systemd materialises 0440 root:root plus an ACL")
	}
	if !strings.Contains(u, "0440") {
		t.Fatal("the unit comment must state the real credential file mode")
	}
}

// A runc-based runtime needs execve and fstatfs after it installs the filter and before the
// container process runs its first instruction (observed: runc 1.4.2 StartError fstatfs, then
// "exec /soundpost: operation not permitted"). The profile allows exactly those two extra
// syscalls unconditionally and must not grow other unconstrained process-control calls.
func TestPerfSeccompProfileAllowsRuntimeStartSyscalls(t *testing.T) {
	text := deployFile(t, "deploy/seccomp/soundpost-perf.json")
	if !strings.Contains(text, `{"names":["execve","fstatfs"],"action":"SCMP_ACT_ALLOW"}`) {
		t.Fatal("profile must allow exactly execve and fstatfs in one unconditional rule")
	}
	for _, banned := range []string{`"execveat"`, `"ptrace"`, `"mount"`, `"setns"`, `"unshare"`, `"bpf"`} {
		if strings.Contains(text, banned) {
			t.Errorf("profile mentions %s", banned)
		}
	}
}

// The data directory must be a subdirectory of the volume: with fsGroup the kubelet makes the
// volume root group-writable and serve refuses to chmod a root it does not own to 0700.
func TestChartDataDirIsNotTheVolumeRoot(t *testing.T) {
	text := deployFile(t, "deploy/helm/soundpost/templates/statefulset.yaml")
	mount := regexp.MustCompile(`name: data, mountPath: (\S+)\}`).FindStringSubmatch(text)
	flag := regexp.MustCompile(`- --data-dir=(\S+)`).FindStringSubmatch(text)
	if mount == nil || flag == nil {
		t.Fatal("data mount or --data-dir flag not found")
	}
	if flag[1] == mount[1] || !strings.HasPrefix(flag[1], mount[1]+"/") {
		t.Fatalf("--data-dir=%s must be a subdirectory of the data mount %s", flag[1], mount[1])
	}
}
