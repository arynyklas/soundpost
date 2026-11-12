// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
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
