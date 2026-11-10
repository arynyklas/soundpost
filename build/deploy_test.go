// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func deployFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// directives returns the non-comment lines of a Dockerfile/unit/yaml file.
func directives(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return out
}

func hasLine(text, prefix string) bool {
	for _, line := range directives(text) {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// The deployment files are the install contract: a server that is not root, a data directory
// that is 0700 and owned by that user, no network at build time, and no privilege in the
// units unless an operator opts in. These checks fail the build if a later edit loosens one.
func TestDockerfileIsNonrootPrivateAndOffline(t *testing.T) {
	d := deployFile(t, "deploy/Dockerfile")
	if !hasLine(d, "FROM scratch") {
		t.Fatal("the image must not pull a base image")
	}
	user := regexp.MustCompile(`(?m)^USER (\d+):(\d+)$`).FindStringSubmatch(d)
	if user == nil || user[1] == "0" || user[2] == "0" {
		t.Fatalf("the image must run as a numeric non-root user: %v", user)
	}
	if !regexp.MustCompile(`(?m)^COPY --chown=` + user[1] + `:` + user[2] + ` --chmod=0700 data/ /var/lib/soundpost/$`).MatchString(d) {
		t.Fatal("the data directory must be created 0700 and owned by the runtime user")
	}
	if !regexp.MustCompile(`(?m)^COPY --chown=\d+:\d+ --chmod=0555 soundpost /soundpost$`).MatchString(d) {
		t.Fatal("the binary must be read-only and not writable by the runtime user")
	}
	for _, line := range directives(d) {
		for _, banned := range []string{"ADD ", "RUN ", "curl", "wget", "http://", "https://"} {
			if strings.HasPrefix(line, banned) || (banned != "ADD " && banned != "RUN " && strings.Contains(line, banned)) {
				t.Fatalf("the build must not fetch or execute anything: %q", line)
			}
		}
	}
	if !hasLine(d, "HEALTHCHECK") || !strings.Contains(d, `"/soundpost", "ready"`) {
		t.Fatal("the health check must be the functional readiness command")
	}
	if strings.Contains(strings.ToUpper(strings.Join(directives(d), "\n")), "PASSWORD") {
		t.Fatal("the image must not carry a password")
	}
}

func TestComposeDropsPrivilegeAndPublishesLoopbackByDefault(t *testing.T) {
	c := deployFile(t, "deploy/compose.single.yaml")
	for _, required := range []string{`user: "65532:65532"`, "read_only: true", "cap_drop: [ALL]", "no-new-privileges:true", "soundpost-data:/var/lib/soundpost", "127.0.0.1:8443"} {
		if !strings.Contains(c, required) {
			t.Fatalf("compose lacks %q", required)
		}
	}
	for _, banned := range []string{"privileged", "network_mode: host", "cap_add", "pid: host", "latest", "PASSWORD", "password"} {
		if strings.Contains(strings.Join(directives(c), "\n"), banned) {
			t.Fatalf("compose contains %q", banned)
		}
	}
	if !strings.Contains(c, "${SOUNDPOST_IMAGE:?") {
		t.Fatal("the image must be required and pinned by the operator, with no default")
	}
}

func TestServerUnitHoldsNoPrivilege(t *testing.T) {
	u := deployFile(t, "deploy/systemd/soundpost.service")
	for _, required := range []string{"User=soundpost", "StateDirectoryMode=0700", "UMask=0077", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "ProtectSystem=strict", "MemoryDenyWriteExecute=yes"} {
		if !hasLine(u, required) {
			t.Fatalf("server unit lacks %q", required)
		}
	}
	for _, line := range directives(u) {
		if strings.HasPrefix(line, "CapabilityBoundingSet=") && line != "CapabilityBoundingSet=" {
			t.Fatalf("the server unit grants a capability: %q", line)
		}
		if strings.HasPrefix(line, "AmbientCapabilities=") && line != "AmbientCapabilities=" {
			t.Fatalf("the server unit grants an ambient capability: %q", line)
		}
		if line == "User=root" || strings.Contains(line, "CAP_PERFMON") || strings.Contains(line, "CAP_SYS_ADMIN") {
			t.Fatalf("server unit: %q", line)
		}
	}
}

// Native acquisition is opt-in: the agent unit starts with no capability, the one it could
// use is only present commented out, and it never runs as root or with CAP_SYS_ADMIN.
func TestAgentUnitCapabilityIsOptIn(t *testing.T) {
	u := deployFile(t, "deploy/systemd/soundpost-agent.service")
	if !hasLine(u, "User=soundpost-agent") || !hasLine(u, "NoNewPrivileges=yes") || !hasLine(u, "StateDirectoryMode=0700") {
		t.Fatal("agent unit must be unprivileged with a private state directory")
	}
	for _, line := range directives(u) {
		if strings.Contains(line, "CAP_") || line == "User=root" {
			t.Fatalf("the agent unit grants privilege by default: %q", line)
		}
	}
	if !strings.Contains(u, "#CapabilityBoundingSet=CAP_PERFMON") || strings.Contains(u, "CAP_SYS_ADMIN\n") && !strings.Contains(u, "NEVER add CAP_SYS_ADMIN") {
		t.Fatal("the opt-in capability must be documented as commented-out CAP_PERFMON only")
	}
}
