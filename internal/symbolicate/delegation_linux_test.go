//go:build linux && (amd64 || arm64)

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A freshly delegated systemd subtree lists memory and pids in cgroup.controllers
// but leaves cgroup.subtree_control empty, so children have no controller files.
// The launcher must enable exactly those two for its children and still read the
// limits back. Run in `systemd-run --user -p Delegate=... -p DelegateSubgroup=main`
// with SOUNDPOST_SYMBOLICATE_DELEGATED_ROOT set to the delegated parent.
func TestNativeGroupEnablesChildControllersInDelegatedParent(t *testing.T) {
	root := os.Getenv("SOUNDPOST_SYMBOLICATE_DELEGATED_ROOT")
	if root == "" {
		t.Skip("requires SOUNDPOST_SYMBOLICATE_DELEGATED_ROOT (a delegated, empty cgroup v2 parent)")
	}
	if b, _ := os.ReadFile(filepath.Join(root, "cgroup.subtree_control")); strings.TrimSpace(string(b)) != "" {
		t.Skip("parent already has child controllers enabled; scenario not reproducible")
	}
	g, e := newNativeGroup(root)
	if e != nil {
		t.Fatalf("newNativeGroup on freshly delegated parent: %v", e)
	}
	g.cleanup()
}
