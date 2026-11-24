//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A kubelet gives a pod a private cgroup namespace (only a privileged container gets the host's), so the target's
// "0::/path" is relative to the helper's own cgroup: "/../../../<tail>". The tree below is a cgroup hierarchy on a
// temporary directory: the helper's cgroup is four levels below the root, the target's is a sibling of its great
// grandparent's child (a Guaranteed pod next to a Burstable one), a foreign workload sits elsewhere.
func ancestorTree(t *testing.T) (root string, own, target, foreign uint64) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podh.slice/cri-helper.scope",
		"kubepods.slice/kubepods-podt.slice/cri-target.scope",
		"kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf.slice/cri-foreign.scope",
		"system.slice/k3s.service",
	} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ino := func(rel string) uint64 {
		var st syscall.Stat_t
		if err := syscall.Stat(filepath.Join(root, rel), &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	return root, ino("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podh.slice/cri-helper.scope"),
		ino("kubepods.slice/kubepods-podt.slice/cri-target.scope"),
		ino("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podf.slice/cri-foreign.scope")
}

func TestPrivateCgroupNamespaceIsRefusedWithoutAnAncestorMount(t *testing.T) {
	// the behaviour before the ancestor mount: a ".." path is never walked
	if _, err := cgroupIdentity([]byte("0::/../../../kubepods-podt.slice/cri-target.scope\n")); !errors.Is(err, ErrAuthorization) {
		t.Fatalf("a path with .. components and no ancestor mount must be refused as unauthorized, got %v", err)
	}
}

func TestRelativeCgroupResolvesToTheTargetUnderAnAncestorMount(t *testing.T) {
	root, own, target, foreign := ancestorTree(t)
	anc := ancestorMount{dir: root, depth: 4}
	got, err := resolveRelativeCgroup("/../../../kubepods-podt.slice/cri-target.scope", anc, own)
	if err != nil || got != target {
		t.Fatalf("target resolved to %d (%v), want its own cgroup id %d", got, err, target)
	}
	// a foreign workload resolves to ITS id, which the operator policy does not allow: identity is still decided by the id
	got, err = resolveRelativeCgroup("/../../kubepods-burstable-podf.slice/cri-foreign.scope", anc, own)
	if err != nil || got != foreign || got == target {
		t.Fatalf("foreign resolved to %d (%v), want %d distinct from the target %d", got, err, foreign, target)
	}
	// the helper's own cgroup (no ..) is not a relative path and needs no ancestor
	if got, err = resolveRelativeCgroup("/", anc, own); err != nil || got != own {
		t.Fatalf("own cgroup %d (%v), want %d", got, err, own)
	}
}

func TestRelativeCgroupRefusals(t *testing.T) {
	root, own, _, _ := ancestorTree(t)
	anc := ancestorMount{dir: root, depth: 4}
	for name, c := range map[string]struct {
		path string
		anc  ancestorMount
		own  uint64
	}{
		"more .. than the mount's depth":    {"/../../../../../x", anc, own},
		".. after a name":                   {"/../kubepods-podt.slice/../x", anc, own},
		"single dot":                        {"/../././x", anc, own},
		"own cgroup not under the mount":    {"/../../../kubepods-podt.slice/cri-target.scope", anc, own + 1<<40},
		"mount depth deeper than the tree":  {"/../../../../../../x", ancestorMount{dir: root, depth: 6}, own},
		"nonexistent tail":                  {"/../../../kubepods-nope.slice", anc, own},
		"symlink component is not followed": {"/../../../link/cri-target.scope", anc, own},
		"empty mount directory":             {"/../x", ancestorMount{dir: "", depth: 1}, own},
	} {
		if name == "symlink component is not followed" {
			if err := os.Symlink(filepath.Join(root, "kubepods.slice", "kubepods-podt.slice"), filepath.Join(root, "kubepods.slice", "link")); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := resolveRelativeCgroup(c.path, c.anc, c.own); err == nil {
			t.Errorf("%s: resolved to %d, want a refusal", name, got)
		}
	}
}

func TestParseCgroup2AncestorMounts(t *testing.T) {
	info := []byte("988 987 0:26 / /sys/fs/cgroup ro,nosuid - cgroup2 cgroup rw\n" +
		"989 981 0:26 /../../../.. /hostcg ro,relatime - cgroup2 cgroup2 rw\n" +
		"990 981 0:26 /../x /bad ro - cgroup2 cgroup2 rw\n" +
		"991 981 0:27 /../.. /notcgroup ro - tmpfs tmpfs rw\n")
	got := parseCgroup2AncestorMounts(info)
	if len(got) != 1 || got[0].dir != "/hostcg" || got[0].depth != 4 {
		t.Fatalf("ancestor mounts %+v, want only /hostcg at depth 4", got)
	}
}
