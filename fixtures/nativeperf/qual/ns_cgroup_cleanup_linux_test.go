//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// The cgroup_move case moves its target into a cgroup of its own and promises to remove it when the case ends. Cleanups run
// last-registered first, so the removal ran while the target was still a member (EBUSY for the whole retry window) and every run
// left one empty l4w33-nscase-<pid> cgroup on the host (46, 25 and 66 of them were found on the three qualification VMs).
func TestCgroupMoveCaseLeavesNoCgroupBehind(t *testing.T) {
	if reason := NSPrerequisites(); reason != "" {
		t.Skip("NOT run: " + reason)
	}
	root, err := cgroup2Path()
	if err != nil {
		t.Skip("NOT run: no cgroup v2 hierarchy: " + err.Error())
	}
	left := filepath.Join(root, "l4w33-nscase-"+strconv.Itoa(os.Getpid()))
	if _, err := os.Stat(left); err == nil {
		t.Fatalf("%s exists before the case ran", left)
	}
	res := RunNSCasesNamed(context.Background(), "cgroup_move")
	if res.Unavailable != "" {
		t.Fatal(res.Unavailable)
	}
	if len(res.Records) != 1 || res.Records[0].Error != "" {
		t.Fatalf("the cgroup_move case did not run: %+v", res.Records)
	}
	if _, err := os.Stat(left); err == nil {
		syscall.Rmdir(left)
		t.Errorf("%s was left behind by the case", left)
	}
}
