//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"os"
	"testing"
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
