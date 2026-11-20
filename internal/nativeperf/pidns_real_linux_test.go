//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf_test

import (
	"context"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// A helper in a nested PID namespace that kept the parent's /proc resolves a PID through /proc as one process and through
// perf_event_open/pidfd_open as another. The real case (qual/ns_cases_linux.go, proc_view_mismatch) authorizes an idle
// process of the parent namespace, gives a busy process of the nested namespace the same number, and requires the helper to
// refuse (closed code generation_changed, no event): samples would be the busy process's, labeled as the idle target's.
// The same run covers the other namespace shapes (nested target, helper inside the target's namespace, PID reuse across a
// namespace boundary, exec/cgroup move/layer replacement while events are in flight).
func TestHelperAcrossPIDNamespaceBoundaries(t *testing.T) {
	if reason := qual.NSPrerequisites(); reason != "" {
		t.Skip("NOT run: " + reason)
	}
	res := qual.RunNSCasesIsolated(context.Background())
	for _, line := range res.Summary() {
		t.Log(line)
	}
	if res.Unavailable != "" {
		t.Fatal(res.Unavailable)
	}
	for _, c := range res.Controls {
		if !c.Behaved {
			t.Errorf("negative control %s: %s", c.Name, c.Reason)
		}
	}
	for name, failures := range res.Failures {
		t.Errorf("%s: %s", name, strings.Join(failures, "; "))
	}
	if len(res.Records) != len(qual.NSCaseNames) {
		t.Errorf("%d of %d cases ran", len(res.Records), len(qual.NSCaseNames))
	}
}
