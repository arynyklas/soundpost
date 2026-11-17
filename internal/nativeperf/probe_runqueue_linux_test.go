//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package nativeperf

import (
	"context"
	"os"
	"testing"
)

// 04.05-C13: Probe used to pin RunqueueSplit to Unsupported even where the correlator had qualified the split on real
// kernels (D38: 8 of 8 rows on 6.1.0-54 and 6.6.162). The split is derived from exactly the three scheduler events the
// probe opens (sched_switch, sched_wakeup, sched_wakeup_new) plus the correlator, so its status is the scheduler
// path's: supported where the three open, and denied/unsupported/error exactly where they do not.
func TestProbeReportsTheRunqueueSplitOfTheSchedulerEventsItOpened(t *testing.T) {
	target, err := ResolveLocalTarget(os.Getpid())
	if err != nil {
		t.Skip("local target unresolved")
	}
	caps, _ := Probe(context.Background(), []Target{target})
	if caps.RunqueueSplit != caps.OffCPU {
		t.Fatalf("runqueue_split %s but off_cpu %s with scheduler_event_open %s (reasons %v): the split rides on the same three events",
			caps.RunqueueSplit, caps.OffCPU, caps.Permissions.SchedulerEventOpen, caps.Reasons)
	}
	if err := caps.Validate(); err != nil {
		t.Fatalf("%+v: %v", caps, err)
	}
	t.Logf("kernel %s: cpu %s off_cpu %s runqueue_split %s", caps.Kernel, caps.CPU, caps.OffCPU, caps.RunqueueSplit)
}
