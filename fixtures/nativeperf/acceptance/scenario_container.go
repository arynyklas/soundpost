//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// container_modes: real captures across PID, mount, cgroup, UTS, IPC and network namespaces built on this host with
// unshare-style clone flags and mounts (no container runtime): a target in a nested PID namespace with the helper outside, the
// helper inside the target's own namespace, and the transitions a container workload can make while events are in flight
// (exec, cgroup move, executable replaced in a layer, mount namespace swapped, PID reused across a namespace boundary, a
// /proc that is not the helper's own). Each is judged from what the helper really delivered and refused (qual/ns_judge_linux.go);
// the judge itself is first shown to reject contaminated records (negative controls).
func init() {
	registerHostScenario("container_modes", func(a *accept) qual.Row {
		a.record("container namespace cases (unshare-equivalent sandboxes, real helper captures)", true, "")
		res := qual.RunNSCases(a.ctx)
		return containerModesRow(res)
	})
}

func containerModesRow(res qual.NSResult) qual.Row {
	detail := map[string]any{"kernel": res.Kernel, "cgroup_mode": res.CgroupMode, "cases": res.Summary()}
	controls := make([]string, 0, len(res.Controls))
	for _, c := range res.Controls {
		controls = append(controls, fmt.Sprintf("%s: rejected=%v behaved=%v", c.Name, c.Rejected, c.Behaved))
	}
	detail["negative_controls"] = controls
	if res.Unavailable != "" {
		return qual.Unqualified("container_modes could not run on this host: "+res.Unavailable, detail)
	}
	var problems []string
	for _, c := range res.Controls {
		if !c.Behaved {
			problems = append(problems, "negative control "+c.Name+": "+c.Reason)
		}
	}
	for _, name := range qual.NSCaseNames {
		if f := res.Failures[name]; len(f) > 0 {
			problems = append(problems, name+": "+strings.Join(f, "; "))
		}
	}
	if len(res.Records) != len(qual.NSCaseNames) {
		problems = append(problems, fmt.Sprintf("%d of %d cases ran", len(res.Records), len(qual.NSCaseNames)))
	}
	if len(problems) > 0 {
		return qual.Failed(strings.Join(problems, " | "), detail)
	}
	evidence := append([]string{"fixtures/nativeperf/qual/ns_cases_linux.go: " + strings.Join(qual.NSCaseNames, ",")}, res.Summary()...)
	return qual.Supported(evidence, detail)
}
