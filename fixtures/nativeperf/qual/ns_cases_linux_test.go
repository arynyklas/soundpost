//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"context"
	"strings"
	"testing"
)

func TestNamespaceControlsRejectEveryContaminatedRecord(t *testing.T) {
	for _, c := range runNSControls(judgeNS) {
		if !c.Behaved {
			t.Errorf("control %s: rejected=%v: %s", c.Name, c.Rejected, c.Reason)
		}
	}
}

// A judge that stops noticing one defect must be caught by exactly the control built for it: each mutant drops the failure
// text of one control and the controls must report that one (and only that one) as not behaving.
func TestNamespaceControlsKillJudgesThatAcceptAContaminatedRecord(t *testing.T) {
	wants := map[string]string{
		"joined_generation_reuser_shares_task_key":        "share TaskKey",
		"transition_not_noticed_old_events_continue":      "not noticed",
		"identity_proven_after_the_transition":            "last proven",
		"old_identity_capture_accepted_after_cgroup_move": "expected a refusal",
		"events_labeled_with_nested_pid":                  "TaskKey",
		"proc_mismatch_capture_delivered_samples":         "expected a refusal",
		"layer_resolved_to_host_path_build":               "build",
		"path_canary_in_frames":                           "canary",
	}
	for name, want := range wants {
		mutant := func(spec NSSpec, rec NSRecord) []string {
			var kept []string
			for _, f := range judgeNS(spec, rec) {
				if !strings.Contains(f, want) {
					kept = append(kept, f)
				}
			}
			return kept
		}
		killed := false
		for _, c := range runNSControls(mutant) {
			if c.Name == name && c.Behaved {
				continue
			}
			if c.Name == name {
				killed = true
			}
		}
		if !killed {
			t.Errorf("a judge that ignores %q was not caught by control %s", want, name)
		}
	}
	// and a judge that accepts everything is caught by all of them
	for _, c := range runNSControls(func(NSSpec, NSRecord) []string { return nil }) {
		if c.Behaved {
			t.Errorf("a judge that accepts everything passed control %s", c.Name)
		}
	}
}

// TestNamespaceCasesOnThisHost runs every case with real captures. It needs root and a compiler, and says so when it
// does not have them; the acceptance runner's container_modes row turns the same missing prerequisite into an unqualified row.
func TestNamespaceCasesOnThisHost(t *testing.T) {
	if reason := NSPrerequisites(); reason != "" {
		t.Skip("NOT run: " + reason)
	}
	res := RunNSCases(context.Background())
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
	for _, name := range NSCaseNames {
		for _, f := range res.Failures[name] {
			t.Errorf("%s: %s", name, f)
		}
	}
	if len(res.Records) != len(NSCaseNames) {
		t.Errorf("%d of %d cases ran", len(res.Records), len(NSCaseNames))
	}
}
