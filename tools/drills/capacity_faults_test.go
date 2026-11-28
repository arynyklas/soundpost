//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestCapacityFaultsScenario runs the whole scenario through Execute (real replica journals and a
// real application over HTTPS, about 20-40 seconds) and checks what the report must carry. It is
// the scenario-level guard: a verifier that was unit-tested but no longer called, a reconciliation
// that was skipped or a fault that never fired fails here.
func TestCapacityFaultsScenario(t *testing.T) {
	if testing.Short() {
		t.Skip("scenario run skipped in -short mode")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the drill's allowlisted data root is /tmp/soundpost-drills on linux")
	}
	m, err := LoadManifest("../../drills/scenarios.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Execute(t.Context(), m, "capacity-faults", "isolated", "../..", "", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	failing := []string{}
	byName := map[string]bool{}
	for _, c := range rep.Checks {
		byName[c.Name] = c.OK
		if !c.OK {
			failing = append(failing, c.Name+": "+c.Detail)
		}
	}
	if rep.Status != StatusPassed {
		t.Fatalf("scenario %s (%s); failing checks %v", rep.Status, rep.Reason, failing)
	}
	for _, name := range []string{
		"failed_sync.hook_fired", "failed_sync.no_ack_and_typed_refusal_while_sync_fails", "failed_sync.status_reports_failed_group",
		"failed_sync.readiness_reports_sync_failed", "failed_sync.reads_continue_exact_while_failed",
		"failed_sync.healing_the_hook_alone_does_not_revive_the_node", "failed_sync.restarted_node_is_ready",
		"failed_sync.no_duplicate_apply", "failed_sync.reconcile_after_reopen",
		"slow_apply.slow_apply_caller_deadline_refusals_observed", "slow_apply.slow_apply_probe_fails_closed_while_apply_is_in_flight",
		"slow_apply.slow_sync_hook_fired", "slow_apply.no_duplicate_apply", "slow_apply.reconcile_after_reopen",
		"engine_faults.engine_hook_fired_at_wal_sync", "engine_faults.no_ack_and_typed_refusal_while_the_engine_sync_fails",
		"engine_faults.a_group_of_the_engine_is_failed_after_the_sync_failure", "engine_faults.healing_the_hook_alone_does_not_revive_the_engine",
		"engine_faults.restarted_engine_is_ready", "engine_faults.slow_apply_hook_fired_at_before_apply",
		"engine_faults.slow_apply_caller_deadline_refusals_observed", "engine_faults.slow_apply_patient_callers_acknowledged",
		"engine_faults.ready_after_slow_apply_heals", "engine_faults.every_sent_batch_retained_once", "engine_faults.reconcile_after_reopen",
		"full_disk.readiness_reports_disk_pressure_at_90", "full_disk.readiness_reports_disk_pressure_at_95",
		"full_disk.deny_all_refuses_every_new_batch_typed_and_acks_none", "full_disk.reads_continue_exact_at_95_percent",
		"full_disk.delete_allowed_at_95_percent", "full_disk.pressure_warning_sequence_matches_01_08", "full_disk.reconcile_after_reopen",
		"timeline_keeps_every_failed_attempt", "exact_reconciliation",
	} {
		if ok, present := byName[name]; !present || !ok {
			t.Errorf("check %s present=%v ok=%v", name, present, ok)
		}
	}
	// The retry contract is checked for every refused batch, and the checks are recorded even when they hold.
	for _, want := range []struct {
		prefix, suffix string
		min            int
	}{
		{"failed_sync.repeat_returns_same_receipt:", "", 5},
		{"slow_apply.repeat_returns_same_receipt:", "", 32},
		{"engine_faults.repeat_returns_same_receipt:", "", 16},
		{"full_disk.retry_", "_repeat_same_receipt_and_bytes", 7},
		{"full_disk.acked_retry_", "_unchanged_at_95_percent", 5},
	} {
		n := 0
		for _, c := range rep.Checks {
			if c.OK && strings.HasPrefix(c.Name, want.prefix) && strings.HasSuffix(c.Name, want.suffix) {
				n++
			}
		}
		if n < want.min {
			t.Errorf("%d passing checks %s*%s, want at least %d", n, want.prefix, want.suffix, want.min)
		}
	}
	if rep.Reconciliation == nil || rep.Reconciliation.ExactMatches != len(rep.AckLedger) || len(rep.AckLedger) == 0 {
		t.Fatalf("reconciliation %+v does not cover the %d acknowledged ids", rep.Reconciliation, len(rep.AckLedger))
	}
	for _, a := range rep.AckLedger {
		if strings.HasSuffix(a.Label, "acked_during_sync_fault") {
			t.Errorf("%s was acknowledged while the journal fsync step failed", a.ID)
		}
	}
	if len(rep.FailedAttempts) == 0 {
		t.Fatal("no refusal was recorded: no fault was exercised")
	}
	for _, a := range rep.FailedAttempts {
		if !capClass(a.Outcome).typedRefusal() {
			t.Errorf("attempt %s has outcome %q, not a typed refusal", a.ID, a.Outcome)
		}
	}
	if len(rep.NotRunItems) != 0 {
		t.Errorf("%d not-run items recorded: %+v", len(rep.NotRunItems), rep.NotRunItems)
	}
	if _, ok := rep.Facts["finding.retry_of_capacity_refused_batch_across_a_policy_epoch_change"]; !ok {
		t.Error("the retry-across-policy-epoch finding is not reported")
	}
}
