// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"soundpost/internal/health"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

func TestCapacityClassifyTypedRefusals(t *testing.T) {
	capacity := model.Fail(model.Unavailable)
	capacity.Retryable, capacity.SafeDetail = true, "capacity"
	cases := []struct {
		name  string
		err   error
		want  capClass
		typed bool
	}{
		{"nil is an acknowledgement", nil, capAck, false},
		{"replica unavailable", replica.ErrUnavailable, capUnavailable, true},
		{"wrapped replica unavailable", fmt.Errorf("propose: %w", replica.ErrUnavailable), capUnavailable, true},
		{"replica freshness fence", replica.ErrStale, capStale, true},
		{"capacity fault", capacity, capCapacity, true},
		{"wrapped capacity fault", fmt.Errorf("append: %w", capacity), capCapacity, true},
		{"plain unavailable fault", model.Fail(model.Unavailable), capUnavailable, true},
		{"caller deadline", context.DeadlineExceeded, capTimeout, true},
		{"caller cancellation", context.Canceled, capTimeout, true},
		{"conflict is a verdict, not a refusal", replica.ErrConflict, capConflict, false},
		{"invalid is a verdict, not a refusal", model.Fail(model.Invalid), capInvalid, false},
		{"an untyped text error", errors.New("disk exploded"), capUntyped, false},
		{"an io error", fmt.Errorf("write: %w", errors.New("input/output error")), capUntyped, false},
	}
	for _, c := range cases {
		got := capClassify(c.err)
		if got != c.want {
			t.Errorf("%s: classified %q, want %q", c.name, got, c.want)
		}
		if got.typedRefusal() != c.typed {
			t.Errorf("%s: typedRefusal() = %v, want %v", c.name, got.typedRefusal(), c.typed)
		}
	}
}

func TestCapacityClassifyHTTP(t *testing.T) {
	capacity := `{"code":"unavailable","retryable":true,"detail":"capacity","request_id":"00000000000000000000000000000000"}`
	plain := `{"code":"unavailable","retryable":true,"detail":"unavailable","request_id":"00000000000000000000000000000000"}`
	conflict := `{"code":"conflict","retryable":false,"detail":"conflict","request_id":"00000000000000000000000000000000"}`
	cases := []struct {
		name       string
		status     int
		retryAfter string
		body       string
		want       capClass
	}{
		{"accepted", 200, "", `{"version":1}`, capAck},
		{"capacity with retry hint", 503, "1", capacity, capCapacity},
		{"capacity without a retry hint is not a typed refusal", 503, "", capacity, capUntyped},
		{"plain unavailable with retry hint", 503, "1", plain, capUnavailable},
		{"unavailable without retry hint", 503, "", plain, capUntyped},
		{"conflict", 409, "", conflict, capConflict},
		{"server error with no body", 500, "", "", capUntyped},
		{"503 with a garbage body", 503, "1", "<html>bad gateway</html>", capUntyped},
		{"200 is only an ack when it is a 200", 201, "", `{"version":1}`, capUntyped},
	}
	for _, c := range cases {
		if got := capClassifyHTTP(c.status, c.retryAfter, []byte(c.body)); got != c.want {
			t.Errorf("%s: classified %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCapacityVerifyWindow(t *testing.T) {
	refused := capOutcome{ID: "a", Digest: "da", Class: capUnavailable}
	acked := capOutcome{ID: "b", Digest: "db", Acked: true, Class: capAck}
	if err := capVerifyWindow([]capOutcome{refused, {ID: "c", Digest: "dc", Class: capCapacity}}, false, nil); err != nil {
		t.Fatalf("typed refusals with no ACK must pass: %v", err)
	}
	if err := capVerifyWindow([]capOutcome{refused, acked}, false, map[string]string{"b": "db"}); err == nil {
		t.Fatal("an ACK during a fault that must refuse everything passed, even though the data was retained")
	}
	if err := capVerifyWindow([]capOutcome{{ID: "d", Digest: "dd", Class: capUntyped}}, false, nil); err == nil {
		t.Fatal("an untyped failure passed as a typed refusal")
	}
	if err := capVerifyWindow([]capOutcome{{ID: "e", Digest: "de", Class: capConflict}}, true, nil); err == nil {
		t.Fatal("a conflict verdict passed as a typed refusal")
	}
	if err := capVerifyWindow([]capOutcome{{ID: "f", Digest: "df", Acked: true, Class: capUnavailable}}, true, map[string]string{"f": "df"}); err == nil {
		t.Fatal("an outcome that is both acknowledged and refused passed")
	}
	if err := capVerifyWindow([]capOutcome{acked}, true, map[string]string{"b": "db"}); err != nil {
		t.Fatalf("an ACK with identical retained data must pass when ACKs are allowed: %v", err)
	}
	if err := capVerifyWindow([]capOutcome{acked}, true, map[string]string{}); err == nil {
		t.Fatal("an ACK that vanished passed")
	}
	if err := capVerifyWindow([]capOutcome{acked}, true, map[string]string{"b": "other"}); err == nil {
		t.Fatal("an ACK whose retained data differs passed")
	}
	if err := capVerifyWindow(nil, true, nil); err == nil {
		t.Fatal("an empty fault window passed: the fault was never exercised")
	}
}

func TestCapacitySameReceipt(t *testing.T) {
	base := capReceipt{Group: "g", Index: 7, Digest: "d"}
	if err := capSameReceipt(base, base); err != nil {
		t.Fatal(err)
	}
	for name, other := range map[string]capReceipt{
		"index":  {Group: "g", Index: 8, Digest: "d"},
		"group":  {Group: "h", Index: 7, Digest: "d"},
		"digest": {Group: "g", Index: 7, Digest: "e"},
	} {
		if err := capSameReceipt(base, other); err == nil {
			t.Errorf("a repeat with a different %s passed as the same receipt", name)
		}
	}
}

func TestCapacityDigest(t *testing.T) {
	a := capRecord{ID: "r1", At: 1, Name: "m", Value: 10}
	b := capRecord{ID: "r2", At: 2, Name: "m", Value: 20}
	want := capDigest([]capRecord{a, b})
	if want == "" {
		t.Fatal("empty digest")
	}
	if capDigest([]capRecord{b, a}) != want {
		t.Error("the digest depends on record order")
	}
	for name, got := range map[string]string{
		"a dropped record":   capDigest([]capRecord{a}),
		"an extra record":    capDigest([]capRecord{a, b, {ID: "r3", At: 3, Name: "m", Value: 30}}),
		"a changed value":    capDigest([]capRecord{a, {ID: "r2", At: 2, Name: "m", Value: 21}}),
		"a changed time":     capDigest([]capRecord{a, {ID: "r2", At: 3, Name: "m", Value: 20}}),
		"a changed name":     capDigest([]capRecord{a, {ID: "r2", At: 2, Name: "n", Value: 20}}),
		"a changed id":       capDigest([]capRecord{a, {ID: "r9", At: 2, Name: "m", Value: 20}}),
		"a shifted boundary": capDigest([]capRecord{{ID: "r1", At: 1, Name: "m", Value: 10}, {ID: "r2", At: 2, Name: "m2", Value: 0}}),
	} {
		if got == want {
			t.Errorf("%s did not change the digest", name)
		}
	}
	if capDigest([]capRecord{{ID: "ab", Name: "c"}}) == capDigest([]capRecord{{ID: "a", Name: "bc"}}) {
		t.Error("field boundaries are ambiguous")
	}
}

func TestCapacityFold(t *testing.T) {
	r1 := capRecord{ID: "r1", At: 1, Name: "m", Value: 1}
	r2 := capRecord{ID: "r2", At: 2, Name: "m", Value: 2}
	r3 := capRecord{ID: "r3", At: 3, Name: "m", Value: 3}
	batches := map[string][]string{"b1": {"r1", "r2"}, "b2": {"r3"}, "b3": {"r4"}}
	full := capFold(batches, map[string]capRecord{"r1": r1, "r2": r2, "r3": r3})
	if full["b1"] != capDigest([]capRecord{r1, r2}) || full["b2"] != capDigest([]capRecord{r3}) {
		t.Fatalf("complete batches fold to the wrong digest: %v", full)
	}
	if _, present := full["b3"]; present {
		t.Fatal("a batch none of whose records were read back is reported as retained")
	}
	partial := capFold(batches, map[string]capRecord{"r1": r1, "r3": r3})
	if partial["b1"] == "" || partial["b1"] == capDigest([]capRecord{r1, r2}) {
		t.Fatal("a batch with a missing record folds to the digest of the whole batch")
	}
	foreign := capFold(batches, map[string]capRecord{"zz": {ID: "zz", At: 1, Name: "m", Value: 1}})
	if len(foreign) != 0 {
		t.Fatalf("rows that belong to no batch were attributed to one: %v", foreign)
	}
}

func TestCapacityProbeSummary(t *testing.T) {
	timedOut, ready, unready := capProbeSummary([]capProbe{
		{TimedOut: true}, {TimedOut: true}, {Ready: true}, {Reason: "sync_failed"}, {Reason: "disk_pressure"}, {Ready: true},
	})
	if timedOut != 2 || ready != 2 || unready != 2 {
		t.Fatalf("summary = %d/%d/%d, want 2/2/2", timedOut, ready, unready)
	}
}

func TestCapacityRequireReason(t *testing.T) {
	if err := capRequireReason(health.Readiness{Reason: health.ReasonSyncFailed}, health.ReasonSyncFailed); err != nil {
		t.Fatalf("the expected reason was refused: %v", err)
	}
	if err := capRequireReason(health.Readiness{Ready: true}, health.ReasonSyncFailed); err == nil || !strings.Contains(err.Error(), "ready") {
		t.Fatalf("a ready node passed as reporting the fault: %v", err)
	}
	if err := capRequireReason(health.Readiness{Reason: health.ReasonDiskPressure}, health.ReasonSyncFailed); err == nil {
		t.Fatal("a different reason passed")
	}
	if err := capRequireReason(health.Readiness{}, health.ReasonSyncFailed); err == nil {
		t.Fatal("an unready answer with no reason passed")
	}
}

// fakeProposer answers with a scripted cursor index per call.
type fakeProposer struct {
	group model.ID
	index []uint64
	err   error
	calls int
}

func (f *fakeProposer) propose(capBatch, time.Duration) (replica.CommittedEntry, error) {
	if f.err != nil {
		return replica.CommittedEntry{}, f.err
	}
	i := f.index[min(f.calls, len(f.index)-1)]
	f.calls++
	return replica.CommittedEntry{Group: f.group, ApplicationCursor: model.Cursor{Group: f.group, Index: model.Uint64(i)}}, nil
}

func TestCapacityRetryBatchRequiresTheSameReceiptOnRepeat(t *testing.T) {
	b := capNewBatch()
	t.Run("honest node", func(t *testing.T) {
		rep := &Report{}
		p := newCapPart(rep, "t")
		if err := p.retryBatch(&fakeProposer{group: model.NewID(), index: []uint64{5, 5}}, b, "x"); err != nil {
			t.Fatal(err)
		}
		if p.led.Len() != 1 {
			t.Fatalf("%d acknowledgements recorded, want 1", p.led.Len())
		}
		if len(rep.Checks) != 1 || !rep.Checks[0].OK || !strings.HasPrefix(rep.Checks[0].Name, "t.repeat_returns_same_receipt:") {
			t.Fatalf("the passing repeat check was not recorded: %+v", rep.Checks)
		}
		if events := rep.Timeline().Events(); len(events) != 1 || events[0].Outcome != "delivered" {
			t.Fatalf("the delivery was not recorded: %+v", events)
		}
	})
	t.Run("a repeat that moves the receipt", func(t *testing.T) {
		rep := &Report{}
		p := newCapPart(rep, "t")
		if err := p.retryBatch(&fakeProposer{group: model.NewID(), index: []uint64{5, 6}}, b, "x"); err == nil {
			t.Fatal("a repeat that answered a different receipt was accepted")
		}
		if len(rep.Checks) != 1 || rep.Checks[0].OK {
			t.Fatalf("the failing repeat check was not recorded: %+v", rep.Checks)
		}
	})
	t.Run("a refusal is an error and no acknowledgement", func(t *testing.T) {
		rep := &Report{}
		p := newCapPart(rep, "t")
		if err := p.retryBatch(&fakeProposer{err: replica.ErrUnavailable}, b, "x"); err == nil || p.led.Len() != 0 {
			t.Fatalf("a refused retry was accepted: err=%v acks=%d", err, p.led.Len())
		}
	})
}

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
	if len(rep.NotRunItems) != 2 {
		t.Errorf("%d not-run items recorded, want the 2 documented ones", len(rep.NotRunItems))
	}
	if _, ok := rep.Facts["finding.retry_of_capacity_refused_batch_across_a_policy_epoch_change"]; !ok {
		t.Error("the retry-across-policy-epoch finding is not reported")
	}
}
