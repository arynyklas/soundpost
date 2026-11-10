// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"testing"
	"time"

	"soundpost/internal/conditions"
	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/replica"
)

func TestWorkerDelayBacksOffAndCaps(t *testing.T) {
	w := &Workers{cfg: WorkerConfig{Interval: time.Second, MaxBackoff: 10 * time.Second}}
	for failures, want := range map[int]time.Duration{0: time.Second, 1: 2 * time.Second, 2: 4 * time.Second, 3: 8 * time.Second, 4: 10 * time.Second, 40: 10 * time.Second} {
		if got := w.delay(failures); got != want {
			t.Fatalf("delay(%d) = %v, want %v", failures, got, want)
		}
	}
}

func TestDeposedRecognisesOnlyAGoneLease(t *testing.T) {
	if !deposed(replica.ErrStale) || !deposed(model.Fail(model.Stale)) {
		t.Fatal("a stale lease is not recognised as deposed")
	}
	for _, err := range []error{nil, errors.New("boom"), model.Fail(model.Unavailable), model.Fail(model.Conflict)} {
		if deposed(err) {
			t.Fatalf("%v is not a lost lease", err)
		}
	}
}

func TestWorkerErrorCodesAreClosed(t *testing.T) {
	for err, want := range map[error]string{
		model.Fail(model.Forbidden): string(model.Forbidden),
		errors.New("free text 42"):  string(model.Unavailable),
		context.Canceled:            string(model.Cancelled),
		context.DeadlineExceeded:    string(model.Timeout),
	} {
		if got := code(err); got != want {
			t.Fatalf("code(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestConditionSeverityNeverEscalatesUnknownText(t *testing.T) {
	for text, want := range map[string]notify.Severity{"critical": notify.SeverityCritical, "CRITICAL": notify.SeverityCritical, "major": notify.SeverityMajor, "minor": notify.SeverityMinor, "page-now": notify.SeverityMinor, "": notify.SeverityMinor} {
		if got := conditionSeverity(text); got != want {
			t.Fatalf("conditionSeverity(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestConditionEvidenceSaysNothingBeforeADefiniteEpisode(t *testing.T) {
	episode := model.ID{0xe1}
	base := conditions.State{Version: 7, Notify: true, Episode: &episode, Freshness: conditions.FreshnessFresh, Severity: "major"}
	cases := map[string]struct {
		phase conditions.Phase
		drop  bool
		quiet bool
		ok    bool
		state notify.SourceState
	}{
		"firing":     {phase: conditions.PhaseFiring, ok: true, state: notify.SourceFiring},
		"recovering": {phase: conditions.PhaseRecovering, ok: true, state: notify.SourceFiring},
		"recovered":  {phase: conditions.PhaseRecovered, ok: true, state: notify.SourceRecovered},
		"pending":    {phase: conditions.PhasePending},
		"none":       {phase: conditions.PhaseNone},
		"no episode": {phase: conditions.PhaseFiring, drop: true},
		"backfill":   {phase: conditions.PhaseFiring, quiet: true},
	}
	for name, c := range cases {
		st := base
		st.Phase = c.phase
		if c.drop {
			st.Episode = nil
		}
		st.Notify = !c.quiet
		ev, ok := conditionEvidence(st)
		if ok != c.ok {
			t.Fatalf("%s: ok = %v", name, ok)
		}
		if ok && (ev.State != c.state || ev.Seq != 7 || ev.Episode != episode || ev.Severity != notify.SeverityMajor || ev.Freshness != notify.FreshnessFresh) {
			t.Fatalf("%s: %+v", name, ev)
		}
	}
}

func TestRecipientsMatchNeedsEveryEnabledRecipient(t *testing.T) {
	a, b := model.ID{1}, model.ID{2}
	state := notify.PolicyState{Recipients: []notify.Recipient{{ID: a, Enabled: true}, {ID: b, Enabled: false}}}
	if !recipientsMatch(state, []model.ID{a}) || !recipientsMatch(state, nil) {
		t.Fatal("an enabled recipient did not match")
	}
	if recipientsMatch(state, []model.ID{a, b}) || recipientsMatch(state, []model.ID{{3}}) {
		t.Fatal("a disabled or unknown recipient matched")
	}
}

func TestPolicyFramingBringsConfigurationOnlyForANewRevision(t *testing.T) {
	binding := NotificationBinding{Policy: model.ID{9}, Revision: 3, Config: notify.DefaultConfig()}
	ref, owner := policyFraming(false, notify.PolicyState{}, binding)
	if ref.Revision != 3 || ref.Config == nil || owner != 1 {
		t.Fatalf("first event: %+v owner %d", ref, owner)
	}
	adopted := notify.PolicyState{PolicyRevision: 3, OwnerRevision: 5}
	if ref, owner = policyFraming(true, adopted, binding); ref.Revision != 3 || ref.Config != nil || owner != 5 {
		t.Fatalf("adopted revision: %+v owner %d", ref, owner)
	}
	older := notify.PolicyState{PolicyRevision: 2, OwnerRevision: 4}
	if ref, owner = policyFraming(true, older, binding); ref.Revision != 3 || ref.Config == nil || owner != 4 {
		t.Fatalf("new revision: %+v owner %d", ref, owner)
	}
	ref.Config.MinFailures = 99
	if binding.Config.MinFailures == 99 {
		t.Fatal("the framed configuration aliases the binding's")
	}
}
