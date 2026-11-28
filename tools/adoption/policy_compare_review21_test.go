// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// PC-01 (08.04 review): a real signed no-send window is normalized into a private
// legacy ledger of up to ledgerMaxEntries delivery attempts. The command must be
// able to read such a file; the shared 1 MiB intake bound cannot hold one.
func TestComparisonCommandReadsLargePrivateInputsReview21(t *testing.T) {
	targets, _ := fixture(t)
	t.Chdir(targets.Targets[0].Repository)
	l, c, a := policyFullWindow(t)
	scoped := a
	scoped.Scope = "synthetic-scope"

	var big []LedgerEntry
	for i := range 6000 {
		big = policyAdd(big, LedgerEntry{Entity: policyInc, Kind: notify.KindOpen, ImpactRevision: uint64(i + 1), Ordinal: 1, Recipient: &policyRcptA,
			AttemptID: fmt.Sprintf("op-%d", i), EventTime: policyT0 + model.UnixNano(i)*policyMin, SourceVersion: uint64(i + 1)})
	}
	raw, err := json.Marshal(big)
	if err != nil || len(raw) <= 1<<20 {
		t.Fatalf("the fixture ledger must exceed the old 1 MiB input bound: %d bytes (%v)", len(raw), err)
	}
	legacy := l
	legacy.Ledger = big

	inputs := t.TempDir()
	write := func(name string, v any) string {
		p := filepath.Join(inputs, name)
		if err := writeExclusive(p, v); err != nil {
			t.Fatal(err)
		}
		return p
	}
	lp, cp, ap := write("legacy.json", legacy), write("canonical.json", c), write("approved.json", scoped)
	private := privateTempDir(t)
	args := []string{"--legacy", lp, "--canonical", cp, "--approved-policy", ap, "--private-output", private, "--public-summary", filepath.Join(inputs, "summary.json")}
	runErr := runPolicyCompare(context.Background(), args)
	if runErr != nil && strings.Contains(runErr.Error(), "invalid private operator input") {
		t.Fatalf("a realistic-size legacy ledger was refused as invalid operator input: %v", runErr)
	}
	if _, statErr := os.Stat(filepath.Join(private, "policy-report.json")); statErr != nil {
		t.Fatalf("no evidence was written for a large window (command error %v): %v", runErr, statErr)
	}
}

// PC-02 (08.04 review): "the canonical owner already interrupted" must mean it
// interrupted at or before the legacy page's own event time. An unrelated later
// opening cannot retroactively turn a lost urgent page into approvable noise.
func TestComparisonCoveringOpeningMustPrecedeTheLegacyPageReview21(t *testing.T) {
	m := policyMin
	f := newPolicyFixture(t)

	// The canonical owner only saw the evidence an hour late, so its single
	// grouped opening is decided at t0+60m, while legacy paged the first
	// occurrence at t0 and never repeated it.
	lateCanon := f.canonical(PolicyReplay{Subject: policyIss, Steps: []PolicyStep{f.dest(policyRcptA, policyT0), f.issue(policyT0+60*m, 1, "payment_failed", 1, nil)}})
	lateLegacy := policyAdd(policyLegacy(policyDecisions(t, lateCanon)), LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 2,
		Recipient: &policyRcptA, EventTime: policyT0, Trigger: ledgerTriggerPerOccurrence})
	r := policyCompare(t, LegacyEvidence{Ledger: lateLegacy, Ownership: policyOwnership()}, lateCanon, f.approved())
	if len(r.MissingUrgency) != 1 || r.MissingUrgency[0].Reason != policyReasonUrgentLost {
		t.Fatalf("an urgent page the canonical owner opened only an hour later is lost urgency, not approvable noise: missing=%+v noise=%+v", r.MissingUrgency, r.Noise)
	}
	if r.Verdict != policyVerdictBlocked {
		t.Fatalf("lost urgency must block, verdict %s", r.Verdict)
	}

	// The same difference against an opening that came first is grouping noise.
	earlyCanon := f.canonical(PolicyReplay{Subject: policyIss, Steps: []PolicyStep{f.dest(policyRcptA, policyT0), f.issue(policyT0, 1, "payment_failed", 1, nil)}})
	earlyLegacy := policyAdd(policyLegacy(policyDecisions(t, earlyCanon)), LedgerEntry{Entity: policyIss, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 2,
		Recipient: &policyRcptA, EventTime: policyT0 + m, Trigger: ledgerTriggerPerOccurrence})
	r2 := policyCompare(t, LegacyEvidence{Ledger: earlyLegacy, Ownership: policyOwnership()}, earlyCanon, f.approved())
	if len(r2.MissingUrgency) != 0 {
		t.Fatalf("a repeat of an already opened group is not lost urgency: %+v", r2.MissingUrgency)
	}
	policyWantReasons(t, r2.Noise, map[PolicyReason]int{policyReasonRepeatOccurrence: 1})
}
