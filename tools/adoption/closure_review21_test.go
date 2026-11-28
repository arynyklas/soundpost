// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"
	"time"
)

// Review l5w21 wave 21, task 08.07: the outage drill must be a drill of the
// adopted system, and a read-only origin with an unusable evidence reference
// must not be reported as a writable origin.

// TestReview21ClosureRejectsAnOutageThatPredatesTheCutover: the ledger records
// both the cutover boundary (history.boundary.cutover_at) and the drill, so a
// drill from before the product owned the normal route cannot certify closure.
func TestReview21ClosureRejectsAnOutageThatPredatesTheCutover(t *testing.T) {
	const code = "outage_before_cutover"
	t.Run("a drill that ran before the cutover", func(t *testing.T) {
		l := closureLedgerFixture(t)
		// The fixture's outage is now-3h..now-2h; here the cutover came after it.
		l.History.Boundary.CutoverAt = l.Now.Add(-90 * time.Minute)
		r := closureClose(t, l)
		if r.Closed || !closureHas(r, ClosureAreaDeadman, code) {
			t.Fatalf("closed=%v blockers=%v", r.Closed, r.Blockers)
		}
		if r.EvidenceDigest != "" {
			t.Fatalf("a blocked closure carries an evidence digest: %+v", r)
		}
		if pub := ClosurePublicProjection(r); pub.Closed || len(pub.Blockers) != len(r.Blockers) {
			t.Fatalf("the projection dropped the ordering blocker: %v vs %v", pub.Blockers, r.Blockers)
		}
	})
	t.Run("a drill that starts at the cutover boundary", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.History.Boundary.CutoverAt = closureProofFixture(l.Now).Outage.StartedAt
		if r := closureClose(t, l); !r.Closed || len(r.Blockers) != 0 {
			t.Fatalf("closed=%v blockers=%v", r.Closed, r.Blockers)
		}
	})
	t.Run("a boundary history already refuses needs no second verdict", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.History.Boundary.CutoverAt = l.Now.Add(time.Second) // future: boundary_missing
		r := closureClose(t, l)
		if r.Closed || !closureHas(r, ClosureAreaHistory, string(HistoryCodeBoundaryMissing)) {
			t.Fatalf("closed=%v blockers=%v", r.Closed, r.Blockers)
		}
		if closureHas(r, ClosureAreaDeadman, code) {
			t.Fatalf("an unusable boundary must not also blame the drill: %v", r.Blockers)
		}
	})
	t.Run("a ledger with no boundary at all is blocked by history alone", func(t *testing.T) {
		l := closureLedgerFixture(t)
		l.History.Boundary = nil
		r := closureClose(t, l)
		if r.Closed || !closureHas(r, ClosureAreaHistory, string(HistoryCodeBoundaryMissing)) || closureHas(r, ClosureAreaDeadman, code) {
			t.Fatalf("closed=%v blockers=%v", r.Closed, r.Blockers)
		}
	})
}

// TestReview21HistoryNamesMissingOriginEvidenceSeparately: `legacy_not_read_only`
// must mean the origin is writable; an unusable origin evidence reference is its
// own reason. Both keep blocking.
func TestReview21HistoryNamesMissingOriginEvidenceSeparately(t *testing.T) {
	const missing = "origin_evidence_missing"
	statusOf := func(edit func(h *HistoryObligations)) HistoryReport {
		h := closureHistoryFixture(closureNow)
		edit(&h)
		r, err := HistoryStatus(context.Background(), h)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	has := func(r HistoryReport, c string) bool {
		for _, b := range r.Blockers {
			if string(b) == c {
				return true
			}
		}
		return false
	}
	if r := statusOf(func(h *HistoryObligations) { h.Origin.EvidenceDigest = "" }); r.Clear || !has(r, missing) || has(r, string(HistoryCodeOriginNotReadOnly)) {
		t.Fatalf("a read-only origin with no evidence must name the evidence: %v", r.Blockers)
	}
	if r := statusOf(func(h *HistoryObligations) { h.Origin.EvidenceDigest = "not-a-digest" }); r.Clear || !has(r, missing) {
		t.Fatalf("a malformed origin evidence digest must name the evidence: %v", r.Blockers)
	}
	if r := statusOf(func(h *HistoryObligations) { h.Origin.ReadOnly = false }); r.Clear || !has(r, string(HistoryCodeOriginNotReadOnly)) || has(r, missing) {
		t.Fatalf("a writable origin must not be reported as missing evidence: %v", r.Blockers)
	}
	r := statusOf(func(h *HistoryObligations) { h.Origin.ReadOnly, h.Origin.EvidenceDigest = false, "" })
	if r.Clear || !has(r, string(HistoryCodeOriginNotReadOnly)) || !has(r, missing) || len(r.Blockers) != 2 {
		t.Fatalf("both defects must be reported, exactly once each: %v", r.Blockers)
	}
	if pub := HistoryPublicProjection(r); pub.Clear || len(pub.Blockers) != 2 {
		t.Fatalf("the public projection dropped a code: %v", pub.Blockers)
	}
}
