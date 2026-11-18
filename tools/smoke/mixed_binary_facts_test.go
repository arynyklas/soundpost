// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// The checks of TestMixedBinaryVoters (which needs real binaries) were conditional on the observation
// having worked: review N1 found that a run whose three state reads all failed observed nothing and
// passed, N2 that a divergence between the survivors went unreported while voter 1 was down, N5 that one
// state patch satisfied the phase-A bound. These tests pin the analysis on facts, without any process.

func serving(id uint64, digest string) memberFact {
	return memberFact{ID: id, Release: "new", Alive: true, Ready: true, SealOK: true, Digest: digest}
}

func problemsOf(t *testing.T, facts ...memberFact) []string {
	t.Helper()
	got, _ := factProblems(facts)
	return got
}

func TestFactsOfAnObservationThatFailedAreProblemsNotAgreement(t *testing.T) {
	// Every state read failed: no digest, no seal, an error. The first version compared "" with "" and
	// reported nothing.
	failed := func(id uint64) memberFact {
		f := serving(id, "")
		f.SealOK, f.StateErr = false, "state seal does not match the copy"
		return f
	}
	got := problemsOf(t, failed(1), failed(2), failed(3))
	if len(got) != 3 {
		t.Fatalf("three unreadable states: %d problems %v, want one per voter", len(got), got)
	}
	for _, p := range got {
		if !strings.Contains(p, "could not be read") {
			t.Errorf("problem %q does not say the state could not be read", p)
		}
	}
	// A copy that does not match its seal, with a digest.
	sealed := serving(2, "aa")
	sealed.SealOK = false
	if got = problemsOf(t, serving(1, "aa"), sealed, serving(3, "aa")); len(got) != 1 || !strings.Contains(got[0], "seal") {
		t.Fatalf("a failed seal: %v", got)
	}
	// An empty digest without an error is no observation either.
	if got = problemsOf(t, serving(1, ""), serving(2, ""), serving(3, "")); len(got) != 3 || !strings.Contains(got[0], "no state digest") {
		t.Fatalf("empty digests: %v", got)
	}
	if got = problemsOf(t, serving(1, "aa"), serving(2, "aa"), serving(3, "aa")); len(got) != 0 {
		t.Fatalf("three agreeing voters: %v", got)
	}
}

func TestEveryAliveVoterIsComparedWithEveryOther(t *testing.T) {
	down := serving(1, "aa")
	down.Alive, down.Ready, down.Exit = false, false, "exit status 1"
	// Voter 1 (the first version's reference) is down and the survivors diverge: the divergence is reported.
	got, stopped := factProblems([]memberFact{down, serving(2, "bb"), serving(3, "cc")})
	if !stopped {
		t.Fatal("a voter that is down is not reported as stopped")
	}
	divergence := false
	for _, p := range got {
		if strings.Contains(p, "state digest of voter 2") && strings.Contains(p, "voter 3") {
			divergence = true
		}
	}
	if !divergence {
		t.Fatalf("voter 1 down, voters 2 and 3 hold different states: %v", got)
	}
	// Survivors that agree leave only the voter that does not serve.
	if got, _ = factProblems([]memberFact{down, serving(2, "bb"), serving(3, "bb")}); len(got) != 1 || !strings.Contains(got[0], "voter 1") {
		t.Fatalf("voter 1 down, survivors agree: %v", got)
	}
	// Divergence between voters 2 and 3 with voter 1 alive is reported once for the pair, and 1 differs from both.
	if got = problemsOf(t, serving(1, "aa"), serving(2, "bb"), serving(3, "cc")); len(got) != 3 {
		t.Fatalf("three different states: %d problems %v, want one per pair", len(got), got)
	}
}

func TestPatchGrowthNeedsOnePatchPerTrackedSavePerVoter(t *testing.T) {
	base := map[uint64]int{1: 10, 2: 10, 3: 10}
	// Eight saves and one patch on every voter (what "got > base" accepted) is a shortfall on every voter.
	if short := patchShortfall(map[uint64]int{1: 11, 2: 11, 3: 11}, base, 8); len(short) != 3 {
		t.Fatalf("one patch for eight saves: %v", short)
	}
	// One voter short is named.
	short := patchShortfall(map[uint64]int{1: 18, 2: 17, 3: 18}, base, 8)
	if len(short) != 1 || !strings.Contains(short[0], "voter 2") {
		t.Fatalf("voter 2 gained 7 for 8 saves: %v", short)
	}
	if short = patchShortfall(map[uint64]int{1: 20, 2: 18, 3: 30}, base, 8); len(short) != 0 {
		t.Fatalf("every voter gained at least 8: %v", short)
	}
}
