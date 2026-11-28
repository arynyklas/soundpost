// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMixedBinaryRuleLedgerMarkerWaitsForContraction is the other half of TestMixedBinaryRuleLedgerMarker: an installation born on the previous
// release (its indexes are NOT contracted) is rolled to the candidate. Every member then declares protocol 10 and the rules keep being
// evaluated, and the marker must not fire; `soundpost upgrade contract-indexes` then contracts, and the marker commits once, at the same index on
// every voter, after which the evaluations use the ledger form and the books and outputs are the same on every voter.
//
//	1  three voters on the previous release, rules saved and evaluated, ledgers and replays written (so the contraction has an index to move);
//	2  the voters are rolled to the candidate one by one; with all three declared at 10, evaluations observed for 60 s more: rule_layout=blob and
//	   rule_marker_index=0 on every voter (diag), no rule table rows, no ledger_rules key in any file;
//	3  contract-indexes: rule_layout=ledger at one marker index on every voter, evaluations newer than it are in the tables, books and outputs
//	   identical on the three, the marker unchanged after more evaluations.
//
// The assertions read /debug/soundpost, so SOUNDPOST_MIXED_NEW_BINARY must be built with -tags soundpost_diag (as for the first test).
func TestMixedBinaryRuleLedgerMarkerWaitsForContraction(t *testing.T) {
	oldBin, newBin, evidence := os.Getenv("SOUNDPOST_MIXED_OLD_BINARY"), os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if oldBin == "" || newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_OLD_BINARY (the previous release) and SOUNDPOST_MIXED_NEW_BINARY (the candidate, -tags soundpost_diag)")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	dir := filepath.Join(evidence, "rules-contract")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	trace, err := os.Create(filepath.Join(dir, "trace.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()
	m := &mixedRun{t: t, trace: trace, evidence: dir, oldBin: oldBin, newBin: newBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
	runErr := m.runRuleMarkerContract()
	m.writeLogs()
	if runErr != nil && m.violation == "" {
		m.violation = "harness_error: " + runErr.Error()
	}
	m.say("RESULT violation=%q harness_error=%v", m.violation, runErr)
	if m.violation != "" {
		t.Fatalf("rule marker contraction scenario violated: %s", m.violation)
	}
}

func (m *mixedRun) runRuleMarkerContract() error {
	var err error
	m.diag = map[uint64]string{}
	for _, id := range []uint64{1, 2, 3} {
		if m.diag[id], err = freeLoopback(); err != nil {
			return err
		}
	}
	cleanup, err := m.startGroup(func(uint64) string { return "old" })
	defer cleanup()
	if err != nil {
		return err
	}
	blobOnly := func(_ uint64, s ruleStore) string {
		if s.ledger || s.tableBooks != 0 || s.tableOuts != 0 {
			return "blob expected: " + s.summary()
		}
		return ""
	}

	// ---- 1 ----
	m.say("PHASE 1: three voters on the previous release, rules and ledgers written")
	labels, err := m.ruleSave(1)
	if err != nil {
		return err
	}
	want := int64(len(labels))
	if err = m.expandSetup(1); err != nil {
		return err
	}
	for i, via := range []uint64{1, 2, 3} {
		if err = m.expandWriteVia(via, fmt.Sprintf("wait-%d", i+1)); err != nil {
			return err
		}
	}
	if _, err = m.waitRuleBooks("1 all old", want, time.Now().UnixNano(), blobOnly); err != nil {
		return err
	}
	if err = m.expandRequire("1 all old, expanded", false); err != nil {
		return err
	}

	// ---- 2 ----
	m.say("PHASE 2: rolled to the candidate; all three at protocol 10, uncontracted: the marker must not fire")
	for _, id := range []uint64{1, 2, 3} {
		if err = m.rollTo(id, "new"); err != nil {
			return err
		}
	}
	if err = m.waitDeclarations(); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		f := m.observe(id)
		m.say("  voter %d (%s) declared %v", id, m.release[id], f.Declared)
		if len(f.Declared) == 0 {
			return m.violate("no_declarations", fmt.Sprintf("voter %d declared nothing", id))
		}
	}
	declaredBefore := m.declaredMin()
	start := time.Now()
	for time.Since(start) < 60*time.Second {
		time.Sleep(5 * time.Second)
		for _, id := range []uint64{1, 2, 3} {
			l, at, derr := m.diagRuleLayout(id)
			if derr != nil || l != "blob" || at != 0 {
				return m.violate("marker_fired_uncontracted", fmt.Sprintf("voter %d after %s: rule_layout=%q rule_marker_index=%d err=%v", id, time.Since(start).Round(time.Second), l, at, derr))
			}
		}
	}
	if _, err = m.waitRuleBooks("2 all on the candidate, uncontracted, 60 s of evaluations", want, start.UnixNano()+int64(55*time.Second), blobOnly); err != nil {
		return err
	}
	if _, err = m.requireDiagLayout("2 after 60 s", "blob"); err != nil {
		return err
	}
	if err = m.expandRequire("2 still expanded", false); err != nil {
		return err
	}
	m.say("PHASE 2 ok: rule_layout=blob, rule_marker_index=0 on every voter for 60 s; the lowest recorded declaration was protocol %d before the 60 s (the candidate declares 10 only once contracted); the files hold no rule table rows", declaredBefore)

	// ---- 3 ----
	m.say("PHASE 3: contract-indexes")
	out, code, err := m.contract(1)
	if err != nil {
		return err
	}
	m.say("contract-indexes against voter 1: exit %d: %s", code, out)
	if code != 0 || !strings.Contains(out, "indexes contracted") {
		return m.violate("contract_failed", fmt.Sprintf("exit %d output %q", code, out))
	}
	marker, err := m.requireDiagLayout("3 after the contraction", "ledger")
	if err != nil {
		return err
	}
	if err = m.waitDeclaredAll("3 after the contraction", 10); err != nil {
		return err
	}
	after := time.Now().UnixNano()
	post, err := m.waitRuleBooks("3 evaluations in the ledger form", want, after, func(_ uint64, s ruleStore) string {
		if !s.ledger || s.blobBooks != 0 || s.blobOutputs != 0 || s.tableBooks != int(want) {
			return "ledger expected: " + s.summary()
		}
		return ""
	})
	if err != nil {
		return err
	}
	if again, aerr := m.requireDiagLayout("3 the marker after more evaluations", "ledger"); aerr != nil {
		return aerr
	} else if again != marker {
		return m.violate("marker_committed_twice", fmt.Sprintf("marker index %d, then %d", marker, again))
	}
	if !post[1].same(post[2]) || !post[1].same(post[3]) {
		return m.violate("books_differ", "books and outputs differ between voters after the marker")
	}
	if err = m.expandRequire("3 contracted", true); err != nil {
		return err
	}
	m.say("PHASE 3 ok: the marker fired once at index %d on every voter after the contraction; ledger-form evaluations; books and outputs identical", marker)
	return nil
}

// declaredMin is the lowest protocol any voter's apply database records for any member.
func (m *mixedRun) declaredMin() uint64 {
	lowest := ^uint64(0)
	for _, id := range []uint64{1, 2, 3} {
		for k, v := range m.observe(id).Declared {
			if strings.Contains(k, ":node-") { // not the stale "single" declaration of the installation's first run
				lowest = min(lowest, v)
			}
		}
	}
	return lowest
}

// waitDeclaredAll waits until every declaration every voter records is at least protocol.
func (m *mixedRun) waitDeclaredAll(label string, protocol uint64) error {
	deadline := time.Now().Add(120 * time.Second)
	for {
		low := m.declaredMin()
		if low >= protocol {
			m.say("%s: every member declared at least protocol %d", label, protocol)
			return nil
		}
		if time.Now().After(deadline) {
			return m.violate("declarations_below", fmt.Sprintf("%s: lowest declaration %d, want %d", label, low, protocol))
		}
		time.Sleep(2 * time.Second)
	}
}
