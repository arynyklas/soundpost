// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// TestFreshInstallOfTheCandidateIsContractedOnRealVoters (D72) runs a REAL three-voter cluster of the candidate
// binary on an installation the candidate itself bootstrapped (no previous release ever wrote its control
// state). The Bootstrap command writes the born-contracted mark into the replicated control state, so every
// voter holds it, the organization created on the installation is born contracted, and real ledger and replay
// writes through each voter leave NONE of the previous release's per-project values (no whole-project index or
// anchor, no whole-project pin map) on any voter: the shards, the per-replay pins and the marker only. The stored
// states of the three voters agree (equal digests, valid seals).
//
// Its counterpart is TestMixedBinaryVoters and TestUpgradeRollbackOfProducedBinaries: an installation bootstrapped
// by the previous release (5475ef6) and then upgraded stays expanded until `soundpost upgrade contract-indexes`.
//
//	SOUNDPOST_MIXED_NEW_BINARY=/path/new go test ./tools/smoke -run TestFreshInstallOfTheCandidateIsContractedOnRealVoters -count=1
func TestFreshInstallOfTheCandidateIsContractedOnRealVoters(t *testing.T) {
	newBin, evidence := os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_NEW_BINARY to the static soundpost binary of the candidate")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	if err := os.MkdirAll(evidence, 0o755); err != nil {
		t.Fatal(err)
	}
	trace, err := os.Create(filepath.Join(evidence, "trace.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()
	// The harness bootstraps with its "old" binary; here it is the candidate, so no previous release is involved.
	m := &mixedRun{t: t, trace: trace, evidence: evidence, oldBin: newBin, newBin: newBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
	cleanup, err := m.startGroup(func(uint64) string { return "new" })
	defer func() {
		m.writeLogs()
		cleanup()
	}()
	if err != nil {
		t.Fatal(err)
	}
	fail := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%v (violation %q)", err, m.violation)
		}
	}
	// The mark is in the replicated state of every voter from the first write.
	fail(m.requireBornContracted("S00 fresh group, before any write"))
	fail(m.expandSetup(1))
	for _, id := range []uint64{1, 2, 3} {
		fail(m.expandWriteVia(id, fmt.Sprintf("fresh-voter-%d", id)))
	}
	for _, id := range []uint64{1, 2, 3} {
		fail(m.expandReadVia(id, "new"))
	}
	fail(m.expandRequire("fresh installation after writes through every voter", true))
	fail(m.requireBornContracted("after the writes"))
	for _, id := range []uint64{1, 2, 3} {
		l, err := readStoredLayout(m.c.data[id], m.fx.org, m.fx.project)
		fail(err)
		if keys := l.perProjectKeys(); len(keys) > 0 {
			t.Fatalf("voter %d stores the previous release's per-project values %v on a fresh installation", id, keys)
		}
		if len(l.Ledgers) < 3 || len(l.OwnPins) < 3 {
			t.Fatalf("voter %d: %s: the writes are missing", id, l.summary())
		}
	}
	fail(m.settle("S99 fresh installation: every voter holds the same state"))
}

// requireBornContracted checks that every voter's stored control state carries the born-contracted mark.
func (m *mixedRun) requireBornContracted(label string) error {
	for _, id := range []uint64{1, 2, 3} {
		state, _, err := readControlState(m.c.data[id])
		if err != nil {
			return m.violate("born_contracted_state", fmt.Sprintf("%s: voter %d: %v", label, id, err))
		}
		var st struct{ OIDC map[string]json.RawMessage }
		if err = json.Unmarshal(state, &st); err != nil {
			return m.violate("born_contracted_state", fmt.Sprintf("%s: voter %d: %v", label, id, err))
		}
		if _, ok := st.OIDC[model.IndexesContractedKey]; !ok {
			return m.violate("not_born_contracted", fmt.Sprintf("%s: voter %d's stored control state has no %q", label, id, model.IndexesContractedKey))
		}
	}
	m.say("born contracted: every voter holds the mark (%s)", strings.TrimSpace(label))
	return nil
}
