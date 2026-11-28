// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// D108: the rule books and the rule outbox are records of the ledger once every member of the control group
// declared protocol 10 (and the installation is contracted), so a rule commit reads and writes the records
// of its own rule and nothing else. Until then they stay members of the blob, as every release holds them.

// newRuleFxProtocol10 is the fixture of a contracted group whose members all declared protocol 10 (the
// compact gate is the protocol-10 gate).
func newRuleFxProtocol10(t *testing.T) *ruleFx {
	t.Helper()
	f := newRuleFx(t)
	f.store.SetStatePatchGate(func() bool { return true })
	f.store.SetCompactAdmissionGate(func() bool { return true })
	return f
}

// growRuleFacts adds megabytes of rule books of other rules to the control state, in records of 64 KB (a rule
// book of the gate's estate is 170 KB) and commands of 128 records: the state a long-running installation holds
// after months of evaluations.
func growRuleFacts(t *testing.T, f *ruleFx, megabytes int) {
	t.Helper()
	pad := strings.Repeat("x", 64<<10-256)
	for done := 0; done < megabytes*16; {
		n := min(128, megabytes*16-done)
		if err := f.store.Update(f.ctx, func(st *control.State) error {
			if st.RuleBooks == nil {
				st.RuleBooks = map[string]json.RawMessage{}
			}
			for i := range n {
				rule := model.ID{0xaa, byte((done + i) >> 8), byte(done + i)}
				key := fmt.Sprintf("%s:%s:%s", f.org, f.project, rule)
				st.RuleBooks[key] = json.RawMessage(fmt.Sprintf(`{"org":%q,"project":%q,"rule":%q,"head":1,"versions":[],"pad":%q}`, f.org, f.project, rule, pad))
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		done += n
	}
}

// A commit of one rule evaluation writes the rule's own records, whatever the rest of the control state holds:
// the bytes of pages it allocates are those of a state of a megabyte or of a hundred, and it makes no reader
// decode the state again (the blob is not decoded for it, nor the shared decode rebuilt after it).
func TestARuleCommitCostsWhatItsOwnRecordsCostWhateverTheStateHolds(t *testing.T) {
	f := newRuleFxProtocol10(t)
	lease := f.lease()
	scope := f.adminScope()
	at, expected := uint64(0), uint64(0)
	payload := func(n uint64) string { return fmt.Sprintf(`{"n":%d,"series":%q}`, n, strings.Repeat("s", 6<<10)) }
	// The command is built as the rules package builds it (rules.transact): the revision comes from Store.Revision,
	// which decodes nothing, and the scope of the worker is the one it holds.
	commit := func(n int) (perCommit int64, blobDecodes, wholeDecodes uint64) {
		w0, d0, s0 := f.store.BoltWriteStatsForTest(), f.store.DecodeStats(), f.store.SparseCommitsForTest()
		for range n {
			at++
			raw, err := json.Marshal(control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &lease, Evaluation: f.evaluation(1, at, expected, control.RuleModeLive, payload(at), recordingIntent(byte(at)))})
			if err != nil {
				t.Fatal(err)
			}
			revision, err := f.store.Revision(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = f.store.Transact(f.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: revision, Kind: string(control.KindApplyRuleEvaluation), Payload: raw}); err != nil {
				t.Fatal(err)
			}
			expected++
		}
		w1, d1 := f.store.BoltWriteStatsForTest(), f.store.DecodeStats()
		t.Logf("%d commits: %d of them as records; rule_books holds %d records, the blob's RuleBooks starts %.40q", n, f.store.SparseCommitsForTest()-s0, f.store.LedgerCountForTest("rule_books"), f.store.BlobMemberForTest("RuleBooks"))
		return (w1.AllocBytes - w0.AllocBytes) / int64(n), d1.Blobs - d0.Blobs, d1.Whole - d0.Whole
	}
	commit(20) // the book holds its sixteen retained evaluations
	small, _, _ := commit(10)
	growRuleFacts(t, f, 96)
	commit(2) // the shared decode the growth dropped is rebuilt once, by whoever reads next
	large, blobs, wholes := commit(10)
	t.Logf("a rule commit allocates %d bytes of pages beside a state of a few megabytes and %d beside 96 MB more rule books; %d blob decodes and %d whole decodes in the last 10", small, large, blobs, wholes)
	if large > small+192<<10 || large > 1<<20 {
		t.Errorf("a rule commit allocates %d bytes of pages on a small state and %d after the state grew by 96 MB: what it writes follows the size of the state", small, large)
	}
	if blobs != 0 || wholes != 0 {
		t.Errorf("10 rule commits decoded the whole control state %d times (blob) and made the shared readers decode it %d times", blobs, wholes)
	}
}
