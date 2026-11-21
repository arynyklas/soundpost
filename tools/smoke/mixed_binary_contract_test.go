// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mixedExpand is what the real ledger and replay writes of a mixed-group scenario keep: the accounts that
// write and read through the HTTPS API and every write acknowledged so far.
type mixedExpand struct {
	owner, analyst *expandUser
	writes         []expandWrite
}

func (m *mixedRun) expandReady() bool { return m.exp != nil && m.exp.analyst != nil }

// expandSetup creates the analyst account through voter id.
func (m *mixedRun) expandSetup(id uint64) error {
	owner, err := loginOwner(m.sites[id], m.fx)
	if err != nil {
		return err
	}
	analyst, err := provisionAnalyst(owner, m.sites[id], m.fx)
	if err != nil {
		return err
	}
	m.exp = &mixedExpand{owner: owner, analyst: analyst}
	m.say("expand: analyst account created through voter %d (%s)", id, m.release[id])
	return nil
}

// expandWriteVia makes the cluster write a ledger and a replay through voter id (an uploaded map named by an
// error occurrence, held by the issue producer on whichever voter leads, and a new replay), and waits until
// every voter's stored state holds both.
func (m *mixedRun) expandWriteVia(id uint64, salt string) error {
	m.say("expand: write %q through voter %d (%s)", salt, id, m.release[id])
	// The scenario changes the source policy: batches must carry its current revision.
	owner, err := m.login(id)
	if err != nil {
		return m.violate("expand_login", err.Error())
	}
	src, err := m.waitSourceOpen(id, owner)
	if err != nil {
		return m.violate("expand_policy", err.Error())
	}
	m.fx.policyRevision = src.Policy.Revision
	if err := m.exp.analyst.login(m.sites[id]); err != nil {
		return m.violate("expand_login", err.Error())
	}
	w, err := writeLedgerAndReplay(m.sites[id], m.exp.analyst, m.fx, m.c.data[id], salt)
	if err != nil {
		return m.violate("expand_write", fmt.Sprintf("%s through voter %d (%s): %v", salt, id, m.release[id], err))
	}
	m.exp.writes = append(m.exp.writes, w)
	root, replay := w.artifact.root().String(), w.replay.String()
	for _, other := range []uint64{1, 2, 3} {
		if _, err = waitStored(m.c.data[other], m.fx.org, m.fx.project, 120*time.Second, "the write "+salt+" on voter "+strconv.FormatUint(other, 10), func(l storedLayout) bool {
			_, a := l.Ledgers[root]
			_, g := l.Groups[replay]
			return a && g
		}); err != nil {
			return m.violate("expand_write_not_replicated", err.Error())
		}
	}
	return nil
}

// expandReadVia reads every write so far through voter id.
func (m *mixedRun) expandReadVia(id uint64, who string) error {
	if err := m.exp.analyst.login(m.sites[id]); err != nil {
		return m.violate("expand_login", err.Error())
	}
	if err := requireReads(m.sites[id], m.exp.analyst, m.fx, who, m.exp.writes); err != nil {
		return m.violate("expand_read", fmt.Sprintf("voter %d (%s) %s: %v", id, m.release[id], who, err))
	}
	m.say("expand: voter %d (%s) read %d ledgers and replays", id, m.release[id], len(m.exp.writes))
	return nil
}

// expandLayouts reads the stored layout of every voter, waiting until the three agree (the voters are one
// replicated state: equal layout digests).
func (m *mixedRun) expandLayouts(label string) (map[uint64]storedLayout, error) {
	deadline := time.Now().Add(90 * time.Second)
	for {
		out := map[uint64]storedLayout{}
		agree := true
		var first string
		for _, id := range []uint64{1, 2, 3} {
			l, err := readStoredLayout(m.c.data[id], m.fx.org, m.fx.project)
			if err != nil {
				agree = false
				break
			}
			out[id] = l
			if first == "" {
				first = l.Digest
			} else if l.Digest != first {
				agree = false
			}
		}
		if agree && len(out) == 3 {
			for _, id := range []uint64{1, 2, 3} {
				m.say("expand layout %s: voter %d: %s", label, id, out[id].summary())
			}
			return out, nil
		}
		if time.Now().After(deadline) {
			for id, l := range out {
				m.say("expand layout %s (no agreement): voter %d: %s", label, id, l.summary())
			}
			return out, m.violate("expand_layouts_differ", label+": the voters' stored ledger index and pins do not agree")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// expandRequire checks the stored layout of every voter: expanded (all three per-project values, shards and
// pins when the new binary wrote) or contracted (none, marker present).
func (m *mixedRun) expandRequire(label string, contracted bool) error {
	layouts, err := m.expandLayouts(label)
	if err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		var problems []string
		if contracted {
			problems = layouts[id].problems(true)
		} else {
			problems = layouts[id].problems(false)
		}
		if len(problems) > 0 {
			return m.violate("expand_layout", fmt.Sprintf("%s: voter %d: %s", label, id, strings.Join(problems, "; ")))
		}
	}
	return nil
}

// expandD is phase D of TestMixedBinaryVoters: the all-candidate group writes real ledgers and replays through
// each voter and every voter reads them; the stored state of every voter then holds the sharded index, the
// per-replay pins and the previous release's per-project values.
func (m *mixedRun) expandD(newNode uint64) error {
	if err := m.expandSetup(newNode); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if err := m.expandWriteVia(id, fmt.Sprintf("D-voter-%d", id)); err != nil {
			return err
		}
	}
	for _, id := range []uint64{1, 2, 3} {
		if err := m.expandReadVia(id, "new"); err != nil {
			return err
		}
	}
	layouts, err := m.expandLayouts("D all candidate")
	if err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if problems := layouts[id].requireExpanded(true, true); len(problems) > 0 {
			return m.violate("expanded_state_wrong", fmt.Sprintf("D voter %d: %s", id, strings.Join(problems, "; ")))
		}
	}
	return nil
}

// expandE is phase E: the voter rolled back to the previous release reads the ledgers and replays the
// candidates wrote, writes its own, and the candidate reads them all.
func (m *mixedRun) expandE(back, newNode uint64) error {
	if err := m.expandReadVia(back, "old"); err != nil {
		return err
	}
	if err := m.expandWriteVia(back, fmt.Sprintf("E-old-voter-%d", back)); err != nil {
		return err
	}
	if err := m.expandReadVia(newNode, "new"); err != nil {
		return err
	}
	return m.expandRequire("E one voter rolled back", false)
}

// expandG is phase G: with the group on the candidate again every voter reads every ledger and replay,
// including what the previous release wrote.
func (m *mixedRun) expandG() error {
	for _, id := range []uint64{1, 2, 3} {
		if err := m.expandReadVia(id, "new"); err != nil {
			return err
		}
	}
	return m.expandRequire("G all candidate again", false)
}

// TestMixedBinaryContractRefusal is the operator step `soundpost upgrade contract-indexes` on a REAL three-voter
// cluster that is rolled back and forth between the candidate and the previous release (D70):
//
//	1  all three voters run the candidate; it writes ledgers (uploaded maps named by error occurrences) and replays:
//	   every voter's stored state holds the shards, the per-replay pins AND the previous release's per-project values;
//	2  two voters are rolled back to the previous release, one at a time: each reads every ledger and replay the
//	   candidate wrote and the group keeps writing (the previous release's own layout enters the state);
//	3  one candidate voter and two previous-release voters: contract-indexes against the candidate is REFUSED
//	   (unsupported, layout_unsupported_by:<the two previous-release identities>) and no voter's stored ledger index
//	   or pins changed;
//	4  the previous-release voters are rolled to the candidate one at a time: after the first the step is still
//	   refused (naming the one that is left); after the last it succeeds: every voter's stored state has none of the
//	   per-project values, the marker is present, the states agree and /readyz stays ok; a repeat is a no-op;
//	5  a further ledger and replay write leave no per-project value on any voter and every voter reads everything.
//
// Environment: SOUNDPOST_MIXED_OLD_BINARY, SOUNDPOST_MIXED_NEW_BINARY (as TestMixedBinaryVoters),
// SOUNDPOST_MIXED_EVIDENCE, SOUNDPOST_MIXED_NEW_NODE (the voter that stays on the candidate throughout; default 1).
func TestMixedBinaryContractRefusal(t *testing.T) {
	oldBin, newBin, evidence := os.Getenv("SOUNDPOST_MIXED_OLD_BINARY"), os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if oldBin == "" || newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_OLD_BINARY and SOUNDPOST_MIXED_NEW_BINARY to static soundpost binaries of the previous release and the candidate")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	nodes := []uint64{1}
	if v := os.Getenv("SOUNDPOST_MIXED_NEW_NODE"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil || n < 1 || n > 3 {
			t.Fatalf("SOUNDPOST_MIXED_NEW_NODE=%q", v)
		}
		nodes = []uint64{n}
	}
	for _, newNode := range nodes {
		t.Run(fmt.Sprintf("candidate_voter_%d", newNode), func(t *testing.T) {
			dir := filepath.Join(evidence, fmt.Sprintf("contract-voter-%d", newNode))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			trace, err := os.Create(filepath.Join(dir, "trace.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer trace.Close()
			m := &mixedRun{t: t, trace: trace, evidence: dir, oldBin: oldBin, newBin: newBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
			runErr := m.runContract(newNode)
			m.writeLogs()
			if runErr != nil && m.violation == "" {
				m.violation = "harness_error: " + runErr.Error()
			}
			m.say("RESULT violation=%q harness_error=%v", m.violation, runErr)
			if m.violation != "" {
				t.Fatalf("contract scenario violated: %s", m.violation)
			}
		})
	}
}

// contract runs the operator step against voter id and returns its output and exit status.
func (m *mixedRun) contract(id uint64) (string, int, error) {
	return runContractCLI(m.newBin, "https://"+m.c.public[id], filepath.Join(m.c.data[id], "server.crt"), "owner@install-smoke.invalid", m.fx.password)
}

// requireRefused runs the step against voter id and requires the typed refusal naming exactly the voters that
// run the previous release, then that nothing of the ledger index or the pins changed on any voter.
func (m *mixedRun) requireRefused(label string, id uint64, before map[uint64]storedLayout) error {
	out, code, err := m.contract(id)
	if err != nil {
		return err
	}
	m.say("contract-indexes against voter %d (%s) [%s]: exit %d: %s", id, m.release[id], label, code, out)
	if code == 0 || !strings.Contains(out, "unsupported") || !strings.Contains(out, "layout_unsupported_by:") {
		return m.violate("contract_not_refused", fmt.Sprintf("%s: exit %d output %q", label, code, out))
	}
	tail := out[strings.Index(out, "layout_unsupported_by:"):]
	for _, n := range []uint64{1, 2, 3} {
		identity := distNodes[n-1].identity
		named := strings.Contains(tail, identity)
		if m.release[n] == "old" && !named {
			return m.violate("contract_refusal_misses_member", fmt.Sprintf("%s: %s runs the previous release but is not named: %s", label, identity, out))
		}
		if m.release[n] == "new" && named {
			return m.violate("contract_refusal_names_candidate", fmt.Sprintf("%s: %s runs the candidate but is named: %s", label, identity, out))
		}
	}
	after, err := m.expandLayouts(label + " after the refusal")
	if err != nil {
		return err
	}
	for _, v := range []uint64{1, 2, 3} {
		if after[v].Digest != before[v].Digest || after[v].Contracted {
			return m.violate("refused_step_changed_state", fmt.Sprintf("%s: voter %d layout %s -> %s", label, v, before[v].summary(), after[v].summary()))
		}
	}
	return nil
}

func (m *mixedRun) runContract(newNode uint64) error {
	cleanup, err := m.startGroup(func(uint64) string { return "new" })
	defer cleanup()
	if err != nil {
		return err
	}
	others := m.others(newNode)

	// ---- 1. the candidate writes (all three voters run it) ----
	if err = m.expandSetup(newNode); err != nil {
		return err
	}
	for i, via := range []uint64{newNode, others[0], others[1]} {
		if err = m.expandWriteVia(via, fmt.Sprintf("all-new-%d", i+1)); err != nil {
			return err
		}
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = m.expandReadVia(id, "new"); err != nil {
			return err
		}
	}
	layouts, err := m.expandLayouts("1 all candidate")
	if err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if problems := layouts[id].requireExpanded(true, true); len(problems) > 0 {
			return m.violate("expanded_state_wrong", fmt.Sprintf("voter %d: %s", id, strings.Join(problems, "; ")))
		}
	}
	if err = m.settle("1 all candidate, ledgers and replays written"); err != nil {
		return err
	}

	// ---- 2. two voters back to the previous release, one at a time ----
	for i, id := range others {
		if err = m.rollTo(id, "old"); err != nil {
			return err
		}
		if err = m.expandReadVia(id, "old"); err != nil {
			return err
		}
		if err = m.expandWriteVia(id, fmt.Sprintf("old-voter-%d", id)); err != nil {
			return err
		}
		if err = m.expandReadVia(newNode, "new"); err != nil {
			return err
		}
		if err = m.expandRequire(fmt.Sprintf("2.%d after the write through the rolled-back voter %d", i+1, id), false); err != nil {
			return err
		}
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = m.expandReadVia(id, m.release[id]); err != nil {
			return err
		}
	}
	if err = m.settle("2 one candidate voter and two previous-release voters"); err != nil {
		return err
	}

	// ---- 3. refused while previous-release voters are members ----
	before, err := m.expandLayouts("3 before the refused step")
	if err != nil {
		return err
	}
	if err = m.requireRefused("3 candidate + two previous-release voters", newNode, before); err != nil {
		return err
	}
	if err = m.settle("3 after the refused step"); err != nil {
		return err
	}

	// ---- 4. roll the previous-release voters to the candidate, one at a time ----
	if err = m.rollTo(others[0], "new"); err != nil {
		return err
	}
	if err = m.expandWriteVia(others[0], fmt.Sprintf("rolled-forward-%d", others[0])); err != nil {
		return err
	}
	if before, err = m.expandLayouts("4 one previous-release voter left"); err != nil {
		return err
	}
	if err = m.requireRefused("4 one previous-release voter left", newNode, before); err != nil {
		return err
	}
	if err = m.rollTo(others[1], "new"); err != nil {
		return err
	}
	if err = m.expandWriteVia(others[1], fmt.Sprintf("rolled-forward-%d", others[1])); err != nil {
		return err
	}
	if err = m.expandRequire("4 all candidate again, before the step", false); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = m.expandReadVia(id, "new"); err != nil {
			return err
		}
	}
	if err = m.settle("4 all candidate again, before the step"); err != nil {
		return err
	}
	out, code, err := m.contract(newNode)
	if err != nil {
		return err
	}
	m.say("contract-indexes against voter %d (all candidate): exit %d: %s", newNode, code, out)
	if code != 0 || !strings.Contains(out, "indexes contracted") {
		return m.violate("contract_failed", fmt.Sprintf("exit %d output %q", code, out))
	}
	if err = m.settle("4 after the step"); err != nil {
		return err
	}
	if err = m.expandRequire("4 contracted", true); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = m.expandReadVia(id, "new_contracted"); err != nil {
			return err
		}
	}
	contracted, err := m.expandLayouts("4 contracted")
	if err != nil {
		return err
	}
	out, code, err = m.contract(newNode)
	if err != nil {
		return err
	}
	m.say("contract-indexes repeated against voter %d: exit %d: %s", newNode, code, out)
	if code != 0 || !strings.Contains(out, "indexes already contracted") {
		return m.violate("repeat_not_a_noop", fmt.Sprintf("exit %d output %q", code, out))
	}
	again, err := m.expandLayouts("4 after the repeat")
	if err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if again[id].Digest != contracted[id].Digest {
			return m.violate("repeat_changed_state", fmt.Sprintf("voter %d: %s -> %s", id, contracted[id].summary(), again[id].summary()))
		}
	}

	// ---- 5. writes after the step leave no per-project value ----
	for i, via := range []uint64{newNode, others[0], others[1]} {
		if err = m.expandWriteVia(via, fmt.Sprintf("contracted-%d", i+1)); err != nil {
			return err
		}
	}
	if err = m.expandRequire("5 writes after the step", true); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if err = m.expandReadVia(id, "new_contracted"); err != nil {
			return err
		}
	}
	return m.settle("5 final")
}
