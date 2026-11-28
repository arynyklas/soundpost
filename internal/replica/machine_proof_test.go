// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func proofFileOf(dir string) string { return filepath.Join(dir, "raft", machineProofFile) }

// restamp recomputes the trailing checksum of a proof record.
func restamp(b []byte) {
	binary.BigEndian.PutUint32(b[len(b)-4:], crc32.ChecksumIEEE(b[:len(b)-4]))
}

func requireResidueWithout(t *testing.T, g *Group, ruleSet uint64, name string) {
	t.Helper()
	got, err := g.MachineResidue(ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(got, name) {
		t.Fatalf("MachineResidue(%d) = %v, must not name %s", ruleSet, got, name)
	}
}

// The proof a pass leaves is durable: after a restart the voter still answers for the rule set
// the pass covered, with the same floor, and a later pass is not needed to prove it.
func TestMachineProofSurvivesARestart(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	s.pass(1)
	s.cleanCut()
	residueIs(t, s.group, 1)
	floor := func() uint64 { s.group.mu.Lock(); defer s.group.mu.Unlock(); return s.group.machineFloor }()
	s.reopen(newWholeMachine(id))
	residueIs(t, s.group, 1)
	s.group.mu.Lock()
	rules, got := s.group.machineRules, s.group.machineFloor
	s.group.mu.Unlock()
	if rules != 1 || got != floor || floor == 0 {
		t.Fatalf("restored proof (%d, %d), want (1, %d)", rules, got, floor)
	}
	residueIs(t, s.group, 2, ResidueMachineCommands) // a newer rule set is not covered
	requireNoHits(t, root, "after the restart", wholeCanaryA)
	// Commands after the restart keep the proof, durably: a second restart still has it.
	s.put(map[string]string{"keep": wholeKeep, "later": "x"})
	residueIs(t, s.group, 1)
	s.reopen(newWholeMachine(id))
	residueIs(t, s.group, 1)
}

// The proof survives the journal's compaction and a snapshot cut, which rewrite the journal.
func TestMachineProofSurvivesCompactionAndRestart(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	s.pass(1)
	s.cleanCut()
	s.cutAndCompact()
	s.reopen(newWholeMachine(id))
	residueIs(t, s.group, 1)
}

// A missing or damaged record is no proof, never a trusted one.
func TestAMissingOrCorruptMachineProofIsNoProof(t *testing.T) {
	damage := map[string]func(t *testing.T, path string){
		"missing": func(t *testing.T, path string) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		},
		"rule set flipped": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			b[8+len(model.ID{})+7] ^= 0x02 // rules 1 -> 3: would still cover rule set 1
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"floor flipped": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			b[8+len(model.ID{})+15] ^= 0x01
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"truncated": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(path, b[:len(b)-3], 0600); err != nil {
				t.Fatal(err)
			}
		},
		"another group's": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			b[8] ^= 0xff
			restamp(b) // a well-formed record of another group
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"empty": func(t *testing.T, path string) {
			if err := os.WriteFile(path, nil, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"floor beyond the log": func(t *testing.T, path string) {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			binary.BigEndian.PutUint64(b[8+len(model.ID{})+8:], 1<<40)
			restamp(b)
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, apply := range damage {
		t.Run(name, func(t *testing.T) {
			id := model.NewID()
			dir := t.TempDir()
			s := openWhole(t, dir, id, nil)
			s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
			s.put(map[string]string{"keep": wholeKeep})
			s.pass(1)
			s.cleanCut()
			residueIs(t, s.group, 1)
			s.stop()
			apply(t, proofFileOf(dir))
			s.open(newWholeMachine(id))
			residueIs(t, s.group, 1, ResidueMachineCommands)
		})
	}
}

// A committed stale command withdraws the proof durably: a restart on a machine that already
// applied it (no replay) does not find a proof.
func TestAStaleCommandWithdrawsTheDurableProof(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	stale := wholeEntry(s.machine.current().Rev, map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	s.put(map[string]string{"keep": wholeKeep})
	s.pass(1)
	s.cleanCut()
	if _, err := os.Stat(proofFileOf(dir)); err != nil {
		t.Fatalf("the pass left no durable proof: %v", err)
	}
	if _, err := s.propose(stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("the stale command was not rejected: %v", err)
	}
	if _, err := os.Stat(proofFileOf(dir)); !os.IsNotExist(err) {
		t.Fatalf("a stale command left the durable proof in place: %v", err)
	}
	s.reopen(s.machine) // the machine kept what it applied: nothing is replayed
	residueIs(t, s.group, 1, ResidueMachineCommands)
}

// A command that applies cleanly leaves the proof in place, on disk too.
func TestACleanControlCommandKeepsTheDurableProof(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	s.pass(1)
	s.cleanCut()
	s.put(map[string]string{"keep": wholeKeep, "again": "y"})
	if _, err := os.Stat(proofFileOf(dir)); err != nil {
		t.Fatalf("a clean command removed the durable proof: %v", err)
	}
}

// A snapshot installed from the leader withdraws the durable proof before the machine is restored.
func TestInstalledSnapshotRemovesTheDurableProof(t *testing.T) {
	v := newWholeVoters(t)
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	v.wire.block(3)
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	v.put(map[string]string{"keep": wholeKeep})
	v.pass(3, 1)
	file := filepath.Join(v.dirs[3], machineProofFile)
	if _, err := os.Stat(file); err != nil {
		t.Fatalf("fixture invalid: voter 3 has no durable proof: %v", err)
	}
	leader := v.wire.nodes[1]
	if err := testAwait(t, v.wire, func(ctx context.Context) error {
		_, err := leader.CreateSnapshot(ctx, model.Cursor{Group: v.id, Index: leader.Status().ApplicationCursor.Index})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.put(map[string]string{"keep": wholeKeep, "after": "cut"})
	v.catchUp(3)
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("an installed snapshot left the durable proof in place: %v", err)
	}
}
