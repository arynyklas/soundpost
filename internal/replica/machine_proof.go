// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
)

// machineProofFile is the durable form of the proof RedactMachineCommands leaves: one small
// file next to the journal holding the rule set the last completed pass covered and the physical
// index it finished at, checksummed and bound to the group. It is replaced atomically (temp file,
// fsync, rename, directory fsync) after the pass's journal rewrite is durable, and removed
// (directory fsync) BEFORE anything that withdraws the proof takes effect: a snapshot install
// from the leader (dropProof, before the machine is restored) and the apply of a retained
// control command, which may turn out stale (suspendProof, before the machine applies it;
// resumeProof only when it applied cleanly). A missing, short, corrupt, foreign or implausible
// file (floor beyond what the group has applied) is NO proof: the voter reports
// ResidueMachineCommands until a pass runs again. The file is independent of the journal's
// compaction and rewrites: the floor is a physical index, and Residue(floor) is asked of the
// journal head and snapshots as they are.
const (
	machineProofFile = "machine.proof"
	machineProofSize = 8 + len(model.ID{}) + 8 + 8 + 4
)

var machineProofMagic = [8]byte{'S', 'P', 'M', 'P', 'R', 'F', 0, 1}

func (g *Group) proofPath() string { return filepath.Join(g.dir, machineProofFile) }

func (g *Group) encodeProof(rules, floor uint64) []byte {
	b := make([]byte, 0, machineProofSize)
	b = append(b, machineProofMagic[:]...)
	b = append(b, g.group[:]...)
	b = binary.BigEndian.AppendUint64(b, rules)
	b = binary.BigEndian.AppendUint64(b, floor)
	return binary.BigEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
}

// storeProof makes (rules, floor) durable and then current in memory.
func (g *Group) storeProof(rules, floor uint64) error {
	if err := g.writeProofFile(rules, floor); err != nil {
		return err
	}
	g.machineRules, g.machineFloor = rules, floor
	return nil
}

func (g *Group) writeProofFile(rules, floor uint64) error {
	path := g.proofPath()
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(g.encodeProof(rules, floor)); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return durablefs.SyncDir(g.dir)
}

// removeProofFile removes the durable proof and makes the removal durable.
func (g *Group) removeProofFile() error {
	if err := os.Remove(g.proofPath()); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return durablefs.SyncDir(g.dir)
}

// dropProof withdraws the proof: durably first, then in memory. While the group is opening (no
// raft node yet) the journal's own head snapshot is being restored, which is not an install from
// the leader and must keep the proof loadProof is about to read.
func (g *Group) dropProof() error {
	if g.raw == nil {
		g.machineRules = 0
		return nil
	}
	if err := g.removeProofFile(); err != nil {
		return err
	}
	g.machineRules = 0
	return nil
}

// suspendProof removes the durable proof before a control command is applied (the command may be
// stale: its outcome is known only after the machine applied it). It reports whether it removed
// one; the memory proof is untouched until the outcome is known.
func (g *Group) suspendProof() (bool, error) {
	if g.machineRules == 0 {
		return false, nil
	}
	if err := g.removeProofFile(); err != nil {
		return false, err
	}
	return true, nil
}

// resumeProof writes back the proof suspendProof removed, after a clean apply.
func (g *Group) resumeProof() error {
	if g.machineRules == 0 {
		return nil
	}
	return g.writeProofFile(g.machineRules, g.machineFloor)
}

// loadProof reads the durable proof when the group opens. Anything but a well-formed file of
// this group whose floor lies within the durable log (last) is no proof.
func (g *Group) loadProof(last uint64) {
	g.machineRules, g.machineFloor = 0, 0
	b, err := os.ReadFile(g.proofPath())
	if err != nil || len(b) != machineProofSize {
		return
	}
	body := b[:len(b)-4]
	if binary.BigEndian.Uint32(b[len(b)-4:]) != crc32.ChecksumIEEE(body) || string(body[:8]) != string(machineProofMagic[:]) {
		return
	}
	if string(body[8:8+len(g.group)]) != string(g.group[:]) {
		return
	}
	rest := body[8+len(g.group):]
	rules, floor := binary.BigEndian.Uint64(rest), binary.BigEndian.Uint64(rest[8:])
	if rules == 0 || last == 0 || floor > last {
		return
	}
	g.machineRules, g.machineFloor = rules, floor
}
