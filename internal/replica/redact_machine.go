// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// Residue names reported by MachineResidue besides ResidueJournal and ResidueSnapshots.
const (
	// ResidueMachineCommands: no redaction pass of this process covers the retained commands
	// (none ran, a snapshot was installed, a stale command was committed, or the caller's rules
	// grew since).
	ResidueMachineCommands = "raft_machine_commands"
	// ResiduePins: a backup pin is live; the backup in flight holds copies this node cannot
	// rewrite or vouch for.
	ResiduePins = "raft_journal_pins"
)

// ProofWatcher is implemented by a machine that wants to know when the group drops the proof a
// redaction pass left (MachineResidue turns non-empty): when a snapshot is restored from the
// leader and when a stale control command is committed. The control store withdraws its
// cluster attestation (internal/control/attest.go) on it. ProofWithdrawn is called with the
// group lock held, from the apply path: it must return at once and must not call back into the
// group (a channel send that cannot block is the intended body).
type ProofWatcher interface{ ProofWithdrawn() }

// proofWithdrawn tells the machine, when it is a ProofWatcher, that the proof is gone.
func (g *Group) proofWithdrawn() {
	if w, ok := g.machine.(ProofWatcher); ok {
		w.ProofWithdrawn()
	}
}

// MachineRedaction is the state machine's half of redacting its retained commands: given the
// payload of one retained command it returns the payload to retain instead, and changed=false
// (replacement ignored) when nothing in it is to be forgotten. It must be a pure function of the
// payload and of state that does not change while the group lock is held (it is called with the
// lock held, so it must not call back into the group), idempotent (redacting a replacement
// changes nothing), and the replacement must be a payload the machine applies to the state the
// original produces on replay.
type MachineRedaction func(payload []byte) (replacement []byte, changed bool, err error)

// MachineRedactResult is what one RedactMachineCommands call changed (RedactResult.Redacted counts
// the commands the retry table names that the pass redacted: those whose payload it replaced in the
// table and those the table keeps by digest, whose copies in the log, journal and pins it replaced)
// and Floor, the physical index the group had applied when the pass
// finished: a snapshot or journal head cut at or before it may still carry the original
// payloads (Residue(Floor)).
type MachineRedactResult struct {
	RedactResult
	Floor uint64
}

// RedactMachineCommands rewrites the payload of every retained command of kind Control for which
// redact reports a change, in every place this group keeps one that it can rewrite: the retry
// table, every entry of the on-disk journal (temp file, fsync, atomic rename; superseded entries
// that were overwritten in the log included), the in-memory log that is sent to a voter that is
// behind (it receives the redacted command and never stores the original), the commands kept for
// retry recognition, and the entries of every backup pin archive. It is RedactCompleted for a
// machine that owns the replacement function itself, because a control command carries the
// whole state and its replacement cannot be listed by application index: it is derived from the
// payload. A retry-table command kept by digest (DigestRetryMachine) has no payload: it is not
// offered to redact and no replacement is written into it; the copies of that command in the log,
// the journal and the pins are redacted, and Redacted counts it.
//
// A command keeps its ID, kind, term, physical and application index and outcome, so a retry
// answers with the original receipt; its Original digest keeps the digest of the payload it was
// proposed with, so a retry carrying the original payload is still recognized. The crash
// discipline is RedactCompleted's: an error before the journal rename leaves the group untouched
// and the call is repeated; an error after it fails the group until a restart and the call is
// repeated. The pass is idempotent.
//
// What cannot be rewritten in place is a snapshot directory and the journal's sealed head
// snapshot (the raft MemoryStorage cannot replace a snapshot at the same index): they are
// replaced by a snapshot cut at a LATER index, SnapshotStore.DropSuperseded and CompactJournal
// (see the Floor of the result and Residue).
//
// ruleSet is an opaque, caller-chosen number stamped on the pass; the caller asks MachineResidue
// with the rule set that is in force now, and a pass covers every rule set it is not older than.
// It must not be zero. The proof the pass leaves (MachineResidue) is withdrawn when a snapshot
// is installed from the leader (it is the leader's retry table as cut) and when a command that
// was rejected as stale is committed afterwards (it carries the state it was built from).
// Everything is about THIS voter's copy; other voters redact their own.
//
// Only commands of kind Control are offered to redact; every other kind is left alone. A
// redact error, an empty or oversized replacement, or two copies of one command ID that were
// not proposed with the same payload refuse the whole call before anything is written.
func (g *Group) RedactMachineCommands(ctx context.Context, ruleSet uint64, redact MachineRedaction) (MachineRedactResult, error) {
	if err := ctx.Err(); err != nil {
		return MachineRedactResult{}, err
	}
	if ruleSet == 0 || redact == nil {
		return MachineRedactResult{}, ErrInvalid
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return MachineRedactResult{}, ErrUnavailable
	}
	collect := &machineCollector{redact: redact, memo: map[[32]byte]machineMemo{}, targets: map[model.ID]*redactTarget{}, proposed: map[model.ID]model.Hash{}}
	completed := make([]model.ID, 0, len(g.completed))
	for id := range g.completed {
		completed = append(completed, id)
	}
	sort.Slice(completed, func(i, j int) bool { return bytes.Compare(completed[i][:], completed[j][:]) < 0 })
	for _, id := range completed {
		if err := collect.consider(g.completed[id].Entry); err != nil {
			return MachineRedactResult{}, err
		}
	}
	if err := g.eachMemoryEntryLocked(func(ent *pb.Entry) error {
		if e, ok := parseEntry(ent); ok {
			return collect.consider(e)
		}
		return nil
	}); err != nil {
		return MachineRedactResult{}, err
	}
	if err := scanJournalEntries(filepath.Join(filepath.Dir(g.disk.file.Name()), "ready.wal"), func(ent *pb.Entry) error {
		if e, ok := parseEntry(ent); ok {
			return collect.consider(e)
		}
		return nil
	}); err != nil {
		return MachineRedactResult{}, err
	}
	for _, p := range g.pins {
		if err := scanPinArchive(p.path, func(ent *pb.Entry) error {
			if e, ok := parseEntry(ent); ok {
				return collect.consider(e)
			}
			return nil
		}); err != nil {
			return MachineRedactResult{}, err
		}
	}
	targets := collect.targets
	var res MachineRedactResult
	if len(targets) == 0 {
		g.machineRules, g.machineFloor = ruleSet, g.applied
		res.Floor = g.applied
		return res, nil
	}

	memory, err := g.redactedLogLocked(targets)
	if err != nil {
		return MachineRedactResult{}, err
	}
	journalChanges := 0
	if err = scanJournalEntries(filepath.Join(filepath.Dir(g.disk.file.Name()), "ready.wal"), func(ent *pb.Entry) error {
		replaced, rerr := redactedEntry(ent, targets)
		if replaced != nil {
			journalChanges++
		}
		return rerr
	}); err != nil {
		return MachineRedactResult{}, err
	}
	if err = g.trip(HookRedactBegin); err != nil {
		return MachineRedactResult{}, err
	}
	if res.Pins, err = g.redactPinsLocked(targets); err != nil {
		return MachineRedactResult{}, err
	}
	if len(memory) > 0 || journalChanges > 0 {
		if res.Journal, err = g.rewriteJournalRedacted(targets); err != nil {
			var torn *tornError
			if errors.As(err, &torn) {
				g.failStop(FailMaintenance)
				return MachineRedactResult{}, torn.error
			}
			return MachineRedactResult{}, err
		}
		if len(memory) > 0 {
			if err = g.trip(HookRedactMemory); err != nil {
				g.failStop(FailMaintenance)
				return MachineRedactResult{}, err
			}
			if err = g.swapLogLocked(memory); err != nil {
				g.failStop(FailMaintenance)
				return MachineRedactResult{}, err
			}
		}
	}
	for id, t := range targets {
		if c, ok := g.completed[id]; ok {
			switch {
			case len(c.Entry.Payload) == 0:
				// Kept by digest (DigestRetryMachine): the table holds no payload and the
				// replacement is never written into it; the command is redacted all the same,
				// in the log, the journal and the pins above.
				res.Redacted++
			case !bytes.Equal(c.Entry.Payload, t.replacement):
				c.Entry = redactedCommand(c.Entry, t.replacement)
				g.completed[id] = c
				res.Redacted++
			}
		}
		if l, ok := g.logCommands[id]; ok && len(l.Entry.Payload) > 0 && !bytes.Equal(l.Entry.Payload, t.replacement) {
			l.Entry = redactedCommand(l.Entry, t.replacement)
			g.logCommands[id] = l
		}
	}
	g.sendSnap = nil // built from the retry table
	g.machineRules, g.machineFloor = ruleSet, g.applied
	res.Floor = g.applied
	return res, nil
}

type machineMemo struct {
	replacement []byte
	changed     bool
}

// machineCollector decides, once per distinct payload, what the machine replaces it by, and
// remembers one replacement per command ID.
type machineCollector struct {
	redact   MachineRedaction
	memo     map[[32]byte]machineMemo
	targets  map[model.ID]*redactTarget
	proposed map[model.ID]model.Hash
}

func (c *machineCollector) consider(e Entry) error {
	if e.Kind != Control || len(e.Payload) == 0 { // an empty payload is a retry-table entry kept by digest: nothing to redact
		return nil
	}
	key := sha256.Sum256(e.Payload)
	m, ok := c.memo[key]
	if !ok {
		replacement, changed, err := c.redact(e.Payload)
		if err != nil {
			return err
		}
		if changed {
			if len(replacement) == 0 || len(replacement) > maxEntryPayload {
				return ErrInvalid
			}
			m = machineMemo{replacement: bytes.Clone(replacement), changed: true}
		}
		c.memo[key] = m
	}
	if !m.changed {
		return nil
	}
	proposed := e.proposed()
	if old, seen := c.proposed[e.ID]; seen {
		if old != proposed {
			return ErrConflict // one command ID, two different proposals
		}
		return nil // the first replacement stands: any is a payload the machine accepts
	}
	c.proposed[e.ID] = proposed
	c.targets[e.ID] = &redactTarget{replacement: m.replacement}
	return nil
}

// eachMemoryEntryLocked calls visit for every entry of the retained in-memory log.
func (g *Group) eachMemoryEntryLocked(visit func(*pb.Entry) error) error {
	first, _ := g.memory.FirstIndex()
	last, _ := g.memory.LastIndex()
	for lo := first; lo <= last; {
		entries, err := g.memory.Entries(lo, last+1, 8<<20)
		if err != nil {
			return err
		}
		for _, ent := range entries {
			lo = ent.GetIndex() + 1
			if err = visit(ent); err != nil {
				return err
			}
		}
	}
	return nil
}

// scanJournalEntries reads ready.wal and calls visit for every entry of every record, in file
// order, superseded entries included. It writes nothing.
func scanJournalEntries(path string, visit func(*pb.Entry) error) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	for {
		var header [16]byte
		if _, err = io.ReadFull(in, header[:]); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		if string(header[:4]) != "SPR1" || binary.BigEndian.Uint32(header[12:]) != crc32.Checksum(header[:12], readyCRC) {
			return ErrInvalid
		}
		length := binary.BigEndian.Uint32(header[4:8])
		if length == 0 || length > maxReadyBytes {
			return ErrInvalid
		}
		raw := make([]byte, length)
		if _, err = io.ReadFull(in, raw); err != nil {
			return err
		}
		if crc32.Checksum(raw, readyCRC) != binary.BigEndian.Uint32(header[8:12]) {
			return ErrInvalid
		}
		var record readyRecord
		if model.StrictJSON(raw, &record) != nil {
			return ErrInvalid
		}
		for _, rawEntry := range record.Entries {
			ent := &pb.Entry{}
			if proto.Unmarshal(rawEntry, ent) != nil {
				return ErrInvalid
			}
			if err = visit(ent); err != nil {
				return err
			}
		}
	}
}

// scanPinArchive calls visit for every entry of one pin archive (a torn tail is ignored as
// redactPinArchive does). It writes nothing.
func scanPinArchive(path string, visit func(*pb.Entry) error) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for len(raw) >= 8 {
		n := binary.BigEndian.Uint32(raw[:4])
		if uint64(n) > uint64(len(raw)-8) || crc32.Checksum(raw[8:8+n], readyCRC) != binary.BigEndian.Uint32(raw[4:8]) {
			return nil
		}
		record := raw[8 : 8+n]
		raw = raw[8+n:]
		var r pinRecord
		if model.StrictJSON(record, &r) != nil {
			return ErrCorrupt
		}
		if r.Entry != nil {
			ent := &pb.Entry{}
			if proto.Unmarshal(r.Entry, ent) != nil {
				return ErrCorrupt
			}
			if err = visit(ent); err != nil {
				return err
			}
		}
	}
	return nil
}

// MachineResidue reports where this voter can still hold a copy of what RedactMachineCommands
// forgets, for the rule set in force now: ResidueMachineCommands while no pass of this process
// covers ruleSet (the retained commands are not proven redacted); otherwise Residue of the
// pass's floor (the journal head or a snapshot cut at or before it, sealed and replaced only by
// a later cut, DropSuperseded and CompactJournal); and ResiduePins while a backup pin is live.
// It reads state only. An empty answer is a statement about this voter alone.
func (g *Group) MachineResidue(ruleSet uint64) ([]string, error) {
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	if err := g.reapExpiredPinsLocked(); err != nil {
		g.mu.Unlock()
		return nil, err
	}
	proven := ruleSet != 0 && g.machineRules >= ruleSet
	floor, pins := g.machineFloor, len(g.pins)
	g.mu.Unlock()
	var out []string
	if !proven {
		out = append(out, ResidueMachineCommands)
	} else {
		residue, err := g.Residue(floor)
		if err != nil {
			return nil, err
		}
		out = append(out, residue...)
	}
	if pins > 0 {
		out = append(out, ResiduePins)
	}
	return out, nil
}
