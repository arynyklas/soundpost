// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"

	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Every control command carries the whole control state, so each command the control Raft
// group retains (its journal ready.wal, its in-memory log, its snapshot envelopes, the backup pin
// archives; the retry table keeps a digest only) holds the payloads a later deletion erased from the live
// state. RedactRetainedControlCommands removes them from THIS node's copy; ResidualStores stops
// naming ResidualControlJournal exactly when that pass was proven for every erasure committed
// so far (replica.Group.MachineResidue), and keeps naming it when it was not.
//
// What it guarantees, per voter: this voter's journal, retry table (a digest only), in-memory log, snapshot
// directories and pin archives hold none of the payloads covered by the finished deletions this
// voter has committed, as of the pass, except what MachineResidue reports. A voter redacts only
// its own copy and the receipt is about the node that issues it: a voter that has not run the
// pass (it is down, partitioned, or has not applied the deletion) still holds and still names
// the residue; the pass of another voter says nothing about it, and nothing here observes the
// other voters. It does not reach backups cut before the pass, snapshots already shipped off
// the node, or bytes the filesystem keeps in freed blocks of the rewritten files.

// controlJournalScope reads, from committed state, how many erasing audits the log holds (the
// rule set a pass must cover: every erasure adds one) and whether every operation they name is
// finished (complete or failed) and still recorded. Only a finished deletion's covered payloads
// are redacted from retained commands: while it is fencing, the live state still holds effects
// the live erasure only drops when it completes.
func controlJournalScope(st State) (erasures uint64, finished bool) {
	finished = true
	for _, a := range st.Audits {
		if a.Action != controlErasedAction {
			continue
		}
		erasures++
		for _, id := range a.Targets {
			op, ok := st.Deletions[id.String()]
			if !ok || op.Phase != model.DeletePhaseComplete && op.Phase != model.DeletePhaseFailed {
				finished = false
			}
		}
	}
	return erasures, finished
}

// controlJournalResidue is what the control group can still hold, for the erasures committed so
// far, as this voter measures it; an error is reported as unmeasurable.
func (s *Store) controlJournalResidue(st State) ([]string, error) {
	g := s.ReplicaGroup()
	if g == nil {
		return nil, model.Fail(model.Unavailable)
	}
	erasures, finished := controlJournalScope(st)
	if !finished {
		return []string{replica.ResidueMachineCommands}, nil
	}
	return g.MachineResidue(erasures)
}

// controlRedactor is the redaction function handed to the replication layer. It reads the
// committed state once, under the group lock the replication layer holds while it runs (no
// command is applied meanwhile), so every retained command is redacted against the same state
// and the pass's floor is the index that state was at.
type controlRedactor struct {
	s      *Store
	loaded bool
	rules  State // the current state with only the finished deletions
	live   State
	canon  []byte
}

func (r *controlRedactor) load() error {
	live, err := r.s.localState()
	if err != nil {
		return err
	}
	r.live = live
	if r.canon, err = model.CanonicalJSON(live); err != nil {
		return err
	}
	r.rules = live
	r.rules.Deletions = map[string]model.DeletionOperation{}
	for id, op := range live.Deletions {
		if op.Phase == model.DeletePhaseComplete || op.Phase == model.DeletePhaseFailed {
			r.rules.Deletions[id] = op
		}
	}
	r.loaded = true
	return nil
}

func (r *controlRedactor) redact(payload []byte) ([]byte, bool, error) {
	if !r.loaded {
		if err := r.load(); err != nil {
			return nil, false, err
		}
	}
	replacement, changed, err := redactControlPayload(r.rules, payload)
	if err != nil || !changed {
		return payload, false, err
	}
	// The command that establishes the current state is replayed against it (the machine
	// compares them): redacting it would change what a replay computes. A deletion only
	// removes what the current state no longer has, so this refuses a state that still
	// holds covered payloads instead of rewriting history under it.
	var original controlReplacement
	if model.StrictJSON(payload, &original) != nil {
		return nil, false, model.Fail(model.Corrupt)
	}
	if original.State.Revision == r.live.Revision {
		canon, err := model.CanonicalJSON(original.State)
		if err != nil {
			return nil, false, err
		}
		if bytes.Equal(canon, r.canon) {
			return nil, false, model.Fail(model.Corrupt)
		}
	}
	return replacement, true, nil
}

// withoutPins drops the pin residue: a live backup pin is not something this pass can clear.
func withoutPins(residue []string) []string {
	var out []string
	for _, name := range residue {
		if name != replica.ResiduePins {
			out = append(out, name)
		}
	}
	return out
}

// RedactRetainedControlCommands removes the payloads that committed, finished deletions erased
// from the live control state out of every copy this node's control Raft group retains: it
// redacts the retained commands (replica.Group.RedactMachineCommands, with the rule of
// RedactControlCommand), commits one empty control revision when no command is newer than the
// redaction (a snapshot cut at the redaction's own index would be the sealed one), cuts a
// snapshot, drops the superseded snapshot directories and compacts the journal onto the new
// cut. It is a no-op, and touches no file, when nothing is owed or the pass is already proven
// for every erasure; it does nothing while an erasing deletion is still fencing. The retention
// worker calls it on every pass. An error means the pass did not complete: ResidualStores keeps
// naming ResidualControlJournal and the next call repeats it.
//
// Two limits of the bytes it writes. The replacement of a retained command is computed from
// the state of THIS voter when the pass reads its rules, so the same command holds different
// redacted bytes on two voters, and their snapshot envelopes (hence the snap-<index>-<checksum>
// names and Manifest.Checksum) differ until every voter has run every pass: nothing may
// compare them across voters. And the rules are read once, when the pass starts: an erasure
// that commits while it runs leaves its covered payload in the ready.wal the pass rewrites and
// in the snapshot it cuts, so a pass can introduce a copy of a payload committed after its
// rules were read. The receipt stays honest (ResidualStores re-reads the live state) and the
// next pass removes it.
func (s *Store) RedactRetainedControlCommands(ctx context.Context) error {
	g := s.ReplicaGroup()
	if g == nil {
		return nil
	}
	st, err := s.localState()
	if err != nil {
		return err
	}
	erasures, finished := controlJournalScope(st)
	if erasures == 0 || !finished {
		return nil
	}
	if residue, err := g.MachineResidue(erasures); err == nil && len(withoutPins(residue)) == 0 {
		return nil
	}
	redactor := &controlRedactor{s: s}
	res, err := g.RedactMachineCommands(ctx, erasures, redactor.redact)
	if err != nil {
		return replicaFault(err)
	}
	if g.Status().Applied <= res.Floor {
		if err = s.updateAs(ctx, writerRedactNoop, func(*State) error { return nil }); err != nil {
			return err
		}
	}
	snapshot, err := g.CreateSnapshot(ctx, g.Status().ApplicationCursor)
	if err != nil {
		return replicaFault(err)
	}
	if snapshot.Manifest.Index <= res.Floor {
		return model.Fail(model.Unavailable)
	}
	if _, err = g.Snapshots().DropSuperseded(); err != nil {
		return replicaFault(err)
	}
	if _, err = g.CompactJournal(ctx); err != nil {
		return replicaFault(err)
	}
	residue, err := g.MachineResidue(erasures)
	if err != nil {
		return replicaFault(err)
	}
	if len(withoutPins(residue)) != 0 {
		return model.Fail(model.Unavailable) // a stale command or a newer erasure arrived meanwhile
	}
	return nil
}
