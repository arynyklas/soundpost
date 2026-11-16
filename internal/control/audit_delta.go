// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// The audit delta is the second shape of a replicated control command (D49). Every other command
// is a controlReplacement: the whole next state, which every voter decodes and rewrites. The audit
// of one released chunk of elevated bytes (auth.Service.CommitElevatedRead) changes nothing but the
// end of the audit log, and at a production-sized state the whole-state command cost about 0.26 s and
// 180 MB per chunk (lane1-wave14-report.md 2.4), so a chunk is committed as this append-only
// command instead: the revision it expects and the rows, a few hundred bytes.
//
// What it does at apply, on every voter, is exactly what the whole-state path writes for a commit
// that only appended audit rows (updateAs(writerAuditAppend)): the same compare-and-swap on the
// expected revision (a stale delta is rejected like a stale replacement), revision = expected+1,
// the revision clock stamped with the proposer's clock carried in the command, the rows appended,
// AuthorityRevision unchanged. TestAuditDeltaApplyEqualsReplacementApply pins the equivalence.
//
// What it does not do: it carries no state and no key files (a replacement installs those), so a
// voter still decodes the whole committed state, appends and encodes it again; only the payload
// that is proposed, journaled and replicated is small.
//
// A binary that does not know the shape fails to decode it and stops applying, so it is proposed only
// once every member of the committed configuration declared protocol 4 (storage.auditDeltaProtocol,
// SetAuditDeltaGate); until then AppendAudit commits through the whole-state path.

// maxAuditDeltaRows bounds the rows of one delta; the one user commits one.
const maxAuditDeltaRows = 64

// auditDelta is the body of the audit delta command.
type auditDelta struct {
	Installation model.ID             `json:"installation"`
	Expected     model.Revision       `json:"expected"`
	At           int64                `json:"at"`
	Audits       []model.ControlAudit `json:"audits"`
}

// auditDeltaCommand is the payload of an audit delta: one member, which is what tells it from a
// controlReplacement (whose first member is "expected"). Both are decoded strictly; a payload that
// mixes the two shapes matches neither.
type auditDeltaCommand struct {
	AuditDelta auditDelta `json:"audit_delta"`
}

const auditDeltaKey = "audit_delta"

// controlCommand is a decoded payload of a Control entry: exactly one of the two shapes.
type controlCommand struct {
	replacement *controlReplacement
	delta       *auditDelta
}

// decodeControlCommand decodes a Control payload strictly (no unknown member, no duplicate key, no
// trailing data) into the shape its first member names; the shape's own struct refuses every
// member of the other.
func decodeControlCommand(payload []byte) (controlCommand, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return controlCommand{}, model.Fail(model.Invalid)
	}
	key, err := dec.Token()
	if err != nil {
		return controlCommand{}, model.Fail(model.Invalid)
	}
	if name, ok := key.(string); ok && name == auditDeltaKey {
		var c auditDeltaCommand
		if model.StrictJSON(payload, &c) != nil || len(c.AuditDelta.Audits) == 0 || len(c.AuditDelta.Audits) > maxAuditDeltaRows || c.AuditDelta.Expected == ^model.Revision(0) {
			return controlCommand{}, model.Fail(model.Invalid)
		}
		// model.ControlAudit decodes itself (UnmarshalJSON, not strict), so a row with a member this
		// build does not know would decode and then encode without it: the journal would hold bytes
		// whose canonical form is not the one the proposer digested. A row is the delta's only
		// externally supplied text; it has to be exactly what this build writes.
		var rows struct {
			AuditDelta struct {
				Audits []json.RawMessage `json:"audits"`
			} `json:"audit_delta"`
		}
		if json.Unmarshal(payload, &rows) != nil || len(rows.AuditDelta.Audits) != len(c.AuditDelta.Audits) {
			return controlCommand{}, model.Fail(model.Invalid)
		}
		for i, row := range c.AuditDelta.Audits {
			if again, err := json.Marshal(row); err != nil || !bytes.Equal(again, rows.AuditDelta.Audits[i]) {
				return controlCommand{}, model.Fail(model.Invalid)
			}
		}
		return controlCommand{delta: &c.AuditDelta}, nil
	}
	var next controlReplacement
	if model.StrictJSON(payload, &next) != nil {
		return controlCommand{}, model.Fail(model.Invalid)
	}
	return controlCommand{replacement: &next}, nil
}

// SetAuditDeltaGate installs the function that says whether every member of the replica group
// declared the audit delta protocol (storage.Engine.ControlAuditDeltaReady). It is read at every
// AppendAudit, never cached. A Store without a gate proposes no delta: the delta is a wire format an
// older peer cannot decode, so the default is the whole-state commit every release applies, and a
// caller that enables replication on several voters has to install the gate to get the delta (a
// single-process test installs func() bool { return true }). Passing nil removes the gate, which
// closes it again.
func (s *Store) SetAuditDeltaGate(ready func() bool) {
	if ready == nil {
		s.auditDeltaGate.Store(nil)
		return
	}
	s.auditDeltaGate.Store(&ready)
}

// AuditDelta reports whether AppendAudit proposes the delta command: what the gate says, false
// without a gate.
func (s *Store) AuditDelta() bool {
	gate := s.auditDeltaGate.Load()
	return gate != nil && (*gate)()
}

// SharesUpdateOf reports whether c commits through this store's own Update. A type that embeds the
// store and overrides Update (a test double that counts or fails commits) has UpdateAuditAppend and
// AppendAudit promoted unchanged, and a service that preferred them would skip the override:
// auth.Service asks first and commits through the Update it was given when the answer is no.
func (s *Store) SharesUpdateOf(c auth.ControlStore) bool { return c == auth.ControlStore(s) }

// AppendAudit commits one audit row after check accepted the committed state it reads. It does not
// move AuthorityRevision (the audit log is evidence; writerAuditAppend). With the audit delta
// protocol declared by every member it proposes the delta command and never marshals the state: the
// state is read once through the shared decode, checked, and only (installation, revision, clock,
// row) travel. Before that it is the whole-state commit of the same row, checked inside the same
// transition. check reads the state through the read-only interface and must not retain it.
func (s *Store) AppendAudit(ctx context.Context, check func(model.ReadOnlyControl) error, a model.ControlAudit) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl == nil {
		return model.Fail(model.Unavailable)
	}
	if !s.AuditDelta() {
		return s.updateAs(ctx, writerAuditAppend, func(st *State) error {
			if err := check(model.ReadOnlyOf(st)); err != nil {
				return err
			}
			st.Audits = append(st.Audits, a)
			return nil
		})
	}
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	var d auditDelta
	if err := s.ViewShared(ctx, func(ro model.ReadOnlyControl) error {
		if err := check(ro); err != nil {
			return err
		}
		d.Installation, d.Expected = ro.Installation(), ro.Revision()
		return nil
	}); err != nil {
		return err
	}
	if d.Expected == ^model.Revision(0) {
		return model.Fail(model.Unavailable)
	}
	d.At = s.clockNow().UnixNano()
	d.Audits = []model.ControlAudit{a}
	payload, err := json.Marshal(auditDeltaCommand{AuditDelta: d})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	s.auditDeltas.Add(1)
	s.auditDeltaBytes.Add(uint64(len(payload)))
	_, err = s.repl.group.Propose(ctx, replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload, ApplicationIndex: uint64(d.Expected + 1)})
	return replicaFault(err)
}

// applyAuditDelta is the delta's transition of the committed state current: what the whole-state
// path leaves after fn appended the rows (replicatedUpdate with bump false). It reports whether the
// rows added an erasing audit, which owes this file a scrub like a replacement that adds one.
func applyAuditDelta(current *State, d auditDelta) (owe bool) {
	owe = erasureCount(d.Audits) > 0
	current.Audits = append(current.Audits, d.Audits...)
	current.Revision = d.Expected + 1
	noteRevisionTime(current, d.At)
	return owe
}

// verifyCurrentDelta is verifyCurrentState for a delta the machine already applied (a replay): the
// committed state is for the same installation and not older than the delta's revision; at that
// very revision its last rows are the delta's.
func (m *replicatedControl) verifyCurrentDelta(d auditDelta) error {
	return m.store.db.View(func(tx *bolt.Tx) error {
		var current State
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &current) != nil {
			return model.Fail(model.Corrupt)
		}
		if d.Expected == ^model.Revision(0) || current.Installation != d.Installation || current.Revision < d.Expected+1 {
			return model.Fail(model.Corrupt)
		}
		if current.Revision != d.Expected+1 {
			return nil
		}
		n := len(d.Audits)
		if len(current.Audits) < n {
			return model.Fail(model.Corrupt)
		}
		tail := current.Audits[len(current.Audits)-n:]
		for i := range d.Audits {
			left, err := model.CanonicalJSON(tail[i])
			if err != nil {
				return err
			}
			right, err := model.CanonicalJSON(d.Audits[i])
			if err != nil || !bytes.Equal(left, right) {
				return model.Fail(model.Corrupt)
			}
		}
		return nil
	})
}
