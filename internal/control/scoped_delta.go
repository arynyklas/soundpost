// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// The scoped delta is the fourth shape of a replicated control command (D102). Every other shape that
// is computed from a read of the state names the revision it read (Expected) and is applied only at
// the very next revision: any other control commit between the read and the leader's ordering, an
// admission round, a job pass, an issue write, a commit of another organization, makes it stale. The
// writers that run once and have nobody to repeat them (the instance scope of `soundpost backup
// create`, a login) lost that race to a writer that commits continuously, however often they repeated
// (distributed.md): the loser learns of the winner's commit through its own refusal, and the winner
// has read the new revision when its commit returns.
//
// A scoped delta carries a precondition on exactly the records its transition read instead: the table
// (Users or Sessions) and key of each, and a digest of the record as it was read ("" when it was not
// there). It names no revision. The leader orders it at the next application index whatever that is
// (ApplicationIndex 0, as every other kind of entry is), and every voter, at apply, steps the revision
// by one from the one it holds, checks the digests against the records it holds, and applies the writes
// only when they all match. A mismatch is what a stale command is at apply: the revision steps to the
// command's slot, the state is kept, and the proposer is answered the typed stale. The leader checks the
// same digests in Validate, against the committed state, so that a command that is already known to be
// refused is not ordered. A commit of anything else, in this or any other organization, leaves the
// records alone and so leaves the command valid; a change of a record it read (the user disabled, the
// session ended, the password changed) is the one stale it still answers.
//
// What it writes is the records it names (ops: set or delete of [table, key]), the audit rows it
// appends, and AuthorityRevision when the writer's own rule says the transition changed authority
// (Bump); never the whole state. A voter applies it to the bytes of its committed state without decoding
// them (scopedRaw, as an audit delta is applied), and decodes only when the splice cannot prove what it
// does (applyScopedDelta).
//
// It is a wire format an older binary cannot decode (it stops applying a command it does not
// understand), so it is proposed only once every member of the control group declared the state patch
// protocol of this shape (storage.statePatchProtocol, 9; SetStatePatchGate) and the installation is
// contracted (layoutLedger): an installation that the previous release can still read never sees it,
// and UpdateSessionCreateRecords / UpdateAuditRecords commit the previous form there.

const scopedDeltaKey = "scoped_delta"

const (
	tableUsers    = "Users"
	tableSessions = "Sessions"
	// maxScopedReads bounds the records one scoped delta names; the transitions that use it read two.
	maxScopedReads = 8
	// maxRecordKey bounds the length of a record key (a user id, the digest of a session token).
	maxRecordKey = 128
)

// scopedRead is one record of the precondition: Digest is recordDigest of the record as the proposer
// read it, "" when it was not there.
type scopedRead struct {
	Table  string `json:"t"`
	Key    string `json:"k"`
	Digest string `json:"d"`
}

// scopedDelta is the body of the scoped delta command. Every op addresses a record that Reads names.
type scopedDelta struct {
	Installation model.ID             `json:"installation"`
	At           int64                `json:"at"`
	Reads        []scopedRead         `json:"reads"`
	Ops          []patchOp            `json:"ops,omitempty"`
	Audits       []model.ControlAudit `json:"audits,omitempty"`
	Bump         bool                 `json:"bump,omitempty"`
}

// scopedDeltaCommand is the payload of a scoped delta: one member, which is what tells it from the
// other shapes.
type scopedDeltaCommand struct {
	ScopedDelta scopedDelta `json:"scoped_delta"`
}

// decodeScopedDelta decodes a payload whose first member is scopedDeltaKey, strictly, and checks the
// structure of what it carries before any state is read.
func decodeScopedDelta(payload []byte) (scopedDelta, error) {
	var c scopedDeltaCommand
	if model.StrictJSON(payload, &c) != nil {
		return scopedDelta{}, model.Fail(model.Invalid)
	}
	d := c.ScopedDelta
	if len(d.Reads) == 0 || len(d.Reads) > maxScopedReads || len(d.Ops) > len(d.Reads) || len(d.Audits) > maxAuditDeltaRows || len(d.Ops) == 0 && len(d.Audits) == 0 {
		return scopedDelta{}, model.Fail(model.Invalid)
	}
	named := make(map[[2]string]bool, len(d.Reads))
	for _, r := range d.Reads {
		if r.Table != tableUsers && r.Table != tableSessions || r.Key == "" || len(r.Key) > maxRecordKey || !validDigest(r.Digest) || named[[2]string{r.Table, r.Key}] {
			return scopedDelta{}, model.Fail(model.Invalid)
		}
		named[[2]string{r.Table, r.Key}] = true
	}
	written := make(map[[2]string]bool, len(d.Ops))
	for _, op := range d.Ops {
		if len(op.Path) != 2 || !named[[2]string{op.Path[0], op.Path[1]}] || written[[2]string{op.Path[0], op.Path[1]}] || op.Cut != 0 {
			return scopedDelta{}, model.Fail(model.Invalid)
		}
		written[[2]string{op.Path[0], op.Path[1]}] = true
		switch op.Op {
		case opSet:
			if _, err := decodeRecord(op.Path[0], op.Value); err != nil {
				return scopedDelta{}, model.Fail(model.Invalid)
			}
		case opDelete:
			if len(op.Value) != 0 {
				return scopedDelta{}, model.Fail(model.Invalid)
			}
		default:
			return scopedDelta{}, model.Fail(model.Invalid)
		}
	}
	// model.ControlAudit decodes itself (UnmarshalJSON, not strict): a row has to be exactly what this
	// build writes, as in an audit delta.
	if len(d.Audits) != 0 && !canonicalAuditRows(payload, scopedDeltaKey, d.Audits) {
		return scopedDelta{}, model.Fail(model.Invalid)
	}
	return d, nil
}

// validDigest is whether s is a digest recordDigest writes, or empty (the record is not there).
func validDigest(s string) bool {
	if s == "" {
		return true
	}
	if len(s) != 2*sha256.Size {
		return false
	}
	for i := range len(s) {
		if c := s[i]; c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// record is a decoded record of one of the two tables.
type record struct {
	user    model.ControlUser
	session model.ControlSession
}

// decodeRecord decodes the encoding of a record of table, strictly: a state holds no member the
// build does not know (decoding it strictly is how a voter reads the whole state).
func decodeRecord(table string, value []byte) (record, error) {
	var r record
	switch table {
	case tableUsers:
		if model.StrictJSON(value, &r.user) != nil {
			return record{}, model.Fail(model.Corrupt)
		}
	case tableSessions:
		if model.StrictJSON(value, &r.session) != nil {
			return record{}, model.Fail(model.Corrupt)
		}
	default:
		return record{}, model.Fail(model.Invalid)
	}
	return r, nil
}

// encode is the encoding of the record the state holds it as.
func (r record) encode(table string) ([]byte, error) {
	if table == tableUsers {
		return json.Marshal(r.user)
	}
	return json.Marshal(r.session)
}

// recordDigest is the digest of the record whose stored encoding is value: of the record as the
// encoder writes it back once decoded, so what the bytes spell otherwise (white space, an escape) is
// not a difference. nil (the record is not there) is "".
func recordDigest(table string, value []byte) (string, error) {
	if value == nil {
		return "", nil
	}
	r, err := decodeRecord(table, value)
	if err != nil {
		return "", err
	}
	canonical, err := r.encode(table)
	if err != nil {
		return "", model.Fail(model.Corrupt)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// recordBytes is the stored encoding of the record of table under key in the state encoding raw,
// without decoding the state. ok is false when the bytes do not say (not the compact encoding of a
// State): the caller decodes the state.
func recordBytes(raw []byte, root stateRoot, table, key string) (value []byte, ok bool) {
	if !root.ok {
		return nil, false
	}
	m, has := root.member(raw, table)
	if !has {
		return nil, true
	}
	if string(raw[m.vs:m.ve]) == "null" {
		return nil, true
	}
	members, scanned := scanObject(raw, m.vs, m.ve, nil)
	if !scanned {
		return nil, false
	}
	for _, mm := range members {
		name, good := unquoteMemberName(raw, mm)
		if !good {
			return nil, false
		}
		if name == key {
			return raw[mm.vs:mm.ve], true
		}
	}
	return nil, true
}

// recordView is a record as the committed state holds it.
type recordView struct {
	table, key string
	found      bool
	rec        record
	digest     string
}

// readRecords reads the records that refs name from the state encoding raw (root scanned). The state
// is decoded, once, only when the bytes cannot be scanned.
func readRecords(raw []byte, root stateRoot, refs []scopedRead) ([]recordView, error) {
	out := make([]recordView, len(refs))
	var full *State
	for i, ref := range refs {
		out[i] = recordView{table: ref.Table, key: ref.Key}
		value, ok := recordBytes(raw, root, ref.Table, ref.Key)
		if !ok {
			if full == nil {
				full = new(State)
				if json.Unmarshal(raw, full) != nil {
					return nil, model.Fail(model.Corrupt)
				}
			}
			var err error
			if value, err = storedRecord(full, ref.Table, ref.Key); err != nil {
				return nil, err
			}
		}
		if value == nil {
			continue
		}
		r, err := decodeRecord(ref.Table, value)
		if err != nil {
			return nil, err
		}
		digest, err := recordDigest(ref.Table, value)
		if err != nil {
			return nil, err
		}
		out[i].found, out[i].rec, out[i].digest = true, r, digest
	}
	return out, nil
}

// storedRecord is the encoding of a record of a decoded state; nil when it is not there.
func storedRecord(st *State, table, key string) ([]byte, error) {
	var value any
	switch table {
	case tableUsers:
		u, ok := st.Users[key]
		if !ok {
			return nil, nil
		}
		value = u
	case tableSessions:
		s, ok := st.Sessions[key]
		if !ok {
			return nil, nil
		}
		value = s
	default:
		return nil, model.Fail(model.Invalid)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	return raw, nil
}

// holds says whether every record the command read is, in the committed state encoded in raw, the
// record it read.
func (d scopedDelta) holds(raw []byte, root stateRoot) (bool, error) {
	views, err := readRecords(raw, root, d.Reads)
	if err != nil {
		return false, err
	}
	for i, v := range views {
		if v.digest != d.Reads[i].Digest {
			return false, nil
		}
	}
	return true, nil
}

// stepOps are the ops that step the state encoded in raw to revision: the revision itself, the
// revision clock stamped with at (noteRevisionTime), and rows appended to the audit log. It is what an
// audit delta does, which is where deltaRaw has it from.
func stepOps(raw []byte, root stateRoot, revision model.Revision, at int64, rows []model.ControlAudit) ([]patchOp, bool) {
	ops := []patchOp{revisionOp(revision)}
	if len(rows) != 0 {
		encoded, err := json.Marshal(rows)
		if err != nil {
			return nil, false
		}
		if m, ok := root.member(raw, "Audits"); ok && raw[m.vs] == '[' {
			ops = append(ops, patchOp{Op: opArray, Path: []string{"Audits"}, Value: encoded})
		} else {
			ops = append(ops, patchOp{Op: opSet, Path: []string{"Audits"}, Value: encoded}) // no log yet: it starts with the rows
		}
	}
	clock := State{Revision: revision}
	if m, ok := root.member(raw, "revision_clock"); ok {
		if json.Unmarshal(raw[m.vs:m.ve], &clock.RevisionClock) != nil {
			return nil, false
		}
	}
	before := slices.Clone(clock.RevisionClock)
	noteRevisionTime(&clock, at)
	if !slices.Equal(before, clock.RevisionClock) {
		stamps, err := json.Marshal(clock.RevisionClock)
		if err != nil {
			return nil, false
		}
		ops = append(ops, patchOp{Op: opSet, Path: []string{"revision_clock"}, Value: stamps})
	}
	return ops, true
}

// scopedRaw is applyScopedDelta on the encoding: the state at revision with the delta's records,
// rows and clock. ok is false when the splice does not apply.
func scopedRaw(raw []byte, root stateRoot, d scopedDelta, revision model.Revision) ([]byte, bool) {
	if !root.ok {
		return nil, false
	}
	ops, ok := stepOps(raw, root, revision, d.At, d.Audits)
	if !ok {
		return nil, false
	}
	ops = append(ops, d.Ops...)
	if d.Bump {
		value, err := json.Marshal(revision)
		if err != nil {
			return nil, false
		}
		ops = append(ops, patchOp{Op: opSet, Path: []string{"authority_revision"}, Value: value})
	}
	out, eff, ok := patchRaw(raw, root, ops)
	if !ok || !eff.revisionSet || eff.revision != revision {
		return nil, false
	}
	return out, true
}

// applyScopedDelta is the delta's transition of the decoded committed state current, at revision. It
// reports whether the rows added an erasing audit, which owes the file a scrub.
func applyScopedDelta(current *State, d scopedDelta, revision model.Revision) (owe bool, err error) {
	for _, op := range d.Ops {
		table, key := op.Path[0], op.Path[1]
		if op.Op == opDelete {
			if table == tableUsers {
				delete(current.Users, key)
			} else {
				delete(current.Sessions, key)
			}
			continue
		}
		r, err := decodeRecord(table, op.Value)
		if err != nil {
			return false, err
		}
		if table == tableUsers {
			if current.Users == nil {
				current.Users = map[string]model.ControlUser{}
			}
			current.Users[key] = r.user
		} else {
			if current.Sessions == nil {
				current.Sessions = map[string]model.ControlSession{}
			}
			current.Sessions[key] = r.session
		}
	}
	owe = erasureCount(d.Audits) > 0
	current.Audits = append(current.Audits, d.Audits...)
	current.Revision = revision
	noteRevisionTime(current, d.At)
	if d.Bump {
		current.AuthorityRevision = revision
	}
	return owe, nil
}

// verifyCurrentScoped is verifyCurrentState for a scoped delta the machine already applied (a replay):
// the committed state is for the same installation and not older than the revision the command made
// (its application slot); at that very revision it holds what the command wrote.
func (m *replicatedControl) verifyCurrentScoped(d scopedDelta, slot model.Revision) error {
	return m.store.db.View(func(tx *bolt.Tx) error {
		raw, err := stateRaw(tx.Bucket([]byte("control")))
		if err != nil {
			return err
		}
		root := scanStateRoot(raw)
		installation, revision := root.installation, root.revision
		var current State
		decoded := false
		if !root.ok {
			if json.Unmarshal(raw, &current) != nil {
				return model.Fail(model.Corrupt)
			}
			installation, revision, decoded = current.Installation, current.Revision, true
		}
		if installation != d.Installation || revision < slot {
			return model.Fail(model.Corrupt)
		}
		if revision != slot {
			return nil
		}
		if len(d.Ops) != 0 {
			if err := verifyPatchRaw(raw, d.Ops); err != nil {
				return err
			}
		}
		n := len(d.Audits)
		if n == 0 {
			return nil
		}
		total, tail, ok := lastAudits(raw, root, n)
		if !ok {
			if !decoded && json.Unmarshal(raw, &current) != nil {
				return model.Fail(model.Corrupt)
			}
			total = len(current.Audits)
			tail = current.Audits[max(total-n, 0):]
		}
		if total < n {
			return model.Fail(model.Corrupt)
		}
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

// validateScoped is the leader's check of a scoped delta before it orders it: the command names the
// installation, takes the next index whatever it is, and the records it read are the committed ones.
func validateScoped(tx *bolt.Tx, d scopedDelta, command replica.Entry) error {
	if command.ApplicationIndex != 0 {
		return model.Fail(model.Invalid) // the leader gives the index: a scoped delta is ordered where it lands
	}
	ctrl := tx.Bucket([]byte("control"))
	installation, _, err := stateHead(ctrl)
	if err != nil {
		return err
	}
	if installation != d.Installation {
		return model.Fail(model.Stale)
	}
	raw, err := stateRaw(ctrl)
	if err != nil {
		return err
	}
	ok, err := d.holds(raw, scanStateRoot(raw))
	if err != nil {
		return err
	}
	if !ok {
		return model.Fail(model.Stale)
	}
	return nil
}

// ScopedDeltaStats is the number of scoped delta commands this store proposed, and their payload bytes.
func (s *Store) ScopedDeltaStats() (commands, payloadBytes uint64) {
	return s.scopedDeltas.Load(), s.scopedDeltaBytes.Load()
}

// RecordScope reports whether UpdateSessionCreateRecords and UpdateAuditRecords propose the scoped
// delta now: replication on, every member of the control group declared the protocol of the shape, and
// the installation contracted. Otherwise they commit the previous form.
func (s *Store) RecordScope() bool {
	return s.repl != nil && s.StatePatch() && s.layoutLedger.Load()
}

// errScopedClosed is returned by the proposer when the file turned out not to be contracted under the
// read: the previous form commits instead.
var errScopedClosed = errors.New("control: records are not scoped")

// UpdateSessionCreateRecords is UpdateSessionCreate for a login whose transition reads and writes only
// the records in reads (it is given a state that holds exactly those, and must add the new session
// under a key it names): the commit is a scoped delta, which only a change of those records can make
// stale. Where the scoped delta is not proposed (RecordScope), it is UpdateSessionCreate on the whole
// state, the form every release applies.
func (s *Store) UpdateSessionCreateRecords(ctx context.Context, reads model.ControlRecords, fn func(*State) error) error {
	return s.updateRecords(ctx, writerSessionCreate, reads, fn, s.UpdateSessionCreate)
}

// UpdateAuditRecords is Update for a transition that reads only the records in reads and appends audit
// rows (the grant of an instance scope: the administrator's user and session records, and the audit of
// the grant). Where the scoped delta is not proposed (RecordScope), it is Update on the whole state.
func (s *Store) UpdateAuditRecords(ctx context.Context, reads model.ControlRecords, fn func(*State) error) error {
	return s.updateRecords(ctx, writerAuditAppend, reads, fn, s.Update)
}

func (s *Store) updateRecords(ctx context.Context, w writer, reads model.ControlRecords, fn func(*State) error, previous func(context.Context, func(*State) error) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !s.RecordScope() {
		return previous(ctx, fn)
	}
	err := s.updateRecordsOnce(ctx, w, reads, fn)
	if errors.Is(err, errScopedClosed) {
		return previous(ctx, fn)
	}
	return err
}

// recordGuard is the rule of a writer that keeps AuthorityRevision: what it may change in the view it
// is given (the same masks and checks its whole-state form uses, authority.go).
func recordGuard(w writer) (mask func(*State) ([]byte, error), preserve func(*State) func(*State) bool) {
	if w == writerSessionCreate {
		return stateWithoutSessionsAndFactors, sessionsGrowFactorsConsumed
	}
	return stateWithoutAudits, auditsOnlyAppended
}

// outsideRecords is the encoding of a view without the members a records transition may write.
func outsideRecords(st *State) ([]byte, error) {
	masked := *st
	masked.Users, masked.Sessions, masked.Audits = nil, nil, nil
	return json.Marshal(masked)
}

// updateRecordsOnce is one read-compute-propose round of a scoped delta.
func (s *Store) updateRecordsOnce(ctx context.Context, w writer, reads model.ControlRecords, fn func(*State) error) error {
	defer s.lockUpdates()()
	r := s.repl
	if _, err := r.group.ReadIndex(ctx); err != nil {
		return replicaFaultUnder(ctx, err)
	}
	refs := make([]scopedRead, 0, len(reads.Users)+len(reads.Sessions))
	for _, key := range reads.Users {
		refs = append(refs, scopedRead{Table: tableUsers, Key: key})
	}
	for _, key := range reads.Sessions {
		refs = append(refs, scopedRead{Table: tableSessions, Key: key})
	}
	if len(refs) == 0 || len(refs) > maxScopedReads {
		return model.Fail(model.Invalid)
	}
	var views []recordView
	view := State{Users: map[string]model.ControlUser{}, Sessions: map[string]model.ControlSession{}}
	if err := s.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		if !ledgerLayout(ctrl) {
			return errScopedClosed
		}
		var err error
		if view.Installation, view.Revision, err = stateHead(ctrl); err != nil {
			return err
		}
		raw, err := stateRaw(ctrl)
		if err != nil {
			return err
		}
		views, err = readRecords(raw, scanStateRoot(raw), refs)
		return err
	}); err != nil {
		return err
	}
	if view.Revision == ^model.Revision(0) {
		return model.Fail(model.Unavailable)
	}
	for _, v := range views {
		if !v.found {
			continue
		}
		if v.table == tableUsers {
			view.Users[v.key] = v.rec.user
		} else {
			view.Sessions[v.key] = v.rec.session
		}
	}
	mask, preserve := recordGuard(w)
	outside, err := outsideRecords(&view)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	masked, err := mask(&view)
	holds := preserve(&view)
	bump := err != nil
	if err := fn(&view); err != nil {
		return err
	}
	if after, err := mask(&view); err != nil || !bytes.Equal(masked, after) || !holds(&view) {
		bump = true // outside what the writer owns: the whole rule applies, as in its whole-state form
	}
	if after, err := outsideRecords(&view); err != nil || !bytes.Equal(outside, after) {
		return model.Fail(model.Invalid) // a transition of records wrote what it was not given
	}
	d := scopedDelta{Installation: view.Installation, At: s.clockNow().UnixNano(), Reads: make([]scopedRead, len(refs)), Audits: view.Audits, Bump: bump}
	named := map[[2]string]bool{}
	for i, v := range views {
		d.Reads[i] = scopedRead{Table: v.table, Key: v.key, Digest: v.digest}
		named[[2]string{v.table, v.key}] = true
		var after record
		var exists bool
		if v.table == tableUsers {
			after.user, exists = view.Users[v.key]
		} else {
			after.session, exists = view.Sessions[v.key]
		}
		switch {
		case !exists && v.found:
			d.Ops = append(d.Ops, patchOp{Op: opDelete, Path: []string{v.table, v.key}})
		case exists:
			encoded, err := after.encode(v.table)
			if err != nil {
				return model.Fail(model.Invalid)
			}
			digest, err := recordDigest(v.table, encoded)
			if err != nil {
				return model.Fail(model.Invalid)
			}
			if !v.found || digest != v.digest {
				d.Ops = append(d.Ops, patchOp{Op: opSet, Path: []string{v.table, v.key}, Value: encoded})
			}
		}
	}
	for key := range view.Users {
		if !named[[2]string{tableUsers, key}] {
			return model.Fail(model.Invalid) // a record the transition did not declare it reads
		}
	}
	for key := range view.Sessions {
		if !named[[2]string{tableSessions, key}] {
			return model.Fail(model.Invalid)
		}
	}
	if len(d.Ops) == 0 && len(d.Audits) == 0 {
		return nil // the transition changed nothing: there is nothing to order
	}
	if len(d.Audits) > maxAuditDeltaRows {
		return model.Fail(model.Invalid)
	}
	payload, err := json.Marshal(scopedDeltaCommand{ScopedDelta: d})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	s.scopedDeltas.Add(1)
	s.scopedDeltaBytes.Add(uint64(len(payload)))
	_, err = r.group.Propose(ctx, replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload})
	if errors.Is(err, replica.ErrConflict) {
		return model.Fail(model.Stale) // a record it read changed between the check and the order: it reads again
	}
	return replicaFault(err)
}
