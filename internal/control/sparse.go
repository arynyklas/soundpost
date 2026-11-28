// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// Sparse transitions of the workers' books (D84).
//
// The whole-state funnel (replicatedUpdateOnce) decodes the committed state, runs the transition on it,
// encodes the next state, diffs the two encodings and proposes the patch, all while it holds updateMu: at the
// estate of the single-host gate that is a hold of tens to hundreds of milliseconds for a change of one
// record, and every other writer, the admission rounds among them, waits for it. A job update and an issue
// commit are such changes: one record of the job or issue books and a few rows. They run here instead, on
// what they name: the decode of the state without the ledger that every core reader shares (coreState, not
// the writer's to change), the records of their book (the ledger, one transaction), and what they write is the
// patch ops of those records. Nothing they cost depends on how many records the books or the state hold
// beyond the project they act in.
//
// They do not take a commit of their own either. A sparse transition is an item of the round of the group
// commit (admission_group.go): it waits in the same queue as the admission transitions, runs in the same read
// transaction against the same ledger and its records are the ops of the same patch, with one revision step, one
// journal record and one database apply for everything the round carries. A control command costs about 6 ms
// whatever it carries (the journal fsync, the two fsyncs of the apply, the barrier and the encoding), and the
// 34 commits a second of the workers that took one each held the lock for a fifth of every second, in front of
// the admission rounds. The tables the books write are never the admission's, so the only thing a round has to
// keep right is the sparse plans among themselves: each is judged against the records as the plans before it in
// the round left them (sparseRound), exactly as it would be judged if it had its own commit after theirs.

// errSparseFallback is what a plan answers when its command is not one it can write as records of its own:
// the caller runs it through the whole-state funnel.
var errSparseFallback = errors.New("control: the command needs the whole-state funnel")

// sparsePlan reads core (shared, never changed) and the ledger l of one read transaction and answers the
// ops that write the command's records (none when it found its answer already committed).
type sparsePlan func(core *State, l *ledgerTx) ([]patchOp, error)

// sparseUpdate commits what plan writes as one control command. handled is false when the group does not
// apply such commands (the file keeps its books in the blob, or a member has not declared the protocol of the
// ledger layout) or the plan sent the command to the funnel: the caller then commits it there. A proposal that
// lost the application-index race, or that the leader held for admission's sake (admission_yield.go), is read
// and judged again by the round, up to maxLostProposals times, a millisecond apart: the plan judges the
// records it is given, so a retry cannot apply a stale decision.
func (s *Store) sparseUpdate(ctx context.Context, plan sparsePlan) (handled bool, err error) {
	if e := ctx.Err(); e != nil {
		return true, e
	}
	if s.repl == nil {
		return true, model.Fail(model.Unavailable)
	}
	err = s.enqueue(&admissionItem{ctx: ctx, plan: plan, done: make(chan error, 1)})
	if errors.Is(err, errSparseFallback) || errors.Is(err, errNotLedgerLayout) {
		return false, nil
	}
	return true, err
}

// warmCore makes the shared decode of the state current before the writer takes the lock. A commit that
// changed the blob (an issue commit writes issues and a command record there) drops the decode, and the next
// writer that needs it would otherwise decode the whole state while it holds the lock: every writer behind
// it would wait for that. A reader that finds a decode of its transaction takes it as it is (coreState).
func (s *Store) warmCore() {
	_ = s.db.View(func(tx *bolt.Tx) error {
		_, err := s.coreState(tx)
		return err
	})
}

// sparseRoundBytes bounds the bytes of the records that the sparse plans of one round write, so that a patch
// stays far below the replica's entry limit however many projects write at once. The first plan of a round is
// never held back by it: a plan that waits is judged in the next round.
const sparseRoundBytes = 2 << 20

// bookTables are the tables a sparse plan may read or write.
var bookTables = [...]int{tableJobBooks, tableIssueBooks, tableGroupingIssues, tableCommands, tableCommandOwners, tableJobPositions, tableRuleBooks, tableRuleOutputs}

// roundTable is a table of the books as the sparse plans of a round left it: the records they wrote in front of
// the table of the transaction behind them (a nil value is a deleted record).
type roundTable struct {
	ledgerTable
	puts map[string][]byte
}

func (t *roundTable) Get(key []byte) []byte {
	if v, ok := t.puts[string(key)]; ok {
		return v
	}
	return t.ledgerTable.Get(key)
}

func (t *roundTable) Cursor() tableCursor {
	base := t.ledgerTable.Cursor()
	if len(t.puts) == 0 {
		return base
	}
	ents := make([]ovEnt, 0, len(t.puts))
	for k, v := range t.puts {
		ents = append(ents, ovEnt{k: k, v: v})
	}
	slices.SortFunc(ents, func(a, b ovEnt) int { return strings.Compare(a.k, b.k) })
	return &mergeCursor{over: &sliceIter{ents: ents}, base: base}
}

// sparseRound runs the sparse plans of one round in order, each against the ledger as the ones before it left it,
// and keeps the ops they wrote. The plans of two jobs of one project meet at the project's quota (the records
// of the project are counted), the plans of one job at its record, the plans that commit one command at the
// command's record: running them against each other's records judges all of them as one commit after the other
// would, and no plan has to wait for another.
type sparseRound struct {
	view  ledgerTx
	tbl   [ledgerTableCount]*roundTable
	ready bool
	final map[string]patchOp // the op that writes each record (the last one of the plans), by member and key
	bytes int
	// The audit rows the plans appended (an issue action audits its transition), in the order the plans ran, and the op
	// that writes them: set while the log has no rows, append once it has (every plan judges that against the same state).
	audits  []json.RawMessage
	auditOp string
	// compact says that the group applies the compact ops (record_delta.go): a record of the job books or the grouping issues that
	// the round changes is written as the delta of the record the round started from when that is smaller.
	compact bool
}

// auditsPath is the path of the append-only audit log, the one op on a path that is not a record a plan may write.
var auditsPath = []string{"Audits"}

// auditRowsOf is the rows an audit op appends; ok is false for an op on another path. An op that cuts the log or whose rows are not an array is Invalid.
func auditRowsOf(op patchOp) (rows []json.RawMessage, ok bool, err error) {
	if !slices.Equal(op.Path, auditsPath) {
		return nil, false, nil
	}
	if op.Op != opSet && op.Op != opArray || op.Cut != 0 || json.Unmarshal(op.Value, &rows) != nil {
		return nil, false, model.Fail(model.Invalid)
	}
	return rows, true, nil
}

func (r *sparseRound) open(l *ledgerTx) {
	r.view, r.ready = *l, true
	r.final = map[string]patchOp{}
	for _, table := range bookTables {
		r.tbl[table] = &roundTable{ledgerTable: l.t[table], puts: map[string][]byte{}}
		r.view.t[table] = r.tbl[table]
	}
}

// admit judges plan against the records of l as the plans of the round before it left them and takes what it
// writes into the round. wait is true when the round already holds sparseRoundBytes of records and the plan
// has to be judged in a later round (the first plan of a round never waits). A plan that fails with an error
// answers it (errSparseFallback among them) and writes nothing.
func (r *sparseRound) admit(plan sparsePlan, core *State, l *ledgerTx) (written []patchOp, wait bool, err error) {
	if !r.ready {
		r.open(l)
	}
	if written, err = plan(core, &r.view); err != nil {
		return nil, false, err
	}
	size := 0
	records := make([][]byte, len(written))
	var rows []json.RawMessage
	var rowsOp string
	for i, op := range written {
		if got, ok, err := auditRowsOf(op); err != nil {
			return nil, false, err
		} else if ok {
			if rows != nil || len(got) == 0 {
				return nil, false, model.Fail(model.Invalid) // one op of rows to a plan
			}
			rows, rowsOp = got, op.Op
			size += len(op.Value)
			continue
		}
		if len(op.Path) != 2 || !bookRoot(op.Path[0]) && !ruleRoot(op.Path[0]) || op.Op != opSet && op.Op != opDelete {
			return nil, false, model.Fail(model.Invalid)
		}
		size += len(op.Value)
		if op.Op == opSet {
			if records[i], err = canonicalRecord(recordTable(op.Path[0]), op.Value); err != nil {
				return nil, false, err
			}
		}
	}
	if rows != nil && r.auditOp != "" && r.auditOp != rowsOp {
		return nil, false, errSparseFallback // the plans disagree whether the log has rows: the funnel judges this one alone
	}
	if (len(r.final) != 0 || len(r.audits) != 0) && r.bytes+size > sparseRoundBytes {
		return nil, true, nil
	}
	for i, op := range written {
		if slices.Equal(op.Path, auditsPath) {
			continue
		}
		r.tbl[recordTable(op.Path[0])].puts[op.Path[1]] = records[i]
		r.final[op.Path[0]+"\x00"+op.Path[1]] = op
	}
	if rows != nil {
		r.audits, r.auditOp = append(r.audits, rows...), rowsOp
	}
	r.bytes += size
	return written, false, nil
}

// ops are the ops that write what the plans the round took wrote, in no order: one for each record and one for the audit rows.
func (r *sparseRound) ops() []patchOp {
	out := make([]patchOp, 0, len(r.final)+1)
	for _, op := range r.final {
		if r.compact && op.Op == opSet && (op.Path[0] == "JobBooks" || op.Path[0] == "GroupingIssues") {
			table := r.tbl[recordTable(op.Path[0])]
			// the record as the transaction holds it (the round has not written it) and as the plans of the round left it
			if before := table.ledgerTable.Get([]byte(op.Path[1])); before != nil {
				if rec, ok := recordDeltaOp(op.Path, before, table.puts[op.Path[1]]); ok {
					op = rec
				}
			}
		}
		out = append(out, op)
	}
	if len(r.audits) != 0 {
		raw, _ := json.Marshal(r.audits) // rows that were valid json come back as valid json
		out = append(out, patchOp{Op: r.auditOp, Path: slices.Clone(auditsPath), Value: raw})
	}
	return out
}

// stepOps are the ops that step a layout 2 file from revision expected: the revision and, when the stamp
// of this commit moves it, the revision clock.
func (s *Store) stepOps(ctrl *bolt.Bucket, expected model.Revision) ([]patchOp, error) {
	var stamps []model.RevisionStamp
	if raw := ctrl.Get(stateClockKey); raw != nil {
		if json.Unmarshal(raw, &stamps) != nil {
			return nil, model.Fail(model.Corrupt)
		}
	}
	if expected == ^model.Revision(0) {
		return nil, model.Fail(model.Unavailable)
	}
	step := []patchOp{revisionOp(expected + 1)}
	st := State{Revision: expected + 1, RevisionClock: slices.Clone(stamps)}
	noteRevisionTime(&st, s.clockNow().UnixNano())
	if !slices.Equal(stamps, st.RevisionClock) {
		step = append(step, patchOp{Op: opSet, Path: []string{"revision_clock"}, Value: mustJSON(st.RevisionClock)})
	}
	return step, nil
}

// lateErasureMayApply says whether eraseLateEffect would do anything for a write in the project: a finished
// deletion covers it. Such a write goes through the funnel, which gives the erasure the whole state.
func lateErasureMayApply(st *State, org, project model.ID) bool {
	for _, op := range st.Deletions {
		if (op.Phase == model.DeletePhaseComplete || op.Phase == model.DeletePhaseFailed) && op.Predicate.CoversProject(org, project) {
			return true
		}
	}
	return false
}

// bookRecords copies the records of one table of the ledger whose key starts with prefix into a map, the
// state a transition that reads the books of one project is given. The bytes are the transaction's own and
// are not to be kept past it.
func (l *ledgerTx) bookRecords(table int, prefix string) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	l.each(table, []byte(prefix), func(key, value []byte) bool {
		out[string(key)] = value
		return true
	})
	return out
}
