// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// This file is what makes a committed deletion reach the control books that
// carry payloads derived from telemetry: RuleBooks and RuleOutputs (a recording
// intent holds a whole batch), IncidentBooks, ConditionBooks and DeliveryBooks.
// The C12 saga hides and erases the data groups; without this, the values those
// groups held stayed readable here, in control.db and in the control snapshot.
//
// The erasure is one deterministic function of (state, predicate, time) that
// runs INSIDE the transition that begins a deletion (beginDeletion), completes
// it (completeDeletion: it catches an effect that committed between the two) or
// re-applies it from the restore authority (ImportDeletions). Control commands
// replicate the whole resulting state, so every replica, every snapshot restore
// and every journal replay installs the same bytes the proposer computed.

// Residual store names Store.ResidualStores reports, in the vocabulary of
// storage.ResidualStores.
const (
	// ResidualControlState is control.db: bbolt never zeroes a page it frees, so
	// the state an erasure replaced still sits in free pages of the file until
	// ScrubErased zeroes them.
	ResidualControlState = "control_state"
	// ResidualControlJournal is the control group's Raft journal, snapshots and
	// retry table: every control command carries the whole control state, and
	// the group retains every command (and so its payload) for retry
	// recognition. RedactRetainedControlCommands removes the covered payloads
	// from this node's copy; ResidualStores names it until that is proven.
	ResidualControlJournal = "control_raft_journal"
)

const (
	controlErasedAction = "delete.control_erased"
	controlErasedReason = "control_payloads_erased"
	// controlScrubbedAction settles the control.db scrub an erasing audit owes:
	// it is appended after ScrubErased zeroed every free page, and names the
	// operations whose erasing audits the scrub covered.
	controlScrubbedAction = "delete.control_scrubbed"
	controlScrubbedReason = "control_db_free_pages_zeroed"
)

// eraseControlPayloads drops every control payload the operation's predicate
// covers and audits the fact when it dropped any. at is the deterministic time
// of the transition; it never reads a clock. While the operation is fencing, a
// delivery it covers only loses its body and stays paused (deliveryGate); once
// it is complete or failed the unsent ones are settled. It is the begin,
// complete and import erasure: an opaque state is covered by stateErased.
func eraseControlPayloads(st *State, op model.DeletionOperation, at model.UnixNano) error {
	return eraseControlPayloadsBy(st, op, at, stateErased)
}

func eraseControlPayloadsBy(st *State, op model.DeletionOperation, at model.UnixNano, rule stateRule) error {
	dropped, err := eraseBooks(st, op, at, rule)
	if err != nil {
		return err
	}
	if dropped > 0 {
		audit(st, op.Principal, op.Predicate.Org, controlErasedAction, controlErasedReason, at, []model.ID{op.Predicate.Operation})
	}
	return nil
}

// eraseLateEffect runs inside every transition that commits an effect derived
// from telemetry (a rule evaluation, an incident or condition action, a job
// update, issue evidence, a delivery enqueue) of project. The barrier saga lets
// a worker that read its batch before the barrier finish its write, so such an
// effect can commit AFTER a deletion completed (or failed); the erasure that ran
// when the operation completed has long passed. For every committed deletion
// that covers the project and has finished (complete or failed: a fencing one
// erases at its completion, and a held one has not begun) the erasure runs
// again over the state the effect just changed, so the covered payload never
// reaches the committed state, the snapshot or control.db.
//
// It is NOT the begin/complete erasure over again: that one drops an opaque
// state (incident, condition, job) whose newest time is at or after the range's
// start with no end bound, because the payloads under it really were old. Run on
// every later commit that rule would tombstone a brand-new state in the very
// transition that commits it, forever (09.06 review C-1). The late pass uses
// stateErasedLate, which covers an opaque state only when it names evidence
// inside the range's [start,end); the other books (rule evaluations, issue
// evidence, deliveries) already are half-open and are unchanged. The pass is
// idempotent and adds an erasing audit (and so owes a scrub) only when it
// dropped something, like every erasure; the transition time is the
// operation's own completion time, so it stays a pure function of (state,
// predicate), identical on every replica.
func eraseLateEffect(st *State, org, project model.ID) error {
	if len(st.Deletions) == 0 {
		return nil
	}
	ids := make([]string, 0, len(st.Deletions))
	for id := range st.Deletions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		op := st.Deletions[id]
		if op.Phase != model.DeletePhaseComplete && op.Phase != model.DeletePhaseFailed || !op.Predicate.CoversProject(org, project) {
			continue
		}
		if err := eraseControlPayloadsBy(st, op, op.CompletedAt, stateErasedLate); err != nil {
			return err
		}
	}
	return nil
}

// eraseControlBooks is the begin/complete/import erasure itself: every control
// book, one call each, in a fixed order. It returns how many payloads it dropped.
func eraseControlBooks(st *State, op model.DeletionOperation, at model.UnixNano) (dropped int, err error) {
	return eraseBooks(st, op, at, stateErased)
}

// eraseBooks is eraseControlBooks with the rule that covers an opaque state.
func eraseBooks(st *State, op model.DeletionOperation, at model.UnixNano, rule stateRule) (dropped int, err error) {
	p := op.Predicate
	_, dropped, err = eraseRuleFacts(st, p, false)
	if err != nil {
		return 0, err
	}
	settle := op.Phase == model.DeletePhaseComplete || op.Phase == model.DeletePhaseFailed
	for _, erase := range []func() (int, error){
		func() (int, error) { return eraseIncidentsBy(st, p, rule) },
		func() (int, error) { return eraseConditionsBy(st, p, rule) },
		func() (int, error) { return eraseDeliveries(st, p, at, settle, op.Principal) },
		func() (int, error) { return eraseIssueBooks(st, p, at) },
		func() (int, error) { return eraseJobBooksBy(st, p, at, rule) },
		func() (int, error) { return eraseCutoverBooks(st, p, at) },
	} {
		n, err := erase()
		if err != nil {
			return 0, err
		}
		dropped += n
	}
	return dropped, nil
}

// RedactControlCommand is the control machine's half of redacting the control
// group's retained commands. Every control command carries the whole control
// state, so a command committed before a deletion still carries the payloads the
// deletion erased, in the journal, the retry table and every snapshot. Given the
// retained payload of one control command it returns the payload to retain
// instead: the same command (same expected revision, state and keys) with every
// payload covered by a deletion this node has committed removed, by the same
// functions the live erasure runs. changed is false when nothing was covered.
// The replacement applies to the same state: it differs only in erased books.
//
// RedactRetainedControlCommands is the driver that hands this function the retained commands
// of the control Raft group; this method is the one-payload form of the same rule.
func (s *Store) RedactControlCommand(payload []byte) (replacement []byte, changed bool, err error) {
	current, err := s.localState()
	if err != nil {
		return nil, false, err
	}
	return redactControlPayload(current, payload)
}

// redactControlPayload is RedactControlCommand against an explicit current state.
func redactControlPayload(current State, payload []byte) (replacement []byte, changed bool, err error) {
	var next controlReplacement
	if model.StrictJSON(payload, &next) != nil {
		return nil, false, model.Fail(model.Corrupt)
	}
	ids := make([]string, 0, len(current.Deletions))
	for id := range current.Deletions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		op := current.Deletions[id]
		if op.Phase == model.DeletePhaseHeld {
			continue // a held deletion has not begun: nothing of it is erased
		}
		at := op.CompletedAt
		if at == 0 {
			at = op.RequestedAt
		}
		// A command whose own state already has the deletion finished was committed
		// after it, so the live apply screened its effect with the late rule: the
		// redaction must not drop what that apply kept.
		rule := stateRule(stateErased)
		if committed, ok := next.State.Deletions[id]; ok && (committed.Phase == model.DeletePhaseComplete || committed.Phase == model.DeletePhaseFailed) {
			rule = stateErasedLate
		}
		n, err := eraseBooks(&next.State, op, at, rule)
		if err != nil {
			return nil, false, err
		}
		changed = changed || n > 0
	}
	if !changed {
		return payload, false, nil
	}
	replacement, err = json.Marshal(next)
	if err != nil {
		return nil, false, model.Fail(model.Invalid)
	}
	return replacement, true, nil
}

// stateRule decides whether the opaque state of one record is covered by a
// predicate: stateErased when a deletion begins, completes or is imported,
// stateErasedLate in the transition of an effect that commits after it finished.
type stateRule func(p model.DeletePredicate, org, project model.ID, raw json.RawMessage) bool

// stateErased decides whether the opaque state of one record is covered when a
// deletion begins, completes or is imported, while the payloads under it really
// are old. A retirement covers every record of its projects. A range covers the
// records whose state names an evidence time at or after its start (NO end
// bound: the state may mix times and the whole is dropped) and every record
// whose state names none or cannot be read: a payload that cannot be attributed
// is dropped whole. An entity deletion names replay and profile roots, which
// these records only link by ID: it covers none. A tombstone is never covered
// again.
func stateErased(p model.DeletePredicate, org, project model.ID, raw json.RawMessage) bool {
	if !p.CoversProject(org, project) || stateIsTombstone(raw) {
		return false
	}
	switch p.Mode {
	case model.DeleteRetireOrg, model.DeleteRetireProject:
		return true
	case model.DeleteHistoricalRange:
		latest, ok := stateLatestTime(raw)
		return !ok || latest >= p.Start
	}
	return false
}

// stateErasedLate is stateErased for the late re-erasure (eraseLateEffect): the
// state was just written by an effect that may have been read before the
// deletion's barrier, so what decides is whether it names evidence INSIDE the
// range's half-open [start,end), exactly the interval the books that are
// precise already use (CoversOrigin). A range covers the state when a named time
// lies in [start,end), and, as at begin, when the state names no evidence time
// at all or one that cannot be read (unattributable, dropped whole). Evidence
// before start or at and after end derives from data the range did not delete: a
// state first committed from such data is kept, whatever else it names (the
// action's own time, a watermark, the evaluation time). Durations
// (lateDurationKeys) and unset times (zero or negative) are no evidence of an
// instant and are not read as one. A retirement covers every record of its
// projects and an entity deletion none, as in stateErased. The signal list is
// ignored, as in stateErased: a state does not name the signal its evidence came
// from.
func stateErasedLate(p model.DeletePredicate, org, project model.ID, raw json.RawMessage) bool {
	if !p.CoversProject(org, project) || stateIsTombstone(raw) {
		return false
	}
	switch p.Mode {
	case model.DeleteRetireOrg, model.DeleteRetireProject:
		return true
	case model.DeleteHistoricalRange:
		named, inside := false, false
		readable := stateTimes(raw, func(key string, at model.UnixNano) {
			if at <= 0 || lateDurationKeys[key] {
				return
			}
			named = true
			inside = inside || at >= p.Start && at < p.End
		})
		return !readable || !named || inside
	}
	return false
}

// lateDurationKeys are the keys under which an opaque state carries a length of
// time (job definition revisions), not an instant, though they end in "_ns".
var lateDurationKeys = map[string]bool{"grace_ns": true, "max_runtime_ns": true, "observer_stale_after_ns": true}

// tombstoneState is what an erased record keeps in place of its state: the
// closed header and the erasing operation, nothing derived from telemetry.
func tombstoneState(idKey string, id, org, project model.ID, version model.Revision, operation model.ID) json.RawMessage {
	v, _ := json.Marshal(version)
	return json.RawMessage(fmt.Sprintf(`{%q:%q,"org_id":%q,"project_id":%q,"version":%s,"erased":%q}`, idKey, id.String(), org.String(), project.String(), v, operation.String()))
}

func stateIsTombstone(raw json.RawMessage) bool {
	var t struct {
		Erased string `json:"erased"`
	}
	return json.Unmarshal(raw, &t) == nil && t.Erased != ""
}

// stateLatestTime is the newest evidence time a state names: every number or
// numeric string under a key "at", "*_at" or "*_ns", at any depth. ok is false
// when it names none or a time cannot be read.
func stateLatestTime(raw json.RawMessage) (latest model.UnixNano, ok bool) {
	named := false
	readable := stateTimes(raw, func(_ string, at model.UnixNano) {
		if !named || at > latest {
			latest, named = at, true
		}
	})
	return latest, named && readable
}

// stateTimes calls visit, in sorted key order, for every time a state names:
// every number or numeric string under a key "at", "*_at" or "*_ns", at any
// depth, with that key. readable is false when the state is not JSON or a named
// time cannot be read.
func stateTimes(raw json.RawMessage, visit func(key string, at model.UnixNano)) (readable bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var root any
	if dec.Decode(&root) != nil {
		return false
	}
	bad := false
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if k == "at" || strings.HasSuffix(k, "_at") || strings.HasSuffix(k, "_ns") {
					var text string
					switch n := t[k].(type) {
					case json.Number:
						text = n.String()
					case string:
						text = n
					case nil:
						continue
					default:
						bad = true
						continue
					}
					ns, err := strconv.ParseInt(text, 10, 64)
					if err != nil {
						bad = true
						continue
					}
					visit(k, model.UnixNano(ns))
					continue
				}
				walk(t[k])
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(root)
	return !bad
}

// scrubDebt is the control.db scrub one operation still owes: the position of its
// newest erasing audit in the audit log and that audit's time.
type scrubDebt struct {
	last int
	at   model.UnixNano
}

// owedScrubs reads, from the audit log alone, which operations still owe a scrub
// of control.db: an erasing audit makes its operation owe one, and a scrubbed
// audit for the operation settles everything before it. The log is append-only
// and ordered by commit, so the answer is a function of committed state, survives
// restart and snapshot restore, and does not depend on the operation's phase (a
// failed operation, whose physical step is never recorded, owes it too).
func owedScrubs(audits []model.ControlAudit) map[model.ID]scrubDebt {
	debts := map[model.ID]scrubDebt{}
	for i, a := range audits {
		switch a.Action {
		case controlErasedAction:
			for _, id := range a.Targets {
				debts[id] = scrubDebt{last: i, at: model.UnixNano(a.Time)}
			}
		case controlScrubbedAction:
			for _, id := range a.Targets {
				delete(debts, id)
			}
		}
	}
	return debts
}

// controlErasures reads, from committed state only, what is still owed on this
// node: control.db while an erasing audit has no scrubbed audit after it, the
// journal residue from the first erasure on.
func controlErasures(st State) (stateOwed, journalOwed bool) {
	for _, a := range st.Audits {
		if a.Action == controlErasedAction {
			journalOwed = true
			break
		}
	}
	return len(owedScrubs(st.Audits)) != 0, journalOwed
}

func (s *Store) localState() (st State, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &st) != nil {
			return model.Fail(model.Corrupt)
		}
		return nil
	})
	return
}

// ResidualStores names the local control stores that can still hold a copy of
// erased control payloads right now (same contract as storage.Engine.
// ResidualStores; it reads this node only and never blocks on consensus):
//
//   - ResidualControlState from an erasure until ScrubErased has zeroed the free
//     pages of control.db after it (any erasure: begin, completion, failure,
//     import, or an effect erased as it committed after its operation finished);
//   - ResidualControlJournal from the first erasing deletion on, until
//     RedactRetainedControlCommands has proven, for every erasure committed so
//     far, that this node's control Raft group holds none of the covered
//     payloads (replica.Group.MachineResidue is empty). A group that cannot be
//     measured, a pass that did not complete, a live backup pin and a node that
//     has not run the pass all keep it named.
//
// A state that cannot be read is reported as both.
func (s *Store) ResidualStores() []string {
	st, err := s.localState()
	if err != nil {
		return []string{ResidualControlJournal, ResidualControlState}
	}
	stateOwed, journalOwed := controlErasures(st)
	var out []string
	if journalOwed {
		if residue, err := s.controlJournalResidue(st); err != nil || len(residue) != 0 {
			out = append(out, ResidualControlJournal)
		}
	}
	if stateOwed {
		out = append(out, ResidualControlState)
	}
	return out
}

const (
	scrubChunkPages  = 8192 // 32 MiB at 4 KiB pages per write transaction
	scrubAttempts    = 40
	scrubBackoff     = 25 * time.Millisecond
	scrubZeroRunPage = 256
)

var errScrubBusy = errors.New("read transaction open")

// ScrubErased overwrites every free page of control.db with zeros while an
// erasure's scrub is owed, then records that it did (settleScrub), so the owed
// state clears and a later erasure owes a new scrub. bbolt is copy-on-write and
// never zeroes a page it frees, so the state that an erasure replaced would
// otherwise stay in the file. It does not depend on the operation's phase: a
// completed operation's physical step runs it first (RecordPhysicalCleanup), and
// the retention worker runs it on every pass, which is the only way the scrub of
// a FAILED operation (whose physical step is never recorded) or of an effect that
// was erased after its operation's physical step ever runs. It is a no-op, and
// does not touch the file, when nothing is owed.
//
// Safety (the storage engine's argument, which this mirrors): inside a bbolt
// write transaction, the single writer, a page the freelist reports free is
// referenced by no committed tree provided no read transaction is open; so each
// chunk runs in its own write transaction and defers while a reader is open. A
// crash leaves some free pages zeroed and others not, the file valid, and the
// scrub still owed (it is derived from committed state), so the next call redoes
// it. It does not touch the Raft journal or its snapshots (ResidualControlJournal).
func (s *Store) ScrubErased(ctx context.Context) error {
	st, err := s.localState()
	if err != nil {
		return err
	}
	// The scrub covers exactly the erasures committed before it read the state:
	// an erasure committed while it runs freed pages it may have passed.
	through := len(st.Audits)
	if len(owedScrubs(st.Audits)) == 0 {
		return nil
	}
	file, err := os.OpenFile(s.db.Path(), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	pageSize := uint64(s.db.Info().PageSize)
	var high uint64
	if err = s.db.View(func(tx *bolt.Tx) error { high = uint64(tx.Size()) / pageSize; return nil }); err != nil {
		return err
	}
	for first := uint64(2); first < high; first += scrubChunkPages {
		if err = ctx.Err(); err != nil {
			return model.Fail(model.Cancelled)
		}
		if err = s.scrubChunk(ctx, file, first, min(first+scrubChunkPages, high), pageSize); err != nil {
			return err
		}
	}
	return s.settleScrub(ctx, through)
}

// settleScrub appends one scrubbed audit per operation whose erasing audits all
// precede position `through` of the audit log (the scrub's coverage) and are not
// settled yet. The audit's time is the newest erasure's own time (the scrub
// knows no clock of its own and no transition reads one), so what is appended is
// a function of the committed state and `through` only.
func (s *Store) settleScrub(ctx context.Context, through int) error {
	err := s.Update(ctx, func(st *State) error {
		debts := owedScrubs(st.Audits)
		ids := make([]model.ID, 0, len(debts))
		for id, d := range debts {
			if d.last < through {
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return errNothingToSettle // another pass settled them first: commit nothing
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		for _, id := range ids {
			op := st.Deletions[id.String()]
			audit(st, op.Principal, op.Predicate.Org, controlScrubbedAction, controlScrubbedReason, debts[id].at, []model.ID{id})
		}
		return nil
	})
	if errors.Is(err, errNothingToSettle) {
		return nil
	}
	return err
}

var errNothingToSettle = errors.New("no scrub to settle")

func (s *Store) scrubChunk(ctx context.Context, file *os.File, first, last, pageSize uint64) error {
	zero := make([]byte, pageSize*scrubZeroRunPage)
	for attempt := 0; ; attempt++ {
		zeroed := uint64(0)
		err := s.db.Update(func(tx *bolt.Tx) error {
			if s.db.Stats().OpenTxN > 0 {
				return errScrubBusy
			}
			for id := first; id < last; {
				info, err := tx.Page(int(id))
				if err != nil {
					return err
				}
				if info == nil { // beyond this transaction's high-water mark
					break
				}
				if info.Type != "free" {
					id++
					continue
				}
				start := id
				for id < last {
					if info, err = tx.Page(int(id)); err != nil {
						return err
					}
					if info == nil || info.Type != "free" {
						break
					}
					id++
				}
				for run := start; run < id; {
					n := min(id-run, scrubZeroRunPage)
					if _, err := file.WriteAt(zero[:n*pageSize], int64(run*pageSize)); err != nil {
						return err
					}
					run += n
				}
				zeroed += id - start
			}
			if zeroed > 0 {
				return file.Sync()
			}
			return nil
		})
		switch {
		case err == nil:
			return nil
		case errors.Is(err, errScrubBusy):
			if attempt+1 >= scrubAttempts {
				return model.Fail(model.Unavailable) // a reader stayed open: the scrub is still owed
			}
			select {
			case <-ctx.Done():
				return model.Fail(model.Cancelled)
			case <-time.After(scrubBackoff):
			}
		default:
			return err
		}
	}
}
