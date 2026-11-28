// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// D108, the marker: the one replicated command that moves the rule books and the rule outbox out of the blob. These tests follow
// it through the paths a group takes across it: a voter that installs a snapshot cut after it, a voter that replays the log over
// it, a second marker, a stop of the process on either side of it, a member that does not read the new layout, a restart.

// markerRule is a rule a test commits evaluations of. The outputs of a blob are keyed by their ID alone, so the seeds of the
// outputs of two rules do not meet (base).
type markerRule struct {
	id   model.ID
	base byte
	n    uint64
}

// markerVoters is three control voters whose compact gate (protocol 10, the gate of the move) a test opens by hand.
type markerVoters struct {
	*controlVoters
	gate  atomic.Bool
	lease replica.FenceToken
}

func newMarkerVoters(t *testing.T, cadence replica.Cadence) *markerVoters {
	t.Helper()
	m := &markerVoters{controlVoters: newControlVotersCadence(t, cadence)}
	for _, s := range m.stores {
		m.install(s)
	}
	token, err := m.stores[1].ReplicaGroup().Fence(m.fx[1].ctx)
	if err != nil {
		t.Fatal(err)
	}
	m.lease = token
	return m
}

// install gives a store the gates of a group whose members all declared protocol 9 (the state patch) and, once m.gate is open,
// protocol 10. A restarted store has none until its owner installs them.
func (m *markerVoters) install(s *control.Store) {
	s.SetStatePatchGate(func() bool { return true })
	s.SetCompactAdmissionGate(m.gate.Load)
}

func (m *markerVoters) newRule(base byte) *markerRule {
	return &markerRule{id: model.NewID(), base: base}
}

// evaluate commits n evaluations of r through the store of voter id. retry runs a command again, as the scheduler does, when it
// lost the revision to another commit (conflict, stale): a test of two writers at once needs it, the others none.
func (m *markerVoters) evaluate(id uint64, r *markerRule, n int, retry bool) error {
	f := &ruleFx{fenceFx: m.fx[1].fenceFx, rule: r.id}
	for range n {
		r.n++
		at := r.n
		command := model.NewID()
		for attempt := 1; ; attempt++ {
			err := f.write(func() error {
				scope, err := f.scopeNow()
				if err != nil {
					return err
				}
				cmd, err := f.cmdNow(control.KindApplyRuleEvaluation, command, control.RuleCommand{Operation: control.RuleOpEvaluation, Lease: &m.lease,
					Evaluation: f.evaluation(1, 60*at, at-1, control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, at), recordingIntent(r.base+byte(at)))})
				if err != nil {
					return err
				}
				_, err = m.stores[id].Transact(f.ctx, scope, cmd)
				return err
			})
			if err == nil {
				break
			}
			if c := code(err); !retry || attempt >= 30 || c != model.Conflict && c != model.Stale {
				return fmt.Errorf("voter %d, evaluation %d: %w", id, at, err)
			}
		}
	}
	return nil
}

func (m *markerVoters) must(err error) {
	m.t.Helper()
	if err != nil {
		m.t.Fatal(err)
	}
}

// handed is how many snapshots the mesh delivered to voter id.
func (m *markerVoters) handed(id uint64) int {
	m.mesh.mu.Lock()
	defer m.mesh.mu.Unlock()
	return int(m.mesh.snaps[id])
}

// logicalRuleFacts is the rule books and the outbox of a store as a reader sees them: the outputs are keyed by their ID in the
// blob and by their rule and ID in the ledger, so the facts are the values.
func logicalRuleFacts(ctx context.Context, s *control.Store) (string, error) {
	var out string
	err := s.View(ctx, func(st control.State) error {
		var books, outputs []string
		for k, v := range st.RuleBooks {
			books = append(books, k+"="+string(v))
		}
		for _, v := range st.RuleOutputs {
			outputs = append(outputs, string(v))
		}
		sort.Strings(books)
		sort.Strings(outputs)
		out = strings.Join(books, "\n") + "\n--\n" + strings.Join(outputs, "\n")
		return nil
	})
	return out, err
}

// identical waits for the voters to converge and compares every voter with the leader: the canonical state, the rule facts a
// reader sees, the records of the two rule tables byte for byte, and the side of the marker the voter is on. ledger says which.
func (m *markerVoters) identical(phase string, ledger bool) {
	m.t.Helper()
	m.converge()
	ctx := m.fx[1].ctx
	wantState := m.fx[1].canonicalState()
	wantFacts, err := logicalRuleFacts(ctx, m.stores[1])
	m.must(err)
	wantTables, err := m.stores[1].RuleTablesForTest()
	m.must(err)
	wantLayout, wantAt := m.stores[1].RuleLayout()
	if ledger != (wantLayout == "ledger") {
		m.t.Fatalf("%s: the leader keeps the rule facts in the %s, want ledger=%v", phase, wantLayout, ledger)
	}
	if ledger != (len(wantTables) != 0) {
		m.t.Fatalf("%s: the leader holds %d rule records in its tables, ledger=%v", phase, len(wantTables), ledger)
	}
	for id := uint64(2); id <= 3; id++ {
		if got := m.fx[id].canonicalState(); got != wantState {
			m.t.Fatalf("%s: voter %d holds another state than the leader", phase, id)
		}
		if got, err := logicalRuleFacts(ctx, m.stores[id]); err != nil || got != wantFacts {
			m.t.Fatalf("%s: voter %d reads other rule facts than the leader (%v)", phase, id, err)
		}
		tables, err := m.stores[id].RuleTablesForTest()
		m.must(err)
		if !reflect.DeepEqual(tables, wantTables) {
			m.t.Fatalf("%s: voter %d holds %d rule records, the leader %d, and they differ", phase, id, len(tables), len(wantTables))
		}
		if layout, at := m.stores[id].RuleLayout(); layout != wantLayout || at != wantAt {
			m.t.Fatalf("%s: voter %d reports the layout %s at %d, the leader %s at %d", phase, id, layout, at, wantLayout, wantAt)
		}
		if blob := m.stores[id].BlobMemberForTest("RuleBooks"); ledger && blob != "null" {
			m.t.Fatalf("%s: the blob of voter %d still holds RuleBooks: %.60s", phase, id, blob)
		}
	}
}

// A voter cut off while the group wrote the marker and then enough rule commands for the journal to be compacted past it is
// handed a snapshot cut after the marker. It ends with the rule tables of the leader, the blob without the rule facts, the layout
// the leader has, and then applies and proposes rule commands in the ledger form over what it installed.
func TestAVoterThatInstallsASnapshotTakenAfterTheMarkerEndsWithTheBooksOfTheLeader(t *testing.T) {
	const lagging = 3
	m := newMarkerVoters(t, replica.Cadence{Commands: 16})
	r := m.newRule(0)
	m.must(m.evaluate(1, r, 3, false))
	m.identical("before the marker", false)
	m.mesh.cut(lagging, true)
	m.gate.Store(true)
	m.must(m.evaluate(1, r, 52, false)) // the first of them writes the marker; the cadence cuts and compacts over it
	for id := uint64(1); id <= 2; id++ {
		if !m.stores[id].RuleLedgerForTest() || m.stores[id].LedgerCountForTest("rule_books") != 1 {
			t.Fatalf("voter %d did not move the rule facts", id)
		}
	}
	if m.stores[lagging].RuleLedgerForTest() {
		t.Fatalf("voter %d moved the rule facts while it was cut off", lagging)
	}
	if n := m.handed(lagging); n != 0 {
		t.Fatalf("voter %d was handed %d snapshots while it was cut off", lagging, n)
	}
	m.mesh.cut(lagging, false)
	m.await(lagging, m.mustRevision(1))
	if m.handed(lagging) < 1 {
		t.Fatalf("voter %d caught up without a snapshot: the journal was not compacted past the marker, the premise does not hold", lagging)
	}
	m.identical("installed", true)
	sparse := m.stores[lagging].SparseCommitsForTest()
	m.must(m.evaluate(lagging, r, 2, false))
	if got := m.stores[lagging].SparseCommitsForTest(); got <= sparse {
		t.Fatalf("the voter that installed the snapshot committed its rule commands as %d records, was %d", got, sparse)
	}
	m.must(m.evaluate(1, r, 2, false))
	m.identical("after", true)
}

// A voter cut off over the marker, whose journal is not compacted, replays the log: the commands before the marker, the marker
// and the commands after it. It ends where the leader is, with no snapshot installed.
func TestAVoterThatReplaysTheLogAcrossTheMarkerEndsWithTheBooksOfTheLeader(t *testing.T) {
	const lagging = 2
	m := newMarkerVoters(t, replica.Cadence{})
	r := m.newRule(0)
	m.must(m.evaluate(1, r, 3, false))
	m.identical("before the marker", false)
	m.mesh.cut(lagging, true)
	m.gate.Store(true)
	m.must(m.evaluate(1, r, 6, false)) // voters 1 and 3 are the quorum
	if m.stores[lagging].RuleLedgerForTest() {
		t.Fatalf("voter %d moved the rule facts while it was cut off", lagging)
	}
	m.mesh.cut(lagging, false)
	m.await(lagging, m.mustRevision(1))
	if n := m.handed(lagging); n != 0 {
		t.Fatalf("voter %d was handed %d snapshots: it did not replay the log, the premise does not hold", lagging, n)
	}
	m.identical("replayed", true)
	m.must(m.evaluate(lagging, r, 2, false))
	m.identical("after", true)
}

// The marker moves the books once. Two voters whose first rule command after the gate opened are concurrent both propose it: one
// commits and the other finds the file moved or is refused as stale, and neither moves anything twice. A marker proposed after the
// move commits nothing, and a command that carries the mark again leaves the records as they are.
func TestTheMarkerMovesTheBooksOnceWhateverIsProposedAfterIt(t *testing.T) {
	m := newMarkerVoters(t, replica.Cadence{})
	a, b, c := m.newRule(0), m.newRule(100), m.newRule(150)
	m.must(m.evaluate(1, a, 3, false))
	m.identical("blob", false)
	before := m.mustRevision(1)
	m.gate.Store(true)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = m.evaluate(2, b, 1, true) }()
	go func() { defer wg.Done(); errs[1] = m.evaluate(3, c, 1, true) }()
	wg.Wait()
	for _, err := range errs {
		m.must(err)
	}
	m.identical("moved", true)
	if got := m.mustRevision(1); got != before+3 {
		t.Fatalf("the revision is %d, want %d: two evaluations and one marker", got, before+3)
	}
	if _, at := m.stores[1].RuleLayout(); at != uint64(before)+1 {
		t.Fatalf("the marker names revision %d, want %d", at, before+1)
	}
	for id := uint64(1); id <= 3; id++ {
		if books, outputs := m.stores[id].LedgerCountForTest("rule_books"), m.stores[id].LedgerCountForTest("rule_outputs"); books != 3 || outputs != 5 {
			t.Fatalf("voter %d holds %d rule books and %d outputs after the move, want 3 and 5", id, books, outputs)
		}
	}
	tables, err := m.stores[1].RuleTablesForTest()
	m.must(err)
	revision := m.mustRevision(1)
	if m.stores[1].EnsureRuleLedgerForTest(m.fx[1].ctx) || m.mustRevision(1) != revision {
		t.Fatal("a marker proposed after the move committed")
	}
	// The state a command that names the mark again leaves: the records are the ones they were.
	m.must(m.stores[1].Update(m.fx[1].ctx, func(st *control.State) error {
		if !st.RulesInLedger() {
			t.Error("the state read does not carry the mark")
		}
		st.MarkRulesInLedger(st.Revision + 1)
		return nil
	}))
	m.identical("marked again", true)
	if again, err := m.stores[1].RuleTablesForTest(); err != nil || !reflect.DeepEqual(again, tables) {
		t.Fatalf("a second marker changed the rule records (%v)", err)
	}
	// The point of the move is read from the state, not from what a voter kept (RuleLayout reads it once): a second marker did not
	// move it on any voter.
	for id := uint64(1); id <= 3; id++ {
		m.must(m.stores[id].View(m.fx[id].ctx, func(st control.State) error {
			if at := st.RulesMarkedAt(); at != uint64(before)+1 {
				t.Errorf("voter %d: the state names the marker at revision %d after a second marker, want %d", id, at, before+1)
			}
			return nil
		}))
	}
	m.must(m.evaluate(2, a, 2, false))
	m.identical("after", true)
}

// A member that reads the contracted layout and not the rule ledger (every build before the move, protocol 9) is accepted into
// the group while the books are in the blob and refused once the marker is committed: as a learner, as a voter, in the report of
// the members that cannot read the layout, and as the receiver of a snapshot. A learner nothing is running for yet is admitted as a
// learner, as for the contracted layout; the snapshot guard sends it nothing until it answers.
func TestAMemberThatDoesNotReadTheRuleLedgerIsRefusedAfterTheMarker(t *testing.T) {
	const lagging = 3
	m := newMarkerVoters(t, replica.Cadence{Commands: 16})
	ctx := m.fx[1].ctx
	var refuse atomic.Bool
	notRunning := replica.Member{ID: 6, NodeIdentity: "node-6", Address: "https://node6.invalid"}
	old := replica.Member{ID: 5, NodeIdentity: "node-5", Address: "https://node5.invalid"}
	fine := replica.Member{ID: 4, NodeIdentity: "node-4", Address: "https://node4.invalid"}
	// The leader's answers: every member reads the contracted layout (a protocol-9 build does); the rule ledger is read by all but
	// the old build, the one nothing runs for, and voter 3 while a test says it does not.
	m.stores[1].SetMemberRuleLedgerQuery(func(_ context.Context, to replica.Member) error {
		switch {
		case to.NodeIdentity == old.NodeIdentity, to.NodeIdentity == "voter-3" && refuse.Load():
			return model.Fail(model.Unsupported)
		case to.NodeIdentity == notRunning.NodeIdentity:
			return replica.ErrMemberNotRunning
		}
		return nil
	})
	m.stores[1].SetMemberLayoutQuery(func(_ context.Context, to replica.Member) error {
		if to.NodeIdentity == notRunning.NodeIdentity {
			return replica.ErrMemberNotRunning
		}
		return nil
	})
	r := m.newRule(0)
	m.must(m.evaluate(1, r, 2, false)) // the gate is closed: the books are in the blob
	for _, member := range []replica.Member{old, fine, notRunning} {
		if err := m.stores[1].CheckMemberLayout(ctx, member); member == notRunning && err == nil {
			t.Fatalf("a member nothing runs for was admitted as a voter before the marker")
		} else if member != notRunning && err != nil {
			t.Fatalf("%s was refused before the marker: %v", member.NodeIdentity, err)
		}
	}
	m.gate.Store(true)
	m.must(m.evaluate(1, r, 1, false)) // the marker
	if !m.stores[1].RuleLedgerForTest() {
		t.Fatal("the premise does not hold: the books did not move")
	}
	refused := func(err error, identity string) bool {
		var fault *model.Fault
		return errors.As(err, &fault) && fault.Code == model.Unsupported && fault.SafeDetail == control.LayoutIncompatiblePrefix+identity
	}
	if err := m.stores[1].CheckLearnerLayout(ctx, old); !refused(err, old.NodeIdentity) {
		t.Fatalf("a protocol-9 learner was not refused after the marker: %v", err)
	}
	if err := m.stores[1].CheckMemberLayout(ctx, old); !refused(err, old.NodeIdentity) {
		t.Fatalf("a protocol-9 voter was not refused after the marker: %v", err)
	}
	if err := m.stores[1].CheckLearnerLayout(ctx, fine); err != nil {
		t.Fatalf("a member that reads the rule ledger was refused as a learner: %v", err)
	}
	if err := m.stores[1].CheckMemberLayout(ctx, fine); err != nil {
		t.Fatalf("a member that reads the rule ledger was refused as a voter: %v", err)
	}
	if err := m.stores[1].CheckLearnerLayout(ctx, notRunning); err != nil {
		t.Fatalf("a learner nothing runs for was refused: %v", err)
	}
	if err := m.stores[1].CheckMemberLayout(ctx, notRunning); !refused(err, notRunning.NodeIdentity) {
		t.Fatalf("a voter nothing runs for was admitted: %v", err)
	}
	if got, want := m.stores[1].MembersIncompatible(ctx, []replica.Member{old, fine}), []string{control.LayoutIncompatiblePrefix + old.NodeIdentity}; !reflect.DeepEqual(got, want) {
		t.Fatalf("the members the report names: %v, want %v", got, want)
	}
	// The snapshot: a voter cut off over the marker and the compaction is sent nothing while it does not read the rule ledger.
	m.mesh.cut(lagging, true)
	refuse.Store(true)
	m.must(m.evaluate(1, r, 40, false))
	m.mesh.cut(lagging, false)
	time.Sleep(3 * time.Second)
	if n := m.handed(lagging); n != 0 {
		t.Fatalf("voter %d was sent %d snapshots of the moved state while it did not read the rule ledger", lagging, n)
	}
	if got, want := m.mustRevisionOf(lagging), m.mustRevision(1); got >= want && m.stores[lagging].RuleLedgerForTest() {
		t.Fatalf("voter %d caught up (%d of %d) without a snapshot: the premise (a journal compacted past the marker) does not hold", lagging, got, want)
	}
	refuse.Store(false)
	m.await(lagging, m.mustRevision(1))
	if m.handed(lagging) < 1 {
		t.Fatalf("voter %d caught up without a snapshot once it answered", lagging)
	}
	m.identical("installed once it answered", true)
}

// mustRevisionOf is mustRevision for a voter that may be behind: its own revision, 0 when it cannot serve a read yet.
func (m *markerVoters) mustRevisionOf(id uint64) model.Revision {
	m.t.Helper()
	r, _ := m.revision(id)
	return r
}

// A voter restarted between the marker and the first rule command that follows keeps the layout (the file says so), reports the same
// side and the same revision of the marker, and its next rule command is committed as the records of its rule.
func TestARestartBetweenTheMarkerAndTheFirstRuleCommandKeepsTheLayout(t *testing.T) {
	m := newMarkerVoters(t, replica.Cadence{})
	r := m.newRule(0)
	m.must(m.evaluate(1, r, 3, false))
	m.identical("before the marker", false)
	m.gate.Store(true)
	if !m.stores[1].EnsureRuleLedgerForTest(m.fx[1].ctx) {
		t.Fatal("the marker was not committed")
	}
	m.converge()
	_, at := m.stores[1].RuleLayout()
	for id := uint64(1); id <= 3; id++ {
		if layout, got := m.stores[id].RuleLayout(); layout != "ledger" || got != at || at == 0 {
			t.Fatalf("voter %d reports %s at %d after the marker, voter 1 at %d", id, layout, got, at)
		}
	}
	m.identical("marked", true)
	m.restart(2)
	m.install(m.stores[2])
	if layout, got := m.stores[2].RuleLayout(); !m.stores[2].RuleLedgerForTest() || layout != "ledger" || got != at {
		t.Fatalf("the restarted voter reports %s at %d, want ledger at %d", layout, got, at)
	}
	m.identical("restarted", true)
	sparse := m.stores[2].SparseCommitsForTest()
	m.must(m.evaluate(2, r, 1, false))
	if got := m.stores[2].SparseCommitsForTest(); got <= sparse {
		t.Fatalf("the first rule command of the restarted voter was not committed as records (%d, was %d)", got, sparse)
	}
	m.identical("first rule command", true)
	if m.stores[2].LedgerCountForTest("rule_books") != 1 || m.stores[2].BlobMemberForTest("RuleBooks") != "null" {
		t.Fatal("the rule facts are not in the ledger of the restarted voter")
	}
	m.must(m.evaluate(1, r, 2, false))
	m.identical("after", true)
}

// The diagnostic reports the side of the marker: the blob and no revision until the marker is applied, the ledger and the revision
// of the command that wrote it after, the same that the state names.
func TestRuleLayoutNamesTheSideOfTheMarker(t *testing.T) {
	f := newRuleFxProtocol10(t)
	if layout, at := f.store.RuleLayout(); layout != "blob" || at != 0 {
		t.Fatalf("before any rule command: %s at %d", layout, at)
	}
	revision := f.revision()
	if _, err := f.eval(f.lease(), f.evaluation(1, 60, 0, control.RuleModeLive, `{"n":1}`, recordingIntent(1))); err != nil {
		t.Fatal(err)
	}
	layout, at := f.store.RuleLayout()
	if layout != "ledger" || at != uint64(revision)+1 {
		t.Fatalf("after the first rule command: %s at %d, want ledger at %d", layout, at, revision+1)
	}
	if err := f.store.View(f.ctx, func(st control.State) error {
		if st.RulesMarkedAt() != at {
			t.Errorf("the state names revision %d, the diagnostic %d", st.RulesMarkedAt(), at)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The process stops before the marker is applied, between the blob without the rule facts and the tables that hold them, and
// after the transaction committed. Each leaves a file that opens, whose journal brings the voter to the state the marker makes, with
// the rule facts a reader saw before it and the tables the move writes, and in which the marker is applied once.
func TestACrashAtThePointsOfTheMarkerApplyLeavesAStateOpenAccepts(t *testing.T) {
	for _, point := range []string{control.RuleMarkerBefore, control.RuleMarkerSplit, control.RuleMarkerAfter} {
		t.Run(point, func(t *testing.T) {
			var gate atomic.Bool
			f := newRuleFx(t)
			f.store.SetStatePatchGate(func() bool { return true })
			f.store.SetCompactAdmissionGate(gate.Load)
			lease := f.lease()
			for i := range 4 {
				if _, err := f.eval(lease, f.evaluation(1, uint64(60*(i+1)), uint64(i), control.RuleModeLive, fmt.Sprintf(`{"n":%d}`, i), recordingIntent(byte(i+1)), conditionIntent(byte(i+101), false))); err != nil {
					t.Fatal(err)
				}
			}
			want, err := logicalRuleFacts(f.ctx, f.store)
			if err != nil {
				t.Fatal(err)
			}
			revision := f.revision()
			var fired atomic.Bool
			remove := control.SetRuleMarkerFaultForTest(func(at string) error {
				if at == point && fired.CompareAndSwap(false, true) {
					return errInjectedFault
				}
				return nil
			})
			gate.Store(true)
			_ = f.store.EnsureRuleLedgerForTest(f.ctx) // committed by the group; its apply stops at the point
			remove()
			if !fired.Load() {
				t.Fatalf("the point %s was never reached: the case proves nothing", point)
			}
			if err := f.store.Close(); err != nil {
				t.Logf("close after the stop: %v", err)
			}
			s := openFaulted(t, f.ctx, f.dir, nil)
			t.Cleanup(func() { s.Close() })
			s.SetStatePatchGate(func() bool { return true })
			s.SetCompactAdmissionGate(func() bool { return true })
			if !s.RuleLedgerForTest() {
				t.Fatalf("after a stop at %s the reopened file does not keep the rule facts in the ledger", point)
			}
			if layout, at := s.RuleLayout(); layout != "ledger" || at != uint64(revision)+1 {
				t.Fatalf("after a stop at %s the file reports %s at %d, want ledger at %d", point, layout, at, revision+1)
			}
			if got, err := logicalRuleFacts(f.ctx, s); err != nil || got != want {
				t.Fatalf("after a stop at %s the rule facts differ from what a reader saw before the marker (%v):\nwant %.600s\ngot  %.600s", point, err, want, got)
			}
			if books, outputs := s.LedgerCountForTest("rule_books"), s.LedgerCountForTest("rule_outputs"); books != 1 || outputs != 8 {
				t.Fatalf("after a stop at %s the tables hold %d rule books and %d outputs, want 1 and 8", point, books, outputs)
			}
			if blob := s.BlobMemberForTest("RuleBooks"); blob != "null" {
				t.Fatalf("after a stop at %s the blob still holds RuleBooks: %.60s", point, blob)
			}
			var committed model.Revision
			if err := s.View(f.ctx, func(st control.State) error { committed = st.Revision; return nil }); err != nil || committed != revision+1 {
				t.Fatalf("after a stop at %s the revision is %d (%v), want %d: the marker is one command", point, committed, err, revision+1)
			}
			if s.EnsureRuleLedgerForTest(f.ctx) {
				t.Fatalf("after a stop at %s the marker was committed again", point)
			}
		})
	}
}
