// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/retention"
)

// noData is the storage half of a receipt: it owes nothing, so a receipt names exactly what the
// control store reports.
type noData struct{ retention.DataPlane }

func (noData) ResidualStores() []string { return nil }

// receiptOn is the residual list a deletion receipt answered by voter id carries: the
// retention plane the application hands the service, over that voter's control store.
func (v *controlVoters) receiptOn(id uint64) []string {
	v.t.Helper()
	return retention.NewResidualPlane(noData{}, v.stores[id]).ResidualStores()
}

// erasedWithVoter3Idle runs the three-voter erasure the tests below start from: the payload is
// on all three voters, the project is retired on the leader, voters 1 and 2 hold it no more once
// they ran their own scrub and pass; voter 3 has applied the erasure and has run nothing.
func (v *controlVoters) erasedWithVoter3Idle(canary string) {
	v.t.Helper()
	leader := v.fx[1]
	// The fixture writes through voter 1, so each write phase starts with voter 1 confirmed as the leader: on a slow
	// host (a 2-vCPU CI runner) a delayed heartbeat can move the lead between phases, and a write sent to a voter
	// that stopped leading answers unavailable. The assertions are unchanged; only the fixture's precondition is
	// re-established.
	// Each round is a replicated commit of the whole control state, which grows with every round, so the
	// fixture costs the square of the round count (measured under -race on 8 vCPU: 40 rounds took 76 s
	// before the saga even started and the whole three-voter package ran for hours, with the leader moving
	// off voter 1 mid-fixture: "stale"). The race build keeps the same sequence of events (writes, saga,
	// passes, scrub) with fewer rounds; the "fixture invalid" checks below still prove voter 3 holds a copy.
	rounds := 40
	if raceEnabled {
		rounds = 10
	}
	for round := range rounds { // the replaced state spans freed pages that later writes do not all reuse
		if round%10 == 0 {
			v.leaderIs(1)
		}
		leader.seedAll(leader.newSeed(leader.project, canary), 50)
	}
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	v.leaderIs(1)
	leader.saga(control.DeleteScope{Mode: model.DeleteRetireProject, Projects: []model.ID{leader.project}})
	for _, id := range []uint64{2, 3} {
		v.await(id, v.mustRevision(1))
	}
	v.leaderIs(1)
	leader.pass()
	v.fx[2].pass()
	if err := v.stores[2].ScrubErased(context.Background()); err != nil {
		v.t.Fatal(err)
	}
	for _, id := range []uint64{1, 2} {
		if got := v.stores[id].ResidualStores(); len(got) != 0 {
			v.t.Fatalf("fixture invalid: voter %d's own residue after its own pass and scrub: %v", id, got)
		}
	}
}

// attest runs voter id's worker step and waits until every voter has the commit.
func (v *controlVoters) attest(id uint64) {
	v.t.Helper()
	if err := v.stores[id].AttestControlResidue(context.Background()); err != nil {
		v.t.Fatalf("voter %d: %v", id, err)
	}
	v.converge()
}

// converge waits until every running voter reached the newest revision any of them has.
func (v *controlVoters) converge() {
	v.t.Helper()
	var top model.Revision
	for id, s := range v.stores {
		if s == nil || v.down[id] {
			continue
		}
		if r, ok := v.revision(id); ok && r > top {
			top = r
		}
	}
	for id := range v.stores {
		if !v.down[id] {
			v.await(id, top)
		}
	}
}

// finish is the retention worker's own sequence on voter id.
func (v *controlVoters) finish(id uint64) {
	v.t.Helper()
	if err := v.stores[id].ScrubErased(context.Background()); err != nil {
		v.t.Fatal(err)
	}
	v.fx[id].pass()
	v.attest(id)
}

// facts reads, on voter `on`, which facts the record of `node` states for the current erasures.
func (v *controlVoters) facts(on, node uint64) (journal, state bool) {
	v.t.Helper()
	err := v.stores[on].View(context.Background(), func(st control.State) error {
		raw, ok := st.OIDC[fmt.Sprintf("control_attest:%d", node)]
		if !ok {
			return nil
		}
		var rec struct {
			Journal *struct{ Erasures uint64 } `json:"journal"`
			State   *struct{ Erasures uint64 } `json:"state"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			return err
		}
		journal, state = rec.Journal != nil, rec.State != nil
		return nil
	})
	if err != nil {
		v.t.Fatal(err)
	}
	return
}

func (v *controlVoters) eventually(what string, cond func() bool) {
	v.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	v.t.Fatalf("timed out waiting for: %s", what)
}

func (v *controlVoters) noResidue(canary string, ids ...uint64) {
	v.t.Helper()
	for _, id := range ids {
		if hits := v.fx[id].raftHits(canary); len(hits) != 0 {
			v.t.Fatalf("voter %d's journal still holds the payload: %v", id, hits)
		}
		if hits := controlDBHits(v.t, v.dirs[id], canary); len(hits) != 0 {
			v.t.Fatalf("voter %d's control.db still holds the payload: %v", id, hits)
		}
	}
}

func (v *controlVoters) holdsPayload(canary string, id uint64) bool {
	v.t.Helper()
	return len(v.fx[id].raftHits(canary)) != 0 && len(controlDBHits(v.t, v.dirs[id], canary)) != 0
}

// IM-1. Every voter redacts and scrubs only its own files, so a receipt built from the
// answering voter alone stopped naming the control journal and control.db while another voter's
// ready.wal, snapshots and control.db free pages still held the erased payload. The receipt,
// whichever voter answers it, names each store until every node has attested it for itself.
func TestReceiptNamesControlResidueUntilEveryVoterAttests(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTIDLE0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	if !v.holdsPayload(gone, 3) {
		t.Fatalf("fixture invalid: voter 3 holds no copy in its journal %v and control.db %v", v.fx[3].raftHits(gone), controlDBHits(t, v.dirs[3], gone))
	}
	for _, id := range []uint64{1, 2} {
		got := v.receiptOn(id)
		if !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
			t.Fatalf("FALSE CLEAN: the receipt answered by voter %d is %v while voter 3's files still hold the erased payload", id, got)
		}
	}

	// Voters 1 and 2 attest: it is not every voter.
	v.attest(1)
	v.attest(2)
	for id := uint64(1); id <= 3; id++ {
		got := v.receiptOn(id)
		if id == 3 && len(got) == 0 {
			t.Fatalf("voter 3 answered clean while it holds the payload: %v", got)
		}
		if id != 3 && (!contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState)) {
			t.Fatalf("FALSE CLEAN: two attestations of three, the receipt answered by voter %d is %v", id, got)
		}
	}
	if j, s := v.facts(1, 1); !j || !s {
		t.Fatalf("voter 1 attested neither fact: journal=%v state=%v", j, s)
	}

	// Voter 3 asked to attest before its own pass: it has no proof, so it states nothing.
	v.attest(3)
	if j, s := v.facts(1, 3); j || s {
		t.Fatalf("FORGED: voter 3 attested journal=%v state=%v without having run its scrub or its pass", j, s)
	}
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("an attestation request without a proof cleaned the receipt: %v", got)
	}

	// The two facts are independent: the scrub alone clears control.db, not the journal.
	if err := v.stores[3].ScrubErased(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.attest(3)
	if j, s := v.facts(1, 3); j || !s {
		t.Fatalf("after its scrub voter 3 states journal=%v state=%v, want state only", j, s)
	}
	if got := v.receiptOn(1); contains(got, control.ResidualControlState) || !contains(got, control.ResidualControlJournal) {
		t.Fatalf("after every voter scrubbed and one has not redacted its journal: %v", got)
	}

	v.finish(3)
	v.noResidue(gone, 1, 2, 3)
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("every voter attested and the receipt answered by voter %d still names %v", id, got)
		}
	}

	// A repeat commits nothing (bounded writes) and AttestControl never moved authority.
	before := v.mustRevision(1)
	for id := uint64(1); id <= 3; id++ {
		v.attest(id)
	}
	if after := v.mustRevision(1); after != before {
		t.Fatalf("a repeated attestation committed: revision %d -> %d", before, after)
	}
}

// An attestation is evidence, not authority: committing one must not move AuthorityRevision,
// or every voter's pass would starve a deletion Begin.
func TestAnAttestationDoesNotMoveAuthorityRevision(t *testing.T) {
	v := newControlVoters(t)
	v.erasedWithVoter3Idle("CANARYATTESTAUTH0d2b86a7c41e")
	var authority model.Revision
	read := func() (r, a model.Revision) {
		if err := v.stores[1].View(context.Background(), func(st control.State) error { r, a = st.Revision, st.AuthorityRevision; return nil }); err != nil {
			t.Fatal(err)
		}
		return
	}
	_, authority = read()
	rev, _ := read()
	v.attest(1)
	v.attest(2)
	v.finish(3)
	rev2, authority2 := read()
	if rev2 <= rev {
		t.Fatalf("fixture invalid: attestations committed nothing (%d -> %d)", rev, rev2)
	}
	// finish(3) runs voter 3's pass, whose empty revision is a classified non-authority writer.
	if authority2 != authority {
		t.Fatalf("attestations moved AuthorityRevision %d -> %d", authority, authority2)
	}
}

// A snapshot install replaces the voter's files and withdraws its redaction proof: its earlier
// attestation must not outlive that, so the receipt names the residue again, answered by ANOTHER
// voter, until the voter has scrubbed, redacted and attested once more.
func TestAnAttestationIsSupersededByASnapshotInstall(t *testing.T) {
	v := newControlVoters(t)
	w := v.watch(installTestBudget())
	const gone = "CANARYATTESTINSTALL0d2b86a7c41e"
	w.at("fixture: erasure with voter 3 idle")
	v.erasedWithVoter3Idle(gone)
	w.at("attest on voters 1 and 2, finish on voter 3")
	v.attest(1)
	v.attest(2)
	v.finish(3)
	if got := v.receiptOn(1); len(got) != 0 {
		t.Fatalf("fixture invalid: every voter attested and the receipt names %v", got)
	}
	w.at("cut voter 3 off")
	v.mesh.cut(3, true)
	var lead uint64 // the fixture's passes move leadership: find the leader among the connected voters
	w.at("wait for a leader among voters 1 and 2")
	v.eventually("a leader among voters 1 and 2", func() bool {
		for _, id := range []uint64{1, 2} {
			if st := v.stores[id].ReplicaGroup().Status(); st.Leader == id && st.ID == id {
				lead = id
				return true
			}
		}
		return false
	})
	w.at("wait until the leader serves writes (Fence)")
	v.eventually("the leader serves writes", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := v.stores[lead].ReplicaGroup().Fence(ctx)
		return err == nil
	})
	for i := range 60 { // voter 3 never receives these commands; a commit retries while leadership settles
		w.at(fmt.Sprintf("commit %d of 60 while voter 3 is cut off", i+1))
		v.eventually("a commit while voter 3 is cut off", func() bool {
			return v.stores[1].Update(context.Background(), func(st *control.State) error {
				if st.Quotas == nil {
					st.Quotas = map[string]model.QuotaState{}
				}
				st.Quotas[fmt.Sprintf("after:%d", i)] = model.QuotaState{MaxBytes: 1}
				return nil
			}) == nil
		})
	}
	w.at(fmt.Sprintf("cut the journal of leader %d (cutControl)", lead))
	v.fx[lead].cutControl() // the leader's journal no longer holds what voter 3 needs: it will be sent a snapshot
	w.at("reconnect voter 3 and wait for it to reach the newest revision")
	v.mesh.cut(3, false)
	v.await(3, v.mustRevision(1))
	// The install withdrew voter 3's proof and owes its file a scrub: voter 1's receipt says so.
	w.at("wait for voter 1's receipt to name the residue of the install")
	v.eventually("voter 1's receipt names the residue of the voter that installed a snapshot", func() bool {
		got := v.receiptOn(1)
		return contains(got, control.ResidualControlJournal) && contains(got, control.ResidualControlState)
	})
	w.at("read the attestation facts")
	if j, s := v.facts(1, 3); j || s {
		t.Fatalf("voter 3's attestation outlived the install: journal=%v state=%v", j, s)
	}
	if got := v.receiptOn(3); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("voter 3's own receipt after the install: %v", got)
	}
	// Voters 1 and 2 keep their own attestations: the install says nothing about their files.
	for _, id := range []uint64{1, 2} {
		if j, s := v.facts(1, id); !j || !s {
			t.Fatalf("voter %d's attestation was withdrawn by voter 3's install: journal=%v state=%v", id, j, s)
		}
	}
	w.at("voter 3 scrubs, redacts and attests again (finish)")
	v.finish(3)
	w.at("converge")
	v.converge()
	w.at("final receipts on every voter")
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("voter 3 scrubbed, redacted and attested again: the receipt answered by voter %d names %v", id, got)
		}
	}
	v.noResidue(gone, 3)
	w.stop()
}

// installTestBudget is how long TestAnAttestationIsSupersededByASnapshotInstall may take before its
// watchdog reports where it is waiting (the test has been seen to take 20 to 35 s alone, and to hang
// once past a 200 s wrapper, undiagnosed).
func installTestBudget() time.Duration {
	if raceEnabled {
		return 300 * time.Second
	}
	return 120 * time.Second
}

// voterWatch is a watchdog over one voter test. The test names the step it is in (at); if the test
// is still running when the budget lapses, the watchdog reports, from its own goroutine, the step it
// is in and for how long, the steps that finished with their durations, each voter's replica status
// and the stacks of every goroutine that is inside this module, then fails the test. The report is
// what a hang past the budget leaves behind: with it a timeout names where it waited, not only that
// it did. It never stops the test; go test's own timeout still ends a test that never returns.
type voterWatch struct {
	mu      sync.Mutex
	t       failer
	stores  map[uint64]*control.Store
	began   time.Time
	step    string
	stepAt  time.Time
	done    []string
	stopped bool
	timer   *time.Timer
}

// failer is what a watchdog reports to: the test, or a recorder in the watchdog's own test.
type failer interface {
	Errorf(format string, args ...any)
}

// watch arms the watchdog; it is disarmed by stop and when the test ends. A test that fails (a
// fixture helper gave up) logs the same report when it ends, so a failure names the step it was in.
func (v *controlVoters) watch(budget time.Duration) *voterWatch {
	v.t.Helper()
	w := newVoterWatch(v.t, v.stores, budget)
	v.t.Cleanup(w.stop)
	v.t.Cleanup(func() {
		if v.t.Failed() {
			w.mu.Lock()
			defer w.mu.Unlock()
			v.t.Logf("%s", w.describe("the test failed"))
		}
	})
	return w
}

func newVoterWatch(t failer, stores map[uint64]*control.Store, budget time.Duration) *voterWatch {
	w := &voterWatch{t: t, stores: map[uint64]*control.Store{}, began: time.Now()}
	for id, s := range stores {
		w.stores[id] = s
	}
	w.stepAt = w.began
	w.timer = time.AfterFunc(budget, func() { w.report(budget) })
	return w
}

// at records that the test moved on to step.
func (w *voterWatch) at(step string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if w.step != "" {
		w.done = append(w.done, fmt.Sprintf("%8.1fs  %s", now.Sub(w.stepAt).Seconds(), w.step))
	}
	w.step, w.stepAt = step, now
}

func (w *voterWatch) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	w.timer.Stop()
}

// within runs f and reports whether it returned inside d (a status call that blocks on the group's
// lock is itself the finding).
func within(d time.Duration, f func()) bool {
	finished := make(chan struct{})
	go func() { f(); close(finished) }()
	select {
	case <-finished:
		return true
	case <-time.After(d):
		return false
	}
}

func (w *voterWatch) report(budget time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopped {
		return
	}
	w.t.Errorf("%s", w.describe(fmt.Sprintf("WATCHDOG: the test is still running %v after it began (budget %v)", time.Since(w.began).Round(time.Second), budget)))
}

// describe is the report: the headline, the step the test is in, the steps that finished, each
// voter's state and the stacks of the goroutines inside this module. The caller holds w.mu.
func (w *voterWatch) describe(headline string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s; step %q began %.1fs ago\n", headline, w.step, time.Since(w.stepAt).Seconds())
	b.WriteString("steps finished (seconds in each):\n")
	for _, line := range w.done {
		b.WriteString("  " + line + "\n")
	}
	ids := make([]uint64, 0, len(w.stores))
	for id := range w.stores {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		s := w.stores[id]
		if s == nil || s.ReplicaGroup() == nil {
			fmt.Fprintf(&b, "voter %d: no replication group\n", id)
			continue
		}
		var st replica.Status
		var rev model.Revision
		var revErr error
		if !within(2*time.Second, func() { st = s.ReplicaGroup().Status() }) {
			fmt.Fprintf(&b, "voter %d: Status blocked for 2s (the group's lock is held)\n", id)
			continue
		}
		readDone := within(3*time.Second, func() {
			revErr = s.View(context.Background(), func(cs control.State) error { rev = cs.Revision; return nil })
		})
		switch {
		case !readDone:
			fmt.Fprintf(&b, "voter %d: id=%d leader=%d term=%d commit=%d applied=%d last=%d; a linearizable read is still blocked after 3s\n", id, st.ID, st.Leader, st.Term, st.Commit, st.Applied, st.LastIndex)
		case revErr != nil:
			fmt.Fprintf(&b, "voter %d: id=%d leader=%d term=%d commit=%d applied=%d last=%d; read failed: %v\n", id, st.ID, st.Leader, st.Term, st.Commit, st.Applied, st.LastIndex, revErr)
		default:
			fmt.Fprintf(&b, "voter %d: id=%d leader=%d term=%d commit=%d applied=%d last=%d revision=%d\n", id, st.ID, st.Leader, st.Term, st.Commit, st.Applied, st.LastIndex, rev)
		}
	}
	var stacks bytes.Buffer
	_ = pprof.Lookup("goroutine").WriteTo(&stacks, 2)
	b.WriteString("goroutines inside this module (the rest are runtime and test machinery):\n")
	kept := 0
	for _, g := range strings.Split(stacks.String(), "\n\n") {
		if !strings.Contains(g, "soundpost/internal/") || strings.Contains(g, "voterWatch).describe") {
			continue
		}
		if kept++; kept > 40 || b.Len() > 120<<10 {
			b.WriteString("  ... more goroutines not shown\n")
			break
		}
		b.WriteString(g + "\n\n")
	}
	return b.String()
}

// recorder is a failer that keeps what it was told.
type recorder struct {
	mu  sync.Mutex
	got []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.mu.Lock()
	r.got = append(r.got, fmt.Sprintf(format, args...))
	r.mu.Unlock()
}

func (r *recorder) reports() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

// parkedInTheWatchdogTest waits for release: the stack the watchdog must show for a goroutine that
// does not return.
//
//go:noinline
func parkedInTheWatchdogTest(release <-chan struct{}) { <-release }

// A voter test that stalls past its budget has to say where: the step it was in, the steps that
// finished, every voter's state and the stacks of the goroutines inside this module; a test that
// finished in time (stop) says nothing.
func TestAVoterTestWatchdogNamesTheStepAndWhereTheGoroutinesWait(t *testing.T) {
	rec := &recorder{}
	w := newVoterWatch(rec, map[uint64]*control.Store{7: nil}, 50*time.Millisecond)
	defer w.stop()
	w.at("the first step")
	w.at("the step that hangs")
	release := make(chan struct{})
	defer close(release)
	go parkedInTheWatchdogTest(release)
	deadline := time.Now().Add(10 * time.Second)
	for len(rec.reports()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	reports := rec.reports()
	if len(reports) != 1 {
		t.Fatalf("a stalled test produced %d watchdog reports, want 1", len(reports))
	}
	for _, want := range []string{`step "the step that hangs"`, "the first step", "voter 7: no replication group", "parkedInTheWatchdogTest"} {
		if !strings.Contains(reports[0], want) {
			t.Fatalf("the watchdog report does not contain %q:\n%s", want, reports[0])
		}
	}

	quiet := &recorder{}
	finished := newVoterWatch(quiet, nil, 30*time.Millisecond)
	finished.at("a step")
	finished.stop()
	time.Sleep(150 * time.Millisecond)
	if got := quiet.reports(); len(got) != 0 {
		t.Fatalf("a watchdog that was stopped reported anyway: %s", got[0])
	}
}

// The redaction proof is durable (replica machine.proof): a process that restarted over a record
// its pass left keeps what it attested. A restart over a missing record holds no proof, so it
// withdraws what it attested and states it again from its next pass.
func TestARestartedVoterKeepsItsAttestationOnlyWithItsDurableProof(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTRESTART0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	v.attest(1)
	v.attest(2)
	v.finish(3)
	if got := v.receiptOn(1); len(got) != 0 {
		t.Fatalf("fixture invalid: %v", got)
	}
	v.restart(3)
	time.Sleep(2 * time.Second) // a withdrawal, if the restart caused one, would have been committed by now
	if j, s := v.facts(1, 3); !j || !s {
		t.Fatalf("a restart over the durable proof withdrew voter 3's attestation: journal=%v state=%v", j, s)
	}
	if got := v.receiptOn(1); len(got) != 0 {
		t.Fatalf("a restarted voter holds its durable proof and the receipt names %v", got)
	}

	if err := os.Remove(filepath.Join(v.dirs[3], "raft-control", "machine.proof")); err != nil {
		t.Fatalf("the pass left no durable proof: %v", err)
	}
	v.restart(3)
	v.eventually("voter 3's journal attestation is withdrawn by a restart without its proof", func() bool {
		j, _ := v.facts(1, 3)
		return !j
	})
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("a restarted voter holds no proof and the receipt does not name the journal: %v", got)
	}
	if _, s := v.facts(1, 3); !s {
		t.Fatalf("a restart withdrew the scrub fact: the marker is a fact about the file and survives it")
	}
	v.fx[3].pass() // finds its files already clean and proves it
	v.attest(3)
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("after its next pass the receipt answered by voter %d names %v", id, got)
		}
	}
}

// restart closes voter id's store and group and opens them again over the same files.
func (v *controlVoters) restart(id uint64) {
	v.t.Helper()
	old := v.stores[id]
	position := old.ReplicaGroup().Status()
	if err := old.Close(); err != nil {
		v.t.Fatal(err)
	}
	store, err := control.Open(v.dirs[id])
	if err != nil {
		v.t.Fatal(err)
	}
	v.stores[id] = store
	seed, application, err := store.ReplicationSeed()
	if err != nil {
		v.t.Fatal(err)
	}
	for _, bind := range []func() error{store.BindRuleEvaluation, store.BindIncidentAction, store.BindConditionApply, store.BindDeliveryOutbox, store.BindRetention} {
		if err = bind(); err != nil {
			v.t.Fatal(err)
		}
	}
	group, err := store.EnableReplication(replica.Config{ID: id, Group: position.Group, Directory: filepath.Join(v.dirs[id], "raft-control"), TickInterval: voterTick(), Members: position.Members,
		Transport: voterTransport{mesh: v.mesh, node: id}, Seed: seed, Application: application})
	if err != nil {
		v.t.Fatal(err)
	}
	v.mesh.set(id, group)
	svc, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return v.fx[id].now }})
	if err != nil {
		v.t.Fatal(err)
	}
	v.fx[id].store, v.fx[id].svc = store, svc
	v.await(id, v.mustRevision(1))
}

// Nobody can write an attestation but the voter's own worker path.
func TestAnAttestationCannotBeForged(t *testing.T) {
	v := newControlVoters(t)
	v.erasedWithVoter3Idle("CANARYATTESTFORGE0d2b86a7c41e")
	leader := v.fx[1]
	var erasures int
	if err := v.stores[1].View(context.Background(), func(st control.State) error {
		for _, a := range st.Audits {
			if a.Action == "delete.control_erased" {
				erasures++
			}
		}
		return nil
	}); err != nil || erasures == 0 {
		t.Fatalf("fixture invalid: erasures=%d err=%v", erasures, err)
	}
	forged := json.RawMessage(fmt.Sprintf(`{"node":3,"identity":"voter-3","journal":{"erasures":%d,"applied":1},"state":{"erasures":%d,"applied":1}}`, erasures, erasures))
	expect := func(err error, code model.Code, what string) {
		t.Helper()
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != code {
			t.Fatalf("%s: %v, want %s", what, err, code)
		}
	}
	untouched := func(what string) {
		t.Helper()
		if j, s := v.facts(1, 3); j || s {
			t.Fatalf("%s: a forged attestation of voter 3 is in the state", what)
		}
		if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
			t.Fatalf("%s: the receipt is %v", what, got)
		}
	}

	// A client scope has no command kind to write it with: the vocabulary is closed.
	for _, kind := range []string{"AttestControlResidue", "AttestControl", "Attest"} {
		_, err := v.stores[1].Transact(leader.ctx, leader.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: v.mustRevision(1), Kind: kind, Payload: forged})
		expect(err, model.Invalid, "kind "+kind)
	}
	untouched("closed vocabulary")

	// Even a handler registered for a real kind cannot write one on behalf of a client.
	if err := v.stores[1].RegisterHandler(control.KindRegisterRelease, func(_ auth.Scope, st *control.State, _ control.Command) (control.Effect, error) {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["control_attest:3"] = forged
		return control.Effect{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	_, err := v.stores[1].Transact(leader.ctx, leader.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: v.mustRevision(1), Kind: string(control.KindRegisterRelease), Payload: json.RawMessage(`{}`)})
	expect(err, model.Forbidden, "a Transact handler writing an attestation")
	untouched("Transact handler")

	// Nor the exported Update, from any package.
	err = v.stores[1].Update(leader.ctx, func(st *control.State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["control_attest:3"] = forged
		return nil
	})
	expect(err, model.Forbidden, "Update writing an attestation")
	untouched("Update")

	// It may delete one (a receipt only names more), and it may write unrelated records.
	if err = v.stores[1].Update(leader.ctx, func(st *control.State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC["unrelated:key"] = json.RawMessage(`{}`)
		return nil
	}); err != nil {
		t.Fatalf("an unrelated OIDC record was refused: %v", err)
	}

	// A voter whose local proof does not hold: voter 3 has not scrubbed nor redacted. Its
	// request (the only way to write its record) states nothing, and nobody else can name it.
	v.attest(3)
	untouched("a voter without a local proof")
}

// A replacement voter (the group moves from {1,2,3} to {1,2,4}) is not covered by the others'
// attestations and must attest before the receipt is clean; the voter it replaced no longer
// counts, though its files still hold the payload.
func TestAJoinedVoterMustAttestAndARemovedOneNoLongerCounts(t *testing.T) {
	v := newControlVoters(t)
	const gone = "CANARYATTESTMEMBERS0d2b86a7c41e"
	v.erasedWithVoter3Idle(gone)
	v.attest(1)
	v.attest(2)
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) {
		t.Fatalf("fixture invalid: voter 3 has not attested and the receipt names %v", got)
	}

	// Voter 4 joins as a learner and receives the cluster by snapshot.
	leader := v.fx[1]
	genesis := v.genesis
	var err error
	position := v.stores[1].ReplicaGroup().Status()
	members := position.Members
	learner := replica.Members{Revision: members.Revision + 1, Nodes: append(append([]replica.Member(nil), members.Nodes...), replica.Member{ID: 4, Address: "https://voter4.invalid", NodeIdentity: "voter-4", FailureDomain: "disk-4", Learner: true})}
	dir := t.TempDir()
	v.dirs[4] = dir
	store, err := control.OpenSeed(dir, genesis.seed)
	if err != nil {
		t.Fatal(err)
	}
	v.stores[4] = store
	for _, bind := range []func() error{store.BindRuleEvaluation, store.BindIncidentAction, store.BindConditionApply, store.BindDeliveryOutbox, store.BindRetention} {
		if err = bind(); err != nil {
			t.Fatal(err)
		}
	}
	group, err := store.EnableReplication(replica.Config{ID: 4, Group: position.Group, Directory: filepath.Join(dir, "raft-control"), TickInterval: voterTick(), Members: learner,
		Transport: voterTransport{mesh: v.mesh, node: 4}, Seed: genesis.seed, Application: genesis.application, SeedIndex: genesis.index, SeedTerm: genesis.term})
	if err != nil {
		t.Fatal(err)
	}
	v.mesh.set(4, group)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err = v.changeMembers(ctx, members.Revision, learner, 0); err != nil {
		t.Fatal(err)
	}
	v.eventually("voter 4 caught up", func() bool { r, ok := v.revision(4); return ok && r >= v.mustRevision(1) })
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("a node that joined after the erasure is not covered by the others' attestations: %v", got)
	}

	// Voter 3 leaves; voter 4 becomes a voter. Voter 3 never attested and still holds the payload.
	next := replica.Members{Revision: learner.Revision + 1}
	for _, n := range learner.Nodes {
		switch n.ID {
		case 3:
			continue
		case 4:
			n.Learner = false
		}
		next.Nodes = append(next.Nodes, n)
	}
	if err = v.changeMembers(ctx, learner.Revision, next, 3); err != nil {
		t.Fatal(err)
	}
	if !v.holdsPayload(gone, 3) {
		t.Fatal("fixture invalid: the removed voter holds no copy of the payload")
	}
	v.eventually("voter 1 sees the new configuration", func() bool {
		return v.stores[1].ReplicaGroup().Status().Members.Revision == next.Revision
	})
	// The configuration moved but voter 4 has attested nothing: it is the one that is missing.
	if got := v.receiptOn(1); !contains(got, control.ResidualControlJournal) || !contains(got, control.ResidualControlState) {
		t.Fatalf("the replacement voter has not attested and the receipt is %v", got)
	}
	v.markDown(3)
	v.fx[4] = &eraseFx{&delFx{fenceFx: &fenceFx{t: t, dir: dir, ctx: leader.ctx, store: store, now: leader.now}, dest: leader.dest, policy: leader.policy, subject: leader.subject}}
	v.finish(4)
	v.eventually("voter 1's receipt is clean once the replacement attested", func() bool { return len(v.receiptOn(1)) == 0 })
	for _, id := range []uint64{1, 2, 4} {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("voter %d's receipt names %v although every current voter attested", id, got)
		}
	}
	v.noResidue(gone, 4)
}

// Without a replication group the local view is the whole cluster.
func TestAStoreWithoutAGroupAnswersForItself(t *testing.T) {
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, want := store.ClusterResidualStores(), store.ResidualStores(); len(got) != len(want) {
		t.Fatalf("cluster %v, local %v", got, want)
	}
	if err = store.AttestControlResidue(context.Background()); err != nil {
		t.Fatalf("attesting without a group: %v", err)
	}
}

// markDown records that voter id is no longer part of the running group, so converge and
// attest stop waiting for it.
func (v *controlVoters) markDown(id uint64) {
	if v.down == nil {
		v.down = map[uint64]bool{}
	}
	v.down[id] = true
}

// CheckReadiness is what a leader asks before it promotes a learner: the learner's applied index.
func (t voterTransport) CheckReadiness(_ context.Context, _ model.ID, node uint64) (uint64, error) {
	t.mesh.mu.Lock()
	g := t.mesh.groups[node]
	t.mesh.mu.Unlock()
	if g == nil {
		return 0, replica.ErrUnavailable
	}
	return g.Status().Applied, nil
}

// Once every node attested, an idle group commits nothing for attestations: no withdrawal or
// attestation loop, and leadership does not move.
func TestSettledAttestationsCommitNothingOnAnIdleCluster(t *testing.T) {
	v := newControlVoters(t)
	lg := func(s string) {
		st := v.stores[1].ReplicaGroup().Status()
		t.Logf("DIAG %s: leader=%d term=%d rev=%d", s, st.Leader, st.Term, st.Revision)
	}
	lg("start")
	v.erasedWithVoter3Idle("CANARYATTESTIDLECOMMITS0d2b86a7c41e")
	lg("erased")
	v.attest(1)
	lg("a1")
	v.attest(2)
	lg("a2")
	v.finish(3)
	lg("f3")
	time.Sleep(2 * time.Second) // let any pending withdrawal settle
	v.converge()
	rev := v.mustRevision(1)
	status := v.stores[1].ReplicaGroup().Status()
	time.Sleep(10 * time.Second)
	after := v.stores[1].ReplicaGroup().Status()
	if got := v.mustRevision(1); got != rev {
		t.Fatalf("an idle settled cluster committed %d control revisions in 10 s", got-rev)
	}
	if after.Term != status.Term || after.Leader != status.Leader {
		t.Fatalf("leadership moved on an idle cluster: term %d->%d leader %d->%d", status.Term, after.Term, status.Leader, after.Leader)
	}
	for id := uint64(1); id <= 3; id++ {
		if got := v.receiptOn(id); len(got) != 0 {
			t.Fatalf("voter %d: %v", id, got)
		}
	}
	t.Logf("leader=%d term=%d revision=%d", after.Leader, after.Term, rev)
}

// changeMembers drives a membership change through whichever voter is the leader now (the
// passes of the fixture move leadership), retrying while leadership is moving. avoid names a
// voter that is leaving: leadership is moved off it first.
func (v *controlVoters) changeMembers(ctx context.Context, expected model.Revision, next replica.Members, avoid uint64) error {
	var last error
	for ctx.Err() == nil {
		var lead *replica.Group
		for id, s := range v.stores {
			if s == nil || v.down[id] || s.ReplicaGroup() == nil {
				continue
			}
			if st := s.ReplicaGroup().Status(); st.Leader == id && st.ID == id {
				lead = s.ReplicaGroup()
			}
		}
		if lead != nil {
			if st := lead.Status(); avoid != 0 && st.ID == avoid {
				last = lead.TransferLeadership(ctx, 1)
			} else if last = lead.ChangeMembers(ctx, expected, next); last == nil || !errors.Is(last, replica.ErrConflict) && !errors.Is(last, replica.ErrUnavailable) && !errors.Is(last, replica.ErrStale) {
				return last
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("membership change did not complete: %v", last)
}
