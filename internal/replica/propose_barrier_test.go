// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The ReadIndex in front of Validate (Group.propose): what these tests pin, and why nothing more can be amortised.
//
// Pinned, on a hand-pumped wire where a ReadIndex round is "in flight" exactly while its heartbeats sit undelivered:
//   (a) a proposal that arrives while a round is in flight is validated only after the NEXT round, put after it
//       arrived; the answer of the round already in flight never serves it;
//   (d) 32 concurrent proposers of one group cost two rounds (the one in flight, the one they all joined), not 32;
//   (b) a leader that was cut off and deposed (it still believes it leads, its applied state lags the new leader's)
//       neither validates nor proposes (ErrNoQuorum); the one command that does reach its log (ProposeQueued skips
//       the round by contract) is overwritten, and no member applies it once the partition heals;
//   (c) a command built on stale state never applies: ErrStale from the head check, ErrStale from the application
//       index check of the queue (also inside one batch), or ErrConflict from the apply of the voters.
// Deleting the g.ReadIndex call of propose fails (a), (d) and (b); (c) runs on a lone voter (lock-free cursor) and
// does not depend on it: commit safety is the apply's, the round only makes Validate's verdict a linearizable one.
//
// Amortisation beyond what exists, for the control group: none, so node.go is unchanged.
//  1. A round serves a call only if it was put after the call arrived (reads.go), so rounds can only be shared
//     between calls that wait at the same time. The control proposer is serialised by the update lock: command n+1
//     is built from the state n left, so it arrives after n was applied. A cycle's queue holds at most one control
//     proposal, and none waits on a round when the next arrives. The quorum acknowledgement of n's append predates
//     n+1 as well, so it is not a confirmation for n+1.
//  2. The other callers of that group (Fence, ReadIndexAtLeast, the reads of the data engine's appends) already share
//     rounds with it. A proposal that arrives behind one of them waits for the rest of that round and one whole
//     round. Putting a second round at arrival would save half a round trip on average and double the rounds a
//     second, the load reads.go removed.
//  3. Validating at apply only (ErrConflict), at the queue's application index only, or after a lease, a term or a
//     clock, would give the verdicts of a lagging or deposed leader (test b): the shortcut the barrier forbids. A
//     round that was answered before the proposal arrived is the same shortcut by another name.

// barrierValidation is one call of a member's Validate: the command, and how many ReadIndex rounds the member had put
// to its leader by then.
type barrierValidation struct {
	node   uint64
	id     model.ID
	rounds uint64
}

// barrierResult is what a Propose answered.
type barrierResult struct {
	committed CommittedEntry
	err       error
}

// barrierCluster is three voters of one group on the hand-pumped wire of quorum_test.go (messages move only when a
// test delivers them, the members are ticked by hand), each with a whole-state machine and a Validate that records its
// calls and applies the head check of the control group's Validate against the state the member has applied.
type barrierCluster struct {
	wire     *testWire
	machines []*wholeMachine

	mu          sync.Mutex
	validations []barrierValidation
}

func newBarrierCluster(t *testing.T) *barrierCluster {
	t.Helper()
	id := model.NewID()
	c := &barrierCluster{wire: &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for i := range 3 {
		machine := newWholeMachine(id)
		c.machines = append(c.machines, machine)
		g, err := Open(Config{ID: uint64(i + 1), Group: id, Directory: t.TempDir(), Members: members, Machine: machine, Transport: c.wire, Validate: c.validator(uint64(i + 1))})
		if err != nil {
			t.Fatal(err)
		}
		c.wire.nodes[uint64(i+1)] = g
		t.Cleanup(func() { g.Close() })
	}
	if err := c.wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	c.wire.pump(t)
	for node := uint64(1); node <= 3; node++ {
		if got := c.wire.nodes[node].Status().Leader; got != 1 {
			t.Fatalf("node %d follows %d, want the leader 1", node, got)
		}
	}
	return c
}

// validator is the Validate of member node. A Control command is refused with ErrStale when the revision it expects
// is not the one this member has applied (control's Validate refuses on the head of its database the same way);
// every other kind passes.
func (c *barrierCluster) validator(node uint64) func(context.Context, Entry) error {
	return func(_ context.Context, e Entry) error {
		c.mu.Lock()
		c.validations = append(c.validations, barrierValidation{node: node, id: e.ID, rounds: c.wire.nodes[node].phases.readRounds.Load()})
		c.mu.Unlock()
		if e.Kind != Control {
			return nil
		}
		var cmd wholeCommand
		if err := json.Unmarshal(e.Payload, &cmd); err != nil {
			return ErrInvalid
		}
		if cmd.Expected != c.machines[node-1].current().Rev {
			return ErrStale
		}
		return nil
	}
}

// validated is the validation of command id by any member, when there was one.
func (c *barrierCluster) validated(id model.ID) (barrierValidation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, v := range c.validations {
		if v.id == id {
			return v, true
		}
	}
	return barrierValidation{}, false
}

func (c *barrierCluster) validationCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.validations)
}

// rev is the revision of the whole state member node has applied.
func (c *barrierCluster) rev(node uint64) uint64 { return c.machines[node-1].current().Rev }

// barrierDeliver hands the oldest queued message to its member, as pump does for all of them, and reports whether
// there was one. A test that delivers one message at a time decides which round a message belongs to.
func barrierDeliver(t *testing.T, w *testWire) bool {
	t.Helper()
	w.mu.Lock()
	if len(w.queue) == 0 {
		w.mu.Unlock()
		return false
	}
	message := w.queue[0]
	w.queue = w.queue[1:]
	g := w.nodes[message.GetTo()]
	blocked := w.blocked[message.GetFrom()] || w.blocked[message.GetTo()]
	w.mu.Unlock()
	if g != nil && !blocked {
		if err := g.Step(context.Background(), message); err != nil && !errors.Is(err, ErrUnavailable) {
			t.Fatal(err)
		}
	}
	return true
}

// barrierSettle pumps the wire until done, for at most 10 seconds.
func barrierSettle(t *testing.T, w *testWire, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("not within 10s: %s", what)
		}
		w.pump(t)
		time.Sleep(time.Millisecond)
	}
}

// barrierPropose proposes e on g from its own goroutine; the answer is ready (len 1) when Propose returned.
func barrierPropose(g *Group, e Entry) <-chan barrierResult {
	out := make(chan barrierResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		committed, err := g.Propose(ctx, e)
		out <- barrierResult{committed: committed, err: err}
	}()
	return out
}

// barrierReads is the state of g's ReadIndex rounds: how many are in flight and whether callers wait for the next.
func barrierReads(g *Group) (inFlight int, waiting bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.reads), g.readNext != nil
}

// barrierTraces reports whether g's tables hold the command id: the table of the commands in its log, and the retry
// table of those that were applied (a refused or overwritten command is in neither).
func barrierTraces(g *Group, id model.ID) (inLog, completed bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, inLog = g.logCommands[id]
	_, completed = g.completed[id]
	return inLog, completed
}

// barrierBooks is the books of a whole-state command that wrote book.
func barrierBooks(book string) map[string]string { return map[string]string{"book": book} }

// barrierFirstRevision commits revision 1 on the leader (node 1) and waits until every member applied it.
func barrierFirstRevision(t *testing.T, c *barrierCluster) {
	t.Helper()
	if _, err := testPropose(t, c.wire, 1, wholeEntry(0, barrierBooks("one"))); err != nil {
		t.Fatal(err)
	}
	barrierSettle(t, c.wire, "every member applied revision 1", func() bool { return c.rev(1) == 1 && c.rev(2) == 1 && c.rev(3) == 1 })
}

// barrierCutOff cuts node 1 off the wire and does not tick it, so it does not hear that it lost its quorum and still
// believes it leads; the other two are ticked until one leads, and revision 2 is committed on that leader and applied by
// its quorum. It returns that leader and the third member. Revision 1 must be committed (barrierFirstRevision).
func barrierCutOff(t *testing.T, c *barrierCluster) (next, other uint64) {
	t.Helper()
	old := c.wire.nodes[1]
	c.wire.block(1)
	for range 200 {
		for _, node := range []uint64{2, 3} {
			c.wire.nodes[node].Tick()
			c.wire.pump(t)
			if _, self := c.wire.nodes[node].Leader(); self {
				next = node
				break
			}
		}
		if next != 0 {
			break
		}
	}
	if next == 0 {
		t.Fatal("the members that can talk elected no leader")
	}
	other = 5 - next
	successor := c.wire.nodes[next]
	// Revision 2 is acknowledged by the new leader and applied by its quorum; node 1 has not seen it.
	if _, err := testPropose(t, c.wire, next, wholeEntry(1, barrierBooks("two"))); err != nil {
		t.Fatal(err)
	}
	barrierSettle(t, c.wire, "the new quorum applied revision 2", func() bool { return c.rev(next) == 2 && c.rev(other) == 2 })
	if leader, self := old.Leader(); leader != 1 || !self {
		t.Fatalf("the cut-off member follows %d (leads: %v): the scenario of a leader that does not know it was deposed is not built", leader, self)
	}
	if c.rev(1) != 1 || old.Status().Term >= successor.Status().Term {
		t.Fatalf("the deposed leader is at revision %d, term %d; the new leader at term %d", c.rev(1), old.Status().Term, successor.Status().Term)
	}
	return next, other
}

// barrierHeal reconnects node 1, ticks the new leader next until node 1 follows it and has applied what it applied, and
// checks that every member applied exactly revisions 1 and 2, as the acknowledged commands made them.
func barrierHeal(t *testing.T, c *barrierCluster, next uint64) {
	t.Helper()
	old, successor := c.wire.nodes[1], c.wire.nodes[next]
	c.wire.mu.Lock()
	delete(c.wire.blocked, 1)
	c.wire.mu.Unlock()
	deadline := time.Now().Add(10 * time.Second)
	for {
		leader, _ := old.Leader()
		if leader == next && c.rev(1) == 2 && old.Status().Applied == successor.Status().Applied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the deposed leader did not catch up: leader %d, revision %d, applied %d of %d", leader, c.rev(1), old.Status().Applied, successor.Status().Applied)
		}
		successor.Tick()
		c.wire.pump(t)
		time.Sleep(time.Millisecond)
	}
	for node := uint64(1); node <= 3; node++ {
		if got := c.rev(node); got != 2 {
			t.Fatalf("node %d is at revision %d, want 2", node, got)
		}
		history := c.machines[node-1].history()
		if len(history) != 2 || history[0].Books["book"] != "one" || history[1].Books["book"] != "two" {
			t.Fatalf("node %d applied %v, want exactly revisions 1 and 2 as the acknowledged commands made them", node, history)
		}
	}
}

// barrierNoTraces checks that no member holds any of the commands in its tables: none was committed, and none that
// reached a log was left there.
func barrierNoTraces(t *testing.T, c *barrierCluster, commands map[string]Entry) {
	t.Helper()
	for node := uint64(1); node <= 3; node++ {
		for name, e := range commands {
			if inLog, completed := barrierTraces(c.wire.nodes[node], e.ID); inLog || completed {
				t.Fatalf("node %d holds the %s command that was never committed (in log %v, applied %v)", node, name, inLog, completed)
			}
		}
	}
}

// barrierClosed reports whether ch is closed.
func barrierClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// barrierDeliverUntil delivers queued messages one at a time until done, for at most 10 seconds; a quiet wire is waited on
// (the answer may be produced by a goroutine).
func barrierDeliverUntil(t *testing.T, w *testWire, what string, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			t.Fatalf("not within 10s: %s", what)
		}
		if !barrierDeliver(t, w) {
			time.Sleep(time.Millisecond)
		}
	}
}

// A proposal that arrives while a ReadIndex round is in flight is answered by the round after it. The round in
// flight may have been confirmed by a quorum before the proposal arrived, so a Validate that rested on it would be
// a verdict on state older than the proposal; the second round is put when the first is answered, after the arrival.
func TestBarrierProposalArrivingDuringAReadRoundWaitsForTheNextRound(t *testing.T) {
	c := newBarrierCluster(t)
	leader := c.wire.nodes[1]
	base := leader.phases.readRounds.Load()
	first := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("first")}
	second := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("second")}

	firstDone := barrierPropose(leader, first)
	await(t, 5*time.Second, "the first proposal puts a ReadIndex round to the leader", func() bool { return leader.phases.readRounds.Load() == base+1 })
	// The round is in flight: its heartbeats wait in the wire and nothing has answered them.
	secondDone := barrierPropose(leader, second)
	await(t, 5*time.Second, "the second proposal waits for the round after the one in flight", func() bool {
		_, waiting := barrierReads(leader)
		return waiting
	})
	if n := c.validationCount(); n != 0 {
		t.Fatalf("%d proposals were validated while the only ReadIndex round in flight was unanswered", n)
	}
	if rounds := leader.phases.readRounds.Load(); rounds != base+1 {
		t.Fatalf("%d rounds were put while the first was in flight: the second proposal must wait for it, not put its own", rounds-base)
	}

	// Deliver messages one at a time until the leader has the answer of the first round: that is the moment it
	// puts the next one.
	for leader.phases.readRounds.Load() == base+1 {
		if !barrierDeliver(t, c.wire) {
			t.Fatal("the wire went quiet before the first round was answered")
		}
	}
	await(t, 5*time.Second, "the first proposal is validated on the answer of its round", func() bool {
		_, ok := c.validated(first.ID)
		return ok
	})
	time.Sleep(150 * time.Millisecond)
	if _, ok := c.validated(second.ID); ok {
		t.Fatal("the second proposal was validated on the answer of a round that was already in flight when it arrived")
	}
	if inFlight, waiting := barrierReads(leader); inFlight != 1 || waiting {
		t.Fatalf("after the first round was answered %d rounds are in flight and a caller waits: %v, want the second round alone in flight", inFlight, waiting)
	}
	select {
	case r := <-secondDone:
		t.Fatalf("the second proposal returned (%v) before its own round was answered", r.err)
	default:
	}

	barrierSettle(t, c.wire, "both proposals commit", func() bool { return len(firstDone) == 1 && len(secondDone) == 1 })
	if r := <-firstDone; r.err != nil {
		t.Fatalf("first proposal: %v", r.err)
	}
	if r := <-secondDone; r.err != nil {
		t.Fatalf("second proposal: %v", r.err)
	}
	if v, _ := c.validated(first.ID); v.rounds < base+1 {
		t.Fatalf("the first proposal was validated with %d rounds put, before its own round", v.rounds-base)
	}
	if v, ok := c.validated(second.ID); !ok || v.rounds != base+2 {
		t.Fatalf("the second proposal was validated at %d rounds put, want 2: the round after the one in flight", v.rounds-base)
	}
	if rounds := leader.phases.readRounds.Load() - base; rounds != 2 {
		t.Fatalf("two proposals cost %d rounds, want 2", rounds)
	}
}

// Proposers that wait at the same time share one round: with one round in flight, the proposals that arrive meanwhile
// are all answered by the one round that follows it, so N concurrent proposals cost two rounds and not N.
func TestBarrierConcurrentProposersShareReadRounds(t *testing.T) {
	c := newBarrierCluster(t)
	leader := c.wire.nodes[1]
	base := leader.phases.readRounds.Load()
	const proposers = 32
	entries := make([]Entry, proposers)
	for i := range entries {
		entries[i] = Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("proposal %d", i))}
	}
	done := make([]<-chan barrierResult, proposers)
	done[0] = barrierPropose(leader, entries[0])
	await(t, 5*time.Second, "the first proposal puts a ReadIndex round to the leader", func() bool { return leader.phases.readRounds.Load() == base+1 })
	for i := 1; i < proposers; i++ {
		done[i] = barrierPropose(leader, entries[i])
	}
	await(t, 5*time.Second, "the other proposals wait for the round after the one in flight", func() bool {
		_, waiting := barrierReads(leader)
		return waiting
	})
	time.Sleep(200 * time.Millisecond) // the rest of them have joined it as well
	if n := c.validationCount(); n != 0 {
		t.Fatalf("%d proposals were validated while the only ReadIndex round in flight was unanswered", n)
	}
	if rounds := leader.phases.readRounds.Load(); rounds != base+1 {
		t.Fatalf("%d rounds were put while the first was in flight: the proposals that arrived meanwhile must wait for it", rounds-base)
	}

	for leader.phases.readRounds.Load() == base+1 {
		if !barrierDeliver(t, c.wire) {
			t.Fatal("the wire went quiet before the first round was answered")
		}
	}
	barrierSettle(t, c.wire, "every proposal commits", func() bool {
		for _, d := range done {
			if len(d) == 0 {
				return false
			}
		}
		return true
	})
	for i, d := range done {
		if r := <-d; r.err != nil {
			t.Fatalf("proposal %d: %v", i, r.err)
		}
		if _, ok := c.validated(entries[i].ID); !ok {
			t.Fatalf("proposal %d committed without a validation", i)
		}
	}
	if n := c.validationCount(); n != proposers {
		t.Fatalf("%d validations for %d proposals", n, proposers)
	}
	// Two rounds are expected; a proposer that was slow to arrive may cost one more, never one per proposal.
	if rounds := leader.phases.readRounds.Load() - base; rounds > 4 {
		t.Fatalf("%d concurrent proposals put %d ReadIndex rounds to the leader: proposers must share them", proposers, rounds)
	}
}

// A leader that was cut off from its quorum and deposed still believes it leads for up to an election timeout, and
// its applied state is behind the new leader's. A command made to it is neither validated against that state nor
// proposed: ReadIndex cannot be confirmed, so the proposal is refused with ErrNoQuorum. The one command that does
// reach its log (ProposeQueued takes no round: its caller made the read) is never committed, and when the partition
// heals it is overwritten: no member applies it, and the write the new leader acknowledged stays.
func TestBarrierADeposedLeaderNeitherValidatesNorProposesAndAppliesNothing(t *testing.T) {
	c := newBarrierCluster(t)
	old := c.wire.nodes[1]
	barrierFirstRevision(t, c)
	next, _ := barrierCutOff(t, c)
	before := old.Status()

	// Proposals to the deposed leader. The first is built on the state it still holds, so its head check passes on
	// that state; the second on the state the new leader acknowledged, which that head check would refuse.
	stale := wholeEntry(1, barrierBooks("stale"))
	fresh := wholeEntry(2, barrierBooks("fresh"))
	for _, tc := range []struct {
		name  string
		entry Entry
	}{{"a command built on the state the deposed leader holds", stale}, {"a command built on the state the new leader acknowledged", fresh}} {
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		_, err := old.Propose(ctx, tc.entry)
		cancel()
		if !errors.Is(err, ErrNoQuorum) {
			t.Fatalf("%s: the deposed leader answered %v, want ErrNoQuorum from its ReadIndex", tc.name, err)
		}
		if _, ok := c.validated(tc.entry.ID); ok {
			t.Fatalf("%s: validated by a leader whose ReadIndex was never confirmed", tc.name)
		}
		if inLog, _ := barrierTraces(old, tc.entry.ID); inLog {
			t.Fatalf("%s: proposed by a leader whose ReadIndex was never confirmed", tc.name)
		}
	}
	if got := old.Status(); got.LastIndex != before.LastIndex || got.Commit != before.Commit {
		t.Fatalf("the refused proposals moved the log of the deposed leader: last %d -> %d, commit %d -> %d", before.LastIndex, got.LastIndex, before.Commit, got.Commit)
	}

	// The command that skips the round reaches the log of the deposed leader and no further.
	queued := wholeEntry(1, barrierBooks("queued"))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	pending, err := old.ProposeQueued(ctx, queued)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pending.Wait(ctx); err == nil {
		t.Fatal("a command that no quorum took was acknowledged by the deposed leader")
	}
	cancel()
	if got := old.Status(); got.LastIndex <= before.LastIndex || got.Commit != before.Commit {
		t.Fatalf("the queued command should sit uncommitted in the deposed leader's log: last %d -> %d, commit %d -> %d", before.LastIndex, got.LastIndex, before.Commit, got.Commit)
	}

	// The partition heals: the new leader's log wins everywhere.
	barrierHeal(t, c, next)
	barrierNoTraces(t, c, map[string]Entry{"stale": stale, "fresh": fresh, "queued": queued})
}

// openBarrierSolo is a lone voter with a whole-state machine and, when validate is not nil, the Validate it makes for
// that machine.
func openBarrierSolo(t *testing.T, validate func(*wholeMachine) func(context.Context, Entry) error) (*Group, *wholeMachine) {
	t.Helper()
	id := model.NewID()
	machine := newWholeMachine(id)
	var check func(context.Context, Entry) error
	if validate != nil {
		check = validate(machine)
	}
	transport := NewLoopback()
	g, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(t.TempDir(), "raft"), Transport: transport, Members: soloMembers(), Machine: machine, Validate: check})
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { g.Close(); transport.Close() })
	if err = transport.Register(g); err == nil {
		err = g.Campaign()
	}
	if err != nil {
		t.Fatal(err)
	}
	return g, machine
}

// barrierHead is the head check of the control group's Validate against the revision machine has applied: the
// command must expect that revision and name the next application index. It counts its calls.
func barrierHead(machine *wholeMachine, calls *atomic.Int64) func(context.Context, Entry) error {
	return func(_ context.Context, e Entry) error {
		calls.Add(1)
		var cmd wholeCommand
		if err := json.Unmarshal(e.Payload, &cmd); err != nil {
			return ErrInvalid
		}
		if rev := machine.current().Rev; cmd.Expected != rev || e.ApplicationIndex != rev+1 {
			return ErrStale
		}
		return nil
	}
}

// barrierControl is a control command that expects revision expected and names the application index after it, as
// every command of the control group does.
func barrierControl(expected uint64, book string) Entry {
	e := wholeEntry(expected, map[string]string{"book": book})
	e.ApplicationIndex = expected + 1
	return e
}

func barrierCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// barrierState checks that the machine holds revision rev, made by the command that wrote book, through rev
// commands and no other.
func barrierState(t *testing.T, machine *wholeMachine, rev uint64, book string) {
	t.Helper()
	if got := machine.current(); got.Rev != rev || got.Books["book"] != book {
		t.Fatalf("the machine holds revision %d with book %q, want revision %d with %q", got.Rev, got.Books["book"], rev, book)
	}
	if n := uint64(len(machine.history())); n != rev {
		t.Fatalf("the machine installed %d states for revision %d: a stale command was applied", n, rev)
	}
}

// A command built on state that another command has since replaced is never applied. The head check of Validate
// refuses it; the queue refuses one that names an application index that is no longer the next, also when the
// command that took the index is in the same batch; and a command that names none and reaches the log anyway is
// answered ErrConflict by the apply of every voter, with the state untouched.
func TestBarrierStaleProposalIsRefusedAndNeverApplied(t *testing.T) {
	t.Run("the head check of Validate refuses it", func(t *testing.T) {
		var calls atomic.Int64
		g, machine := openBarrierSolo(t, func(m *wholeMachine) func(context.Context, Entry) error { return barrierHead(m, &calls) })
		if _, err := g.Propose(barrierCtx(t), barrierControl(0, "base")); err != nil {
			t.Fatal(err)
		}
		winner, loser := barrierControl(1, "winner"), barrierControl(1, "loser")
		receipt, err := g.Propose(barrierCtx(t), winner)
		if err != nil || receipt.ApplicationCursor.Index != 2 {
			t.Fatalf("the winner answered %v at %v, want application index 2", err, receipt.ApplicationCursor)
		}
		before := g.Status()
		if _, err = g.Propose(barrierCtx(t), loser); !errors.Is(err, ErrStale) || errors.Is(err, ErrNoQuorum) {
			t.Fatalf("a command built before the winner committed answered %v, want a plain ErrStale", err)
		}
		if got := calls.Load(); got != 3 {
			t.Fatalf("Validate ran %d times for three proposals", got)
		}
		if inLog, completed := barrierTraces(g, loser.ID); inLog || completed {
			t.Fatalf("the refused command is in the tables of the group (log %v, applied %v)", inLog, completed)
		}
		if got := g.Status(); got.LastIndex != before.LastIndex || got.ApplicationCursor != before.ApplicationCursor {
			t.Fatalf("the refused command moved the log: last %d -> %d, application %v -> %v", before.LastIndex, got.LastIndex, before.ApplicationCursor, got.ApplicationCursor)
		}
		barrierState(t, machine, 2, "winner")
	})

	t.Run("the queue refuses an application index that was taken in the same batch", func(t *testing.T) {
		g, machine := openBarrierSolo(t, nil)
		if _, err := g.Propose(barrierCtx(t), barrierControl(0, "base")); err != nil {
			t.Fatal(err)
		}
		// Both were built on revision 1 and name application index 2; both are queued before the cycle runs.
		winner, loser := barrierControl(1, "winner"), barrierControl(1, "loser")
		won := &proposal{ctx: barrierCtx(t), entry: winner, done: make(chan proposalResult, 1)}
		lost := &proposal{ctx: barrierCtx(t), entry: loser, done: make(chan proposalResult, 1)}
		if !g.enqueue(won) || !g.enqueue(lost) {
			t.Fatal("the group refused to queue")
		}
		if err := g.kick(); err != nil {
			t.Fatal(err)
		}
		receive := func(name string, p *proposal) proposalResult {
			t.Helper()
			select {
			case r := <-p.done:
				return r
			case <-time.After(10 * time.Second):
				t.Fatalf("the %s was never answered", name)
			}
			return proposalResult{}
		}
		wonResult, lostResult := receive("winner", won), receive("loser", lost)
		if wonResult.err != nil || wonResult.entry.ApplicationCursor.Index != 2 {
			t.Fatalf("the winner answered %v at %v, want application index 2", wonResult.err, wonResult.entry.ApplicationCursor)
		}
		if !errors.Is(lostResult.err, ErrStale) || errors.Is(lostResult.err, ErrNoQuorum) {
			t.Fatalf("the command built on the index the winner took answered %v, want a plain ErrStale", lostResult.err)
		}
		if inLog, completed := barrierTraces(g, loser.ID); inLog || completed {
			t.Fatalf("the refused command is in the tables of the group (log %v, applied %v)", inLog, completed)
		}
		barrierState(t, machine, 2, "winner")
		// The refusal consumed no application index: a command built on the winner takes the next one.
		next, err := g.Propose(barrierCtx(t), barrierControl(2, "next"))
		if err != nil || next.ApplicationCursor.Index != 3 {
			t.Fatalf("the command after the refusal answered %v at %v, want application index 3", err, next.ApplicationCursor)
		}
		barrierState(t, machine, 3, "next")
	})

	t.Run("apply answers ErrConflict and leaves the state", func(t *testing.T) {
		g, machine := openBarrierSolo(t, nil)
		if _, err := g.Propose(barrierCtx(t), wholeEntry(0, map[string]string{"book": "base"})); err != nil {
			t.Fatal(err)
		}
		if _, err := g.Propose(barrierCtx(t), wholeEntry(1, map[string]string{"book": "winner"})); err != nil {
			t.Fatal(err)
		}
		// No head check and no application index: nothing before the log refuses it, so the apply must.
		loser := wholeEntry(1, map[string]string{"book": "loser"})
		got, err := g.Propose(barrierCtx(t), loser)
		if !errors.Is(err, ErrConflict) || got.Outcome != "conflict" {
			t.Fatalf("a command built on revision 1 answered %v (outcome %q) after revision 2 was applied, want ErrConflict", err, got.Outcome)
		}
		barrierState(t, machine, 2, "winner")
		// The retry table keeps the verdict: the same command asked again is the same conflict, not a second apply.
		again, err := g.Propose(barrierCtx(t), loser)
		if !errors.Is(err, ErrConflict) || again.Index != got.Index {
			t.Fatalf("the retry answered %v at index %d, want ErrConflict at index %d", err, again.Index, got.Index)
		}
		barrierState(t, machine, 2, "winner")
	})
}
