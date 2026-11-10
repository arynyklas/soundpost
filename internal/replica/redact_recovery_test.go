// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"soundpost/internal/model"
)

// The journal is compacted onto a cut at the applied index A (it begins with a sealed snapshot
// record at A and retains entries from A+1). A command erased at exactly A (no write in between)
// has floor A: no retained entry is at or before the floor, but the sealed head record still
// carries the original payload, and so does the snapshot directory. Both must be reported.
func TestResidueReportsTheSealedJournalHeadWhenTheFloorIsTheCutIndex(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openSolo(t, dir, id, nil)
	a := s.putRow(redactCanaryA)
	s.snapshot() // cut at the applied index, nothing written after it
	if _, err := s.group.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	floor := s.group.Status().Applied
	if first, _ := s.group.JournalRange(); first <= floor {
		t.Fatalf("fixture invalid: the journal retains entries at or before the floor (first %d, floor %d)", first, floor)
	}
	s.machine.redact(a)
	if res, err := s.group.RedactCompleted(s.redactCtx(), requests(a)); err != nil || res.Redacted != 1 {
		t.Fatalf("redaction %+v %v", res, err)
	}
	if hits := hitsUnder(t, root, redactCanaryA); !hasFile(hits, "ready.wal") || !hasFile(hits, "envelope.json") {
		t.Fatalf("fixture invalid: the sealed head and the snapshot must still carry the payload: %v", hits)
	}
	residue, err := s.group.Residue(floor)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(residue, ","); got != ResidueJournal+","+ResidueSnapshots {
		t.Fatalf("Residue(%d) = %q: the sealed journal head at the cut is not reported", floor, got)
	}
	s.cleanCut("after the floor-at-cut redaction")
	if residue, err = s.group.Residue(floor); err != nil || len(residue) != 0 {
		t.Fatalf("residue after a newer cut: %v %v", residue, err)
	}
	if hits := hitsUnder(t, root, redactCanaryA); len(hits) != 0 {
		t.Fatalf("payload survives a newer cut in %v", hits)
	}
}

// retransient runs one redaction whose hook fails once, and proves the failure was recoverable:
// the group is still a working consensus participant, nothing is lost, and the same call, made
// again, converges to a replication layer without the payload.
func retransient(t *testing.T, hook string) {
	t.Helper()
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openSolo(t, dir, id, faultOnce(hook))
	keep := s.putRow("KEEPER-5a2c8f17b0e4")
	a, b := s.putRow(redactCanaryA), s.putRow(redactCanaryB)
	s.snapshot()
	if _, err := s.group.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := s.putRow(redactCanaryC)
	if _, err := s.group.PinJournal(0); err != nil { // a backup pin archive holds copies too
		t.Fatal(err)
	}
	targets := []redactRow{a, b, c}
	s.machine.redact(targets...)
	if _, err := s.group.RedactCompleted(s.redactCtx(), requests(targets...)); err == nil {
		t.Fatalf("hook %s did not fire", hook)
	}
	if s.group.Status().Failed {
		t.Fatalf("a transient error at %s, before anything was written, failed the group for good", hook)
	}
	// Still a working group: it accepts and answers proposals and still answers old retries.
	s.propose(Data, "after the transient error at "+hook)
	retriesStillAnswer(t, s, "after the transient error", keep, a, b, c)
	res, err := s.group.RedactCompleted(s.redactCtx(), requests(targets...))
	if err != nil || res.Redacted != 3 {
		t.Fatalf("the retry after a transient error at %s: %+v %v", hook, res, err)
	}
	s.cleanCut("after a transient error at " + hook)
	for _, r := range targets {
		if hits := hitsUnder(t, root, r.canary); len(hits) != 0 {
			t.Fatalf("%s survives a transient error at %s and a retry: %v", r.canary, hook, hits)
		}
	}
	retriesStillAnswer(t, s, "after the retry converged", keep, a, b, c)
}

// An error before the redaction wrote anything (or before it replaced the journal) is the
// caller's to retry: the whole operation is idempotent and re-derived from the stored redacted
// commands. It must not turn one worker pass into a dead consensus participant.
func TestRedactTransientErrorBeforeTheJournalSwitchLeavesTheGroupUsable(t *testing.T) {
	for _, hook := range []string{HookRedactBegin, HookRedactPins, HookRedactWrite, HookRedactSync, HookRedactSwitch} {
		t.Run(hook, func(t *testing.T) { retransient(t, hook) })
	}
}

// A real I/O error before the journal rename (the temp file cannot be cleared) is the same case.
func TestRedactIOErrorBeforeTheJournalSwitchLeavesTheGroupUsable(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openSolo(t, dir, id, nil)
	a := s.putRow(redactCanaryA)
	obstacle := filepath.Join(root, journalRedactTemp)
	if err := os.MkdirAll(filepath.Join(obstacle, "occupied"), 0700); err != nil {
		t.Fatal(err)
	}
	s.machine.redact(a)
	if _, err := s.group.RedactCompleted(s.redactCtx(), requests(a)); err == nil {
		t.Fatal("a temp path that cannot be cleared did not fail the redaction")
	}
	if s.group.Status().Failed {
		t.Fatal("an I/O error before the journal was touched failed the group for good")
	}
	s.propose(Data, "still accepting")
	if err := os.RemoveAll(obstacle); err != nil {
		t.Fatal(err)
	}
	if res, err := s.group.RedactCompleted(s.redactCtx(), requests(a)); err != nil || res.Redacted != 1 {
		t.Fatalf("retry %+v %v", res, err)
	}
	s.cleanCut("after the I/O error")
	if hits := hitsUnder(t, root, redactCanaryA); len(hits) != 0 {
		t.Fatalf("payload survives in %v", hits)
	}
}

// Once the journal was replaced (or the in-memory log partially swapped) the group's state may be
// torn: the open journal handle, the retained log and the retry table disagree. That still fails
// the group; a restart repairs it (TestRedactCompletedCrashPoints).
func TestRedactErrorAfterTheJournalSwitchFailsTheGroup(t *testing.T) {
	for _, hook := range []string{HookRedactRenamed, HookRedactMemory} {
		t.Run(hook, func(t *testing.T) {
			id := model.NewID()
			dir := t.TempDir()
			s := openSolo(t, dir, id, faultOnce(hook))
			a := s.putRow(redactCanaryA)
			s.machine.redact(a)
			if _, err := s.group.RedactCompleted(s.redactCtx(), requests(a)); err == nil {
				t.Fatalf("hook %s did not fire", hook)
			}
			if !s.group.Status().Failed {
				t.Fatalf("an error at %s, after the journal was replaced, left a possibly torn group in service", hook)
			}
			if _, err := s.tryPropose(Entry{ID: model.NewID(), Kind: Data, Payload: []byte("x")}); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("a failed group accepted a proposal: %v", err)
			}
		})
	}
}

// The in-memory copy of a committed command that the group keeps for the retained log is a copy
// of the payload too (never serialized, but the claim is that the bytes exist nowhere).
func TestRedactReplacesTheInMemoryLogCommandToo(t *testing.T) {
	id := model.NewID()
	s := openSolo(t, t.TempDir(), id, nil)
	a := s.putRow(redactCanaryA)
	s.machine.redact(a)
	g := s.group
	g.mu.Lock()
	before, ok := g.logCommands[a.entry.ID]
	g.mu.Unlock()
	if !ok || string(before.Entry.Payload) != string(a.entry.Payload) {
		t.Fatalf("fixture invalid: the retained-log copy is %+v (present %v)", before.Entry, ok)
	}
	if res, err := g.RedactCompleted(s.redactCtx(), requests(a)); err != nil || res.Redacted != 1 {
		t.Fatalf("redaction %+v %v", res, err)
	}
	g.mu.Lock()
	after := g.logCommands[a.entry.ID]
	g.mu.Unlock()
	if string(after.Entry.Payload) != string(a.replacement()) || after.Entry.Original == nil || *after.Entry.Original != model.HashCanonical(a.entry.Payload) {
		t.Fatalf("the retained-log copy still carries %q (original digest %v)", after.Entry.Payload, after.Entry.Original)
	}
}

// A learner added after a truncation is offered a snapshot cut at the applied index and cached
// until it is delivered. A redaction that happens while that offer is pinned must not leave the
// pre-redaction retry table in it: the next offer is built from the redacted state.
func TestRedactDiscardsTheSnapshotCachedForANewLearner(t *testing.T) {
	wire, id, machines := testCluster(t)
	leader := wire.nodes[1]
	secret := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("payload " + redactCanaryA)}
	acked, err := testPropose(t, wire, 1, secret)
	if err != nil {
		t.Fatal(err)
	}
	// The learner joins under a new id but never receives a message: the offer stays pinned.
	wire.block(4)
	learnerMembers := Members{Revision: 2, Nodes: append(append([]Member(nil), leader.Status().Members.Nodes...), Member{ID: 4, Address: "https://node4.invalid", FailureDomain: "disk-d", NodeIdentity: "node-4", Learner: true})}
	learner := &testMachine{rows: map[string]string{}}
	g4, err := Open(Config{ID: 4, Group: id, Directory: t.TempDir(), Members: learnerMembers, Machine: learner, Transport: wire})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { g4.Close() })
	wire.mu.Lock()
	wire.nodes[4] = g4
	wire.mu.Unlock()
	if err = testAwait(t, wire, func(ctx context.Context) error { return leader.ChangeMembers(ctx, 1, learnerMembers) }); err != nil {
		t.Fatal(err)
	}
	offer := func() []byte {
		t.Helper()
		leader.mu.Lock()
		defer leader.mu.Unlock()
		stored, serr := leader.memory.Snapshot()
		if serr != nil {
			t.Fatal(serr)
		}
		snap, serr := leader.membershipSnapshotLocked(stored)
		if serr != nil {
			t.Fatal(serr)
		}
		return snap.GetData()
	}
	if !deepHas(offer(), []byte(redactCanaryA), 6) {
		t.Fatal("fixture invalid: the pinned offer does not carry the payload")
	}
	leader.mu.Lock()
	pinned := leader.sendSnap != nil
	leader.mu.Unlock()
	if !pinned {
		t.Fatal("fixture invalid: no offer is pinned")
	}
	// The machine redacts its own copy first, as the storage engine does.
	replacement := []byte("redacted " + secret.ID.String())
	for _, m := range machines {
		m.mu.Lock()
		m.rows[secret.ID.String()] = string(replacement)
		m.mu.Unlock()
	}
	if res, rerr := leader.RedactCompleted(context.Background(), []Redaction{{ApplicationIndex: uint64(acked.ApplicationCursor.Index), Replacement: replacement}}); rerr != nil || res.Redacted != 1 {
		t.Fatalf("redaction %+v %v", res, rerr)
	}
	if deepHas(offer(), []byte(redactCanaryA), 6) {
		t.Fatal("the snapshot offered to a new learner after the redaction still carries the payload")
	}
}
