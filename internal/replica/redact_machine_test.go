// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"soundpost/internal/model"
)

const (
	wholeCanaryA = "WHOLE-A-5d1e8b3f7a20"
	wholeCanaryB = "WHOLE-B-9c2f40d8e617"
	wholeCanaryC = "WHOLE-C-17a6b3e9d054"
	wholeKeep    = "WHOLE-KEEP-c08b51e2a7f3"
	wholeData    = "WHOLE-DATA-4e7d90a1b3c6"
)

// wholeState / wholeCommand model the control machine: every Control command carries the whole
// next state and the revision it expects, a command whose expectation is stale is rejected.
type wholeState struct {
	Rev   uint64            `json:"rev,string"`
	Books map[string]string `json:"books"`
}
type wholeCommand struct {
	Expected uint64     `json:"expected,string"`
	State    wholeState `json:"state"`
}

func (s wholeState) has(book string) bool { _, ok := s.Books[book]; return ok }

type wholeMachine struct {
	mu      sync.Mutex
	group   model.ID
	applied uint64
	state   wholeState
	seen    []wholeState // every state Apply installed, in order
}

func newWholeMachine(group model.ID) *wholeMachine {
	return &wholeMachine{group: group, state: wholeState{Books: map[string]string{}}}
}
func (m *wholeMachine) Applied() uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.applied }
func (m *wholeMachine) Apply(c CommittedEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Index <= m.applied {
		return nil
	}
	m.applied = c.Index
	if c.Entry.Kind != Control {
		return nil
	}
	var cmd wholeCommand
	if err := json.Unmarshal(c.Entry.Payload, &cmd); err != nil || cmd.State.Rev != cmd.Expected+1 {
		return errors.New("machine: corrupt command")
	}
	if cmd.Expected != m.state.Rev {
		return ErrConflict
	}
	m.state = cmd.State
	m.seen = append(m.seen, cmd.State)
	return nil
}
func (m *wholeMachine) Snapshot() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.Marshal(m.state)
}
func (m *wholeMachine) Restore(raw []byte, index uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := json.Unmarshal(raw, &m.state); err != nil {
		return err
	}
	m.applied = index
	return nil
}
func (m *wholeMachine) DeletionLedger() (Ledger, error) {
	return Ledger{Version: 1, Group: m.group, Entries: []LedgerEntry{}}, nil
}
func (m *wholeMachine) current() wholeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	books := map[string]string{}
	for k, v := range m.state.Books {
		books[k] = v
	}
	return wholeState{Rev: m.state.Rev, Books: books}
}
func (m *wholeMachine) history() []wholeState {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.seen)
}

// eraseSecret is the machine's redaction: a command's "secret" book is what a committed deletion
// erased. It rejects anything that is not a control command, so a redaction handed a command of
// another kind fails loudly.
func eraseSecret(payload []byte) ([]byte, bool, error) {
	var cmd wholeCommand
	if err := json.Unmarshal(payload, &cmd); err != nil {
		return nil, false, err
	}
	if !cmd.State.has("secret") {
		return payload, false, nil
	}
	delete(cmd.State.Books, "secret")
	raw, err := json.Marshal(cmd)
	return raw, true, err
}

type wholeRow struct {
	entry Entry
	acked CommittedEntry
}

type wholeSolo struct {
	t         *testing.T
	dir       string
	id        model.ID
	machine   *wholeMachine
	transport *Loopback
	group     *Group
	fault     func(string) error
}

func openWhole(t *testing.T, dir string, id model.ID, fault func(string) error) *wholeSolo {
	t.Helper()
	s := &wholeSolo{t: t, dir: dir, id: id, fault: fault}
	s.open(newWholeMachine(id))
	t.Cleanup(s.stop)
	return s
}

func (s *wholeSolo) open(machine *wholeMachine) {
	s.t.Helper()
	s.machine = machine
	s.transport = NewLoopback()
	group, err := Open(Config{ID: 1, Group: s.id, Directory: filepath.Join(s.dir, "raft"), Transport: s.transport, Members: soloMembers(), Machine: machine, Fault: s.fault})
	if err != nil {
		s.transport.Close()
		s.t.Fatal(err)
	}
	s.group = group
	if err = s.transport.Register(group); err == nil {
		err = group.Campaign()
	}
	if err != nil {
		s.t.Fatal(err)
	}
}

func (s *wholeSolo) stop() { s.group.Close(); s.transport.Close() }

// reopen is a process restart on the same directory with a machine that starts from nothing and
// replays the journal.
func (s *wholeSolo) reopen(machine *wholeMachine) {
	s.t.Helper()
	s.stop()
	s.fault = nil
	s.open(machine)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := s.group.ReadIndex(ctx); err != nil {
		s.t.Fatal(err)
	}
}

func (s *wholeSolo) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.t.Cleanup(cancel)
	return ctx
}

func wholeEntry(expected uint64, books map[string]string) Entry {
	raw, err := json.Marshal(wholeCommand{Expected: expected, State: wholeState{Rev: expected + 1, Books: books}})
	if err != nil {
		panic(err)
	}
	return Entry{ID: model.NewID(), Kind: Control, Payload: raw}
}

// put commits one whole-state command on top of the machine's current revision.
func (s *wholeSolo) put(books map[string]string) wholeRow {
	s.t.Helper()
	e := wholeEntry(s.machine.current().Rev, books)
	c, err := s.propose(e)
	if err != nil {
		s.t.Fatal(err)
	}
	return wholeRow{entry: e, acked: c}
}

func (s *wholeSolo) propose(e Entry) (CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.group.Propose(ctx, e)
}

func (s *wholeSolo) cut() Snapshot {
	s.t.Helper()
	snap, err := s.group.CreateSnapshot(s.ctx(), model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)})
	if err != nil {
		s.t.Fatal(err)
	}
	return snap
}

func (s *wholeSolo) cutAndCompact() {
	s.t.Helper()
	s.cut()
	if _, err := s.group.CompactJournal(s.ctx()); err != nil {
		s.t.Fatal(err)
	}
}

// cleanCut is what the control driver does after a redaction: one command so the applied index
// is past the redaction, a snapshot cut after it, the superseded snapshots dropped, the journal
// compacted onto the new cut.
func (s *wholeSolo) cleanCut() {
	s.t.Helper()
	s.put(map[string]string{"keep": "advance"})
	s.cut()
	if _, err := s.group.Snapshots().DropSuperseded(); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.group.CompactJournal(s.ctx()); err != nil {
		s.t.Fatal(err)
	}
}

func (s *wholeSolo) pass(ruleSet uint64) MachineRedactResult {
	s.t.Helper()
	res, err := s.group.RedactMachineCommands(s.ctx(), ruleSet, eraseSecret)
	if err != nil {
		s.t.Fatal(err)
	}
	return res
}

func requireNoHits(t *testing.T, root, label string, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if hits := hitsUnder(t, root, c); len(hits) != 0 {
			t.Fatalf("%s: %s is still held by %v", label, c, hits)
		}
	}
}

func residueIs(t *testing.T, g *Group, ruleSet uint64, want ...string) {
	t.Helper()
	got, err := g.MachineResidue(ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("MachineResidue(%d) = %v, want %v", ruleSet, got, want)
	}
}

// Every control command carries the whole state, so every retained command of an erased state is
// a copy of it: the retry table, every journal entry, every snapshot envelope, the journal's
// sealed head and the backup pin archive. After the pass, a cut past it and the compaction onto
// it, none of them holds the payload; a retry of an old command still gets its receipt.
func TestRedactMachineCommandsRemovesThePayloadFromEveryReplicaCopy(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	a := s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	b := s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	s.cutAndCompact() // a and b are only in the snapshot now
	c := s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryC})
	if _, err := s.group.PinJournal(0); err != nil { // a backup in flight holds copies too
		t.Fatal(err)
	}
	dataEntry := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("data " + wholeData)}
	if _, err := s.propose(dataEntry); err != nil {
		t.Fatal(err)
	}
	s.put(map[string]string{"keep": wholeKeep}) // the deletion committed: the state no longer has the secret

	for _, canary := range []string{wholeCanaryA, wholeCanaryB, wholeCanaryC} {
		if hits := hitsUnder(t, root, canary); !hasFile(hits, "envelope.json") && !hasFile(hits, "ready.wal") {
			t.Fatalf("fixture invalid: %s is held by %v", canary, hits)
		}
	}
	if hits := hitsUnder(t, root, wholeCanaryA); !hasFile(hits, "envelope.json") || !hasFile(hits, "ready.wal") {
		t.Fatalf("fixture invalid: the sealed snapshot and the journal head must carry A: %v", hits)
	}
	if hits := hitsUnder(t, root, wholeCanaryC); !hasFile(hits, "ready.wal") || !hasFile(hits, s.pinName(t)) {
		t.Fatalf("fixture invalid: the journal tail and the pin archive must carry C: %v", hits)
	}
	residueIs(t, s.group, 1, ResidueMachineCommands, ResiduePins) // no pass has run, and the pin is live

	res := s.pass(1)
	if res.Redacted != 3 || res.Journal < 1 || res.Pins < 1 || res.Floor == 0 {
		t.Fatalf("pass result %+v: want the three commands in the retry table, the journal tail and the pin archive rewritten", res)
	}
	// The tail and the pin archive are clean at once; the sealed cut and the journal head are
	// not, and the group says so until a later cut replaces them.
	if hits := hitsUnder(t, root, wholeCanaryC); len(hits) != 0 {
		t.Fatalf("C survives the pass in %v", hits)
	}
	if hits := hitsUnder(t, root, wholeCanaryA); !hasFile(hits, "envelope.json") {
		t.Fatalf("fixture invalid: a sealed snapshot cannot have been rewritten: %v", hits)
	}
	residueIs(t, s.group, 1, ResidueJournal, ResidueSnapshots, ResiduePins)
	if left, err := s.group.Residue(res.Floor); err != nil || len(left) == 0 {
		t.Fatalf("Residue(floor) after the pass and before the cut: %v %v", left, err)
	}

	s.cleanCut()
	requireNoHits(t, root, "after the pass, the cut and the compaction", wholeCanaryA, wholeCanaryB, wholeCanaryC)
	if hits := hitsUnder(t, root, wholeKeep); !hasFile(hits, "ready.wal") || !hasFile(hits, "envelope.json") {
		t.Fatalf("the redaction took the payload no deletion covers: %v", hits)
	}
	if hits := hitsUnder(t, root, wholeData); len(hits) == 0 {
		t.Fatal("a command of another kind was rewritten")
	}
	if left, err := s.group.Residue(res.Floor); err != nil || len(left) != 0 {
		t.Fatalf("Residue(floor) after the cut: %v %v", left, err)
	}
	// The live pin still lets a backup in flight hold copies the node cannot vouch for.
	residueIs(t, s.group, 1, ResiduePins)
	pins, err := s.group.Pins()
	if err != nil || len(pins) != 1 {
		t.Fatalf("pins %v %v", pins, err)
	}
	if err = s.group.DropPin(pins[0].ID); err != nil {
		t.Fatal(err)
	}
	residueIs(t, s.group, 1)
	// A later rule set has not been covered by the pass.
	residueIs(t, s.group, 2, ResidueMachineCommands)

	// The retry still answers with the original receipt; a different payload is still a conflict.
	for name, r := range map[string]wholeRow{"a": a, "b": b, "c": c} {
		retry, err := s.propose(r.entry)
		if err != nil || retry.Index != r.acked.Index || retry.Term != r.acked.Term || retry.Entry.ID != r.entry.ID || retry.Entry.Kind != Control {
			t.Fatalf("retry of %s: %+v %v, original %+v", name, retry, err, r.acked)
		}
		other := r.entry
		other.Payload = []byte(`{"expected":"1","state":{"rev":"2","books":{}}}`)
		if _, err = s.propose(other); !errors.Is(err, ErrConflict) {
			t.Fatalf("a different payload under the id of %s: %v", name, err)
		}
	}
	if retry, err := s.propose(dataEntry); err != nil || retry.Entry.Kind != Data {
		t.Fatalf("retry of the data command: %v", err)
	}
}

func (s *wholeSolo) pinName(t *testing.T) string {
	t.Helper()
	var name string
	err := filepath.WalkDir(filepath.Join(s.dir, "raft"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(p) == ".pin" {
			name = filepath.Base(p)
		}
		return err
	})
	if err != nil || name == "" {
		t.Fatalf("no pin archive: %v", err)
	}
	return name
}

// A machine that replays the journal after a restart must reach the state it would have reached:
// each command carries the whole next state, so the redacted older commands are superseded by
// the newer ones and the last command, which establishes the current state, is never changed by
// the redaction (it only removes what the state no longer has).
func TestRedactedJournalReplaysToTheSameState(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB, "more": "x"})
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryC})
	last := s.put(map[string]string{"keep": wholeKeep, "more": "y"})
	want := s.machine.current()
	if want.has("secret") {
		t.Fatal("fixture invalid")
	}
	before := s.machine.history()
	if len(before) != 4 || !before[2].has("secret") {
		t.Fatalf("fixture invalid: %+v", before)
	}
	res := s.pass(1)
	if res.Redacted != 3 {
		t.Fatalf("the last command, the one that establishes the current state, must be left as it is: redacted %d of 4 commands, want 3", res.Redacted)
	}
	requireNoHits(t, root, "the redacted journal", wholeCanaryA, wholeCanaryB, wholeCanaryC)

	// A restart with a machine that has applied nothing replays every redacted entry.
	replay := newWholeMachine(id)
	s.reopen(replay)
	if got := replay.current(); got.Rev != want.Rev || !mapsEqual(got.Books, want.Books) {
		t.Fatalf("the replay of the redacted journal reached %+v, want %+v", got, want)
	}
	seen := replay.history()
	if len(seen) != 4 {
		t.Fatalf("the replay applied %d commands, want 4", len(seen))
	}
	for i, st := range seen {
		if st.has("secret") {
			t.Fatalf("replayed state %d still carries the secret: %+v", i+1, st)
		}
		if st.Rev != uint64(i+1) || st.Books["keep"] != wholeKeep {
			t.Fatalf("replayed state %d lost what no deletion covers: %+v", i+1, st)
		}
	}
	if !mapsEqual(seen[1].Books, map[string]string{"keep": wholeKeep, "more": "x"}) {
		t.Fatalf("a redacted command lost more than the covered payload: %+v", seen[1])
	}
	// A restart with the machine that kept its state (applied through the end) does not replay
	// and keeps answering the original receipts.
	s.reopen(replay)
	if retry, err := s.propose(last.entry); err != nil || retry.Index != last.acked.Index {
		t.Fatalf("the retry of the last command after the restart: %+v %v", retry, err)
	}
	// And the group keeps taking commands on top of the replayed state.
	s.put(map[string]string{"keep": wholeKeep, "more": "z"})
	s.cleanCut()
	requireNoHits(t, root, "after a cut", wholeCanaryA, wholeCanaryB, wholeCanaryC)
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// The pass is idempotent: a second call rewrites nothing and does not touch the files.
func TestRedactMachineCommandsIsIdempotent(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	first := s.pass(1)
	if first.Redacted != 1 || first.Journal < 1 {
		t.Fatalf("first pass %+v", first)
	}
	journal := filepath.Join(dir, "raft", "ready.wal")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	second := s.pass(1)
	if second.Redacted != 0 || second.Journal != 0 || second.Pins != 0 {
		t.Fatalf("second pass %+v changed something", second)
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a pass with nothing to redact rewrote the journal: %v", err)
	}
}

// A pass that is refused or that fails before anything was written changes nothing and the group
// keeps working: the machine's function failing, an empty replacement, a rule set of zero.
func TestRedactMachineCommandsRefusesBadRequestsWithoutWriting(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	journal := filepath.Join(dir, "raft", "ready.wal")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("machine cannot redact")
	for name, c := range map[string]struct {
		rules  uint64
		redact MachineRedaction
		want   error
	}{
		"machine error":     {1, func([]byte) ([]byte, bool, error) { return nil, false, boom }, boom},
		"empty replacement": {1, func(p []byte) ([]byte, bool, error) { return nil, true, nil }, ErrInvalid},
		"zero rule set":     {0, eraseSecret, ErrInvalid},
		"no function":       {1, nil, ErrInvalid},
	} {
		if _, err := s.group.RedactMachineCommands(s.ctx(), c.rules, c.redact); !errors.Is(err, c.want) {
			t.Fatalf("%s: %v, want %v", name, err, c.want)
		}
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a refused pass rewrote the journal: %v", err)
	}
	if s.group.Status().Failed {
		t.Fatal("a refused pass failed the group")
	}
	residueIs(t, s.group, 1, ResidueMachineCommands)
	if res := s.pass(1); res.Redacted != 1 {
		t.Fatalf("the pass after the refusals: %+v", res)
	}
}

// An error before the journal was replaced leaves the group in service and the same call
// converges; after the rename the group fails until a restart and the call is repeated.
func TestRedactMachineCommandsCrashPoints(t *testing.T) {
	setup := func(t *testing.T, hook string) (*wholeSolo, string) {
		id := model.NewID()
		dir := t.TempDir()
		s := openWhole(t, dir, id, faultOnce(hook))
		s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
		s.cutAndCompact()
		s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryC})
		if _, err := s.group.PinJournal(0); err != nil {
			t.Fatal(err)
		}
		s.put(map[string]string{"keep": wholeKeep})
		return s, filepath.Join(dir, "raft")
	}
	for _, hook := range []string{HookRedactBegin, HookRedactPins, HookRedactWrite, HookRedactSync, HookRedactSwitch} {
		t.Run(hook, func(t *testing.T) {
			s, root := setup(t, hook)
			if _, err := s.group.RedactMachineCommands(s.ctx(), 1, eraseSecret); err == nil {
				t.Fatalf("hook %s did not fire", hook)
			}
			if s.group.Status().Failed {
				t.Fatalf("a transient error at %s, before the journal was replaced, failed the group", hook)
			}
			s.put(map[string]string{"keep": wholeKeep, "after": hook})
			if res := s.pass(1); res.Redacted != 2 {
				t.Fatalf("the repeated call after %s: %+v", hook, res)
			}
			s.cleanCut()
			requireNoHits(t, root, "after "+hook, wholeCanaryA, wholeCanaryC)
		})
	}
	for _, hook := range []string{HookRedactRenamed, HookRedactMemory} {
		t.Run(hook, func(t *testing.T) {
			s, root := setup(t, hook)
			if _, err := s.group.RedactMachineCommands(s.ctx(), 1, eraseSecret); err == nil {
				t.Fatalf("hook %s did not fire", hook)
			}
			if !s.group.Status().Failed {
				t.Fatalf("an error at %s, after the journal was replaced, left a possibly torn group in service", hook)
			}
			if _, err := s.group.MachineResidue(1); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("a failed group reported a residue: %v", err)
			}
			// A restart rebuilds the group from the journal; the caller repeats the call.
			s.reopen(newWholeMachine(s.id))
			s.pass(1)
			s.cleanCut()
			requireNoHits(t, root, "after the restart that repaired "+hook, wholeCanaryA, wholeCanaryC)
		})
	}
}

// A restart rebuilds the retry table from the selected snapshot, which is older than the pass:
// the next pass redacts it again and does not trip over the copies that are already redacted.
func TestRedactMachineCommandsAfterARestartConvergesWithoutAConflict(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	s.cut() // sealed, holds A and B in its retry table
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryC})
	s.put(map[string]string{"keep": wholeKeep})
	if res := s.pass(1); res.Redacted != 3 {
		t.Fatalf("first pass %+v", res)
	}
	s.reopen(newWholeMachine(id))
	residueIs(t, s.group, 1, ResidueMachineCommands) // the proof does not survive a restart
	if res := s.pass(1); res.Floor == 0 {
		t.Fatalf("second pass %+v", res)
	}
	s.cleanCut()
	requireNoHits(t, root, "after the restart and a second pass", wholeCanaryA, wholeCanaryB, wholeCanaryC)
	residueIs(t, s.group, 1)
}

// The proof is for the commands that were retained when the pass ran. A command that was
// rejected as stale and committed afterwards still carries the state it was built from, so
// the proof is withdrawn until the next pass.
func TestAStaleCommandAfterThePassWithdrawsTheProof(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	stale := wholeEntry(s.machine.current().Rev, map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	s.put(map[string]string{"keep": wholeKeep}) // the deletion committed
	s.pass(1)
	s.cleanCut()
	residueIs(t, s.group, 1)
	if _, err := s.propose(stale); !errors.Is(err, ErrConflict) {
		t.Fatalf("the stale command was not rejected: %v", err)
	}
	if hits := hitsUnder(t, root, wholeCanaryB); !hasFile(hits, "ready.wal") {
		t.Fatalf("fixture invalid: the rejected command is not in the journal: %v", hits)
	}
	residueIs(t, s.group, 1, ResidueMachineCommands)
	s.pass(1)
	s.cleanCut()
	requireNoHits(t, root, "after the second pass", wholeCanaryA, wholeCanaryB)
	residueIs(t, s.group, 1)
	if got := s.machine.current(); got.has("secret") || got.Books["keep"] != "advance" {
		t.Fatalf("the rejected command changed the state: %+v", got)
	}
}

type wholeVoters struct {
	t        *testing.T
	wire     *testWire
	id       model.ID
	machines map[uint64]*wholeMachine
	dirs     map[uint64]string
}

func newWholeVoters(t *testing.T) *wholeVoters {
	t.Helper()
	v := &wholeVoters{t: t, id: model.NewID(), wire: &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}, machines: map[uint64]*wholeMachine{}, dirs: map[uint64]string{}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	for node := uint64(1); node <= 3; node++ {
		v.dirs[node] = t.TempDir()
		v.machines[node] = newWholeMachine(v.id)
		g, err := Open(Config{ID: node, Group: v.id, Directory: v.dirs[node], Members: members, Machine: v.machines[node], Transport: v.wire})
		if err != nil {
			t.Fatal(err)
		}
		v.wire.nodes[node] = g
		t.Cleanup(func() { g.Close() })
	}
	if err := v.wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	v.wire.pump(t)
	return v
}

func (v *wholeVoters) put(books map[string]string) {
	v.t.Helper()
	if _, err := testPropose(v.t, v.wire, 1, wholeEntry(v.machines[1].current().Rev, books)); err != nil {
		v.t.Fatal(err)
	}
}

func (v *wholeVoters) pass(node, ruleSet uint64) MachineRedactResult {
	v.t.Helper()
	res, err := v.wire.nodes[node].RedactMachineCommands(context.Background(), ruleSet, eraseSecret)
	if err != nil {
		v.t.Fatal(err)
	}
	return res
}

func (v *wholeVoters) catchUp(node uint64) {
	v.t.Helper()
	v.wire.mu.Lock()
	delete(v.wire.blocked, node)
	v.wire.mu.Unlock()
	for range 1500 {
		v.wire.nodes[1].Tick()
		v.wire.pump(v.t)
		if v.machines[node].current().Rev == v.machines[1].current().Rev {
			return
		}
		time.Sleep(time.Millisecond)
	}
	v.t.Fatalf("voter %d did not catch up: %+v vs %+v", node, v.machines[node].current(), v.machines[1].current())
}

// A voter redacts only its own copy. The leader's pass makes the log it sends redacted, so a
// voter that was behind receives the redacted commands and never stores the original of the
// ones it had not yet received; it replays them to the same state. A voter that has not run the
// pass still holds, and still names, what it was sent before.
func TestRedactMachineCommandsLeavesALaggingVoterWithoutTheOriginals(t *testing.T) {
	v := newWholeVoters(t)
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA}) // on all three voters
	v.wire.block(3)
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryC})
	v.put(map[string]string{"keep": wholeKeep, "after": "deletion"}) // the deletion committed
	want := v.machines[1].current()
	if hits := hitsUnder(t, v.dirs[3], wholeCanaryB); len(hits) != 0 {
		t.Fatalf("fixture invalid: the voter that was cut off holds B: %v", hits)
	}
	if hits := hitsUnder(t, v.dirs[3], wholeCanaryA); !hasFile(hits, "ready.wal") {
		t.Fatalf("fixture invalid: the cut-off voter must hold A from before: %v", hits)
	}
	for _, node := range []uint64{1, 2} {
		if hits := hitsUnder(t, v.dirs[node], wholeCanaryC); !hasFile(hits, "ready.wal") {
			t.Fatalf("fixture invalid: voter %d lacks C: %v", node, hits)
		}
	}

	v.pass(1, 1)
	requireNoHits(t, v.dirs[1], "the leader after its own pass", wholeCanaryA, wholeCanaryB, wholeCanaryC)
	v.catchUp(3)
	if got := v.machines[3].current(); got.Rev != want.Rev || !mapsEqual(got.Books, want.Books) {
		t.Fatalf("the voter that replayed the redacted log reached %+v, want %+v", got, want)
	}
	for i, st := range v.machines[3].history() {
		// State 0 is A, which this voter received as an original before any pass ran.
		if i > 0 && st.has("secret") {
			t.Fatalf("the voter replayed state %d with the secret in it", i)
		}
	}
	requireNoHits(t, v.dirs[3], "the voter that was behind, never sent the originals", wholeCanaryB, wholeCanaryC)
	if hits := hitsUnder(t, v.dirs[3], wholeCanaryA); !hasFile(hits, "ready.wal") {
		t.Fatalf("a voter's redaction is its own: voter 3 never ran the pass and must still hold A: %v", hits)
	}
	// What each voter says about itself.
	residueIs(t, v.wire.nodes[2], 1, ResidueMachineCommands)
	residueIs(t, v.wire.nodes[3], 1, ResidueMachineCommands)
	if hits := hitsUnder(t, v.dirs[2], wholeCanaryB); !hasFile(hits, "ready.wal") {
		t.Fatalf("voter 2 never ran the pass and must still hold B: %v", hits)
	}
	// The voters that did not run the pass do it themselves.
	v.pass(3, 1)
	v.pass(2, 1)
	for _, node := range []uint64{2, 3} {
		requireNoHits(t, v.dirs[node], "after its own pass", wholeCanaryA, wholeCanaryB, wholeCanaryC)
	}
	// The proof of one voter says nothing about another's: voter 1's stays its own.
	residueIs(t, v.wire.nodes[1], 1, ResidueJournal)
}

// An installed snapshot is the leader's retry table as it was cut: it may carry what this voter
// had already redacted, so the voter's proof is withdrawn.
func TestInstalledSnapshotWithdrawsTheProof(t *testing.T) {
	v := newWholeVoters(t)
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	v.wire.block(3)
	v.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	v.put(map[string]string{"keep": wholeKeep})
	v.pass(3, 1)
	if got := func() uint64 { g := v.wire.nodes[3]; g.mu.Lock(); defer g.mu.Unlock(); return g.machineRules }(); got != 1 {
		t.Fatalf("fixture invalid: voter 3's pass recorded rule set %d", got)
	}
	// The leader cuts and compacts past voter 3, which can only be repaired by a snapshot.
	leader := v.wire.nodes[1]
	if err := testAwait(t, v.wire, func(ctx context.Context) error {
		_, err := leader.CreateSnapshot(ctx, model.Cursor{Group: v.id, Index: leader.Status().ApplicationCursor.Index})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	v.put(map[string]string{"keep": wholeKeep, "after": "cut"})
	v.catchUp(3)
	residueIs(t, v.wire.nodes[3], 1, ResidueMachineCommands)
	if got := func() uint64 { g := v.wire.nodes[3]; g.mu.Lock(); defer g.mu.Unlock(); return g.machineRules }(); got != 0 {
		t.Fatalf("an installed snapshot left the proof at rule set %d", got)
	}
}
