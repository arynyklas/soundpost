// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Task 10.13. A Control command carries the whole state of its machine, so a retry table that
// keeps every applied command's payload retains O(commands x state) bytes for as long as the
// group lives: measured on the control group, the retry table, the second decoded copy the log
// index keeps, and the snapshot envelope that serializes the retry table were 3.3x the sum of
// all payloads ever committed, and no snapshot cut or journal compaction released any of it.
// A machine that says so (DigestRetryMachine) gets a retry table that keeps what the retry
// contract needs instead: the receipt (term, index, application cursor, outcome) and the digest
// of the payload the command was proposed with, so a retry of a committed command is still
// answered with its original receipt and a different payload under the same ID is still a
// conflict.

// digestMachine is wholeMachine (the control machine's shape: every Control command carries the
// whole next state) with the retry table kept by digest.
type digestMachine struct{ *wholeMachine }

func (digestMachine) RetryByDigest(k Kind) bool { return k == Control }

type digestSolo struct {
	t         *testing.T
	dir       string
	id        model.ID
	machine   *wholeMachine
	transport *Loopback
	group     *Group
}

func openDigest(t *testing.T, dir string, id model.ID) *digestSolo {
	t.Helper()
	s := &digestSolo{t: t, dir: dir, id: id}
	s.open(newWholeMachine(id))
	t.Cleanup(s.stop)
	return s
}

func (s *digestSolo) open(machine *wholeMachine) {
	s.t.Helper()
	s.machine = machine
	s.transport = NewLoopback()
	group, err := Open(Config{ID: 1, Group: s.id, Directory: filepath.Join(s.dir, "raft"), Transport: s.transport, Members: soloMembers(), Machine: digestMachine{machine}})
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

func (s *digestSolo) stop() { s.group.Close(); s.transport.Close() }

func (s *digestSolo) reopen() {
	s.t.Helper()
	s.stop()
	s.open(newWholeMachine(s.id))
	if _, err := s.group.ReadIndex(s.ctx()); err != nil {
		s.t.Fatal(err)
	}
}

func (s *digestSolo) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	s.t.Cleanup(cancel)
	return ctx
}

func (s *digestSolo) propose(e Entry) (CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.group.Propose(ctx, e)
}

func (s *digestSolo) put(books map[string]string) wholeRow {
	s.t.Helper()
	e := wholeEntry(s.machine.current().Rev, books)
	c, err := s.propose(e)
	if err != nil {
		s.t.Fatal(err)
	}
	return wholeRow{entry: e, acked: c}
}

func (s *digestSolo) cut() Snapshot {
	s.t.Helper()
	snap, err := s.group.CreateSnapshot(s.ctx(), model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)})
	if err != nil {
		s.t.Fatal(err)
	}
	return snap
}

func (s *digestSolo) cutAndCompact() Snapshot {
	s.t.Helper()
	snap := s.cut()
	if _, err := s.group.CompactJournal(s.ctx()); err != nil {
		s.t.Fatal(err)
	}
	return snap
}

// retained is what the group keeps in memory for the commands it has applied: the payload bytes
// of its retry table and of the log index, and how many commands the retry table names.
func (s *digestSolo) retained() (payloadBytes, commands int) {
	g := s.group
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, c := range g.completed {
		payloadBytes += len(c.Entry.Payload)
		commands++
	}
	for _, c := range g.logCommands {
		payloadBytes += len(c.Entry.Payload)
	}
	return payloadBytes, commands
}

func envelopeSize(t *testing.T, snap Snapshot) int {
	t.Helper()
	for _, f := range snap.Manifest.Files {
		if f.Name == fileEnvelope {
			return int(f.Size)
		}
	}
	t.Fatal("snapshot has no envelope")
	return 0
}

// bigState is a state of about 9 KB; every command carries a different one, as a control command
// carries the whole next state.
func bigState(i int) map[string]string {
	books := map[string]string{}
	for k := range 64 {
		books[fmt.Sprintf("book-%02d", k)] = strings.Repeat(string(rune('a'+(i+k)%26)), 128)
	}
	return books
}

// requireOriginalReceipts retries every row: the answer is the receipt the command was
// acknowledged with, the digest of the payload it was proposed with is what recognizes it, and
// the same ID with a different payload is a conflict.
func requireOriginalReceipts(t *testing.T, s *digestSolo, label string, rows []wholeRow) {
	t.Helper()
	for i, r := range rows {
		retry, err := s.propose(r.entry)
		if err != nil {
			t.Fatalf("%s: retry %d: %v", label, i, err)
		}
		requireSameReceipt(t, fmt.Sprintf("%s: retry %d", label, i), r.acked, retry)
		if retry.Entry.Original == nil || *retry.Entry.Original != model.HashCanonical(r.entry.Payload) {
			t.Fatalf("%s: retry %d is not recognized by the digest of the payload it was proposed with: %+v", label, i, retry.Entry)
		}
		other := r.entry
		other.Payload = append([]byte(nil), r.entry.Payload...)
		other.Payload[len(other.Payload)-2] ^= 1
		if _, err = s.propose(other); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: retry %d with another payload under the same ID: %v, want ErrConflict", label, i, err)
		}
	}
}

// Retained bytes after N commits of a state of S bytes are a function of S and a per-command
// constant, not of N x S: the retry table and the log index hold no payload, and the envelope a
// snapshot cut serializes holds the state once plus a fixed-size record per command.
func TestDigestRetryRetainsNoPayloadAndKeepsTheOriginalReceipts(t *testing.T) {
	const commands = 40
	const perCommand = 1024 // receipt fields, digest and ids of one retry-table entry, with margin
	s := openDigest(t, t.TempDir(), model.NewID())
	rows := make([]wholeRow, 0, commands)
	for i := range commands {
		rows = append(rows, s.put(bigState(i)))
	}
	if bytes, n := s.retained(); n < commands || bytes != 0 {
		t.Fatalf("after %d commands the group retains %d payload bytes in %d retry-table commands: want 0 payload bytes", commands, bytes, n)
	}
	requireOriginalReceipts(t, s, "before a cut", rows)

	state, err := s.machine.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	payload := len(rows[0].entry.Payload)
	snap := s.cutAndCompact()
	size, bound := envelopeSize(t, snap), 2*len(state)+commands*perCommand+4096
	if size > bound {
		t.Fatalf("the snapshot envelope is %d bytes after %d commands of %d bytes each (state %d bytes): bound %d = 2 x state + %d x %d + 4096; a retry table that keeps payloads is %d",
			size, commands, payload, len(state), bound, commands, perCommand, commands*payload*4/3)
	}

	// A restart restores the retry table from the sealed envelope and replays the tail.
	tail := s.put(bigState(commands))
	s.reopen()
	if bytes, n := s.retained(); n < commands+1 || bytes != 0 {
		t.Fatalf("after a restart the group retains %d payload bytes in %d retry-table commands: want 0 payload bytes", bytes, n)
	}
	requireOriginalReceipts(t, s, "after a restart", append(rows, tail))
}

// The redaction pass has nothing to rewrite in a retry table that holds no payload, and must not
// write the replacement of a payload into it: the retry table stays payload-free, no copy of what
// the deletion covered is left anywhere once the cut and the compaction past the pass are done,
// and a retry of a redacted command still gets its receipt.
func TestDigestRetryRedactionLeavesTheRetryTablePayloadFree(t *testing.T) {
	dir := t.TempDir()
	s := openDigest(t, dir, model.NewID())
	root := filepath.Join(dir, "raft")
	var rows []wholeRow
	for _, canary := range []string{wholeCanaryA, wholeCanaryB, wholeCanaryC} {
		rows = append(rows, s.put(map[string]string{"keep": wholeKeep, "secret": canary}))
	}
	rows = append(rows, s.put(map[string]string{"keep": wholeKeep})) // the deletion committed
	if hits := hitsUnder(t, root, wholeCanaryA); !hasFile(hits, "ready.wal") {
		t.Fatalf("fixture invalid: the journal must carry A: %v", hits)
	}

	res, err := s.group.RedactMachineCommands(s.ctx(), 1, eraseSecret)
	if err != nil {
		t.Fatal(err)
	}
	if res.Redacted != 3 || res.Journal < 1 || res.Floor == 0 {
		t.Fatalf("pass result %+v: want the three commands that carried the secret counted (their copies in the log and the journal are rewritten, the table holds no payload to rewrite)", res)
	}
	if bytes, _ := s.retained(); bytes != 0 {
		t.Fatalf("the pass put %d payload bytes into the retry table or the log index", bytes)
	}
	s.put(map[string]string{"keep": "advance"})
	s.cut()
	if _, err = s.group.Snapshots().DropSuperseded(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.group.CompactJournal(s.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{wholeCanaryA, wholeCanaryB, wholeCanaryC} {
		if hits := hitsUnder(t, root, canary); len(hits) != 0 {
			t.Fatalf("%s is still held by %v", canary, hits)
		}
	}
	if left, err := s.group.Residue(res.Floor); err != nil || len(left) != 0 {
		t.Fatalf("Residue(floor) after the cut and the compaction: %v %v", left, err)
	}
	requireOriginalReceipts(t, s, "after redaction", rows)
}
