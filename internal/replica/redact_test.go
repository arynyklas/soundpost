// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"soundpost/internal/model"
)

const (
	redactCanaryA = "CANARY-A-7c41e90d2b86"
	redactCanaryB = "CANARY-B-3e9a5f10c7d2"
	redactCanaryC = "CANARY-C-91b0d6a4e358"
)

var redactBase64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// deepHas looks for needle in data and in everything that decodes out of it: the journal wraps a
// command in base64 inside protobuf inside base64 inside JSON, so a plain search proves nothing.
func deepHas(data, needle []byte, depth int) bool {
	if bytes.Contains(data, needle) {
		return true
	}
	if depth == 0 {
		return false
	}
	for _, run := range redactBase64Run.FindAll(data, -1) {
		for skip := range 4 {
			if skip >= len(run) {
				break
			}
			for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
				text := bytes.TrimRight(run[skip:], "=")
				if len(text)%4 == 1 {
					text = text[:len(text)-1]
				}
				if decoded, err := enc.DecodeString(string(text)); err == nil && deepHas(decoded, needle, depth-1) {
					return true
				}
			}
		}
	}
	return false
}

// hitsUnder lists the files below root (journal, snapshots, pin archives, derived files) that hold
// canary in any nesting of encodings.
func hitsUnder(t *testing.T, root, canary string) []string {
	t.Helper()
	var hits []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if deepHas(raw, []byte(canary), 6) {
			rel, _ := filepath.Rel(root, p)
			hits = append(hits, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hits)
	return hits
}

func hasFile(hits []string, name string) bool {
	for _, h := range hits {
		if filepath.Base(h) == name {
			return true
		}
	}
	return false
}

// redactRow is one ACKed command: what was proposed and what the proposer was told.
type redactRow struct {
	entry  Entry
	acked  CommittedEntry
	canary string
}

func (s *solo) putRow(label string) redactRow {
	s.t.Helper()
	e := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("payload " + label)}
	c, err := s.tryPropose(e)
	if err != nil {
		s.t.Fatal(err)
	}
	return redactRow{entry: e, acked: c, canary: label}
}

// replacement is what a machine would accept in place of the payload: replayable, canary-free.
func (r redactRow) replacement() []byte { return []byte("redacted " + r.entry.ID.String()) }
func (r redactRow) request() Redaction {
	return Redaction{ApplicationIndex: uint64(r.acked.ApplicationCursor.Index), Replacement: r.replacement()}
}
func requests(rows ...redactRow) []Redaction {
	out := make([]Redaction, len(rows))
	for i, r := range rows {
		out[i] = r.request()
	}
	return out
}

// redact is what the storage machine does to its own stored command before the replica layer is
// asked to forget the same bytes.
func (m *ledgerMachine) redact(rows ...redactRow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		m.rows[r.entry.ID.String()] = string(r.replacement())
	}
}

func (s *solo) redactCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	s.t.Cleanup(cancel)
	return ctx
}

func requireSameReceipt(t *testing.T, label string, original, retry CommittedEntry) {
	t.Helper()
	if retry.Group != original.Group || retry.Term != original.Term || retry.Index != original.Index ||
		retry.ApplicationCursor != original.ApplicationCursor || retry.Outcome != original.Outcome ||
		retry.Entry.ID != original.Entry.ID || retry.Entry.Kind != original.Entry.Kind ||
		retry.Entry.ApplicationIndex != original.Entry.ApplicationIndex {
		t.Fatalf("%s: the retry did not return the original receipt:\n got  %+v\n want %+v", label, retry, original)
	}
}

// retriesStillAnswer proves the redaction took nothing a proposer relies on: every ACKed command
// still answers its retry with the original receipt, and a different payload under an old ID is
// still a conflict.
func retriesStillAnswer(t *testing.T, s *solo, label string, rows ...redactRow) {
	t.Helper()
	for _, r := range rows {
		retry, err := s.tryPropose(r.entry)
		if err != nil {
			t.Fatalf("%s: retry of %s: %v", label, r.canary, err)
		}
		requireSameReceipt(t, label+" "+r.canary, r.acked, retry)
		changed := r.entry
		changed.Payload = append([]byte("changed "), r.entry.Payload...)
		if _, err = s.tryPropose(changed); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: a different payload under the ID of %s: %v", label, r.canary, err)
		}
	}
}

// cleanCut is the maintenance that follows a redaction: advance the index (a snapshot at an index
// the group already has is the retained snapshot), cut, drop every older directory, truncate the
// journal onto the new cut.
func (s *solo) cleanCut(label string) {
	s.t.Helper()
	s.propose(Data, "advance "+label)
	s.snapshot()
	if _, err := s.group.Snapshots().DropSuperseded(); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.group.CompactJournal(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}

// The retry table that makes proposals idempotent keeps every committed command with its payload;
// it is written into every snapshot envelope and into the journal. Redaction must remove every
// copy of the payload from the replication layer while the retry keeps answering.
func TestRedactCompletedRemovesThePayloadFromEveryReplicaCopy(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openSolo(t, dir, id, nil)
	keep := s.putRow("KEEPER-5a2c8f17b0e4")
	a, b := s.putRow(redactCanaryA), s.putRow(redactCanaryB)
	s.snapshot()
	if _, err := s.group.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	c := s.putRow(redactCanaryC) // in the retained journal tail, beyond the snapshot
	for _, r := range []redactRow{a, b, c} {
		hits := hitsUnder(t, root, r.canary)
		if !hasFile(hits, "ready.wal") {
			t.Fatalf("fixture invalid: %s is not in the journal (%v)", r.canary, hits)
		}
	}
	for _, r := range []redactRow{a, b} {
		if hits := hitsUnder(t, root, r.canary); !hasFile(hits, "envelope.json") {
			t.Fatalf("fixture invalid: %s is not in the snapshot envelope (%v)", r.canary, hits)
		}
	}

	s.machine.redact(a, b, c)
	floor := s.group.Status().Applied
	res, err := s.group.RedactCompleted(s.redactCtx(), requests(a, b, c))
	if err != nil {
		t.Fatal(err)
	}
	if res.Redacted != 3 || res.Absent != 0 {
		t.Fatalf("result %+v", res)
	}

	// The retry table answers with the original receipt; the payload it holds is the replacement
	// and the digest of what was proposed.
	for _, r := range []redactRow{a, b, c} {
		retry, err := s.tryPropose(r.entry)
		if err != nil {
			t.Fatal(err)
		}
		requireSameReceipt(t, r.canary, r.acked, retry)
		if string(retry.Entry.Payload) != string(r.replacement()) || retry.Entry.Original == nil || *retry.Entry.Original != model.HashCanonical(r.entry.Payload) {
			t.Fatalf("%s: retry carries payload %q original %v", r.canary, retry.Entry.Payload, retry.Entry.Original)
		}
	}
	if retry, err := s.tryPropose(keep.entry); err != nil || string(retry.Entry.Payload) != string(keep.entry.Payload) || retry.Entry.Original != nil {
		t.Fatalf("an unredacted command changed: %+v %v", retry, err)
	}
	retriesStillAnswer(t, s, "after redaction", keep, a, b, c)

	// The retained journal tail is rewritten at once; the journal head and the snapshot directory
	// are sealed at an older cut and can only be replaced by a newer one, so they are reported.
	if hits := hitsUnder(t, root, redactCanaryC); len(hits) != 0 {
		t.Fatalf("the journal tail still carries a redacted payload: %v", hits)
	}
	residue, err := s.group.Residue(floor)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(residue, ",") != ResidueJournal+","+ResidueSnapshots {
		t.Fatalf("the sealed copies at the older cut are not reported: %v", residue)
	}
	for _, r := range []redactRow{a, b} {
		if hits := hitsUnder(t, root, r.canary); !hasFile(hits, "ready.wal") || !hasFile(hits, "envelope.json") {
			t.Fatalf("the older cut cannot have been rewritten in place: %s %v", r.canary, hits)
		}
	}

	s.cleanCut("after redaction")
	for _, r := range []redactRow{a, b, c} {
		if hits := hitsUnder(t, root, r.canary); len(hits) != 0 {
			t.Fatalf("%s survives in %v after a newer cut replaced the old one", r.canary, hits)
		}
	}
	if hits := hitsUnder(t, root, "KEEPER-5a2c8f17b0e4"); !hasFile(hits, "ready.wal") && !hasFile(hits, "envelope.json") {
		t.Fatalf("redaction removed a command that was not named: %v", hits)
	}
	if residue, err = s.group.Residue(floor); err != nil || len(residue) != 0 {
		t.Fatalf("residue after the cut: %v %v", residue, err)
	}
	retriesStillAnswer(t, s, "after the cut", keep, a, b, c)

	// A restart rebuilds the retry table from the new snapshot and the journal.
	s.close()
	re := openSolo(t, dir, id, nil)
	for _, r := range []redactRow{keep, a, b, c} {
		if _, ok := re.machine.rows[r.entry.ID.String()]; !ok {
			t.Fatalf("ACKed row %s lost on restart", r.canary)
		}
	}
	retriesStillAnswer(t, re, "after restart", keep, a, b, c)
	if hits := hitsUnder(t, root, redactCanaryA); len(hits) != 0 {
		t.Fatalf("a restart brought %s back: %v", redactCanaryA, hits)
	}
}

// Kill the process at every step of the redaction. No ACKed command is lost, a retry still returns
// the original receipt, and re-driving the same redaction (what the storage engine does on open)
// converges to a replication layer without the payload.
func TestRedactCompletedCrashPoints(t *testing.T) {
	hooks := []string{HookRedactBegin, HookRedactPins, HookRedactWrite, HookRedactSync, HookRedactSwitch, HookRedactRenamed, HookRedactMemory}
	for _, hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			id := model.NewID()
			dir := t.TempDir()
			root := filepath.Join(dir, "raft")
			s := openSolo(t, dir, id, nil)
			var kept []redactRow
			for i := range 3 {
				kept = append(kept, s.putRow(fmt.Sprintf("KEEP-%d-e1d09a", i)))
			}
			a, b := s.putRow(redactCanaryA), s.putRow(redactCanaryB)
			s.snapshot()
			if _, err := s.group.CompactJournal(context.Background()); err != nil {
				t.Fatal(err)
			}
			c := s.putRow(redactCanaryC)
			targets := []redactRow{a, b, c}
			all := append(append([]redactRow(nil), kept...), targets...)
			s.close()

			crashing := openSoloWith(t, dir, id, s.machine, faultOnce(hook))
			if _, err := crashing.group.PinJournal(0); err != nil { // a backup pin archive holds copies too
				t.Fatal(err)
			}
			crashing.machine.redact(targets...)
			if _, err := crashing.group.RedactCompleted(crashing.redactCtx(), requests(targets...)); err == nil {
				t.Fatalf("hook %s did not fire", hook)
			}
			crashing.close()

			fresh := openSolo(t, dir, id, nil)
			for _, r := range all {
				if _, ok := fresh.machine.rows[r.entry.ID.String()]; !ok {
					t.Fatalf("ACKed row %s lost after a crash at %s", r.canary, hook)
				}
			}
			retriesStillAnswer(t, fresh, "after the crash", all...)

			// Re-drive from durable state: the machine redacts its own copy again (its state is
			// rebuilt from the journal and the older snapshot), then the replica layer.
			fresh.machine.redact(targets...)
			if _, err := fresh.group.RedactCompleted(fresh.redactCtx(), requests(targets...)); err != nil {
				t.Fatalf("re-driving the redaction after a crash at %s: %v", hook, err)
			}
			fresh.cleanCut("after " + hook)
			for _, r := range targets {
				if hits := hitsUnder(t, root, r.canary); len(hits) != 0 {
					t.Fatalf("%s survives a crash at %s in %v", r.canary, hook, hits)
				}
			}
			retriesStillAnswer(t, fresh, "after convergence", all...)
		})
	}
}

// A request that cannot be honoured is refused whole: nothing is redacted, nothing is rewritten.
func TestRedactCompletedRefusesMalformedRequestsWithoutChangingAnything(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	data := s.putRow(redactCanaryA)
	barrier := s.propose(Barrier, "fence-payload")
	control := s.propose(Control, "control-payload")
	journal := filepath.Join(dir, "raft", "ready.wal")
	before, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	good := data.request()
	app := func(c CommittedEntry) uint64 { return uint64(c.ApplicationCursor.Index) }
	cases := map[string][]Redaction{
		"empty replacement":           {{ApplicationIndex: good.ApplicationIndex}},
		"oversized replacement":       {{ApplicationIndex: good.ApplicationIndex, Replacement: make([]byte, 16<<20+1)}},
		"application index zero":      {{ApplicationIndex: 0, Replacement: []byte("x")}},
		"duplicate application":       {good, {ApplicationIndex: good.ApplicationIndex, Replacement: []byte("other")}},
		"a barrier is never redacted": {{ApplicationIndex: app(barrier), Replacement: []byte("x")}},
		"control is never redacted":   {{ApplicationIndex: app(control), Replacement: []byte("x")}},
		"one valid and one refused":   {good, {ApplicationIndex: app(barrier), Replacement: []byte("x")}},
	}
	for name, request := range cases {
		if _, err := s.group.RedactCompleted(s.redactCtx(), request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	after, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a refused request rewrote the journal (%v)", err)
	}
	if retry, err := s.tryPropose(data.entry); err != nil || retry.Entry.Original != nil || string(retry.Entry.Payload) != string(data.entry.Payload) {
		t.Fatalf("a refused request redacted the command: %+v %v", retry, err)
	}
	// An application index this group holds no command for is not an error: the command may have
	// been redacted already or never reached this voter. It is counted so a caller can tell.
	res, err := s.group.RedactCompleted(s.redactCtx(), []Redaction{{ApplicationIndex: app(control) + 1000, Replacement: []byte("x")}})
	if err != nil || res.Redacted != 0 || res.Absent != 1 {
		t.Fatalf("absent index: %+v %v", res, err)
	}
	// Redaction is idempotent: the second call changes nothing and rewrites nothing.
	s.machine.redact(data)
	if res, err = s.group.RedactCompleted(s.redactCtx(), []Redaction{good}); err != nil || res.Redacted != 1 {
		t.Fatalf("first redaction: %+v %v", res, err)
	}
	once, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if res, err = s.group.RedactCompleted(s.redactCtx(), []Redaction{good}); err != nil || res.Redacted != 0 || res.Journal != 0 {
		t.Fatalf("second redaction: %+v %v", res, err)
	}
	twice, err := os.ReadFile(journal)
	if err != nil || !bytes.Equal(once, twice) {
		t.Fatalf("an idempotent redaction rewrote the journal (%v)", err)
	}
	// A further redaction of the same command replaces the replacement and keeps the digest of
	// what was proposed.
	if res, err = s.group.RedactCompleted(s.redactCtx(), []Redaction{{ApplicationIndex: good.ApplicationIndex, Replacement: []byte("narrower replacement")}}); err != nil || res.Redacted != 1 {
		t.Fatalf("second-level redaction: %+v %v", res, err)
	}
	retry, err := s.tryPropose(data.entry)
	if err != nil || string(retry.Entry.Payload) != "narrower replacement" || retry.Entry.Original == nil || *retry.Entry.Original != model.HashCanonical(data.entry.Payload) {
		t.Fatalf("second-level redaction lost the original digest: %+v %v", retry, err)
	}
}

// A voter that was behind when a command was redacted on its leader receives the redacted entry
// from the leader's log: it never stores the original payload, and its journal stays clean.
func TestRedactedCommandReachesALaggingFollowerRedacted(t *testing.T) {
	wire, _, machines := testCluster(t)
	wire.block(3)
	secret := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("payload " + redactCanaryA)}
	acked, err := testPropose(t, wire, 1, secret)
	if err != nil {
		t.Fatal(err)
	}
	replacement := []byte("redacted " + secret.ID.String())
	ctx := context.Background()
	leader := wire.nodes[1]
	if res, rerr := leader.RedactCompleted(ctx, []Redaction{{ApplicationIndex: uint64(acked.ApplicationCursor.Index), Replacement: replacement}}); rerr != nil || res.Redacted != 1 {
		t.Fatalf("leader redaction: %+v %v", res, rerr)
	}
	if hits := hitsUnder(t, leader.dir, redactCanaryA); len(hits) != 0 {
		t.Fatalf("the leader's journal still carries the payload: %v", hits)
	}
	wire.mu.Lock()
	delete(wire.blocked, 3)
	wire.mu.Unlock()
	var got string
	for range 400 {
		for _, id := range []uint64{1, 2, 3} {
			wire.nodes[id].Tick()
			wire.pump(t)
		}
		machines[2].mu.Lock()
		got = machines[2].rows[secret.ID.String()]
		machines[2].mu.Unlock()
		if got != "" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got != string(replacement) {
		t.Fatalf("the lagging voter applied %q, want the replacement", got)
	}
	if hits := hitsUnder(t, wire.nodes[3].dir, redactCanaryA); len(hits) != 0 {
		t.Fatalf("the lagging voter stored the original payload: %v", hits)
	}
	g := wire.nodes[3]
	g.mu.Lock()
	done := g.completed[secret.ID]
	g.mu.Unlock()
	if done.Entry.Original == nil || *done.Entry.Original != model.HashCanonical(secret.Payload) || done.Index != acked.Index {
		t.Fatalf("the voter's retry table does not recognize the original command: %+v", done)
	}
	// The voter that already held the original redacts its own copy with the same call.
	if res, rerr := wire.nodes[2].RedactCompleted(ctx, []Redaction{{ApplicationIndex: uint64(acked.ApplicationCursor.Index), Replacement: replacement}}); rerr != nil || res.Redacted != 1 {
		t.Fatalf("follower redaction: %+v %v", res, rerr)
	}
	if hits := hitsUnder(t, wire.nodes[2].dir, redactCanaryA); len(hits) != 0 {
		t.Fatalf("the follower's journal still carries the payload: %v", hits)
	}
}
