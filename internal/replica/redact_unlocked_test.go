// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
)

// IM-5(c): RedactCompleted does not hold the group lock while it rewrites the journal and the
// pin archives (a long rewrite would stop Propose and ReadIndex for the whole group, and a leader
// that cannot step loses its leadership). It plans under the lock, stages without it, and commits
// under it only when the group is exactly what the plan read.

// redactGate holds the redaction at one of its hooks: entered is closed when the pass reaches
// the hook (the first time), and the hook returns when release is closed.
type redactGate struct {
	at      string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	freed   sync.Once
}

func newRedactGate(t *testing.T, at string) *redactGate {
	g := &redactGate{at: at, entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(g.unblock) // a failed test must not leave the pass waiting
	return g
}

func (g *redactGate) unblock() { g.freed.Do(func() { close(g.release) }) }

func (g *redactGate) fault(at string) error {
	if at == g.at {
		g.once.Do(func() {
			close(g.entered)
			<-g.release
		})
	}
	return nil
}

func (g *redactGate) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatalf("the redaction never reached %s", g.at)
	}
}

type redactOutcome struct {
	res RedactResult
	err error
}

func (s *solo) redactAsync(requests []Redaction) <-chan redactOutcome {
	done := make(chan redactOutcome, 1)
	go func() {
		res, err := s.group.RedactCompleted(context.Background(), requests)
		done <- redactOutcome{res, err}
	}()
	return done
}

func awaitRedact(t *testing.T, done <-chan redactOutcome) RedactResult {
	t.Helper()
	select {
	case out := <-done:
		if out.err != nil {
			t.Fatalf("the redaction failed: %v", out.err)
		}
		return out.res
	case <-time.After(30 * time.Second):
		t.Fatal("the redaction did not finish")
		return RedactResult{}
	}
}

// While the redaction stages its copy of the journal, the group commits, answers ReadIndex and
// reports its status.
func TestRedactCompletedDoesNotHoldTheGroupLockWhileItRewrites(t *testing.T) {
	for _, at := range []string{HookRedactBegin, HookRedactPins, HookRedactWrite, HookRedactSync} {
		t.Run(at, func(t *testing.T) {
			gate := newRedactGate(t, at)
			id := model.NewID()
			dir := t.TempDir()
			root := filepath.Join(dir, "raft")
			s := openSolo(t, dir, id, gate.fault)
			s.putRow("KEEP-0b6f21d9a4c7")
			a := s.putRow(redactCanaryA)
			s.putRow("KEEP-1c7a32e0b5d8")
			if _, err := s.group.PinJournal(0); err != nil { // HookRedactPins fires only for a group with a pin
				t.Fatal(err)
			}
			s.machine.redact(a)
			done := s.redactAsync(requests(a))
			gate.awaitEntered(t)

			late := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("payload LATE-5d0e93a7c2f1")}
			errs := make(chan error, 2) // the probe may outlive a failed test: it must not use t
			ok := answersWithin(3*time.Second, func() {
				s.group.Status()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_, err := s.group.ReadIndex(ctx)
				errs <- err
				_, err = s.tryPropose(late)
				errs <- err
			})
			if !ok {
				gate.unblock()
				<-done
				t.Fatalf("the group did not answer Status, ReadIndex and Propose for 3 s at %s: the redaction holds the group lock across its file phase", at)
			}
			gate.unblock()
			for _, what := range []string{"ReadIndex", "Propose"} {
				if err := <-errs; err != nil {
					t.Fatalf("%s while the redaction stages its copy: %v", what, err)
				}
			}
			if res := awaitRedact(t, done); res.Redacted != 1 {
				t.Fatalf("the redaction: %+v", res)
			}
			if _, err := os.Stat(filepath.Join(root, journalRedactTemp)); !os.IsNotExist(err) {
				t.Fatalf("the temporary journal is still there: %v", err)
			}
			s.cleanCut("after " + at)
			requireNoHits(t, root, "after the redaction at "+at, redactCanaryA)
			s.close()
			re := openSolo(t, dir, id, nil)
			if _, ok := re.machine.rows[late.ID.String()]; !ok {
				t.Fatalf("the command committed while the redaction staged its copy is lost after a restart")
			}
		})
	}
}

// What changes while the redaction stages its copy decides whether the copy may be installed. A
// copy installed over a changed journal drops an acknowledged command, puts back a compacted
// journal or misses a pin archive that holds the payload; the redaction starts over instead.
func TestRedactCompletedStartsOverWhenTheGroupChangesWhileItStages(t *testing.T) {
	type event func(s *solo) (late []Entry, err error)
	events := map[string]event{
		"a command is committed": func(s *solo) ([]Entry, error) {
			e := Entry{ID: model.NewID(), Kind: Data, Payload: []byte("payload LATE-8a1c47e9d3b0")}
			_, err := s.tryPropose(e)
			return []Entry{e}, err
		},
		"the journal is cut and compacted": func(s *solo) ([]Entry, error) {
			ctx := context.Background()
			if _, err := s.group.CreateSnapshot(ctx, model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)}); err != nil {
				return nil, err
			}
			_, err := s.group.CompactJournal(ctx)
			return nil, err
		},
		"a backup pins the journal": func(s *solo) ([]Entry, error) {
			_, err := s.group.PinJournal(0)
			return nil, err
		},
	}
	for name, ev := range events {
		for _, pinned := range []bool{false, true} {
			name, ev, pinned := name, ev, pinned
			label := name
			if pinned {
				label += " while a pin is live"
			}
			t.Run(label, func(t *testing.T) {
				gate := newRedactGate(t, HookRedactSync)
				id := model.NewID()
				dir := t.TempDir()
				root := filepath.Join(dir, "raft")
				var begins int
				var leftover []string // staged copies of a discarded attempt still there when the next one begins
				s := openSolo(t, dir, id, func(at string) error {
					if at == HookRedactBegin {
						if begins++; begins >= 2 {
							entries, _ := os.ReadDir(filepath.Join(root, "pins"))
							for _, e := range entries {
								if strings.HasSuffix(e.Name(), ".tmp") {
									leftover = append(leftover, e.Name())
								}
							}
						}
					}
					return gate.fault(at)
				})
				keep := s.putRow("KEEP-2e8b43f1c6a9")
				a := s.putRow(redactCanaryA)
				tail := s.putRow(redactCanaryB)
				if pinned {
					if _, err := s.group.PinJournal(0); err != nil { // a pin archive holds the payloads too and is staged by the first attempt
						t.Fatal(err)
					}
				}
				s.machine.redact(a, tail)
				done := s.redactAsync(requests(a, tail))
				gate.awaitEntered(t)

				var late []Entry
				var eventErr error
				if !answersWithin(5*time.Second, func() { late, eventErr = ev(s) }) {
					gate.unblock()
					<-done
					t.Fatalf("%s: the group could not do it for 5 s while the redaction staged its copy", label)
				}
				if eventErr != nil {
					gate.unblock()
					<-done
					t.Fatalf("%s: %v", label, eventErr)
				}
				first, _ := s.group.JournalRange()
				gate.unblock()
				if res := awaitRedact(t, done); res.Redacted != 2 {
					t.Fatalf("%s: the redaction redacted %d commands, want 2: %+v", label, res.Redacted, res)
				}
				if got, _ := s.group.JournalRange(); got != first {
					t.Fatalf("%s: the retained log starts at %d after the redaction, at %d before it", label, got, first)
				}
				if begins < 2 {
					t.Fatalf("%s: the change was not seen: the redaction made %d attempt(s), want a second one", label, begins)
				}
				if len(leftover) != 0 {
					t.Fatalf("%s: a discarded attempt left %v behind", label, leftover)
				}
				if _, err := os.Stat(filepath.Join(root, journalRedactTemp)); !os.IsNotExist(err) {
					t.Fatalf("%s: a discarded staged journal is still there: %v", label, err)
				}
				pins, _ := os.ReadDir(filepath.Join(root, "pins"))
				for _, p := range pins {
					if strings.HasSuffix(p.Name(), ".tmp") {
						t.Fatalf("%s: a discarded staged pin archive is still there: %s", label, p.Name())
					}
					if raw, err := os.ReadFile(filepath.Join(root, "pins", p.Name())); err != nil || deepHas(raw, []byte(redactCanaryA), 0) || deepHas(raw, []byte(redactCanaryB), 0) {
						t.Fatalf("%s: pin archive %s still carries a redacted payload (%v)", label, p.Name(), err)
					}
				}
				s.cleanCut("after " + label)
				requireNoHits(t, root, "after "+label, redactCanaryA, redactCanaryB)
				s.close()
				re := openSolo(t, dir, id, nil)
				if got, _ := re.group.JournalRange(); got == 0 {
					t.Fatalf("%s: the reopened journal is empty", label)
				}
				for _, e := range append([]Entry{keep.entry, a.entry, tail.entry}, late...) {
					if _, ok := re.machine.rows[e.ID.String()]; !ok {
						t.Fatalf("%s: acknowledged command %s lost after a restart", label, e.ID)
					}
				}
			})
		}
	}
}

// A group that commits during every unlocked attempt still gets its redaction: the last attempt
// holds the lock, where nothing can change.
func TestRedactCompletedOverAGroupThatNeverStopsCommittingStillCompletes(t *testing.T) {
	var s *solo
	var begins int
	var lockHeld []int
	fault := func(at string) error {
		if at != HookRedactSync {
			return nil
		}
		begins++
		if begins > redactUnlockedAttempts {
			return nil // the locked attempt: nothing can be committed now
		}
		committed := make(chan struct{})
		go func() {
			_, _ = s.tryPropose(Entry{ID: model.NewID(), Kind: Data, Payload: []byte("payload busy")})
			close(committed)
		}()
		select {
		case <-committed:
		case <-time.After(3 * time.Second):
			lockHeld = append(lockHeld, begins)
		}
		return nil
	}
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s = openSolo(t, dir, id, fault)
	a := s.putRow(redactCanaryA)
	s.machine.redact(a)
	res, err := s.group.RedactCompleted(context.Background(), requests(a))
	if err != nil {
		t.Fatal(err)
	}
	if len(lockHeld) != 0 {
		t.Fatalf("a command could not be committed during attempt(s) %v: they ran under the group lock", lockHeld)
	}
	if begins != redactUnlockedAttempts+1 || res.Redacted != 1 {
		t.Fatalf("%d attempts (want %d unlocked ones that each lose a race and one locked one), result %+v", begins, redactUnlockedAttempts, res)
	}
	s.cleanCut("after the locked attempt")
	requireNoHits(t, root, "after the locked attempt", redactCanaryA)
}

// IM-5(b): a pin archives only the commands with an application index above its After, so a pin
// whose After is not below the highest application index of the commands to redact cannot hold
// one: it is not opened. A pin whose After is one below can, and is rewritten.

// corruptPinTail appends a record with a valid frame and a payload that is not a pin record: an
// archive that is opened and read to its end fails with ErrCorrupt, one that is not opened does not.
func corruptPinTail(t *testing.T, path string) []byte {
	t.Helper()
	payload := []byte("not a pin record")
	var h [8]byte
	binary.BigEndian.PutUint32(h[:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(h[4:], crc32.Checksum(payload, readyCRC))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = f.Write(append(h[:], payload...)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pinPath(t *testing.T, s *solo, p *JournalPin) string {
	t.Helper()
	return filepath.Join(s.dir, "raft", "pins", p.id.String()+".pin")
}

func TestRedactCompletedDoesNotOpenAPinThatCannotHoldTheCommand(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openSolo(t, dir, id, nil)
	x := s.putRow("KEEP-3f9c54a2d7b1")
	a := s.putRow(redactCanaryA)
	c := s.putRow("KEEP-4a0d65b3e8c2")
	target := uint64(a.acked.ApplicationCursor.Index)
	if uint64(x.acked.ApplicationCursor.Index)+1 != target {
		t.Fatalf("fixture: application indexes %d, %d are not adjacent", x.acked.ApplicationCursor.Index, target)
	}
	below, err := s.group.PinJournal(target - 1) // archives a and c
	if err != nil {
		t.Fatal(err)
	}
	equal, err := s.group.PinJournal(target) // archives c only: exactly the boundary
	if err != nil {
		t.Fatal(err)
	}
	above, err := s.group.PinJournal(uint64(c.acked.ApplicationCursor.Index)) // archives nothing
	if err != nil {
		t.Fatal(err)
	}
	if hits := hitsUnder(t, filepath.Dir(pinPath(t, s, below)), redactCanaryA); !hasFile(hits, below.id.String()+".pin") || hasFile(hits, equal.id.String()+".pin") || hasFile(hits, above.id.String()+".pin") {
		t.Fatalf("fixture: only the pin below the command holds it, got %v", hits)
	}
	equalBytes := corruptPinTail(t, pinPath(t, s, equal))
	aboveBytes := corruptPinTail(t, pinPath(t, s, above))

	s.machine.redact(a)
	res, err := s.group.RedactCompleted(context.Background(), requests(a))
	if err != nil {
		t.Fatalf("the redaction opened a pin that cannot hold the command: %v", err)
	}
	if res.Redacted != 1 || res.PinsSkipped != 2 || res.Pins != 1 {
		t.Fatalf("result %+v, want one command redacted, one pin entry rewritten, two pins skipped", res)
	}
	if hits := hitsUnder(t, filepath.Join(root, "pins"), redactCanaryA); len(hits) != 0 {
		t.Fatalf("the pin below the command still holds it: %v", hits)
	}
	for name, want := range map[string][]byte{equal.id.String(): equalBytes, above.id.String(): aboveBytes} {
		if got, err := os.ReadFile(filepath.Join(root, "pins", name+".pin")); err != nil || string(got) != string(want) {
			t.Fatalf("a skipped pin changed (%v)", err)
		}
	}
}

// The same watermark bounds the search for a command the retry table forgot: a pin whose After
// is not below the requested application index is not read to look for it.
func TestRedactCompletedDoesNotSearchAPinThatCannotHoldTheRequestedIndex(t *testing.T) {
	const missing = 9999
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	s.putRow("KEEP-5b1e76c4f9d3")
	boundary, err := s.group.PinJournal(missing)
	if err != nil {
		t.Fatal(err)
	}
	corruptPinTail(t, pinPath(t, s, boundary))
	request := []Redaction{{ApplicationIndex: missing, Replacement: []byte("redacted")}}
	res, err := s.group.RedactCompleted(context.Background(), request)
	if err != nil {
		t.Fatalf("the redaction read a pin that cannot hold application index %d: %v", missing, err)
	}
	if res.Absent != 1 || res.PinsSkipped != 1 {
		t.Fatalf("result %+v, want the index absent and the pin skipped", res)
	}
	below, err := s.group.PinJournal(missing - 1) // can hold it
	if err != nil {
		t.Fatal(err)
	}
	corruptPinTail(t, pinPath(t, s, below))
	if _, err = s.group.RedactCompleted(context.Background(), request); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a pin one below the requested index was not read: %v", err)
	}
}

// A command the retry table forgot is found by application index in the retained log and in the
// pins, and the pin that holds a copy is still rewritten: the watermark skip is only for a command
// the table holds (a copy of a forgotten ID may carry another application index).
func TestRedactCompletedStillReachesAPinArchivedCopyOfAForgottenCommand(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openSolo(t, dir, id, nil)
	s.putRow("KEEP-6c2f87d5a0e4")
	a := s.putRow(redactCanaryA)
	s.putRow("KEEP-7d30980b6f1a5")
	if _, err := s.group.PinJournal(0); err != nil {
		t.Fatal(err)
	}
	s.group.mu.Lock()
	delete(s.group.completed, a.entry.ID) // the table has forgotten the command
	s.group.mu.Unlock()
	s.machine.redact(a)
	res, err := s.group.RedactCompleted(context.Background(), requests(a))
	if err != nil {
		t.Fatal(err)
	}
	if res.Absent != 0 || res.PinsSkipped != 0 || res.Pins != 1 {
		t.Fatalf("result %+v", res)
	}
	if hits := hitsUnder(t, filepath.Join(root, "pins"), redactCanaryA); len(hits) != 0 {
		t.Fatalf("the pin still holds the forgotten command: %v", hits)
	}
}

// The bound that lets a pin be skipped is the highest application index of every copy of every
// target the group knows. A copy in the retained log or in the log index with a higher application
// index than the table's raises it; a target with no known bound unbounds all.
func TestRedactPinBoundCoversEveryKnownCopyOfATarget(t *testing.T) {
	id := model.NewID()
	entry := func(index, application uint64) *pb.Entry {
		raw, err := encodeEntry(Entry{ID: id, Kind: Data, Payload: []byte("payload"), ApplicationIndex: application})
		if err != nil {
			t.Fatal(err)
		}
		return rawEntry(index, 1, raw)
	}
	targets := map[model.ID]*redactTarget{id: {replacement: []byte("r"), application: 5}}
	raiseCopyBounds([]*pb.Entry{entry(1, 5), entry(2, 9), entry(3, 7), rawEntry(4, 1, nil)}, targets)
	if got := pinBound(targets); got != 9 {
		t.Fatalf("the bound is %d after a copy with application index 9 in the retained log, want 9", got)
	}
	other := model.NewID()
	raiseCopyBounds([]*pb.Entry{entry(5, 20)}, map[model.ID]*redactTarget{other: {application: 1}})
	if got := pinBound(targets); got != 9 {
		t.Fatalf("a copy of another command moved the bound to %d", got)
	}
	targets[other] = &redactTarget{replacement: []byte("r")} // located by application index: no known bound
	if got := pinBound(targets); got != ^uint64(0) {
		t.Fatalf("a target with no known bound left the bound at %d: a pin could be skipped", got)
	}

	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	row := s.putRow("KEEP-8e41a9c5d072")
	s.group.mu.Lock()
	defer s.group.mu.Unlock()
	committed := s.group.completed[row.entry.ID]
	if got := s.group.copyBoundLocked(row.entry.ID, committed); got != committed.Entry.ApplicationIndex {
		t.Fatalf("the bound of a command with one copy is %d, want its application index %d", got, committed.Entry.ApplicationIndex)
	}
	later := s.group.logCommands[row.entry.ID]
	later.Entry.ApplicationIndex += 7
	s.group.logCommands[row.entry.ID] = later
	if got := s.group.copyBoundLocked(row.entry.ID, committed); got != committed.Entry.ApplicationIndex+7 {
		t.Fatalf("a log index entry with a higher application index left the bound at %d", got)
	}
}
