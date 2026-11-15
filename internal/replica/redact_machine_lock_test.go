// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

const wholeCanaryD = "WHOLE-D-6b2a91c4f0d8"

// A redaction pass over a journal of a few megabytes takes hundreds of milliseconds. A group that
// cannot tick or step for that long loses its leadership when its election timeout is shorter
// (the control voters' tests tick every 20 ms: election timeout 200 to 400 ms), and the pass's
// own next write then finds the group leaderless. The pass therefore reads and rewrites without
// the group lock and takes it only to install the result.

// answersWithin reports whether f returned within d.
func answersWithin(d time.Duration, f func()) bool {
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// heldRedaction is the machine's redaction with its first call held: entered is closed when the
// pass has called it, and the call returns when unblock is called. The pass is then somewhere in
// its read of the group.
type heldRedaction struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	freed   sync.Once
}

func newHeldRedaction(t *testing.T) *heldRedaction {
	h := &heldRedaction{entered: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(h.unblock) // a failed test must not leave the pass waiting
	return h
}

func (h *heldRedaction) unblock() { h.freed.Do(func() { close(h.release) }) }

func (h *heldRedaction) redact(payload []byte) ([]byte, bool, error) {
	h.once.Do(func() {
		close(h.entered)
		<-h.release
	})
	return eraseSecret(payload)
}

// awaitEntered waits until the pass has called the held redaction.
func (h *heldRedaction) awaitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the pass never called the machine's redaction")
	}
}

type passOutcome struct {
	res MachineRedactResult
	err error
}

func (s *wholeSolo) passAsync(ruleSet uint64, redact MachineRedaction) <-chan passOutcome {
	ctx := s.ctx()
	done := make(chan passOutcome, 1)
	go func() {
		res, err := s.group.RedactMachineCommands(ctx, ruleSet, redact)
		done <- passOutcome{res, err}
	}()
	return done
}

func awaitPass(t *testing.T, done <-chan passOutcome) MachineRedactResult {
	t.Helper()
	select {
	case out := <-done:
		if out.err != nil {
			t.Fatalf("the pass failed: %v", out.err)
		}
		return out.res
	case <-time.After(30 * time.Second):
		t.Fatal("the pass did not finish")
		return MachineRedactResult{}
	}
}

// While the pass reads the retained commands, the group answers: it can tick, step and report.
func TestARedactionPassDoesNotHoldTheGroupLockWhileItReads(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	held := newHeldRedaction(t)
	done := s.passAsync(1, held.redact)
	held.awaitEntered(t)
	if !answersWithin(2*time.Second, func() { s.group.Status() }) {
		held.unblock()
		<-done
		t.Fatal("the group did not answer for 2 s while the pass read its commands: the pass holds the group lock across the read")
	}
	held.unblock()
	if res := awaitPass(t, done); res.Redacted != 1 {
		t.Fatalf("the pass: %+v", res)
	}
	s.cleanCut()
	requireNoHits(t, filepath.Join(dir, "raft"), "after the pass", wholeCanaryA)
}

// The temporary journal is written and synced without the group lock too (those are the hooks of
// a crash while it is written); the lock is taken to rename it over the journal.
func TestARedactionPassWritesItsJournalWithoutTheGroupLock(t *testing.T) {
	var s *wholeSolo
	var held []string
	fault := func(at string) error {
		switch at {
		case HookRedactBegin, HookRedactWrite, HookRedactSync:
			if !answersWithin(2*time.Second, func() { s.group.Status() }) {
				held = append(held, at)
			}
		}
		return nil
	}
	id := model.NewID()
	dir := t.TempDir()
	s = openWhole(t, dir, id, fault)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	if res := s.pass(1); res.Redacted != 1 || res.Journal == 0 {
		t.Fatalf("the pass: %+v", res)
	}
	if len(held) != 0 {
		t.Fatalf("the group did not answer at %v: the pass holds the group lock while it writes the journal", held)
	}
}

// A command applied while the pass reads is a command the pass has not read: the pass starts over
// and covers it, and its floor is the index the group has applied when it installs.
func TestARedactionPassStartsOverWhenACommandIsAppliedWhileItReads(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep})
	held := newHeldRedaction(t)
	done := s.passAsync(1, held.redact)
	held.awaitEntered(t)

	late := wholeEntry(s.machine.current().Rev, map[string]string{"keep": wholeKeep, "secret": wholeCanaryD})
	proposed := make(chan error, 1)
	go func() {
		_, err := s.propose(late)
		proposed <- err
	}()
	select {
	case err := <-proposed:
		if err != nil {
			t.Fatalf("the command proposed while the pass read: %v", err)
		}
	case <-time.After(3 * time.Second):
		held.unblock()
		<-done
		t.Fatal("a command could not be committed for 3 s while the pass read: the pass holds the group lock across the read")
	}
	held.unblock()
	res := awaitPass(t, done)
	if res.Redacted != 2 {
		t.Fatalf("the pass redacted %d commands, want A and the one that arrived while it read: %+v", res.Redacted, res)
	}
	if applied := s.group.Status().Applied; res.Floor != applied {
		t.Fatalf("the floor %d is not the applied index %d: the pass installed a read of an older group", res.Floor, applied)
	}
	if _, err := os.Stat(filepath.Join(root, journalRedactTemp)); !os.IsNotExist(err) {
		t.Fatalf("the temporary journal is still there: %v", err)
	}
	s.cleanCut()
	requireNoHits(t, root, "after the pass that started over", wholeCanaryA, wholeCanaryD)
	residueIs(t, s.group, 1)
}

// A cut and a compaction that finish while the pass reads replace the journal it read: installing
// its copy would put the old journal back.
func TestARedactionPassStartsOverWhenTheJournalIsCompactedWhileItReads(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	root := filepath.Join(dir, "raft")
	s := openWhole(t, dir, id, nil)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryB})
	s.put(map[string]string{"keep": wholeKeep})
	held := newHeldRedaction(t)
	done := s.passAsync(1, held.redact)
	held.awaitEntered(t)

	compacted := make(chan struct{})
	go func() {
		defer close(compacted)
		snap, err := s.group.CreateSnapshot(s.ctx(), model.Cursor{Group: id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)})
		if err == nil {
			_, err = s.group.CompactJournal(s.ctx())
		}
		if err != nil {
			t.Errorf("cut and compaction while the pass read (snapshot %v): %v", snap.Manifest.Index, err)
		}
	}()
	select {
	case <-compacted:
	case <-time.After(5 * time.Second):
		held.unblock()
		<-done
		<-compacted
		t.Fatal("the journal could not be cut and compacted for 5 s while the pass read: the pass holds the group lock across the read")
	}
	first, _ := s.group.JournalRange()
	held.unblock()
	awaitPass(t, done)
	if got, _ := s.group.JournalRange(); got != first {
		t.Fatalf("the retained log starts at %d after the pass, at %d before it", got, first)
	}
	s.reopen(newWholeMachine(id))
	if got, _ := s.group.JournalRange(); got != first {
		t.Fatalf("the journal on disk starts at %d after the pass and a restart, at %d before it: the pass put back the journal it had read", got, first)
	}
	s.pass(1)
	s.cleanCut()
	requireNoHits(t, root, "after the pass that started over", wholeCanaryA, wholeCanaryB)
}

// A group that commits during every unlocked attempt still gets its pass: the last attempt holds
// the lock, where nothing can change.
func TestARedactionPassOverAGroupThatNeverStopsCommittingStillCompletes(t *testing.T) {
	var s *wholeSolo
	var begins int
	var lockHeld []int
	lateCanaries := []string{wholeCanaryB, wholeCanaryC, wholeCanaryD}
	fault := func(at string) error {
		if at != HookRedactBegin {
			return nil
		}
		begins++
		if begins > machineRedactUnlockedAttempts {
			return nil // the locked attempt: nothing can be committed now
		}
		e := wholeEntry(s.machine.current().Rev, map[string]string{"keep": wholeKeep, "secret": lateCanaries[begins-1]})
		committed := make(chan struct{})
		go func() {
			s.propose(e)
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
	s = openWhole(t, dir, id, fault)
	s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
	res := s.pass(1)
	if len(lockHeld) != 0 {
		t.Fatalf("a command could not be committed during attempt(s) %v: they ran under the group lock", lockHeld)
	}
	if begins != machineRedactUnlockedAttempts+1 {
		t.Fatalf("the pass made %d attempts, want %d unlocked ones that each lose a race and one locked one", begins, machineRedactUnlockedAttempts)
	}
	if res.Redacted != 4 {
		t.Fatalf("the pass redacted %d commands, want A and the three that arrived while it read: %+v", res.Redacted, res)
	}
	s.cleanCut()
	requireNoHits(t, root, "after the locked attempt", append([]string{wholeCanaryA}, lateCanaries...)...)
	residueIs(t, s.group, 1)
}

// The crash points of TestRedactMachineCommandsCrashPoints run with a backup pin live, which holds
// the group lock throughout. Without a pin the pass builds its journal unlocked and installs it
// under the lock: an error before the rename leaves the group in service and the repeated call
// converges; after the rename the group fails until a restart.
func TestRedactMachineCommandsCrashPointsWithoutAPin(t *testing.T) {
	setup := func(t *testing.T, hook string) (*wholeSolo, string) {
		id := model.NewID()
		dir := t.TempDir()
		s := openWhole(t, dir, id, faultOnce(hook))
		s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryA})
		s.cutAndCompact()
		s.put(map[string]string{"keep": wholeKeep, "secret": wholeCanaryC})
		s.put(map[string]string{"keep": wholeKeep})
		return s, filepath.Join(dir, "raft")
	}
	for _, hook := range []string{HookRedactBegin, HookRedactWrite, HookRedactSync, HookRedactSwitch} {
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
			s.reopen(newWholeMachine(s.id))
			s.pass(1)
			s.cleanCut()
			requireNoHits(t, root, "after the restart that repaired "+hook, wholeCanaryA, wholeCanaryC)
		})
	}
}
