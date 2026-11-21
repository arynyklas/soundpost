// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/replica"
)

// Open-to-ready of the control store replays the journal, so the journal has to stay small. The
// byte bound of DefaultJournalCadence counts the data bytes of applied entries; the journal file
// holds them base64-encoded inside JSON records (4/3), so a journal that sat at the bound is
// about 1.34 times the bound on disk, plus the snapshot record it begins with and the commands
// that arrive while the cut runs.

// journalByteBound is the byte bound these tests hold the default cadence to (decision D4 as
// amended in wave 6, see cadence.go). The tests use the constant, not DefaultJournalCadence.Bytes,
// so a cadence without a byte bound runs the same workload and fails on what it leaves on disk.
const journalByteBound = 8 << 20

// bigCommit is the state one commit carries in these tests: about 190 KB of journal, the order of a
// control state with a few hundred issues or sources, so a few dozen commits make a cut.
var bigCommit = stateShape{Owners: 3000}

// journalCeiling is the largest ready.wal a store at the byte bound may show: the bound at its 4/3
// encoding with a quarter of margin, plus the snapshot record and the commands that arrive while a
// cut runs (eight commands of commandFile bytes).
func journalCeiling(commandFile int64) int64 {
	return journalByteBound*3/2 + 8*commandFile
}

// commandFileBytes is what one bigCommit adds to the journal.
func commandFileBytes(t *testing.T, s *Store, raft string) int64 {
	t.Helper()
	commitShape(t, s, 0, bigCommit)
	before := journalSize(t, raft)
	commitShape(t, s, 1, bigCommit)
	return journalSize(t, raft) - before
}

func TestControlJournalIsBoundedByBytes(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTimed(t, dir, replica.Cadence{})
	t.Cleanup(func() { s.Close() })
	raft := filepath.Join(dir, "raft-control")
	g := s.ReplicaGroup()
	if got := g.Cadence(); got != DefaultJournalCadence {
		t.Fatalf("the control group runs with cadence %+v, want %+v", got, DefaultJournalCadence)
	}
	commandFile := commandFileBytes(t, s, raft)
	if int64(DefaultJournalCadence.Commands)*commandFile < 4*journalByteBound {
		t.Fatalf("a command of %d bytes reaches the command bound %d before the byte bound", commandFile, DefaultJournalCadence.Commands)
	}
	ceiling := journalCeiling(commandFile)
	first, _ := g.JournalRange()
	var peak int64
	cuts := 0
	for i := 2; cuts < 3; i++ {
		// Eight times the bound is written before the test gives up: with no byte cadence the journal never
		// shrinks.
		if int64(i)*commandFile > 8*journalByteBound*4/3 {
			t.Fatalf("%d commands of %d bytes (%d bytes of journal, bound %d) cut the journal %d times, peak ready.wal %d bytes: want 3 cuts and at most %d bytes", i, commandFile, int64(i)*commandFile, journalByteBound, cuts, peak, ceiling)
		}
		commitShape(t, s, i, bigCommit)
		peak = max(peak, journalSize(t, raft))
		if now, _ := g.JournalRange(); now > first {
			first, cuts = now, cuts+1
		}
	}
	t.Logf("peak ready.wal %d bytes at a byte bound of %d (ceiling %d), command %d bytes, %d cuts", peak, journalByteBound, ceiling, commandFile, cuts)
	if peak > ceiling {
		t.Fatalf("ready.wal reached %d bytes, more than the %d the byte bound %d allows", peak, ceiling, journalByteBound)
	}
}

// reopenAt closes s, reopens the store at the default cadence and reports the median Open-to-ready of
// three reopens, the journal then and the entries it holds after the snapshot.
func reopenAt(t *testing.T, dir string, s *Store) (open time.Duration, journal int64, entries uint64) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	var totals []time.Duration
	for range 3 {
		r, p := openTimed(t, dir, replica.Cadence{})
		totals = append(totals, p.total())
		journal = journalSize(t, filepath.Join(dir, "raft-control"))
		first, last := r.ReplicaGroup().JournalRange()
		entries = last - first + 1
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
	}
	slices.Sort(totals)
	return totals[1], journal, entries
}

func TestControlStartupDoesNotScaleWithCommands(t *testing.T) {
	dir := t.TempDir()
	s, _ := openTimed(t, dir, replica.Cadence{})
	t.Cleanup(func() { s.Close() })
	raft := filepath.Join(dir, "raft-control")
	commandFile := commandFileBytes(t, s, raft)
	// Both stops sit half way through a cut cycle, so the journal each leaves is the same size at the
	// default cadence, and the second history is more than twice the first.
	perCycle := journalByteBound * 4 / (3 * commandFile) // commands per byte bound: a command's entry is 3/4 of its journal bytes
	short, long := int(perCycle*3/2), int(perCycle*7/2)
	for i := 2; i < short; i++ {
		commitShape(t, s, i, bigCommit)
	}
	time.Sleep(200 * time.Millisecond) // a cut that is still running would move the journal under the reopen
	openA, journalA, entriesA := reopenAt(t, dir, s)

	s, _ = openTimed(t, dir, replica.Cadence{})
	t.Cleanup(func() { s.Close() })
	for i := short; i < long; i++ {
		commitShape(t, s, i, bigCommit)
	}
	time.Sleep(200 * time.Millisecond)
	openB, journalB, entriesB := reopenAt(t, dir, s)

	t.Logf("%d commands: ready.wal %d bytes, %d entries, open-to-ready %v; %d commands: ready.wal %d bytes, %d entries, open-to-ready %v (byte bound %d, command %d bytes)", short, journalA, entriesA, openA, long, journalB, entriesB, openB, journalByteBound, commandFile)
	if ceiling := journalCeiling(commandFile); journalA > ceiling || journalB > ceiling {
		t.Fatalf("ready.wal is %d then %d bytes after %d then %d commands, more than the %d bytes the byte bound allows", journalA, journalB, short, long, ceiling)
	}
	if entriesB > entriesA*5/4+8 {
		t.Fatalf("a journal of %d commands replays %d entries, one of %d replays %d: replay grows with the history", long, entriesB, short, entriesA)
	}
	if openB > 2*openA+500*time.Millisecond {
		t.Fatalf("open-to-ready took %v after %d commands and %v after %d: it grows with the history", openB, long, openA, short)
	}
	budget := 5 * time.Second
	if raceBuild {
		budget = 10 * time.Second
	}
	if openB > budget {
		t.Fatalf("open-to-ready took %v at a journal of %d bytes, budget %v", openB, journalB, budget)
	}
}
