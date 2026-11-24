// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// D87 (L2w20Admission17): the control group's cut serialized the whole retry table into every snapshot's envelope and
// the journal rewrite that followed carried it in its head, so every cut created and removed a file that grew with
// the table (20 to 40 MB at the cap). A group whose machine cuts compact snapshots keeps the table in immutable
// parts of the snapshot directory and a cut writes only what is new.

// compactDigestMachine is digestMachine that cuts compact snapshots: its CompactSnapshot is its state (a whole
// state is what a reopened test machine can restore from) and it states that the state is the compact form.
type compactDigestMachine struct{ digestMachine }

func (m compactDigestMachine) CompactSnapshot() ([]byte, error) { return m.wholeMachine.Snapshot() }
func (compactDigestMachine) CompactState([]byte) bool           { return true }

type compactSolo struct {
	t         *testing.T
	dir       string
	id        model.ID
	cfg       Config
	machine   *wholeMachine
	transport *Loopback
	group     *Group
}

func openCompactSolo(t *testing.T, cfg Config) *compactSolo {
	t.Helper()
	s := &compactSolo{t: t, dir: t.TempDir(), id: model.NewID(), cfg: cfg}
	s.open()
	t.Cleanup(s.stop)
	return s
}

func (s *compactSolo) open() {
	s.t.Helper()
	s.machine = newWholeMachine(s.id)
	s.transport = NewLoopback()
	cfg := s.cfg
	cfg.ID, cfg.Group, cfg.Directory, cfg.Transport, cfg.Members, cfg.Machine = 1, s.id, filepath.Join(s.dir, "raft"), s.transport, soloMembers(), compactDigestMachine{digestMachine{s.machine}}
	group, err := Open(cfg)
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

func (s *compactSolo) stop() { s.group.Close(); s.transport.Close() }

func (s *compactSolo) reopen() {
	s.t.Helper()
	s.stop()
	s.open()
	if _, err := s.group.ReadIndex(s.t.Context()); err != nil {
		s.t.Fatal(err)
	}
}

func (s *compactSolo) put(i int) wholeRow {
	s.t.Helper()
	e := wholeEntry(s.machine.current().Rev, map[string]string{"book": fmt.Sprint(i)})
	c, err := s.group.Propose(s.t.Context(), e)
	if err != nil {
		s.t.Fatal(err)
	}
	return wholeRow{entry: e, acked: c}
}

func (s *compactSolo) cut() Snapshot {
	s.t.Helper()
	snap, err := s.group.CreateSnapshot(s.t.Context(), model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)})
	if err != nil {
		s.t.Fatal(err)
	}
	return snap
}

func (s *compactSolo) cutAndCompact() Snapshot {
	s.t.Helper()
	snap := s.cut()
	if _, err := s.group.CompactJournal(s.t.Context()); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.group.Snapshots().DropSuperseded(); err != nil {
		s.t.Fatal(err)
	}
	return snap
}

// requireRetried proves every row is still recognized: its retry returns the receipt it was acknowledged with.
func (s *compactSolo) requireRetried(label string, rows []wholeRow) {
	s.t.Helper()
	for i, r := range rows {
		retry, err := s.group.Propose(s.t.Context(), r.entry)
		if err != nil {
			s.t.Fatalf("%s: retry of row %d: %v", label, i, err)
		}
		requireSameReceipt(s.t, fmt.Sprintf("%s row %d", label, i), r.acked, retry)
	}
}

func retryPartFiles(t *testing.T, snap Snapshot) []string {
	t.Helper()
	var out []string
	for _, f := range snap.Manifest.Files {
		if strings.HasPrefix(f.Name, filePrefix+"retry-") {
			out = append(out, f.Name)
		}
	}
	return out
}

func smallParts(t *testing.T, n int) {
	t.Helper()
	old := retryPartEntries
	retryPartEntries = n
	t.Cleanup(func() { retryPartEntries = old })
}

// The envelope of a cut names the parts instead of carrying the table, a later cut takes the sealed parts of the
// previous one by link and writes only the entries after them, and a group opened on the journal answers every
// retry from the parts.
func TestACutOfACompactRetryTableWritesOnlyWhatIsNew(t *testing.T) {
	smallParts(t, 16)
	s := openCompactSolo(t, Config{})
	var rows []wholeRow
	for i := range 200 {
		rows = append(rows, s.put(i))
	}
	first := s.cutAndCompact()
	if n := envelopeSize(t, first); n > 4096 {
		t.Fatalf("the envelope of a cut of a table of %d entries is %d bytes: the table is inside it", len(rows), n)
	}
	parts := retryPartFiles(t, first)
	if len(parts) != 13 { // 12 sealed parts of 16 and a partial one of 8
		t.Fatalf("the cut holds %d retry parts, want 13: %v", len(parts), parts)
	}
	for i := 200; i < 220; i++ {
		rows = append(rows, s.put(i))
	}
	second := s.cut() // the first snapshot is still there to compare with
	if n := envelopeSize(t, second); n > 4096 {
		t.Fatalf("the second envelope is %d bytes", n)
	}
	// The 12 sealed parts are the same files; the partial one was rewritten with what followed it.
	linked, fresh := 0, 0
	for _, name := range retryPartFiles(t, second) {
		a, errA := os.Stat(filepath.Join(first.Dir(), filepath.FromSlash(name)))
		b, errB := os.Stat(filepath.Join(second.Dir(), filepath.FromSlash(name)))
		switch {
		case errB != nil:
			t.Fatal(errB)
		case errA == nil && os.SameFile(a, b):
			linked++
		case errA == nil:
			t.Fatalf("%s was copied instead of linked", name)
		default:
			fresh++
		}
	}
	if linked != 12 || fresh != 2 { // 8 + 20 entries after the sealed parts: one full part and one of 12
		t.Fatalf("the second cut linked %d parts and wrote %d, want 12 and 2", linked, fresh)
	}
	if written := s.group.Phases().CutRetryBytes; written == 0 || written > 40*1024 {
		t.Fatalf("the second cut serialized %d bytes of retry table (a table of %d entries is ~%d bytes inline)", written, len(rows), len(rows)*400)
	}
	if _, err := s.group.CompactJournal(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.group.Snapshots().DropSuperseded(); err != nil {
		t.Fatal(err)
	}
	s.requireRetried("before reopening", rows)
	s.reopen()
	s.requireRetried("after reopening", rows)
	if got := retryCount(s.group); got != len(rows) {
		t.Fatalf("the reopened group holds %d retry entries, want %d", got, len(rows))
	}
	if _, err := s.group.Snapshots().Verify(); err != nil {
		t.Fatalf("the snapshot with retry parts does not verify: %v", err)
	}
}

// The table is bounded: parts that hold nothing but evicted entries are dropped by the next cut, and a group that
// is opened restores exactly the retained table, not what the parts still hold.
func TestRetryPartsFollowTheEvictionOfTheTable(t *testing.T) {
	smallParts(t, 16)
	s := openCompactSolo(t, Config{RetryMax: 40})
	var rows []wholeRow
	for i := range 300 {
		rows = append(rows, s.put(i))
		if i%50 == 49 {
			s.cutAndCompact()
		}
	}
	snap := s.cutAndCompact()
	if parts := retryPartFiles(t, snap); len(parts) > 4 { // 40 retained entries: at most 3 parts, one of them partial, and one that straddles
		t.Fatalf("a table of 40 entries is spread over %d parts: %v", len(parts), parts)
	}
	s.requireRetried("before reopening", rows[260:])
	s.reopen()
	if got := retryCount(s.group); got != 40 {
		t.Fatalf("the reopened group holds %d retry entries, want 40", got)
	}
	s.requireRetried("after reopening", rows[260:])
	for _, old := range []wholeRow{rows[0], rows[250]} {
		if _, err := s.group.Propose(t.Context(), old.entry); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrStale) {
			t.Fatalf("an evicted command is still recognized after reopening: %v", err)
		}
	}
}

// A crash after a cut was published and before the journal was compacted onto it leaves the journal head anchored on
// the previous snapshot: the parts that head names are in that snapshot's directory, not in the selected one.
func TestAJournalAnchoredOnTheSupersededSnapshotStillFindsItsRetryParts(t *testing.T) {
	smallParts(t, 16)
	s := openCompactSolo(t, Config{})
	var rows []wholeRow
	for i := range 100 {
		rows = append(rows, s.put(i))
	}
	s.cutAndCompact()
	for i := 100; i < 130; i++ {
		rows = append(rows, s.put(i))
	}
	second := s.cut() // published, the journal not compacted onto it, the first snapshot not dropped
	if cur, ok := s.group.Snapshots().Current(); !ok || cur.Manifest.Index != second.Manifest.Index {
		t.Fatal("the second cut is not the selected snapshot")
	}
	s.reopen()
	s.requireRetried("journal on the first snapshot, second selected", rows)
	// A cut after that reopening rebuilds its belief about the files from the journal head: it must take what
	// the selected snapshot holds or write the rest, and the table must survive another reopening.
	for i := 130; i < 140; i++ {
		rows = append(rows, s.put(i))
	}
	s.cutAndCompact()
	s.reopen()
	s.requireRetried("after the next cut", rows)
}

// A snapshot that is not the one the retry parts were planned against (the selected one lost a part) makes the cut
// write the whole table once instead of failing for good.
func TestACutWhoseRetryPartsAreGoneWritesTheTableWhole(t *testing.T) {
	smallParts(t, 16)
	s := openCompactSolo(t, Config{})
	var rows []wholeRow
	for i := range 60 {
		rows = append(rows, s.put(i))
	}
	first := s.cutAndCompact()
	parts := retryPartFiles(t, first)
	sort.Strings(parts)
	// The selected snapshot loses a sealed part's content (same name, other hash): the reuse is refused.
	g := s.group
	g.mu.Lock()
	if len(g.retryParts) == 0 {
		g.mu.Unlock()
		t.Fatal("the group keeps no retry parts")
	}
	g.retryParts[0].Sum = model.Hash{1}
	g.mu.Unlock()
	rows = append(rows, s.put(60))
	snap := s.cutAndCompact()
	if got := len(retryPartFiles(t, snap)); got < 4 {
		t.Fatalf("the repeated cut holds %d parts", got)
	}
	s.reopen()
	s.requireRetried("after the repeated cut", rows)
}

// A cut is the cost of what is new, not of the table: with a cadence, the files the cuts create beside the
// journal stay small while the table grows (red before D87: each cut wrote the whole table into the envelope).
func TestCadenceCutsOfAGrowingRetryTableCreateNoLargeFiles(t *testing.T) {
	smallParts(t, 16)
	var s *compactSolo
	var mu sync.Mutex // the hook runs on the cadence goroutine
	var prevDir string
	var biggest int64
	var biggestName string
	var cuts, journalBytes int
	hook := func(at string) error {
		mu.Lock()
		defer mu.Unlock()
		switch at {
		case "snapshot_published":
			root := filepath.Join(s.dir, "raft", "snapshots")
			dirs, _ := filepath.Glob(filepath.Join(root, "snap-*"))
			sort.Strings(dirs)
			if len(dirs) == 0 {
				return nil
			}
			newest := dirs[len(dirs)-1]
			_ = filepath.Walk(newest, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(newest, path)
				if prevDir != "" {
					if before, err := os.Stat(filepath.Join(prevDir, rel)); err == nil && os.SameFile(before, info) {
						return nil // linked from the previous snapshot: nothing was created
					}
				}
				if info.Size() > biggest {
					biggest, biggestName = info.Size(), filepath.ToSlash(rel)
				}
				return nil
			})
			prevDir = newest
			cuts++
		case HookCompactBegin:
			if info, err := os.Stat(filepath.Join(s.dir, "raft", "ready.wal")); err == nil {
				journalBytes += int(info.Size())
			}
		}
		return nil
	}
	s = &compactSolo{t: t, dir: t.TempDir(), id: model.NewID(), cfg: Config{Cadence: Cadence{Commands: 60}, Fault: hook}}
	s.open()
	t.Cleanup(s.stop)
	puts := 0
	for deadline := time.Now().Add(30 * time.Second); s.group.CadenceCuts() < 8 && time.Now().Before(deadline); puts++ {
		s.put(puts)
		if puts%20 == 19 {
			time.Sleep(5 * time.Millisecond) // the cuts run beside the commands
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if cuts < 8 {
		t.Fatalf("%d cuts for %d commands at a cadence of 60", cuts, puts)
	}
	if biggest > 64<<10 {
		t.Fatalf("a cut created a file of %d bytes (%s) while the table held %d entries (~%d bytes inline): the cut writes the table again", biggest, biggestName, puts, puts*400)
	}
	if journalBytes == 0 {
		t.Fatal("the journal was never observed")
	}
}
