// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// openSoloLeased opens the group with a pin lifetime and a clock the test controls.
func openSoloLeased(t *testing.T, dir string, id model.ID, machine *ledgerMachine, clock *fakeClock, ttl time.Duration) *solo {
	t.Helper()
	if machine == nil {
		machine = newLedgerMachine(id, filepath.Join(dir, "machine"))
		if err := os.MkdirAll(machine.dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	transport := NewLoopback()
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine, PinTTL: ttl, Now: clock.Now})
	if err != nil {
		transport.Close()
		t.Fatal(err)
	}
	if err = transport.Register(group); err == nil {
		err = group.Campaign()
	}
	if err != nil {
		group.Close()
		transport.Close()
		t.Fatal(err)
	}
	s := &solo{t: t, dir: dir, id: id, machine: machine, transport: transport, group: group}
	t.Cleanup(s.close)
	return s
}

func pinFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "raft", "pins"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func compactAfterWork(t *testing.T, s *solo, label string) CompactionResult {
	t.Helper()
	s.propose(Data, "work "+label)
	s.snapshot()
	res, err := s.group.CompactJournal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A backup that dies between BeginBackup and Seal/Abort leaves durable pins. They are reloaded on
// every start, and without a way to list and drop them every truncation archives the journal
// into them forever.
func TestCrashedBackupLeavesAnOrphanedPinThatCanBeListedAndDropped(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	for range 4 {
		s.propose(Data, "processed")
	}
	processed := uint64(s.group.Status().ApplicationCursor.Index)
	if _, err := s.group.PinJournal(processed); err != nil {
		t.Fatal(err)
	}
	s.propose(Data, "after the pin")
	live, err := s.group.Pins()
	if err != nil || len(live) != 1 || live[0].Orphaned || live[0].After != processed || !live[0].Expires.After(live[0].Created) {
		t.Fatalf("a pin of this process must be listed as live with a lease: %+v %v", live, err)
	}
	s.close() // the process dies: no Release, no Abort

	re := openSolo(t, dir, id, nil)
	pins, err := re.group.Pins()
	if err != nil || len(pins) != 1 {
		t.Fatalf("the crashed backup's pin is not listed after the restart: %+v %v", pins, err)
	}
	pin := pins[0]
	if pin.ID != live[0].ID || !pin.Orphaned {
		t.Fatalf("a pin left by a dead process must be listed as orphaned: %+v", pin)
	}
	files := pinFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("pin files %v", files)
	}
	path := filepath.Join(dir, "raft", "pins", files[0])
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	compactAfterWork(t, re, "orphan keeps archiving")
	after, err := os.Stat(path)
	if err != nil || after.Size() <= before.Size() {
		t.Fatalf("the fixture must show the leak: an orphaned pin keeps archiving every truncation (%d -> %d)", before.Size(), after.Size())
	}

	if err = re.group.DropPin(pin.ID); err != nil {
		t.Fatal(err)
	}
	if pins, err = re.group.Pins(); err != nil || len(pins) != 0 {
		t.Fatalf("dropped pin still listed: %+v %v", pins, err)
	}
	if files = pinFiles(t, dir); len(files) != 0 {
		t.Fatalf("dropped pin left its archive behind: %v", files)
	}
	if res := compactAfterWork(t, re, "after the drop"); res.Archived != 0 {
		t.Fatalf("truncation still archived %d entries for a dropped pin", res.Archived)
	}
	if files = pinFiles(t, dir); len(files) != 0 {
		t.Fatalf("truncation recreated the archive of a dropped pin: %v", files)
	}
	if err = re.group.DropPin(pin.ID); err != nil {
		t.Fatalf("dropping a pin twice must be a no-op for a reaper that retries: %v", err)
	}
	// And the drop survives another restart.
	re.close()
	again := openSolo(t, dir, id, nil)
	if pins, err = again.group.Pins(); err != nil || len(pins) != 0 {
		t.Fatalf("a dropped pin came back after a restart: %+v %v", pins, err)
	}
}

// Dropping a pin that a live backup holds makes that backup fail closed, it does not let it seal
// evidence the journal no longer keeps.
func TestDroppedLivePinFailsTheBackupThatHoldsIt(t *testing.T) {
	id := model.NewID()
	s := openSolo(t, t.TempDir(), id, nil)
	s.propose(Data, "processed")
	pin, err := s.group.PinJournal(uint64(s.group.Status().ApplicationCursor.Index))
	if err != nil {
		t.Fatal(err)
	}
	s.propose(Data, "evidence")
	pins, err := s.group.Pins()
	if err != nil || len(pins) != 1 {
		t.Fatalf("%+v %v", pins, err)
	}
	if err = s.group.DropPin(pins[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err = pin.Entries(uint64(s.group.Status().ApplicationCursor.Index)); !errors.Is(err, ErrStale) {
		t.Fatalf("a dropped pin served evidence: %v", err)
	}
}

// A pin carries a lease. Once it lapses nothing needs to reap it: truncation drops it instead of
// archiving into it, an open drops it, and the backup holding it fails closed.
func TestJournalPinLeaseLapsesWithoutAReaper(t *testing.T) {
	t.Run("truncation drops an expired pin", func(t *testing.T) {
		id := model.NewID()
		dir := t.TempDir()
		clock := newFakeClock()
		s := openSoloLeased(t, dir, id, nil, clock, time.Hour)
		s.propose(Data, "processed")
		pin, err := s.group.PinJournal(uint64(s.group.Status().ApplicationCursor.Index))
		if err != nil {
			t.Fatal(err)
		}
		clock.Advance(30 * time.Minute)
		if res := compactAfterWork(t, s, "inside the lease"); res.Archived == 0 {
			t.Fatal("a live pin inside its lease must keep archiving")
		}
		if pins, err := s.group.Pins(); err != nil || len(pins) != 1 {
			t.Fatalf("pin inside its lease: %+v %v", pins, err)
		}
		clock.Advance(31 * time.Minute)
		if res := compactAfterWork(t, s, "after the lease"); res.Archived != 0 {
			t.Fatalf("truncation archived %d entries into a pin whose lease lapsed", res.Archived)
		}
		if pins, err := s.group.Pins(); err != nil || len(pins) != 0 {
			t.Fatalf("expired pin still listed: %+v %v", pins, err)
		}
		if files := pinFiles(t, dir); len(files) != 0 {
			t.Fatalf("expired pin archive still on disk: %v", files)
		}
		if _, err = pin.Entries(uint64(s.group.Status().ApplicationCursor.Index)); !errors.Is(err, ErrStale) {
			t.Fatalf("the backup holding an expired pin must fail closed: %v", err)
		}
	})
	t.Run("an open drops an expired pin", func(t *testing.T) {
		id := model.NewID()
		dir := t.TempDir()
		clock := newFakeClock()
		s := openSoloLeased(t, dir, id, nil, clock, time.Hour)
		s.propose(Data, "processed")
		if _, err := s.group.PinJournal(uint64(s.group.Status().ApplicationCursor.Index)); err != nil {
			t.Fatal(err)
		}
		s.propose(Data, "evidence")
		s.close()
		clock.Advance(2 * time.Hour)
		re := openSoloLeased(t, dir, id, nil, clock, time.Hour)
		if pins, err := re.group.Pins(); err != nil || len(pins) != 0 {
			t.Fatalf("expired pin survived the open: %+v %v", pins, err)
		}
		if files := pinFiles(t, dir); len(files) != 0 {
			t.Fatalf("expired pin archive survived the open: %v", files)
		}
	})
	t.Run("an unexpired pin of a dead process survives the open and is orphaned", func(t *testing.T) {
		id := model.NewID()
		dir := t.TempDir()
		clock := newFakeClock()
		s := openSoloLeased(t, dir, id, nil, clock, time.Hour)
		s.propose(Data, "processed")
		if _, err := s.group.PinJournal(uint64(s.group.Status().ApplicationCursor.Index)); err != nil {
			t.Fatal(err)
		}
		s.close()
		clock.Advance(30 * time.Minute)
		re := openSoloLeased(t, dir, id, nil, clock, time.Hour)
		if pins, err := re.group.Pins(); err != nil || len(pins) != 1 || !pins[0].Orphaned {
			t.Fatalf("%+v %v", pins, err)
		}
	})
}

// writePinRecords frames raw JSON records exactly as a pin archive stores them.
func writePinRecords(t *testing.T, path string, records ...string) {
	t.Helper()
	var out []byte
	for _, r := range records {
		raw := []byte(r)
		var h [8]byte
		binary.BigEndian.PutUint32(h[:4], uint32(len(raw)))
		binary.BigEndian.PutUint32(h[4:], crc32.Checksum(raw, readyCRC))
		out = append(append(out, h[:]...), raw...)
	}
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatal(err)
	}
}

func pinHeaderJSON(id model.ID, owner *model.ID, created, expires int64) string {
	if owner == nil { // the format before pins carried a lease
		return fmt.Sprintf(`{"header":{"id":%q,"after":"0","next":"1"}}`, id.String())
	}
	return fmt.Sprintf(`{"header":{"id":%q,"after":"0","next":"1","owner":%q,"created":"%d","expires":"%d"}}`, id.String(), owner.String(), created, expires)
}

// Nothing that can be validated about a pin is trusted at open, and nothing that cannot be
// trusted blocks the node from starting: a header that was torn by the crash (the pin never became
// durable, PinJournal had not returned), a pin from before pins carried a lease, and a pin whose
// lease lapsed are dropped; a corrupt archive that did register is still refused.
func TestOpenValidatesPinsInsteadOfTrustingEveryFile(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	s.propose(Data, "processed")
	s.close()
	pins := filepath.Join(dir, "raft", "pins")
	if err := os.MkdirAll(pins, 0700); err != nil {
		t.Fatal(err)
	}
	torn, legacy, lapsed := model.NewID(), model.NewID(), model.NewID()
	if err := os.WriteFile(filepath.Join(pins, torn.String()+".pin"), []byte{0, 0, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	owner := model.NewID()
	writePinRecords(t, filepath.Join(pins, legacy.String()+".pin"), pinHeaderJSON(legacy, nil, 0, 0))
	writePinRecords(t, filepath.Join(pins, lapsed.String()+".pin"), pinHeaderJSON(lapsed, &owner, 1, 2))
	re := openSolo(t, dir, id, nil)
	if got, err := re.group.Pins(); err != nil || len(got) != 0 {
		t.Fatalf("untrustworthy pins were registered: %+v %v", got, err)
	}
	if files := pinFiles(t, dir); len(files) != 0 {
		t.Fatalf("untrustworthy pin files left on disk: %v", files)
	}
	re.close()

	// A header that names another pin is not this pin.
	mismatch := model.NewID()
	writePinRecords(t, filepath.Join(pins, mismatch.String()+".pin"), pinHeaderJSON(model.NewID(), &owner, time.Now().UnixNano(), time.Now().Add(time.Hour).UnixNano()))
	transport := NewLoopback()
	defer transport.Close()
	machine := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if g, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine}); err == nil {
		g.Close()
		t.Fatal("a pin file whose header names another pin was accepted")
	} else if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unexpected refusal: %v", err)
	}
}
