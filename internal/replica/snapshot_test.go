// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// ledgerMachine is the replica-level fixture: rows plus a deletion ledger that
// grows with every Barrier command, so a snapshot without it is detectable.
type ledgerMachine struct {
	mu         sync.Mutex
	group      model.ID
	applied    uint64
	rows       map[string]string
	fences     []LedgerEntry
	generation uint64
	applies    []uint64 // physical indexes of every non-noop Apply, in order

	files    map[string][]byte // name -> content of a derived file the machine owns
	dir      string
	pins     int
	releases int
	retired  []string
}

type ledgerState struct {
	Rows       map[string]string `json:"rows"`
	Fences     []LedgerEntry     `json:"fences"`
	Generation uint64            `json:"generation,string"`
}

func newLedgerMachine(group model.ID, dir string) *ledgerMachine {
	return &ledgerMachine{group: group, rows: map[string]string{}, dir: dir, files: map[string][]byte{}}
}
func (m *ledgerMachine) Applied() uint64 { m.mu.Lock(); defer m.mu.Unlock(); return m.applied }
func (m *ledgerMachine) Apply(c CommittedEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.Index <= m.applied {
		return nil
	}
	if c.Entry.Kind != Noop {
		m.rows[c.Entry.ID.String()] = string(c.Entry.Payload)
		m.applies = append(m.applies, c.Index)
		if c.Entry.Kind == Barrier {
			sum := sha256.Sum256(c.Entry.Payload)
			m.fences = append(m.fences, LedgerEntry{Index: uint64(c.ApplicationCursor.Index), Kind: "fence", Hash: sum})
			m.generation++
		}
	}
	m.applied = c.Index
	return nil
}
func (m *ledgerMachine) Snapshot() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return json.Marshal(ledgerState{Rows: m.rows, Fences: m.fences, Generation: m.generation})
}
func (m *ledgerMachine) Restore(raw []byte, index uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var s ledgerState
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	m.rows, m.fences, m.generation, m.applied = s.Rows, s.Fences, s.Generation, index
	return nil
}
func (m *ledgerMachine) DeletionLedger() (Ledger, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Ledger{Version: 1, Group: m.group, Generation: m.generation, Entries: append([]LedgerEntry{}, m.fences...)}, nil
}
func (m *ledgerMachine) PinFiles() ([]PinnedFile, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pins++
	var out []PinnedFile
	for name := range m.files {
		out = append(out, PinnedFile{Name: name, Path: filepath.Join(m.dir, name)})
	}
	return out, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.pins--
		m.releases++
		if m.pins == 0 {
			for _, path := range m.retired {
				_ = os.Remove(path)
			}
			m.retired = nil
		}
	}, nil
}

// retire models storage compaction: a pinned file is removed only after release.
func (m *ledgerMachine) retire(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	path := filepath.Join(m.dir, name)
	if m.pins > 0 {
		m.retired = append(m.retired, path)
		return
	}
	_ = os.Remove(path)
}

type solo struct {
	t         *testing.T
	dir       string
	id        model.ID
	machine   *ledgerMachine
	transport *Loopback
	group     *Group
}

func soloMembers() Members {
	return Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}
}

func openSolo(t *testing.T, dir string, id model.ID, fault func(string) error) *solo {
	t.Helper()
	machine := newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(machine.dir, 0700); err != nil {
		t.Fatal(err)
	}
	return openSoloWith(t, dir, id, machine, fault)
}
func openSoloWith(t *testing.T, dir string, id model.ID, machine *ledgerMachine, fault func(string) error) *solo {
	t.Helper()
	transport := NewLoopback()
	group, err := Open(Config{ID: 1, Group: id, Directory: filepath.Join(dir, "raft"), Transport: transport, Members: soloMembers(), Machine: machine, Fault: fault})
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
func (s *solo) close() { s.group.Close(); s.transport.Close() }
func (s *solo) propose(kind Kind, payload string) CommittedEntry {
	s.t.Helper()
	c, err := s.tryPropose(Entry{ID: model.NewID(), Kind: kind, Payload: []byte(payload)})
	if err != nil {
		s.t.Fatal(err)
	}
	return c
}
func (s *solo) tryPropose(e Entry) (CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.group.Propose(ctx, e)
}
func (s *solo) snapshot() Snapshot {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snap, err := s.group.CreateSnapshot(ctx, model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)})
	if err != nil {
		s.t.Fatal(err)
	}
	return snap
}
func faultOnce(name string) func(string) error {
	var once sync.Once
	return func(at string) error {
		var err error
		if at == name {
			once.Do(func() { err = errors.New("injected crash at " + name) })
		}
		return err
	}
}
func stream(t *testing.T, s Snapshot) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := s.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// reseal rebuilds a manifest checksum so a test can forge exactly one defect.
func reseal(m SnapshotManifest) SnapshotManifest { m.Checksum = m.seal(); return m }

func TestSnapshotChecksumAndGenerationFence(t *testing.T) {
	id := model.NewID()
	origin := openSolo(t, t.TempDir(), id, nil)
	for i := range 6 {
		origin.propose(Data, fmt.Sprintf("row-%d", i))
	}
	origin.propose(Barrier, "tombstone-a")
	first := origin.snapshot()
	firstStream := stream(t, first)
	for i := range 4 {
		origin.propose(Data, fmt.Sprintf("later-%d", i))
	}
	origin.propose(Barrier, "tombstone-b")
	second := origin.snapshot()
	secondStream := stream(t, second)
	if first.Manifest.Generation >= second.Manifest.Generation || first.Manifest.Index >= second.Manifest.Index {
		t.Fatal("fixture must cut two distinct generations")
	}
	if first.Manifest.Ledger.Count != 1 || second.Manifest.Ledger.Count != 2 {
		t.Fatalf("deletion ledger not carried: %d %d", first.Manifest.Ledger.Count, second.Manifest.Ledger.Count)
	}
	open := func(t *testing.T) *SnapshotStore {
		s, err := OpenSnapshotStore(t.TempDir(), id, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("flipped byte never becomes ready and keeps the old directory", func(t *testing.T) {
		store := open(t)
		if err := store.InstallSnapshot(context.Background(), first.Manifest, bytes.NewReader(firstStream)); err != nil {
			t.Fatal(err)
		}
		bad := bytes.Clone(secondStream)
		bad[len(bad)/2] ^= 0x01
		if err := store.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(bad)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("corrupt stream installed: %v", err)
		}
		current, ok := store.Current()
		if !ok || current.Manifest.Checksum != first.Manifest.Checksum {
			t.Fatal("old valid directory was not retained")
		}
		if _, err := store.Verify(); err != nil {
			t.Fatalf("old directory no longer verifies: %v", err)
		}
	})
	t.Run("truncated and over-long streams are rejected", func(t *testing.T) {
		store := open(t)
		if err := store.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(secondStream[:len(secondStream)-1])); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("short stream installed: %v", err)
		}
		if err := store.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(append(bytes.Clone(secondStream), 0))); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("over-long stream installed: %v", err)
		}
		if _, ok := store.Current(); ok {
			t.Fatal("a rejected stream became ready")
		}
	})
	t.Run("missing or null deletion ledger never becomes ready", func(t *testing.T) {
		store := open(t)
		withoutLedger := second.Manifest
		withoutLedger.Files = nil
		var kept bytes.Buffer
		for _, f := range second.Manifest.Files {
			if f.Name != fileLedger {
				withoutLedger.Files = append(withoutLedger.Files, f)
			}
		}
		withoutLedger = reseal(withoutLedger)
		if err := store.InstallSnapshot(context.Background(), withoutLedger, &kept); !errors.Is(err, ErrNoLedger) {
			t.Fatalf("ledger-less manifest accepted: %v", err)
		}
		// A ledger file that exists but says nothing ("entries": null) is also absent.
		nullLedger := []byte(fmt.Sprintf(`{"version":1,"group":%q,"generation":"%d","entries":null}`, id.String(), second.Manifest.Generation))
		forged := second.Manifest
		forged.Files = append([]SnapshotFile(nil), second.Manifest.Files...)
		var forgedStream bytes.Buffer
		for i, f := range forged.Files {
			in, err := second.File(f.Name)
			if err != nil {
				t.Fatal(err)
			}
			var raw bytes.Buffer
			raw.ReadFrom(in)
			in.Close()
			data := raw.Bytes()
			if f.Name == fileLedger {
				data = nullLedger
				sum := sha256.Sum256(data)
				forged.Files[i] = SnapshotFile{Name: f.Name, Size: uint64(len(data)), SHA256: sum}
				forged.Ledger.Digest = sum
			}
			forgedStream.Write(data)
		}
		forged = reseal(forged)
		if err := store.InstallSnapshot(context.Background(), forged, &forgedStream); !errors.Is(err, ErrNoLedger) {
			t.Fatalf("null ledger accepted: %v", err)
		}
		if _, ok := store.Current(); ok {
			t.Fatal("a snapshot without a deletion ledger became ready")
		}
	})
	t.Run("tampered manifest fails its checksum", func(t *testing.T) {
		store := open(t)
		forged := second.Manifest
		forged.Cursor.Index++ // claims a later cut than the bytes hold
		if err := store.InstallSnapshot(context.Background(), forged, bytes.NewReader(secondStream)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("tampered manifest accepted: %v", err)
		}
	})
	t.Run("generation fence refuses older or conflicting snapshots", func(t *testing.T) {
		store := open(t)
		if err := store.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(secondStream)); err != nil {
			t.Fatal(err)
		}
		if err := store.InstallSnapshot(context.Background(), first.Manifest, bytes.NewReader(firstStream)); !errors.Is(err, ErrStale) {
			t.Fatalf("older generation overwrote a newer one: %v", err)
		}
		if err := store.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(secondStream)); err != nil {
			t.Fatalf("idempotent retry of the installed snapshot failed: %v", err)
		}
		if err := store.RequireGeneration(second.Manifest.Generation + 5); err != nil {
			t.Fatal(err)
		}
		fresh := open(t)
		if err := fresh.RequireGeneration(second.Manifest.Generation + 1); err != nil {
			t.Fatal(err)
		}
		if err := fresh.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(secondStream)); !errors.Is(err, ErrStale) {
			t.Fatalf("snapshot older than the restore-authority fence installed: %v", err)
		}
		if _, ok := fresh.Current(); ok {
			t.Fatal("fenced snapshot became ready")
		}
		if err := fresh.RequireGeneration(1); !errors.Is(err, ErrStale) {
			t.Fatalf("fence moved backwards: %v", err)
		}
	})
	t.Run("interrupted installation keeps the old valid directory at every hook", func(t *testing.T) {
		hooks := []string{HookInstallBegin, HookInstallFileWrite, HookInstallFileSync, HookInstallManifestWrite, HookInstallDirSync, HookInstallSwitch, HookInstallRenamed, HookInstallCurrentWrite, HookInstallCurrentSwitch, HookInstallPublished}
		for _, hook := range hooks {
			t.Run(hook, func(t *testing.T) {
				dir := t.TempDir()
				store, err := OpenSnapshotStore(dir, id, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err = store.InstallSnapshot(context.Background(), first.Manifest, bytes.NewReader(firstStream)); err != nil {
					t.Fatal(err)
				}
				crashing, err := OpenSnapshotStore(dir, id, faultOnce(hook))
				if err != nil {
					t.Fatal(err)
				}
				if err = crashing.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(secondStream)); err == nil {
					t.Fatal("hook did not interrupt installation")
				}
				repaired, err := OpenSnapshotStore(dir, id, nil)
				if err != nil {
					t.Fatal(err)
				}
				want := first.Manifest.Checksum
				if hook == HookInstallPublished {
					want = second.Manifest.Checksum // the pointer switch already happened
				}
				current, err := repaired.Verify()
				if err != nil || current.Manifest.Checksum != want {
					t.Fatalf("selected directory after %s: %v", hook, err)
				}
				entries, _ := os.ReadDir(filepath.Join(dir, "snapshots"))
				for _, e := range entries {
					if strings.HasPrefix(e.Name(), "install-") || strings.HasPrefix(e.Name(), "tmp-") {
						t.Fatalf("repair left %s behind", e.Name())
					}
				}
				if err = repaired.InstallSnapshot(context.Background(), second.Manifest, bytes.NewReader(secondStream)); err != nil {
					t.Fatalf("retry after crash at %s: %v", hook, err)
				}
				if current, err = repaired.Verify(); err != nil || current.Manifest.Checksum != second.Manifest.Checksum {
					t.Fatal("retry did not complete the installation")
				}
			})
		}
	})
	t.Run("a deleted directory falls back to the previous verified one", func(t *testing.T) {
		dir := t.TempDir()
		store, err := OpenSnapshotStore(dir, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range []struct {
			m SnapshotManifest
			s []byte
		}{{first.Manifest, firstStream}, {second.Manifest, secondStream}} {
			if err = store.InstallSnapshot(context.Background(), in.m, bytes.NewReader(in.s)); err != nil {
				t.Fatal(err)
			}
		}
		current, _ := store.Current()
		if err = os.WriteFile(filepath.Join(current.Dir(), fileEnvelope), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenSnapshotStore(dir, id, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := reopened.Verify()
		if err != nil || got.Manifest.Checksum != first.Manifest.Checksum {
			t.Fatalf("did not fall back to the older verified snapshot: %v", err)
		}
	})
}

// Truncation must wait for a verified snapshot and keep every acknowledged
// entry; a restart then replays only the suffix beyond the snapshot.
func TestSnapshotJournalCompactionReplaysOnlySuffix(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	if _, err := s.group.CompactJournal(context.Background()); !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("compaction without a verified snapshot: %v", err)
	}
	acked := map[model.ID]CommittedEntry{}
	entries := map[model.ID]Entry{}
	put := func(kind Kind, payload string) {
		e := Entry{ID: model.NewID(), Kind: kind, Payload: []byte(payload)}
		c, err := s.tryPropose(e)
		if err != nil {
			t.Fatal(err)
		}
		acked[e.ID], entries[e.ID] = c, e
	}
	for i := range 30 {
		put(Data, fmt.Sprintf("history-%d", i))
	}
	put(Barrier, "tombstone")
	snapshot := s.snapshot()
	for i := range 5 {
		put(Data, fmt.Sprintf("suffix-%d", i))
	}
	before, _ := s.group.JournalRange()
	result, err := s.group.CompactJournal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after, last := s.group.JournalRange()
	if before != 1 || after != snapshot.Manifest.Index+1 || result.FirstIndex != after || last <= after {
		t.Fatalf("journal not truncated to the snapshot cut: before=%d after=%d cut=%d last=%d", before, after, snapshot.Manifest.Index, last)
	}
	s.close()
	re := openSolo(t, dir, id, nil)
	if got := len(re.machine.rows); got != len(acked) {
		t.Fatalf("restart lost acknowledged rows: %d of %d", got, len(acked))
	}
	for _, c := range re.machine.applies {
		if c <= snapshot.Manifest.Index {
			t.Fatalf("restart replayed index %d at or below the snapshot cut %d (O(history) startup)", c, snapshot.Manifest.Index)
		}
	}
	if len(re.machine.applies) != 5 {
		t.Fatalf("restart replayed %d suffix entries, want 5", len(re.machine.applies))
	}
	for id, original := range acked {
		retry, err := re.tryPropose(entries[id])
		if err != nil {
			t.Fatalf("idempotent retry failed: %v", err)
		}
		if retry.Index != original.Index || retry.Term != original.Term || retry.ApplicationCursor != original.ApplicationCursor {
			t.Fatal("retry after truncation did not return the original receipt")
		}
	}
	changed := entries[func() model.ID {
		for id := range entries {
			return id
		}
		return model.ID{}
	}()]
	changed.Payload = []byte("different")
	if _, err = re.tryPropose(changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed payload under an old ID after truncation: %v", err)
	}
	if got := re.machine.fences; len(got) != 1 {
		t.Fatalf("deletion ledger lost across truncation: %d", len(got))
	}
}

// Kill the process at every durability boundary of snapshot creation and journal
// truncation. No acknowledged entry may disappear, retry returns the original
// receipt, and a stop never leaves an unverified snapshot selected.
func TestSnapshotCrashPoints(t *testing.T) {
	hooks := []string{HookSnapshotCut, HookSnapshotPin, HookSnapshotFileWrite, HookSnapshotFileSync, HookSnapshotManifestWrite, HookSnapshotDirSync, HookSnapshotSwitch, HookSnapshotRenamed, HookSnapshotCurrentWrite, HookSnapshotCurrentSwitch, HookSnapshotPublished,
		HookCompactBegin, HookCompactArchive, HookCompactWrite, HookCompactSync, HookCompactSwitch, HookCompactRenamed, HookCompactMemory}
	for _, hook := range hooks {
		t.Run(hook, func(t *testing.T) {
			id := model.NewID()
			dir := t.TempDir()
			s := openSolo(t, dir, id, nil)
			machineDir := s.machine.dir
			if err := os.WriteFile(filepath.Join(machineDir, "derived.seg"), []byte("derived-bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			s.machine.files["derived.seg"] = []byte("derived-bytes")
			acked := map[model.ID]CommittedEntry{}
			entries := map[model.ID]Entry{}
			put := func(group *solo, payload string) {
				e := Entry{ID: model.NewID(), Kind: Data, Payload: []byte(payload)}
				c, err := group.tryPropose(e)
				if err != nil {
					t.Fatal(err)
				}
				acked[e.ID], entries[e.ID] = c, e
			}
			for i := range 12 {
				put(s, fmt.Sprintf("a-%d", i))
			}
			s.close()
			crashing := openSoloWith(t, dir, id, s.machine, faultOnce(hook))
			// The reopened group replays from the full journal on the same machine state.
			pin, err := crashing.group.PinJournal(0)
			if err != nil {
				t.Fatal(err)
			}
			_ = pin
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err = crashing.group.CreateSnapshot(ctx, model.Cursor{Group: id, Index: model.Uint64(crashing.group.Status().ApplicationCursor.Index)})
			cancel()
			if err == nil && strings.HasPrefix(hook, "compact_") {
				_, err = crashing.group.CompactJournal(context.Background())
			}
			if err == nil {
				t.Fatalf("hook %s did not fire", hook)
			}
			if crashing.machine.pins != 0 {
				t.Fatalf("machine file pins leaked after a crash at %s: %d", hook, crashing.machine.pins)
			}
			crashing.close()
			// Restart on the same directory with a fresh machine: replay must give back every ACKed entry.
			fresh := openSolo(t, dir, id, nil)
			for eid, original := range acked {
				if _, ok := fresh.machine.rows[eid.String()]; !ok {
					t.Fatalf("acknowledged entry lost after crash at %s", hook)
				}
				retry, err := fresh.tryPropose(entries[eid])
				if err != nil || retry.Index != original.Index || retry.Term != original.Term || retry.ApplicationCursor != original.ApplicationCursor {
					t.Fatalf("retry after crash at %s did not return the original receipt: %v", hook, err)
				}
			}
			if snap, err := fresh.group.Snapshots().Verify(); err == nil {
				if snap.Manifest.Index > fresh.group.Status().Applied {
					t.Fatal("selected snapshot is ahead of the journal")
				}
			} else if !errors.Is(err, ErrNoSnapshot) {
				t.Fatalf("crash at %s left a selected snapshot that does not verify: %v", hook, err)
			}
			put(fresh, "after-crash")
			if _, err = fresh.group.CreateSnapshot(context.Background(), model.Cursor{Group: id, Index: fresh.group.Status().ApplicationCursor.Index}); err != nil {
				t.Fatalf("snapshot after crash at %s: %v", hook, err)
			}
			if _, err = fresh.group.CompactJournal(context.Background()); err != nil {
				t.Fatalf("compaction after crash at %s: %v", hook, err)
			}
			if _, err = os.Stat(filepath.Join(dir, "raft", journalCompactTemp)); !os.IsNotExist(err) {
				t.Fatal("temporary journal left behind")
			}
		})
	}
}

func TestSnapshotPinsMachineFilesWhileCopying(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	var machine *ledgerMachine
	fault := func(at string) error {
		if at == HookSnapshotFileWrite {
			// Compaction retires the segment while the snapshot is still copying it.
			machine.retire("segment-1.seg")
		}
		return nil
	}
	machine = newLedgerMachine(id, filepath.Join(dir, "machine"))
	if err := os.MkdirAll(machine.dir, 0700); err != nil {
		t.Fatal(err)
	}
	content := bytes.Repeat([]byte("authoritative-segment-bytes\n"), 4096)
	if err := os.WriteFile(filepath.Join(machine.dir, "segment-1.seg"), content, 0600); err != nil {
		t.Fatal(err)
	}
	machine.files["segment-1.seg"] = content
	s := openSoloWith(t, dir, id, machine, fault)
	s.propose(Data, "row")
	snap := s.snapshot()
	in, err := snap.File(filePrefix + "segment-1.seg")
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	got.ReadFrom(in)
	in.Close()
	if !bytes.Equal(got.Bytes(), content) {
		t.Fatal("snapshot lost a file retired during the copy")
	}
	if machine.pins != 0 || machine.releases != 1 {
		t.Fatalf("pin not released exactly once: pins=%d releases=%d", machine.pins, machine.releases)
	}
	if _, err = os.Stat(filepath.Join(machine.dir, "segment-1.seg")); !os.IsNotExist(err) {
		t.Fatal("retired file was not reclaimed after the pin was released")
	}
	if err = snap.Manifest.Validate(); err != nil {
		t.Fatal(err)
	}
}

// A backup pin must keep post-checkpoint evidence readable after truncation.
func TestSnapshotJournalPinSurvivesTruncation(t *testing.T) {
	id := model.NewID()
	dir := t.TempDir()
	s := openSolo(t, dir, id, nil)
	for i := range 5 {
		s.propose(Data, fmt.Sprintf("processed-%d", i))
	}
	processed := s.group.Status().ApplicationCursor.Index
	pin, err := s.group.PinJournal(uint64(processed))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 7 {
		s.propose(Data, fmt.Sprintf("post-checkpoint-%d", i))
	}
	s.snapshot()
	if _, err = s.group.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, _ := s.group.JournalRange()
	if first <= uint64(processed)+1 {
		t.Fatal("journal was not actually truncated past the pin")
	}
	through := uint64(s.group.Status().ApplicationCursor.Index)
	got, err := pin.Entries(through)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 {
		t.Fatalf("pinned evidence lost: %d of 7", len(got))
	}
	for i, e := range got {
		if e.ApplicationIndex != uint64(processed)+uint64(i)+1 {
			t.Fatalf("non-contiguous pinned evidence at %d: %d", i, e.ApplicationIndex)
		}
	}
	// A pin survives a restart and keeps archiving.
	s.close()
	re := openSolo(t, dir, id, nil)
	re.propose(Data, "more")
	re.snapshot()
	if _, err = re.group.CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	reloaded := func() *JournalPin {
		re.group.mu.Lock()
		defer re.group.mu.Unlock()
		for _, p := range re.group.pins {
			return p
		}
		return nil
	}()
	if reloaded == nil {
		t.Fatal("pin not reloaded after restart")
	}
	got, err = reloaded.Entries(uint64(re.group.Status().ApplicationCursor.Index))
	if err != nil || len(got) != 8 {
		t.Fatalf("pinned evidence after restart+truncation: %d, %v", len(got), err)
	}
	if err = reloaded.Release(); err != nil {
		t.Fatal(err)
	}
	if _, err = reloaded.Entries(1); !errors.Is(err, ErrStale) {
		t.Fatalf("released pin still served evidence: %v", err)
	}
}

// An isolated restore: an installed snapshot becomes the starting point of a
// fresh group directory, with receipts, rows and the deletion ledger intact.
func TestSnapshotInstallRestoresIsolatedGroup(t *testing.T) {
	id := model.NewID()
	origin := openSolo(t, t.TempDir(), id, nil)
	acked := map[model.ID]CommittedEntry{}
	entries := map[model.ID]Entry{}
	for i := range 9 {
		e := Entry{ID: model.NewID(), Kind: Data, Payload: []byte(fmt.Sprintf("row-%d", i))}
		c, err := origin.tryPropose(e)
		if err != nil {
			t.Fatal(err)
		}
		acked[e.ID], entries[e.ID] = c, e
	}
	origin.propose(Barrier, "tombstone")
	snap := origin.snapshot()
	origin.propose(Data, "after-the-cut") // committed later, not part of this snapshot
	dir := t.TempDir()
	store, err := OpenSnapshotStore(filepath.Join(dir, "raft"), id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.InstallSnapshot(context.Background(), snap.Manifest, bytes.NewReader(stream(t, snap))); err != nil {
		t.Fatal(err)
	}
	restored := openSolo(t, dir, id, nil)
	// Only the new leader's own no-op may follow the cut.
	if got := restored.machine.Applied(); got < snap.Manifest.Index || got > snap.Manifest.Index+1 {
		t.Fatalf("restored group resumed at %d, want the cut %d", got, snap.Manifest.Index)
	}
	if got := restored.group.Status().ApplicationCursor.Index; got < snap.Manifest.Cursor.Index {
		t.Fatalf("application cursor %d behind the snapshot cursor %d", got, snap.Manifest.Cursor.Index)
	}
	if len(restored.machine.fences) != 1 || len(restored.machine.rows) != 10 {
		t.Fatalf("rows/ledger not restored: %d rows, %d fences", len(restored.machine.rows), len(restored.machine.fences))
	}
	for _, c := range restored.machine.applies {
		if c <= snap.Manifest.Index {
			t.Fatalf("re-applied index %d at or below the cut", c)
		}
	}
	for id, original := range acked {
		retry, err := restored.tryPropose(entries[id])
		if err != nil || retry.Index != original.Index || retry.ApplicationCursor != original.ApplicationCursor {
			t.Fatalf("restored group changed an original receipt: %v", err)
		}
	}
	restored.propose(Data, "new work after restore")
	restored.close()
	again := openSolo(t, dir, id, nil)
	if len(again.machine.rows) != 11 {
		t.Fatalf("restart of the restored group lost rows: %d", len(again.machine.rows))
	}
}

// A follower behind a truncated journal must be repaired by the leader's
// snapshot and then receive exactly the committed suffix after the cut.
func TestSnapshotLaggingFollowerCatchesUpAfterTruncation(t *testing.T) {
	id := model.NewID()
	wire := &testWire{nodes: map[uint64]*Group{}, blocked: map[uint64]bool{}}
	members := Members{Revision: 1, Nodes: []Member{{ID: 1, Address: "https://node1.invalid", FailureDomain: "disk-a", NodeIdentity: "node-1"}, {ID: 2, Address: "https://node2.invalid", FailureDomain: "disk-b", NodeIdentity: "node-2"}, {ID: 3, Address: "https://node3.invalid", FailureDomain: "disk-c", NodeIdentity: "node-3"}}}
	machines := map[uint64]*ledgerMachine{}
	for node := uint64(1); node <= 3; node++ {
		dir := t.TempDir()
		machines[node] = newLedgerMachine(id, filepath.Join(dir, "machine"))
		g, err := Open(Config{ID: node, Group: id, Directory: filepath.Join(dir, "raft"), Members: members, Machine: machines[node], Transport: wire})
		if err != nil {
			t.Fatal(err)
		}
		wire.nodes[node] = g
		t.Cleanup(func() { g.Close() })
	}
	if err := wire.nodes[1].Campaign(); err != nil {
		t.Fatal(err)
	}
	wire.pump(t)
	acked := map[model.ID]CommittedEntry{}
	entries := map[model.ID]Entry{}
	put := func(kind Kind, payload string) {
		e := Entry{ID: model.NewID(), Kind: kind, Payload: []byte(payload)}
		c, err := testPropose(t, wire, 1, e)
		if err != nil {
			t.Fatal(err)
		}
		acked[e.ID], entries[e.ID] = c, e
	}
	for i := range 3 {
		put(Data, fmt.Sprintf("early-%d", i))
	}
	wire.block(3)
	for i := range 10 {
		put(Data, fmt.Sprintf("row-%d", i))
	}
	put(Barrier, "tombstone")
	var snap Snapshot
	if err := testAwait(t, wire, func(ctx context.Context) error {
		var err error
		snap, err = wire.nodes[1].CreateSnapshot(ctx, model.Cursor{Group: id, Index: wire.nodes[1].Status().ApplicationCursor.Index})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.nodes[1].CompactJournal(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		put(Data, fmt.Sprintf("suffix-%d", i))
	}
	if first, _ := wire.nodes[1].JournalRange(); first != snap.Manifest.Index+1 {
		t.Fatalf("leader journal not truncated to the cut: first=%d cut=%d", first, snap.Manifest.Index)
	}
	seen := len(machines[3].applies)
	wire.mu.Lock()
	delete(wire.blocked, 3)
	wire.mu.Unlock()
	for range 600 {
		wire.nodes[1].Tick()
		wire.pump(t)
		if len(machines[3].rows) == len(acked) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(machines[3].rows) != len(acked) {
		t.Fatalf("lagging follower did not catch up: %d of %d", len(machines[3].rows), len(acked))
	}
	for _, index := range machines[3].applies[seen:] {
		if index <= snap.Manifest.Index {
			t.Fatalf("suffix replay began at %d, at or below the snapshot cut %d", index, snap.Manifest.Index)
		}
	}
	if got := len(machines[3].applies) - seen; got != 4 {
		t.Fatalf("replayed %d suffix entries, want exactly the 4 committed after the cut", got)
	}
	if len(machines[3].fences) != 1 {
		t.Fatal("tombstone missing on the repaired follower")
	}
	for eid, original := range acked {
		retry, err := testPropose(t, wire, 1, entries[eid])
		if err != nil || retry.Index != original.Index {
			t.Fatalf("retry changed the original receipt: %v", err)
		}
	}
}
