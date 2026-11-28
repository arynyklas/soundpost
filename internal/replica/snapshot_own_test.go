// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// ownFile makes the machine offer data as a file it gives to the snapshot store (PinnedFile.Own), written at a path of its own, and
// returns that path.
func ownFile(t *testing.T, s *solo, name string, data []byte, sum model.Hash) string {
	t.Helper()
	path := filepath.Join(s.machine.dir, name+".staged")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s.machine.files[name] = data
	s.machine.reuse = map[string]PinnedFile{name: {Name: name, Path: path, Own: true, Size: uint64(len(data)), SHA256: sum}}
	return path
}

// A file the machine gives to the store is moved into the snapshot directory, not copied: the cut writes its bytes once, no inode is shared
// with the machine's name afterwards (it is gone), and the snapshot verifies as any other.
func TestSnapshotMovesAnOwnedFileInsteadOfCopyingIt(t *testing.T) {
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	data := []byte(strings.Repeat("owned-window-bytes;", 1000))
	path := ownFile(t, s, "w.dat", data, fileHash(data))
	s.propose(Data, "one")
	before := SnapshotBytesCopied()
	snap := s.snapshot()
	if got := SnapshotBytesCopied() - before; got != 0 {
		t.Fatalf("the store copied %d bytes of a file it was given", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the machine's name of an owned file is still there after the cut: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(snap.Dir(), "files", "w.dat"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the snapshot's file is not the owned file: %v", err)
	}
	info, err := os.Stat(filepath.Join(snap.Dir(), "files", "w.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if links := info.Sys().(*syscall.Stat_t).Nlink; links != 1 {
		t.Fatalf("the owned file has %d names, want the snapshot's alone", links)
	}
	if _, err = s.group.Snapshots().VerifyCut(); err != nil {
		t.Fatalf("a cut with a moved file does not verify: %v", err)
	}
	if _, err = s.group.Snapshots().Verify(); err != nil {
		t.Fatalf("a snapshot with a moved file does not verify: %v", err)
	}
	// Removing the snapshot does not touch anything else, and the next cut that takes the file as reused links the snapshot's own.
	s.machine.reuse = map[string]PinnedFile{"w.dat": {Name: "w.dat", Reuse: true, Size: uint64(len(data)), SHA256: fileHash(data)}}
	s.propose(Data, "two")
	second := s.snapshot()
	a, _ := os.Stat(filepath.Join(snap.Dir(), "files", "w.dat"))
	b, _ := os.Stat(filepath.Join(second.Dir(), "files", "w.dat"))
	if a == nil || b == nil || !os.SameFile(a, b) {
		t.Fatal("the file moved into a snapshot is not the one the next cut links")
	}
}

// Where the move fails (a staging directory on another file system) the file is copied, checked against the hash the machine stated, and
// the machine's own name stays for its release to remove.
func TestSnapshotCopiesAnOwnedFileWhereTheMoveFails(t *testing.T) {
	old := adoptRename
	adoptRename = func(string, string) error { return &os.LinkError{Op: "rename", Err: syscall.EXDEV} }
	t.Cleanup(func() { adoptRename = old })
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	data := []byte(strings.Repeat("owned-window-bytes;", 1000))
	path := ownFile(t, s, "w.dat", data, fileHash(data))
	s.propose(Data, "one")
	before := SnapshotBytesCopied()
	snap := s.snapshot()
	if got := SnapshotBytesCopied() - before; got != uint64(len(data)) {
		t.Fatalf("the store copied %d bytes, want the %d of the file", got, len(data))
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the machine's file is gone after a copy: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(snap.Dir(), "files", "w.dat"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the copy is not the owned file: %v", err)
	}
	if _, err = s.group.Snapshots().Verify(); err != nil {
		t.Fatalf("the snapshot with a copied file does not verify: %v", err)
	}
	// A hash the file does not have: the copy is refused and nothing is left.
	other := []byte(strings.Repeat("something else;", 1000))
	ownFile(t, s, "w.dat", other, fileHash(data))
	s.propose(Data, "two")
	if _, err = s.group.CreateSnapshot(t.Context(), model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a copied file that is not the one the machine described: %v (want ErrCorrupt)", err)
	}
	cur, ok := s.group.Snapshots().Current()
	if !ok || cur.Manifest.Checksum != snap.Manifest.Checksum {
		t.Fatal("a refused cut changed the selected snapshot")
	}
}

// A file of another size than the machine stated is refused before it is taken, and a hash it does not have is caught by the check of the
// cut that wrote it.
func TestSnapshotRefusesAnOwnedFileThatIsNotWhatTheMachineDescribed(t *testing.T) {
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	data := []byte(strings.Repeat("owned-window-bytes;", 1000))
	path := ownFile(t, s, "w.dat", data, fileHash(data))
	s.machine.reuse["w.dat"] = PinnedFile{Name: "w.dat", Path: path, Own: true, Size: uint64(len(data)) + 1, SHA256: fileHash(data)}
	s.propose(Data, "one")
	if _, err := s.group.CreateSnapshot(t.Context(), model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a file of another size: %v (want ErrCorrupt)", err)
	}
	if _, ok := s.group.Snapshots().Current(); ok {
		t.Fatal("a refused cut selected a snapshot")
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "raft", "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tmp-") {
			t.Fatalf("a refused cut left %s behind", e.Name())
		}
	}
	// Same size, other bytes: the machine's description is wrong, and VerifyCut reads the bytes the cut wrote.
	flipped := bytes.Clone(data)
	flipped[len(flipped)/2] ^= 1
	ownFile(t, s, "w.dat", flipped, fileHash(data))
	s.propose(Data, "two")
	s.snapshot()
	if _, err = s.group.Snapshots().VerifyCut(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("a moved file that is not the one described: %v (want ErrCorrupt from VerifyCut)", err)
	}
}

// Stop the process at every durability boundary of a cut that moves an owned file: nothing acknowledged is lost, the selected snapshot
// still verifies (or there is none), and the next cut after the restart is made.
func TestSnapshotCrashPointsWithAnOwnedFile(t *testing.T) {
	hooks := []string{HookSnapshotCut, HookSnapshotPin, HookSnapshotFileWrite, HookSnapshotFileSync, HookSnapshotManifestWrite, HookSnapshotDirSync, HookSnapshotSwitch, HookSnapshotRenamed, HookSnapshotCurrentWrite, HookSnapshotCurrentSwitch, HookSnapshotPublished}
	for _, hook := range hooks {
		for _, withPrior := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/prior=%t", hook, withPrior), func(t *testing.T) {
				id := model.NewID()
				dir := t.TempDir()
				s := openSolo(t, dir, id, nil)
				data := []byte(strings.Repeat("owned-window-bytes;", 1000))
				put := func(group *solo, payload string) Entry {
					e := Entry{ID: model.NewID(), Kind: Data, Payload: []byte(payload)}
					if _, err := group.tryPropose(e); err != nil {
						t.Fatal(err)
					}
					return e
				}
				var acked []Entry
				for i := range 6 {
					acked = append(acked, put(s, fmt.Sprintf("a-%d", i)))
				}
				if withPrior { // a snapshot is selected already, with the file in it
					ownFile(t, s, "w.dat", data, fileHash(data))
					s.snapshot()
					acked = append(acked, put(s, "b"))
				}
				ownFile(t, s, "w.dat", append(bytes.Clone(data), 'x'), fileHash(append(bytes.Clone(data), 'x')))
				s.close()
				crashing := openSoloWith(t, dir, id, s.machine, faultOnce(hook))
				ownFile(t, crashing, "w.dat", append(bytes.Clone(data), 'x'), fileHash(append(bytes.Clone(data), 'x')))
				_, err := crashing.group.CreateSnapshot(t.Context(), model.Cursor{Group: id, Index: model.Uint64(crashing.group.Status().ApplicationCursor.Index)})
				if err == nil {
					t.Fatalf("hook %s did not fire", hook)
				}
				if crashing.machine.pins != 0 {
					t.Fatalf("machine file pins leaked after a crash at %s: %d", hook, crashing.machine.pins)
				}
				crashing.close()
				fresh := openSolo(t, dir, id, nil)
				for _, e := range acked {
					if _, ok := fresh.machine.rows[e.ID.String()]; !ok {
						t.Fatalf("acknowledged entry lost after a crash at %s", hook)
					}
				}
				if snap, err := fresh.group.Snapshots().Verify(); err == nil {
					if snap.Manifest.Index > fresh.group.Status().Applied {
						t.Fatal("selected snapshot is ahead of the journal")
					}
				} else if !errors.Is(err, ErrNoSnapshot) {
					t.Fatalf("a crash at %s left a selected snapshot that does not verify: %v", hook, err)
				}
				put(fresh, "after")
				ownFile(t, fresh, "w.dat", append(bytes.Clone(data), 'x', 'y'), fileHash(append(bytes.Clone(data), 'x', 'y')))
				snap := fresh.snapshot()
				if _, err = fresh.group.Snapshots().VerifyCut(); err != nil {
					t.Fatalf("cut after a crash at %s: %v", hook, err)
				}
				got, err := os.ReadFile(filepath.Join(snap.Dir(), "files", "w.dat"))
				if err != nil || !bytes.Equal(got, append(bytes.Clone(data), 'x', 'y')) {
					t.Fatalf("file of the cut after a crash at %s: %v", hook, err)
				}
				if _, err = fresh.group.CompactJournal(t.Context()); err != nil {
					t.Fatalf("compaction after a crash at %s: %v", hook, err)
				}
			})
		}
	}
}
