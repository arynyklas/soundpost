// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func fileHash(data []byte) model.Hash { return model.Hash(sha256.Sum256(data)) }

// A file the machine offers by name, size and hash is taken from the selected snapshot without
// reading the machine's copy; a file that snapshot does not hold under that hash makes the cut
// fail typed and leaves the selected snapshot and the directory as they were.
func TestSnapshotReusesFilesOfTheSelectedSnapshot(t *testing.T) {
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	data := []byte(strings.Repeat("window-bytes;", 100))
	s.machine.files["w.dat"] = data
	if err := os.WriteFile(filepath.Join(s.machine.dir, "w.dat"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s.propose(Data, "one")
	first := s.snapshot()
	// The machine's own copy is gone: reading it would fail the cut. The cut names it instead.
	if err := os.Remove(filepath.Join(s.machine.dir, "w.dat")); err != nil {
		t.Fatal(err)
	}
	s.machine.reuse = map[string]PinnedFile{"w.dat": {Name: "w.dat", Reuse: true, Size: uint64(len(data)), SHA256: fileHash(data)}}
	s.propose(Data, "two")
	second := s.snapshot()
	a, err := os.Stat(filepath.Join(first.Dir(), "files", "w.dat"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.Stat(filepath.Join(second.Dir(), "files", "w.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(a, b) {
		t.Fatal("a reused file was copied instead of linked")
	}
	if _, err = s.group.Snapshots().Verify(); err != nil {
		t.Fatalf("the snapshot with a reused file does not verify: %v", err)
	}
	// A hash the selected snapshot does not hold.
	s.machine.reuse = map[string]PinnedFile{"w.dat": {Name: "w.dat", Reuse: true, Size: uint64(len(data)), SHA256: fileHash([]byte("other"))}}
	s.propose(Data, "three")
	_, err = s.group.CreateSnapshot(t.Context(), model.Cursor{Group: s.id, Index: model.Uint64(s.group.Status().ApplicationCursor.Index)})
	if !errors.Is(err, ErrReuseLost) {
		t.Fatalf("a file the selected snapshot does not hold: %v (want ErrReuseLost)", err)
	}
	cur, ok := s.group.Snapshots().Current()
	if !ok || cur.Manifest.Checksum != second.Manifest.Checksum {
		t.Fatal("a failed cut changed the selected snapshot")
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "raft", "snapshots"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tmp-") {
			t.Fatalf("a failed cut left %s behind", e.Name())
		}
	}
}

// VerifyCut hashes the files the cut wrote and nothing it reused: the first is the point of
// verifying a new snapshot, the second is what keeps verification proportional to the cut.
func TestVerifyCutHashesOnlyWhatTheCutWrote(t *testing.T) {
	s := openSolo(t, t.TempDir(), model.NewID(), nil)
	data := []byte(strings.Repeat("window-bytes;", 100))
	s.machine.files["w.dat"] = data
	if err := os.WriteFile(filepath.Join(s.machine.dir, "w.dat"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s.propose(Data, "one")
	first := s.snapshot()
	if _, err := s.group.Snapshots().VerifyCut(); err != nil {
		t.Fatalf("a clean cut: %v", err)
	}
	flip := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)/2] ^= 1
		// The file may be a hard link: damage the bytes in place, as bit rot does.
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.WriteAt(raw[len(raw)/2:len(raw)/2+1], int64(len(raw)/2)); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	// Damage in a file the cut wrote itself is found.
	flip(filepath.Join(first.Dir(), "files", "w.dat"))
	if _, err := s.group.Snapshots().VerifyCut(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("damage in a freshly written file: %v (want ErrCorrupt)", err)
	}
	// A reused file is not re-read by VerifyCut (every full Verify still reads it).
	s.machine.reuse = map[string]PinnedFile{"w.dat": {Name: "w.dat", Reuse: true, Size: uint64(len(data)), SHA256: fileHash(data)}}
	s.machine.files["w.dat"] = data
	if err := os.WriteFile(filepath.Join(s.machine.dir, "w.dat"), data, 0600); err != nil {
		t.Fatal(err)
	}
	// The previous snapshot's copy is damaged, so reusing it by the original hash must fail typed
	// only if the file were hashed; the store trusts the manifest it wrote, which is the point.
	s.propose(Data, "two")
	second := s.snapshot()
	if _, err := s.group.Snapshots().VerifyCut(); err != nil {
		t.Fatalf("VerifyCut re-read a reused file: %v", err)
	}
	if _, err := s.group.Snapshots().Verify(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("the full Verify must still find the damage in the reused file: %v", err)
	}
	_ = second
}
