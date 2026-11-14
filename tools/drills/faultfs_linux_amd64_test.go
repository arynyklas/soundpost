//go:build linux && amd64

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain lets the test binary act as the injector's re-exec helper, as the drills binary does.
func TestMain(m *testing.M) {
	if os.Getenv(dcFaultExecEnv) != "" {
		os.Exit(dcFaultExecMain())
	}
	os.Exit(m.Run())
}

func writeFile(t *testing.T, p string, n int) {
	t.Helper()
	if err := os.WriteFile(p, bytes.Repeat([]byte{'x'}, n), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPowerCutRollsBackWhatWasNeverSynced(t *testing.T) {
	root := t.TempDir()
	shadow := filepath.Join(t.TempDir(), "shadow")
	wal := filepath.Join(root, "wal")
	writeFile(t, wal, 100)
	cur := filepath.Join(root, "CURRENT")
	writeFile(t, cur, 10)
	d, err := newDCDisk(root, shadow)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.rebaseline(); err != nil {
		t.Fatal(err)
	}
	// 60 more bytes were appended to the WAL, never fsynced; a new file was created, never
	// published by a directory fsync; CURRENT was replaced by rename and the directory not synced.
	writeFile(t, wal, 160)
	writeFile(t, filepath.Join(root, "new"), 5)
	tmp := filepath.Join(root, "CURRENT.tmp")
	writeFile(t, tmp, 20)
	if errno := d.renameOp(tmp, cur); errno != 0 {
		t.Fatal(errno)
	}
	if err = os.Rename(tmp, cur); err != nil {
		t.Fatal(err)
	}
	s, err := d.PowerCut(false)
	if err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(wal); err != nil || st.Size() != 100 {
		t.Errorf("wal after the cut: %v %v, want 100 bytes", st, err)
	}
	if _, err = os.Stat(filepath.Join(root, "new")); !os.IsNotExist(err) {
		t.Errorf("an entry that was never published survived: %v", err)
	}
	if st, err := os.Stat(cur); err != nil || st.Size() != 10 {
		t.Errorf("CURRENT after the cut: %v %v, want the old 10-byte file", st, err)
	}
	if s.FilesTruncated < 1 || s.EntriesRemoved < 1 || s.RenamesUndone != 1 || s.BytesLost != 60 {
		t.Errorf("stats %+v", s)
	}
}

func TestPowerCutKeepsWhatWasSyncedAndTearsTheTail(t *testing.T) {
	root := t.TempDir()
	wal := filepath.Join(root, "wal")
	writeFile(t, wal, 100)
	d, err := newDCDisk(root, filepath.Join(t.TempDir(), "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.rebaseline(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, wal, 200)
	d.files[wal] = 160 // an fsync saw 160 bytes
	if _, err = d.PowerCut(true); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(wal); st.Size() != 180 {
		t.Errorf("torn tail kept %d bytes, want 160 synced + half of the 40 unsynced = 180", st.Size())
	}
}

// TestInjectorFailsAndObservesRealFsync runs a real child under the seccomp injector: a synced write
// is observed, and the same write with the injected EIO makes the child's fsync fail.
func TestInjectorFailsAndObservesRealFsync(t *testing.T) {
	if _, err := os.Stat("/bin/dd"); err != nil {
		t.Skip("no dd")
	}
	root := filepath.Join(t.TempDir(), "disk")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := newDCDisk(root, filepath.Join(t.TempDir(), "shadow"))
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string) error {
		cmd, err := dcSpawnFaulted(d, "/bin/dd", []string{"if=/dev/zero", "of=" + filepath.Join(root, name), "bs=1k", "count=1", "conv=fsync"}, os.Stderr)
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err = <-done:
		case <-time.After(30 * time.Second):
			_ = dcKillGroup(cmd)
			t.Fatal("child did not finish")
		}
		d.stop()
		return err
	}
	if err = run("ok"); err != nil {
		t.Fatalf("dd with a working fsync: %v", err)
	}
	if st := d.Stats(); st.Syncs < 1 {
		t.Errorf("the fsync was not observed: %+v", st)
	}
	d.setFailSync(true)
	if err = run("bad"); err == nil {
		t.Fatal("dd succeeded although every fsync answers EIO")
	}
	if st := d.Stats(); st.SyncsFailed < 1 {
		t.Errorf("the failed fsync was not counted: %+v", st)
	}
	d.setFailSync(false)
	away := root + "-away"
	if err = d.detach(away); err != nil {
		t.Fatal(err)
	}
	if err = d.reattachOriginal(away); err != nil {
		t.Fatal(err)
	}
	if err = run("again"); err != nil {
		t.Fatalf("dd after the disk came back: %v", err)
	}
}

func TestPartitionProxyDropsResetsAndHeals(t *testing.T) {
	n := newDCNet()
	defer n.close()
	if n.mode(1, 2) != dcLinkOpen {
		t.Fatal("links start open")
	}
	n.isolate(1, dcLinkDrop)
	if n.mode(1, 2) != dcLinkDrop || n.mode(3, 1) != dcLinkDrop || n.mode(2, 3) != dcLinkOpen {
		t.Fatal("isolate must cut every link of member 1 in both directions and no other")
	}
	n.heal()
	if n.mode(1, 2) != dcLinkOpen || n.mode(3, 1) != dcLinkOpen {
		t.Fatal("heal reopens every link")
	}
}
