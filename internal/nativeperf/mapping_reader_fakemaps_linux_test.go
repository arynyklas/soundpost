//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// The mapping reader over a maps file the test writes (l4w33 mutation battery D): a private mount namespace where a bind
// mount puts a file of the test's own over /proc/<pid>/maps of a real, idle process. Everything else of the process - the
// pidfd, its identity, its executable, its cgroup, its threads - is real, and the maps row names a real ELF file with two
// adjacent executable segments, which no ordinary process maps as one row. Needs CAP_SYS_ADMIN; skips, loudly, without.

const fakeMapsChildEnv = "L4W33_FAKEMAPS_CHILD"

func TestMappingReaderTableOfAMappedFileWithManyExecutableSegments(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a private mount namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFakeMapsChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), fakeMapsChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "FAKEMAPS SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "FAKEMAPS SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "FAKEMAPS FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "FAKEMAPS DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

// twoSegmentELF is an ELF64 with two adjacent executable PT_LOAD segments (file offsets 0x1000 and 0x2000, 0x1000 bytes
// each) and the GNU build ID 0xcd34.
func twoSegmentELF(t *testing.T, path string) {
	t.Helper()
	o := binary.LittleEndian
	b := make([]byte, 0x3000)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	o.PutUint16(b[16:], 3)
	o.PutUint16(b[18:], 62)
	o.PutUint32(b[20:], 1)
	o.PutUint64(b[32:], 64)
	o.PutUint16(b[52:], 64)
	o.PutUint16(b[54:], 56)
	o.PutUint16(b[56:], 3)
	load := func(i int, offset, address uint64) {
		ph := b[64+56*i:]
		o.PutUint32(ph, 1)
		o.PutUint32(ph[4:], 5)
		o.PutUint64(ph[8:], offset)
		o.PutUint64(ph[16:], address)
		o.PutUint64(ph[32:], 0x1000)
		o.PutUint64(ph[40:], 0x1000)
	}
	load(0, 0x1000, 0x1000)
	load(1, 0x2000, 0x2000)
	note := b[64+56*2:]
	o.PutUint32(note, 4)
	o.PutUint64(note[8:], 400)
	o.PutUint64(note[32:], 20)
	o.PutUint32(b[400:], 4)
	o.PutUint32(b[404:], 2)
	o.PutUint32(b[408:], 3)
	copy(b[412:], []byte{'G', 'N', 'U', 0, 0xcd, 0x34})
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// devText is the major:minor of a dev_t the way /proc/<pid>/maps prints it.
func devText(dev uint64) string {
	major := (dev>>8)&0xfff | (dev>>32)&^uint64(0xfff)
	minor := dev&0xff | (dev>>12)&^uint64(0xff)
	return fmt.Sprintf("%02x:%02x", major, minor)
}

func TestFakeMapsChild(t *testing.T) {
	if os.Getenv(fakeMapsChildEnv) == "" {
		t.Skip("helper of TestMappingReaderTableOfAMappedFileWithManyExecutableSegments")
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Println("FAKEMAPS SKIP: cannot make the mount tree private:", err)
		return
	}
	cmd, target, _ := idleTarget(t)
	dir := t.TempDir()
	library := filepath.Join(dir, "libtwo.so")
	twoSegmentELF(t, library)
	var st syscall.Stat_t
	if err := syscall.Stat(library, &st); err != nil {
		t.Fatal(err)
	}
	const start = 0x7f0000000000
	row := fmt.Sprintf("%x-%x r-xp 00000000 %s %d %s\n", start, start+0x3000, devText(uint64(st.Dev)), st.Ino, library)
	fakeMaps := filepath.Join(dir, "maps")
	if err := os.WriteFile(fakeMaps, []byte(row), 0o644); err != nil {
		t.Fatal(err)
	}
	mountPoint := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/maps"
	if err := syscall.Mount(fakeMaps, mountPoint, "", syscall.MS_BIND, ""); err != nil {
		fmt.Println("FAKEMAPS SKIP: cannot bind a file over", mountPoint+":", err)
		return
	}
	defer syscall.Unmount(mountPoint, syscall.MNT_DETACH)

	read := func(approved bool, maxMappings uint32) (MappingTable, error) {
		tgt := target
		tgt.AllowedBuildIDs = append([]string(nil), target.AllowedBuildIDs...)
		if approved {
			tgt.AllowedBuildIDs = append(tgt.AllowedBuildIDs, "cd34")
		}
		policy := DefaultSymbolPolicy(1)
		policy.AllowMappedELF = true
		policy.MaxMappings = maxMappings
		reader, err := NewMappingReader(AuthorizedTargets{targets: []Target{tgt}, mode: ModeCPU}, tgt, 1, policy)
		if err != nil {
			return MappingTable{}, fmt.Errorf("the reader of the idle process: %w", err)
		}
		defer reader.Close()
		return reader.Read(context.Background())
	}
	fail := func(format string, args ...any) { fmt.Printf("FAKEMAPS FAIL "+format+"\n", args...) }

	// both executable segments are listed, each as the range of the row that the segment covers
	table, err := read(true, 2)
	if err != nil || len(table.entries) != 2 {
		fail("two segments and a bound of two: %+v %v", table.entries, err)
	} else {
		for i, want := range []struct{ start, end, offset uint64 }{{start + 0x1000, start + 0x2000, 0x1000}, {start + 0x2000, start + 0x3000, 0x2000}} {
			e := table.entries[i]
			if e.start != want.start || e.end != want.end || e.offset != want.offset || e.module.BuildID != "cd34" || e.reason != "" {
				fail("entry %d: %+v, want %#x-%#x at file offset %#x of cd34", i, e, want.start, want.end, want.offset)
			}
		}
	}
	// the bound is on the entries, not on the rows: one row of two segments does not fit a bound of one
	if _, err = read(true, 1); !errors.Is(err, ErrResourceBudget) {
		fail("two segments and a bound of one: %v, want ErrResourceBudget", err)
	}
	// a file whose build was not approved stays in the table as a range with its reason (never dropped, never named)
	table, err = read(false, 2)
	if err != nil || len(table.entries) != 1 || table.entries[0].reason != FrameUnapproved || table.entries[0].module.ID != "" ||
		table.entries[0].start != start || table.entries[0].end != start+0x3000 {
		fail("a file of a build that is not approved: %+v %v, want the whole row as build_not_approved", table.entries, err)
	}
	fmt.Println("FAKEMAPS DONE")
}
