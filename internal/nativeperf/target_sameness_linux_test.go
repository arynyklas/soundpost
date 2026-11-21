//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.02-C16 mutation battery re-run (mut0402, G266 G274 G276 G278): openCheckedTarget reads the target's identity twice
// around its cgroup read; what makes two reads "the same" is decided by three small predicates, tested here directly (the
// race that would make them differ cannot be staged deterministically on a real process), and a target whose executable
// carries no GNU build ID is refused even when the approved list holds an empty identity.

func TestTargetReadsAreTheSameOnlyWhenEveryComponentIs(t *testing.T) {
	boom := errors.New("boom")
	a := &syscall.Stat_t{Dev: 1, Ino: 2}
	for _, tc := range []struct {
		name string
		got  bool
		want bool
	}{
		{"the same file", sameFile(nil, nil, a, &syscall.Stat_t{Dev: 1, Ino: 2}), true},
		{"another inode", sameFile(nil, nil, a, &syscall.Stat_t{Dev: 1, Ino: 3}), false},
		{"another device", sameFile(nil, nil, a, &syscall.Stat_t{Dev: 9, Ino: 2}), false},
		{"another device and inode", sameFile(nil, nil, a, &syscall.Stat_t{Dev: 9, Ino: 3}), false},
		{"the first stat failed", sameFile(boom, nil, a, &syscall.Stat_t{Dev: 1, Ino: 2}), false},
		{"the second stat failed", sameFile(nil, boom, a, &syscall.Stat_t{Dev: 1, Ino: 2}), false},
		{"identical bytes", sameMetadata(nil, []byte("0::/a\n"), []byte("0::/a\n")), true},
		{"different bytes", sameMetadata(nil, []byte("0::/a\n"), []byte("0::/a\n9:x:/\n")), false},
		{"a failed read of identical bytes", sameMetadata(boom, []byte("0::/a\n"), []byte("0::/a\n")), false},
		{"a failed read of different bytes", sameMetadata(boom, []byte("0::/a\n"), []byte("x")), false},
		{"empty reads", sameMetadata(nil, nil, []byte{}), true},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, tc.got, tc.want)
		}
	}
	before := Target{PIDNamespace: 4, ProcessStart: 5, TGID: 6, CgroupID: 7}
	same := before
	same.CgroupID = 8 // the cgroup is read and compared separately
	for _, tc := range []struct {
		name  string
		after Target
		e     error
		want  bool
	}{
		{"the same process", same, nil, true},
		{"another namespace", Target{PIDNamespace: 5, ProcessStart: 5, TGID: 6}, nil, false},
		{"another start time", Target{PIDNamespace: 4, ProcessStart: 6, TGID: 6}, nil, false},
		{"another process id", Target{PIDNamespace: 4, ProcessStart: 5, TGID: 7}, nil, false},
		{"a failed resolution of the same process", same, boom, false},
		{"a failed resolution", Target{}, boom, false},
	} {
		if got := sameProcess(tc.e, before, tc.after); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// startPatchedTarget starts a copy of sleep(1) whose PT_NOTE program headers are neutralised: the process runs, but its
// executable has no GNU build ID to read.
func startPatchedTarget(t *testing.T) Target {
	t.Helper()
	data, err := os.ReadFile("/usr/bin/sleep")
	if err != nil {
		t.Skipf("NOT run: %v", err)
	}
	if len(data) < 64 || string(data[:4]) != "\x7fELF" || data[4] != 2 || data[5] != 1 {
		t.Skip("NOT run: sleep(1) is not a little-endian ELF64")
	}
	phoff := binary.LittleEndian.Uint64(data[32:])
	phentsize, phnum := binary.LittleEndian.Uint16(data[54:]), binary.LittleEndian.Uint16(data[56:])
	patched := 0
	for i := uint16(0); i < phnum; i++ {
		at := int(phoff) + int(i)*int(phentsize)
		if elf.ProgType(binary.LittleEndian.Uint32(data[at:])) == elf.PT_NOTE {
			binary.LittleEndian.PutUint32(data[at:], uint32(elf.PT_NULL))
			patched++
		}
	}
	if patched == 0 {
		t.Skip("NOT run: sleep(1) has no PT_NOTE header")
	}
	exe := filepath.Join(t.TempDir(), "target")
	if err = os.WriteFile(exe, data, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "60")
	if err = cmd.Start(); err != nil {
		t.Skipf("NOT run: cannot start the patched copy: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	own, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if running, err := os.Stat("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe"); err == nil && os.SameFile(running, own) {
			break
		}
		if time.Now().After(deadline) {
			t.Skip("NOT run: the patched copy never started running")
		}
	}
	target, err := ResolveLocalTarget(cmd.Process.Pid)
	if err != nil {
		t.Skipf("NOT run: target identity unavailable: %v", err)
	}
	cg, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	inode, err := cgroupIdentity(cg)
	if err != nil {
		t.Skipf("NOT run: cgroup v2 identity unavailable: %v", err)
	}
	target.CgroupID = model.Uint64(inode)
	return target
}

func TestOpenCheckedTargetRefusesAnExecutableWithoutABuildIDWhateverTheApprovedListHolds(t *testing.T) {
	target := startPatchedTarget(t)
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(target.TGID), 10) + "/exe")
	if err != nil {
		t.Skip(err)
	}
	id, idErr := executableBuildID(f)
	f.Close()
	if idErr == nil {
		t.Skipf("NOT run: the patched executable still reports build ID %s", id)
	}
	for _, approved := range [][]string{{""}, {"", "00"}, {"00"}} {
		target.AllowedBuildIDs = approved
		if h, e := openCheckedTarget(target); !errors.Is(e, ErrTargetIdentity) {
			if h != nil {
				h.Close()
			}
			t.Errorf("approved %q: %v, want ErrTargetIdentity", approved, e)
		}
	}
}
