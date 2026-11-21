//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
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

// The bound on the cgroup file of a target (l4w33 mutation battery D, guardLocked): the reader reads /proc/<pid>/cgroup
// up to exactly 65536 bytes and refuses a byte more. A private mount namespace puts a file of the test's own over
// /proc/<pid>/cgroup of a real, idle process - its genuine content followed by padding lines of another hierarchy (the
// identity is the "0::" line and nothing else) - once of exactly 65536 bytes and once of 65537. Everything else of the
// process is real. Needs CAP_SYS_ADMIN; skips, loudly, without.

const fakeCgroupChildEnv = "L4W33_FAKECGROUP_CHILD"

func TestMappingReaderReadsTheCgroupFileOfExactlyItsBoundAndNotAByteMore(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a private mount namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestFakeCgroupChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), fakeCgroupChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "FAKECGROUP SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "FAKECGROUP SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "FAKECGROUP FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "FAKECGROUP DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

func TestFakeCgroupChild(t *testing.T) {
	if os.Getenv(fakeCgroupChildEnv) == "" {
		t.Skip("helper of TestMappingReaderReadsTheCgroupFileOfExactlyItsBoundAndNotAByteMore")
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Println("FAKECGROUP SKIP: cannot make the mount tree private:", err)
		return
	}
	cmd, target, authorized := idleTarget(t)
	mountPoint := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/cgroup"
	genuine, err := os.ReadFile(mountPoint)
	if err != nil || !strings.Contains(string(genuine), "0::/") {
		fmt.Printf("FAKECGROUP SKIP: the idle process has no unified cgroup line: %q %v\n", genuine, err)
		return
	}
	dir := t.TempDir()
	fail := func(format string, args ...any) { fmt.Printf("FAKECGROUP FAIL "+format+"\n", args...) }
	// padded is the genuine file followed by one line of another hierarchy, n bytes in all
	padded := func(n int) string {
		pad := n - len(genuine)
		if pad < 14 {
			t.Fatalf("the genuine cgroup file is already %d bytes", len(genuine))
		}
		return string(genuine) + "9:name=pad:/" + strings.Repeat("x", pad-13) + "\n"
	}
	read := func(content string) error {
		path := filepath.Join(dir, "cgroup")
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(path, mountPoint, "", syscall.MS_BIND, ""); err != nil {
			fmt.Println("FAKECGROUP SKIP: cannot bind a file over", mountPoint+":", err)
			os.Exit(0)
		}
		defer syscall.Unmount(mountPoint, syscall.MNT_DETACH)
		reader, err := NewMappingReader(authorized, target, 1, DefaultSymbolPolicy(1))
		if reader != nil {
			reader.Close()
		}
		return err
	}

	if err := read(string(genuine)); err != nil {
		fail("the genuine cgroup file: %v", err)
	}
	if len(padded(65536)) != 65536 || len(padded(65537)) != 65537 {
		t.Fatalf("the padding is %d and %d bytes", len(padded(65536)), len(padded(65537)))
	}
	if err := read(padded(65536)); err != nil {
		fail("a cgroup file of exactly 65536 bytes: %v, want it accepted", err)
	}
	if err := read(padded(65537)); !errors.Is(err, ErrTargetIdentity) {
		fail("a cgroup file of 65537 bytes: %v, want ErrTargetIdentity", err)
	}
	fmt.Println("FAKECGROUP DONE")
}
