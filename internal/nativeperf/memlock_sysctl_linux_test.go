//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// perfLockBytes reads three kernel files of its own (perf_event_paranoid, perf_event_mlock_kb, /proc/self/status) and
// RLIMIT_MEMLOCK. 04.02-C16 mutation battery re-run (mut0402): the paranoid threshold (-1 means "unbounded", not -2) and the
// fallback for a negative perf_event_mlock_kb had no test, because the paths are read directly. A private mount namespace
// puts files of the test's own over those three paths and the child process sets its own RLIMIT_MEMLOCK, so everything else
// is the real function. Needs CAP_SYS_ADMIN (and the root capability set is hidden by the fake status file); skips, loudly,
// without.

const memlockChildEnv = "MUT0402_MEMLOCK_CHILD"

func TestPerfLockBytesReadsTheKernelLimitsItIsGiven(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a private mount namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestPerfLockBytesChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), memlockChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNS}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "MEMLOCK SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "MEMLOCK SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "MEMLOCK FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "MEMLOCK DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

func TestPerfLockBytesChild(t *testing.T) {
	if os.Getenv(memlockChildEnv) == "" {
		t.Skip("helper of TestPerfLockBytesReadsTheKernelLimitsItIsGiven")
	}
	if err := syscall.Mount("none", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		fmt.Println("MEMLOCK SKIP: cannot make the mount tree private:", err)
		return
	}
	dir := t.TempDir()
	fail := func(format string, args ...any) { fmt.Printf("MEMLOCK FAIL "+format+"\n", args...) }
	const infinity = ^uint64(0)
	bind := func(name, path, content string) func() {
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount(file, path, "", syscall.MS_BIND, ""); err != nil {
			fmt.Println("MEMLOCK SKIP: cannot bind a file over", path+":", err)
			os.Exit(0)
		}
		return func() { syscall.Unmount(path, syscall.MNT_DETACH) }
	}
	const noIPCLock = "0000000000000000"
	const withIPCLock = "0000000000004000"
	const cpus = 4
	const page = 4096 // perf_event_mlock_kb is in KiB
	run := func(name, paranoid, mlockKB, capEff string, rlimit uint64, want uint64) {
		defer bind("paranoid", perfEventParanoiPath, paranoid)()
		defer bind("mlock", perfMlockKBPath, mlockKB)()
		defer bind("status", selfStatusPath, "Name:\tx\nCapInh:\t0000000000000000\nCapEff:\t"+capEff+"\nCapBnd:\t000001ffffffffff\n")()
		if err := syscall.Setrlimit(rlimitMemlock, &syscall.Rlimit{Cur: rlimit, Max: rlimit}); err != nil {
			fmt.Println("MEMLOCK SKIP: cannot set RLIMIT_MEMLOCK:", err)
			os.Exit(0)
		}
		if got := perfLockBytes(cpus); got != want {
			fail("%s: perfLockBytes(%d) = %d, want %d", name, cpus, got, want)
		}
	}
	defaultAllowance := uint64(defaultPerfMlockKB) * 1024 * cpus
	run("the default bound: rlimit plus the per-CPU allowance", "2\n", "516\n", noIPCLock, 8<<20, 8<<20+defaultAllowance)
	run("perf_event_paranoid 0 still bounds", "0\n", "516\n", noIPCLock, 8<<20, 8<<20+defaultAllowance)
	run("perf_event_paranoid 1 still bounds", "1\n", "516\n", noIPCLock, 8<<20, 8<<20+defaultAllowance)
	run("perf_event_paranoid -1 imposes no bound", "-1\n", "516\n", noIPCLock, 8<<20, 0)
	run("perf_event_paranoid below -1 imposes no bound", "-2\n", "516\n", noIPCLock, 8<<20, 0)
	run("an unreadable perf_event_paranoid leaves the kernel the judge", "not a number\n", "516\n", noIPCLock, 8<<20, 0)
	run("CAP_IPC_LOCK imposes no bound", "2\n", "516\n", withIPCLock, 8<<20, 0)
	run("an infinite RLIMIT_MEMLOCK imposes no bound", "2\n", "516\n", noIPCLock, infinity, 0)
	run("an infinite RLIMIT_MEMLOCK imposes no bound even with a zero allowance", "2\n", "0\n", noIPCLock, infinity, 0)
	run("a negative perf_event_mlock_kb falls back to the default allowance", "2\n", "-1\n", noIPCLock, 8<<20, 8<<20+defaultAllowance)
	run("an unreadable perf_event_mlock_kb falls back to the default allowance", "2\n", "lots\n", noIPCLock, 8<<20, 8<<20+defaultAllowance)
	run("perf_event_mlock_kb is in KiB per online CPU", "2\n", "128\n", noIPCLock, 8<<20, 8<<20+128*1024*cpus)
	run("a zero perf_event_mlock_kb leaves the rlimit alone", "2\n", "0\n", noIPCLock, 1<<20, 1<<20)
	run("a zero limit and a zero allowance still refuse", "2\n", "0\n", noIPCLock, 0, 1)
	_ = page
	fmt.Println("MEMLOCK DONE")
}

// lockBytesFrom: an infinite RLIMIT_MEMLOCK is unbounded whatever the per-user allowance is (mut0402 P-M01: with a zero
// allowance the sum is the infinity itself, which is not the "unbounded" zero).
func TestLockBytesFromInfiniteRlimitIsUnboundedForEveryAllowance(t *testing.T) {
	const infinity = ^uint64(0)
	for _, perfKB := range []uint64{0, 1, 516} {
		for _, cpus := range []uint64{0, 1, 8} {
			if got := lockBytesFrom(infinity, perfKB, cpus); got != 0 {
				t.Errorf("lockBytesFrom(inf, %d, %d) = %d, want 0 (unbounded)", perfKB, cpus, got)
			}
		}
	}
}
