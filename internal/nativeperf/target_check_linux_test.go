//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// The whole-target check (l4w33 mutation battery D): which process openCheckedTarget accepts, what it hands out, and
// that nothing is left open by a refusal.

func TestOpenCheckedTargetHandsOutLiveHandlesAndCloseReleasesAllOfThem(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	before := openFDs(t)
	h, err := openCheckedTarget(fx.target)
	if err != nil {
		t.Fatalf("the authorized process was refused: %v", err)
	}
	if h.pidfd == nil || h.proc == nil || h.exe == nil || h.Target.TGID != fx.target.TGID {
		t.Fatalf("handle %+v", h)
	}
	if got := openFDs(t); got != before+3 {
		t.Fatalf("%d descriptors open, want the %d of before and one each for pidfd, proc and executable", got, before+3)
	}
	var running syscall.Stat_t
	if err = syscall.Stat(fx.exe, &running); err != nil {
		t.Fatal(err)
	}
	var held syscall.Stat_t
	if err = syscall.Fstat(int(h.exe.Fd()), &held); err != nil || held.Ino != running.Ino || held.Dev != running.Dev {
		t.Fatalf("the handle holds another executable: %+v %v", held, err)
	}
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	if got := openFDs(t); got != before {
		t.Fatalf("%d descriptors open after Close, want %d", got, before)
	}
	for name, f := range map[string]*os.File{"pidfd": h.pidfd, "proc": h.proc, "exe": h.exe} {
		if _, err := f.Stat(); err == nil {
			t.Errorf("the %s of a closed handle is still open", name)
		}
	}
	// a handle that never got as far as holding everything closes what it holds
	if err = (&TargetHandle{}).Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenCheckedTargetRefusesAProcessThatIsNotTheAuthorizedOneAndLeavesNothingOpen(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	good := fx.target
	if h, err := openCheckedTarget(good); err != nil {
		t.Fatalf("baseline: %v", err)
	} else {
		h.Close()
	}
	other := "/usr/bin/true"
	otherID := fileBuildID(t, other)
	cases := map[string]func(*Target){
		"no approved build":           func(x *Target) { x.AllowedBuildIDs = nil },
		"another approved build":      func(x *Target) { x.AllowedBuildIDs = []string{otherID} },
		"another cgroup":              func(x *Target) { x.CgroupID++ },
		"another start":               func(x *Target) { x.ProcessStart++ },
		"another namespace":           func(x *Target) { x.PIDNamespace++ },
		"a process that is not there": func(x *Target) { x.TGID = 4194300 },
	}
	for name, mutate := range cases {
		target := good
		target.AllowedBuildIDs = append([]string(nil), good.AllowedBuildIDs...)
		mutate(&target)
		before := openFDs(t)
		h, err := openCheckedTarget(target)
		if err == nil {
			h.Close()
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrTargetIdentity) || h != nil {
			t.Errorf("%s: %v %v, want ErrTargetIdentity and no handle", name, h, err)
		}
		if after := openFDs(t); after != before {
			t.Errorf("%s: %d descriptors open after the refusal, %d before", name, after, before)
		}
	}
	// any one of several approved builds is enough
	target := good
	target.AllowedBuildIDs = []string{otherID, good.AllowedBuildIDs[0], "00"}
	if h, err := openCheckedTarget(target); err != nil {
		t.Errorf("one approved build among several: %v", err)
	} else {
		h.Close()
	}
	// a process that has exited is refused, and so is its pid. The kill is asynchronous: wait until the child is reaped, through
	// os/exec. A poll of a few hundred non-blocking Wait4 calls returned within microseconds, before a sleeping child had been
	// woken to die (d12, 6.1.0-54: "an exited process was accepted", 6 of 40 runs), and a raw Wait4 takes the child away from
	// os/exec, which then leaves the pidfd of its Process to the garbage collector: it closed it in the middle of the next test's
	// descriptor count ("8 descriptors open after the checks, 9 before").
	if err := fx.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := fx.cmd.Wait(); err == nil {
		t.Fatal("the killed target exited cleanly")
	}
	if h, err := openCheckedTarget(good); err == nil {
		h.Close()
		t.Error("an exited process was accepted")
	}
}

// Revalidate is the check of every authorized target in turn: all of them must pass, and nothing stays open.
func TestRevalidateChecksEveryAuthorizedTarget(t *testing.T) {
	fx := startTargetFixture(t, "/usr/bin/sleep")
	before := openFDs(t)
	if err := (AuthorizedTargets{}).Revalidate(); err != nil {
		t.Fatalf("no targets: %v", err)
	}
	if err := (AuthorizedTargets{targets: []Target{fx.target, fx.target}}).Revalidate(); err != nil {
		t.Fatalf("two good targets: %v", err)
	}
	bad := fx.target
	bad.ProcessStart++
	if err := (AuthorizedTargets{targets: []Target{fx.target, bad}}).Revalidate(); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("a bad second target: %v", err)
	}
	if err := (AuthorizedTargets{targets: []Target{bad, fx.target}}).Revalidate(); !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("a bad first target: %v", err)
	}
	if after := openFDs(t); after != before {
		t.Fatalf("%d descriptors open after the checks, %d before", after, before)
	}
}

const unprovenChildEnv = "L4W33_UNPROVEN_CHILD"

// A /proc that does not show this process's PID namespace cannot prove any target: the check says so, with that error,
// and closes what it had opened to look. The child is PID 1 of a new PID namespace over the host's /proc.
func TestUnprovenPIDNamespaceIsReportedAndLeavesNothingOpen(t *testing.T) {
	if os.Getenv(unprovenChildEnv) != "" {
		before := openFDs(t)
		h, err := openCheckedTarget(Target{TGID: 1, PIDNamespace: 1, ProcessStart: 1, CgroupID: 1, AllowedBuildIDs: []string{"00"}})
		after := openFDs(t)
		if h != nil {
			h.Close()
		}
		t.Logf("UNPROVEN err=%v handle=%v before=%d after=%d", errors.Is(err, ErrPIDNamespaceUnproven), h != nil, before, after)
		if !errors.Is(err, ErrPIDNamespaceUnproven) {
			t.Fatalf("a target seen through a /proc of another PID namespace: %v, want ErrPIDNamespaceUnproven", err)
		}
		if h != nil || after != before {
			t.Fatalf("handle %v and %d descriptors open after the refusal, %d before", h, after, before)
		}
		return
	}
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: a PID namespace needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestUnprovenPIDNamespaceIsReportedAndLeavesNothingOpen$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), unprovenChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil && !strings.Contains(text, "UNPROVEN") {
		t.Skipf("SKIPPED: a PID namespace cannot be created here: %v\n%s", err, text)
	}
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if !strings.Contains(text, "UNPROVEN err=true") {
		t.Fatalf("the child reported nothing useful:\n%s", text)
	}
}
