//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// 04.02-C16 mutation battery re-run (mut0402, G314 G315 G339): a process that is the first of a new PID namespace and kept
// the host's /proc is told, by procViewIsOwn, that /proc does not show its own namespace: /proc/self names it by the host's
// number, getpid says 1. Every identity read through that /proc is refused (resolveTask), never answered for a process that
// shares a number with another one. Needs CAP_SYS_ADMIN for CLONE_NEWPID; skips, loudly, without.

const pidnsChildEnv = "MUT0402_PIDNS_CHILD"

func TestIdentityThroughAProcOfAnotherPIDNamespaceIsRefused(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("SKIPPED: CLONE_NEWPID needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestPIDNamespaceChild$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), pidnsChildEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	out, err := cmd.CombinedOutput()
	text := string(out)
	if strings.Contains(text, "PIDNS SKIP") {
		t.Skipf("SKIPPED: %s", text[strings.Index(text, "PIDNS SKIP"):])
	}
	failed := 0
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "PIDNS FAIL") {
			t.Error(line)
			failed++
		}
	}
	if !strings.Contains(text, "PIDNS DONE") {
		t.Fatalf("the namespace child did not finish (%v):\n%s", err, text)
	}
	if err != nil && failed == 0 {
		t.Fatalf("the namespace child failed: %v\n%s", err, text)
	}
}

func TestPIDNamespaceChild(t *testing.T) {
	if os.Getenv(pidnsChildEnv) == "" {
		t.Skip("helper of TestIdentityThroughAProcOfAnotherPIDNamespaceIsRefused")
	}
	if os.Getpid() != 1 {
		fmt.Println("PIDNS SKIP: the child is not the first process of a new PID namespace:", os.Getpid())
		return
	}
	if e := procViewIsOwn(); !errors.Is(e, ErrPIDNamespaceUnproven) || !errors.Is(e, ErrTargetIdentity) {
		fmt.Printf("PIDNS FAIL procViewIsOwn through the host's /proc: %v, want ErrPIDNamespaceUnproven\n", e)
	}
	if key, e := resolveTask(os.Getpid(), 1); !errors.Is(e, ErrPIDNamespaceUnproven) || key != (TaskKey{}) {
		fmt.Printf("PIDNS FAIL resolveTask through the host's /proc: %+v %v, want the zero key and ErrPIDNamespaceUnproven\n", key, e)
	}
	fmt.Println("PIDNS DONE")
}
