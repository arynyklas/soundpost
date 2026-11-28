//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const thpChildEnv = "SOUNDPOST_THP_CHILD"

// thpEnabled reads the THP_enabled line of /proc/self/status ("1": the process may get transparent huge pages,
// "0": it opted out with PR_SET_THP_DISABLE). ok is false when the kernel does not report it.
func thpEnabled(t *testing.T) (value string, ok bool) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "THP_enabled:" {
			return f[1], true
		}
	}
	return "", false
}

// D53: the 6.1 host runs transparent huge pages "always", which put the helper's Go heap on 2 MiB pages and inflated its
// resident size by about 7.7 MB. The helper opts itself out as its first action, so its memory does not depend on the
// host's THP mode. The child here is this test binary with THP re-enabled (prctl option 41 with 0), the state a
// helper has on an "always" host; the child must report THP_enabled 0 after the call.
func TestDisableTransparentHugePagesOptsTheHelperProcessOut(t *testing.T) {
	if os.Getenv(thpChildEnv) == "1" {
		if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 41, 0, 0, 0, 0, 0); errno != 0 {
			t.Fatal(errno)
		}
		if before, _ := thpEnabled(t); before != "1" {
			t.Fatalf("THP_enabled %s after re-enabling, want 1 (the control state)", before)
		}
		if err := DisableTransparentHugePages(); err != nil {
			t.Fatal(err)
		}
		if got, _ := thpEnabled(t); got != "0" {
			t.Fatalf("THP_enabled %s after DisableTransparentHugePages, want 0", got)
		}
		return
	}
	if _, ok := thpEnabled(t); !ok {
		t.Skip("this kernel does not report THP_enabled in /proc/self/status")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDisableTransparentHugePagesOptsTheHelperProcessOut$", "-test.v")
	cmd.Env = append(os.Environ(), thpChildEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// The helper binary's run() must make the call before anything else, so no allocation of significance precedes it.
func TestHelperMainDisablesTransparentHugePagesFirst(t *testing.T) {
	src, err := os.ReadFile("../../cmd/soundpost-perf-acquire/main.go")
	if err != nil {
		t.Fatal(err)
	}
	const head = "func run() error {\n"
	body := string(src)
	i := strings.Index(body, head)
	if i < 0 {
		t.Fatal("run() not found in the helper main")
	}
	first := strings.TrimSpace(strings.SplitN(body[i+len(head):], "\n", 2)[0])
	if first != "if e := nativeperf.DisableTransparentHugePages(); e != nil {" {
		t.Fatalf("the first statement of run() is %q, want the THP opt-out", first)
	}
}
