//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func TestMain(m *testing.M) {
	if handled, code := HelperRole(os.Args[1:]); handled {
		os.Exit(code)
	}
	os.Exit(m.Run())
}

func thpOf(t *testing.T, pid int) string {
	t.Helper()
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "THP_enabled:" {
			return f[1]
		}
	}
	t.Skip("no THP_enabled in /proc/<pid>/status")
	return ""
}

// D53: the helper process the overhead and acceptance runners measure is the harness binary in helper role. It must
// opt itself out of transparent huge pages, not rely on the parent having done so (the product helper does it as its
// first action). The parent is put in the "always" state first (option 41 with 0), so inheritance cannot hide a miss.
func TestHelperRoleProcessReportsTransparentHugePagesDisabled(t *testing.T) {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, 41, 0, 0, 0, 0, 0); errno != 0 {
		t.Fatal(errno)
	}
	if got := thpOf(t, os.Getpid()); got != "1" {
		t.Fatalf("parent THP_enabled %s after re-enabling, want 1", got)
	}
	h, err := StartHelper([]nativeperf.Target{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	if got := thpOf(t, h.PID); got != "0" {
		t.Fatalf("helper process THP_enabled %s, want 0", got)
	}
}
