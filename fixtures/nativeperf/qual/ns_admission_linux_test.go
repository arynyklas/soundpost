//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func residentBytes(t *testing.T) uint64 {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(raw))
	if len(f) < 2 {
		t.Fatalf("statm %q", raw)
	}
	pages, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return pages * uint64(os.Getpagesize())
}

// residentBallast maps and touches anonymous memory outside the Go heap (the race detector keeps no shadow of it) until this
// process's resident size is at least bytes.
func residentBallast(t *testing.T, bytes uint64) {
	t.Helper()
	var maps [][]byte
	t.Cleanup(func() {
		for _, m := range maps {
			syscall.Munmap(m)
		}
	})
	page := os.Getpagesize()
	for {
		have := residentBytes(t)
		if have >= bytes {
			return
		}
		chunk := min(bytes-have, 8<<20)
		chunk = (chunk + uint64(page) - 1) / uint64(page) * uint64(page)
		m, err := syscall.Mmap(-1, 0, int(chunk), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(m); i += page {
			m[i] = 1
		}
		maps = append(maps, m)
	}
}

// The helper of a case runs in the process that drives it, and every capture's admission charges that process's resident
// size against the 64 MiB budget. A race-instrumented binary carries the detector's own memory on top of the product's (measured on the
// 6.1.0-54 and 6.6.162 qualification VMs: 43 MB before the first capture and 59 MB after a few, against 19.5 and 25 MB for the same
// test binary built without -race, and 16-20 MB more where transparent huge pages are "always"), so the capture of a plain
// workload was refused as resource_limit for reasons that are not the product's. This pins both halves of the answer: with the
// detector the session is admitted whatever the process's resident size is, and in every other build the admission still reads
// the real size, so a harness that bypassed it everywhere would fail here.
func TestNSSessionAdmissionReadsTheRealResidentSizeExceptUnderTheRaceDetector(t *testing.T) {
	if reason := NSPrerequisites(); reason != "" {
		t.Skip("NOT run: " + reason)
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	workload, _, err := compileNSWorkloads(dir)
	if err != nil {
		t.Fatal(err)
	}
	proc, err := startNSProc(exec.Command(workload))
	if err != nil {
		t.Fatal(err)
	}
	defer proc.kill()
	target, _, err := identify(proc.pid)
	if err != nil {
		t.Fatal(err)
	}
	residentBallast(t, nativeperf.MaxMemoryBytes+(2<<20))
	r := &nsRunner{ctx: context.Background(), rec: &NSRecord{Facts: map[string]string{}}}
	s := r.session(sessionOpts{label: "admission", mode: nativeperf.ModeCPU, target: target, need: 2})
	if raceDetectorOn {
		if !s.Ready || s.ErrorCode != "" || s.CPU < 2 {
			t.Fatalf("race-instrumented binary (resident size above the budget by itself): ready=%v code=%q read_error=%q cpu=%d, want an admitted capture with samples", s.Ready, s.ErrorCode, s.ReadError, s.CPU)
		}
		return
	}
	if s.Ready || s.ErrorCode != "resource_limit" {
		t.Fatalf("resident size above the budget: ready=%v code=%q read_error=%q cpu=%d, want the real accounting to refuse it as resource_limit", s.Ready, s.ErrorCode, s.ReadError, s.CPU)
	}
}

// raceBuild is what the harness keys the stand-in on; the tests' own expectation comes from the build tags of race_on_test.go and
// race_off_test.go, so a constant that says the wrong thing in either build is caught here even if the admission test were skipped.
func TestRaceBuildSaysWhetherTheRaceDetectorIsOn(t *testing.T) {
	if raceBuild != raceDetectorOn {
		t.Fatalf("raceBuild = %v in a binary built with the race detector %v", raceBuild, raceDetectorOn)
	}
	if got := nsResidentReader() != nil; got != raceDetectorOn {
		t.Fatalf("nsResidentReader installs a stand-in = %v with the race detector %v", got, raceDetectorOn)
	}
}

// The size a race-instrumented case reports for itself is a stand-in for the product's, so it must not be a smaller one than
// anything measured, and the capture that needs the most (the scheduler's three rings per CPU, an 8-CPU qualification host) must
// still fit the budget with it.
func TestNSRaceResidentSizeCoversTheMeasuredProductAndLeavesRoomForTheScheduler(t *testing.T) {
	const largestMeasured = 25686016 // helper RSS at the last admission of this test binary built without -race, 6.1.0-54
	if nsRaceResidentBytes < largestMeasured {
		t.Errorf("stand-in %d bytes is below the %d measured without the race detector", uint64(nsRaceResidentBytes), largestMeasured)
	}
	charge, err := nativeperf.CaptureCharge(true, 1, 8, nativeperf.DefaultConfig(1), uint64(os.Getpagesize()), nativeperf.MemoryUsage{HelperRSS: nsRaceResidentBytes})
	if err != nil {
		t.Fatalf("the scheduler capture of one target on 8 CPUs does not fit the budget with the stand-in: %v", err)
	}
	if charge < nsRaceResidentBytes || charge > nativeperf.MaxMemoryBytes {
		t.Errorf("charge %d outside [%d, %d]", charge, uint64(nsRaceResidentBytes), nativeperf.MaxMemoryBytes)
	}
}
