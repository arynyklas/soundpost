// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	"os"
	"strings"
	"testing"

	"soundpost/internal/appcore"
)

func parseSymbolicatorFlags(t *testing.T, args ...string) (appcore.SymbolicatorSettings, error) {
	t.Helper()
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	o := addSymbolicatorFlags(f)
	if err := f.Parse(args); err != nil {
		t.Fatal(err)
	}
	return o.settings()
}

// Only the two exact argument vectors turn the binary into a worker; any extra
// argument, subcommand or flag falls through to the normal CLI. With no request on
// stdin the worker/probe entry refuses before doing anything.
func TestWorkerEntryIsExactlyTwoArgumentVectors(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"soundpost"},
		{"soundpost", "serve"},
		{"soundpost", "--worker-v1", "extra"},
		{"soundpost", "--probe-v1", "extra"},
		{"soundpost", "--worker-v2"},
		{"soundpost", "worker"},
		{"--worker-v1"},
	} {
		if code, ok := symbolicateWorker(args); ok {
			t.Fatalf("%q ran as a worker (exit %d)", args, code)
		}
	}
	// An empty, closed stdin: the entry must refuse at its handshake, long before
	// any sandbox, decoder or watchdog matters.
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writer.Close()
	previous := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = previous; reader.Close() }()
	for _, flagName := range []string{workerFlag, probeFlag} {
		code, ok := symbolicateWorker([]string{"soundpost", flagName})
		if !ok || code == 0 {
			t.Fatalf("%s: handled=%v code=%d; the entry must be handled here and refuse an empty request", flagName, ok, code)
		}
	}
}

func TestSymbolicatorFlagSurface(t *testing.T) {
	if s, err := parseSymbolicatorFlags(t); err != nil || s.Disabled || s.ConfigPath != "" || s.CgroupRoot != "" {
		t.Fatalf("default must be the sandbox on: %+v %v", s, err)
	}
	if s, err := parseSymbolicatorFlags(t, "--symbolicate-sandbox=off"); err != nil || !s.Disabled {
		t.Fatalf("off: %+v %v", s, err)
	}
	if s, err := parseSymbolicatorFlags(t, "--symbolicate-config", "/etc/soundpost/sym.json"); err != nil || s.Disabled || s.ConfigPath != "/etc/soundpost/sym.json" {
		t.Fatalf("config: %+v %v", s, err)
	}
	if s, err := parseSymbolicatorFlags(t, "--symbolicate-cgroup-root", "/sys/fs/cgroup/soundpost"); err != nil || s.CgroupRoot != "/sys/fs/cgroup/soundpost" {
		t.Fatalf("cgroup root: %+v %v", s, err)
	}
	for _, bad := range [][]string{
		{"--symbolicate-sandbox=on"},
		{"--symbolicate-sandbox=native"},
		{"--symbolicate-sandbox=off", "--symbolicate-config", "/x"},
		{"--symbolicate-sandbox=off", "--symbolicate-cgroup-root", "/x"},
		{"--symbolicate-config", "/x", "--symbolicate-cgroup-root", "/y"},
	} {
		if _, err := parseSymbolicatorFlags(t, bad...); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestSymbolicatorNoticeCarriesOnlyStaticCodes(t *testing.T) {
	if got := symbolicatorNotice(appcore.SymbolicatorStatus{State: appcore.SymbolicatorReady, Reason: "probe_passed"}); got != "symbolicator: ready (sandbox probes passed)" {
		t.Fatal(got)
	}
	got := symbolicatorNotice(appcore.SymbolicatorStatus{State: appcore.SymbolicatorUnavailable, Reason: "probe_file_sandbox_unavailable"})
	if !strings.Contains(got, "unavailable") || !strings.Contains(got, "probe_file_sandbox_unavailable") || !strings.Contains(got, "sandbox_unavailable") || strings.ContainsAny(got, "/\\") {
		t.Fatal(got)
	}
}
