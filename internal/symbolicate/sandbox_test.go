// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// The parent explicitly provisions this private operator config and built
// worker. Tests never build binaries, mount controllers or weaken privileges.
func sandboxConfig(t *testing.T) Config {
	t.Helper()
	name := os.Getenv("SOUNDPOST_SYMBOLICATE_TEST_CONFIG")
	if name == "" {
		t.Skip("actual sandbox qualification requires SOUNDPOST_SYMBOLICATE_TEST_CONFIG")
	}
	b, e := os.ReadFile(name)
	if e != nil {
		t.Fatal(e)
	}
	var c Config
	if json.Unmarshal(b, &c) != nil {
		t.Fatal("invalid sandbox fixture config")
	}
	return c
}

// nativeSandboxConfig is sandboxConfig for the tests that only make sense for
// the native sandbox (staged launch, clone3, delegated cgroup groups, the
// worker's inherited descriptors, a worker file path). Under an OCI
// configuration they skip: the same SOUNDPOST_SYMBOLICATE_TEST_CONFIG names one
// backend, and a native-only test run against an OCI config measures nothing.
func nativeSandboxConfig(t *testing.T) Config {
	t.Helper()
	c := sandboxConfig(t)
	if c.Mode != "native" {
		t.Skipf("native-sandbox test: the test configuration selects mode %q", c.Mode)
	}
	return c
}
func TestActualSandboxDeniesFileNetworkExec(t *testing.T) {
	c := sandboxConfig(t)
	for _, k := range []ProbeKind{ProbeFile, ProbeNetwork, ProbeExec} {
		r := Probe(context.Background(), c, k)
		if !r.Denied || r.Reason != Resolved {
			t.Fatalf("actual %s probe: %+v", k, r)
		}
	}
}
func TestActualSandboxMemoryKilled(t *testing.T) {
	r := Probe(context.Background(), sandboxConfig(t), ProbeMemory)
	if !r.OOMKilled || r.Reason != ResourceLimit {
		t.Fatalf("actual 256MiB OS memory probe: %+v", r)
	}
}
func TestActualSandboxDeadlineAndRestart(t *testing.T) {
	c := sandboxConfig(t)
	r := Probe(context.Background(), c, ProbeTimeout)
	if r.Reason != Deadline {
		t.Fatalf("actual timeout: %+v", r)
	}
	r = Probe(context.Background(), c, ProbeFile)
	if !r.Denied {
		t.Fatalf("post-kill restart: %+v", r)
	}
}
func TestSandboxUnavailableFailsClosed(t *testing.T) {
	s, e := New(&unusedReader{}, unusedGenerations{}, Config{Mode: "native", CgroupRoot: "not-an-absolute-delegation"})
	if e != nil {
		t.Fatal(e)
	}
	if got := s.runOne(context.Background(), workerInput{Version: 1, Positions: []workerPosition{{Line: 1}}}); got.Reason != SandboxUnavailable || got.Position != nil {
		t.Fatal("unsupported sandbox executed decoder", got)
	}
}
