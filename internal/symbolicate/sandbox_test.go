// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"encoding/json"
	"os"
	"sync"
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

// Every launch of the worker answers its request. The worker is a fresh process whose Go runtime starts threads after the filter is installed (the
// main goroutine blocks reading the request while the runtime hands its processor to another thread), so a call the allowlist forgot kills a random
// fraction of the launches, never all of them: a worker linked against glibc (cgo enabled) registers each such thread's restartable-sequences area
// (rseq) and died of SIGABRT in 7 to 13 of 100 launches on an idle host, which a frame showed as worker_failure. One launch proves nothing; this
// runs 300 against the actual sandbox, two at a time, and refuses a single non-resolved answer. deploy/ci/symbolicate-native.sh runs it for the
// release's static worker and again for a worker built with cgo enabled.
func TestActualNativeSandboxAnswersEveryLaunchOfItsWorker(t *testing.T) {
	c := nativeSandboxConfig(t)
	s, e := New(&unusedReader{}, unusedGenerations{}, c)
	if e != nil {
		t.Fatal(e)
	}
	raw := lineMap(40000)
	const launches, parallel = 300, 2
	var mu sync.Mutex
	answers := map[Reason]int{}
	var wg sync.WaitGroup
	slots := make(chan struct{}, parallel)
	for range launches {
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			got := s.run(context.Background(), batchInput(raw, 1, 7, 99, 1000, 5000))
			mu.Lock()
			defer mu.Unlock()
			for _, o := range got {
				answers[o.Reason]++
			}
		}()
	}
	wg.Wait()
	if want := launches * 5; answers[Resolved] != want {
		t.Fatalf("%d launches of the actual worker, 5 positions each: want %d resolved, got %v", launches, want, answers)
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
