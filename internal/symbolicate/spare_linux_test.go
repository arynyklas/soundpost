//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// fastSpare shortens the spare age bound and turns the keep-warm refill off, so
// a test sees exactly one pool generation unless it opts in with keepWarm.
func fastSpare(t *testing.T) {
	t.Helper()
	prev, prevWarm := spareMaxAge, spareKeepWarm
	spareMaxAge, spareKeepWarm = 500*time.Millisecond, 0
	t.Cleanup(func() { spareMaxAge, spareKeepWarm = prev, prevWarm })
}

func keepWarm(t *testing.T, d time.Duration) {
	t.Helper()
	prev := spareKeepWarm
	spareKeepWarm = d
	t.Cleanup(func() { spareKeepWarm = prev })
}

// A spare that expires while requests are still arriving is replaced, so a
// request after a short pause still finds a warm worker; once the keep-warm
// window closes with no request the pool drains and stays empty (no endless
// container churn on an idle service).
func TestExpiredSparesAreRefilledWhileWarmAndNotWhenIdle(t *testing.T) {
	fastRetries(t)
	fastSpare(t)
	keepWarm(t, 1500*time.Millisecond)
	d := newFakeDocker(t, "ok")
	s := d.warm(t)
	answered(t, s)
	s.spares.started.Wait()
	first := len(d.runNames()) // its own + two spares
	time.Sleep(spareMaxAge + 300*time.Millisecond)
	s.spares.started.Wait()
	if got := len(d.runNames()); got <= first {
		t.Fatalf("no replacement spare started after the spares expired inside the keep-warm window (%d starts, %d before)", got, first)
	}
	if live := d.live(); len(live) == 0 {
		t.Fatal("the pool is empty right after an expiry inside the keep-warm window")
	}
	// Idle past the window: everything drains and no new worker is started.
	time.Sleep(spareKeepWarm + 2*spareMaxAge + 600*time.Millisecond)
	s.spares.started.Wait()
	removeRetries.Wait()
	if live := d.live(); len(live) != 0 {
		t.Fatalf("an idle service kept workers alive: %v", live)
	}
	settled := len(d.runNames())
	time.Sleep(2 * spareMaxAge)
	if got := len(d.runNames()); got != settled {
		t.Fatalf("an idle service kept starting workers: %d -> %d", settled, got)
	}
	counts := d.removeCounts()
	for _, n := range d.runNames() {
		if counts[n] < 1 {
			t.Errorf("container %s was never removed", n)
		}
	}
}

// runNames are the container names of every `run` the fake runtime saw, in order.
func (d *fakeDocker) runNames() []string {
	var out []string
	for _, l := range d.argv() {
		f := strings.Fields(l)
		if len(f) > 3 && f[0] == "run" && f[1] == "--name" {
			out = append(out, f[2])
		}
	}
	return out
}

// removeCounts is how many `rm --force <name>` each container received.
func (d *fakeDocker) removeCounts() map[string]int {
	out := map[string]int{}
	for _, l := range d.argv() {
		if n, ok := strings.CutPrefix(l, "rm --force "); ok {
			out[n]++
		}
	}
	return out
}

func warmInput() workerInput {
	return workerInput{Version: 1, Positions: []workerPosition{{Line: 1}}, Map: []byte("{}"), MapHash: model.HashCanonical([]byte("{}"))}
}

func (d *fakeDocker) warm(t *testing.T) *Service {
	t.Helper()
	d.config.WarmSpare = true
	return d.service(t)
}

func answered(t *testing.T, s *Service) {
	t.Helper()
	if got := s.runOne(context.Background(), warmInput()); got.Reason != Unmapped {
		t.Fatalf("fake worker answer: %+v", got)
	}
}

// A spare takes the container start off the request: after the first (cold)
// request one worker already waits; the second request is served by it and starts
// no container itself. Every worker serves exactly one request and is removed
// exactly once, and an unused spare does not outlive its age bound.
func TestWarmSpareServesExactlyOneRequestAndIsRemovedOnce(t *testing.T) {
	fastRetries(t)
	fastSpare(t)
	d := newFakeDocker(t, "ok")
	s := d.warm(t)

	answered(t, s) // cold: starts its own worker, then queues a spare
	s.spares.started.Wait()
	if got := len(d.runNames()); got != 3 {
		t.Fatalf("after the first request %d containers were started, want 3 (its own and one spare per request slot): %q", got, d.runNames())
	}
	if live := d.live(); len(live) != 2 || slices.Contains(live, d.runNames()[0]) {
		t.Fatalf("live containers %v, want only the two spares %v", live, d.runNames()[1:])
	}

	before := len(d.runNames())
	answered(t, s) // served by the spare
	s.spares.started.Wait()
	if grew := len(d.runNames()) - before; grew != 1 {
		t.Fatalf("the warm request started %d containers, want exactly the replacement spare: %q", grew, d.runNames())
	}

	time.Sleep(spareMaxAge + 400*time.Millisecond) // the replacement expires unused
	removeRetries.Wait()
	if live := d.live(); len(live) != 0 {
		t.Fatalf("containers left after the spare's age bound: %v", live)
	}
	names := d.runNames()
	counts := d.removeCounts()
	for _, n := range names {
		if counts[n] < 1 {
			t.Errorf("container %s was never removed: %v", n, counts)
		}
	}
	if len(names) != 4 {
		t.Fatalf("%d containers for 2 requests (3 starts at first, 1 refill) and 3 spares: %q", len(names), names)
	}
}

// An expired spare is never handed out: the next request starts its own worker.
func TestWarmSpareThatExpiredIsNotServed(t *testing.T) {
	fastRetries(t)
	fastSpare(t)
	d := newFakeDocker(t, "ok")
	s := d.warm(t)
	answered(t, s)
	s.spares.started.Wait()
	time.Sleep(spareMaxAge + 400*time.Millisecond)
	if live := d.live(); len(live) != 0 {
		t.Fatalf("the expired spare is still alive: %v", live)
	}
	before := len(d.runNames())
	answered(t, s)
	s.spares.started.Wait()
	if got := len(d.runNames()) - before; got != 3 {
		t.Fatalf("a request after the spares expired started %d containers, want its own plus a spare per slot (3)", got)
	}
	s.spares.started.Wait()
	time.Sleep(spareMaxAge + 400*time.Millisecond)
	removeRetries.Wait()
	if live := d.live(); len(live) != 0 {
		t.Fatalf("containers left: %v", live)
	}
}

// Without the option a request starts exactly one worker and leaves nothing.
func TestNoSpareWithoutTheOption(t *testing.T) {
	fastRetries(t)
	d := newFakeDocker(t, "ok")
	s := d.service(t)
	answered(t, s)
	answered(t, s)
	s.spares.started.Wait()
	if got := len(d.runNames()); got != 2 {
		t.Fatalf("%d containers for 2 requests: %q", got, d.runNames())
	}
	d.assertRemoved(t)
}

// The option only exists for the OCI launcher.
func TestWarmSpareIsRefusedOutsideOCIMode(t *testing.T) {
	d := newFakeDocker(t, "ok")
	c := d.config
	c.Mode, c.WarmSpare = "native", true
	if _, err := New(&unusedReader{}, unusedGenerations{}, c); err == nil {
		t.Fatal("warm_spare was accepted for a native service")
	}
}

// A burst as wide as the request slots finds a warm worker for every request:
// neither request starts a container on its own path, and each worker serves
// exactly one request.
func TestWarmSparesServeAConcurrentBurstOneEach(t *testing.T) {
	fastRetries(t)
	fastSpare(t)
	d := newFakeDocker(t, "ok")
	s := d.warm(t)
	answered(t, s)
	s.spares.started.Wait()
	spares := d.live()
	if len(spares) != 2 {
		t.Fatalf("%d spares waiting, want 2: %v", len(spares), spares)
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); answered(t, s) }()
	}
	wg.Wait()
	s.spares.started.Wait()
	names := d.runNames()
	// 1 cold + 2 spares, then 2 refills; the burst itself started nothing.
	if len(names) != 5 {
		t.Fatalf("%d containers, want 5 (cold, two spares, two refills): %q", len(names), names)
	}
	counts := d.removeCounts()
	for _, n := range spares {
		if counts[n] < 1 {
			t.Errorf("spare %s served a request and was not removed: %v", n, counts)
		}
	}
	time.Sleep(spareMaxAge + 400*time.Millisecond)
	removeRetries.Wait()
	if live := d.live(); len(live) != 0 {
		t.Fatalf("containers left: %v", live)
	}
}
