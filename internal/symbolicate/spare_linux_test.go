//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func fastSpare(t *testing.T) {
	t.Helper()
	prev := spareMaxAge
	spareMaxAge = 500 * time.Millisecond
	t.Cleanup(func() { spareMaxAge = prev })
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
	if got := len(d.runNames()); got != 2 {
		t.Fatalf("after the first request %d containers were started, want 2 (its own and the spare): %q", got, d.runNames())
	}
	if live := d.live(); len(live) != 1 || live[0] != d.runNames()[1] {
		t.Fatalf("live containers %v, want only the spare %s", live, d.runNames()[1])
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
	if len(names) != 3 {
		t.Fatalf("%d containers for 2 requests and 1 expired spare: %q", len(names), names)
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
	if got := len(d.runNames()) - before; got != 1 {
		t.Fatalf("a request after the spare expired started %d workers itself, want 1", got)
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
