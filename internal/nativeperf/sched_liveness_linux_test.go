//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The decision "this per-CPU event stopped counting" is pure arithmetic over two reads and two clock instants; its
// boundaries are pinned here so that no kernel, root or hotplug is needed to see them (the real-kernel behaviour is in
// hotplug_linux_test.go).
func TestEnabledKeptDecision(t *testing.T) {
	const ms = uint64(time.Millisecond)
	const m = model.MonoNano(ms)
	for _, tc := range []struct {
		name         string
		prev, now    uint64
		prevAt, then model.MonoNano
		want         bool
	}{
		{"counting the whole 100 ms", 500 * ms, 600 * ms, 1000 * m, 1100 * m, true},
		{"counting a bit more than the interval", 500 * ms, 601 * ms, 1000 * m, 1100 * m, true},
		{"short by the slack and the rate allowance only", 500 * ms, 599 * ms, 1000 * m, 1100 * m, true},
		{"off for the last 10 ms", 500 * ms, 590 * ms, 1000 * m, 1100 * m, false},
		{"off since the previous read", 500 * ms, 500 * ms, 1000 * m, 1100 * m, false},
		{"off for 3 ms of 100", 500 * ms, 597 * ms, 1000 * m, 1100 * m, false},
		{"counter went backwards", 500 * ms, 499 * ms, 1000 * m, 1100 * m, false},
		{"nothing provably elapsed", 500 * ms, 500 * ms, 1100 * m, 1100 * m, true},
		{"clock stepped back", 500 * ms, 500 * ms, 1200 * m, 1100 * m, true},
		{"first read after a start", 0, 120 * ms, 1000 * m, 1100 * m, true},
		{"first read of an event that never counted", 0, 0, 1000 * m, 1100 * m, false},
	} {
		if got := enabledKept(tc.prev, tc.now, tc.prevAt, tc.then); got != tc.want {
			t.Errorf("%s: enabledKept(%d, %d, %d, %d) = %v, want %v", tc.name, tc.prev, tc.now, tc.prevAt, tc.then, got, tc.want)
		}
	}
}

// livenessFixture is a scheduler source over fake rings whose online set the test drives and whose enabled time behaves
// like the kernel's: it is the clock since the event was enabled, frozen at the instant the event is stopped.
type livenessFixture struct {
	src     *schedulerSource
	online  []uint32
	since   model.MonoNano
	stopped map[*Ring]model.MonoNano
	readErr error
}

func newLivenessFixture(t *testing.T, cpus ...uint32) *livenessFixture {
	t.Helper()
	f := &livenessFixture{online: cpus, stopped: map[*Ring]model.MonoNano{}}
	src := &schedulerSource{done: make(chan struct{}), cpus: append([]uint32(nil), cpus...), cpu: &cpuSource{domain: correlationDomain, verify: func() error { return nil }}}
	for _, cpu := range cpus {
		for range 3 {
			src.rings = append(src.rings, schedulerRing{ring: &Ring{}, cpu: cpu})
		}
	}
	src.onlineCPUs = func() ([]uint32, error) { return append([]uint32(nil), f.online...), nil }
	src.enabledOf = func(r *Ring) (uint64, error) {
		if f.readErr != nil {
			return 0, f.readErr
		}
		end := f.stopped[r]
		if end == 0 {
			now, e := schedulerNow()
			if e != nil {
				return 0, e
			}
			end = now
		}
		return uint64(end - f.since), nil
	}
	f.src = src
	start, e := schedulerNow()
	if e != nil {
		t.Fatal(e)
	}
	f.since, src.start = start, start
	src.live.arm(start, len(src.rings))
	return f
}

func (f *livenessFixture) stop(rings ...*Ring) {
	now, _ := schedulerNow()
	for _, r := range rings {
		f.stopped[r] = now
	}
}

// round lets the clock run for wait (the dead rings stop half way through it), then runs one verification that is due.
func (f *livenessFixture) round(wait time.Duration, dead ...*Ring) error {
	time.Sleep(wait / 2)
	f.stop(dead...)
	time.Sleep(wait / 2)
	f.src.live.at = time.Time{} // the enabled-time round is due
	return f.src.verify(false)
}

func TestSchedulerVerifyPassesAndMovesTheProofWhileEveryEventCounts(t *testing.T) {
	f := newLivenessFixture(t, 0, 1, 2, 3)
	var last model.MonoNano
	for i := range 3 {
		if e := f.round(120 * time.Millisecond); e != nil {
			t.Fatalf("round %d: %v", i, e)
		}
		if p := f.src.provenThrough(); p <= last {
			t.Fatalf("round %d: the proven instant did not advance (%d after %d)", i, p, last)
		}
		last = f.src.provenThrough()
	}
}

func TestSchedulerTopologyErrorsCarryTheLastProvenInstant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(f *livenessFixture) error
	}{
		{"a CPU left the online set", func(f *livenessFixture) error {
			f.online = []uint32{0, 1, 2}
			return f.round(30 * time.Millisecond)
		}},
		{"a CPU joined the online set", func(f *livenessFixture) error {
			f.online = []uint32{0, 1, 2, 3, 4}
			return f.round(30 * time.Millisecond)
		}},
		{"the set is unchanged but every event of one CPU stopped counting (offline and back)", func(f *livenessFixture) error {
			return f.round(120*time.Millisecond, f.src.rings[9].ring, f.src.rings[10].ring, f.src.rings[11].ring)
		}},
		{"a single event of one CPU stopped counting", func(f *livenessFixture) error {
			return f.round(120*time.Millisecond, f.src.rings[4].ring)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLivenessFixture(t, 0, 1, 2, 3)
			// a healthy round first, so there is a proven instant to carry
			if e := f.round(120 * time.Millisecond); e != nil {
				t.Fatal(e)
			}
			proven := f.src.provenThrough()
			if proven == 0 {
				t.Fatal("fixture: nothing proven")
			}
			before, _ := schedulerNow()
			e := tc.break_(f)
			if !errors.Is(e, ErrTopologyChanged) {
				t.Fatalf("got %v, want %v", e, ErrTopologyChanged)
			}
			if got := ProvenThroughOf(e); got != proven || got >= before {
				t.Fatalf("error proves the topology through %d, want exactly the last good round %d (and before %d)", got, proven, before)
			}
			if helperErrorCode(e) != "topology_changed" {
				t.Fatalf("closed code %q", helperErrorCode(e))
			}
		})
	}
}

func TestSchedulerVerifyReadFailureIsAnExplicitFailureNotAPass(t *testing.T) {
	f := newLivenessFixture(t, 0, 1)
	if e := f.round(120 * time.Millisecond); e != nil {
		t.Fatal(e)
	}
	f.readErr = ErrAcquisitionFailed
	if e := f.round(120 * time.Millisecond); !errors.Is(e, ErrAcquisitionFailed) {
		t.Fatalf("an unreadable event passed the check: %v", e)
	}
}

// The enabled-time round is throttled: between two rounds a stalled event is not looked at (the cost of the check is
// bounded by the CPU count per interval, not by the event rate), and Stop forces a round whatever the throttle says.
func TestSchedulerLivenessRoundIsThrottledAndForcedAtStop(t *testing.T) {
	f := newLivenessFixture(t, 0, 1)
	if e := f.round(120 * time.Millisecond); e != nil {
		t.Fatal(e)
	}
	proven := f.src.provenThrough()
	reads := 0
	inner := f.src.enabledOf
	f.src.enabledOf = func(r *Ring) (uint64, error) { reads++; return inner(r) }
	// inside the interval: no reads, the proof of the events does not move
	if e := f.src.verify(false); e != nil || reads != 0 {
		t.Fatalf("a check inside the interval read %d events: %v", reads, e)
	}
	if f.src.provenThrough() != proven {
		t.Fatalf("the proven instant moved without a round: %d -> %d", proven, f.src.provenThrough())
	}
	time.Sleep(30 * time.Millisecond)
	if e := f.src.verify(true); e != nil || reads != len(f.src.rings) {
		t.Fatalf("a forced check read %d of %d events: %v", reads, len(f.src.rings), e)
	}
}

// Stop makes the final proof possible, so it looks at the events itself, whatever the throttle says: an event that stopped
// counting since the last round ends the capture instead of being disabled and certified. (The fake rings have no
// descriptor: a Stop that got as far as disabling them would panic.)
func TestSchedulerStopRunsAFreshLivenessRound(t *testing.T) {
	f := newLivenessFixture(t, 0, 1, 2, 3)
	if e := f.round(120 * time.Millisecond); e != nil {
		t.Fatal(e)
	}
	proven := f.src.provenThrough()
	f.stop(f.src.rings[7].ring)
	time.Sleep(150 * time.Millisecond)
	f.src.live.at = time.Now() // the periodic round is not due: only a forced one can see the stopped event
	e := f.src.Stop()
	if !errors.Is(e, ErrTopologyChanged) || ProvenThroughOf(e) != proven {
		t.Fatalf("Stop with a stopped event returned %v (proven through %d), want %v through %d", e, ProvenThroughOf(e), ErrTopologyChanged, proven)
	}
	if f.src.terminal == nil || f.src.stopped {
		t.Fatalf("the capture was marked stopped (%v) or not terminal (%v) although its coverage was gone", f.src.stopped, f.src.terminal)
	}
}
