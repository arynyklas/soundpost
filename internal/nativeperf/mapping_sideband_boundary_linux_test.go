//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"sync/atomic"
	"testing"
	"unsafe"
)

// Pins for the mapping sideband sweep (l4w33 mutation battery A).

// Whatever a sweep returns carries the domain it was asked for, and a record the decoder refuses fails the whole sweep
// with that error and no partial result.
func TestSweepRingsStampsTheDomainAndFailsOnADecodeError(t *testing.T) {
	domain := ClockDomain{HostID: "host", BootID: "boot"}
	r := sidebandRing("aa11cc22")
	push(r, mmap2Record(defaultMmap2()))
	events, full, err := sweepRings([]*Ring{r}, domain)
	if err != nil || full || len(events) != 1 || events[0].Domain != domain {
		t.Fatalf("%+v %v %v", events, full, err)
	}

	bad := sidebandRing("aa11cc22")
	good := defaultMmap2()
	push(bad, mmap2Record(good))
	foreign := defaultMmap2()
	foreign.pid, foreign.tid = 71, 72 // not the ring's own thread
	foreign.at = good.at + 1
	push(bad, mmap2Record(foreign))
	events, full, err = sweepRings([]*Ring{bad}, domain)
	if !errors.Is(err, ErrTargetIdentity) || events != nil || full {
		t.Fatalf("events %+v, full %v, err %v: want no events, not full and ErrTargetIdentity", events, full, err)
	}
}

// Announcements of the same instant keep the order of the rings they came from.
func TestSweepRingsKeepsRingOrderForEqualTimes(t *testing.T) {
	first, second := defaultMmap2(), defaultMmap2()
	first.at, second.at = 500, 500
	first.addr, second.addr = 0x7f0000010000, 0x7f0000020000
	rings := func() (*Ring, *Ring) {
		a, b := sidebandRing("aa11cc22"), sidebandRing("aa11cc22")
		push(a, mmap2Record(first))
		push(b, mmap2Record(second))
		return a, b
	}
	a, b := rings()
	events, _, err := sweepRings([]*Ring{a, b}, ClockDomain{HostID: "host", BootID: "boot"})
	if err != nil || len(events) != 2 || uint64(events[0].Mapping.Start) != first.addr || uint64(events[1].Mapping.Start) != second.addr {
		t.Fatalf("%+v %v", events, err)
	}
	a, b = rings()
	events, _, err = sweepRings([]*Ring{b, a}, ClockDomain{HostID: "host", BootID: "boot"})
	if err != nil || len(events) != 2 || uint64(events[0].Mapping.Start) != second.addr || uint64(events[1].Mapping.Start) != first.addr {
		t.Fatalf("%+v %v", events, err)
	}
}

// The build IDs a mapping may name are those the operator approved for exactly that process; the list handed out is a
// copy.
func TestApprovedBuildsAreThoseOfTheTargetAndACopy(t *testing.T) {
	a := AuthorizedTargets{targets: []Target{{TGID: 1, AllowedBuildIDs: []string{"aa11"}}, {TGID: 2, AllowedBuildIDs: []string{"bb22", "cc33"}}}}
	got := a.approvedBuilds(2)
	if len(got) != 2 || got[0] != "bb22" || got[1] != "cc33" {
		t.Fatalf("%v", got)
	}
	got[0] = "tampered"
	if again := a.approvedBuilds(2); again[0] != "bb22" || a.targets[1].AllowedBuildIDs[0] != "bb22" {
		t.Fatalf("the operator's list was aliased: %v", again)
	}
	if one := a.approvedBuilds(1); len(one) != 1 || one[0] != "aa11" {
		t.Fatalf("%v", one)
	}
	if none := a.approvedBuilds(3); len(none) != 0 {
		t.Fatalf("%v", none)
	}
}

// A source that has failed or was closed sweeps nothing: it reports why, and a healthy one sweeps its rings.
func TestSourcesSweepSidebandOnlyWhileTheyAreLive(t *testing.T) {
	domain := ClockDomain{HostID: "host", BootID: "boot"}
	ring := func() *Ring {
		r := sidebandRing("aa11cc22")
		push(r, mmap2Record(defaultMmap2()))
		return r
	}
	failure := errors.New("identity lost")
	closed := make(chan struct{})
	close(closed)
	t.Run("cpu", func(t *testing.T) {
		live := &cpuSource{done: make(chan struct{}), rings: []*Ring{ring()}, domain: domain}
		if events, full, err := live.sweepSideband(); err != nil || full || len(events) != 1 || events[0].Domain != domain {
			t.Fatalf("%+v %v %v", events, full, err)
		}
		failed := &cpuSource{done: make(chan struct{}), rings: []*Ring{ring()}, domain: domain, terminal: failure}
		if events, _, err := failed.sweepSideband(); !errors.Is(err, failure) || events != nil {
			t.Fatalf("%+v %v", events, err)
		}
		gone := &cpuSource{done: closed, rings: []*Ring{ring()}, domain: domain}
		if events, _, err := gone.sweepSideband(); !errors.Is(err, ErrAcquisitionClosed) || events != nil {
			t.Fatalf("%+v %v", events, err)
		}
	})
	t.Run("scheduler", func(t *testing.T) {
		live := &schedulerSource{done: make(chan struct{}), cpu: &cpuSource{rings: []*Ring{ring()}, domain: domain}}
		if events, full, err := live.sweepSideband(); err != nil || full || len(events) != 1 || events[0].Domain != domain {
			t.Fatalf("%+v %v %v", events, full, err)
		}
		failed := &schedulerSource{done: make(chan struct{}), cpu: &cpuSource{rings: []*Ring{ring()}, domain: domain}, terminal: failure}
		if events, _, err := failed.sweepSideband(); !errors.Is(err, failure) || events != nil {
			t.Fatalf("%+v %v", events, err)
		}
		gone := &schedulerSource{done: closed, cpu: &cpuSource{rings: []*Ring{ring()}, domain: domain}}
		if events, _, err := gone.sweepSideband(); !errors.Is(err, ErrAcquisitionClosed) || events != nil {
			t.Fatalf("%+v %v", events, err)
		}
	})
}

// The consumer marks a record it hands out before it decodes it: one the decoder refused stays in the ring (the
// consumer reports the failure and stops) and a later sweep does not hand it out again.
func TestSidebandConsumeMarksTheRecordItHandsOut(t *testing.T) {
	r := sidebandRing("aa11cc22")
	// the ring is not at its start: a record's offset is larger than its own length
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1024])), 1000)
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1032])), 1000)
	foreign := defaultMmap2()
	foreign.pid, foreign.tid = 71, 72
	push(r, mmap2Record(foreign))
	err := drainRing(r, func(SanitizedEvent) error { return nil })
	if !errors.Is(err, ErrTargetIdentity) {
		t.Fatalf("%v", err)
	}
	if r.tail() != 1000 {
		t.Fatalf("the refused record was consumed (tail %d)", r.tail())
	}
	if events, full, err := sweepRings([]*Ring{r}, ClockDomain{HostID: "host", BootID: "boot"}); err != nil || full || len(events) != 0 {
		t.Fatalf("a record the consumer already handed out was swept again: %+v %v %v", events, full, err)
	}
}
