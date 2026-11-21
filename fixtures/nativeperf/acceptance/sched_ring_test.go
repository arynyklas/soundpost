//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// bufferedSlots is how many scheduler events the Correlator may buffer when the harness hands it the share its admission
// leaves (the product's own Configure turns the reservation into slots).
func bufferedSlots(t *testing.T, cfg nativeperf.Config, adm qual.AdmissionMemory) int {
	t.Helper()
	share, err := qual.CorrelationReservation(cfg, adm, 8)
	if err != nil {
		t.Fatal(err)
	}
	cpus := make([]uint32, 8)
	for i := range cpus {
		cpus[i] = uint32(i)
	}
	c := nativeperf.NewCorrelator(cfg)
	if err := c.Configure(nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}, cpus, share); err != nil {
		t.Fatal(err)
	}
	return c.Stats().MaxHeapEvents
}

// Wave 18: runqueue_split (contend) failed 4 of 12 acceptance runs on 6.1 and 6.6 with one correlator overflow
// ("native resource budget exceeded"), 449-562 events buffered at the overflow, while the passing runs peaked at 481-605
// events in a share of 668-763 slots. The share is what the 64 MiB budget leaves after the admission charge (resident sizes
// of the helper and of this process at admission, 25 rings), the ProfileSource leases and the consumer allowance, so a run
// whose helper and harness were a few MiB larger at admission got fewer slots than the capture needs. The harness's own ring
// size is part of its admission (D52): at the admission of the failing runs the share has to hold the busiest observed
// window, with room, and that is not so with the product's default 256 KiB rings.
func TestSchedulerRingsLeaveTheCorrelatorRoomForTheBusiestObservedWindowAtTheLargerAdmissions(t *testing.T) {
	const busiestObserved = 605
	// 22 MiB of resident size at admission (9 MiB helper, 13 MiB this process), larger than the 19.5-20.5 MiB of the passing
	// runs' charges and about what the failing runs had
	adm := qual.AdmissionMemory{Targets: 1, Threads: 3, HelperRSS: 9 << 20, ClientRSS: 13 << 20}
	cfg := nativeperf.DefaultConfig(1)
	cfg.RingBytes = schedulerRingBytes
	got := bufferedSlots(t, cfg, adm)
	if got < busiestObserved*11/10 {
		t.Errorf("the scheduler rings (%d KiB) leave the correlator %d buffered events, less than the busiest observed window of %d with 10%% room", schedulerRingBytes>>10, got, busiestObserved)
	}
	def := nativeperf.DefaultConfig(1)
	if base := bufferedSlots(t, def, adm); base >= busiestObserved {
		t.Errorf("the product's default rings already leave %d events, so the smaller rings are not what this admission needed", base)
	}
	if page := uint64(os.Getpagesize()); schedulerRingBytes < page || schedulerRingBytes&(schedulerRingBytes-1) != 0 || schedulerRingBytes > def.RingBytes {
		t.Errorf("scheduler ring %d is not a power of two between the page size %d and the product default %d", schedulerRingBytes, page, def.RingBytes)
	}
}

// The ledger of a scheduler capture is computed from the configuration the capture ran with: with rings smaller than the
// product default the admission charge and the correlator's share are both smaller rings' worth, and a ledger that
// assumed the default rings would count 25 rings of 128 KiB twice over and fail a capture that fits (wave 18, first
// run with the smaller rings: nominal 68.3 MB against 67.1 MB while the real charge was 3 MB lower).
func TestSchedulerLedgerChargesTheRingSizeTheCaptureRan(t *testing.T) {
	cfg := nativeperf.DefaultConfig(1)
	cfg.RingBytes = schedulerRingBytes
	sc := contendScenario(2, 1_000_000, 1_000_000)
	sc.Cfg = cfg
	share, err := qual.CorrelationReservation(cfg, sc.Admission, 8)
	if err != nil {
		t.Fatal(err)
	}
	sc.Corr.ReservationBytes = share
	a := newAccept()
	a.results["sched_contend"] = sc
	a.deriveSchedulerFromCaptures(a.res, map[string]any{})
	if a.res.RunqueueSplit.State != qual.StateSupported {
		t.Fatalf("a capture whose share was derived from its own rings did not fit its ledger: %+v", a.res.RunqueueSplit)
	}
	ledger, _ := a.res.RunqueueSplit.Detail["memory_ledger"].(map[string]any)
	if got, want := ledger["admission_charge_bytes"], uint64(25*(schedulerRingBytes+4096))+(1<<20+256<<10)+sc.Admission.HelperRSS+sc.Admission.ClientRSS; got != want {
		t.Errorf("admission charge %v, want %v: the ledger charged other rings than the capture ran", got, want)
	}
}
