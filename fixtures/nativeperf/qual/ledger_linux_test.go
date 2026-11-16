//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"os"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func ledgerFixed() uint64 {
	// 1 target + 3 rings x 8 CPUs = 25 rings of (256 KiB + a page), plus 1 MiB + 256 KiB of per-target buffers
	return 25*(256<<10+uint64(os.Getpagesize())) + (1<<20 + 256<<10)
}

// The capture of the arithmetic tests: 1 target (one thread) on 8 CPUs, a helper that was 10 MiB and a harness that
// was 12 MiB resident when it was admitted, high-water marks of 24 and 27 MiB afterwards, a 32 MiB correlator.
func ledgerInput() LedgerInput {
	return LedgerInput{Config: nativeperf.DefaultConfig(1), Admission: AdmissionMemory{Targets: 1, Threads: 1, HelperRSS: 10 << 20, ClientRSS: 12 << 20},
		CPUs: 8, HelperHWM: 24 << 20, ClientHWM: 27 << 20, Correlator: 32 << 20}
}

// The arithmetic of one scheduler capture on the qualification hosts (1 target,
// 8 CPUs): 25 rings, the fixed buffers, the helper's and the harness's resident
// sizes at admission, plus the correlation reservation, against 64 MiB.
func TestCaptureMemoryLedgerArithmetic(t *testing.T) {
	fixed := ledgerFixed()
	l, err := CaptureMemoryLedger(ledgerInput())
	if err != nil {
		t.Fatal(err)
	}
	if l.Charge != fixed+22<<20 || l.ExtraRings != 0 || l.Nominal != l.Charge+32<<20 || l.Physical != fixed+51<<20 || l.Budget != 64<<20 || !l.NominalFits || !l.PhysicalFits || !l.ConsumerFits {
		t.Fatalf("%+v", l)
	}
	// the same capture with a harness that was 16 MiB resident: a full 32 MiB share no longer fits
	in := ledgerInput()
	in.Admission.ClientRSS = 16 << 20
	if l, err = CaptureMemoryLedger(in); err != nil || l.NominalFits {
		t.Fatalf("a 16 MiB resident harness leaves no room for the 32 MiB reservation: %+v %v", l, err)
	}
	in = ledgerInput()
	in.Admission.HelperRSS, in.Correlator = 64<<20, 0
	if _, err := CaptureMemoryLedger(in); err == nil {
		t.Fatal("a charge that alone exceeds the budget produced a ledger")
	}
}

// Everything the harness itself holds is in the nominal sum: the events it retained and the intervals the
// correlator returned, and the CPU rings the helper adds for every target thread beyond the first.
func TestCaptureMemoryLedgerCountsTheHarnessAndThreadRings(t *testing.T) {
	fixed := ledgerFixed()
	in := ledgerInput()
	in.Correlator, in.Retained, in.Intervals = 20<<20, 1<<20, 2<<20
	in.Admission.Threads = 3
	l, err := CaptureMemoryLedger(in)
	if err != nil {
		t.Fatal(err)
	}
	ring := uint64(256<<10 + os.Getpagesize())
	if l.ExtraRings != 2*ring || l.Nominal != fixed+22<<20+2*ring+20<<20+1<<20+2<<20 || l.Physical != fixed+51<<20+2*ring || !l.ConsumerFits {
		t.Fatalf("%+v", l)
	}
	in.Retained, in.Intervals = 3<<20, 2<<20 // 5 MiB against the 4 MiB allowance
	if l, err = CaptureMemoryLedger(in); err != nil || l.ConsumerFits {
		t.Fatalf("retained events and returned intervals over their allowance must not fit: %+v %v", l, err)
	}
	in.Retained, in.Intervals, in.Correlator = 4<<20, 0, 33<<20 // the allowance is met, the nominal sum is not
	if l, err = CaptureMemoryLedger(in); err != nil || !l.ConsumerFits || l.NominalFits {
		t.Fatalf("%+v %v", l, err)
	}
	// threads whose rings alone overflow the budget have no ledger
	in = ledgerInput()
	in.Admission.Threads = 256
	if _, err = CaptureMemoryLedger(in); err == nil {
		t.Fatal("256 thread rings cannot fit 64 MiB behind the capture's charge")
	}
}

// The product admits a profile capture with three working leases (14 + 8 + 2 MiB for one target) behind the
// admission charge. The ledger replays that through the real Reserve/ReserveWorking, reports what is left, and
// says whether the correlator reservation and the harness's own sets fit in it too.
func TestCaptureMemoryLedgerReplaysTheProductLeases(t *testing.T) {
	l, err := CaptureMemoryLedger(ledgerInput())
	if err != nil {
		t.Fatal(err)
	}
	if !l.ProductAdmits || l.Leases != 24<<20 || l.ProductRefusal != "" || l.ProductHeadroom != nativeperf.MaxMemoryBytes-l.Charge-24<<20 {
		t.Fatalf("%+v", l)
	}
	if l.CombinedFits {
		t.Fatalf("a 32 MiB correlator cannot fit the %d B left behind the leases: %+v", l.ProductHeadroom, l)
	}
	in := ledgerInput()
	in.Correlator = 8 << 20
	if l, err = CaptureMemoryLedger(in); err != nil || !l.CombinedFits {
		t.Fatalf("an 8 MiB correlator fits the %d B left behind the leases: %+v %v", l.ProductHeadroom, l, err)
	}
	// a 30 MiB harness: the leases are refused, and the ledger says so with the product's own refusal
	in = ledgerInput()
	in.Admission.ClientRSS, in.Correlator = 30<<20, 12<<20
	l, err = CaptureMemoryLedger(in)
	if err != nil || l.ProductAdmits || l.ProductRefusal == "" || l.CombinedFits || !l.NominalFits {
		t.Fatalf("%+v %v", l, err)
	}
	// the target's thread rings come out of what the leases leave
	in = ledgerInput()
	in.Admission.Threads = 3
	in.Correlator = 8 << 20
	if l, err = CaptureMemoryLedger(in); err != nil || l.ProductHeadroom != nativeperf.MaxMemoryBytes-l.Charge-24<<20-l.ExtraRings {
		t.Fatalf("%+v %v", l, err)
	}
}

// The correlator is handed what the admission charge leaves of the 64 MiB, up to 32
// MiB, less the allowance for the harness's own sets: a harness that was resident with
// 21 MiB (the 6.1 full acceptance run: charge 39.6 MB, which with a fixed 32 MiB share
// is 73 MB) gets the remaining share instead of overrunning the budget.
func TestCorrelationReservationIsWhatTheAdmissionChargeLeaves(t *testing.T) {
	cfg := nativeperf.DefaultConfig(1)
	fixed := ledgerFixed()
	got, err := CorrelationReservation(cfg, AdmissionMemory{Targets: 1, HelperRSS: 8 << 20, ClientRSS: 4 << 20}, 8)
	if err != nil || got != CorrelationReservationBytes {
		t.Fatalf("a small charge leaves more than the cap: %d %v", got, err)
	}
	m := AdmissionMemory{Targets: 1, HelperRSS: 11 << 20, ClientRSS: 21 << 20}
	got, err = CorrelationReservation(cfg, m, 8)
	if want := nativeperf.MaxMemoryBytes - (fixed + 32<<20) - ConsumerAllowanceBytes; err != nil || got != want || got >= CorrelationReservationBytes {
		t.Fatalf("got %d, want %d (%v)", got, want, err)
	}
	// the target's thread rings are charged before the share is derived
	m.Threads = 3
	ring := uint64(256<<10 + os.Getpagesize())
	if more, err := CorrelationReservation(cfg, m, 8); err != nil || more != got-2*ring {
		t.Fatalf("thread rings were not charged: %d vs %d (%v)", more, got, err)
	}
	if _, err := CorrelationReservation(cfg, AdmissionMemory{Targets: 1, HelperRSS: 64 << 20}, 8); err == nil {
		t.Fatal("no reservation exists when the charge alone fills the budget")
	}
	// a charge that leaves less than the allowance has nothing for the correlator either
	if _, err := CorrelationReservation(cfg, AdmissionMemory{Targets: 1, HelperRSS: 30 << 20, ClientRSS: 24 << 20}, 8); err == nil {
		t.Fatal("a charge that leaves less than the consumer allowance got a reservation")
	}
	// together with the charge the share always fits
	l, err := CaptureMemoryLedger(LedgerInput{Config: cfg, Admission: AdmissionMemory{Targets: 1, HelperRSS: 11 << 20, ClientRSS: 21 << 20}, CPUs: 8, HelperHWM: 24 << 20, ClientHWM: 27 << 20, Correlator: got})
	if err != nil || !l.NominalFits {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestCorrelateWithinConfiguresTheCorrelatorWithTheRemainingBudget(t *testing.T) {
	res, cycles := longCapture(200, true)
	cfg := nativeperf.DefaultConfig(1)
	c := CorrelateWithin(res, cfg, AdmissionMemory{Targets: 1, HelperRSS: 11 << 20, ClientRSS: 21 << 20})
	// longCapture's topology proof has 2 CPUs: 1 target + 6 rings
	fixed := 7*(256<<10+uint64(os.Getpagesize())) + (1<<20 + 256<<10)
	if want := nativeperf.MaxMemoryBytes - (fixed + 32<<20) - ConsumerAllowanceBytes; c.Err != "" || c.ReservationBytes != want {
		t.Fatalf("reservation %d, want %d: %+v", c.ReservationBytes, want, c)
	}
	if blocked, runnable := sumKinds(c); blocked != cycles*1_000_000 || runnable != cycles*1_000_000 {
		t.Fatalf("%d %d", blocked, runnable)
	}
	if c.IntervalBytes == 0 || c.IntervalBytes != IntervalsFootprint(c.Intervals) {
		t.Fatalf("the returned intervals were not measured: %d", c.IntervalBytes)
	}
	// a client so large that the budget has nothing left for the correlator: an explicit error, no intervals
	c = CorrelateWithin(res, cfg, AdmissionMemory{Targets: 1, HelperRSS: 20 << 20, ClientRSS: 43 << 20})
	if !strings.Contains(c.Err, "configure") && !strings.Contains(c.Err, "reservation") || len(c.Intervals) != 0 {
		t.Fatalf("%+v", c)
	}
}
