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

// The arithmetic of one scheduler capture on the qualification hosts (1 target,
// 8 CPUs): 25 rings, the fixed buffers, the helper's and the harness's resident
// sizes at admission, plus the correlation reservation, against 64 MiB.
func TestCaptureMemoryLedgerArithmetic(t *testing.T) {
	fixed := ledgerFixed()
	l, err := CaptureMemoryLedger(nativeperf.DefaultConfig(1), 1, 8, 10<<20, 12<<20, 24<<20, 27<<20, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if l.Charge != fixed+22<<20 || l.Nominal != l.Charge+32<<20 || l.Physical != fixed+51<<20 || l.Budget != 64<<20 || !l.NominalFits || !l.PhysicalFits {
		t.Fatalf("%+v", l)
	}
	// the same capture with a harness that was 16 MiB resident: a full 32 MiB share no longer fits
	l, err = CaptureMemoryLedger(nativeperf.DefaultConfig(1), 1, 8, 10<<20, 16<<20, 24<<20, 27<<20, 32<<20)
	if err != nil || l.NominalFits {
		t.Fatalf("a 16 MiB resident harness leaves no room for the 32 MiB reservation: %+v %v", l, err)
	}
	if _, err := CaptureMemoryLedger(nativeperf.DefaultConfig(1), 1, 8, 64<<20, 12<<20, 24<<20, 27<<20, 0); err == nil {
		t.Fatal("a charge that alone exceeds the budget produced a ledger")
	}
}

// The correlator is handed what the admission charge leaves of the 64 MiB, up to 32
// MiB: a harness that was resident with 21 MiB (the 6.1 full acceptance run: charge
// 39.6 MB, which with a fixed 32 MiB share is 73 MB) gets the remaining 25 MiB
// instead of overrunning the budget.
func TestCorrelationReservationIsWhatTheAdmissionChargeLeaves(t *testing.T) {
	cfg := nativeperf.DefaultConfig(1)
	fixed := ledgerFixed()
	got, err := CorrelationReservation(cfg, AdmissionMemory{Targets: 1, HelperRSS: 10 << 20, ClientRSS: 12 << 20}, 8)
	if err != nil || got != CorrelationReservationBytes {
		t.Fatalf("a small charge leaves more than the cap: %d %v", got, err)
	}
	got, err = CorrelationReservation(cfg, AdmissionMemory{Targets: 1, HelperRSS: 11 << 20, ClientRSS: 21 << 20}, 8)
	if want := nativeperf.MaxMemoryBytes - (fixed + 32<<20); err != nil || got != want || got >= CorrelationReservationBytes {
		t.Fatalf("got %d, want %d (%v)", got, want, err)
	}
	if _, err := CorrelationReservation(cfg, AdmissionMemory{Targets: 1, HelperRSS: 64 << 20}, 8); err == nil {
		t.Fatal("no reservation exists when the charge alone fills the budget")
	}
	// together with the charge the share always fits
	l, err := CaptureMemoryLedger(cfg, 1, 8, 11<<20, 21<<20, 24<<20, 27<<20, got)
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
	if want := nativeperf.MaxMemoryBytes - (fixed + 32<<20); c.Err != "" || c.ReservationBytes != want {
		t.Fatalf("reservation %d, want %d: %+v", c.ReservationBytes, want, c)
	}
	if blocked, runnable := sumKinds(c); blocked != cycles*1_000_000 || runnable != cycles*1_000_000 {
		t.Fatalf("%d %d", blocked, runnable)
	}
	// a client so large that the budget has nothing left for the correlator: an explicit error, no intervals
	c = CorrelateWithin(res, cfg, AdmissionMemory{Targets: 1, HelperRSS: 20 << 20, ClientRSS: 43 << 20})
	if !strings.Contains(c.Err, "configure") && !strings.Contains(c.Err, "reservation") || len(c.Intervals) != 0 {
		t.Fatalf("%+v", c)
	}
}
