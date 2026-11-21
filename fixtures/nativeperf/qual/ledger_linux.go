//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"fmt"
	"os"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// CorrelationReservationBytes is the most the harness hands the Correlator out of
// the 64 MiB aggregate budget (nativeperf.MaxMemoryBytes): the correlator turns it
// into about 1000 buffered events (16 KiB of reservation per event slot and per
// task slot), which is the 100 ms reorder window of a contended CPU at several
// thousand scheduler events per second. The reservation is nominal and
// conservative: the correlator's physical worst case at that size is a few MiB (see
// TestCorrelatorPhysicalWorstCaseFitsItsReservation in internal/nativeperf).
// CorrelationReservation lowers it to what the capture's admission charge leaves.
const CorrelationReservationBytes uint64 = 32 << 20

// ConsumerAllowanceBytes is what the harness sets aside, out of the same budget, for
// everything it holds besides the correlator's reorder buffer: the CPU-sample and
// loss events it retains for the row judges (it streams every scheduler event
// through the correlator and keeps none of them) and the intervals the correlator
// returns, which it keeps without their stacks (StreamCorrelation.DropStacks) and, for a judge that only adds up
// durations, folded per thread and kind (FoldDurations). The ledger measures both after the capture and the rows fail
// when they outgrew this allowance. It was 4 MiB while the harness retained the intervals whole; every byte it does
// not hold is a byte of the correlator's reorder buffer (D52: the harness's own admission shrinks, the product's
// 8 KiB slot charge and the 64 MiB budget do not move).
const ConsumerAllowanceBytes uint64 = 5 << 19

// AdmissionMemory is what one capture's admission charges besides its rings: the
// targets of the request, the threads they had when it was admitted (each one gets
// its own CPU ring beyond the first) and the resident sizes (bytes) of the helper
// and of this process, the exporting peer, at that moment.
type AdmissionMemory struct{ Targets, Threads, HelperRSS, ClientRSS uint64 }

func (m AdmissionMemory) usage() nativeperf.MemoryUsage {
	return nativeperf.MemoryUsage{HelperRSS: m.HelperRSS, ExportRSS: m.ClientRSS}
}

// admissionCharge is the helper's Reserve charge of the capture plus the CPU rings
// the helper adds for every target thread beyond the one per target it started with
// (ReserveCPURings), against the budget.
func admissionCharge(cfg nativeperf.Config, m AdmissionMemory, cpus uint64) (charge, extraRings uint64, err error) {
	page := uint64(os.Getpagesize())
	charge, err = nativeperf.CaptureCharge(true, m.Targets, cpus, cfg, page, m.usage())
	if err != nil {
		return 0, 0, fmt.Errorf("the capture's own charge does not fit the budget: %w", err)
	}
	if m.Threads > m.Targets {
		extraRings = (m.Threads - m.Targets) * (cfg.RingBytes + page)
	}
	if extraRings > cfg.MaxMemory-charge {
		return 0, 0, fmt.Errorf("the capture's %d thread rings do not fit the budget: %w", m.Threads, nativeperf.ErrResourceBudget)
	}
	return charge, extraRings, nil
}

// CorrelationReservation is the share of the aggregate budget the correlator is
// handed (D40): CorrelationReservationBytes, but never more than cfg.MaxMemory minus
// every other working set of the same capture: its admission charge (rings with their
// metadata pages, per-target buffers, the helper's and the exporting peer's resident
// size, the per-thread rings), the product's ProfileSource working leases and the
// ConsumerAllowanceBytes. A capture whose charge, leases and allowance do not fit the
// budget is refused here, at admission, with nativeperf.ErrResourceBudget
// (resource_limit): a measured excess is a defect, never a reported number.
func CorrelationReservation(cfg nativeperf.Config, m AdmissionMemory, cpus uint64) (uint64, error) {
	charge, extra, err := admissionCharge(cfg, m, cpus)
	if err != nil {
		return 0, err
	}
	mapping, assembly, export := nativeperf.ProfileWorkingBytes(m.Targets)
	leases := mapping + assembly + export
	if cfg.MaxMemory-charge-extra < leases+ConsumerAllowanceBytes {
		return 0, fmt.Errorf("nothing is left for the correlator after the admission charge, the ProfileSource leases (%d B) and the consumer allowance: %w", leases, nativeperf.ErrResourceBudget)
	}
	return min(CorrelationReservationBytes, cfg.MaxMemory-charge-extra-leases-ConsumerAllowanceBytes), nil
}

// LedgerInput is everything the ledger of one scheduler capture is computed from:
// the admission snapshot, the correlator's reservation and what the harness
// measured after the capture (resident high-water marks, the bytes of retained
// events and of returned intervals).
type LedgerInput struct {
	Config               nativeperf.Config
	Admission            AdmissionMemory
	CPUs                 uint64
	HelperHWM, ClientHWM uint64
	Correlator           uint64
	Retained, Intervals  uint64
}

// MemoryLedger is the memory arithmetic of one scheduler capture, in bytes.
//
// Nominal: what the helper's own reservation charges at the moment it admits the
// capture (every ring with its metadata page, the fixed per-target buffers, the
// helper's and the exporting peer's resident size then), the CPU rings of the
// target's other threads, the ProfileSource working leases (D40), the reservation the correlator was handed and the
// harness's own working sets measured afterwards: the events it retained and the
// intervals the correlator returned (both must fit ConsumerAllowanceBytes). This is
// the sum the aggregate budget must cover.
//
// Physical: the measured resident high-water marks of the helper and of this
// process after the capture (the correlator's real allocation, the retained events
// and the returned intervals are inside the client's), plus the rings and per-target
// buffers again. It double counts the rings (they are resident in the helper) on
// purpose.
//
// Product: the same capture admitted the way the product admits a profile
// capture, with the three ProfileSource working leases (map-read scratch, assembly,
// export) that sit on top of the admission charge. ProductHeadroom is what the real
// Reserve and ReserveWorking leave of the budget; ProductAdmits says the leases fit;
// CombinedFits says the leases, the correlator reservation and the consumer's own
// sets all fit together (D40: they have to, CorrelationReservation refuses the capture otherwise).
type MemoryLedger struct {
	Charge, ExtraRings, Correlator, Retained, Intervals uint64
	Nominal                                             uint64
	HelperHWM, ClientHWM                                uint64
	Physical, Budget                                    uint64
	NominalFits, PhysicalFits, ConsumerFits             bool
	TargetCount, Threads, CPUs, PageBytes               uint64
	Leases, ProductHeadroom                             uint64
	ProductAdmits, CombinedFits                         bool
	ProductRefusal                                      string
}

// CaptureMemoryLedger computes the ledger of one off-CPU capture.
func CaptureMemoryLedger(in LedgerInput) (MemoryLedger, error) {
	page := uint64(os.Getpagesize())
	cfg, m := in.Config, in.Admission
	l := MemoryLedger{Correlator: in.Correlator, Retained: in.Retained, Intervals: in.Intervals, HelperHWM: in.HelperHWM, ClientHWM: in.ClientHWM, Budget: cfg.MaxMemory,
		TargetCount: m.Targets, Threads: m.Threads, CPUs: in.CPUs, PageBytes: page}
	charge, extra, err := admissionCharge(cfg, m, in.CPUs)
	if err != nil {
		return l, err
	}
	fixed, err := nativeperf.CaptureCharge(true, m.Targets, in.CPUs, cfg, page, nativeperf.MemoryUsage{})
	if err != nil {
		return l, err
	}
	l.Charge, l.ExtraRings = charge, extra
	mapping, assembly, export := nativeperf.ProfileWorkingBytes(m.Targets)
	l.Leases = mapping + assembly + export
	l.Nominal = charge + extra + l.Leases + l.Correlator + l.Retained + l.Intervals
	l.Physical = in.HelperHWM + in.ClientHWM + fixed + extra
	l.NominalFits = l.Nominal <= l.Budget
	l.PhysicalFits = l.Physical <= l.Budget
	l.ConsumerFits = l.Retained+l.Intervals <= ConsumerAllowanceBytes
	headroom, err := nativeperf.ProfileAdmissionHeadroom(cfg, true, m.Targets, in.CPUs, page, m.usage())
	switch {
	case err != nil:
		l.ProductRefusal = err.Error()
	case extra > headroom:
		l.ProductRefusal = "the leases leave no room for the target's thread rings"
	default:
		l.ProductAdmits, l.ProductHeadroom = true, headroom-extra
		l.CombinedFits = l.Correlator+l.Retained+l.Intervals <= l.ProductHeadroom
	}
	return l, nil
}

// Detail is the ledger as report fields.
func (l MemoryLedger) Detail() map[string]any {
	return map[string]any{
		"budget_bytes": l.Budget, "targets": l.TargetCount, "target_threads": l.Threads, "cpus": l.CPUs,
		"admission_charge_bytes": l.Charge, "extra_thread_rings_bytes": l.ExtraRings, "correlation_reservation_bytes": l.Correlator,
		"retained_events_bytes": l.Retained, "returned_intervals_bytes": l.Intervals, "consumer_allowance_bytes": ConsumerAllowanceBytes, "consumer_fits": l.ConsumerFits,
		"nominal_total_bytes": l.Nominal, "nominal_fits": l.NominalFits,
		"helper_hwm_bytes": l.HelperHWM, "client_hwm_bytes": l.ClientHWM, "physical_total_bytes": l.Physical, "physical_fits": l.PhysicalFits,
		"profile_source_leases_bytes": l.Leases, "product_admits_leases": l.ProductAdmits, "product_headroom_after_leases_bytes": l.ProductHeadroom,
		"product_refusal": l.ProductRefusal, "leases_and_correlator_fit_together": l.CombinedFits,
	}
}
