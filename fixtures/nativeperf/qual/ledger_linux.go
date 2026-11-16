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

// AdmissionMemory is what one capture's admission charges besides its rings: the
// targets of the request and the resident sizes (bytes) of the helper and of this
// process, the exporting peer, when the capture was admitted.
type AdmissionMemory struct{ Targets, HelperRSS, ClientRSS uint64 }

// CorrelationReservation is the share of the aggregate budget the correlator is
// handed: CorrelationReservationBytes, but never more than cfg.MaxMemory minus the
// capture's admission charge (rings with their metadata pages, per-target buffers,
// the helper's and the exporting peer's resident size). A capture whose charge
// alone fills the budget has no reservation (an error); one that leaves less than
// the correlator needs overflows its bounded buffer explicitly and fails its rows.
func CorrelationReservation(cfg nativeperf.Config, m AdmissionMemory, cpus uint64) (uint64, error) {
	charge, err := nativeperf.CaptureCharge(true, m.Targets, cpus, cfg, uint64(os.Getpagesize()), nativeperf.MemoryUsage{HelperRSS: m.HelperRSS, ExportRSS: m.ClientRSS})
	if err != nil {
		return 0, fmt.Errorf("the capture's own charge does not fit the budget: %w", err)
	}
	return min(CorrelationReservationBytes, cfg.MaxMemory-charge), nil
}

// MemoryLedger is the memory arithmetic of one scheduler capture, in bytes.
//
// Nominal: what the helper's own reservation charges at the moment it admits the
// capture (every ring with its metadata page, the fixed per-target buffers, the
// helper's and the exporting peer's resident size then) plus the reservation the
// correlator was handed. This is the sum the aggregate budget must cover.
//
// Physical: the measured resident high-water marks of the helper and of this
// process after the capture (the correlator's real allocation and the harness's
// retained events are inside the client's), plus the rings and per-target buffers
// again. It double counts the rings (they are resident in the helper) on purpose.
type MemoryLedger struct {
	Charge, Correlator, Nominal  uint64
	HelperHWM, ClientHWM         uint64
	Physical, Budget             uint64
	NominalFits, PhysicalFits    bool
	TargetCount, CPUs, PageBytes uint64
}

// CaptureMemoryLedger computes the ledger of one off-CPU capture whose correlator
// was handed reserved bytes. helperRSS and clientRSS are the resident sizes when
// the capture was admitted, the HWMs the high-water marks afterwards (bytes).
func CaptureMemoryLedger(cfg nativeperf.Config, targets, cpus, helperRSS, clientRSS, helperHWM, clientHWM, reserved uint64) (MemoryLedger, error) {
	page := uint64(os.Getpagesize())
	l := MemoryLedger{Correlator: reserved, HelperHWM: helperHWM, ClientHWM: clientHWM, Budget: cfg.MaxMemory, TargetCount: targets, CPUs: cpus, PageBytes: page}
	charge, err := nativeperf.CaptureCharge(true, targets, cpus, cfg, page, nativeperf.MemoryUsage{HelperRSS: helperRSS, ExportRSS: clientRSS})
	if err != nil {
		return l, fmt.Errorf("the capture's own charge does not fit the budget: %w", err)
	}
	fixed, err := nativeperf.CaptureCharge(true, targets, cpus, cfg, page, nativeperf.MemoryUsage{})
	if err != nil {
		return l, err
	}
	l.Charge = charge
	l.Nominal = charge + l.Correlator
	l.Physical = helperHWM + clientHWM + fixed
	l.NominalFits = l.Nominal <= l.Budget
	l.PhysicalFits = l.Physical <= l.Budget
	return l, nil
}

// Detail is the ledger as report fields.
func (l MemoryLedger) Detail() map[string]any {
	return map[string]any{
		"budget_bytes": l.Budget, "targets": l.TargetCount, "cpus": l.CPUs,
		"admission_charge_bytes": l.Charge, "correlation_reservation_bytes": l.Correlator, "nominal_total_bytes": l.Nominal, "nominal_fits": l.NominalFits,
		"helper_hwm_bytes": l.HelperHWM, "client_hwm_bytes": l.ClientHWM, "physical_total_bytes": l.Physical, "physical_fits": l.PhysicalFits,
	}
}
