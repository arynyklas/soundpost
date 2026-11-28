//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package realcapture

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// The scheduler capture hands the assembler intervals only from a proven stream: nothing is inferred from events alone.
func TestSessionCorrelationYieldsNothingWithoutItsProofs(t *testing.T) {
	cfg := nativeperf.DefaultConfig(1)
	domain := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	switched := nativeperf.SanitizedEvent{Kind: nativeperf.EventSwitch, Domain: domain, Switch: &nativeperf.SchedulerSwitch{}}

	// A final proof before any topology proof is refused, and nothing was produced.
	s := &sessionCorrelation{cfg: cfg}
	if s.proof(nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: 10, Final: true}) == nil {
		t.Fatal("a final proof without a topology proof was accepted")
	}
	if len(s.intervals) != 0 || s.stats.FinalProof {
		t.Fatalf("a refused proof produced evidence: %+v", s.stats)
	}

	// A scheduler event before the topology proof is refused and is not kept for assembly.
	s = &sessionCorrelation{cfg: cfg}
	keep, err := s.event(switched)
	if err == nil || keep {
		t.Fatalf("a switch before the topology proof: keep=%v err=%v", keep, err)
	}

	// The topology proof once; a second one is refused. The final proof then closes the stream.
	s = &sessionCorrelation{cfg: cfg}
	topology := nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: 5}
	if err = s.proof(topology); err != nil {
		t.Fatalf("topology proof: %v", err)
	}
	if s.proof(topology) == nil {
		t.Fatal("a second topology proof was accepted")
	}
	if err = s.proof(nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: 20, Final: true}); err != nil {
		t.Fatalf("final proof: %v", err)
	}
	if !s.stats.FinalProof || s.stats.CPUs != 1 {
		t.Fatalf("stats after the final proof: %+v", s.stats)
	}
	// A stream that has ended takes no further scheduler event.
	if keep, err = s.event(switched); err == nil || keep {
		t.Fatalf("a switch after the final proof: keep=%v err=%v", keep, err)
	}
	// Loss is kept for assembly and never touches the correlator.
	if keep, err = s.event(nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Domain: domain, Loss: &nativeperf.LossEvent{}}); err != nil || !keep || s.stats.LossEvents != 1 {
		t.Fatalf("a loss event: keep=%v err=%v stats=%+v", keep, err, s.stats)
	}
}
