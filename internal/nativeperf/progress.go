// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
)

var ErrProgressRequired = errors.New("native profiling: explicit acquisition progress consumer required")
var ErrTopologyChanged = errors.New("native profiling: CPU topology changed; restart capture")
var ErrSourceComplete = errors.New("native profiling: stopped source completely drained")

// AcquisitionProof is an explicit, never-inferred drained-prefix proof. The
// first non-final proof of a stream configures the complete CPU topology; every
// later non-final proof has Progress set and certifies that every scheduler and
// CPU stream on every listed CPU was read through Through (boot clock) with all
// admitted records at or before it already delivered; the final proof closes
// the stream. Progress proofs are what lets a consumer drain its bounded
// correlation buffer during a capture instead of only after it.
type AcquisitionProof struct {
	Domain   ClockDomain    `json:"domain"`
	CPUs     []uint32       `json:"cpus"`
	Through  model.MonoNano `json:"through"`
	Final    bool           `json:"final"`
	Progress bool           `json:"progress,omitempty"`
}

// AcquisitionItem is an explicit, bounded union. Proof is never a timestamp
// inferred from a sample; a live stream carries the initial topology proof,
// periodic Progress proofs while its streams are drained, and the final proof.
type AcquisitionItem struct {
	Event *SanitizedEvent
	Proof *AcquisitionProof
}

func (p AcquisitionProof) valid() bool {
	if !p.Domain.valid() || len(p.CPUs) == 0 || len(p.CPUs) > 256 || p.Through == 0 || p.Progress && p.Final {
		return false
	}
	for i, cpu := range p.CPUs {
		if i > 0 && cpu <= p.CPUs[i-1] {
			return false
		}
	}
	return true
}

// NextItem preserves explicit topology/progress/final barriers. Callers apply
// every Progress proof to ReportProgress and Advance where it arrives (that is
// what drains the bounded correlation buffer), and consume all events before
// applying the final proof to ReportProgress and Finalize. The initial proof
// configures the complete topology; Through bounds the fully-enabled start.
func (s *Session) NextItem(ctx context.Context) (AcquisitionItem, error) {
	if s == nil || s.source == nil {
		return AcquisitionItem{}, ErrAcquisitionPending
	}
	if source, ok := s.source.(interface {
		NextItem(context.Context) (AcquisitionItem, error)
	}); ok {
		return source.NextItem(ctx)
	}
	e, err := s.source.Next(ctx)
	if err != nil {
		return AcquisitionItem{}, err
	}
	return AcquisitionItem{Event: &e}, nil
}
func (s *Session) Stop() error {
	if s == nil || s.source == nil {
		return ErrAcquisitionPending
	}
	if source, ok := s.source.(interface{ Stop() error }); ok {
		return source.Stop()
	}
	return &CapabilityError{Unsupported, ReasonEvent}
}
