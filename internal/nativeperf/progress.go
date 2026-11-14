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

type AcquisitionProof struct {
	Domain  ClockDomain    `json:"domain"`
	CPUs    []uint32       `json:"cpus"`
	Through model.MonoNano `json:"through"`
	Final   bool           `json:"final"`
}

// AcquisitionItem is an explicit, bounded union. Proof is never a timestamp
// inferred from a sample. Live streams intentionally provide no progress proof.
type AcquisitionItem struct {
	Event *SanitizedEvent
	Proof *AcquisitionProof
}

func (p AcquisitionProof) valid() bool {
	if !p.Domain.valid() || len(p.CPUs) == 0 || len(p.CPUs) > 256 {
		return false
	}
	for i, cpu := range p.CPUs {
		if i > 0 && cpu <= p.CPUs[i-1] {
			return false
		}
	}
	return true
}

// NextItem preserves explicit topology/final barriers. Callers consume all events
// before applying the final proof to ReportProgress and Finalize. Initial proof
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
