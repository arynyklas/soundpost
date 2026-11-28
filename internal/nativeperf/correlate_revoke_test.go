// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// When a stream ends on an identity error, nothing published after the last successful identity check is proven to belong to
// the authorized threads: the consumer revokes [provenAt, end) (lane 4 open item). RevokeFrom is that consumer side.

// What was drained and returned before provenAt stays; the correction starts at provenAt and reaches the end of the evidence.
func TestRevokeFromRevokesTheUnprovenTailOnly(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, true), correlationIn(20*corrMs))
	prior := drainCorrelation(t, c, []uint32{0}, 20*corrMs)
	if len(prior) != 1 || prior[0].Correction {
		t.Fatalf("prior: %+v", prior)
	}
	feedCorrelation(t, c, correlationOut(150*corrMs, false), correlationIn(180*corrMs))
	got, err := c.RevokeFrom(model.MonoNano(100 * corrMs))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].Correction || got[0].Kind != IntervalUnknown || got[0].Reason != ReasonGeneration || got[0].Task != (TaskKey{}) {
		t.Fatalf("want one domain-wide generation correction: %+v", got)
	}
	if got[0].Start != model.MonoNano(100*corrMs) || got[0].End < model.MonoNano(180*corrMs) {
		t.Fatalf("the correction must be [provenAt, end), not [0, end): %+v", got[0])
	}
	if e := got[0].Validate(); e != nil {
		t.Fatal(e)
	}
	if s := c.Stats(); s.HeapEvents != 0 || s.TaskStates != 0 {
		t.Fatalf("unproven evidence retained: %+v", s)
	}
}

// A wait that began before provenAt and is still open, and an event buffered from before it, can no longer be vouched for: the
// correction reaches back to the earliest of them rather than leaving a hole between the proven prefix and provenAt.
func TestRevokeFromReachesBackToEvidenceItCannotVouchFor(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(50*corrMs, false))
	drainCorrelation(t, c, []uint32{0}, 50*corrMs)
	if c.Stats().TaskStates != 1 {
		t.Fatalf("setup: %+v", c.Stats())
	}
	feedCorrelation(t, c, correlationIn(150*corrMs))
	got, err := c.RevokeFrom(model.MonoNano(100 * corrMs))
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Start != model.MonoNano(50*corrMs) || got[0].End < model.MonoNano(150*corrMs) {
		t.Fatalf("open wait from 50 ms not covered: %+v", got[0])
	}
	c = configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(60*corrMs, false), correlationIn(70*corrMs))
	got, err = c.RevokeFrom(model.MonoNano(100 * corrMs))
	if err != nil || len(got) != 1 || got[0].Start != model.MonoNano(60*corrMs) {
		t.Fatalf("buffered pre-provenAt events not covered: %+v %v", got, err)
	}
}

// The stream has ended: the correlator takes nothing more and cannot be finalized as complete.
func TestRevokeFromEndsTheCorrelation(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(0, true))
	if _, err := c.RevokeFrom(10 * model.MonoNano(corrMs)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Consume(correlationIn(20 * corrMs)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("consume after revoke: %v", err)
	}
	if _, err := c.Finalize(model.MonoNano(20 * corrMs)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finalize after revoke: %v", err)
	}
	if _, err := c.RevokeFrom(0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := NewCorrelator(DefaultConfig(1)).RevokeFrom(0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoke before Configure: %v", err)
	}
}

// Nothing was ever proven (from == 0): the whole epoch is revoked, as every other domain-wide correction does.
func TestRevokeFromZeroRevokesTheWholeEpoch(t *testing.T) {
	c := configuredCorrelation(t, 0)
	feedCorrelation(t, c, correlationOut(5*corrMs, true), correlationIn(9*corrMs))
	got, err := c.RevokeFrom(0)
	if err != nil || len(got) != 1 || got[0].Start != 0 || got[0].End < model.MonoNano(9*corrMs) {
		t.Fatalf("%+v %v", got, err)
	}
}
