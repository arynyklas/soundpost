//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A stream that ends on an identity error says when its identity was last proven, on the event clock, so the consumer can
// revoke [provenThrough, end) (Correlator.RevokeFrom) instead of nothing, or everything.

// provenSource is a cpuSource whose identity verification is the test's: it passes until fail is set.
func provenSource(fail *error) *cpuSource {
	return &cpuSource{domain: correlationDomain, threads: []cpuThread{{task: correlationTask(), start: 1}}, verify: func() error { return *fail }}
}

func TestIdentityErrorCarriesTheLastSuccessfulCheckOnTheEventClock(t *testing.T) {
	var fail error
	c := provenSource(&fail)
	before, err := schedulerNow()
	if err != nil {
		t.Fatal(err)
	}
	if e := c.checkIdentity(); e != nil {
		t.Fatal(e)
	}
	after, _ := schedulerNow()
	if c.provenMono < before || c.provenMono > after {
		t.Fatalf("provenMono %d outside [%d, %d]", c.provenMono, before, after)
	}
	proven := c.provenMono
	fail = ErrThreadCoverageChanged
	e := c.checkIdentity()
	var identity *IdentityError
	if !errors.Is(e, ErrThreadCoverageChanged) || !errors.As(e, &identity) || identity.ProvenThrough != proven {
		t.Fatalf("the failed check lost when it last succeeded: %v (%+v), want %d", e, identity, proven)
	}
	if ProvenThroughOf(e) != proven || c.provenMono != proven {
		t.Fatalf("a failed check moved the proof: %d -> %d", proven, c.provenMono)
	}
	// the cause survives for callers that match it directly
	fail = ErrTargetIdentity
	if e := c.checkIdentity(); !errors.Is(e, ErrTargetIdentity) || ProvenThroughOf(e) != proven {
		t.Fatal(e)
	}
}

func TestIdentityErrorOfAnAcquisitionThatNeverProvedItselfProvesNothing(t *testing.T) {
	fail := ErrThreadCoverageChanged
	c := provenSource(&fail)
	e := c.checkIdentity()
	if !errors.Is(e, ErrThreadCoverageChanged) || ProvenThroughOf(e) != 0 {
		t.Fatalf("%v proven through %d", e, ProvenThroughOf(e))
	}
	if ProvenThroughOf(errors.New("other")) != 0 || ProvenThroughOf(nil) != 0 {
		t.Fatal("a plain error proves nothing")
	}
}

func TestExitedTaskErrorCarriesTheProof(t *testing.T) {
	var fail error
	c := provenSource(&fail)
	if e := c.checkIdentity(); e != nil {
		t.Fatal(e)
	}
	c.gone = func(TaskKey) (bool, error) { return true, nil }
	e := c.taskStillLive(correlationTask())
	if !errors.Is(e, ErrThreadCoverageChanged) || ProvenThroughOf(e) != c.provenMono || c.provenMono == 0 {
		t.Fatalf("%v proven through %d, want %d", e, ProvenThroughOf(e), c.provenMono)
	}
}

type failingIdentitySource struct{ err error }

func (s failingIdentitySource) Next(context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, s.err
}
func (s failingIdentitySource) Close() error { return nil }

// The helper streams the instant with the closed error code and the consumer side rebuilds the typed error.
func TestIdentityProofCrossesTheHelperSocket(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		proven model.MonoNano
		want   error
	}{
		{"thread coverage", &IdentityError{Err: ErrThreadCoverageChanged, ProvenThrough: 123456789}, 123456789, ErrThreadCoverageChanged},
		{"target identity", &IdentityError{Err: ErrTargetIdentity, ProvenThrough: 5}, 5, ErrTargetIdentity},
		{"never proven", &IdentityError{Err: ErrThreadCoverageChanged}, 0, ErrThreadCoverageChanged},
		{"not an identity error", ErrRingOverwrite, 0, ErrRingOverwrite},
	} {
		client, server := cpuSocketPair(t)
		done := make(chan struct{})
		go func() {
			defer close(done)
			streamHelperEvents(context.Background(), server, failingIdentitySource{tc.err})
			server.Close()
		}()
		var ready helperReply
		if e := readMessage(client, &ready); e != nil || !ready.Ready {
			t.Fatal(tc.name, "missing ready", e)
		}
		_, e := (&socketSource{conn: client}).Next(context.Background())
		if !errors.Is(e, tc.want) || ProvenThroughOf(e) != tc.proven {
			t.Fatalf("%s: got %v proven through %d, want %v / %d", tc.name, e, ProvenThroughOf(e), tc.want, tc.proven)
		}
		<-done
	}
}
