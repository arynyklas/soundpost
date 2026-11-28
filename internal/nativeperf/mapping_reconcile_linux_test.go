//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Pins for the reconciliation feed of ProfileSource (l4w33 mutation battery A).

type plainSource struct{}

func (plainSource) Next(context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, ErrSourceComplete
}
func (plainSource) Close() error { return nil }

func otherEpochProcess() ProcessKey {
	p := epochProcess()
	p.TGID = 99
	return p
}

// An announcement is fed to the prediction of the process it names and to no other; snapshot rows (the helper's own
// reads), confirmations, events of other kinds and events without a mapping are never predictions.
func TestAnnounceFeedsOnlyTheProcessItNamesAndOnlyAnnouncements(t *testing.T) {
	s := &ProfileSource{recon: []*reconciler{{process: epochProcess()}, {process: otherEpochProcess()}}}
	own, other := s.recon[0], s.recon[1]

	s.announce(mapEvent(1, 500, 0x10000, 0x20000, 0x2000, libB, ""))
	if len(own.pending) != 1 || len(other.pending) != 0 {
		t.Fatalf("own %d, other %d pending announcements, want 1 and 0", len(own.pending), len(other.pending))
	}
	got := own.pending[0]
	if got.at != 500 || got.m.Start != 0x10000 || got.m.End != 0x20000 || got.m.BuildID != libB || got.m.FileOffset != 0x2000 {
		t.Fatalf("pending %+v: the announcement did not arrive whole", got)
	}

	// an announcement of the other process reaches only the other process
	foreign := mapEvent(2, 600, 0x30000, 0x31000, 0, libC, "")
	foreign.Mapping.Process = otherEpochProcess()
	s.announce(foreign)
	if len(own.pending) != 1 || len(other.pending) != 1 || other.pending[0].at != 600 {
		t.Fatalf("own %d, other %d pending announcements, want 1 and 1", len(own.pending), len(other.pending))
	}

	// not announcements
	s.announce(snapRow(3, 100, 700, 0x10000, 0x20000, 0, libA, ""))
	s.announce(confirm(4, 100, 700))
	s.announce(SanitizedEvent{Kind: EventMapping, Time: 800})
	s.announce(SanitizedEvent{Kind: EventCPU, Time: 900, Mapping: &MappingUpdate{Process: epochProcess(), Start: 1, End: 2}})
	if len(own.pending) != 1 || len(other.pending) != 1 {
		t.Fatalf("own %d, other %d pending announcements after events that are none, want 1 and 1", len(own.pending), len(other.pending))
	}
}

// A sweep that dropped announcements ends with a ring overflow: at the first announcement it did return, or at the
// sample when it returned none. The announcements it did return feed the predictions.
func TestSweepNowReportsTheOverflowAtTheFirstAnnouncementOrTheSample(t *testing.T) {
	domain := epochDomain()
	ann := func(at model.MonoNano) SanitizedEvent {
		e := mapEvent(0, at, 0x10000, 0x11000, 0, libB, "")
		e.Domain = domain
		return e
	}
	t.Run("without announcements", func(t *testing.T) {
		s := &ProfileSource{source: &sweepingSource{swept: [][]SanitizedEvent{nil}, full: []bool{true}}, domain: domain}
		got, err := s.sweepNow(77)
		if err != nil || len(got) != 1 {
			t.Fatalf("%+v %v", got, err)
		}
		if got[0].Kind != EventLoss || got[0].Time != 77 || got[0].Domain != domain || got[0].Loss == nil || got[0].Loss.Count != 1 || got[0].Loss.Reason != ReasonLoss {
			t.Fatalf("%+v", got[0])
		}
	})
	t.Run("with announcements", func(t *testing.T) {
		s := &ProfileSource{source: &sweepingSource{swept: [][]SanitizedEvent{{ann(50), ann(60)}}, full: []bool{true}}, domain: domain, recon: []*reconciler{{process: epochProcess()}}}
		got, err := s.sweepNow(77)
		if err != nil || len(got) != 3 {
			t.Fatalf("%+v %v", got, err)
		}
		if got[0].Kind != EventMapping || got[1].Kind != EventMapping || got[2].Kind != EventLoss || got[2].Time != 50 {
			t.Fatalf("%+v", got)
		}
		if n := len(s.recon[0].pending); n != 2 {
			t.Fatalf("%d announcements reached the prediction, want 2 (the overflow is not one)", n)
		}
	})
	t.Run("complete sweep has no overflow", func(t *testing.T) {
		s := &ProfileSource{source: &sweepingSource{swept: [][]SanitizedEvent{{ann(50)}}, full: []bool{false}}, domain: domain}
		got, err := s.sweepNow(77)
		if err != nil || len(got) != 1 || got[0].Kind != EventMapping {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("a source that cannot sweep", func(t *testing.T) {
		s := &ProfileSource{source: plainSource{}, domain: domain}
		got, err := s.sweepNow(77)
		if err != nil || got != nil {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("a failed sweep is the caller's failure", func(t *testing.T) {
		want := errors.New("ring overwritten")
		s := &ProfileSource{source: &sweepingSource{sweepFn: func() error { return want }}, domain: domain}
		if got, err := s.sweepNow(77); !errors.Is(err, want) || got != nil {
			t.Fatalf("%+v %v", got, err)
		}
	})
}
