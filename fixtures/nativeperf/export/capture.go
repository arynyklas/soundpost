//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	// schedulerWindow is the longest a scheduler capture streams before the fixture
	// (the unprivileged session) asks the helper to stop; the helper then ends the
	// stream with its final drained-prefix proof and a completion frame.
	schedulerWindow = 2 * time.Second
	// assemblyItems is when the capture stops early: the assembler charges 32 KiB for every event and
	// interval it is given against its 8 MiB working set (at most 255 together), and the intervals
	// still in flight at the stop are bounded by the proofs already received.
	assemblyItems = 160
	// correlatorBytes is the exclusive reservation the session's correlator gets.
	correlatorBytes = 8 << 20
)

type helperReply struct {
	Event    *nativeperf.SanitizedEvent   `json:"event"`
	Proof    *nativeperf.AcquisitionProof `json:"proof"`
	Error    string                       `json:"error"`
	Ready    bool                         `json:"ready"`
	Complete bool                         `json:"complete"`
}

// schedulerStats is what the correlator and the stream produced, in counts.
type schedulerStats struct {
	SwitchEvents    int    `json:"switch_events"`
	WakeupEvents    int    `json:"wakeup_events"`
	LossEvents      int    `json:"loss_events"`
	ProgressProofs  int    `json:"progress_proofs"`
	CPUs            int    `json:"cpus"`
	ConsumeErrors   int    `json:"consume_errors"`
	Blocked         int    `json:"blocked_intervals_returned"`
	Runnable        int    `json:"runnable_intervals_returned"`
	Unknown         int    `json:"unknown_intervals_returned"`
	Censored        int    `json:"censored_intervals_returned"`
	Corrections     int    `json:"coverage_corrections_returned"`
	CPUKind         int    `json:"cpu_kind_intervals_not_handed_to_assembly"`
	FinalProof      bool   `json:"final_proof_received"`
	PeakHeapEvents  int    `json:"correlator_peak_heap_events"`
	MaxHeapEvents   int    `json:"correlator_max_heap_events"`
	FirstConsumeErr string `json:"first_consume_error,omitempty"`
}

// sessionCorrelation applies the helper's acquisition proofs and events to one
// per-session Correlator in stream order: the initial topology proof configures
// it, each progress proof reports every CPU drained and advances it, the final
// proof reports every CPU and finalizes it. Nothing is inferred: a stream
// without both the initial and the final proof yields no intervals.
type sessionCorrelation struct {
	cfg       nativeperf.Config
	c         *nativeperf.Correlator
	initial   bool
	final     bool
	intervals []nativeperf.Interval
	stats     schedulerStats
}

func (s *sessionCorrelation) add(got []nativeperf.Interval) {
	for _, i := range got {
		switch {
		case i.Correction:
			s.stats.Corrections++
		case i.Kind == nativeperf.IntervalBlocked:
			s.stats.Blocked++
		case i.Kind == nativeperf.IntervalRunnable:
			s.stats.Runnable++
		case i.Kind == nativeperf.IntervalUnknown:
			s.stats.Unknown++
		case i.Kind == nativeperf.IntervalCensored:
			s.stats.Censored++
		case i.Kind == nativeperf.IntervalCPU:
			// The assembler never turns a native CPU interval into a second sample (it skips it) but
			// still charges it against the assembly budget, so the session does not hand it over.
			s.stats.CPUKind++
			continue
		}
		s.intervals = append(s.intervals, i)
	}
}

func (s *sessionCorrelation) proof(p nativeperf.AcquisitionProof) error {
	switch {
	case p.Final:
		if !s.initial || s.final {
			return errors.New("final_proof_without_topology")
		}
		s.final = true
		s.stats.FinalProof = true
		s.stats.PeakHeapEvents, s.stats.MaxHeapEvents = s.c.Stats().PeakHeapEvents, s.c.Stats().MaxHeapEvents
		for _, cpu := range p.CPUs {
			if e := s.c.ReportProgress(cpu, p.Through); e != nil {
				return errors.New("correlator_progress_refused")
			}
		}
		got, e := s.c.Finalize(p.Through)
		s.add(got)
		if e != nil {
			return errors.New("correlator_finalize_refused")
		}
	case p.Progress:
		if !s.initial || s.final {
			return errors.New("progress_proof_without_topology")
		}
		for _, cpu := range p.CPUs {
			if e := s.c.ReportProgress(cpu, p.Through); e != nil {
				return errors.New("correlator_progress_refused")
			}
		}
		got, e := s.c.Advance(p.Through)
		s.add(got)
		if e != nil {
			return errors.New("correlator_advance_refused")
		}
		s.stats.ProgressProofs++
	default:
		if s.initial {
			return errors.New("duplicate_topology_proof")
		}
		s.initial = true
		s.stats.CPUs = len(p.CPUs)
		s.c = nativeperf.NewCorrelator(s.cfg)
		if e := s.c.Configure(p.Domain, p.CPUs, correlatorBytes); e != nil {
			return errors.New("correlator_configure_refused")
		}
	}
	return nil
}

// event consumes a scheduler event and reports whether the capture keeps it
// for assembly (never a switch or wakeup: the correlator owns what it needs).
func (s *sessionCorrelation) event(e nativeperf.SanitizedEvent) (keep bool, err error) {
	switch {
	case e.Switch != nil:
		s.stats.SwitchEvents++
	case e.Wakeup != nil:
		s.stats.WakeupEvents++
	default:
		if e.Loss != nil {
			s.stats.LossEvents++
		}
		return true, nil
	}
	if !s.initial || s.final {
		return false, errors.New("scheduler_event_outside_proven_stream")
	}
	got, e2 := s.c.Consume(e)
	s.add(got)
	if e2 != nil {
		s.stats.ConsumeErrors++
		if s.stats.FirstConsumeErr == "" {
			s.stats.FirstConsumeErr = e2.Error()
		}
	}
	return false, nil
}

// fixtureLease is the exporter's own 2 MiB working reservation. A completed scheduler stream has
// released the acquisition's reservations, and the exporter is a separate budget from the helper's.
type fixtureLease struct{}

func (fixtureLease) Bytes() uint64 { return 2 << 20 }
func (fixtureLease) Close() error  { return nil }

// readScheduler streams a CPU+scheduler capture: it keeps the CPU samples and
// loss events, feeds every scheduler event and proof to the session correlator,
// asks the helper to stop after schedulerWindow, and returns once the helper's
// completion frame has arrived after its final proof.
func readScheduler(conn *net.UnixConn, c nativeperf.Config, result *realCapture) error {
	corr := &sessionCorrelation{cfg: c}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			frameWrite(conn, struct {
				Stop bool `json:"stop"`
			}{true})
		})
	}
	timer := time.AfterFunc(schedulerWindow, stop)
	defer timer.Stop()
	conn.SetReadDeadline(time.Now().Add(schedulerWindow + 30*time.Second))
	for {
		var reply helperReply
		if e := frameRead(conn, &reply); e != nil {
			return errors.New("real_capture_transport_failed")
		}
		switch {
		case reply.Error != "" || reply.Ready:
			return errors.New("real_capture_refused_or_invalid")
		case reply.Complete:
			if !corr.final {
				return errors.New("helper_completed_without_final_proof")
			}
			result.Intervals, result.Scheduler = corr.intervals, corr.stats
			return nil
		case reply.Proof != nil:
			if !corr.initial {
				// The stream is live: the mapping identities are taken now, because the helper closes
				// the acquisition (and with it the source) when it completes the stream.
				result.Mappings = result.Source.FramesMappings()
			}
			if e := corr.proof(*reply.Proof); e != nil {
				return e
			}
			if len(result.Events)+len(corr.intervals) >= assemblyItems {
				stop()
			}
		case reply.Event != nil:
			if reply.Event.Validate() != nil {
				return errors.New("real_capture_refused_or_invalid")
			}
			keep, e := corr.event(*reply.Event)
			if e != nil {
				return e
			}
			if keep {
				result.Events = append(result.Events, *reply.Event)
			}
			if len(result.Events)+len(corr.intervals) >= assemblyItems {
				stop()
			}
		default:
			return errors.New("real_capture_refused_or_invalid")
		}
	}
}
