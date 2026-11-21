//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package realcapture

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// correlatorBytes is the exclusive reservation the session's correlator gets.
const correlatorBytes = 8 << 20

type schedulerReply struct {
	Event    *nativeperf.SanitizedEvent   `json:"event"`
	Proof    *nativeperf.AcquisitionProof `json:"proof"`
	Error    string                       `json:"error"`
	Ready    bool                         `json:"ready"`
	Complete bool                         `json:"complete"`
}

// sessionCorrelation applies the helper's acquisition proofs and events to one per-session Correlator in stream order: the initial topology proof
// configures it, each progress proof reports every CPU drained and advances it, the final proof reports every CPU and finalizes it. Nothing is
// inferred: a stream without both the initial and the final proof yields no intervals.
type sessionCorrelation struct {
	cfg       nativeperf.Config
	c         *nativeperf.Correlator
	initial   bool
	final     bool
	intervals []nativeperf.Interval
	stats     SchedulerStats
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
			// The assembler never turns a native CPU interval into a second sample (it skips it) but still charges it against the
			// assembly budget, so the capture does not hand it over.
			continue
		}
		s.intervals = append(s.intervals, i)
	}
}

func (s *sessionCorrelation) proof(p nativeperf.AcquisitionProof) error {
	switch {
	case p.Final:
		if !s.initial || s.final {
			return errors.New("final proof without a topology proof")
		}
		s.final = true
		s.stats.FinalProof = true
		for _, cpu := range p.CPUs {
			if e := s.c.ReportProgress(cpu, p.Through); e != nil {
				return errors.New("correlator refused the final progress report")
			}
		}
		got, e := s.c.Finalize(p.Through)
		s.add(got)
		if e != nil {
			return errors.New("correlator refused to finalize")
		}
	case p.Progress:
		if !s.initial || s.final {
			return errors.New("progress proof outside the proven stream")
		}
		for _, cpu := range p.CPUs {
			if e := s.c.ReportProgress(cpu, p.Through); e != nil {
				return errors.New("correlator refused a progress report")
			}
		}
		got, e := s.c.Advance(p.Through)
		s.add(got)
		if e != nil {
			return errors.New("correlator refused to advance")
		}
		s.stats.ProgressProofs++
	default:
		if s.initial {
			return errors.New("duplicate topology proof")
		}
		s.initial = true
		s.stats.CPUs = len(p.CPUs)
		s.c = nativeperf.NewCorrelator(s.cfg)
		if e := s.c.Configure(p.Domain, p.CPUs, correlatorBytes); e != nil {
			return errors.New("correlator refused its topology")
		}
	}
	return nil
}

// event consumes a scheduler event and reports whether the capture keeps it for assembly (never a switch or wakeup: the correlator owns what
// it needs).
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
		return false, errors.New("scheduler event outside the proven stream")
	}
	got, e2 := s.c.Consume(e)
	s.add(got)
	if e2 != nil {
		s.stats.ConsumeErrors++
	}
	return false, nil
}

// readScheduler streams a CPU+scheduler capture: it keeps the CPU samples and loss events, feeds every scheduler event and proof to the session
// correlator, asks the helper to stop after `seconds` (or SchedulerItems kept events and intervals), and returns once the helper's completion
// frame has arrived after its final proof.
func readScheduler(conn *net.UnixConn, cfg nativeperf.Config, source *nativeperf.ProfileSource, seconds int, res *Result) error {
	corr := &sessionCorrelation{cfg: cfg}
	var once sync.Once
	stop := func() {
		once.Do(func() {
			frameWrite(conn, struct {
				Stop bool `json:"stop"`
			}{true})
		})
	}
	timer := time.AfterFunc(time.Duration(seconds)*time.Second, stop)
	defer timer.Stop()
	conn.SetReadDeadline(time.Now().Add(time.Duration(seconds)*time.Second + 30*time.Second))
	for {
		var reply schedulerReply
		if e := frameRead(conn, &reply); e != nil {
			return errors.New("scheduler capture transport failed: " + e.Error())
		}
		switch {
		case reply.Error != "" || reply.Ready:
			return errors.New("scheduler capture refused or invalid: " + reply.Error)
		case reply.Complete:
			if !corr.final {
				return errors.New("the helper completed without a final proof")
			}
			res.Intervals, res.Scheduler = corr.intervals, corr.stats
			if len(res.Events) == 0 {
				return errors.New("no genuine CPU observation arrived")
			}
			return nil
		case reply.Proof != nil:
			if !corr.initial {
				// The stream is live: the mapping identities are taken now, because the helper closes the acquisition (and with it the
				// source) when it completes the stream.
				res.Mappings = source.FramesMappings()
			}
			if e := corr.proof(*reply.Proof); e != nil {
				return e
			}
		case reply.Event != nil:
			if reply.Event.Validate() != nil {
				return errors.New("scheduler capture produced an invalid event")
			}
			keep, e := corr.event(*reply.Event)
			if e != nil {
				return e
			}
			if keep {
				res.Events = append(res.Events, *reply.Event)
			}
		default:
			return errors.New("scheduler capture sent an empty frame")
		}
		if len(res.Events)+len(corr.intervals) >= SchedulerItems {
			stop()
		}
	}
}
