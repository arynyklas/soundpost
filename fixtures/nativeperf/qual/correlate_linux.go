//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"errors"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// Correlation is the outcome of replaying one scheduler capture through the
// committed per-session Correlator.
type Correlation struct {
	Intervals     []nativeperf.Interval
	Err           string // empty on success
	ConsumeErrors int
	FirstError    string
	SwitchEvents  int
	WakeupEvents  int
	CPUSamples    int
	LossEvents    int
	CPUs          int
	FinalThrough  uint64
	// ProgressProofs is how many mid-capture drained-prefix proofs were applied;
	// PeakHeapEvents is the most events the bounded correlation buffer held;
	// ReservationBytes is the share of the aggregate budget the correlator got;
	// IntervalBytes is the memory the returned Intervals hold (see IntervalsFootprint).
	ProgressProofs   int
	PeakHeapEvents   int
	ReservationBytes uint64
	IntervalBytes    uint64
	// IntervalsDropped is how many returned intervals KeepOnly released instead of retaining; ScopedOut how many
	// events of other threads Scope did not hand to the correlator.
	IntervalsDropped int
	ScopedOut        int
	// Consumed is how many events were handed to the correlator (after Scope); MaxHeapEvents is how many it may buffer.
	Consumed, MaxHeapEvents int
	// IntervalCounts is how many intervals of each kind the correlator returned, whatever was retained of them.
	IntervalCounts map[nativeperf.IntervalKind]int
	// RevokedFrom is set (Revoked) when the stream ended on an identity error: the correlation then ends with a domain-wide
	// correction over [RevokedFrom, end) instead of a final proof (see Revoke).
	Revoked     bool
	RevokedFrom uint64
}

// StreamCorrelation replays a scheduler capture through the Correlator while the
// capture is still streaming in: it is the EventSink of a scheduler capture. It
// applies the initial topology proof (the Correlator is configured from it), every
// event in stream order, each progress proof where it arrived (every CPU reported
// drained through it, then Advance, so the bounded buffer drains during the
// capture) and the final proof (every CPU reported, then Finalize). Nothing is
// inferred: a capture without both the initial and the final proof yields an error,
// never intervals. It keeps no scheduler event: the events a Correlator has
// consumed are not retained (Event reports false for switches and wakeups), only
// the CPU samples, losses and other small records the row judges need.
type StreamCorrelation struct {
	cfg     nativeperf.Config
	reserve func(cpus uint64) (uint64, error)
	c       *nativeperf.Correlator
	out     Correlation
	initial bool
	final   bool
	failed  bool
	keep    func(nativeperf.Interval) bool
	scope   uint32
	// dropStacks retains returned intervals without their switch-out stacks (see DropStacks).
	dropStacks bool
	// fold retains the measured intervals as one summed interval per task and kind (see FoldDurations); folded and
	// foldOrder hold them until Result.
	fold      bool
	folded    map[foldKey]*nativeperf.Interval
	foldOrder []foldKey
}

type foldKey struct {
	task nativeperf.TaskKey
	kind nativeperf.IntervalKind
}

// NewStreamCorrelation starts a correlation whose Correlator is handed
// reserve(cpus) bytes of the aggregate budget once the topology is known.
func NewStreamCorrelation(cfg nativeperf.Config, reserve func(cpus uint64) (uint64, error)) *StreamCorrelation {
	return &StreamCorrelation{cfg: cfg, reserve: reserve}
}

func (s *StreamCorrelation) fail(msg string) {
	if !s.failed {
		s.out.Err, s.failed = msg, true
	}
}

// KeepOnly makes the correlation retain only the returned intervals the filter accepts (the rest are counted in
// IntervalsDropped and released at once): a judge that reads one thread of the target need not hold the intervals of
// all the others, which are memory the aggregate budget has to cover. Call it before the first proof.
func (s *StreamCorrelation) KeepOnly(keep func(nativeperf.Interval) bool) { s.keep = keep }

// DropStacks makes the correlation retain the returned intervals without their switch-out stacks: the row judges read
// the kind and the extent of an interval, never its stack, and the stacks are most of what the intervals weigh (the
// consumer's allowance is memory out of the aggregate budget). Call it before the first proof.
func (s *StreamCorrelation) DropStacks() { s.dropStacks = true }

// FoldDurations makes the correlation retain the measured (non-correction) intervals as one summed interval per task and
// kind: for a judge that only adds up durations (the contention row), not for one that places intervals in time. The
// folded interval starts where the first of its kind started and lasts the sum of them all, so it is not a point in
// time; coverage corrections are kept as they came. IntervalCounts still says how many intervals of each kind the
// correlator returned. Call it before the first proof.
func (s *StreamCorrelation) FoldDurations() {
	s.fold = true
	s.folded = map[foldKey]*nativeperf.Interval{}
}

func (s *StreamCorrelation) add(got []nativeperf.Interval) {
	if s.out.IntervalCounts == nil {
		s.out.IntervalCounts = map[nativeperf.IntervalKind]int{}
	}
	for _, iv := range got {
		s.out.IntervalCounts[iv.Kind]++
		if s.keep != nil && !s.keep(iv) {
			s.out.IntervalsDropped++
			continue
		}
		if s.dropStacks || s.fold {
			iv.SwitchOutCallchain = nil
		}
		if s.fold && !iv.Correction {
			k := foldKey{iv.Task, iv.Kind}
			if f := s.folded[k]; f != nil {
				f.End += iv.End - iv.Start
				f.Measure.Value += iv.Measure.Value
			} else {
				s.folded[k] = &iv
				s.foldOrder = append(s.foldOrder, k)
			}
			continue
		}
		s.out.Intervals = append(s.out.Intervals, iv)
	}
}

// Proof applies one acquisition proof in stream order.
func (s *StreamCorrelation) Proof(p nativeperf.AcquisitionProof) {
	if s.failed || s.final {
		return
	}
	switch {
	case p.Final:
		s.finish(p)
	case p.Progress:
		if !s.initial {
			s.fail("progress proof before the initial topology proof")
			return
		}
		for _, cpu := range p.CPUs {
			if err := s.c.ReportProgress(cpu, p.Through); err != nil {
				s.fail("report progress: " + err.Error())
				return
			}
		}
		got, err := s.c.Advance(p.Through)
		s.add(got)
		if err != nil {
			s.fail("advance: " + err.Error())
			return
		}
		s.out.ProgressProofs++
	case !s.initial:
		s.initial = true
		s.out.CPUs = len(p.CPUs)
		s.c = nativeperf.NewCorrelator(s.cfg)
		reservation, err := s.reserve(uint64(len(p.CPUs)))
		if err != nil {
			s.fail("reservation: " + err.Error())
			return
		}
		s.out.ReservationBytes = reservation
		if err := s.c.Configure(p.Domain, p.CPUs, reservation); err != nil {
			s.fail("configure: " + err.Error())
		}
	}
}

func (s *StreamCorrelation) finish(p nativeperf.AcquisitionProof) {
	s.final = true
	s.out.FinalThrough = uint64(p.Through)
	if !s.initial {
		return
	}
	s.out.PeakHeapEvents = s.c.Stats().PeakHeapEvents
	s.out.MaxHeapEvents = s.c.Stats().MaxHeapEvents
	for _, cpu := range p.CPUs {
		if err := s.c.ReportProgress(cpu, p.Through); err != nil {
			s.fail("report progress: " + err.Error())
			return
		}
	}
	got, err := s.c.Finalize(p.Through)
	s.add(got)
	if err != nil {
		s.fail("finalize: " + err.Error())
	}
}

// Revoke ends the correlation of a stream that ended on an identity error: the helper last proved the identity at
// provenThrough (event clock, 0 when it never did), so everything published after it is unproven. The correlator returns one
// domain-wide correction over [provenThrough, end), the result carries it (and no error: a revoked capture is an explicit,
// bounded outcome, not a missing final proof), and nothing more is consumed. Without the initial topology proof there is
// nothing to revoke and the result stays the error it is.
func (s *StreamCorrelation) Revoke(provenThrough uint64) {
	if s.failed || s.final || !s.initial {
		return
	}
	s.final = true
	s.out.Revoked, s.out.RevokedFrom = true, provenThrough
	s.out.PeakHeapEvents = s.c.Stats().PeakHeapEvents
	s.out.MaxHeapEvents = s.c.Stats().MaxHeapEvents
	got, err := s.c.RevokeFrom(model.MonoNano(provenThrough))
	s.add(got)
	if err != nil {
		s.fail("revoke: " + err.Error())
	}
}

// Scope narrows the correlation to one thread: switches that involve it (reduced to the thread's own side, see
// project), wakeups that target it and its own CPU samples are consumed, the scheduler events of the process's other
// threads are not (they are counted in ScopedOut). A task's off-CPU intervals are built from that task's own
// switch-out, wakeup and switch-in only, so the thread's intervals are unchanged, while the correlator no longer
// buffers the other threads' events: a runtime with 16 busy helper threads emits more scheduler events a second than
// a 64 MiB budget can reorder. Loss, mapping and generation events are always consumed. Call it before the first
// proof.
func (s *StreamCorrelation) Scope(tid uint32) { s.scope = tid }

func (s *StreamCorrelation) inScope(e nativeperf.SanitizedEvent) bool {
	switch {
	case e.Switch != nil:
		return e.Switch.Previous != nil && e.Switch.Previous.TID == s.scope || e.Switch.Next != nil && e.Switch.Next.TID == s.scope
	case e.Wakeup != nil:
		return e.Wakeup.Target.TID == s.scope
	case e.CPUEvent != nil:
		return e.Task.TID == s.scope
	}
	return true
}

// project hands the correlator only the judged thread's side of a switch. The thread on the other side has its own
// history, which Scope does not deliver (its switch-in on another CPU names nobody judged): left in the event, that
// task would stay "switched out" in the correlator forever and its next switch-out would revoke the coverage of the
// whole domain (records_lost, from the first such switch on).
func (s *StreamCorrelation) project(e nativeperf.SanitizedEvent) nativeperf.SanitizedEvent {
	if e.Switch == nil {
		return e
	}
	sw := *e.Switch
	if sw.Previous != nil && sw.Previous.TID != s.scope {
		sw.Previous, sw.PreviousState, sw.PreviousStateUnknown, sw.Preempted, sw.SwitchOutCallchain, sw.MissingCallchain = nil, 0, false, false, nil, ""
	}
	if sw.Next != nil && sw.Next.TID != s.scope {
		sw.Next = nil
	}
	e.Switch = &sw
	return e
}

// Event consumes one event in stream order and says whether the capture result
// should keep it: never a switch or a wakeup (the Correlator owns what it needs of
// them), always everything else.
func (s *StreamCorrelation) Event(e nativeperf.SanitizedEvent) bool {
	retain := e.Switch == nil && e.Wakeup == nil
	switch {
	case e.Switch != nil:
		s.out.SwitchEvents++
	case e.Wakeup != nil:
		s.out.WakeupEvents++
	case e.CPUEvent != nil:
		s.out.CPUSamples++
	case e.Loss != nil:
		s.out.LossEvents++
	}
	if s.failed {
		return retain
	}
	if !s.initial {
		s.fail("event before the initial topology proof")
		return retain
	}
	if s.scope != 0 {
		if !s.inScope(e) {
			s.out.ScopedOut++
			return retain
		}
		e = s.project(e)
	}
	s.out.Consumed++
	got, err := s.c.Consume(e)
	s.add(got)
	if err != nil {
		s.out.ConsumeErrors++
		if s.out.FirstError == "" {
			s.out.FirstError = err.Error()
		}
	}
	return retain
}

// Result is the correlation once the capture has ended. A capture that never
// delivered both the initial and the final proof has no intervals to report.
func (s *StreamCorrelation) Result() Correlation {
	if !s.failed && (!s.initial || !s.final) {
		s.out.Err = "capture has no initial and final acquisition proof"
	}
	out := s.out
	if len(s.foldOrder) > 0 {
		out.Intervals = make([]nativeperf.Interval, 0, len(s.out.Intervals)+len(s.foldOrder))
		out.Intervals = append(out.Intervals, s.out.Intervals...)
		for _, k := range s.foldOrder {
			out.Intervals = append(out.Intervals, *s.folded[k])
		}
	}
	out.IntervalBytes = IntervalsFootprint(out.Intervals)
	return out
}

// Correlate replays a finished capture result through a StreamCorrelation with the
// fixed CorrelationReservationBytes: its events in stream order, every progress
// proof where it arrived (ProofAt), the final proof after the last event.
func Correlate(res CaptureResult, cfg nativeperf.Config) Correlation {
	return replay(res, cfg, func(uint64) (uint64, error) { return CorrelationReservationBytes, nil })
}

// CorrelateWithin is Correlate with the correlator handed only what the aggregate
// budget has left after the capture's own admission charge (at most
// CorrelationReservationBytes): the capture's rings, per-target buffers and the
// helper's and this process's resident sizes at admission are charged first.
func CorrelateWithin(res CaptureResult, cfg nativeperf.Config, m AdmissionMemory) Correlation {
	return replay(res, cfg, func(cpus uint64) (uint64, error) { return CorrelationReservation(cfg, m, cpus) })
}

var errNoPosition = errors.New("progress proof without a recorded position in the event stream")

// replay feeds a finished capture to a StreamCorrelation exactly as the live
// stream would have: a proof before the event it preceded, the initial proof
// first and the final proof last.
func replay(res CaptureResult, cfg nativeperf.Config, reserve func(cpus uint64) (uint64, error)) Correlation {
	s := NewStreamCorrelation(cfg, reserve)
	at := make([]int, len(res.Proofs))
	for i, p := range res.Proofs {
		switch {
		case p.Final:
			at[i] = len(res.Events)
		case p.Progress:
			if len(res.ProofAt) != len(res.Proofs) || res.ProofAt[i] < 0 || res.ProofAt[i] > len(res.Events) {
				return Correlation{Err: errNoPosition.Error()}
			}
			at[i] = res.ProofAt[i]
		}
	}
	next := 0
	for i, e := range res.Events {
		for ; next < len(res.Proofs) && at[next] <= i; next++ {
			s.Proof(res.Proofs[next])
		}
		s.Event(e)
	}
	for ; next < len(res.Proofs); next++ {
		s.Proof(res.Proofs[next])
	}
	return s.Result()
}
