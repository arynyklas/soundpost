//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

type schedulerRing struct {
	ring   *Ring
	layout NumericLayout
	cpu    uint32
}
type schedulerSource struct {
	mu              sync.Mutex
	ctx             context.Context
	nextMu          sync.Mutex
	done            chan struct{}
	closeOnce       sync.Once
	cpu             *cpuSource
	rings           []schedulerRing
	cpus            []uint32
	cursor          int
	sequence        uint64
	topologyPending bool
	stopped         bool
	start           model.MonoNano
	finalSent       bool
	end             model.MonoNano
	terminal        error
	pendingEvent    *SanitizedEvent
}

// NewNativeAcquisition selects solely the already authorized signed mode.
func NewNativeAcquisition(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation) (EventSource, error) {
	if a.mode == ModeCPU {
		return NewCPUAcquisition(ctx, a, c, r)
	}
	if a.mode != ModeCPUOffCPU {
		return nil, ErrAuthorization
	}
	return newSchedulerAcquisition(ctx, a, c, r)
}
func readFixedMetadata(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		status, reason := probeStatus(e)
		return nil, &CapabilityError{status, reason}
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrInvalid
	}
	return b, nil
}
func schedulerLayouts() ([]NumericLayout, error) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, &CapabilityError{Unsupported, ReasonPlatform}
	}
	release, e := readFixedMetadata("/proc/sys/kernel/osrelease", 256)
	if e != nil {
		return nil, e
	}
	kernel := ""
	for _, v := range []string{"6.1", "6.6"} {
		if strings.HasPrefix(string(release), v+".") {
			kernel = v
		}
	}
	if kernel == "" {
		return nil, &CapabilityError{Unsupported, ReasonEvent}
	}
	layouts := make([]NumericLayout, 0, 3)
	for _, kind := range []SchedulerKind{SchedulerSwitchKind, SchedulerWakeupKind, SchedulerWakeupNewKind} {
		var b []byte
		for _, root := range []string{"/sys/kernel/tracing/events/sched/", "/sys/kernel/debug/tracing/events/sched/"} {
			b, e = readFixedMetadata(root+string(kind)+"/format", 65536)
			if e == nil {
				break
			}
		}
		if e != nil {
			return nil, e
		}
		l, e := parseTraceFormat(kind, b)
		if e != nil {
			return nil, &CapabilityError{Unsupported, ReasonEvent}
		}
		l.kernel = kernel
		layouts = append(layouts, l)
	}
	return layouts, nil
}
func schedulerPerfAttr(l NumericLayout, c Config) cpuPerfAttr {
	a := cpuPerfAttr{Type: 2, Size: 112, Config: l.id, Frequency: 1, SampleType: 2 | 4 | 32 | 128 | 1024, Wakeup: 1, ClockID: 1, SampleMaxStack: min(uint16(c.MaxFrames), 127)}
	// USE_CLOCKID is required: otherwise the kernel ignores ClockID and the
	// scheduler timestamps cannot be joined to MONOTONIC samples/final proofs.
	// Kernel tracepoints remain enabled; no registers or stack bytes are captured.
	a.Flags = 1 | 1<<18 | 1<<21 | 1<<24 | 1<<25
	return a
}
func openSchedulerRing(cpu uint32, l NumericLayout, c Config) (*Ring, error) {
	a := schedulerPerfAttr(l, c)
	fd, _, errno := syscall.Syscall6(syscall.SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(&a)), ^uintptr(0), uintptr(cpu), ^uintptr(0), 8, 0)
	if errno != 0 {
		s, reason := probeStatus(errno)
		return nil, &CapabilityError{s, reason}
	}
	r := &Ring{fd: os.NewFile(fd, "scheduler-perf")}
	mapping, e := syscall.Mmap(int(fd), 0, int(c.RingBytes)+os.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if e != nil {
		r.Close()
		return nil, &CapabilityError{Error, ReasonEvent}
	}
	r.mapping = mapping
	r.meta = mapping[:os.Getpagesize()]
	offset := *(*uint64)(unsafe.Pointer(&mapping[1040]))
	size := *(*uint64)(unsafe.Pointer(&mapping[1048]))
	if offset != uint64(os.Getpagesize()) || size != c.RingBytes {
		r.Close()
		return nil, ErrRingMalformed
	}
	r.data = mapping[int(offset):]
	return r, nil
}
func newSchedulerAcquisition(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation) (EventSource, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if c.Validate() != nil || r == nil {
		return nil, ErrResources
	}
	if !schedulerPIDsAttributable() {
		return nil, &CapabilityError{Unsupported, ReasonEvent}
	}
	if e := a.Revalidate(); e != nil {
		return nil, e
	}
	layouts, e := schedulerLayouts()
	if e != nil {
		return nil, e
	}
	cpus, e := schedulerCPUs()
	if e != nil {
		return nil, e
	}
	if len(cpus) == 0 || len(cpus) > 256 {
		return nil, ErrResources
	}
	// The baseline reservation must charge all three streams before any opens.
	// Refuse a changed topology rather than relying on a stale helper snapshot.
	expected := uint64(len(a.targets) + 3*len(cpus))
	if r.FDs < expected+3*uint64(len(a.targets))+2 {
		return nil, ErrResources
	}
	domain, e := localCPUDomain()
	if e != nil {
		return nil, e
	}
	threads, e := snapshotCPUThreads(a, domain)
	if e != nil {
		return nil, e
	}
	a.schedulerTasks = threads
	rollback, e := r.ReserveCPURings(uint64(len(threads)), c, uint64(os.Getpagesize()))
	if e != nil {
		return nil, e
	}
	s := &schedulerSource{ctx: ctx, cpus: append([]uint32(nil), cpus...), topologyPending: true, done: make(chan struct{})}
	fail := func(err error) (EventSource, error) { s.Close(); rollback(); return nil, err }
	// Disable every source until the complete coupled set exists.
	for _, cpu := range cpus {
		for _, l := range layouts {
			l.maxFrames = min(uint16(c.MaxFrames), 127)
			if e = ctx.Err(); e != nil {
				return fail(e)
			}
			ring, e := openSchedulerRing(cpu, l, c)
			if e != nil {
				return fail(e)
			}
			if e = r.Own(ring); e != nil {
				return fail(e)
			}
			s.rings = append(s.rings, schedulerRing{ring, l, cpu})
		}
	}
	cs := &cpuSource{done: make(chan struct{}), targets: a, threads: threads, domain: domain, rings: make([]*Ring, 0, len(threads))}
	s.cpu = cs
	for _, t := range threads {
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		ring, e := openThreadCPU(t.task, c, MethodSoftwareCPUClock)
		if e != nil {
			return fail(e)
		}
		if e = r.Own(ring); e != nil {
			return fail(e)
		}
		cs.rings = append(cs.rings, ring)
	}
	if e = s.identity(); e != nil {
		return fail(e)
	}
	for _, sr := range s.rings {
		if e = enableCPU(sr.ring); e != nil {
			return fail(e)
		}
	}
	for _, ring := range cs.rings {
		if e = enableCPU(ring); e != nil {
			return fail(e)
		}
	}
	if e = s.identity(); e != nil {
		return fail(e)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	s.start, e = schedulerNow()
	if e != nil {
		return fail(e)
	}
	return s, nil
}
func schedulerCPUs() ([]uint32, error) {
	values, e := OnlineCPUs()
	if e != nil {
		return nil, e
	}
	out := make([]uint32, len(values))
	for i, v := range values {
		if v < 0 {
			return nil, ErrResources
		}
		out[i] = uint32(v)
	}
	return out, nil
}
func (s *schedulerSource) identity() error {
	if e := s.cpu.checkIdentity(); e != nil {
		return e
	}
	cpus, e := schedulerCPUs()
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(cpus, s.cpus) {
		return ErrTopologyChanged
	}
	return nil
}
func (s *schedulerSource) Next(ctx context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, ErrProgressRequired
}
func (s *schedulerSource) NextItem(ctx context.Context) (AcquisitionItem, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminal != nil {
		return AcquisitionItem{}, s.terminal
	}
	select {
	case <-s.done:
		return AcquisitionItem{}, ErrAcquisitionClosed
	default:
	}
	if e := ctx.Err(); e != nil {
		return AcquisitionItem{}, e
	}
	if s.ctx != nil {
		if e := s.ctx.Err(); e != nil {
			return AcquisitionItem{}, e
		}
	}
	if s.topologyPending {
		s.topologyPending = false
		return AcquisitionItem{Proof: &AcquisitionProof{Domain: s.cpu.domain, CPUs: append([]uint32(nil), s.cpus...), Through: s.start}}, nil
	}
capture:
	for {
		select {
		case <-s.done:
			return AcquisitionItem{}, ErrAcquisitionClosed
		default:
		}
		if e := ctx.Err(); e != nil {
			return AcquisitionItem{}, e
		}
		if s.ctx != nil {
			if e := s.ctx.Err(); e != nil {
				return AcquisitionItem{}, e
			}
		}
		if !s.stopped && time.Since(s.cpu.lastCheck) >= 100*time.Millisecond {
			if e := s.identity(); e != nil {
				s.terminal = e
				return AcquisitionItem{}, e
			}
		}
		if s.pendingEvent != nil {
			progressed := false
			for _, ring := range s.cpu.rings {
				before := ring.tail()
				var cpuEvent *SanitizedEvent
				err := drainRing(ring, func(ev SanitizedEvent) error { cpuEvent = &ev; return nil })
				if err != nil {
					s.terminal = err
					return AcquisitionItem{}, err
				}
				progressed = progressed || ring.tail() != before
				if cpuEvent != nil {
					if cpuEvent.Kind != EventLoss && (cpuEvent.Time < s.start || s.stopped && cpuEvent.Time > s.end) {
						continue
					}
					if s.stopped && cpuEvent.Kind == EventLoss && cpuEvent.Time > s.end {
						cpuEvent.Time = s.end
					}
					return s.publish(*cpuEvent)
				}
			}
			if progressed {
				continue capture
			}
			event := *s.pendingEvent
			s.pendingEvent = nil
			if s.stopped && event.Time > s.end {
				continue capture
			}
			return s.publish(event)
		}
		total := len(s.rings) + len(s.cpu.rings)
		hadRecord := false
		for range total {
			index := s.cursor
			s.cursor = (s.cursor + 1) % total
			var event SanitizedEvent
			ok := false
			var e error
			if index < len(s.rings) {
				sr := s.rings[index]
				before := sr.ring.tail()
				e = sr.ring.consume(func(v KernelRecordView) error {
					if v.u32(0) == perfRecordSample {
						if v.len() < 32 || v.u32(24) != sr.cpu {
							return ErrRingMalformed
						}
						var err error
						event, ok, err = decodeScheduler(v, sr.layout, s.cpu.targets)
						return err
					}
					if v.u32(0) == perfRecordLost || v.u32(0) == perfRecordLostSamples || v.u32(0) == perfRecordThrottle || v.u32(0) == perfRecordUnthrottle {
						loss, t, err := decodeCPULoss(v)
						event = SanitizedEvent{Kind: EventLoss, Time: t, CPU: sr.cpu, Loss: &loss}
						ok = err == nil
						return err
					}
					return ErrRingMalformed
				})
				hadRecord = hadRecord || sr.ring.tail() != before
			} else {
				ring := s.cpu.rings[index-len(s.rings)]
				before := ring.tail()
				e = drainRing(ring, func(ev SanitizedEvent) error { event = ev; ok = true; return nil })
				hadRecord = hadRecord || ring.tail() != before
			}
			if e != nil {
				s.terminal = e
				return AcquisitionItem{}, e
			}
			if ok && event.Kind != EventLoss && (event.Time < s.start || s.stopped && event.Time > s.end) {
				ok = false
			}
			if ok && event.Kind == EventLoss && s.stopped && event.Time > s.end {
				event.Time = s.end
			}
			if ok && (event.Kind == EventSwitch || event.Kind == EventWakeup) {
				s.pendingEvent = &event
				continue capture
			}
			if ok {
				return s.publish(event)
			}
		}
		if hadRecord {
			continue
		}
		if s.stopped {
			if s.finalSent {
				return AcquisitionItem{}, ErrSourceComplete
			}
			s.finalSent = true
			return AcquisitionItem{Proof: &AcquisitionProof{Domain: s.cpu.domain, CPUs: append([]uint32(nil), s.cpus...), Through: s.end, Final: true}}, nil
		}
		timer := time.NewTimer(5 * time.Millisecond)
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			timer.Stop()
			s.mu.Lock()
			return AcquisitionItem{}, ctx.Err()
		case <-s.done:
			timer.Stop()
			s.mu.Lock()
			return AcquisitionItem{}, ErrAcquisitionClosed
		case <-timer.C:
		}
		s.mu.Lock()
	}
}
func (s *schedulerSource) publish(event SanitizedEvent) (AcquisitionItem, error) {
	if !s.stopped {
		if e := s.identity(); e != nil {
			s.terminal = e
			return AcquisitionItem{}, e
		}
	}
	s.sequence++
	event.Sequence = model.Uint64(s.sequence)
	event.Domain = s.cpu.domain
	if e := event.Validate(); e != nil {
		s.terminal = e
		return AcquisitionItem{}, e
	}
	return AcquisitionItem{Event: &event}, nil
}

// Stop records the conservative common cutoff BEFORE the first disable. A
// successful final proof follows actual synchronous disable and complete drain.
func schedulerNow() (model.MonoNano, error) {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return 0, ErrAcquisitionFailed
	}
	return model.MonoNano(uint64(ts.Sec)*1000000000 + uint64(ts.Nsec)), nil
}
func (s *schedulerSource) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.done:
		return ErrAcquisitionClosed
	default:
	}
	if s.ctx != nil {
		if e := s.ctx.Err(); e != nil {
			s.terminal = e
			return e
		}
	}
	if s.terminal != nil {
		return s.terminal
	}
	if s.stopped {
		return nil
	}
	if e := s.identity(); e != nil {
		s.terminal = e
		return e
	}
	end, e := schedulerNow()
	if e != nil {
		s.terminal = e
		return e
	}
	for _, sr := range s.rings {
		if e = disableScheduler(sr.ring); e != nil {
			s.terminal = e
			return e
		}
	}
	for _, r := range s.cpu.rings {
		if e = disableScheduler(r); e != nil {
			s.terminal = e
			return e
		}
	}
	s.end = end
	s.stopped = true
	return nil
}
func disableScheduler(r *Ring) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, r.fd.Fd(), 0x2401, 0)
	if e != 0 {
		return ErrAcquisitionFailed
	}
	return nil
}
func (s *schedulerSource) Close() error {
	s.closeOnce.Do(func() {
		if s.done != nil {
			close(s.done)
		}
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	var first error
	if s.cpu != nil {
		first = s.cpu.Close()
	}
	for _, sr := range s.rings {
		if e := sr.ring.Close(); first == nil {
			first = e
		}
	}
	return first
}
