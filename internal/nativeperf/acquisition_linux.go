//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cpuThread struct {
	task  TaskKey
	start uint64
}
type cpuSource struct {
	nextMu    sync.Mutex
	closeOnce sync.Once
	done      chan struct{}
	rings     []*Ring
	targets   AuthorizedTargets
	threads   []cpuThread
	domain    ClockDomain
	sequence  uint64
	cursor    int
	lastCheck time.Time
	stop      func() bool
	closeErr  error
	terminal  error
	timer     *time.Timer
}

// NewCPUAcquisition is the helper's fixed software CPU-clock factory. CgroupID
// constrains each authorized process's membership; it is NOT a cgroup-wide
// selector. Every existing thread of every listed process receives its own
// task-scoped (pid=TID,cpu=-1) event. No unrelated cgroup member is sampled.
func NewCPUAcquisition(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation) (EventSource, error) {
	return newCPUAcquisition(ctx, a, c, r, MethodSoftwareCPUClock)
}

// NewCyclesAcquisition is an explicit operator-side helper configuration opt-in;
// it is never a request-controlled arbitrary event selector or fallback mode.
func NewCyclesAcquisition(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation) (EventSource, error) {
	return newCPUAcquisition(ctx, a, c, r, MethodHardwareCycles)
}
func newCPUAcquisition(ctx context.Context, a AuthorizedTargets, c Config, r *Reservation, method SamplingMethod) (EventSource, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if a.mode != ModeCPU {
		return nil, &CapabilityError{Unsupported, ReasonEvent}
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if r == nil || len(a.targets) == 0 {
		return nil, ErrResources
	}
	if e := a.Revalidate(); e != nil {
		return nil, e
	}
	domain, e := localCPUDomain()
	if e != nil {
		return nil, e
	}
	threads, e := snapshotCPUThreads(a, domain)
	if e != nil {
		return nil, e
	}
	rollback, e := r.ReserveCPURings(uint64(len(threads)), c, uint64(os.Getpagesize()))
	if e != nil {
		return nil, e
	}
	source := &cpuSource{done: make(chan struct{}), targets: a, threads: threads, domain: domain, rings: make([]*Ring, 0, len(threads))}
	fail := func(err error) (EventSource, error) { source.Close(); rollback(); return nil, err }
	for _, thread := range threads {
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		ring, e := openThreadCPU(thread.task, c, method)
		if e != nil {
			return fail(e)
		}
		if e = r.Own(ring); e != nil {
			return fail(e)
		}
		source.rings = append(source.rings, ring)
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	if e = source.checkIdentity(); e != nil {
		return fail(e)
	}
	for _, ring := range source.rings {
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		if e = enableCPU(ring); e != nil {
			return fail(e)
		}
	}
	if e = source.checkIdentity(); e != nil {
		return fail(e)
	}
	source.nextMu.Lock()
	source.stop = context.AfterFunc(ctx, func() { source.Close() })
	source.nextMu.Unlock()
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	return source, nil
}
func localCPUDomain() (ClockDomain, error) {
	var d ClockDomain
	for _, item := range []struct {
		path string
		out  *string
	}{{"/etc/machine-id", &d.HostID}, {"/proc/sys/kernel/random/boot_id", &d.BootID}} {
		f, e := os.Open(item.path)
		if e != nil {
			return d, ErrTargetIdentity
		}
		b, e := io.ReadAll(io.LimitReader(f, 130))
		f.Close()
		if e != nil || len(b) > 129 {
			return d, ErrTargetIdentity
		}
		*item.out = strings.TrimSpace(string(b))
	}
	if !d.valid() {
		return d, ErrTargetIdentity
	}
	return d, nil
}
func snapshotCPUThreads(a AuthorizedTargets, d ClockDomain) ([]cpuThread, error) {
	out := make([]cpuThread, 0, len(a.targets))
	for _, target := range a.targets {
		base := "/proc/" + strconv.FormatUint(uint64(target.TGID), 10) + "/task"
		dir, e := os.Open(base)
		if e != nil {
			return nil, ErrTargetIdentity
		}
		entries, e := dir.ReadDir(257)
		dir.Close()
		if e != nil && e != io.EOF {
			return nil, ErrTargetIdentity
		}
		if len(entries) > 256 || len(out)+len(entries) > 256 {
			return nil, ErrResources
		}
		for _, entry := range entries {
			tid, e := strconv.ParseUint(entry.Name(), 10, 32)
			if e != nil || tid == 0 {
				return nil, ErrTargetIdentity
			}
			f, e := os.Open(base + "/" + entry.Name() + "/stat")
			if e != nil {
				return nil, ErrTargetIdentity
			}
			b, e := io.ReadAll(io.LimitReader(f, 4097))
			f.Close()
			if e != nil || len(b) > 4096 {
				return nil, ErrTargetIdentity
			}
			// Skip command bytes in place, never formatting or retaining them.
			end := bytes.LastIndexByte(b, ')')
			if end < 0 {
				return nil, ErrTargetIdentity
			}
			fields := bytes.Fields(b[end+1:])
			if len(fields) < 20 {
				return nil, ErrTargetIdentity
			}
			start, e := strconv.ParseUint(string(fields[19]), 10, 64)
			if e != nil || start == 0 {
				return nil, ErrTargetIdentity
			}
			out = append(out, cpuThread{TaskKey{BootID: d.BootID, PIDNamespace: target.PIDNamespace, TGID: target.TGID, TID: uint32(tid), ProcessStart: target.ProcessStart, Generation: 1}, start})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].task.TGID != out[j].task.TGID {
			return out[i].task.TGID < out[j].task.TGID
		}
		return out[i].task.TID < out[j].task.TID
	})
	for i := 1; i < len(out); i++ {
		if out[i].task == out[i-1].task {
			return nil, ErrTargetIdentity
		}
	}
	if len(out) == 0 {
		return nil, ErrTargetIdentity
	}
	return out, nil
}
func (s *cpuSource) checkIdentity() error {
	if e := s.targets.Revalidate(); e != nil {
		return e
	}
	threads, e := snapshotCPUThreads(s.targets, s.domain)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(threads, s.threads) {
		return ErrThreadCoverageChanged
	}
	s.lastCheck = time.Now()
	return nil
}
func (s *cpuSource) Next(ctx context.Context) (SanitizedEvent, error) {
	s.nextMu.Lock()
	defer s.nextMu.Unlock()
	if s.terminal != nil {
		return SanitizedEvent{}, s.terminal
	}
	defer func() {
		if s.timer != nil {
			s.timer.Stop()
		}
	}()
	for {
		if e := ctx.Err(); e != nil {
			return SanitizedEvent{}, e
		}
		select {
		case <-s.done:
			return SanitizedEvent{}, ErrAcquisitionClosed
		default:
		}
		if time.Since(s.lastCheck) >= 100*time.Millisecond {
			if e := s.checkIdentity(); e != nil {
				s.terminal = e
				return SanitizedEvent{}, e
			}
		}
		for range len(s.rings) {
			index := s.cursor
			s.cursor = (s.cursor + 1) % len(s.rings)
			ring := s.rings[index]
			var result SanitizedEvent
			found := false
			e := drainRing(ring, func(event SanitizedEvent) error {
				event.Domain = s.domain
				s.sequence++
				event.Sequence = s.sequence
				if e := event.Validate(); e != nil {
					return e
				}
				result = event
				found = true
				return nil
			})
			if e != nil {
				s.terminal = e
				return SanitizedEvent{}, e
			}
			if found {
				return result, nil
			}
		}
		if s.timer == nil {
			s.timer = time.NewTimer(5 * time.Millisecond)
		} else {
			s.timer.Reset(5 * time.Millisecond)
		}
		select {
		case <-ctx.Done():
			return SanitizedEvent{}, ctx.Err()
		case <-s.done:
			return SanitizedEvent{}, ErrAcquisitionClosed
		case <-s.timer.C:
		}
	}
}
func (s *cpuSource) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.nextMu.Lock()
		defer s.nextMu.Unlock()
		if s.stop != nil {
			s.stop()
		}
		for i := len(s.rings) - 1; i >= 0; i-- {
			if e := s.rings[i].Close(); s.closeErr == nil {
				s.closeErr = e
			}
		}
	})
	return s.closeErr
}
