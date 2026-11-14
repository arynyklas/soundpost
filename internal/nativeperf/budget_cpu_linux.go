//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"io"
	"os"
	"sync"
	"syscall"
)

// ReserveCPURings extends the baseline one-ring-per-process lease to every
// initial target thread, before any perf FD or mmap is opened. The rollback
// closes resources acquired after this checkpoint and releases only the extra
// charge. On success the caller discards rollback; Reservation.Close owns it all.
// A reservation has one acquisition owner; extensions must not overlap.
func (r *Reservation) ReserveCPURings(total uint64, c Config, page uint64) (func(), error) {
	if r == nil || c.Validate() != nil || page != uint64(os.Getpagesize()) || c.RingBytes < page || c.RingBytes%page != 0 || total == 0 || total > 256 {
		return nil, ErrResources
	}
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) != nil {
		return nil, ErrResources
	}
	dir, e := os.Open("/proc/self/fd")
	if e != nil {
		return nil, ErrResources
	}
	fds, e := dir.ReadDir(1025)
	dir.Close()
	if e != nil && e != io.EOF {
		return nil, ErrResources
	}
	if len(fds) > 1024 || limit.Cur < 32 || uint64(len(fds))+total > limit.Cur-32 {
		return nil, ErrResources
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.budget == nil || total < r.cpuRings {
		return nil, ErrResources
	}
	oldRings, oldOwned := r.cpuRings, len(r.owned)
	extra := total - oldRings
	per := c.RingBytes + page
	if extra > c.MaxMemory/per {
		return nil, ErrResources
	}
	memory := extra * per
	if r.Memory > c.MaxMemory || memory > c.MaxMemory-r.Memory || r.FDs > r.fdCeiling || extra > r.fdCeiling-r.FDs {
		return nil, ErrResources
	}
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	if r.budget.memory > c.MaxMemory-memory || r.budget.fds > r.fdCeiling || extra > r.fdCeiling-r.budget.fds {
		return nil, ErrResources
	}
	r.budget.memory += memory
	r.budget.fds += extra
	r.Memory += memory
	r.FDs += extra
	r.cpuRings = total
	var once sync.Once
	rollback := func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.closed {
				return
			}
			for i := len(r.owned) - 1; i >= oldOwned; i-- {
				r.owned[i].Close()
			}
			r.owned = r.owned[:oldOwned]
			r.budget.mu.Lock()
			defer r.budget.mu.Unlock()
			r.budget.memory -= memory
			r.budget.fds -= extra
			r.Memory -= memory
			r.FDs -= extra
			r.cpuRings = oldRings
		})
	}
	return rollback, nil
}
