//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"io"
	"sync"
)

// LockBytes is the perf mapping bound the kernel enforces through the per-user perf allowance and RLIMIT_MEMLOCK (see perfLockBytes); zero is unbounded.
type Topology struct{ CPUs, FDLimit, OpenFDs, PageBytes, LockBytes uint64 }
type MemoryUsage struct{ HelperRSS, ExportRSS uint64 }
type ResourceBudget struct {
	mu          sync.Mutex
	memory, fds uint64
}

func NewResourceBudget() *ResourceBudget { return &ResourceBudget{} }

type Reservation struct {
	budget              *ResourceBudget
	Memory, FDs         uint64
	mu                  sync.Mutex
	closed              bool
	owned               []io.Closer
	cpuRings, fdCeiling uint64
	workingLimit        uint64
	lockBytes           uint64
}

// captureRings is the number of perf rings one capture maps: one per target,
// plus three per online CPU in off-CPU mode.
func captureRings(offCPU bool, targets, cpus uint64) uint64 {
	rings := targets
	if offCPU {
		rings += 3 * cpus
	}
	return rings
}

// captureOverhead is the fixed bounded protocol/socket buffers plus the event,
// decode and export tables of one capture.
func captureOverhead(targets uint64) uint64 { return uint64(1<<20) + targets*(256<<10) }

// CaptureCharge is the memory Reserve charges one capture against Config.MaxMemory:
// every ring with its metadata page, the fixed per-target buffers, and the
// resident sizes of the helper and of its exporting peer. Whatever a consumer (the
// correlator) is handed out of the same budget has to fit in MaxMemory minus this.
func CaptureCharge(offCPU bool, targets, cpus uint64, c Config, pageBytes uint64, m MemoryUsage) (uint64, error) {
	rings := captureRings(offCPU, targets, cpus)
	per := c.RingBytes + pageBytes
	if c.Validate() != nil || rings == 0 || rings > c.MaxMemory/per {
		return 0, ErrResources
	}
	memory := rings * per
	for _, n := range []uint64{captureOverhead(targets), m.HelperRSS, m.ExportRSS} {
		if n > c.MaxMemory-memory {
			return 0, ErrResources
		}
		memory += n
	}
	return memory, nil
}

func (b *ResourceBudget) Reserve(a AuthorizedTargets, c Config, t Topology, m MemoryUsage) (*Reservation, error) {
	if c.Validate() != nil || len(a.targets) == 0 || t.CPUs == 0 || t.PageBytes == 0 || t.FDLimit <= 32 || t.OpenFDs > t.FDLimit-32 {
		return nil, ErrResources
	}
	offCPU := a.mode == ModeCPUOffCPU
	if offCPU && t.CPUs > 256 {
		return nil, ErrResources
	}
	rings := captureRings(offCPU, uint64(len(a.targets)), t.CPUs)
	// pidfds, proc dirs, executable metadata, connection, listener, and ring FDs.
	fds := rings + 3*uint64(len(a.targets)) + 2
	ceiling := t.FDLimit - 32 - t.OpenFDs
	if ceiling > 256 {
		ceiling = 256
	}
	if fds > ceiling || c.RingBytes > c.MaxMemory || t.PageBytes > c.MaxMemory-c.RingBytes {
		return nil, ErrResources
	}
	per := c.RingBytes + t.PageBytes
	if rings > c.MaxMemory/per || t.LockBytes != 0 && rings > t.LockBytes/per {
		return nil, ErrResources
	}
	memory, e := CaptureCharge(offCPU, uint64(len(a.targets)), t.CPUs, c, t.PageBytes, m)
	if e != nil {
		return nil, e
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.memory > c.MaxMemory-memory || b.fds > ceiling-fds {
		return nil, ErrResources
	}
	b.memory += memory
	b.fds += fds
	return &Reservation{budget: b, Memory: memory, FDs: fds, cpuRings: uint64(len(a.targets)), fdCeiling: ceiling, workingLimit: c.MaxMemory, lockBytes: t.LockBytes}, nil
}
func (r *Reservation) Own(c io.Closer) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		c.Close()
		return ErrResources
	}
	if uint64(len(r.owned)) >= r.FDs {
		c.Close()
		return ErrResources
	}
	r.owned = append(r.owned, c)
	return nil
}
func (r *Reservation) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var first error
	for i := len(r.owned) - 1; i >= 0; i-- {
		if e := r.owned[i].Close(); e != nil && first == nil {
			first = e
		}
	}
	r.owned = nil
	r.budget.mu.Lock()
	r.budget.memory -= r.Memory
	r.budget.fds -= r.FDs
	r.budget.mu.Unlock()
	return first
}
