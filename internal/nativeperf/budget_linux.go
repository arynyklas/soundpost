//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"io"
	"sync"
)

type Topology struct{ CPUs, FDLimit, OpenFDs, PageBytes uint64 }
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
}

func (b *ResourceBudget) Reserve(a AuthorizedTargets, c Config, t Topology, m MemoryUsage) (*Reservation, error) {
	if c.Validate() != nil || len(a.targets) == 0 || t.CPUs == 0 || t.PageBytes == 0 || t.FDLimit <= 32 || t.OpenFDs > t.FDLimit-32 {
		return nil, ErrResources
	}
	rings := uint64(len(a.targets))
	if a.mode == ModeCPUOffCPU {
		if t.CPUs > 256 {
			return nil, ErrResources
		}
		rings += 2 * t.CPUs
	}
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
	if rings > c.MaxMemory/per {
		return nil, ErrResources
	}
	memory := rings * per
	// Fixed bounded protocol/socket buffers plus event/decode/export tables.
	overhead := uint64(1<<20) + uint64(len(a.targets))*(256<<10)
	for _, n := range []uint64{overhead, m.HelperRSS, m.ExportRSS} {
		if n > c.MaxMemory-memory {
			return nil, ErrResources
		}
		memory += n
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.memory > c.MaxMemory-memory || b.fds > ceiling-fds {
		return nil, ErrResources
	}
	b.memory += memory
	b.fds += fds
	return &Reservation{budget: b, Memory: memory, FDs: fds, cpuRings: uint64(len(a.targets)), fdCeiling: ceiling}, nil
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
