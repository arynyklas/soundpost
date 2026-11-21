//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import "sync"

// WorkingLease charges retained memory plus worst-case simultaneous transient
// descriptors before either is allocated. Close is idempotent in either parent
// close order; a lease is not a second independently capped resource budget.
type WorkingLease struct {
	mu          sync.Mutex
	parent      *Reservation
	memory, fds uint64
	closed      bool
}

func (l *WorkingLease) Bytes() uint64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0
	}
	return l.memory
}
func (r *Reservation) ReserveWorking(memory, fds uint64) (*WorkingLease, error) {
	if r == nil || memory == 0 {
		return nil, ErrResources
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.budget == nil || r.workingLimit == 0 || r.workingLimit > MaxMemoryBytes || r.Memory > r.workingLimit || memory > r.workingLimit-r.Memory || r.FDs > r.fdCeiling || fds > r.fdCeiling-r.FDs {
		return nil, ErrResources
	}
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	if r.budget.memory > r.workingLimit || memory > r.workingLimit-r.budget.memory || r.budget.fds > r.fdCeiling || fds > r.fdCeiling-r.budget.fds {
		return nil, ErrResources
	}
	r.budget.memory += memory
	r.budget.fds += fds
	r.Memory += memory
	r.FDs += fds
	return &WorkingLease{parent: r, memory: memory, fds: fds}, nil
}
func (l *WorkingLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	r := l.parent
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.budget.mu.Lock()
	defer r.budget.mu.Unlock()
	r.Memory -= l.memory
	r.FDs -= l.fds
	r.budget.memory -= l.memory
	r.budget.fds -= l.fds
	return nil
}

// ProfileAdmissionHeadroom replays the budget side of a profile capture exactly as the product takes it: the
// capture's own Reserve (rings, per-target buffers, the helper's and the exporting peer's resident size) followed by
// the three ProfileSource working leases of NewProfileAcquisition. It returns what is left of c.MaxMemory for
// anything else the capture's consumer holds (a correlator, the retained intervals), or the refusal the product would
// answer with when the leases do not fit. It touches no process, descriptor or ring: it is the budget arithmetic of
// the real Reserve/ReserveWorking, not a second copy of it.
func ProfileAdmissionHeadroom(c Config, offCPU bool, targets, cpus, pageBytes uint64, m MemoryUsage) (uint64, error) {
	if targets == 0 || targets > 256 {
		return 0, ErrInvalid
	}
	mode := ModeCPU
	if offCPU {
		mode = ModeCPUOffCPU
	}
	b := NewResourceBudget()
	r, e := b.Reserve(AuthorizedTargets{targets: make([]Target, targets), mode: mode}, c, Topology{CPUs: cpus, FDLimit: 1024, OpenFDs: 8, PageBytes: pageBytes}, m)
	if e != nil {
		return 0, e
	}
	defer r.Close()
	mapping, assembly, export := ProfileWorkingBytes(targets)
	for _, lease := range []struct{ memory, fds uint64 }{{mapping, targets*3 + 6}, {assembly, 0}, {export, 0}} {
		if _, e = r.ReserveWorking(lease.memory, lease.fds); e != nil {
			return 0, e
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return c.MaxMemory - b.memory, nil
}
