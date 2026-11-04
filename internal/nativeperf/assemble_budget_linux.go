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
