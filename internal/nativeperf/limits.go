// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"github.com/arynyklas/soundpost/internal/model"
	"time"
)

const MaxMemoryBytes uint64 = 64 << 20

// MaxSessionFDs is the installation's fixed file-descriptor ceiling of one capture session (plan 04, Task 2: 256, further
// bounded by RLIMIT_NOFILE-32): every perf ring, three descriptors per target and two for the socket count against it, so a
// target with more than MaxSessionFDs-5 threads is refused at admission with resource_limit.
const MaxSessionFDs uint64 = 256

type Config struct {
	CPUHz          uint32
	MaxFrames      uint32
	RingBytes      uint64
	ReorderWindow  time.Duration
	MaxMemory      uint64
	PolicyRevision model.Revision
}

func DefaultConfig(revision model.Revision) Config {
	return Config{CPUHz: 99, MaxFrames: 128, RingBytes: 256 << 10, ReorderWindow: 100 * time.Millisecond, MaxMemory: MaxMemoryBytes, PolicyRevision: revision}
}
func (c Config) Validate() error {
	if c.MaxMemory > MaxMemoryBytes || c.RingBytes > MaxMemoryBytes || c.RingBytes > c.MaxMemory {
		return ErrResourceBudget
	}
	if c.CPUHz != 99 || c.MaxFrames == 0 || c.MaxFrames > 128 || c.RingBytes < 4096 || c.RingBytes&(c.RingBytes-1) != 0 || c.ReorderWindow != 100*time.Millisecond || c.MaxMemory == 0 || c.PolicyRevision == 0 {
		return ErrInvalid
	}
	return nil
}

// CheckResources includes all active rings, metadata pages, export bytes and FD limits.
func (c Config) CheckResources(rings, metadataPage, exportBytes, fdLimit uint64) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if rings == 0 || metadataPage == 0 {
		return ErrInvalid
	}
	if rings > fdLimit || metadataPage > c.MaxMemory-c.RingBytes {
		return ErrResourceBudget
	}
	per := c.RingBytes + metadataPage
	if exportBytes > c.MaxMemory || rings > (c.MaxMemory-exportBytes)/per {
		return ErrResourceBudget
	}
	return nil
}
