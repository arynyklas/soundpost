// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"
	"time"
)

// 04.02-C16 mutation battery re-run (mut0402, G163 G166 G168-G182): the signed configuration ceiling (Config.Validate) and the
// public admission arithmetic (Config.CheckResources) had one assertion between them. Every field of the fixed C10
// configuration is pinned at both sides of its boundary, with the typed refusal it must produce.

func TestConfigValidateRefusesEachFieldOneStepOutsideTheFixedContract(t *testing.T) {
	type edit func(*Config)
	for _, tc := range []struct {
		name string
		edit edit
		want error // nil: valid
	}{
		{"the default", func(*Config) {}, nil},
		{"CPUHz 98", func(c *Config) { c.CPUHz = 98 }, ErrInvalid},
		{"CPUHz 100", func(c *Config) { c.CPUHz = 100 }, ErrInvalid},
		{"MaxFrames 0", func(c *Config) { c.MaxFrames = 0 }, ErrInvalid},
		{"MaxFrames 1", func(c *Config) { c.MaxFrames = 1 }, nil},
		{"MaxFrames 128", func(c *Config) { c.MaxFrames = 128 }, nil},
		{"MaxFrames 129", func(c *Config) { c.MaxFrames = 129 }, ErrInvalid},
		{"RingBytes 2048", func(c *Config) { c.RingBytes = 2048 }, ErrInvalid},
		{"RingBytes 4096", func(c *Config) { c.RingBytes = 4096 }, nil},
		{"RingBytes 6144 (not a power of two)", func(c *Config) { c.RingBytes = 6144 }, ErrInvalid},
		{"RingBytes equal to MaxMemory and to the 64 MiB ceiling", func(c *Config) { c.RingBytes = MaxMemoryBytes; c.MaxMemory = MaxMemoryBytes }, nil},
		{"RingBytes above the 64 MiB ceiling", func(c *Config) { c.RingBytes = 2 * MaxMemoryBytes; c.MaxMemory = MaxMemoryBytes }, ErrResourceBudget},
		{"RingBytes above MaxMemory", func(c *Config) { c.MaxMemory = 128 << 10; c.RingBytes = 256 << 10 }, ErrResourceBudget},
		{"RingBytes equal to MaxMemory", func(c *Config) { c.MaxMemory = 256 << 10 }, nil},
		{"ReorderWindow 99 ms", func(c *Config) { c.ReorderWindow = 99 * time.Millisecond }, ErrInvalid},
		{"ReorderWindow 101 ms", func(c *Config) { c.ReorderWindow = 101 * time.Millisecond }, ErrInvalid},
		{"ReorderWindow 0", func(c *Config) { c.ReorderWindow = 0 }, ErrInvalid},
		{"MaxMemory 0", func(c *Config) { c.MaxMemory = 0 }, ErrResourceBudget},
		{"MaxMemory at the ceiling", func(c *Config) { c.MaxMemory = MaxMemoryBytes }, nil},
		{"MaxMemory one byte above the ceiling", func(c *Config) { c.MaxMemory = MaxMemoryBytes + 1 }, ErrResourceBudget},
		{"PolicyRevision 0", func(c *Config) { c.PolicyRevision = 0 }, ErrInvalid},
	} {
		c := DefaultConfig(1)
		tc.edit(&c)
		got := c.Validate()
		if tc.want == nil && got != nil || tc.want != nil && !errors.Is(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCheckResourcesBoundaries(t *testing.T) {
	const page = 4096
	cfg := DefaultConfig(1)
	per := cfg.RingBytes + page
	fit := cfg.MaxMemory / per // 252 rings of 256 KiB plus a page fit in 64 MiB
	if fit != 252 {
		t.Fatalf("fixture assumes 252 rings fit, got %d", fit)
	}
	ok := func(name string, e error) {
		t.Helper()
		if e != nil {
			t.Errorf("%s: %v", name, e)
		}
	}
	bad := func(name string, e, want error) {
		t.Helper()
		if !errors.Is(e, want) {
			t.Errorf("%s: %v, want %v", name, e, want)
		}
	}
	ok("the largest ring count that fits", cfg.CheckResources(fit, page, 0, 4096))
	bad("one ring more", cfg.CheckResources(fit+1, page, 0, 4096), ErrResourceBudget)
	// export bytes come off the budget the rings share
	export := uint64(10 << 20)
	fitExport := (cfg.MaxMemory - export) / per
	ok("the largest ring count behind 10 MiB of export", cfg.CheckResources(fitExport, page, export, 4096))
	bad("one ring more behind 10 MiB of export", cfg.CheckResources(fitExport+1, page, export, 4096), ErrResourceBudget)
	bad("export bytes above the budget", cfg.CheckResources(1, page, cfg.MaxMemory+1, 4096), ErrResourceBudget)
	bad("export bytes filling the budget leave no ring", cfg.CheckResources(1, page, cfg.MaxMemory, 4096), ErrResourceBudget)
	// descriptors: one per ring
	ok("as many rings as descriptors", cfg.CheckResources(100, page, 0, 100))
	bad("one ring more than descriptors", cfg.CheckResources(101, page, 0, 100), ErrResourceBudget)
	// the metadata page counts in every ring
	huge := cfg.MaxMemory - cfg.RingBytes
	ok("a metadata page that makes one ring fill the budget", cfg.CheckResources(1, huge, 0, 4096))
	bad("a metadata page one byte larger", cfg.CheckResources(1, huge+1, 0, 4096), ErrResourceBudget)
	bad("two rings of that size", cfg.CheckResources(2, huge, 0, 4096), ErrResourceBudget)
	// invalid arguments and an invalid configuration keep their own refusal
	bad("no rings", cfg.CheckResources(0, page, 0, 4096), ErrInvalid)
	bad("no metadata page", cfg.CheckResources(1, 0, 0, 4096), ErrInvalid)
	bad("no rings and no page", cfg.CheckResources(0, 0, 0, 4096), ErrInvalid)
	broken := cfg
	broken.CPUHz = 100
	bad("an invalid configuration", broken.CheckResources(1, page, 0, 4096), ErrInvalid)
}
