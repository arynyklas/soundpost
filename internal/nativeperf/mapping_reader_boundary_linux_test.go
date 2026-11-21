//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
)

// Boundary pins for the mapping reader of a real process (l4w33 mutation battery D).

// The bytes of a process's maps and the mappings it may list are bounded by the policy, and each bound is exact: a map
// of exactly that size is read, a byte more is refused; exactly that many executable mappings are listed, one more is
// refused.
func TestMappingReaderBoundsAreExact(t *testing.T) {
	cmd, target, authorized := idleTarget(t)
	maps, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/maps")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseExecutableMaps(maps, 1<<20, 4096)
	if err != nil || len(rows) < 2 {
		t.Fatalf("%d executable rows: %v", len(rows), err)
	}
	read := func(adjust func(*SymbolPolicy)) error {
		t.Helper()
		policy := DefaultSymbolPolicy(1)
		adjust(&policy)
		reader, err := NewMappingReader(authorized, target, 1, policy)
		if err != nil {
			t.Skipf("the target cannot be read here: %v", err)
		}
		defer reader.Close()
		_, err = reader.Read(context.Background())
		return err
	}
	size := uint64(len(maps))
	if err := read(func(p *SymbolPolicy) { p.MaxMapsBytes = size }); err != nil {
		t.Errorf("a metadata bound of exactly the %d bytes of the maps: %v", size, err)
	}
	if err := read(func(p *SymbolPolicy) { p.MaxMapsBytes = size - 1 }); !errors.Is(err, ErrResourceBudget) {
		t.Errorf("a metadata bound of one byte less: %v, want ErrResourceBudget", err)
	}
	n := uint32(len(rows))
	if err := read(func(p *SymbolPolicy) { p.MaxMappings = n }); err != nil {
		t.Errorf("a bound of exactly the %d executable mappings: %v", n, err)
	}
	if err := read(func(p *SymbolPolicy) { p.MaxMappings = n - 1 }); !errors.Is(err, ErrResourceBudget) {
		t.Errorf("a bound of one mapping less: %v, want ErrResourceBudget", err)
	}
}

// Every executable mapping of the process is in the table: named when its file is a readable ELF of an approved build, as
// the reason it is not otherwise (and never silently dropped), and not at all above the bound of the table's entries.
func TestMappingReaderTableAccountsForEveryExecutableMapping(t *testing.T) {
	cmd, target, authorized := idleTarget(t)
	maps, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/maps")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseExecutableMaps(maps, 1<<20, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		policy := DefaultSymbolPolicy(1)
		policy.AllowMappedELF = allow
		reader, err := NewMappingReader(authorized, target, 1, policy)
		if err != nil {
			t.Skipf("the target cannot be read here: %v", err)
		}
		table, err := reader.Read(context.Background())
		reader.Close()
		if err != nil {
			t.Fatalf("AllowMappedELF=%v: %v", allow, err)
		}
		pathRows, unapproved, named := 0, 0, 0
		for _, row := range rows {
			if row.path != "" {
				pathRows++
			}
			covered := false
			for _, e := range table.entries {
				if e.start < row.end && e.end > row.start {
					covered = true
					if e.reason == FrameUnapproved {
						unapproved++
					}
					if e.module.ID != "" {
						named++
					}
				}
			}
			if !covered {
				t.Errorf("AllowMappedELF=%v: the executable mapping %#x-%#x is not in the table", allow, row.start, row.end)
			}
		}
		if !allow && (named != 0 || unapproved < pathRows) {
			t.Errorf("AllowMappedELF=false: %d named entries and %d unapproved ones for %d file-backed mappings; want none named and all unapproved", named, unapproved, pathRows)
		}
		if allow && named == 0 {
			t.Errorf("AllowMappedELF=true: the approved executable was not named: %+v", table.entries)
		}
		if allow && pathRows > 1 && unapproved == 0 {
			t.Errorf("AllowMappedELF=true: the files of builds that were not approved left no trace in the table: %+v", table.entries)
		}
	}
}
