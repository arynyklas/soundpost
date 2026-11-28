//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"io"
	"os"
	"syscall"
	"testing"
)

const (
	testPage     = 4096
	testOverhead = uint64(1<<20) + 256<<10 // fixed buffers charged for one target
)

func authTargets(n int, mode CaptureMode) AuthorizedTargets {
	return AuthorizedTargets{targets: make([]Target, n), mode: mode}
}

// smallRing is the smallest valid ring: the per-ring charge is exactly 2 pages.
func smallRing(maxMemory uint64) Config {
	c := DefaultConfig(1)
	c.RingBytes = testPage
	c.MaxMemory = maxMemory
	return c
}

func TestReserveChargesExactlyWhatItOwes(t *testing.T) {
	cfg := DefaultConfig(1)
	per := cfg.RingBytes + testPage
	for _, tc := range []struct {
		name    string
		a       AuthorizedTargets
		cpus    uint64
		fds     uint64
		memory  uint64
		cpuRing uint64
	}{
		{"one target, cpu", authTargets(1, ModeCPU), 8, 1 + 3 + 2, per + testOverhead, 1},
		{"two targets, cpu", authTargets(2, ModeCPU), 8, 2 + 6 + 2, 2*per + uint64(1<<20) + 2*(256<<10), 2},
		{"one target, cpu+offcpu on 4 CPUs", authTargets(1, ModeCPUOffCPU), 4, 13 + 3 + 2, 13*per + testOverhead, 1},
		{"two targets, cpu+offcpu on 2 CPUs", authTargets(2, ModeCPUOffCPU), 2, 8 + 6 + 2, 8*per + uint64(1<<20) + 2*(256<<10), 2},
	} {
		b := NewResourceBudget()
		r, e := b.Reserve(tc.a, cfg, Topology{CPUs: tc.cpus, FDLimit: 4096, PageBytes: testPage}, MemoryUsage{})
		if e != nil {
			t.Fatalf("%s: %v", tc.name, e)
		}
		if r.FDs != tc.fds || r.Memory != tc.memory || r.cpuRings != tc.cpuRing || b.fds != tc.fds || b.memory != tc.memory {
			t.Errorf("%s: lease fds %d memory %d rings %d (budget %d/%d), want %d/%d/%d", tc.name, r.FDs, r.Memory, r.cpuRings, b.fds, b.memory, tc.fds, tc.memory, tc.cpuRing)
		}
		if r.fdCeiling != 256 || r.workingLimit != cfg.MaxMemory {
			t.Errorf("%s: ceiling %d working limit %d", tc.name, r.fdCeiling, r.workingLimit)
		}
	}
}

func TestReserveRefusesBadTopologyAndConfig(t *testing.T) {
	cfg := DefaultConfig(1)
	ok := Topology{CPUs: 8, FDLimit: 4096, OpenFDs: 8, PageBytes: testPage}
	if _, e := NewResourceBudget().Reserve(authTargets(1, ModeCPU), cfg, ok, MemoryUsage{}); e != nil {
		t.Fatal(e)
	}
	bad := cfg
	bad.CPUHz = 50
	for name, tc := range map[string]struct {
		a AuthorizedTargets
		c Config
		t Topology
	}{
		"invalid config":      {authTargets(1, ModeCPU), bad, ok},
		"no targets":          {authTargets(0, ModeCPU), cfg, ok},
		"no CPUs":             {authTargets(1, ModeCPU), cfg, Topology{FDLimit: 4096, OpenFDs: 8, PageBytes: testPage}},
		"no page size":        {authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, FDLimit: 4096, OpenFDs: 8}},
		"FD limit 32":         {authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, FDLimit: 32, PageBytes: testPage}},
		"FD limit 0":          {authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, PageBytes: testPage}},
		"open FDs fill limit": {authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, FDLimit: 4096, OpenFDs: 4096 - 31, PageBytes: testPage}},
		"257 CPUs offcpu":     {authTargets(1, ModeCPUOffCPU), cfg, Topology{CPUs: 257, FDLimit: 1 << 20, PageBytes: testPage}},
		"page above budget":   {authTargets(1, ModeCPU), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: cfg.MaxMemory}},
	} {
		b := NewResourceBudget()
		if _, e := b.Reserve(tc.a, tc.c, tc.t, MemoryUsage{}); !errors.Is(e, ErrResources) {
			t.Errorf("%s: err %v", name, e)
		}
		if b.fds != 0 || b.memory != 0 {
			t.Errorf("%s: refusal charged the budget", name)
		}
	}
}

// The FD ceiling is min(256, FDLimit-32-OpenFDs) and the charge must fit it exactly.
func TestReserveFDCeilingIsExact(t *testing.T) {
	cfg := smallRing(MaxMemoryBytes)
	// One target with cpu+offcpu on C CPUs charges 6+3C FDs; two targets charge 10+3C.
	for _, tc := range []struct {
		name    string
		targets int
		cpus    uint64
		limit   uint64
		open    uint64
		accept  bool
	}{
		{"fits the limit exactly", 1, 4, 32 + 18 + 5, 5, true},
		{"one FD over the limit", 1, 4, 32 + 18 + 5 - 1, 5, false},
		{"one more open FD than the limit allows", 1, 4, 32 + 18 + 5, 6, false},
		{"hard cap 256 reached exactly", 2, 82, 1 << 20, 0, true},
		{"hard cap 256 exceeded by 3", 2, 83, 1 << 20, 0, false},
		{"offcpu charges three rings per CPU, not two", 1, 83, 1 << 20, 0, true}, // 6+249 = 255
		{"offcpu on 84 CPUs", 1, 84, 1 << 20, 0, false},                          // 258
	} {
		r, e := NewResourceBudget().Reserve(authTargets(tc.targets, ModeCPUOffCPU), cfg, Topology{CPUs: tc.cpus, FDLimit: tc.limit, OpenFDs: tc.open, PageBytes: testPage}, MemoryUsage{})
		if (e == nil) != tc.accept {
			t.Errorf("%s: err %v, accept %v", tc.name, e, tc.accept)
		}
		if r != nil {
			r.Close()
		}
	}
}

func TestReserveMemoryBoundsAreExact(t *testing.T) {
	// RingBytes 4096: one target costs 8192 + 1.25 MiB fixed; helper and export RSS are added on top and each is bounded.
	const helper, export = 5000, 7000
	need := uint64(2*testPage) + testOverhead + helper + export
	topology := Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}
	reserve := func(max, h, e uint64) error {
		r, err := NewResourceBudget().Reserve(authTargets(1, ModeCPU), smallRing(max), topology, MemoryUsage{HelperRSS: h, ExportRSS: e})
		if r != nil {
			if r.Memory != uint64(2*testPage)+testOverhead+h+e {
				return errors.New("wrong charge")
			}
			r.Close()
		}
		return err
	}
	if e := reserve(need, helper, export); e != nil {
		t.Fatalf("exact fit refused: %v", e)
	}
	if e := reserve(need-1, helper, export); !errors.Is(e, ErrResources) {
		t.Fatalf("one byte over accepted: %v", e)
	}
	// Each RSS term alone is bounded (a huge value must not wrap or be skipped).
	if e := reserve(need, uint64(1)<<62, 0); !errors.Is(e, ErrResources) {
		t.Fatalf("helper RSS unbounded: %v", e)
	}
	if e := reserve(need, 0, uint64(1)<<62); !errors.Is(e, ErrResources) {
		t.Fatalf("export RSS unbounded: %v", e)
	}
	// The fixed overhead alone must not fit a budget below it.
	if e := reserve(testOverhead, 0, 0); !errors.Is(e, ErrResources) {
		t.Fatalf("fixed overhead not charged: %v", e)
	}
	// Ring bytes larger than the whole budget minus a page are refused (the data area + metadata page never exceed it).
	big := DefaultConfig(1)
	big.RingBytes = 1 << 20
	big.MaxMemory = 1<<20 + testPage - 1
	if _, e := NewResourceBudget().Reserve(authTargets(1, ModeCPU), big, topology, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Fatalf("metadata page not part of the ring charge: %v", e)
	}
}

func TestReserveSharesOneBudgetAcrossLeases(t *testing.T) {
	topology := Topology{CPUs: 8, FDLimit: 32 + 12, PageBytes: testPage} // ceiling 12 = two one-target CPU leases (6 each)
	each := uint64(2*testPage) + testOverhead
	cfg := smallRing(2 * each)
	b := NewResourceBudget()
	first, e := b.Reserve(authTargets(1, ModeCPU), cfg, topology, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	second, e := b.Reserve(authTargets(1, ModeCPU), cfg, topology, MemoryUsage{})
	if e != nil {
		t.Fatalf("exact share of memory and FDs refused: %v", e)
	}
	if b.fds != 12 || b.memory != 2*each {
		t.Fatalf("budget %d/%d", b.fds, b.memory)
	}
	if _, e := b.Reserve(authTargets(1, ModeCPU), cfg, topology, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Fatal("third lease over the shared budget accepted")
	}
	if b.fds != 12 || b.memory != 2*each {
		t.Fatal("refused lease charged the budget")
	}
	first.Close()
	third, e := b.Reserve(authTargets(1, ModeCPU), cfg, topology, MemoryUsage{})
	if e != nil {
		t.Fatalf("released share not reusable: %v", e)
	}
	// Memory alone: one byte less budget than two leases, FDs plentiful.
	roomy := Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}
	tight := smallRing(2*each - 1)
	second.Close()
	third.Close()
	m := NewResourceBudget()
	a, e := m.Reserve(authTargets(1, ModeCPU), tight, roomy, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := m.Reserve(authTargets(1, ModeCPU), tight, roomy, MemoryUsage{}); !errors.Is(e, ErrResources) {
		t.Fatal("shared memory bound not enforced")
	}
	a.Close()
}

type recordingCloser struct {
	log  *[]int
	id   int
	fail error
}

func (c recordingCloser) Close() error { *c.log = append(*c.log, c.id); return c.fail }

func TestReservationOwnsAndClosesInReverse(t *testing.T) {
	b := NewResourceBudget()
	r, e := b.Reserve(authTargets(1, ModeCPU), DefaultConfig(1), Topology{CPUs: 1, FDLimit: 4096, PageBytes: testPage}, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	var log []int
	boom, later := errors.New("first failure"), errors.New("second failure")
	// The lease owns exactly r.FDs resources; one more is closed and refused.
	for i := 0; uint64(i) < r.FDs; i++ {
		var fail error
		switch i {
		case 1:
			fail = boom
		case 3:
			fail = later
		}
		if e := r.Own(recordingCloser{&log, i, fail}); e != nil {
			t.Fatalf("own %d: %v", i, e)
		}
	}
	log = nil
	if e := r.Own(recordingCloser{&log, 99, nil}); !errors.Is(e, ErrResources) || len(log) != 1 || log[0] != 99 {
		t.Fatalf("overflow own: %v closed %v", e, log)
	}
	log = nil
	// Close releases in reverse order, closes all even after a failure, and reports the first failure met (in close order).
	if e := r.Close(); e != later {
		t.Fatalf("Close error %v, want the first failure in close order", e)
	}
	want := []int{5, 4, 3, 2, 1, 0}
	if len(log) != len(want) {
		t.Fatalf("closed %v", log)
	}
	for i := range want {
		if log[i] != want[i] {
			t.Fatalf("closed %v, want %v", log, want)
		}
	}
	if b.fds != 0 || b.memory != 0 {
		t.Fatal("budget not released")
	}
	log = nil
	if e := r.Own(recordingCloser{&log, 7, nil}); !errors.Is(e, ErrResources) || len(log) != 1 {
		t.Fatalf("own on a closed lease: %v closed %v", e, log)
	}
	if e := r.Close(); e != nil || len(r.owned) != 0 {
		t.Fatalf("second close: %v", e)
	}
}

func extendable(t *testing.T, b *ResourceBudget, cfg Config, topology Topology) *Reservation {
	t.Helper()
	r, e := b.Reserve(authTargets(1, ModeCPU), cfg, topology, MemoryUsage{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestCPURingExtensionBoundsAreExact(t *testing.T) {
	needs4KPages(t)
	roomy := Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage} // ceiling 256, the lease holds 6
	cfg := smallRing(MaxMemoryBytes)
	r := extendable(t, NewResourceBudget(), cfg, roomy)
	if _, e := (*Reservation)(nil).ReserveCPURings(2, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("nil lease: %v", e)
	}
	badCfg := cfg
	badCfg.CPUHz = 50
	for name, tc := range map[string]struct {
		total uint64
		c     Config
		page  uint64
	}{
		"zero rings":          {0, cfg, testPage},
		"257 rings":           {257, cfg, testPage},
		"invalid config":      {2, badCfg, testPage},
		"wrong page size":     {2, DefaultConfig(1), 2 * testPage},
		"fewer than baseline": {0, cfg, testPage},
	} {
		if _, e := r.ReserveCPURings(tc.total, tc.c, tc.page); !errors.Is(e, ErrResources) {
			t.Errorf("%s: %v", name, e)
		}
	}
	if r.FDs != 6 || r.cpuRings != 1 {
		t.Fatal("refusals charged the lease")
	}
	// FD ceiling: the lease holds 6 and may grow to exactly 256.
	if _, e := r.ReserveCPURings(252, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("257 FDs accepted: %v", e)
	}
	rollback, e := r.ReserveCPURings(251, cfg, testPage)
	if e != nil {
		t.Fatalf("exactly the ceiling refused: %v", e)
	}
	if r.FDs != 256 || r.cpuRings != 251 || r.Memory != (251*(cfg.RingBytes+testPage))+testOverhead {
		t.Fatalf("lease after extension: fds %d rings %d memory %d", r.FDs, r.cpuRings, r.Memory)
	}
	rollback()
	// Re-requesting the same total is a no-op extension, a smaller one is refused.
	same, e := r.ReserveCPURings(1, cfg, testPage)
	if e != nil || r.FDs != 6 || r.cpuRings != 1 {
		t.Fatalf("no-op extension: %v fds %d", e, r.FDs)
	}
	same()
	three, e := r.ReserveCPURings(3, cfg, testPage)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := r.ReserveCPURings(2, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatal("shrinking below the current rings accepted")
	}
	three()
	r.Close()
	if _, e := r.ReserveCPURings(2, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatal("closed lease extended")
	}
}

func TestCPURingExtensionMemoryAndSharedBudget(t *testing.T) {
	needs4KPages(t)
	roomy := Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage}
	each := uint64(2*testPage) + testOverhead // lease memory at RingBytes 4096
	// Lease memory bound: baseline each + 3 extra rings of 8192 exactly fits; one byte less does not.
	fit := smallRing(each + 3*2*testPage)
	r := extendable(t, NewResourceBudget(), fit, roomy)
	if _, e := r.ReserveCPURings(4, smallRing(each+3*2*testPage-1), testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("one byte over the memory bound accepted: %v", e)
	}
	if r.Memory != each {
		t.Fatal("refusal charged memory")
	}
	rollback, e := r.ReserveCPURings(4, fit, testPage)
	if e != nil {
		t.Fatalf("exact memory refused: %v", e)
	}
	if r.Memory != each+3*2*testPage {
		t.Fatalf("memory %d", r.Memory)
	}
	rollback()
	// A single extension bigger than the whole budget is refused without overflow.
	if _, e := r.ReserveCPURings(256, smallRing(2*testPage), testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("extension beyond the working limit accepted: %v", e)
	}

	// Shared budget: two leases may each fit alone but not together, in memory...
	shared := NewResourceBudget()
	cfg := smallRing(2*each + 2*2*testPage)
	a := extendable(t, shared, cfg, roomy)
	b := extendable(t, shared, cfg, roomy)
	if _, e := a.ReserveCPURings(2, cfg, testPage); e != nil {
		t.Fatalf("first extension: %v", e)
	}
	if _, e := b.ReserveCPURings(3, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("shared memory bound not enforced: %v", e)
	}
	if rb, e := b.ReserveCPURings(2, cfg, testPage); e != nil {
		t.Fatalf("exact shared memory refused: %v", e)
	} else {
		rb()
	}
	// ...and in FDs (ceiling 256 shared by all leases of the budget).
	sharedFD := NewResourceBudget()
	big := smallRing(MaxMemoryBytes)
	c := extendable(t, sharedFD, big, roomy) // 6 FDs
	d := extendable(t, sharedFD, big, roomy) // 6 FDs
	if _, e := c.ReserveCPURings(126, big, testPage); e != nil {
		t.Fatalf("first FD extension: %v", e) // +125 -> budget 137
	}
	if _, e := d.ReserveCPURings(121, big, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("shared FD ceiling not enforced: %v", e) // +120 -> 257
	}
	if rb, e := d.ReserveCPURings(120, big, testPage); e != nil {
		t.Fatalf("exact shared FDs refused: %v", e) // +119 -> 256
	} else {
		rb()
	}
}

func TestCPURingExtensionRollbackKeepsEarlierOwnership(t *testing.T) {
	needs4KPages(t)
	cfg := DefaultConfig(1)
	r := extendable(t, NewResourceBudget(), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage})
	before, e := os.CreateTemp(t.TempDir(), "before")
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Own(before); e != nil {
		t.Fatal(e)
	}
	rollback, e := r.ReserveCPURings(3, cfg, testPage)
	if e != nil {
		t.Fatal(e)
	}
	after, e := os.CreateTemp(t.TempDir(), "after")
	if e != nil {
		t.Fatal(e)
	}
	if e := r.Own(after); e != nil {
		t.Fatal(e)
	}
	rollback()
	if _, e := after.Stat(); e == nil {
		t.Fatal("resource opened during the extension survived the rollback")
	}
	if _, e := before.Stat(); e != nil {
		t.Fatalf("rollback closed a resource opened before the extension: %v", e)
	}
	if len(r.owned) != 1 || r.cpuRings != 1 {
		t.Fatalf("owned %d rings %d after rollback", len(r.owned), r.cpuRings)
	}
}

func openFDCount(t *testing.T) uint64 {
	t.Helper()
	dir, e := os.Open("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	names, e := dir.ReadDir(1025)
	if e != nil && e != io.EOF {
		t.Fatal(e)
	}
	return uint64(len(names))
}

// The process FD limit is checked against what the process really has open before a single perf FD is opened.
func TestCPURingExtensionChecksProcessFDLimit(t *testing.T) {
	needs4KPages(t)
	cfg := DefaultConfig(1)
	r := extendable(t, NewResourceBudget(), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage})
	var saved syscall.Rlimit
	if e := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &saved); e != nil {
		t.Fatal(e)
	}
	restore := func() {
		if e := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &saved); e != nil {
			t.Fatal(e)
		}
	}
	defer restore()
	set := func(cur uint64) {
		l := saved
		l.Cur = cur
		if e := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &l); e != nil {
			t.Fatal(e)
		}
	}
	const total = 10
	open := openFDCount(t) // includes the /proc/self/fd handle itself, exactly as ReserveCPURings counts
	if open >= 31 {
		t.Skipf("process already holds %d FDs", open)
	}
	results := map[string]error{}
	attempt := func(name string, cur uint64) {
		set(cur)
		rollback, e := r.ReserveCPURings(total, cfg, testPage)
		if e == nil {
			rollback()
		}
		results[name] = e
		restore()
	}
	attempt("exact fit", open+total+32)
	attempt("one over", open+total+32-1)
	attempt("limit below the 32 reserve", 31)
	if results["exact fit"] != nil {
		t.Errorf("exact FD fit refused: %v", results["exact fit"])
	}
	if !errors.Is(results["one over"], ErrResources) {
		t.Errorf("one FD over accepted: %v", results["one over"])
	}
	if !errors.Is(results["limit below the 32 reserve"], ErrResources) {
		t.Errorf("limit below the 32-FD reserve accepted: %v", results["limit below the 32 reserve"])
	}
}

func needs4KPages(t *testing.T) {
	t.Helper()
	if os.Getpagesize() != testPage {
		t.Skipf("fixture arithmetic assumes %d-byte pages, this kernel has %d", testPage, os.Getpagesize())
	}
}

// A lease may only be extended while the budget's total FDs fit the lease's own ceiling; a lease reserved under a
// higher ceiling by someone else must not let a low-ceiling lease slip through (unsigned wraparound in the headroom).
func TestCPURingExtensionRefusesWhenBudgetExceedsOwnCeiling(t *testing.T) {
	needs4KPages(t)
	cfg := smallRing(MaxMemoryBytes)
	budget := NewResourceBudget()
	// The low lease has ceiling 50 and holds 6; the big one is reserved under ceiling 256 and holds 6+240.
	low := extendable(t, budget, cfg, Topology{CPUs: 8, FDLimit: 32 + 50, PageBytes: testPage})
	big, e := budget.Reserve(authTargets(1, ModeCPUOffCPU), cfg, Topology{CPUs: 80, FDLimit: 4096, PageBytes: testPage}, MemoryUsage{})
	if e != nil {
		t.Fatalf("setup: %v", e)
	}
	defer big.Close()
	if budget.fds <= 50 {
		t.Fatalf("setup: budget holds only %d FDs", budget.fds)
	}
	if _, e := low.ReserveCPURings(2, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("extension accepted with the budget already above this lease's ceiling: %v", e)
	}
}

// More than 1024 open FDs in the process is refused outright, whatever the rlimit says.
func TestCPURingExtensionRefusesProcessWithOver1024FDs(t *testing.T) {
	needs4KPages(t)
	var limit syscall.Rlimit
	if e := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); e != nil || limit.Cur < 1200 {
		t.Skipf("RLIMIT_NOFILE %d too low to open 1100 descriptors", limit.Cur)
	}
	cfg := smallRing(MaxMemoryBytes)
	r := extendable(t, NewResourceBudget(), cfg, Topology{CPUs: 8, FDLimit: 4096, PageBytes: testPage})
	var held []*os.File
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	for i := 0; i < 1100; i++ {
		f, e := os.Open("/dev/null")
		if e != nil {
			t.Fatal(e)
		}
		held = append(held, f)
	}
	if _, e := r.ReserveCPURings(2, cfg, testPage); !errors.Is(e, ErrResources) {
		t.Fatalf("a process with over 1024 FDs was extended: %v", e)
	}
}
