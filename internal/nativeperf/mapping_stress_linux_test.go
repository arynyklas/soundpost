//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// Plan 04 task 6 (green step; 04.06-C17): repeat the identity and mapping reads with rapidly exiting processes, large
// maps, the same inode and path carrying a different build, and a file changed under the reader. Every case has to end
// bounded (allocation and descriptors) and to fail without echoing a pathname.

// allocated is the bytes the heap allocated while f ran (TotalAlloc is cumulative, so garbage counts).
func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("/proc/self/fd unreadable")
	}
	return len(ents)
}

func mapsLines(n int, perms, path string) []byte {
	var b bytes.Buffer
	for i := range n {
		start := uint64(0x10000) + uint64(i)*0x2000
		fmt.Fprintf(&b, "%x-%x %s 00000000 08:01 42 %s\n", start, start+0x1000, perms, path)
	}
	return b.Bytes()
}

func TestMappingStressLargeMapsAreRefusedWithinTheAllocationBound(t *testing.T) {
	policy := DefaultSymbolPolicy(1)
	const canary = "/home/PRIVATE_CANARY_STRESS/module"

	// a map far beyond the metadata budget is refused before it is parsed: nothing proportional to it is allocated
	huge := mapsLines(500_000, "r-xp", canary)
	if uint64(len(huge)) <= policy.MaxMapsBytes*10 {
		t.Fatalf("the oversized map is only %d bytes", len(huge))
	}
	var e error
	if got := allocated(func() { _, e = parseExecutableMaps(huge, policy.MaxMapsBytes, policy.MaxMappings) }); e != ErrResourceBudget || got > 64<<10 {
		t.Errorf("%d-byte map: err=%v after allocating %d bytes (want ErrResourceBudget within 64 KiB)", len(huge), e, got)
	}

	// a map inside the byte budget but with far more executable rows than the mapping budget is refused AT the budget:
	// what is allocated is what the budgeted rows cost, the same as for a map that has exactly one row too many
	within := mapsLines(int(policy.MaxMapsBytes)/48, "r-xp", canary)
	if uint64(len(within)) > policy.MaxMapsBytes {
		within = within[:policy.MaxMapsBytes]
		within = within[:bytes.LastIndexByte(within, '\n')+1]
	}
	exact := mapsLines(int(policy.MaxMappings)+1, "r-xp", canary)
	if bytes.Count(within, []byte("\n")) < 3*int(policy.MaxMappings) {
		t.Fatalf("only %d rows in the oversized map", bytes.Count(within, []byte("\n")))
	}
	var gotExact, gotWithin uint64
	gotExact = allocated(func() { _, e = parseExecutableMaps(exact, policy.MaxMapsBytes, policy.MaxMappings) })
	if e != ErrResourceBudget {
		t.Errorf("%d rows: err=%v, want ErrResourceBudget", policy.MaxMappings+1, e)
	}
	gotWithin = allocated(func() { _, e = parseExecutableMaps(within, policy.MaxMapsBytes, policy.MaxMappings) })
	t.Logf("allocated %d bytes for %d rows and %d bytes for %d rows (budget %d mappings)", gotExact, policy.MaxMappings+1, gotWithin, bytes.Count(within, []byte("\n")), policy.MaxMappings)
	if e != ErrResourceBudget || gotWithin > gotExact+gotExact/10+64<<10 {
		t.Errorf("%d rows: err=%v after allocating %d bytes, more than the %d a map one row over the budget costs", bytes.Count(within, []byte("\n")), e, gotWithin, gotExact)
	}
	if e != nil && strings.Contains(e.Error(), "PRIVATE_CANARY") {
		t.Error("a pathname was echoed")
	}

	// the same bytes with no executable row parse into nothing at an allocation linear in the (budgeted) input
	flat := mapsLines(int(policy.MaxMapsBytes)/48, "r--p", canary)
	if uint64(len(flat)) > policy.MaxMapsBytes {
		flat = flat[:bytes.LastIndexByte(flat[:policy.MaxMapsBytes], '\n')+1]
	}
	var rows []executableMap
	if got := allocated(func() { rows, e = parseExecutableMaps(flat, policy.MaxMapsBytes, policy.MaxMappings) }); e != nil || len(rows) != 0 || got > 32*policy.MaxMapsBytes {
		t.Errorf("%d non-executable rows: %d kept, err=%v, allocated %d (want none kept within %d)", bytes.Count(flat, []byte("\n")), len(rows), e, got, 32*policy.MaxMapsBytes)
	}

	// one line past the line budget is invalid, however it is spelled, and says nothing of its path
	long := []byte("1000-2000 r-xp 00000000 08:01 42 /home/PRIVATE_CANARY_STRESS/" + strings.Repeat("a", 8192) + "\n")
	if got := allocated(func() { _, e = parseExecutableMaps(long, policy.MaxMapsBytes, policy.MaxMappings) }); e != ErrInvalid || got > 64<<10 || strings.Contains(e.Error(), "PRIVATE_CANARY") {
		t.Errorf("an 8 KiB line: err=%v allocated %d", e, got)
	}
	// a line past the budget whose excess is padding, not a long path: only the line budget can refuse it
	padded := []byte("1000-2000 r-xp 00000000 08:01 42" + strings.Repeat(" ", 8200) + "/short\n")
	if got := allocated(func() { _, e = parseExecutableMaps(padded, policy.MaxMapsBytes, policy.MaxMappings) }); e != ErrInvalid || got > 64<<10 {
		t.Errorf("a padded 8 KiB line: err=%v allocated %d", e, got)
	}
	if _, e = parseExecutableMaps([]byte("1000-2000 r-xp 00000000 08:01 42"+strings.Repeat(" ", 8000)+"/short\n"), policy.MaxMapsBytes, policy.MaxMappings); e != nil {
		t.Errorf("a padded line inside the budget was refused: %v", e)
	}
}

func TestMappingStressRapidlyExitingProcessesNeverResolveToAnotherTask(t *testing.T) {
	self, err := ResolveLocalTarget(os.Getpid())
	if err != nil {
		t.Skip("local target unresolved:", err)
	}
	ns := NamespaceID(self.PIDNamespace)
	if _, err := exec.LookPath("true"); err != nil {
		t.Skip("no true(1)")
	}
	fds := openFDs(t)
	const rounds = 300
	var failed, resolved int
	got := allocated(func() {
		for range rounds {
			child := exec.Command("true")
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			pid := child.Process.Pid
			// race the exit: the child may be running, a zombie or gone while it is resolved
			key, err := resolveTask(pid, ns)
			child.Wait()
			if err == nil {
				resolved++
				if int(key.TGID) != pid || int(key.TID) != pid || key.PIDNamespace != self.PIDNamespace {
					t.Fatalf("pid %d resolved to %+v", pid, key)
				}
			} else {
				failed++
			}
			// once reaped the number names nothing, or somebody else: never the child's identity
			if again, err := resolveTask(pid, ns); err == nil && resolved > 0 && again == key {
				t.Fatalf("pid %d still resolves to the reaped child %+v", pid, key)
			}
		}
	})
	if resolved+failed != rounds {
		t.Fatalf("%d resolved and %d failed of %d", resolved, failed, rounds)
	}
	if after := openFDs(t); after != fds {
		t.Errorf("descriptors leaked by rapid exits: %d before, %d after", fds, after)
	}
	if got > rounds*2*(256<<10) {
		t.Errorf("%d bytes allocated for %d resolutions of exiting processes", got, rounds*2)
	}
}

func TestMappingStressSameInodeAndPathWithADifferentBuildIsNeverReadAsTheOldBuild(t *testing.T) {
	f := symbolFixture(t, "hot_loop")
	path := f.Name()
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	variants := [2][]byte{append([]byte(nil), base...), append([]byte(nil), base...)}
	copy(variants[1][272:], []byte{0xcd, 0x34})
	first, err := fileIdentity(f)
	if err != nil {
		t.Fatal(err)
	}
	fds := openFDs(t)
	got := allocated(func() {
		for i := range 400 {
			want := []string{"ab12", "cd34"}[i%2]
			// the same path and the same inode: an in-place rewrite, as a build tool or an attacker would do
			if err := os.WriteFile(path, variants[i%2], 0o600); err != nil {
				t.Fatal(err)
			}
			g, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			id, err := fileIdentity(g)
			if err != nil || id.inode != first.inode || id.device != first.device {
				t.Fatalf("round %d: the rewrite changed the inode (%+v vs %+v, %v)", i, id, first, err)
			}
			layout, err := readELFLayout(&boundedELF{ctx: context.Background(), input: g, max: 1 << 20})
			g.Close()
			if err != nil || layout.buildID != want {
				t.Fatalf("round %d: build %q (err %v), want %q: a stale build was read", i, layout.buildID, err, want)
			}
		}
	})
	if after := openFDs(t); after != fds {
		t.Errorf("descriptors leaked: %d before, %d after", fds, after)
	}
	if got > 400*(512<<10) {
		t.Errorf("%d bytes allocated for 400 layout reads", got)
	}
}

// A file that grows or shrinks while it is read can never keep its identity: the reader compares the identity it took
// before and after the parse and marks the mapping unreadable instead of mixing two files.
func TestMappingStressFileChangedUnderTheReaderChangesItsIdentity(t *testing.T) {
	f := symbolFixture(t, "hot_loop")
	base, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	for i := range 200 {
		before, err := fileIdentity(f)
		if err != nil {
			t.Fatal(err)
		}
		changed := append(append([]byte(nil), base...), bytes.Repeat([]byte{byte(i)}, 1+i%7)...)
		if err := os.WriteFile(f.Name(), changed, 0o600); err != nil {
			t.Fatal(err)
		}
		after, err := fileIdentity(f)
		if err != nil || before == after || before.inode != after.inode {
			t.Fatalf("round %d: a change of %d bytes under the reader kept the identity (%+v, %+v, %v)", i, len(changed)-len(base), before, after, err)
		}
		if err := os.WriteFile(f.Name(), base, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Invalid and truncated ELF objects of every length fail with ErrInvalid or ErrResourceBudget, bounded, and echo no path.
func TestMappingStressInvalidELFObjectsFailBounded(t *testing.T) {
	f := symbolFixture(t, "hot_loop")
	base, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	got := allocated(func() {
		for n := 0; n < len(base); n += 17 {
			p := fmt.Sprintf("%s/PRIVATE_CANARY_ELF_%d", dir, n)
			if err := os.WriteFile(p, base[:n], 0o600); err != nil {
				t.Fatal(err)
			}
			g, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = readELFLayout(&boundedELF{ctx: context.Background(), input: g, max: 1 << 20})
			g.Close()
			if n < 64 && err == nil {
				t.Fatalf("a %d-byte object parsed", n)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE_CANARY") {
				t.Fatalf("a pathname was echoed: %v", err)
			}
		}
	})
	if got > 64*(1<<20) {
		t.Errorf("%d bytes allocated for %d truncated objects", got, len(base)/17+1)
	}
}
