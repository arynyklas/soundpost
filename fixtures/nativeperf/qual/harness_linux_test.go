//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
)

// realWorkload compiles the acceptance workload with the approved flags, starts
// it (ready, not released) and returns it with a function-address lookup computed
// independently from the ELF symbols and the live /proc/<pid>/maps. Skips when no
// C compiler exists.
func realWorkload(t *testing.T) (*Workload, func(name string) (start, size uint64)) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "workloads")
	src, _ := filepath.Abs("../acceptance/workloads.c")
	if out, err := exec.Command(cc, "-O2", "-pthread", "-fno-omit-frame-pointer", "-g", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("workload does not compile here: %v\n%s", err, out)
	}
	w, err := LaunchWorkload(LaunchOptions{Bin: bin, Mode: "cpu", Seconds: 1, Dir: dir, Nonce: "0123456789abcdef"})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	t.Cleanup(w.Kill)
	f, err := elf.Open(bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	syms, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	maps, _ := os.ReadFile("/proc/" + strconv.Itoa(w.PID) + "/maps")
	return w, func(name string) (uint64, uint64) {
		for _, s := range syms {
			if s.Name != name {
				continue
			}
			for _, p := range f.Progs {
				if p.Type != elf.PT_LOAD || s.Value < p.Vaddr || s.Value >= p.Vaddr+p.Filesz {
					continue
				}
				fileOff := s.Value - p.Vaddr + p.Off
				for _, line := range strings.Split(string(maps), "\n") {
					fields := strings.Fields(line)
					if len(fields) < 6 || !strings.Contains(fields[1], "x") || !strings.HasSuffix(fields[5], "/workloads") {
						continue
					}
					bounds := strings.Split(fields[0], "-")
					lo, _ := strconv.ParseUint(bounds[0], 16, 64)
					hi, _ := strconv.ParseUint(bounds[1], 16, 64)
					off, _ := strconv.ParseUint(fields[2], 16, 64)
					if fileOff >= off && fileOff < off+(hi-lo) {
						return lo + (fileOff - off), s.Size
					}
				}
			}
		}
		t.Fatalf("symbol %s not found in the running workload", name)
		return 0, 0
	}
}

func TestResolverNamesRealWorkloadFunctionsAndNeverInventsOthers(t *testing.T) {
	w, addr := realWorkload(t)
	r := w.Resolver()
	hot, hotSize := addr("spqual_hot")
	serve, _ := addr("spqual_serve")
	if got := r.Resolve(hot); got != "spqual_hot" {
		t.Errorf("hot function start resolved to %q", got)
	}
	if got := r.Resolve(hot + hotSize - 1); got != "spqual_hot" {
		t.Errorf("hot function last byte resolved to %q", got)
	}
	if got := r.Resolve(hot + hotSize); got == "spqual_hot" {
		t.Error("the byte after the hot function resolved to it")
	}
	if got := r.Resolve(serve + 3); got != "spqual_serve" {
		t.Errorf("serve resolved to %q", got)
	}
	if !r.InAnyExecutable(hot) || r.Classify(hot) != "target_executable" {
		t.Errorf("hot address classified %q", r.Classify(hot))
	}
	for _, ip := range []uint64{1, 0x7f0000000000, ^uint64(0) - 8000} {
		if r.Resolve(ip) != "" || r.InAnyExecutable(ip) {
			t.Errorf("address %#x resolved or counted as executable", ip)
		}
	}
}

func chainEvent(seq uint64, ip uint64, chain ...uint64) nativeperf.SanitizedEvent {
	return negEvent(seq, 5_000_000_000+seq*10_000_000, 31337, ip, chain...)
}

func TestAnalyzeCountsTheHotFunctionInRealChainsNotJustNonEmptyOnes(t *testing.T) {
	w, addr := realWorkload(t)
	r := w.Resolver()
	hot, _ := addr("spqual_hot")
	serve, _ := addr("spqual_serve")
	hot, serve = hot+1, serve+1
	var events []nativeperf.SanitizedEvent
	for i := uint64(1); i <= 10; i++ {
		events = append(events, chainEvent(i, hot, hot, serve, serve+8)) // frame-pointer chain: hot <- serve <- serve
	}
	for i := uint64(11); i <= 15; i++ {
		events = append(events, chainEvent(i, hot, hot)) // truncated chain: only the leaf
	}
	for i := uint64(16); i <= 20; i++ {
		events = append(events, chainEvent(i, 0x7f0000001000, 0x7f0000001000, 0x7f0000002000)) // deep non-empty chain, no workload frame
	}
	st := Analyze(events, r, "spqual_hot", []string{"spqual_hot", "spqual_serve"}, [][2]uint64{{5_000_000_000, 5_400_000_000}})
	if st.CPUSamples != 20 || st.ChainsWithHot != 15 || st.HotSamples != 15 {
		t.Errorf("samples %d, chains with hot %d, hot at IP %d (want 20/15/15)", st.CPUSamples, st.ChainsWithHot, st.HotSamples)
	}
	if st.Samples3Frames != 10 {
		t.Errorf("3-frame stacks: %d", st.Samples3Frames)
	}
	if st.ExpectedPresent["spqual_serve"] != 10 || st.NonLeaf["spqual_serve"] != 10 || st.NonLeaf["spqual_hot"] != 0 {
		t.Errorf("serve present %d, non-leaf %d, hot non-leaf %d (want 10/10/0)", st.ExpectedPresent["spqual_serve"], st.NonLeaf["spqual_serve"], st.NonLeaf["spqual_hot"])
	}
	if st.UnresolvedFrames < 10 {
		t.Errorf("frames outside the workload were not counted unresolved: %d", st.UnresolvedFrames)
	}
	if st.InWindow != 20 {
		t.Errorf("samples inside the ground-truth window: %d", st.InWindow)
	}
	if got, want := st.Coverage([]string{"spqual_hot", "spqual_serve"}), (15.0/20+10.0/20)/2; got < want-1e-9 || got > want+1e-9 {
		t.Errorf("coverage %.4f, want %.4f", got, want)
	}
	if st.Coverage(nil) != 0 || (StackStats{}).Coverage([]string{"x"}) != 0 {
		t.Error("coverage of nothing must be zero")
	}
	late := Analyze(events, r, "spqual_hot", nil, [][2]uint64{{1, 2}})
	if late.InWindow != 0 {
		t.Errorf("samples outside the window counted: %d", late.InWindow)
	}
}

func schedEvents(domain nativeperf.ClockDomain, key nativeperf.TaskKey, base uint64) []nativeperf.SanitizedEvent {
	k := key
	return []nativeperf.SanitizedEvent{
		{Kind: nativeperf.EventSwitch, Time: model.MonoNano(base), CPU: 0, Sequence: 1, Domain: domain,
			Switch: &nativeperf.SchedulerSwitch{Previous: &k, PreviousState: 1, MissingCallchain: nativeperf.ReasonMissingSwitchCallchain}},
		{Kind: nativeperf.EventWakeup, Time: model.MonoNano(base + 40_000_000), CPU: 0, Sequence: 2, Domain: domain, Task: key, Wakeup: &nativeperf.SchedulerWakeup{Target: key, TargetCPU: 0}},
		{Kind: nativeperf.EventSwitch, Time: model.MonoNano(base + 55_000_000), CPU: 0, Sequence: 3, Domain: domain, Switch: &nativeperf.SchedulerSwitch{Next: &k}},
	}
}

func TestCorrelateTurnsSchedulerEventsIntoBlockedAndRunnableIntervals(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	key := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	base := uint64(10_000_000_000)
	res := CaptureResult{
		Events: schedEvents(domain, key, base),
		Proofs: []nativeperf.AcquisitionProof{{Domain: domain, CPUs: []uint32{0}, Through: model.MonoNano(base - 1)}, {Domain: domain, CPUs: []uint32{0}, Through: model.MonoNano(base + 300_000_000), Final: true}},
	}
	c := Correlate(res, nativeperf.DefaultConfig(1))
	if c.Err != "" || c.ConsumeErrors != 0 || c.SwitchEvents != 2 || c.WakeupEvents != 1 {
		t.Fatalf("%+v", c)
	}
	var blocked, runnable uint64
	for _, iv := range c.Intervals {
		d := uint64(iv.End - iv.Start)
		switch iv.Kind {
		case nativeperf.IntervalBlocked:
			blocked += d
		case nativeperf.IntervalRunnable:
			runnable += d
		}
	}
	if blocked != 40_000_000 || runnable != 15_000_000 {
		t.Fatalf("blocked %d ns runnable %d ns, want 40 ms / 15 ms; intervals %+v", blocked, runnable, c.Intervals)
	}
	truth := []BlockedTruth{{TID: 7, Start: base, End: base + 40_000_000}}
	for i := 0; i < 20; i++ {
		truth = append(truth, truth[0])
	}
	// the single synthetic interval cannot satisfy 20 intervals: unknown, not pass
	if v := CompareBlocked(truth[:1], c.Intervals).Verdict; v != VerdictUnknown {
		t.Errorf("one interval compared as %s", v)
	}
}

func TestCorrelateRefusesCapturesWithoutBothProofs(t *testing.T) {
	domain := nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}
	key := nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	events := schedEvents(domain, key, 10_000_000_000)
	initial := nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: 9_999_999_999}
	final := nativeperf.AcquisitionProof{Domain: domain, CPUs: []uint32{0}, Through: 10_300_000_000, Final: true}
	for name, proofs := range map[string][]nativeperf.AcquisitionProof{"none": nil, "initial only": {initial}, "final only": {final}} {
		c := Correlate(CaptureResult{Events: events, Proofs: proofs}, nativeperf.DefaultConfig(1))
		if c.Err == "" || len(c.Intervals) != 0 {
			t.Errorf("%s: err %q with %d intervals", name, c.Err, len(c.Intervals))
		}
	}
}

func TestPercentilesAndGaps(t *testing.T) {
	p50, p99 := Percentiles([]uint64{9, 1, 5, 3, 7})
	if p50 != 5 || p99 != 9 {
		t.Errorf("p50 %d p99 %d", p50, p99)
	}
	if a, b := Percentiles(nil); a != 0 || b != 0 {
		t.Error("empty percentiles")
	}
	e := []nativeperf.SanitizedEvent{chainEvent(1, 0x401000), chainEvent(2, 0x401000), chainEvent(3, 0x401000)}
	gaps := SampleGaps(e)
	if len(gaps) != 2 || gaps[0] != 10_000_000 {
		t.Errorf("gaps %v", gaps)
	}
}

func TestNeedleScanFindsTheCanaryAndNothingElse(t *testing.T) {
	needles := [][]byte{[]byte("0123456789abcdef"), []byte("work0123456789"), nil}
	clean := []byte(`{"event":{"kind":"cpu_sample","cpu_sample":{"ip":"4198400"}}}`)
	dirty := []byte(`{"event":{"domain":{"host_id":"work0123456789"}}}`)
	both := []byte(`work0123456789 and 0123456789abcdef`)
	if CountNeedles(clean, needles) != 0 || CountNeedles(dirty, needles) != 1 || CountNeedles(both, needles) != 2 {
		t.Errorf("clean %d dirty %d both %d", CountNeedles(clean, needles), CountNeedles(dirty, needles), CountNeedles(both, needles))
	}
	if CountNeedles(dirty, nil) != 0 {
		t.Error("no needles must never hit")
	}
}
