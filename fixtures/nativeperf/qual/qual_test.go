// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/nativeperf"
)

const testTGID = 4242

var testDomain = nativeperf.ClockDomain{HostID: "host-a", BootID: "boot-a"}

func cpuEvent(seq uint64, at uint64, tid uint32, ip uint64, chain ...uint64) nativeperf.SanitizedEvent {
	var cc []nativeperf.CallchainEntry
	cc = append(cc, nativeperf.CallchainEntry{Context: nativeperf.ContextUser})
	for _, c := range chain {
		cc = append(cc, nativeperf.CallchainEntry{IP: model.Uint64(c)})
	}
	return nativeperf.SanitizedEvent{
		Kind: nativeperf.EventCPU, Time: model.MonoNano(at), CPU: 1, Sequence: model.Uint64(seq), Domain: testDomain,
		Task: nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: testTGID, TID: tid, ProcessStart: 1, Generation: 1},
		CPUEvent: &nativeperf.CPUSample{IP: model.Uint64(ip), Callchain: cc, Method: nativeperf.MethodSoftwareCPUClock,
			Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: model.Uint64(10_000_000 + seq%7)},
	}
}

func inExe(ip uint64) bool     { return ip >= 0x400000 && ip < 0x500000 }
func knownTID(tid uint32) bool { return tid == testTGID || tid == testTGID+1 }

func evidence(events []nativeperf.SanitizedEvent) CaptureEvidence {
	return CaptureEvidence{Events: events, TargetTGID: testTGID, WorkloadCPUSeconds: 10, InExecutable: inExe, KnownThread: knownTID}
}

// genuineLooking is a positive control: jittered timestamps, varying IPs and
// stacks, in-target addresses. The checker must not reject everything.
func genuineLooking(n int) []nativeperf.SanitizedEvent {
	var out []nativeperf.SanitizedEvent
	at := uint64(1_000_000_000)
	for i := 0; i < n; i++ {
		at += 10_100_000 + uint64((i*7919)%2_000_003)
		ip := 0x401000 + uint64((i*37)%64)
		out = append(out, cpuEvent(uint64(i+1), at, testTGID+uint32(i%2), ip, 0x402000+uint64(i%5), 0x403000))
	}
	return out
}

// syntheticSampler is the contaminated "sampler": it fabricates a perfect
// cadence of identical samples that look plausible by count alone.
func syntheticSampler(n int) []nativeperf.SanitizedEvent {
	var out []nativeperf.SanitizedEvent
	for i := 0; i < n; i++ {
		out = append(out, cpuEvent(uint64(i+1), uint64(1_000_000_000+i*10_101_010), testTGID, 0x401000, 0x402000, 0x403000))
	}
	return out
}

func TestPositiveControlGenuineLookingCaptureIsAccepted(t *testing.T) {
	if err := CheckCapture(evidence(genuineLooking(300))); err != nil {
		t.Fatalf("a plausible real capture was rejected: %v", err)
	}
}

func TestRejectsStagedAcquisitionPending(t *testing.T) {
	var staged nativeperf.Session // zero Session: the staged "pending" path
	_, stagedErr := staged.Next(context.Background())
	for name, e := range map[string]error{
		"sentinel":     nativeperf.ErrAcquisitionPending,
		"wrapped":      fmt.Errorf("open: %w", nativeperf.ErrAcquisitionPending),
		"capability":   &nativeperf.CapabilityError{Status: nativeperf.Unsupported, Reason: nativeperf.ReasonAcquisition},
		"zero_session": stagedErr,
	} {
		ev := evidence(genuineLooking(300))
		ev.OpenError = e
		if err := CheckCapture(ev); !errors.Is(err, ErrStagedPending) {
			t.Errorf("%s: got %v, want ErrStagedPending", name, err)
		}
	}
}

func TestGenuinePermissionDenialStaysDistinct(t *testing.T) {
	ev := evidence(nil)
	ev.OpenError = &nativeperf.CapabilityError{Status: nativeperf.Denied, Reason: nativeperf.ReasonPermission}
	err := CheckCapture(ev)
	if err == nil {
		t.Fatal("a denied capture was accepted")
	}
	for _, bad := range []error{ErrStagedPending, ErrEmptySession, ErrSyntheticSamples, ErrNoopSampler} {
		if errors.Is(err, bad) {
			t.Fatalf("permission denial was classified as %v", bad)
		}
	}
	var ce *nativeperf.CapabilityError
	if !errors.As(err, &ce) || ce.Status != nativeperf.Denied {
		t.Fatalf("denial lost its typed error: %v", err)
	}
}

func TestRejectsSuccessfulEmptySession(t *testing.T) {
	if err := CheckCapture(evidence(nil)); !errors.Is(err, ErrEmptySession) {
		t.Fatalf("got %v, want ErrEmptySession", err)
	}
	if err := CheckCapture(evidence([]nativeperf.SanitizedEvent{})); !errors.Is(err, ErrEmptySession) {
		t.Fatalf("got %v, want ErrEmptySession", err)
	}
}

func TestRejectsNoopSampler(t *testing.T) {
	// only non-sample events although the workload burned 10 s of CPU
	loss := nativeperf.SanitizedEvent{Kind: nativeperf.EventLoss, Time: 5, Sequence: 1, Domain: testDomain,
		Task: nativeperf.TaskKey{BootID: "boot-a", PIDNamespace: 1, TGID: testTGID, TID: testTGID, ProcessStart: 1, Generation: 1},
		Loss: &nativeperf.LossEvent{Count: 1, Reason: nativeperf.ReasonLoss}}
	if err := CheckCapture(evidence([]nativeperf.SanitizedEvent{loss})); !errors.Is(err, ErrNoopSampler) {
		t.Fatalf("only-loss capture: got %v, want ErrNoopSampler", err)
	}
	// a trickle: 10 samples for ~990 expected
	if err := CheckCapture(evidence(genuineLooking(10))); !errors.Is(err, ErrNoopSampler) {
		t.Fatalf("trickle capture: got %v, want ErrNoopSampler", err)
	}
}

func TestRejectsSyntheticSamples(t *testing.T) {
	cases := map[string]func() CaptureEvidence{
		"identical_perfect_cadence": func() CaptureEvidence { return evidence(syntheticSampler(300)) },
		"perfect_cadence_varying_ip": func() CaptureEvidence {
			ev := genuineLooking(300)
			for i := range ev {
				ev[i].Time = model.MonoNano(1_000_000_000 + i*10_101_010)
			}
			return evidence(ev)
		},
		"identical_samples_jittered_time": func() CaptureEvidence {
			ev := genuineLooking(300)
			for i := range ev {
				ev[i].CPUEvent.IP = 0x401000
				ev[i].CPUEvent.Callchain = ev[0].CPUEvent.Callchain
			}
			return evidence(ev)
		},
		"foreign_process": func() CaptureEvidence {
			ev := genuineLooking(300)
			for i := range ev {
				ev[i].Task.TGID = testTGID + 1
			}
			return evidence(ev)
		},
		"addresses_outside_target": func() CaptureEvidence {
			ev := genuineLooking(300)
			for i := range ev {
				ev[i].CPUEvent.IP = model.Uint64(0x7f0000000000 + uint64(i))
			}
			return evidence(ev)
		},
		"unknown_threads": func() CaptureEvidence {
			ev := genuineLooking(300)
			for i := range ev {
				ev[i].Task.TID = uint32(90000 + i%3)
			}
			return evidence(ev)
		},
		"time_goes_backwards": func() CaptureEvidence {
			ev := genuineLooking(300)
			ev[100].Time, ev[102].Time = ev[102].Time, ev[100].Time
			return evidence(ev)
		},
		"unverifiable_no_target_evidence": func() CaptureEvidence {
			ev := evidence(genuineLooking(300))
			ev.InExecutable = nil
			return ev
		},
	}
	for name, mk := range cases {
		if err := CheckCapture(mk()); err == nil || (!errors.Is(err, ErrSyntheticSamples) && !errors.Is(err, ErrUnverifiable)) {
			t.Errorf("%s: got %v, want ErrSyntheticSamples/ErrUnverifiable", name, err)
		}
	}
}

func TestRowStateRulesNeverMakeUnexercisedSupported(t *testing.T) {
	bad := []Row{
		{State: StateSupported},                  // not exercised, no evidence
		{State: StateSupported, Exercised: true}, // no evidence
		{State: StateSupported, Exercised: false, Evidence: []string{"x"}},
		{State: StateSupported, Exercised: true, Evidence: []string{"x"}, Reason: "tracefs_denied"},
		{State: StateUnqualified, Reason: "r", Exercised: true},
		{State: StateDenied, Exercised: false}, // denied without a reason
		{State: StateError},
		{State: "maybe"},
	}
	for i, r := range bad {
		if r.Validate("x") == nil {
			t.Errorf("row %d accepted: %+v", i, r)
		}
	}
	if Supported([]string{"e"}, nil).Validate("x") != nil || Unqualified("tracefs_denied", nil).Validate("x") != nil {
		t.Fatal("valid rows rejected")
	}
}

func allSupported() *QualificationResult {
	r := &QualificationResult{Arch: "amd64", KernelBuild: "6.6.99-test"}
	for _, row := range r.Rows() {
		*row = Supported([]string{"e"}, nil)
	}
	return r
}

func TestRequireAllGateExitCodes(t *testing.T) {
	r := allSupported()
	if r.ExitCode() != ExitOK {
		t.Fatalf("all supported: exit %d", r.ExitCode())
	}
	r.OffCPU = Unqualified("tracefs_denied", nil)
	if r.ExitCode() != ExitUnexercised {
		t.Fatalf("unexercised off_cpu: exit %d, want %d", r.ExitCode(), ExitUnexercised)
	}
	if got := r.UnqualifiedRequired(); len(got) != 1 || got[0] != "off_cpu: unqualified (tracefs_denied)" {
		t.Fatalf("unqualified list: %v", got)
	}
	r.CPU = Failed("hot function absent", nil)
	if r.ExitCode() != ExitFail {
		t.Fatalf("failed row must beat unexercised: exit %d", r.ExitCode())
	}
	// a hand-edited report that claims support without evidence is invalid
	r = allSupported()
	r.RunqueueSplit = Row{State: StateSupported}
	if r.ExitCode() != ExitFail || r.Validate() == nil {
		t.Fatal("unexercised supported row passed the gate")
	}
}

func TestMatrixVerdictArchAndSeriesAreExact(t *testing.T) {
	rows := []ManifestRow{
		{KernelSeries: "6.1 LTS", Arch: "amd64"}, {KernelSeries: "6.1 LTS", Arch: "arm64"},
		{KernelSeries: "6.6 LTS", Arch: "amd64"}, {KernelSeries: "6.6 LTS", Arch: "arm64"},
		{KernelSeries: "6.6", Arch: "amd64", KernelBuild: "6.6.87.2-microsoft-standard-WSL2"},
	}
	res := allSupported() // a fully supported 6.6 amd64 result
	got := MatrixVerdict(rows, []*QualificationResult{res})
	want := []string{"kernel 6.1 LTS amd64", "kernel 6.1 LTS arm64", "kernel 6.6 LTS arm64"}
	if len(got) != 3 {
		t.Fatalf("amd64 qualified another row: %v", got)
	}
	for i, w := range want {
		if len(got) <= i || got[i][:len(w)] != w {
			t.Fatalf("missing row %q in %v", w, got)
		}
	}
	res.OffCPU = Unqualified("tracefs_denied", nil)
	if got := MatrixVerdict(rows, []*QualificationResult{res}); len(got) != 4 {
		t.Fatalf("a result with an unqualified row qualified a matrix row: %v", got)
	}
}

func TestRuntimeColumnsAreSeparate(t *testing.T) {
	ok := func(rt string) RuntimeColumn {
		return RuntimeColumn{Runtime: rt, Arch: "amd64", Build: RuntimeBuild{Runtime: rt, Version: "1", Arch: "amd64"},
			Engine: Supported([]string{"e"}, nil), Native: Supported([]string{"n"}, nil), Wait: Supported([]string{"w"}, nil)}
	}
	node := ok("node")
	bun := ok("bun")
	bun.Native = Unqualified("not_run", nil)
	q := QualifiedRuntimes([]RuntimeColumn{node, bun})
	if !q["node/amd64/1"] || q["bun/amd64/1"] {
		t.Fatalf("node success qualified bun: %v", q)
	}
	arm := ok("node")
	arm.Arch = "arm64"
	arm.Build.Arch = "arm64"
	arm.Native = Unqualified("not_run", nil)
	q = QualifiedRuntimes([]RuntimeColumn{node, arm})
	if q["node/arm64/1"] {
		t.Fatalf("amd64 qualified arm64: %v", q)
	}
	mism := ok("python")
	mism.Build.Runtime = "node" // a build record from another runtime
	if QualifiedRuntimes([]RuntimeColumn{mism})["python/amd64/1"] {
		t.Fatal("runtime column qualified with another runtime's build")
	}
}
