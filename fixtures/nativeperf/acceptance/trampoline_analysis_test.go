//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"debug/elf"
	"os"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

const (
	testInterp = "1111111111111111111111111111111111111111"
	testExt    = "2222222222222222222222222222222222222222"
)

func TestPerfMapIsReadByTheVerifierOnly(t *testing.T) {
	data := []byte("7393579e3000 b py::spy_cpu_loop:/x/python_trampolines.py\n" +
		"7393579e300b b py::spy_native_phase:/x/python_trampolines.py\n" +
		"7393579e3016 b py::Runner.__init__:/opt/python3.12/asyncio/runners.py\n" +
		"not a perf map line\n\n" +
		"zz 10 py::bad_address:/y.py\n" +
		"7393579e3021 0 py::zero_size:/y.py\n" +
		"7393579e3022 b py::name with spaces:/y z.py\n")
	entries := parsePerfMap(data)
	if len(entries) != 4 {
		t.Fatalf("%d entries %+v, want the 4 well-formed ones", len(entries), entries)
	}
	for ip, want := range map[uint64]string{
		0x7393579e3000: "spy_cpu_loop",
		0x7393579e300a: "spy_cpu_loop",
		0x7393579e300b: "spy_native_phase",
		0x7393579e3016: "Runner.__init__",
		0x7393579e3022: "name with spaces",
	} {
		if got, ok := lookupPerfMap(entries, ip); !ok || got != want {
			t.Errorf("%#x: %q %v, want %q", ip, got, ok, want)
		}
	}
	for _, ip := range []uint64{0x7393579e2fff, 0x7393579e302d, 0x1} {
		if got, ok := lookupPerfMap(entries, ip); ok {
			t.Errorf("%#x lies in no trampoline but resolved to %q", ip, got)
		}
	}
}

func chainOf(leaf uint64, entries ...nativeperf.CallchainEntry) *nativeperf.CPUSample {
	return &nativeperf.CPUSample{IP: model.Uint64(leaf), Callchain: entries}
}

func ip(v uint64) nativeperf.CallchainEntry { return nativeperf.CallchainEntry{IP: model.Uint64(v)} }

// The addresses the verifier lines up with the product's frames are the ones the product resolves: the instruction
// pointer, then the user-space part of the callchain, with the leaf not repeated and the kernel and guest parts left out.
func TestUserInstructionPointersAreTheOnesTheProductResolves(t *testing.T) {
	kernel, user := nativeperf.CallchainEntry{Context: nativeperf.ContextKernel}, nativeperf.CallchainEntry{Context: nativeperf.ContextUser}
	got := userInstructionPointers(chainOf(0x10, kernel, ip(0xffff0001), ip(0xffff0002), user, ip(0x10), ip(0x20), ip(0x30), ip(0x10), ip(0x40)))
	want := []uint64{0x10, 0x20, 0x30, 0x40}
	if len(got) != len(want) {
		t.Fatalf("%#x, want %#x", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%#x, want %#x", got, want)
		}
	}
	long := chainOf(1)
	for i := range 300 {
		long.Callchain = append(long.Callchain, ip(uint64(0x1000+i)))
	}
	if n := len(userInstructionPointers(long)); n != 128 {
		t.Errorf("%d addresses, want the 128-frame cap", n)
	}
}

// The file-relative offsets the product reports are named by the verifier's own reading of the object: here the test
// binary itself, a Linux ELF with function symbols.
func TestELFOffsetsNameTheFunctionAtAFileOffset(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(self)
	if err != nil {
		t.Skip("not an ELF test binary")
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		t.Skip("no symbols")
	}
	var fn elf.Symbol
	var seg *elf.Prog
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Size < 16 {
			continue
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && s.Value >= p.Vaddr && s.Value+s.Size <= p.Vaddr+p.Filesz {
				fn, seg = s, p
			}
		}
		if seg != nil {
			break
		}
	}
	if seg == nil {
		t.Skip("no function symbol inside a load segment")
	}
	offset := seg.Off + (fn.Value - seg.Vaddr)
	o := newELFOffsets(self)
	if got := o.FunctionAtOffset(offset + 4); got != fn.Name {
		t.Errorf("offset %#x (+4 into %s): %q", offset, fn.Name, got)
	}
	if got := o.FunctionAtOffset(1 << 50); got != "" {
		t.Errorf("an offset in no segment resolved to %q", got)
	}
	if got := newELFOffsets("/nonexistent/object.so").FunctionAtOffset(offset); got != "" {
		t.Errorf("an unreadable object resolved to %q", got)
	}
}

type fakeOffsets map[uint64]string

func (f fakeOffsets) FunctionAtOffset(off uint64) string { return f[off] }

func module(build string, offset uint64) nativeperf.ResolvedFrame {
	return nativeperf.ResolvedFrame{Module: &nativeperf.SafeModule{ID: "m-" + build[:4], BuildID: build}, Offset: model.Uint64(offset)}
}

func anonymous() nativeperf.ResolvedFrame {
	return nativeperf.ResolvedFrame{Reason: nativeperf.FrameJITMissing}
}

func unresolved(reason nativeperf.FrameReason) nativeperf.ResolvedFrame {
	return nativeperf.ResolvedFrame{Reason: reason}
}

func TestAnalyzePhaseReadsTheExtensionAndTheTrampolinesFromGenuineCallchains(t *testing.T) {
	const second = 1_000_000_000
	ext := fakeOffsets{0x100: "spext_hot", 0x140: "spext_mix", 0x1c0: "spext_burn"}
	perf := parsePerfMap([]byte("72000000 b py::spy_cpu_loop:/x.py\n7200000b b py::spy_native_phase:/x.py\n"))
	verifier := func(ip uint64) string {
		switch {
		case ip >= 0x7200_0000 && ip < 0x7201_0000:
			return verifierAnonymous
		case ip >= 0x400000 && ip < 0x500000:
			return "target_executable"
		case ip == 0x7fff_0000:
			return "special:[vdso]"
		}
		return "file:spnative.so"
	}
	samples := []observedSample{
		// native-extension phase [10 s, 12 s]: hot <- mix <- burn <- the interpreter <- the trampoline of spy_native_phase
		{at: 10*second + 1, ips: []uint64{0x7000_0100, 0x7000_0140, 0x7000_01c0, 0x400100, 0x7200_000b},
			frames: []nativeperf.ResolvedFrame{module(testExt, 0x100), module(testExt, 0x140), module(testExt, 0x1c0), module(testInterp, 0x3000), anonymous()}},
		// the same, with a vDSO frame on top (clock_gettime): path-less, so the same closed reason, but not anonymous memory
		{at: 10*second + 2, ips: []uint64{0x7fff_0000, 0x7000_0140, 0x7000_01c0, 0x400100, 0x7200_000b},
			frames: []nativeperf.ResolvedFrame{anonymous(), module(testExt, 0x140), module(testExt, 0x1c0), module(testInterp, 0x3000), anonymous()}},
		// a sample of the Python loop's phase [4 s, 6 s]
		{at: 5 * second, ips: []uint64{0x400100, 0x7200_0000}, frames: []nativeperf.ResolvedFrame{module(testInterp, 0x3000), anonymous()}},
		// outside every window
		{at: 99 * second, ips: []uint64{0x7000_0100}, frames: []nativeperf.ResolvedFrame{module(testExt, 0x100)}},
	}
	st := analyzePhase(samples, testInterp, testExt, ext, verifier, perf, [2]uint64{10 * second, 12 * second}, 0)
	if st.Samples != 2 || st.LeafInExtension != 1 || st.LeafHotFunction != 1 || st.ChainHasMix != 2 || st.ChainHasBurn != 2 || st.ChainHasPythonFn != 2 {
		t.Errorf("native phase %+v", st)
	}
	if st.WithAnonymousMemory != 2 || st.AnonymousFrames != 3 || st.TrampolineByFunction["spy_native_phase"] != 2 || st.AnonymousNamedOrIdent != 0 || st.AnonymousDisagreements != 0 {
		t.Errorf("trampolines %+v (the vDSO frame is a path-less frame, not anonymous memory)", st)
	}
	if st.FrameReasons[string(nativeperf.FrameJITMissing)] != 3 || st.FrameReasons[""] != 7 {
		t.Errorf("frames by reason %v", st.FrameReasons)
	}
	loop := analyzePhase(samples, testInterp, testExt, ext, verifier, perf, [2]uint64{4 * second, 6 * second}, 0)
	if loop.Samples != 1 || loop.TrampolineByFunction["spy_cpu_loop"] != 1 || loop.LeafInExtension != 0 || loop.ChainHasMix != 0 {
		t.Errorf("python loop phase %+v", loop)
	}
	// the slack widens a window on both sides
	if wide := analyzePhase(samples, testInterp, testExt, ext, verifier, perf, [2]uint64{10 * second, 12 * second}, 6*second); wide.Samples != 3 {
		t.Errorf("a 6 s slack gives %d samples, want the 2 in the window and the one 5 s before it", wide.Samples)
	}
}

// The product and the verifier's own /proc/<pid>/maps are two views of the same memory. A frame the product resolved to a
// module or a symbol although it lies in anonymous memory, a path-less frame the product resolved as code of a file, and a
// frame the product calls anonymous although the verifier's maps say a file: each is a defect of the product, not a number.
func TestAnalyzePhaseCountsAnonymousFramesTheProductMisreports(t *testing.T) {
	verifier := func(ip uint64) string {
		switch ip {
		case 0x7200_0010, 0x7200_0020, 0x7200_0030:
			return verifierAnonymous
		case 0x7fff_0000:
			return "special:[vdso]"
		}
		return "file:libc.so.6"
	}
	named := anonymous()
	named.Symbol = "py_trampoline_named_by_a_symbol"
	identified := anonymous()
	identified.Module = &nativeperf.SafeModule{ID: "m", BuildID: testInterp}
	samples := []observedSample{
		{at: 1, ips: []uint64{0x7200_0010}, frames: []nativeperf.ResolvedFrame{named}},
		{at: 2, ips: []uint64{0x7200_0020}, frames: []nativeperf.ResolvedFrame{identified}},
		{at: 3, ips: []uint64{0x7200_0030}, frames: []nativeperf.ResolvedFrame{module(testInterp, 0x10)}},               // anonymous memory the product took for the interpreter
		{at: 4, ips: []uint64{0x7fff_0000}, frames: []nativeperf.ResolvedFrame{unresolved(nativeperf.FrameUnapproved)}}, // path-less, resolved as an unapproved file
		{at: 5, ips: []uint64{0x5000}, frames: []nativeperf.ResolvedFrame{anonymous()}},                                 // a file, called anonymous
		{at: 6, ips: []uint64{0x7fff_0000}, frames: []nativeperf.ResolvedFrame{anonymous()}},                            // the vDSO, called anonymous: agreed
		{at: 7, ips: []uint64{0x5000}, frames: []nativeperf.ResolvedFrame{unresolved(nativeperf.FrameUnapproved)}},      // a file, an unapproved file: agreed
	}
	st := analyzePhase(samples, testInterp, testExt, fakeOffsets{}, verifier, nil, [2]uint64{0, 10}, 0)
	if st.AnonymousNamedOrIdent != 2 || st.AnonymousDisagreements != 3 {
		t.Errorf("%+v, want 2 named-or-identified and 3 disagreements", st)
	}
	if st.FrameReasons[string(nativeperf.FrameUnapproved)] != 2 {
		t.Errorf("frames by reason %v", st.FrameReasons)
	}
}

func TestSampleRateIsSamplesPerCPUSecond(t *testing.T) {
	if got := sampleRate(237, 2.4); got < 98.7 || got > 98.8 {
		t.Errorf("%f", got)
	}
	if sampleRate(10, 0) != 0 || sampleRate(10, -1) != 0 {
		t.Error("a phase with no CPU time has no rate")
	}
}
