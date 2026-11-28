//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"debug/elf"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// The verifier's reading of a python_trampolines capture, kept apart from the capture itself so that it can be tested on
// hand-made samples. Each CPU sample of the capture is resolved by the PRODUCT (nativeperf.ResolveCPUObservation over the
// mapping table the product's own MappingReader built from the live process): a frame in code of an object whose GNU build
// ID the operator approved comes back as that module and a file-relative offset, every other frame as a closed reason.
// The verifier reads the same samples independently: its own ELF symbol lookup of the extension object turns the offsets
// into function names, its own /proc/<pid>/maps snapshots say which addresses are anonymous executable memory, and the
// interpreter's perf map (which only the verifier reads) says which Python function a trampoline belongs to.

// observedSample is one CPU sample, as the product resolved it.
type observedSample struct {
	at     uint64                     // monotonic ns
	ips    []uint64                   // the user-space instruction pointers, leaf first, in the order the product resolves them
	frames []nativeperf.ResolvedFrame // the product's resolution of them, frame by frame
}

// userInstructionPointers is the list of addresses ResolveCPUObservation turns into frames: the sample's instruction pointer,
// then the user-space entries of its callchain (kernel and guest entries are filtered, an entry equal to the instruction
// pointer is not repeated), at most 128.
func userInstructionPointers(s *nativeperf.CPUSample) []uint64 {
	ips := []uint64{uint64(s.IP)}
	context := nativeperf.ContextUser
	for _, c := range s.Callchain {
		if c.Context != "" {
			context = c.Context
			continue
		}
		if context != nativeperf.ContextUser || c.IP == s.IP {
			continue
		}
		if len(ips) == 128 {
			break
		}
		ips = append(ips, uint64(c.IP))
	}
	return ips
}

// perfMapEntry is one line of CPython's /tmp/perf-<pid>.map: an address range and the name of the Python function whose
// trampoline it is.
type perfMapEntry struct {
	start, size uint64
	name        string
}

// parsePerfMap reads the perf map the interpreter wrote ("START SIZE name", the numbers in hex). Lines that are not that
// are skipped.
func parsePerfMap(data []byte) []perfMapEntry {
	var out []perfMapEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.SplitN(strings.TrimSpace(line), " ", 3)
		if len(f) != 3 {
			continue
		}
		start, e1 := strconv.ParseUint(f[0], 16, 64)
		size, e2 := strconv.ParseUint(f[1], 16, 64)
		if e1 != nil || e2 != nil || size == 0 {
			continue
		}
		out = append(out, perfMapEntry{start, size, f[2]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].start < out[j].start })
	return out
}

// pythonFunction is the function a perf map name stands for: "py::spy_cpu_loop:/path/file.py" -> "spy_cpu_loop".
func pythonFunction(name string) string {
	name = strings.TrimPrefix(name, "py::")
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	return name
}

// lookupPerfMap is the function whose trampoline contains ip, from the verifier's own reading of the perf map.
func lookupPerfMap(entries []perfMapEntry, ip uint64) (string, bool) {
	i := sort.Search(len(entries), func(i int) bool { return entries[i].start+entries[i].size > ip })
	if i < len(entries) && ip >= entries[i].start {
		return pythonFunction(entries[i].name), true
	}
	return "", false
}

// offsetSymbols is the verifier-side ELF lookup of one object by the ELF file-relative code offset the product reports.
type offsetSymbols interface{ FunctionAtOffset(offset uint64) string }

// elfOffsets reads an object's function symbols and load segments once.
type elfOffsets struct {
	once  sync.Once
	path  string
	loads []elf.ProgHeader
	fns   []elfFunction
}

type elfFunction struct {
	name        string
	start, size uint64
}

func newELFOffsets(path string) *elfOffsets { return &elfOffsets{path: path} }

func (o *elfOffsets) load() {
	f, err := elf.Open(o.path)
	if err != nil {
		return
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			o.loads = append(o.loads, p.ProgHeader)
		}
	}
	syms, err := f.Symbols()
	if err != nil {
		return
	}
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Size > 0 {
			o.fns = append(o.fns, elfFunction{s.Name, s.Value, s.Size})
		}
	}
	sort.Slice(o.fns, func(i, j int) bool { return o.fns[i].start < o.fns[j].start })
}

// FunctionAtOffset names the function containing a file-relative code offset, or "".
func (o *elfOffsets) FunctionAtOffset(offset uint64) string {
	o.once.Do(o.load)
	for _, p := range o.loads {
		if offset < p.Off || offset >= p.Off+p.Filesz {
			continue
		}
		vaddr := p.Vaddr + (offset - p.Off)
		i := sort.Search(len(o.fns), func(i int) bool { return o.fns[i].start+o.fns[i].size > vaddr })
		if i < len(o.fns) && vaddr >= o.fns[i].start {
			return o.fns[i].name
		}
	}
	return ""
}

// phaseStats is what the samples of one phase window show.
type phaseStats struct {
	Samples int `json:"samples"`
	// the native extension, as the product resolved it (a frame in the module of the approved build ID, with an offset) and
	// as the verifier's ELF lookup of the extension object names it
	LeafInExtension  int `json:"leaf_in_extension_module"`
	LeafHotFunction  int `json:"leaf_in_spext_hot"`
	ChainHasMix      int `json:"chain_has_spext_mix"`
	ChainHasBurn     int `json:"chain_has_spext_burn"`
	ChainHasPythonFn int `json:"chain_has_interpreter_frame"`
	// the trampolines: samples with at least one frame in anonymous executable memory by the verifier's own /proc/<pid>/maps
	// (a perf trampoline's arena), the frames the product gave its closed reason jit_or_anonymous_map_unavailable (anonymous
	// memory, and the other mappings without a file path such as the vDSO), how the verifier's own reading of the perf map
	// names them, and the product-side violations: such a frame that carries a module, an offset or a symbol, or that the
	// product and the verifier's own maps do not agree about
	WithAnonymousMemory    int            `json:"samples_with_a_frame_in_anonymous_executable_memory"`
	AnonymousFrames        int            `json:"frames_with_reason_jit_or_anonymous_map_unavailable"`
	TrampolineByFunction   map[string]int `json:"samples_by_trampoline_function_per_perf_map"`
	AnonymousNamedOrIdent  int            `json:"pathless_frames_with_a_module_or_a_symbol"`
	AnonymousDisagreements int            `json:"frames_the_product_and_the_verifier_disagree_on_pathless_code"`
	// every frame the product could not resolve, by closed reason ("" is a resolved frame of an approved module)
	FrameReasons map[string]int `json:"frames_by_reason"`
}

// the classes the verifier's own /proc/<pid>/maps snapshots (qual.Resolver.Classify) give code that has no file path:
// anonymous executable memory, and a special mapping such as the vDSO
const verifierAnonymous = "anonymous_executable"

func pathless(class string) bool {
	return class == verifierAnonymous || strings.HasPrefix(class, "special:")
}

// analyzePhase reads the samples whose time lies in window (ns), with slack on both sides. verifier is the class the
// verifier's own reading of /proc/<pid>/maps gives an address.
func analyzePhase(samples []observedSample, interpreterBuild, extensionBuild string, ext offsetSymbols, verifier func(ip uint64) string, perf []perfMapEntry, window [2]uint64, slack uint64) phaseStats {
	st := phaseStats{TrampolineByFunction: map[string]int{}, FrameReasons: map[string]int{}}
	for _, s := range samples {
		if s.at+slack < window[0] || s.at > window[1]+slack {
			continue
		}
		st.Samples++
		extNames := map[string]bool{}
		tramp := map[string]bool{}
		sawAnon, sawInterp := false, false
		for i, f := range s.frames {
			st.FrameReasons[string(f.Reason)]++
			anonymous := f.Reason == nativeperf.FrameJITMissing
			if i < len(s.ips) {
				v := verifier(s.ips[i])
				if pathless(v) != anonymous {
					st.AnonymousDisagreements++
				}
				if v == verifierAnonymous {
					sawAnon = true
				}
			}
			switch {
			case anonymous:
				st.AnonymousFrames++
				if f.Module != nil || f.Symbol != "" || f.Offset != 0 {
					st.AnonymousNamedOrIdent++
				}
				if i < len(s.ips) {
					if fn, ok := lookupPerfMap(perf, s.ips[i]); ok {
						tramp[fn] = true
					}
				}
			case f.Module != nil && f.Module.BuildID == extensionBuild:
				if i == 0 {
					st.LeafInExtension++
				}
				if n := ext.FunctionAtOffset(uint64(f.Offset)); n != "" {
					extNames[n] = true
					if i == 0 && n == "spext_hot" {
						st.LeafHotFunction++
					}
				}
			case f.Module != nil && f.Module.BuildID == interpreterBuild:
				sawInterp = true
			}
		}
		if extNames["spext_mix"] {
			st.ChainHasMix++
		}
		if extNames["spext_burn"] {
			st.ChainHasBurn++
		}
		if sawInterp {
			st.ChainHasPythonFn++
		}
		if sawAnon {
			st.WithAnonymousMemory++
		}
		for fn := range tramp {
			st.TrampolineByFunction[fn]++
		}
	}
	return st
}

// sampleRate is the samples a CPU second of the thread produced in a window.
func sampleRate(samples int, cpuSeconds float64) float64 {
	if cpuSeconds <= 0 {
		return 0
	}
	return float64(samples) / cpuSeconds
}
