// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
//go:build linux

package appcore_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// Boundary pins for the native symbolication binding and its frame resolution (l4w33 mutation battery B), on the same
// real application and real ELF objects as native_symbols_test.go.

// mappedObject is one object a process mapped from its first byte, and how many samples ran inside soundpost_hot_loop.
type mappedObject struct {
	obj     nativeObject
	build   string
	samples int
}

// assembleSamples assembles a profile whose process mapped each object consecutively and sampled in each as asked; it
// returns the leaf frame of every sample in order.
func assembleSamples(t *testing.T, binding *nativeperf.SymbolBinding, objects ...mappedObject) ([]model.ProfileFrame, error) {
	t.Helper()
	chunk, err := assembleChunk(t, binding, false, objects...)
	if err != nil {
		return nil, err
	}
	frames := make([]model.ProfileFrame, len(chunk.Samples))
	for i, s := range chunk.Samples {
		frames[i] = chunk.Frames[chunk.Stacks[s.Stack].Frames[0]]
	}
	return frames, nil
}

// assembleStack assembles one sample whose callchain runs through every object in turn and returns the frames of its
// stack, leaf first.
func assembleStack(t *testing.T, binding *nativeperf.SymbolBinding, objects ...mappedObject) ([]model.ProfileFrame, error) {
	t.Helper()
	chunk, err := assembleChunk(t, binding, true, objects...)
	if err != nil {
		return nil, err
	}
	var frames []model.ProfileFrame
	for _, ref := range chunk.Stacks[chunk.Samples[0].Stack].Frames {
		frames = append(frames, chunk.Frames[ref])
	}
	return frames, nil
}

func assembleChunk(t *testing.T, binding *nativeperf.SymbolBinding, oneStack bool, objects ...mappedObject) (model.ProfileChunk, error) {
	t.Helper()
	d := nativeperf.ClockDomain{HostID: "host", BootID: "boot"}
	process := nativeperf.ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 1}
	task := nativeperf.TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
	var events []nativeperf.SanitizedEvent
	seq := uint64(0)
	next := func() model.Uint64 { seq++; return model.Uint64(seq) }
	var ips []uint64
	for i, o := range objects {
		base := uint64(0x7f0000000000) + uint64(i)*0x10000000
		size := (uint64(len(o.obj.bytes)) + 4095) &^ 4095
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventMapping, Time: 110, Sequence: next(), Domain: d,
			Mapping: &nativeperf.MappingUpdate{Process: process, Start: model.Uint64(base), End: model.Uint64(base + size), BuildID: o.build, Snapshot: true, Since: 100}})
		for range o.samples {
			ips = append(ips, base+o.obj.ipOffset)
		}
	}
	events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventMapping, Time: 110, Sequence: next(), Domain: d,
		Mapping: &nativeperf.MappingUpdate{Process: process, Snapshot: true, Confirm: true, Since: 100}})
	if oneStack {
		chain := make([]nativeperf.CallchainEntry, len(ips))
		for i, ip := range ips {
			chain[i] = nativeperf.CallchainEntry{IP: model.Uint64(ip)}
		}
		events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Time: 200, Sequence: next(), Domain: d, Task: task,
			CPUEvent: &nativeperf.CPUSample{IP: model.Uint64(ips[0]), Callchain: chain, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10_000_000, Truncated: nativeperf.ReasonTruncated}})
		ips = ips[:1]
	} else {
		for i, ip := range ips {
			events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventCPU, Time: model.MonoNano(200 + i), Sequence: next(), Domain: d, Task: task,
				CPUEvent: &nativeperf.CPUSample{IP: model.Uint64(ip), Callchain: []nativeperf.CallchainEntry{{IP: model.Uint64(ip)}}, Method: nativeperf.MethodSoftwareCPUClock, Unit: nativeperf.UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10_000_000, Truncated: nativeperf.ReasonTruncated}})
		}
	}
	events = append(events, nativeperf.SanitizedEvent{Kind: nativeperf.EventMapping, Time: 900, Sequence: next(), Domain: d,
		Mapping: &nativeperf.MappingUpdate{Process: process, Snapshot: true, Confirm: true, Since: 300}})
	limits := nativeperf.ProfileLimits{Profile: model.ID{1}, Process: model.ID{2}, Capability: model.ID{3}, Domain: d, PolicyRevision: 1, Sequence: 1, Start: 1, End: 1000, Clock: model.TraceClock{Wall: 1, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}, MaxBytes: 8 << 20, MaxSamples: 1024, MaxIntervals: 1024, MaxFrames: 4096, MaxStacks: 4096, Symbols: binding}
	caps := nativeperf.Capabilities{CPU: nativeperf.Supported, OffCPU: nativeperf.Denied, RunqueueSplit: nativeperf.Denied, Permissions: nativeperf.Permissions{CPUEventOpen: nativeperf.Supported, SchedulerEventOpen: nativeperf.Denied}, FrameCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}, ThreadCoverage: nativeperf.Coverage{Reasons: []nativeperf.Reason{nativeperf.ReasonUnmeasured}}}
	chunk, err := nativeperf.AssembleProfile(context.Background(), events, nil, caps, limits)
	if err != nil {
		return model.ProfileChunk{}, err
	}
	if len(chunk.Samples) != len(ips) {
		t.Fatalf("assembled %d samples, want %d", len(chunk.Samples), len(ips))
	}
	return chunk, nil
}

// recordingResolver forwards to the real C07 resolver and remembers what it was asked.
type recordingResolver struct {
	inner nativeperf.ArtifactResolver
	refs  []nativeperf.ArtifactReference
}

func (r *recordingResolver) ScopedRead(ctx context.Context, ref nativeperf.ArtifactReference) (io.ReadCloser, error) {
	r.refs = append(r.refs, ref)
	return r.inner.ScopedRead(ctx, ref)
}

func (r *wlRig) recording(binding *nativeperf.SymbolBinding) *recordingResolver {
	rec := &recordingResolver{inner: appcore.NativeDebugResolver{Store: r.app.Artifacts}}
	binding.Resolver = rec
	return rec
}

func wantNamed(t *testing.T, what string, frame model.ProfileFrame) {
	t.Helper()
	if frame.Function != "soundpost_hot_loop" || frame.Reason != "" {
		t.Fatalf("%s: the frame was not named: %+v", what, frame)
	}
}

func wantUnavailable(t *testing.T, what string, frame model.ProfileFrame) {
	t.Helper()
	if frame.Function != "" || frame.Reason != string(nativeperf.FrameArtifactUnavailable) {
		t.Fatalf("%s: want artifact_unavailable, got %+v", what, frame)
	}
}

// A binding is refused whole, before any read, for each of the things that make it untrustworthy, and accepted at the
// very edge of each limit.
func TestNativeSymbolBindingIsRefusedWholeForEachUntrustworthyField(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	stored := r.registerNative(t, obj, time.Hour)
	assoc := map[string]model.ID{obj.buildID: stored.ID}
	fresh := func() *nativeperf.SymbolBinding {
		return r.binding(assoc, r.scope(auth.ArtifactRead), r.project)
	}
	assemble := func(b *nativeperf.SymbolBinding) error {
		_, err := assembleSamples(t, b, mappedObject{obj, obj.buildID, 1})
		return err
	}
	if err := assemble(fresh()); err != nil {
		t.Fatalf("the baseline binding was refused: %v", err)
	}
	many := func(n int) map[string]model.ID {
		m := map[string]model.ID{obj.buildID: stored.ID}
		for i := 0; len(m) < n; i++ {
			m[fmt.Sprintf("%040x", i+1)] = model.NewID()
		}
		return m
	}
	refused := map[string]func(*nativeperf.SymbolBinding){
		"no resolver":                  func(b *nativeperf.SymbolBinding) { b.Resolver = nil },
		"no project":                   func(b *nativeperf.SymbolBinding) { b.Project = model.ID{} },
		"257 associations":             func(b *nativeperf.SymbolBinding) { b.Artifacts = many(257) },
		"an object bound over 32 MiB":  func(b *nativeperf.SymbolBinding) { b.MaxELFBytes = 32<<20 + 1; b.Working = workingLease(32<<20 + 2) },
		"no scope":                     func(b *nativeperf.SymbolBinding) { b.Scope = auth.Scope{} },
		"a build key that is no build": func(b *nativeperf.SymbolBinding) { b.Artifacts = map[string]model.ID{"not-a-build": stored.ID} },
		"an upper case build key": func(b *nativeperf.SymbolBinding) {
			b.Artifacts = map[string]model.ID{strings.ToUpper(obj.buildID): stored.ID}
		},
		"an association to no artifact":      func(b *nativeperf.SymbolBinding) { b.Artifacts = map[string]model.ID{obj.buildID: {}} },
		"no working reservation":             func(b *nativeperf.SymbolBinding) { b.Working = nil },
		"a reservation of exactly the bound": func(b *nativeperf.SymbolBinding) { b.Working = workingLease(nativeperf.DefaultSymbolArtifactBytes) },
		"a reservation of exactly a custom bound": func(b *nativeperf.SymbolBinding) {
			b.MaxELFBytes = 1 << 20
			b.Working = workingLease(1 << 20)
		},
	}
	for name, mutate := range refused {
		b := fresh()
		mutate(b)
		if err := assemble(b); !errors.Is(err, nativeperf.ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	accepted := map[string]func(*nativeperf.SymbolBinding){
		"256 associations":                  func(b *nativeperf.SymbolBinding) { b.Artifacts = many(256) },
		"an object bound of exactly 32 MiB": func(b *nativeperf.SymbolBinding) { b.MaxELFBytes = 32 << 20; b.Working = workingLease(32<<20 + 1) },
		"a reservation of the bound and one byte": func(b *nativeperf.SymbolBinding) {
			b.MaxELFBytes = 1 << 20
			b.Working = workingLease(1<<20 + 1)
		},
	}
	for name, mutate := range accepted {
		b := fresh()
		mutate(b)
		if err := assemble(b); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The largest object one symbolication reads is the binding's own bound: exactly that many bytes are read and named,
// one byte over is unavailable.
func TestNativeSymbolBindingBoundsTheObjectItReads(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	stored := r.registerNative(t, obj, time.Hour)
	binding := func(max uint64) *nativeperf.SymbolBinding {
		b := r.binding(map[string]model.ID{obj.buildID: stored.ID}, r.scope(auth.ArtifactRead), r.project)
		b.MaxELFBytes = max
		return b
	}
	size := uint64(len(obj.bytes))
	for _, tc := range []struct {
		max   uint64
		named bool
	}{{size, true}, {size + 1, true}, {size - 1, false}} {
		frames, err := assembleSamples(t, binding(tc.max), mappedObject{obj, obj.buildID, 1})
		if err != nil {
			t.Fatalf("bound %d: %v", tc.max, err)
		}
		if tc.named {
			wantNamed(t, fmt.Sprintf("a bound of %d for an object of %d", tc.max, size), frames[0])
		} else {
			wantUnavailable(t, fmt.Sprintf("a bound of %d for an object of %d", tc.max, size), frames[0])
		}
	}
}

// Each artifact is read once however many samples fall in it, and the read names exactly what the binding bound: the
// scope, the project, the kernel's build ID and the artifact associated with it.
func TestNativeSymbolicationReadsEachArtifactOnceAndAsksForExactlyWhatIsBound(t *testing.T) {
	r := newWLRig(t)
	a, b := buildNativeObject(t, "a"), buildNativeObject(t, "b")
	storedA, storedB := r.registerNative(t, a, time.Hour), r.registerNative(t, b, time.Hour)
	binding := r.binding(map[string]model.ID{a.buildID: storedA.ID, b.buildID: storedB.ID}, r.scope(auth.ArtifactRead), r.project)
	rec := r.recording(binding)
	frames, err := assembleSamples(t, binding, mappedObject{a, a.buildID, 3}, mappedObject{b, b.buildID, 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 5 {
		t.Fatalf("%d frames", len(frames))
	}
	for i, f := range frames {
		wantNamed(t, fmt.Sprintf("sample %d", i), f)
	}
	if len(rec.refs) != 2 {
		t.Fatalf("%d reads for two artifacts and five samples", len(rec.refs))
	}
	want := []struct {
		build string
		id    model.ID
	}{{a.buildID, storedA.ID}, {b.buildID, storedB.ID}}
	for i, ref := range rec.refs {
		if ref.BuildID != want[i].build || ref.ArtifactID != want[i].id || ref.ProjectID != r.project || ref.Scope.OrgID() != r.scope(auth.ArtifactRead).OrgID() || ref.Scope.Permission() != auth.ArtifactRead {
			t.Errorf("read %d asked for %+v, want build %s artifact %s of project %s under an artifacts.read scope", i, ref, want[i].build, want[i].id, r.project)
		}
	}
}

// The bytes of all the objects one assembly reads are bounded by the binding's bound together: what a read cost is
// deducted from what the next may use, a read that did not fit still costs what was left, and once the bound is spent
// no artifact is asked for at all.
func TestNativeSymbolicationChargesEveryObjectAgainstOneByteBound(t *testing.T) {
	r := newWLRig(t)
	objects := []nativeObject{buildNativeObject(t, "a"), buildNativeObject(t, "b"), buildNativeObject(t, "c")}
	assoc := map[string]model.ID{}
	for _, o := range objects {
		assoc[o.buildID] = r.registerNative(t, o, time.Hour).ID
	}
	sa, sb := uint64(len(objects[0].bytes)), uint64(len(objects[1].bytes))
	run := func(max uint64) ([]model.ProfileFrame, int) {
		binding := r.binding(assoc, r.scope(auth.ArtifactRead), r.project)
		binding.MaxELFBytes = max
		rec := r.recording(binding)
		frames, err := assembleSamples(t, binding, mappedObject{objects[0], objects[0].buildID, 1}, mappedObject{objects[1], objects[1].buildID, 1}, mappedObject{objects[2], objects[2].buildID, 1})
		if err != nil {
			t.Fatal(err)
		}
		return frames, len(rec.refs)
	}
	// room for exactly the first two: both are named and the third is never asked for
	frames, reads := run(sa + sb)
	wantNamed(t, "first of three", frames[0])
	wantNamed(t, "second of three", frames[1])
	wantUnavailable(t, "third of three", frames[2])
	if reads != 2 {
		t.Fatalf("%d reads with the bound spent after two", reads)
	}
	// one byte short of the second: it does not fit, it still costs what was left, and the third is not asked for either
	frames, reads = run(sa + sb - 1)
	wantNamed(t, "first of three", frames[0])
	wantUnavailable(t, "second of three", frames[1])
	wantUnavailable(t, "third of three", frames[2])
	if reads != 2 {
		t.Fatalf("%d reads when the second did not fit", reads)
	}
	// room for all three
	frames, reads = run(sa + sb + uint64(len(objects[2].bytes)))
	for i, f := range frames {
		wantNamed(t, fmt.Sprintf("sample %d of three", i), f)
	}
	if reads != 3 {
		t.Fatalf("%d reads for three artifacts that fit", reads)
	}
}

// A backend's answer is classified, never passed through: a denial of any kind is artifact_denied, and nothing about the
// refusal other than that reaches the profile.
type answeringResolver struct{ err error }

func (a answeringResolver) ScopedRead(context.Context, nativeperf.ArtifactReference) (io.ReadCloser, error) {
	return nil, a.err
}

func TestNativeSymbolicationClassifiesWhatTheBackendAnswers(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	stored := r.registerNative(t, obj, time.Hour)
	for _, tc := range []struct {
		name   string
		err    error
		reason nativeperf.FrameReason
	}{
		{"forbidden", model.Fail(model.Forbidden), nativeperf.FrameArtifactDenied},
		{"unauthenticated", model.Fail(model.Unauthenticated), nativeperf.FrameArtifactDenied},
		{"not found", model.Fail(model.NotFound), nativeperf.FrameArtifactUnavailable},
		{"conflict", model.Fail(model.Conflict), nativeperf.FrameArtifactUnavailable},
		{"a plain error", errors.New("backend down"), nativeperf.FrameArtifactUnavailable},
	} {
		binding := r.binding(map[string]model.ID{obj.buildID: stored.ID}, r.scope(auth.ArtifactRead), r.project)
		binding.Resolver = answeringResolver{tc.err}
		frames, err := assembleSamples(t, binding, mappedObject{obj, obj.buildID, 1})
		if err != nil || frames[0].Function != "" || frames[0].Reason != string(tc.reason) {
			t.Errorf("%s: %+v %v, want %s", tc.name, frames, err, tc.reason)
		}
	}
}

// stallingResolver answers every read by waiting for the context it was given to end (a backend that does not answer)
// and counts the reads it was asked for.
type stallingResolver struct{ reads *int }

func (s stallingResolver) ScopedRead(ctx context.Context, _ nativeperf.ArtifactReference) (io.ReadCloser, error) {
	*s.reads++
	<-ctx.Done()
	return nil, ctx.Err()
}

// One symbolication of a stack waits for a stalled backend at most 100 ms per artifact and five seconds altogether:
// with 120 artifacts that all stall, about fifty are asked for and the rest are given up on without a read.
func TestNativeSymbolicationStopsAskingAStalledBackendAfterFiveSeconds(t *testing.T) {
	if testing.Short() {
		t.Skip("takes five seconds by construction")
	}
	r := newWLRig(t)
	const modules = 120
	assoc := map[string]model.ID{}
	var objects []mappedObject
	for i := range modules {
		build := fmt.Sprintf("%040x", i+1)
		assoc[build] = model.NewID()
		objects = append(objects, mappedObject{nativeObject{bytes: make([]byte, 4096), buildID: build, ipOffset: 16}, build, 1})
	}
	binding := r.binding(assoc, r.scope(auth.ArtifactRead), r.project)
	reads := 0
	binding.Resolver = stallingResolver{&reads}
	start := time.Now()
	frames, err := assembleStack(t, binding, objects...)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != modules {
		t.Fatalf("%d frames in the stack, want %d", len(frames), modules)
	}
	for i, f := range frames {
		if f.Function != "" || f.Reason != string(nativeperf.FrameArtifactUnavailable) {
			t.Fatalf("frame %d of a stalled backend: %+v", i, f)
		}
	}
	if reads < 35 || reads > 56 || elapsed < 4500*time.Millisecond || elapsed > 5900*time.Millisecond {
		t.Fatalf("%d of %d artifacts were asked for in %v; want about fifty in five seconds", reads, modules, elapsed)
	}
}

// syntheticObject is a minimal valid ELF64 debug object whose symbol table holds n function symbols (every entry of it,
// the first included) inside its one executable segment, under the GNU build ID 0xab, tag. It is the object of a library
// with very many symbols; a sample at file offset 0x108 falls inside some of them.
func syntheticObject(t *testing.T, tag byte, n int) nativeObject {
	t.Helper()
	o := binary.LittleEndian
	strtab := []byte{0}
	nameOffsets := make([]uint32, n)
	for i := range n {
		nameOffsets[i] = uint32(len(strtab))
		strtab = append(strtab, fmt.Sprintf("f%d", i)...)
		strtab = append(strtab, 0)
	}
	const strOff = 1024
	symOff := (strOff + len(strtab) + 7) &^ 7
	b := make([]byte, symOff+n*24)
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	o.PutUint16(b[16:], 2)
	o.PutUint16(b[18:], 62)
	o.PutUint32(b[20:], 1)
	o.PutUint64(b[32:], 64)
	o.PutUint64(b[40:], 512)
	o.PutUint16(b[52:], 64)
	o.PutUint16(b[54:], 56)
	o.PutUint16(b[56:], 2)
	o.PutUint16(b[58:], 64)
	o.PutUint16(b[60:], 4)
	// PT_LOAD (executable) over the first 1024 bytes at 0x400000, and PT_NOTE with the build ID
	o.PutUint32(b[64:], 1)
	o.PutUint32(b[68:], 5)
	o.PutUint64(b[80:], 0x400000)
	o.PutUint64(b[96:], 1024)
	o.PutUint64(b[104:], 1024)
	o.PutUint32(b[120:], 4)
	o.PutUint64(b[128:], 256)
	o.PutUint64(b[152:], 20)
	o.PutUint32(b[256:], 4)
	o.PutUint32(b[260:], 2)
	o.PutUint32(b[264:], 3)
	copy(b[268:], []byte{'G', 'N', 'U', 0, 0xab, tag})
	// sections: text, string table, symbol table linked to it
	o.PutUint32(b[576+4:], 1)
	o.PutUint64(b[576+8:], 6)
	o.PutUint64(b[576+16:], 0x400000)
	o.PutUint64(b[576+32:], 256)
	o.PutUint32(b[640+4:], 3)
	o.PutUint64(b[640+24:], strOff)
	o.PutUint64(b[640+32:], uint64(len(strtab)))
	o.PutUint32(b[704+4:], 2)
	o.PutUint64(b[704+24:], uint64(symOff))
	o.PutUint64(b[704+32:], uint64(n)*24)
	o.PutUint32(b[704+40:], 2)
	o.PutUint64(b[704+56:], 24)
	copy(b[strOff:], strtab)
	for i := range n {
		s := b[symOff+i*24:]
		o.PutUint32(s, nameOffsets[i])
		s[4] = 2
		o.PutUint16(s[6:], 1)
		o.PutUint64(s[8:], 0x400100+uint64(i%8)*16)
		o.PutUint64(s[16:], 16)
	}
	return nativeObject{bytes: b, buildID: fmt.Sprintf("ab%02x", tag), ipOffset: 0x108}
}

// The symbols of all the objects one assembly reads are bounded together by 65536: what the first objects hold is
// deducted from what the next may hold, an object that does not fit is unavailable and costs what it was, and once the
// bound is spent no artifact is asked for at all.
func TestNativeSymbolicationChargesEverySymbolAgainstOneBound(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector slows the parse of a 40000-symbol object past the 100 ms bound of one artifact read; the same test runs without it")
	}
	r := newWLRig(t)
	first, second, third := syntheticObject(t, 1, 40000), syntheticObject(t, 2, 25536), syntheticObject(t, 3, 4)
	over := syntheticObject(t, 4, 25537)
	assoc := map[string]model.ID{}
	for _, o := range []nativeObject{first, second, third, over} {
		assoc[o.buildID] = r.registerNative(t, o, time.Hour).ID
	}
	run := func(objects ...nativeObject) ([]model.ProfileFrame, int) {
		binding := r.binding(assoc, r.scope(auth.ArtifactRead), r.project)
		rec := r.recording(binding)
		var mapped []mappedObject
		for _, o := range objects {
			mapped = append(mapped, mappedObject{o, o.buildID, 1})
		}
		frames, err := assembleSamples(t, binding, mapped...)
		if err != nil {
			t.Fatal(err)
		}
		return frames, len(rec.refs)
	}
	// 40000 and 25536 symbols are exactly 65536: both are named and a third is never asked for
	frames, reads := run(first, second, third)
	if frames[0].Function == "" || frames[0].Reason != "" || frames[1].Function == "" || frames[1].Reason != "" {
		t.Fatalf("the two objects that fit were not named: %+v %+v", frames[0], frames[1])
	}
	wantUnavailable(t, "the object after the bound was spent", frames[2])
	if reads != 2 {
		t.Fatalf("%d reads, want 2: the bound was spent after the second", reads)
	}
	// one symbol more than what is left: unavailable, and the symbols it held are not counted against the next
	frames, reads = run(first, over, third)
	if frames[0].Function == "" {
		t.Fatalf("the first object was not named: %+v", frames[0])
	}
	wantUnavailable(t, "the object of one symbol too many", frames[1])
	if frames[2].Function == "" || frames[2].Reason != "" {
		t.Fatalf("the small object after it was not named: %+v", frames[2])
	}
	if reads != 3 {
		t.Fatalf("%d reads, want 3", reads)
	}
}

// A sample inside an object but in no function symbol of it is the module's frame without a name: the object was read,
// and it says nothing about that address.
func TestNativeSymbolicationOfAnAddressInNoSymbolIsUnresolved(t *testing.T) {
	r := newWLRig(t)
	obj := buildNativeObject(t, "a")
	stored := r.registerNative(t, obj, time.Hour)
	binding := r.binding(map[string]model.ID{obj.buildID: stored.ID}, r.scope(auth.ArtifactRead), r.project)
	elsewhere := obj
	elsewhere.ipOffset = 0 // the first byte of the ELF header
	frames, err := assembleSamples(t, binding, mappedObject{elsewhere, obj.buildID, 1}, mappedObject{obj, obj.buildID, 1})
	if err != nil {
		t.Fatal(err)
	}
	if frames[0].Function != "" || frames[0].Reason != string(nativeperf.FrameUnresolved) {
		t.Fatalf("an address in no symbol: %+v, want frame_unresolved", frames[0])
	}
	wantNamed(t, "an address in soundpost_hot_loop", frames[1])
}
