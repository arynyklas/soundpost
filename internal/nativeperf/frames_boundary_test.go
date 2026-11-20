// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Boundary pins for frame resolution (l4w33 mutation battery B): which address a mapping owns, which table is valid,
// what a table lists, and how a debug artifact is read, charged and classified. Everything here works on literal
// tables and in-memory objects.

func frameProcess() ProcessKey { return epochProcess() }
func frameTask() TaskKey       { return epochTask() }

func frameTable(entries ...mappingEntry) MappingTable {
	return MappingTable{process: frameProcess(), entries: entries}
}

func moduleOf(build string) SafeModule { return SafeModule{ID: moduleIdentity(build), BuildID: build} }

func resolveOne(t *testing.T, table MappingTable, ip uint64) ResolvedFrame {
	t.Helper()
	out, err := ResolveFrames(context.Background(), []AddressFrame{{Task: frameTask(), IP: ip}}, table, nil)
	if err != nil || len(out) != 1 {
		t.Fatalf("resolve %#x: %v %v", ip, out, err)
	}
	return out[0]
}

// A table lists each module it holds once, in the order it first holds it, and nothing for a range without one.
func TestMappingTableModulesListsEachModuleOnceInFirstSeenOrder(t *testing.T) {
	table := frameTable(
		mappingEntry{start: 0x1000, end: 0x2000, module: moduleOf(libB)},
		mappingEntry{start: 0x2000, end: 0x3000, reason: FrameJITMissing},
		mappingEntry{start: 0x3000, end: 0x4000, module: moduleOf(libA)},
		mappingEntry{start: 0x4000, end: 0x5000, module: moduleOf(libB)},
		mappingEntry{start: 0x5000, end: 0x6000},
	)
	got := table.Modules()
	if len(got) != 2 || got[0] != moduleOf(libB) || got[1] != moduleOf(libA) {
		t.Fatalf("%+v", got)
	}
	if empty := frameTable().Modules(); empty == nil || len(empty) != 0 {
		t.Fatalf("an empty table lists %v, want an empty list", empty)
	}
	if none := frameTable(mappingEntry{start: 1, end: 2, reason: FrameUnapproved}).Modules(); len(none) != 0 {
		t.Fatalf("%+v", none)
	}
}

// Only whole, named, file-backed code is a safe mapping: not a range with a reason, not one without a module or with a
// build the policy cannot name, not an empty or wrapping one.
func TestMappingTableMappingsListsOnlyNamedFileBackedCode(t *testing.T) {
	table := frameTable(
		mappingEntry{start: 0x1000, end: 0x3000, offset: 0x400, module: moduleOf(libA)},
		mappingEntry{start: 0x3000, end: 0x4000, offset: 0, module: moduleOf(libB), reason: FrameGeneration},
		mappingEntry{start: 0x4000, end: 0x5000, reason: FrameJITMissing},
		mappingEntry{start: 0x5000, end: 0x6000, module: SafeModule{ID: moduleIdentity("XYZ"), BuildID: "XYZ"}},
		mappingEntry{start: 0x6000, end: 0x6000, module: moduleOf(libC)},
		mappingEntry{start: 0x7000, end: 0x6800, module: moduleOf(libC)},
		mappingEntry{start: 0x8000, end: 0x9000, offset: ^uint64(0) - 0xfff, module: moduleOf(libC)},
		mappingEntry{start: 0xa000, end: 0xb000, offset: ^uint64(0) - 0x1000, module: moduleOf(libC)},
	)
	got := table.Mappings()
	if len(got) != 2 {
		t.Fatalf("%d mappings: %+v", len(got), got)
	}
	if m := got[0]; m.Process != frameProcess() || m.Module != moduleOf(libA) || m.FileOffset != 0x400 || m.CodeBytes != 0x2000 {
		t.Fatalf("first mapping %+v", m)
	}
	if m := got[1]; m.Module != moduleOf(libC) || m.FileOffset != model.Uint64(^uint64(0)-0x1000) || m.CodeBytes != 0x1000 {
		t.Fatalf("the largest offset that does not wrap: %+v", m)
	}
}

// A sample's address belongs to the entry that contains it - the first byte, not the end - and nothing else.
func TestResolveFramesOwnsExactlyTheHalfOpenRangeOfAnEntry(t *testing.T) {
	table := frameTable(
		mappingEntry{start: 0x1000, end: 0x2000, offset: 0x500, module: moduleOf(libA)},
		mappingEntry{start: 0x3000, end: 0x4000, reason: FrameJITMissing},
		mappingEntry{start: 0x4000, end: 0x5000, module: SafeModule{ID: moduleIdentity("XYZ"), BuildID: "XYZ"}},
		mappingEntry{start: 0x5000, end: 0x6000},
	)
	for _, ip := range []uint64{0, 0xfff, 0x2000, 0x2fff, 0x6000, 1 << 40} {
		if f := resolveOne(t, table, ip); f.Module != nil || f.Reason != FrameUnresolved || f.Offset != 0 {
			t.Errorf("%#x is in no entry: %+v", ip, f)
		}
	}
	for ip, want := range map[uint64]uint64{0x1000: 0x500, 0x1001: 0x501, 0x1fff: 0x14ff} {
		f := resolveOne(t, table, ip)
		if f.Module == nil || f.Module.BuildID != libA || uint64(f.Offset) != want || f.Reason != FrameArtifactUnavailable {
			t.Errorf("%#x: %+v, want offset %#x of %s with no artifact", ip, f, want, libA)
		}
	}
	for _, ip := range []uint64{0x3000, 0x3fff} {
		if f := resolveOne(t, table, ip); f.Module != nil || f.Reason != FrameJITMissing || f.Offset != 0 {
			t.Errorf("%#x: %+v, want the entry's reason", ip, f)
		}
	}
	// a module whose build cannot be named, and a range with neither module nor reason, are unapproved
	for _, ip := range []uint64{0x4000, 0x4fff, 0x5000, 0x5fff} {
		if f := resolveOne(t, table, ip); f.Module != nil || f.Reason != FrameUnapproved || f.Offset != 0 {
			t.Errorf("%#x: %+v, want build_not_approved", ip, f)
		}
	}
}

// Only the first entry that ends after the address is consulted: an address below a later entry, or in a gap, is not
// borrowed by it.
func TestResolveFramesDoesNotBorrowTheNeighbouringEntry(t *testing.T) {
	table := frameTable(
		mappingEntry{start: 0x1000, end: 0x2000, module: moduleOf(libA)},
		mappingEntry{start: 0x4000, end: 0x5000, module: moduleOf(libB)},
		mappingEntry{start: 0x5000, end: 0x6000, module: moduleOf(libC)},
	)
	for ip, want := range map[uint64]string{0x1800: libA, 0x4000: libB, 0x4fff: libB, 0x5000: libC, 0x5fff: libC} {
		if f := resolveOne(t, table, ip); f.Module == nil || f.Module.BuildID != want {
			t.Errorf("%#x: %+v, want %s", ip, f, want)
		}
	}
	for _, ip := range []uint64{0x2000, 0x3000, 0x3fff} {
		if f := resolveOne(t, table, ip); f.Module != nil || f.Reason != FrameUnresolved {
			t.Errorf("%#x lies in the gap: %+v", ip, f)
		}
	}
}

// A table is valid when its entries are non-empty, sorted and disjoint (touching is fine) and none wraps the file
// offset; anything else is refused whole.
func TestResolveFramesRefusesATableThatIsNotSortedDisjointAndWholeButAcceptsOneThatIs(t *testing.T) {
	sample := []AddressFrame{{Task: frameTask(), IP: 0x1100}}
	resolve := func(entries ...mappingEntry) error {
		_, err := ResolveFrames(context.Background(), sample, frameTable(entries...), nil)
		return err
	}
	for name, entries := range map[string][]mappingEntry{
		"touching entries":              {{start: 0x1000, end: 0x2000}, {start: 0x2000, end: 0x3000}},
		"a gap":                         {{start: 0x1000, end: 0x2000}, {start: 0x2800, end: 0x3000}},
		"the largest non-wrapping span": {{start: 0x1000, end: 0x2000, offset: ^uint64(0) - 0x1000, module: moduleOf(libA)}},
		"a one byte entry":              {{start: 0x1000, end: 0x1001}},
	} {
		if err := resolve(entries...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, entries := range map[string][]mappingEntry{
		"an empty entry":      {{start: 0x1000, end: 0x1000}},
		"a reversed entry":    {{start: 0x2000, end: 0x1000}},
		"overlap by one byte": {{start: 0x1000, end: 0x2001}, {start: 0x2000, end: 0x3000}},
		"unsorted":            {{start: 0x3000, end: 0x4000}, {start: 0x1000, end: 0x2000}},
		"the same entry twice": {
			{start: 0x1000, end: 0x2000}, {start: 0x1000, end: 0x2000},
		},
		"an offset that wraps by one byte": {{start: 0x1000, end: 0x2000, offset: ^uint64(0) - 0xfff, module: moduleOf(libA)}},
	} {
		if err := resolve(entries...); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
	// a table that is invalid is refused even when no sample falls in the broken entry
	_, err := ResolveFrames(context.Background(), []AddressFrame{{Task: frameTask(), IP: 0x1100}}, frameTable(
		mappingEntry{start: 0x1000, end: 0x2000}, mappingEntry{start: 0x1800, end: 0x2800}), nil)
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("an overlap behind the sample: %v", err)
	}
}

// At most 128 frames are resolved at once, and an empty list is one missing frame.
func TestResolveFramesTakesAtMost128Samples(t *testing.T) {
	many := func(n int) []AddressFrame {
		s := make([]AddressFrame, n)
		for i := range s {
			s[i] = AddressFrame{Task: frameTask(), IP: 0x1000 + uint64(i)}
		}
		return s
	}
	out, err := ResolveFrames(context.Background(), many(128), frameTable(), nil)
	if err != nil || len(out) != 128 {
		t.Fatalf("128 samples: %d frames, %v", len(out), err)
	}
	if _, err = ResolveFrames(context.Background(), many(129), frameTable(), nil); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("129 samples: %v", err)
	}
	out, err = ResolveFrames(context.Background(), nil, frameTable(), nil)
	if err != nil || len(out) != 1 || out[0].Reason != FrameMissing || out[0].Module != nil {
		t.Fatalf("no samples: %+v %v", out, err)
	}
}

// A sample that carries its own reason keeps it and resolves to nothing else; an unknown reason is refused; a sample of
// another process or generation is generation_changed, never resolved against this table.
func TestResolveFramesKeepsTheReasonOfASampleAndRefusesAForeignTask(t *testing.T) {
	table := frameTable(mappingEntry{start: 0x1000, end: 0x2000, module: moduleOf(libA)})
	out, err := ResolveFrames(context.Background(), []AddressFrame{
		{Task: frameTask(), IP: 0x1100, Reason: FrameTruncated},
		{Task: frameTask(), IP: 0x1100},
	}, table, nil)
	if err != nil || len(out) != 2 {
		t.Fatalf("%+v %v", out, err)
	}
	if out[0].Reason != FrameTruncated || out[0].Module != nil || out[0].Offset != 0 {
		t.Fatalf("a sample with a reason: %+v", out[0])
	}
	if out[1].Module == nil || out[1].Module.BuildID != libA {
		t.Fatalf("the sample after it: %+v", out[1])
	}
	if _, err = ResolveFrames(context.Background(), []AddressFrame{{Task: frameTask(), Reason: FrameReason("/home/x")}}, table, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown reason: %v", err)
	}
	for name, mutate := range map[string]func(*TaskKey){
		"boot":       func(k *TaskKey) { k.BootID = "other" },
		"namespace":  func(k *TaskKey) { k.PIDNamespace++ },
		"process":    func(k *TaskKey) { k.TGID++ },
		"start":      func(k *TaskKey) { k.ProcessStart++ },
		"generation": func(k *TaskKey) { k.Generation++ },
	} {
		task := frameTask()
		mutate(&task)
		got, err := ResolveFrames(context.Background(), []AddressFrame{{Task: task, IP: 0x1100}}, table, nil)
		if err != nil || len(got) != 1 || got[0].Module != nil || got[0].Reason != FrameGeneration {
			t.Errorf("a task of another %s: %+v %v", name, got, err)
		}
	}
	// the thread is not part of a process's identity
	other := frameTask()
	other.TID++
	if got, err := ResolveFrames(context.Background(), []AddressFrame{{Task: other, IP: 0x1100}}, table, nil); err != nil || got[0].Module == nil {
		t.Errorf("another thread of the process: %+v %v", got, err)
	}
}

// ---- reading a debug artifact -------------------------------------------------------------------------------------

func elfFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := io.ReadAll(symbolFixture(t, name))
	if err != nil || len(b) != 1024 {
		t.Fatalf("fixture: %d bytes, %v", len(b), err)
	}
	return b
}

func objectResolver(object []byte) artifactTestResolver {
	return artifactTestResolver{func(context.Context) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(object)), nil }}
}

// An object is accepted up to exactly the bytes still available, charged for what was read, and only when it is a valid
// ELF of exactly the build the reference names.
func TestReadFrameArtifactChargesWhatItReadsAndNamesTheBuildItAccepts(t *testing.T) {
	object := elfFixtureBytes(t, "approved_hot_loop")
	read := func(remaining, maxBytes uint64, maxSymbols uint32, build string) (frameArtifact, error) {
		return readFrameArtifact(context.Background(), context.Background(), objectResolver(object), ArtifactReference{BuildID: build}, make([]byte, 2048), remaining, maxBytes, maxSymbols)
	}
	got, err := read(1024, 1024, 128, "ab12")
	if err != nil || got.reason != "" || got.bytes != 1024 || got.info.buildID != "ab12" {
		t.Fatalf("an object of exactly the remaining bytes: %+v %v", got, err)
	}
	if name, ok := got.info.lookup(0x108); !ok || name != "approved_hot_loop" {
		t.Fatalf("the parsed object names %q %v", name, ok)
	}
	// one byte over what is left: unavailable, charged what was left (never more)
	got, err = read(1023, 1024, 128, "ab12")
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 1023 {
		t.Fatalf("an object one byte over: %+v %v", got, err)
	}
	// another build than the reference names is an invalid object, charged what it is
	got, err = read(1024, 1024, 128, "cd34")
	if err != nil || got.reason != FrameInvalidELF || got.bytes != 1024 {
		t.Fatalf("a mismatching build: %+v %v", got, err)
	}
	// more symbols than the budget allows is unavailable (a resource limit), not invalid
	got, err = read(1024, 1024, 1, "ab12")
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 1024 {
		t.Fatalf("one symbol of budget: %+v %v", got, err)
	}
	got, err = read(1024, 1024, 2, "ab12")
	if err != nil || got.reason != "" {
		t.Fatalf("exactly the symbols the object holds: %+v %v", got, err)
	}
	// bytes that are not an ELF are invalid and charged
	junk := bytes.Repeat([]byte("x"), 100)
	got, err = readFrameArtifact(context.Background(), context.Background(), objectResolver(junk), ArtifactReference{BuildID: "ab12"}, make([]byte, 2048), 1024, 1024, 128)
	if err != nil || got.reason != FrameInvalidELF || got.bytes != 100 {
		t.Fatalf("junk: %+v %v", got, err)
	}
}

// A backend that fails charges nothing; a backend that hands over a reader and a failing close or read is unavailable
// and charged at most what was left.
func TestReadFrameArtifactChargesAFailingBackendNothingAndNeverMoreThanRemains(t *testing.T) {
	scratch := make([]byte, 2048)
	failing := artifactTestResolver{func(context.Context) (io.ReadCloser, error) { return nil, io.ErrClosedPipe }}
	got, err := readFrameArtifact(context.Background(), context.Background(), failing, ArtifactReference{}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 0 {
		t.Fatalf("a failing open: %+v %v", got, err)
	}
	nilReader := artifactTestResolver{func(context.Context) (io.ReadCloser, error) { return nil, nil }}
	got, err = readFrameArtifact(context.Background(), context.Background(), nilReader, ArtifactReference{}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 0 {
		t.Fatalf("no reader and no error: %+v %v", got, err)
	}
	closeFails := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return artifactCloseFailure{bytes.NewReader(elfFixtureBytes(t, "approved_hot_loop"))}, nil
	}}
	got, err = readFrameArtifact(context.Background(), context.Background(), closeFails, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 1024 {
		t.Fatalf("a valid object whose close fails: %+v %v", got, err)
	}
	oversize := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("x"), 300))), nil
	}}
	got, err = readFrameArtifact(context.Background(), context.Background(), oversize, ArtifactReference{BuildID: "ab12"}, scratch, 200, 1024, 128)
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 200 {
		t.Fatalf("300 bytes with 200 left: %+v %v", got, err)
	}
	// a reader that returns an error together with a reader is closed, not leaked
	closed := false
	both := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return &trackedCloser{onClose: func() { closed = true }}, io.ErrClosedPipe
	}}
	if got, err = readFrameArtifact(context.Background(), context.Background(), both, ArtifactReference{}, scratch, 1024, 1024, 128); err != nil || got.reason != FrameArtifactUnavailable || !closed {
		t.Fatalf("a reader with an error: %+v %v closed=%v", got, err, closed)
	}
}

type trackedCloser struct{ onClose func() }

func (trackedCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (c *trackedCloser) Close() error          { c.onClose(); return nil }

// A read that outlives the artifact's own 100 ms bound is unavailable however valid its bytes are, and the caller's own
// cancellation, whenever it happens, is that error and never an artifact reason.
func TestReadFrameArtifactBoundsTheReadAndYieldsToTheCaller(t *testing.T) {
	object := elfFixtureBytes(t, "approved_hot_loop")
	scratch := make([]byte, 2048)
	slow := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(&delayedReader{r: bytes.NewReader(object), delay: 250 * time.Millisecond}), nil
	}}
	start := time.Now()
	got, err := readFrameArtifact(context.Background(), context.Background(), slow, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != FrameArtifactUnavailable {
		t.Fatalf("a read slower than the bound: %+v %v", got, err)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("the test reader did not delay")
	}

	// the caller cancels while the bytes are read
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelling := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(&delayedReader{r: bytes.NewReader(object), before: cancel}), nil
	}}
	if _, err = readFrameArtifact(ctx, ctx, cancelling, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled while reading: %v", err)
	}
	// a caller that has already ended never reaches the backend
	called := false
	ended, stop := context.WithCancel(context.Background())
	stop()
	never := artifactTestResolver{func(context.Context) (io.ReadCloser, error) { called = true; return nil, nil }}
	if _, err = readFrameArtifact(ended, ended, never, ArtifactReference{}, scratch, 1024, 1024, 128); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("an ended caller: %v called=%v", err, called)
	}
	// the caller that cancels while the parse runs
	parsing, stopParsing := context.WithCancel(context.Background())
	defer stopParsing()
	afterRead := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(&delayedReader{r: bytes.NewReader(object), after: stopParsing}), nil
	}}
	if _, err = readFrameArtifact(parsing, parsing, afterRead, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled once the bytes were read: %v", err)
	}
}

// delayedReader serves r after delay; before runs ahead of the first read and after once r is exhausted.
type delayedReader struct {
	r             io.Reader
	delay         time.Duration
	before, after func()
}

func (d *delayedReader) Read(p []byte) (int, error) {
	if d.before != nil {
		d.before()
		d.before = nil
	}
	if d.delay > 0 {
		time.Sleep(d.delay)
		d.delay = 0
	}
	n, err := d.r.Read(p)
	if err != nil && d.after != nil {
		d.after()
		d.after = nil
	}
	return n, err
}
