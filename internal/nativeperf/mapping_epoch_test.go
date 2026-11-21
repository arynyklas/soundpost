// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func epochProcess() ProcessKey {
	return ProcessKey{BootID: "boot", PIDNamespace: 1, TGID: 7, ProcessStart: 1, Generation: 1}
}

func epochTask() TaskKey {
	return TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 8, ProcessStart: 1, Generation: 1}
}

func epochDomain() ClockDomain { return ClockDomain{HostID: "host", BootID: "boot"} }

// mapEvent is a mapping announcement (build != "") or an unnamed range (reason) at an instant.
func mapEvent(seq uint64, at model.MonoNano, start, end, offset uint64, build string, reason FrameReason) SanitizedEvent {
	u := MappingUpdate{Process: epochProcess(), Start: model.Uint64(start), End: model.Uint64(end), BuildID: build, Reason: reason}
	if build != "" {
		u.FileOffset = model.Uint64(offset)
	}
	return SanitizedEvent{Kind: EventMapping, Time: at, Sequence: model.Uint64(seq), Domain: epochDomain(), Mapping: &u}
}

// snapRow is one row of the reconciliation group whose read ran between since and at.
func snapRow(seq uint64, since, at model.MonoNano, start, end, offset uint64, build string, reason FrameReason) SanitizedEvent {
	e := mapEvent(seq, at, start, end, offset, build, reason)
	e.Mapping.Snapshot, e.Mapping.Since = true, since
	return e
}

// confirm closes the group of that read.
func confirm(seq uint64, since, at model.MonoNano) SanitizedEvent {
	e := confirmEvent(epochProcess(), epochDomain(), since, at)
	e.Sequence = model.Uint64(seq)
	return e
}

func epochsOf(t *testing.T, events ...SanitizedEvent) *mappingEpochs {
	t.Helper()
	m, err := newMappingEpochs(events)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func resolveAt(t *testing.T, m *mappingEpochs, at model.MonoNano, ip uint64) ResolvedFrame {
	t.Helper()
	frames, err := ResolveFrames(context.Background(), []AddressFrame{{Task: epochTask(), IP: ip}}, m.tableAt(epochProcess(), at, SymbolPolicy{}), nil)
	if err != nil || len(frames) != 1 {
		t.Fatalf("resolve %#x at %d: %v %v", ip, at, frames, err)
	}
	return frames[0]
}

func wantModule(t *testing.T, f ResolvedFrame, build string, offset uint64) {
	t.Helper()
	if f.Module == nil || f.Module.BuildID != build || uint64(f.Offset) != offset {
		t.Fatalf("frame %+v, want module %s at offset %#x", f, build, offset)
	}
}

func wantNoModule(t *testing.T, f ResolvedFrame, reason FrameReason) {
	t.Helper()
	if f.Module != nil || f.Reason != reason {
		t.Fatalf("frame %+v, want no module and reason %q", f, reason)
	}
}

const (
	libA = "aa11"
	libB = "bb22"
	libC = "cc33"
)

// An address that belonged to library A earlier and belongs to library B later is attributed to A before the
// announcement of B and to B from it: attribution follows the instant of the sample, never the latest mapping.
func TestMappingEpochsAttributeAnAddressToTheMappingOfItsInstant(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		snapRow(2, 100, 110, 0x30000, 0x40000, 0x1000, libC, ""),
		confirm(3, 100, 110),
		mapEvent(4, 500, 0x10000, 0x20000, 0x2000, libB, ""),
		confirm(5, 880, 900),
	)
	wantModule(t, resolveAt(t, m, 120, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 499, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 500, 0x10010), libB, 0x2010)
	wantModule(t, resolveAt(t, m, 899, 0x10010), libB, 0x2010)
	// an address no announcement touched keeps its module and its file offset before and after
	wantModule(t, resolveAt(t, m, 300, 0x30008), libC, 0x1008)
	wantModule(t, resolveAt(t, m, 899, 0x30008), libC, 0x1008)
	// samples go back and forth in time (nearly ordered streams): the answer depends only on the instant
	wantModule(t, resolveAt(t, m, 120, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 899, 0x10010), libB, 0x2010)
}

// A later mapping over part of a library leaves the rest of it, and the rest keeps the file offset of its own bytes.
func TestMappingEpochsOverwriteOfPartOfALibraryKeepsTheRestAndItsFileOffset(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		mapEvent(3, 500, 0x14000, 0x16000, 0x9000, libB, ""),
		confirm(4, 880, 900),
	)
	wantModule(t, resolveAt(t, m, 600, 0x12000), libA, 0x2000)
	wantModule(t, resolveAt(t, m, 600, 0x14000), libB, 0x9000)
	wantModule(t, resolveAt(t, m, 600, 0x15fff), libB, 0xafff)
	wantModule(t, resolveAt(t, m, 600, 0x16000), libA, 0x6000)
	wantModule(t, resolveAt(t, m, 600, 0x1ffff), libA, 0xffff)
	wantModule(t, resolveAt(t, m, 300, 0x14000), libA, 0x4000)
}

// JIT memory (an unnamed range) that a library is later mapped over, and the other way round.
func TestMappingEpochsUnnamedRangesSupersedeAndAreSuperseded(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x50000, 0x60000, 0, "", FrameJITMissing),
		confirm(2, 100, 110),
		mapEvent(3, 400, 0x50000, 0x60000, 0, libA, ""),
		mapEvent(4, 800, 0x50000, 0x58000, 0, "", FrameUnapproved),
		confirm(5, 980, 990),
	)
	wantNoModule(t, resolveAt(t, m, 200, 0x50010), FrameJITMissing)
	wantModule(t, resolveAt(t, m, 500, 0x50010), libA, 0x10)
	wantNoModule(t, resolveAt(t, m, 900, 0x50010), FrameUnapproved)
	wantModule(t, resolveAt(t, m, 900, 0x58010), libA, 0x8010)
}

// The kernel does not announce mremap, mprotect or munmap. A reconciliation read that finds the maps different from
// what the announcements predict corrects exactly the differing ranges, and they are unresolved for the whole
// interval the change happened in: before that interval the old owner is right, after it the new one.
func TestMappingEpochsUnannouncedChangesAreUnknownOnlyInTheirInterval(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		snapRow(2, 100, 110, 0x30000, 0x40000, 0x8000, libC, ""),
		snapRow(3, 100, 110, 0x50000, 0x60000, 0x1000, libB, ""),
		confirm(4, 100, 110),
		confirm(5, 360, 370),
		// between 370 and 610 something moved libC's pages over libA's range without an announcement
		snapRow(6, 600, 610, 0x10000, 0x20000, 0x8000, libC, ""),
		snapRow(7, 600, 610, 0x30000, 0x40000, 0, "", FrameUnresolved),
		confirm(8, 600, 610),
		confirm(9, 850, 860),
	)
	// before the interval of the change: the old owner
	wantModule(t, resolveAt(t, m, 200, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 365, 0x30010), libC, 0x8010)
	// inside it (370 .. 610): both changed ranges are unknown, an untouched one is not
	wantNoModule(t, resolveAt(t, m, 400, 0x10010), FrameGeneration)
	wantNoModule(t, resolveAt(t, m, 400, 0x30010), FrameGeneration)
	wantModule(t, resolveAt(t, m, 400, 0x50010), libB, 0x1010)
	// after it: the new owner, and nothing where it was unmapped
	wantModule(t, resolveAt(t, m, 650, 0x10010), libC, 0x8010)
	wantNoModule(t, resolveAt(t, m, 650, 0x30010), FrameUnresolved)
	wantModule(t, resolveAt(t, m, 650, 0x50010), libB, 0x1010)
	// an announced mapping is explained, not a correction: no unknown range
	n := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		mapEvent(3, 500, 0x10000, 0x20000, 0x2000, libB, ""),
		confirm(4, 600, 610),
		confirm(5, 850, 860),
	)
	wantModule(t, resolveAt(t, n, 550, 0x10010), libB, 0x2010)
	wantModule(t, resolveAt(t, n, 400, 0x10010), libA, 0x10)
}

// A sample after the last group is not confirmed by any read: it stays unresolved however stable the maps look.
func TestMappingEpochsATrailingIntervalIsUnconfirmed(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		confirm(3, 360, 370),
	)
	wantModule(t, resolveAt(t, m, 300, 0x10010), libA, 0x10)
	wantNoModule(t, resolveAt(t, m, 370, 0x10010), FrameGeneration)
	wantNoModule(t, resolveAt(t, m, 900, 0x10010), FrameGeneration)
}

// What the stream cannot prove stays unresolved with a closed reason instead of being guessed.
func TestMappingEpochsNeverGuessWhatTheStreamCannotProve(t *testing.T) {
	base := []SanitizedEvent{
		snapRow(1, 100, 200, 0x10000, 0x20000, 0, libA, ""),
		snapRow(2, 100, 200, 0x30000, 0x40000, 0, libC, ""),
		confirm(3, 100, 200),
	}
	closing := confirm(4, 9980, 9990)
	with := func(extra ...SanitizedEvent) []SanitizedEvent {
		return append(append(append([]SanitizedEvent(nil), base...), extra...), closing)
	}
	t.Run("before the announcements were complete", func(t *testing.T) {
		m := epochsOf(t, with()...)
		wantNoModule(t, resolveAt(t, m, 99, 0x10010), FrameGeneration)
		wantModule(t, resolveAt(t, m, 100, 0x10010), libA, 0x10)
	})
	t.Run("a range replaced while the first read was running", func(t *testing.T) {
		// B was mapped over A at 150, inside the read [100, 200]: the rows may already hold B and no longer say what
		// was there before it, so a sample before 150 in that range is unknown; the other range is not affected.
		// The helper does not replay an announcement older than the group it came with, so if the rows lacked B the
		// next group carries it as a correction: its interval is unknown for that range, and the interval after it is not.
		m := epochsOf(t, with(mapEvent(5, 150, 0x10000, 0x20000, 0, libB, ""), snapRow(6, 600, 610, 0x10000, 0x20000, 0, libB, ""), confirm(7, 600, 610), confirm(8, 9000, 9010))...)
		wantNoModule(t, resolveAt(t, m, 120, 0x10010), FrameGeneration)
		wantModule(t, resolveAt(t, m, 120, 0x30010), libC, 0x10)
		wantModule(t, resolveAt(t, m, 150, 0x10010), libB, 0x10)
		wantNoModule(t, resolveAt(t, m, 250, 0x10010), FrameGeneration)
		wantModule(t, resolveAt(t, m, 650, 0x10010), libB, 0x10)
	})
	t.Run("after a ring overflow", func(t *testing.T) {
		lost := SanitizedEvent{Kind: EventLoss, Time: 400, Sequence: 9, Domain: epochDomain(), Loss: &LossEvent{Count: 1, Reason: ReasonLoss}}
		m := epochsOf(t, with(lost)...)
		wantModule(t, resolveAt(t, m, 399, 0x10010), libA, 0x10)
		wantNoModule(t, resolveAt(t, m, 400, 0x10010), FrameGeneration)
		wantNoModule(t, resolveAt(t, m, 900, 0x30010), FrameGeneration)
	})
	t.Run("lost samples and throttling cannot drop a mapping announcement", func(t *testing.T) {
		lost := SanitizedEvent{Kind: EventLoss, Time: 400, Sequence: 9, Domain: epochDomain(), Loss: &LossEvent{Count: 3, Reason: ReasonSampleLost}}
		m := epochsOf(t, with(lost)...)
		wantModule(t, resolveAt(t, m, 900, 0x10010), libA, 0x10)
	})
	t.Run("more announcements than the bound", func(t *testing.T) {
		var extra []SanitizedEvent
		for i := range maxEpochUpdates + 1 {
			extra = append(extra, mapEvent(uint64(10+i), model.MonoNano(300+i), 0x70000, 0x71000, 0, libB, ""))
		}
		m := epochsOf(t, with(extra...)...)
		wantModule(t, resolveAt(t, m, model.MonoNano(300+maxEpochUpdates-1), 0x70010), libB, 0x10)
		wantNoModule(t, resolveAt(t, m, model.MonoNano(300+maxEpochUpdates), 0x10010), FrameGeneration)
	})
	t.Run("two different reads claiming the same instant", func(t *testing.T) {
		m := epochsOf(t, with(confirm(5, 90, 200))...)
		wantNoModule(t, resolveAt(t, m, 150, 0x10010), FrameGeneration)
	})
	t.Run("a process with no group keeps the identity-only behavior", func(t *testing.T) {
		m := epochsOf(t, mapEvent(1, 500, 0x10000, 0x20000, 0, libB, ""))
		wantNoModule(t, resolveAt(t, m, 900, 0x10010), FrameUnresolved)
	})
	t.Run("the number of mapping events is bounded", func(t *testing.T) {
		events := make([]SanitizedEvent, 0, maxMappingEvents+1)
		for i := range maxMappingEvents + 1 {
			events = append(events, mapEvent(uint64(i+1), model.MonoNano(i+1), 0x1000, 0x2000, 0, libA, ""))
		}
		if _, err := newMappingEpochs(events); err == nil {
			t.Fatal("unbounded mapping events accepted")
		}
	})
}

// owner is what an address belongs to in a table: the module and the file offset of that very address, or the reason.
type owner struct {
	module string
	offset uint64
	reason FrameReason
	mapped bool
}

func ownersOf(entries []mappingEntry, space uint64) []owner {
	out := make([]owner, space/0x1000)
	for i := range out {
		a := uint64(i) * 0x1000
		if e, ok := ownerAt(entries, a); ok {
			out[i] = owner{mapped: true, module: e.module.BuildID, reason: e.reason}
			if e.module.ID != "" {
				out[i].offset = offsetAt(e, a)
			}
		}
	}
	return out
}

func randomTable(r *rand.Rand, space uint64) []mappingEntry {
	var entries []mappingEntry
	for at := uint64(0); at < space; {
		length := uint64(1+r.IntN(6)) * 0x1000
		if at+length > space {
			length = space - at
		}
		switch r.IntN(5) {
		case 0:
			// unmapped
		case 1:
			entries = append(entries, mappingEntry{start: at, end: at + length, reason: FrameJITMissing})
		case 2:
			entries = append(entries, mappingEntry{start: at, end: at + length, reason: FrameUnapproved})
		default:
			build := []string{libA, libB, libC}[r.IntN(3)]
			entries = append(entries, mappingEntry{start: at, end: at + length, offset: uint64(r.IntN(4)) * 0x1000, module: SafeModule{ID: moduleIdentity(build), BuildID: build}})
		}
		at += length
	}
	return entries
}

// The rows of a group are exactly what has to be painted over the prediction to get the real maps: nothing more (the
// matching ranges are not repeated) and nothing less (every difference, including an unmapped range, is a row).
func TestDiffEntriesPaintedOverThePredictionGiveTheRealMaps(t *testing.T) {
	const space = 0x40000
	r := rand.New(rand.NewPCG(7, 11))
	for round := range 300 {
		predicted, actual := randomTable(r, space), randomTable(r, space)
		rows := diffEntries(epochProcess(), predicted, actual, 5, 9)
		got := predicted
		for _, row := range rows {
			if err := (SanitizedEvent{Kind: EventMapping, Time: 9, Sequence: 1, Domain: epochDomain(), Mapping: &row}).Validate(); err != nil {
				t.Fatalf("round %d: row %+v is not a valid event: %v", round, row, err)
			}
			got = paint(got, entryOf(row))
		}
		have, want := ownersOf(got, space), ownersOf(actual, space)
		for i := range want {
			if have[i] != want[i] && !(want[i].mapped == false && have[i].reason == FrameUnresolved) {
				t.Fatalf("round %d page %d: %+v, want %+v (rows %+v)", round, i, have[i], want[i], rows)
			}
		}
		if same := diffEntries(epochProcess(), actual, actual, 5, 9); len(same) != 0 {
			t.Fatalf("round %d: identical tables differ: %+v", round, same)
		}
	}
}

func TestDiffEntriesReportsMovesUnmapsAndMergesContiguousRanges(t *testing.T) {
	module := func(build string, start, end, offset uint64) mappingEntry {
		return mappingEntry{start: start, end: end, offset: offset, module: SafeModule{ID: moduleIdentity(build), BuildID: build}}
	}
	predicted := []mappingEntry{module(libA, 0x10000, 0x20000, 0), module(libC, 0x30000, 0x40000, 0x8000), {start: 0x50000, end: 0x60000, reason: FrameJITMissing}}
	actual := []mappingEntry{module(libC, 0x10000, 0x20000, 0x8000), module(libC, 0x20000, 0x28000, 0x18000), {start: 0x50000, end: 0x60000, reason: FrameJITMissing}}
	rows := diffEntries(epochProcess(), predicted, actual, 5, 9)
	if len(rows) != 2 {
		t.Fatalf("%d rows: %+v", len(rows), rows)
	}
	// the move over A and the continuation right after it have contiguous file offsets: one row
	if rows[0].Start != 0x10000 || rows[0].End != 0x28000 || rows[0].BuildID != libC || rows[0].FileOffset != 0x8000 || !rows[0].Snapshot || rows[0].Since != 5 {
		t.Fatalf("%+v", rows[0])
	}
	// the range that disappeared is a row of its own, not silence
	if rows[1].Start != 0x30000 || rows[1].End != 0x40000 || rows[1].BuildID != "" || rows[1].Reason != FrameUnresolved {
		t.Fatalf("%+v", rows[1])
	}
	// the same owner at the same offset in two differently split tables is no difference
	split := []mappingEntry{module(libA, 0x10000, 0x14000, 0), module(libA, 0x14000, 0x20000, 0x4000)}
	if rows = diffEntries(epochProcess(), []mappingEntry{module(libA, 0x10000, 0x20000, 0)}, split, 5, 9); len(rows) != 0 {
		t.Fatalf("%+v", rows)
	}
}

// A mapping event is a typed record: only an approved build names a module, anything else a closed reason, and no
// path, device or inode has a place in it.
func TestMappingEventsAreTypedAndCarryNoPathOrDevice(t *testing.T) {
	table := MappingTable{process: epochProcess(), entries: []mappingEntry{
		{start: 0x1000, end: 0x2000, offset: 0x40, module: SafeModule{ID: moduleIdentity(libA), BuildID: libA}},
		{start: 0x3000, end: 0x4000, reason: FrameUnapproved},
		{start: 0x5000, end: 0x6000, reason: FrameJITMissing},
		{start: 0x7000, end: 0x8000},
	}}
	events := snapshotEvents(table, epochDomain(), 10, 20)
	if len(events) != 5 || !events[4].Mapping.Confirm {
		t.Fatalf("%d events", len(events))
	}
	for i, e := range events {
		e.Sequence = model.Uint64(i + 1)
		if err := e.Validate(); err != nil {
			t.Fatalf("row %d: %v", i, err)
		}
		raw, _ := json.Marshal(e)
		for _, forbidden := range []string{"path", "dev", "inode", `"ino"`, "filename", "/"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("row %d carries %q: %s", i, forbidden, raw)
			}
		}
	}
	if events[3].Mapping.Reason != FrameUnapproved || events[3].Mapping.BuildID != "" {
		t.Fatalf("an entry with neither module nor reason was not closed: %+v", events[3].Mapping)
	}
	good := events[0]
	good.Sequence = 1
	for name, mutate := range map[string]func(*MappingUpdate){
		"build and reason":                func(u *MappingUpdate) { u.Reason = FrameUnapproved },
		"neither build nor reason":        func(u *MappingUpdate) { u.BuildID = "" },
		"reason with a file offset":       func(u *MappingUpdate) { u.BuildID, u.Reason = "", FrameUnapproved },
		"an invalid reason":               func(u *MappingUpdate) { u.BuildID, u.FileOffset, u.Reason = "", 0, "private_path_text" },
		"an uneven build ID":              func(u *MappingUpdate) { u.BuildID = "abc" },
		"an empty range":                  func(u *MappingUpdate) { u.End = u.Start },
		"a range beyond user space":       func(u *MappingUpdate) { u.End = model.Uint64(1<<56 + 1) },
		"a wrapping file offset":          func(u *MappingUpdate) { u.FileOffset = ^model.Uint64(0) },
		"a snapshot that began after it":  func(u *MappingUpdate) { u.Since = 30 },
		"a snapshot without its start":    func(u *MappingUpdate) { u.Since = 0 },
		"an announcement with a snapshot": func(u *MappingUpdate) { u.Snapshot = false },
		"a confirmation with a range":     func(u *MappingUpdate) { u.Confirm = true },
	} {
		bad := good
		u := *good.Mapping
		mutate(&u)
		bad.Mapping = &u
		if bad.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	confirmation := events[4]
	confirmation.Sequence = 1
	for name, mutate := range map[string]func(*MappingUpdate){
		"a confirmation naming a build":      func(u *MappingUpdate) { u.BuildID = libA },
		"a confirmation with a reason":       func(u *MappingUpdate) { u.Reason = FrameUnapproved },
		"a confirmation outside a snapshot":  func(u *MappingUpdate) { u.Snapshot = false },
		"a confirmation that began after it": func(u *MappingUpdate) { u.Since = 30 },
	} {
		bad := confirmation
		u := *confirmation.Mapping
		mutate(&u)
		bad.Mapping = &u
		if bad.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func epochLimits(d ClockDomain) ProfileLimits {
	l := assemblyLimits(d)
	l.MaxSamples = 4096
	return l
}

func epochSample(seq uint64, at model.MonoNano, ip uint64) SanitizedEvent {
	d, k := assemblyTask()
	return SanitizedEvent{Kind: EventCPU, Domain: d, Task: k, Sequence: model.Uint64(seq), Time: at, CPUEvent: &CPUSample{IP: model.Uint64(ip), Callchain: []CallchainEntry{{IP: model.Uint64(ip)}}, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 10000000}}
}

// The exported frames of a profile carry the module and the file-relative offset of the mapping of each sample's own
// instant, and the snapshot rows and announcements are not counted or exported as observations.
func TestAssembleResolvesEachSampleAgainstItsOwnMappingEpoch(t *testing.T) {
	d, _ := assemblyTask()
	events := []SanitizedEvent{
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		epochSample(3, 300, 0x10040),
		mapEvent(4, 500, 0x10000, 0x20000, 0x2000, libB, ""),
		epochSample(5, 700, 0x10040),
		confirm(6, 880, 900),
	}
	c, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), epochLimits(d))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Samples) != 2 || len(c.Frames) != 2 {
		t.Fatalf("samples %d frames %d: %+v", len(c.Samples), len(c.Frames), c)
	}
	module := func(sample int) (string, model.Uint64) {
		frame := c.Frames[c.Stacks[c.Samples[sample].Stack].Frames[0]]
		return frame.Module, frame.Offset
	}
	moduleA, offsetA := module(0)
	moduleB, offsetB := module(1)
	if moduleA != moduleIdentity(libA) || offsetA != 0x40 || moduleB != moduleIdentity(libB) || offsetB != 0x2040 {
		t.Fatalf("sample before: %s+%#x, after: %s+%#x", moduleA, offsetA, moduleB, offsetB)
	}
	raw, _ := json.Marshal(c)
	for _, forbidden := range []string{"0x10040", "65600", `"` + libA + `"`, `"` + libB + `"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("raw address or build ID %q exported: %s", forbidden, raw)
		}
	}
}

// Without a group in the stream nothing is attributed, exactly as before mapping epochs existed.
func TestAssembleWithoutAMappingSnapshotStaysIdentityOnly(t *testing.T) {
	d, _ := assemblyTask()
	c, err := AssembleProfile(context.Background(), []SanitizedEvent{epochSample(1, 300, 0x10040), mapEvent(2, 200, 0x10000, 0x20000, 0, libA, "")}, nil, assemblyCapability(), epochLimits(d))
	if err != nil {
		t.Fatal(err)
	}
	frame := c.Frames[c.Stacks[c.Samples[0].Stack].Frames[0]]
	if frame.Module != "" || frame.Offset != 0 || frame.Reason != string(FrameUnresolved) {
		t.Fatalf("frame %+v", frame)
	}
}

// Mapping events do not count as observations against the per-item assembly bound.
func TestAssembleChargesMappingEventsAsMetadataNotAsObservations(t *testing.T) {
	d, _ := assemblyTask()
	events := []SanitizedEvent{epochSample(1, 300, 0x10040)}
	for i := range 2000 {
		events = append(events, snapRow(uint64(10+i), 100, 110, uint64(0x10000+i*0x1000), uint64(0x11000+i*0x1000), 0, libA, ""))
	}
	events = append(events, confirm(3000, 100, 110), confirm(3001, 380, 400))
	l := epochLimits(d)
	l.MaxBytes = 1 << 20
	if _, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), l); err != nil {
		t.Fatalf("2000 snapshot rows and one sample did not fit 1 MiB: %v", err)
	}
}
