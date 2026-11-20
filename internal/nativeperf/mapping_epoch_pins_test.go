// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Second pass of the l4w33 mutation battery on the mapping epochs: the numeric bounds as literals (a constant that
// drifts must fail here, not silently move the test with it), and the replay paths that only three or more
// reconciliation groups reach.

// The announcements kept per process are exactly 4096; the 4097th is dropped and marks the history unknown from it.
func TestMappingEpochsKeepExactly4096AnnouncementsPerProcess(t *testing.T) {
	build := func(n int) *processEpochs {
		events := []SanitizedEvent{
			snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
			confirm(2, 100, 110),
		}
		for i := range n {
			events = append(events, mapEvent(uint64(10+i), model.MonoNano(1000+i), 0x30000, 0x31000, 0, libB, ""))
		}
		events = append(events, confirm(90000, 99000, 99500))
		return epochsOf(t, events...).processes[epochProcess()]
	}
	if p := build(4096); len(p.updates) != 4096 || p.overflowAt != 0 {
		t.Fatalf("4096 announcements: %d kept, overflow at %d; want all kept and no overflow", len(p.updates), p.overflowAt)
	}
	p := build(4097)
	if len(p.updates) != 4096 || p.overflowAt != model.MonoNano(1000+4096) {
		t.Fatalf("4097 announcements: %d kept, overflow at %d; want 4096 kept and the overflow at the 4097th (%d)", len(p.updates), p.overflowAt, 1000+4096)
	}
}

// One assembly accepts exactly 16384 mapping events; the 16385th is a resource-budget error.
func TestMappingEpochsAcceptExactly16384MappingEvents(t *testing.T) {
	events := make([]SanitizedEvent, 0, 16385)
	for i := range 16384 {
		events = append(events, confirm(uint64(i+1), 100, 110))
	}
	if _, err := newMappingEpochs(events); err != nil {
		t.Fatalf("16384 mapping events were refused: %v", err)
	}
	events = append(events, confirm(16385, 100, 110))
	if _, err := newMappingEpochs(events); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("16385 mapping events: %v, want ErrResourceBudget", err)
	}
}

// User space ends at 1<<56: a range that ends exactly there is user space, one that starts there is not, and an address
// the stream cannot prove (the history is unknown) is unknown all the way up to the last user address.
func TestMappingEpochsUserSpaceEndsAtTheFiftySixthBit(t *testing.T) {
	const end = uint64(1) << 56
	if got := userEntries([]mappingEntry{{start: end - 0x1000, end: end}, {start: end, end: end + 0x1000}}); len(got) != 1 || got[0].end != end {
		t.Fatalf("user entries %+v, want only the range ending at 1<<56", got)
	}
	unknown := unknownEntries()
	if len(unknown) != 1 || unknown[0].start != 0 || unknown[0].end != end || unknown[0].reason != FrameGeneration {
		t.Fatalf("unknown entries %+v, want [0, 1<<56) generation_changed", unknown)
	}
	// before the first read began nothing is proven, whichever user address the sample is at
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		confirm(3, 880, 900),
	)
	for _, ip := range []uint64{0, 1, end - 1} {
		wantNoModule(t, resolveAt(t, m, 50, ip), FrameGeneration)
	}
}

// Four reconciliation groups: the state after each is the one before it, the announcements between the two reads and the
// group's own rows - never an announcement older than the previous read (it is part of that read) and never one that
// came after the group.
func fourGroupStream() []SanitizedEvent {
	return []SanitizedEvent{
		// announced before the first read began, then replaced again without an announcement: the read says A
		mapEvent(1, 50, 0x10000, 0x20000, 0, libB, ""),
		snapRow(2, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(3, 100, 110),
		confirm(4, 190, 200),
		mapEvent(5, 250, 0x50000, 0x51000, 0x100, libC, ""),
		confirm(6, 290, 300),
		confirm(7, 390, 400),
	}
}

func TestMappingEpochsStateAfterAGroupNeverReplaysAnnouncementsOlderThanThePreviousRead(t *testing.T) {
	m := epochsOf(t, fourGroupStream()...)
	// the interval of the third group: its state is the second group's, which starts from the first read's rows
	wantModule(t, resolveAt(t, m, 240, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 350, 0x10010), libA, 0x10)
}

func TestMappingEpochsStateAfterAGroupNeverReplaysAnnouncementsThatCameAfterIt(t *testing.T) {
	m := epochsOf(t, fourGroupStream()...)
	// 210 lies in the third group's interval, the announcement is stamped 250: not yet in force
	wantNoModule(t, resolveAt(t, m, 210, 0x50010), FrameUnresolved)
	wantModule(t, resolveAt(t, m, 260, 0x50010), libC, 0x110)
}

// Asking about a later interval and then an earlier one resolves the earlier one from its own state, not from the
// later one that was just computed.
func TestMappingEpochsGoingBackInTimeRewindsTheState(t *testing.T) {
	m := epochsOf(t, fourGroupStream()...)
	wantModule(t, resolveAt(t, m, 350, 0x50010), libC, 0x110)
	wantNoModule(t, resolveAt(t, m, 210, 0x50010), FrameUnresolved)
	wantModule(t, resolveAt(t, m, 350, 0x50010), libC, 0x110)
	wantNoModule(t, resolveAt(t, m, 150, 0x50010), FrameUnresolved)
}

// A read is published with the instant it ended on every row and on the confirmation, the instant it began on each of
// them, and never a range above user space (the vsyscall page).
func TestSnapshotEventsStampTheEndOfTheReadAndStopAtUserSpace(t *testing.T) {
	const end = uint64(1) << 56
	table := MappingTable{process: epochProcess(), entries: []mappingEntry{
		{start: 0x10000, end: 0x20000, offset: 0x1000, module: SafeModule{ID: moduleIdentity(libA), BuildID: libA}},
		{start: 0x30000, end: 0x40000, reason: FrameJITMissing},
		{start: 0x50000, end: 0x60000},
		{start: end - 0x1000, end: end, reason: FrameJITMissing},
		{start: 0xffffffffff600000, end: 0xffffffffff601000, reason: FrameUnapproved},
	}}
	events := snapshotEvents(table, epochDomain(), 700, 900)
	if len(events) != 5 {
		t.Fatalf("%d events, want four rows and the confirmation", len(events))
	}
	for i, e := range events {
		if e.Kind != EventMapping || e.Time != 900 || e.Domain != epochDomain() || e.Mapping == nil || !e.Mapping.Snapshot || e.Mapping.Since != 700 || e.Mapping.Process != epochProcess() {
			t.Fatalf("event %d: %+v %+v", i, e, e.Mapping)
		}
	}
	rows := events[:4]
	if m := rows[0].Mapping; m.BuildID != libA || m.FileOffset != 0x1000 || m.Reason != "" || m.Start != 0x10000 || m.End != 0x20000 {
		t.Fatalf("named row %+v", m)
	}
	if m := rows[1].Mapping; m.BuildID != "" || m.Reason != FrameJITMissing || m.Start != 0x30000 {
		t.Fatalf("reasoned row %+v", m)
	}
	if m := rows[2].Mapping; m.BuildID != "" || m.Reason != FrameUnapproved || m.Start != 0x50000 {
		t.Fatalf("unnamed row %+v", m)
	}
	if m := rows[3].Mapping; uint64(m.End) != end {
		t.Fatalf("the last user range %+v", m)
	}
	if last := events[4].Mapping; !last.Confirm || last.Start != 0 || last.End != 0 {
		t.Fatalf("closing event %+v", last)
	}
}

// What lies above user space is not compared: the kernel's vsyscall page differs between two reads of the same
// process and is not a difference.
func TestDiffEntriesIgnoresWhatLiesAboveUserSpace(t *testing.T) {
	page := mappingEntry{start: 0xffffffffff600000, end: 0xffffffffff601000, reason: FrameUnapproved}
	user := mappingEntry{start: 0x10000, end: 0x20000, module: SafeModule{ID: moduleIdentity(libA), BuildID: libA}}
	if rows := diffEntries(epochProcess(), []mappingEntry{user}, []mappingEntry{user, page}, 100, 200); len(rows) != 0 {
		t.Fatalf("a kernel page that only the read holds is a difference: %+v", rows)
	}
	if rows := diffEntries(epochProcess(), []mappingEntry{user, page}, []mappingEntry{user}, 100, 200); len(rows) != 0 {
		t.Fatalf("a kernel page that only the prediction holds is a difference: %+v", rows)
	}
}
