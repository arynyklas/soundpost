// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Boundary and ordering pins for the mapping epochs (l4w33 mutation battery A).

// A mapping event that carries no mapping cannot be folded into an epoch: the whole list is refused instead of
// dereferenced.
func TestMappingEpochsRefuseAMappingEventWithoutAMapping(t *testing.T) {
	_, err := newMappingEpochs([]SanitizedEvent{{Kind: EventMapping, Time: 5, Domain: epochDomain()}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v, want ErrInvalid", err)
	}
	// a loss event without a loss payload is no evidence and no failure
	if _, err = newMappingEpochs([]SanitizedEvent{{Kind: EventLoss, Time: 5, Domain: epochDomain()}}); err != nil {
		t.Fatal(err)
	}
}

// One assembly accepts exactly maxMappingEvents mapping events; one more is a resource-budget error.
func TestMappingEpochsEventBudgetIsExact(t *testing.T) {
	events := make([]SanitizedEvent, 0, maxMappingEvents+1)
	for i := range maxMappingEvents {
		events = append(events, confirm(uint64(i+1), 100, 110))
	}
	if _, err := newMappingEpochs(events); err != nil {
		t.Fatalf("%d mapping events were refused: %v", maxMappingEvents, err)
	}
	events = append(events, confirm(maxMappingEvents+1, 100, 110))
	if _, err := newMappingEpochs(events); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("%d mapping events: %v, want ErrResourceBudget", maxMappingEvents+1, err)
	}
}

// Two announcements of the same instant apply in stream order: the later one owns the range.
func TestMappingEpochsAnnouncementsOfTheSameInstantApplyInStreamOrder(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		mapEvent(3, 500, 0x10000, 0x20000, 0x1000, libB, ""),
		mapEvent(4, 500, 0x10000, 0x20000, 0x2000, libC, ""),
		confirm(5, 880, 900),
	)
	wantModule(t, resolveAt(t, m, 600, 0x10010), libC, 0x2010)
}

// The announcements kept per process are bounded: the ones past maxEpochUpdates are dropped (never stored) and the
// history is unknown from the earliest of them.
func TestMappingEpochsKeepAtMostMaxEpochUpdatesAndMarkTheRestUnknown(t *testing.T) {
	events := []SanitizedEvent{
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
	}
	for i := range maxEpochUpdates {
		events = append(events, mapEvent(uint64(10+i), model.MonoNano(1000+i), 0x30000, 0x31000, 0, libB, ""))
	}
	// three announcements past the bound, the earliest of them in the middle
	events = append(events,
		mapEvent(90001, 90000, 0x40000, 0x41000, 0, libB, ""),
		mapEvent(90002, 80000, 0x40000, 0x41000, 0, libB, ""),
		mapEvent(90003, 95000, 0x40000, 0x41000, 0, libB, ""),
		confirm(90004, 99000, 99500),
	)
	m := epochsOf(t, events...)
	p := m.processes[epochProcess()]
	if len(p.updates) != maxEpochUpdates {
		t.Fatalf("%d announcements stored, want exactly %d", len(p.updates), maxEpochUpdates)
	}
	if p.overflowAt != 80000 {
		t.Fatalf("overflowAt %d, want the earliest dropped announcement (80000)", p.overflowAt)
	}
	wantModule(t, resolveAt(t, m, 79999, 0x10010), libA, 0x10)
	wantNoModule(t, resolveAt(t, m, 80000, 0x10010), FrameGeneration)
}

// A sample inside the first read, taken before an announcement that came after the whole read, is not touched by that
// announcement: the rows are the evidence and nothing newer is guessed into the range.
func TestMappingEpochsFirstReadIsNotCorruptedByAnnouncementsAfterIt(t *testing.T) {
	m := epochsOf(t,
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		mapEvent(3, 500, 0x10000, 0x20000, 0, libB, ""),
		confirm(4, 880, 900),
	)
	wantModule(t, resolveAt(t, m, 105, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 600, 0x10010), libB, 0x10)
}

// An announcement stamped at the very instant the first read began is not repainted over its rows: only the ones after
// that instant are (the rows decide for everything before it).
func TestMappingEpochsFirstReadDoesNotRepaintAnAnnouncementOfTheInstantItBegan(t *testing.T) {
	m := epochsOf(t,
		// the rows hold libC elsewhere and nothing at 0x10000 (the range was unmapped again inside the read)
		snapRow(1, 100, 110, 0x30000, 0x40000, 0, libC, ""),
		confirm(2, 100, 110),
		mapEvent(3, 100, 0x10000, 0x20000, 0, libB, ""),
		confirm(4, 880, 900),
	)
	wantNoModule(t, resolveAt(t, m, 105, 0x10010), FrameUnresolved)
	// one nanosecond later it is repainted: it happened after the read began
	n := epochsOf(t,
		snapRow(1, 100, 110, 0x30000, 0x40000, 0, libC, ""),
		confirm(2, 100, 110),
		mapEvent(3, 101, 0x10000, 0x20000, 0, libB, ""),
		confirm(4, 880, 900),
	)
	wantModule(t, resolveAt(t, n, 105, 0x10010), libB, 0x10)
}

// What was announced before the first read began is already in its rows: the sample inside the first read is
// attributed from the rows, not from the stream replayed over them.
func TestMappingEpochsFirstReadDoesNotReplayAnnouncementsOlderThanIt(t *testing.T) {
	m := epochsOf(t,
		mapEvent(1, 50, 0x10000, 0x20000, 0, libB, ""),
		// replaced again, without an announcement, before the read: the read says A
		snapRow(2, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(3, 100, 110),
		confirm(4, 880, 900),
	)
	wantModule(t, resolveAt(t, m, 105, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 300, 0x10010), libA, 0x10)
}

// A stream that arrives out of time order (rings are merged, not globally sorted) resolves like the sorted one: the
// announcements and the groups are ordered by their own instants.
func TestMappingEpochsAcceptAnnouncementsAndGroupsOutOfTimeOrder(t *testing.T) {
	m := epochsOf(t,
		snapRow(7, 880, 900, 0x30000, 0x40000, 0, libC, ""),
		confirm(8, 880, 900),
		mapEvent(5, 700, 0x10000, 0x20000, 0x3000, libC, ""),
		mapEvent(4, 500, 0x10000, 0x20000, 0x2000, libB, ""),
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		snapRow(2, 100, 110, 0x30000, 0x40000, 0, libC, ""),
		confirm(3, 100, 110),
		confirm(6, 990, 999),
	)
	wantModule(t, resolveAt(t, m, 120, 0x10010), libA, 0x10)
	wantModule(t, resolveAt(t, m, 600, 0x10010), libB, 0x2010)
	wantModule(t, resolveAt(t, m, 800, 0x10010), libC, 0x3010)
	wantModule(t, resolveAt(t, m, 950, 0x30010), libC, 0x10)
}

// Nothing above user space leaves the helper or is compared: the kernel's vsyscall page is not an event, and a range
// that ends exactly at the end of user space is.
func TestMappingEventsAndDiffsStopAtTheEndOfUserSpace(t *testing.T) {
	module := mappingEntry{start: 0x1000, end: 0x2000, module: SafeModule{ID: moduleIdentity(libA), BuildID: libA}}
	vsyscall := mappingEntry{start: 0xffffffffff600000, end: 0xffffffffff601000, reason: FrameUnapproved}
	table := MappingTable{process: epochProcess(), entries: []mappingEntry{module, vsyscall}}
	events := snapshotEvents(table, epochDomain(), 10, 20)
	if len(events) != 2 || events[0].Mapping.Start != 0x1000 || !events[1].Mapping.Confirm {
		t.Fatalf("%+v", events)
	}
	for i, e := range events {
		if e.Time != 20 || e.Mapping.Since != 10 || e.Domain != epochDomain() {
			t.Fatalf("event %d: time %d, since %d, domain %+v: a group is stamped with the end of its read and carries its beginning", i, e.Time, e.Mapping.Since, e.Domain)
		}
	}
	if rows := diffEntries(epochProcess(), nil, table.entries, 5, 9); len(rows) != 1 || rows[0].Start != 0x1000 {
		t.Fatalf("%+v", rows)
	}
	if rows := diffEntries(epochProcess(), table.entries, nil, 5, 9); len(rows) != 1 || rows[0].Start != 0x1000 || rows[0].Reason != FrameUnresolved {
		t.Fatalf("%+v", rows)
	}
	edge := []mappingEntry{
		{start: 1<<55 + 0x1000, end: 1<<55 + 0x2000, reason: FrameJITMissing},
		{start: userSpaceEnd - 0x1000, end: userSpaceEnd, reason: FrameJITMissing},
		{start: userSpaceEnd, end: userSpaceEnd + 0x1000, reason: FrameJITMissing},
	}
	if got := userEntries(edge); len(got) != 2 || got[1].end != userSpaceEnd {
		t.Fatalf("%+v", got)
	}
}

// A range the read holds with neither a module nor a reason is reported as unapproved; one that is no longer mapped is
// reported as unresolved.
func TestDiffEntriesNamesAnUnnamedRangeUnapproved(t *testing.T) {
	rows := diffEntries(epochProcess(), nil, []mappingEntry{{start: 0x1000, end: 0x2000}}, 5, 9)
	if len(rows) != 1 || rows[0].Reason != FrameUnapproved || rows[0].BuildID != "" {
		t.Fatalf("%+v", rows)
	}
}

// The table handed to frame resolution carries the symbolication policy it was asked for.
func TestMappingEpochsTableCarriesThePolicyAndTheProcess(t *testing.T) {
	m := epochsOf(t, snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""), confirm(2, 100, 110), confirm(3, 400, 410))
	table := m.tableAt(epochProcess(), 200, SymbolPolicy{Revision: 7, MaxELFBytes: 123, FramePointersAbsent: true})
	if table.process != epochProcess() || table.policy.Revision != 7 || table.policy.MaxELFBytes != 123 || !table.policy.FramePointersAbsent || len(table.entries) != 1 {
		t.Fatalf("%+v", table)
	}
}
