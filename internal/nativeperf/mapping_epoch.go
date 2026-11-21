// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
)

// Mapping epochs: which mapping owned an address when a sample was taken.
//
// A /proc/<pid>/maps read is the state at the instant it was read; a sample taken earlier can have run in code that
// has since been unmapped, or in a different library that used the same addresses. The epochs are rebuilt from the
// stream instead, from two kinds of evidence:
//
//   - announcements: the kernel announces every executable mmap (PERF_RECORD_MMAP2, decoded by the helper into an
//     EventMapping stamped with the kernel's own clock), so a library mapped over another one is attributed exactly;
//   - reconciliation groups: the helper re-reads the maps every few hundred milliseconds and compares them with what
//     the announcements predict. The kernel does NOT announce mremap, mprotect or munmap, so a difference is an
//     unannounced change. A group carries only the ranges that differ from the prediction, plus a confirmation that
//     everything else matched (rows and the confirmation share the group's Time; Since is the instant before the read).
//
// A sample at time t is resolved against the state after the last group at or before t, plus the announcements up to
// t, and only when a LATER group confirms the interval: the ranges that group corrected changed at some unknown
// instant inside the interval, so they are unresolved there, and a sample after the last group is unconfirmed.
// What the stream cannot prove is never guessed: before the first read began (Since), inside the first read for a
// range an announcement replaced, after a ring overflow (a lost record may have been an announcement), past the
// bounds below, or in a trailing interval nothing confirmed, the frames carry generation_changed instead of a module.
// What no reconciliation can see is a mapping replaced and restored again between two reads without an announcement.
// A process with no group at all keeps the older identity-only behavior (no module, frame_unresolved).
const (
	// maxEpochUpdates bounds the announcements kept per process; the next one marks the history unknown from its time.
	maxEpochUpdates = 4096
	// maxMappingEvents bounds the mapping events one assembly accepts (a snapshot is at most MaxMappings = 4096 rows).
	maxMappingEvents = 16384
	userSpaceEnd     = uint64(1) << 56
)

type timedMapping struct {
	at model.MonoNano
	m  MappingUpdate
}

type reconcileGroup struct {
	at, since model.MonoNano
	rows      []MappingUpdate
}

type processEpochs struct {
	groups     []reconcileGroup
	conflict   bool
	updates    []timedMapping
	overflowAt model.MonoNano

	// the state after groups[stateIdx], and the table last handed out (state + announcements up to cacheN + the
	// unknown ranges of the closing group) for interval cacheIdx
	state      []mappingEntry
	stateIdx   int
	stateValid bool
	cache      []mappingEntry
	cacheIdx   int
	cacheN     int
	cacheValid bool
}

type mappingEpochs struct {
	processes map[ProcessKey]*processEpochs
	lossFrom  model.MonoNano
	events    int
}

// newMappingEpochs collects the mapping events (and the first ring overflow) of an event list. It never reads /proc or
// a file: the list is the whole evidence.
func newMappingEpochs(events []SanitizedEvent) (*mappingEpochs, error) {
	m := &mappingEpochs{processes: map[ProcessKey]*processEpochs{}}
	for _, e := range events {
		switch e.Kind {
		case EventLoss:
			// PERF_RECORD_LOST is a ring overflow: the lost records can include a mapping announcement.
			// Lost samples (PERF_RECORD_LOST_SAMPLES) and throttling never drop sideband records.
			if e.Loss != nil && e.Loss.Reason == ReasonLoss && (m.lossFrom == 0 || e.Time < m.lossFrom) {
				m.lossFrom = e.Time
			}
		case EventMapping:
			if e.Mapping == nil {
				return nil, ErrInvalid
			}
			m.events++
			if m.events > maxMappingEvents {
				return nil, ErrResourceBudget
			}
			p := m.processes[e.Mapping.Process]
			if p == nil {
				p = &processEpochs{}
				m.processes[e.Mapping.Process] = p
			}
			p.add(e)
		}
	}
	for _, p := range m.processes {
		sort.SliceStable(p.updates, func(i, j int) bool { return p.updates[i].at < p.updates[j].at })
		sort.SliceStable(p.groups, func(i, j int) bool { return p.groups[i].at < p.groups[j].at })
	}
	return m, nil
}

func (p *processEpochs) add(e SanitizedEvent) {
	u := *e.Mapping
	if u.Snapshot {
		i := -1
		for j := range p.groups {
			if p.groups[j].at == e.Time {
				i = j
				break
			}
		}
		if i < 0 {
			p.groups = append(p.groups, reconcileGroup{at: e.Time, since: u.Since})
			i = len(p.groups) - 1
		}
		if p.groups[i].since != u.Since {
			p.conflict = true
			return
		}
		if !u.Confirm {
			p.groups[i].rows = append(p.groups[i].rows, u)
		}
		return
	}
	if len(p.updates) >= maxEpochUpdates {
		if p.overflowAt == 0 || e.Time < p.overflowAt {
			p.overflowAt = e.Time
		}
		return
	}
	p.updates = append(p.updates, timedMapping{at: e.Time, m: u})
}

func entryOf(u MappingUpdate) mappingEntry {
	if u.BuildID == "" {
		return mappingEntry{start: uint64(u.Start), end: uint64(u.End), reason: u.Reason}
	}
	return mappingEntry{start: uint64(u.Start), end: uint64(u.End), offset: uint64(u.FileOffset), module: SafeModule{ID: moduleIdentity(u.BuildID), BuildID: u.BuildID}}
}

// paint makes e the owner of [e.start, e.end): what it overlaps is trimmed (a file-backed remainder keeps the file
// offset of its own first byte) or removed. entries stay sorted and disjoint.
func paint(entries []mappingEntry, e mappingEntry) []mappingEntry {
	first := sort.Search(len(entries), func(i int) bool { return entries[i].end > e.start })
	last := first
	for last < len(entries) && entries[last].start < e.end {
		last++
	}
	out := make([]mappingEntry, 0, len(entries)+2)
	out = append(out, entries[:first]...)
	for _, x := range entries[first:last] {
		if x.start < e.start {
			left := x
			left.end = e.start
			out = append(out, left)
		}
	}
	out = append(out, e)
	for _, x := range entries[first:last] {
		if x.end > e.end {
			right := x
			if right.module.ID != "" {
				right.offset += e.end - right.start
			}
			right.start = e.end
			out = append(out, right)
		}
	}
	return append(out, entries[last:]...)
}

func unknownEntries() []mappingEntry {
	return []mappingEntry{{start: 0, end: userSpaceEnd, reason: FrameGeneration}}
}

func unknownRange(u MappingUpdate) mappingEntry {
	return mappingEntry{start: uint64(u.Start), end: uint64(u.End), reason: FrameGeneration}
}

// stateAt is the mapping table at groups[i].at: the previous state, the announcements since, then the group's rows.
func (p *processEpochs) stateAt(i int) []mappingEntry {
	if !p.stateValid || p.stateIdx > i {
		p.state, p.stateIdx, p.stateValid = nil, -1, true
	}
	for p.stateIdx < i {
		k := p.stateIdx + 1
		s := p.state
		if k > 0 {
			lo := sort.Search(len(p.updates), func(j int) bool { return p.updates[j].at > p.groups[k-1].at })
			hi := sort.Search(len(p.updates), func(j int) bool { return p.updates[j].at > p.groups[k].at })
			for _, u := range p.updates[lo:hi] {
				s = paint(s, entryOf(u.m))
			}
		}
		for _, row := range p.groups[k].rows {
			s = paint(s, entryOf(row))
		}
		p.state, p.stateIdx = s, k
	}
	return p.state
}

// entriesAt is the mapping table of a process at t, or nil when the stream carries no group of that process.
func (m *mappingEpochs) entriesAt(k ProcessKey, t model.MonoNano) []mappingEntry {
	p := m.processes[k]
	if p == nil || len(p.groups) == 0 {
		return nil
	}
	if p.conflict || t < p.groups[0].since || m.lossFrom != 0 && t >= m.lossFrom || p.overflowAt != 0 && t >= p.overflowAt {
		return unknownEntries()
	}
	// idx is the group that closes the interval t lies in: the first one that ended after t.
	idx := sort.Search(len(p.groups), func(i int) bool { return p.groups[i].at > t })
	if idx == len(p.groups) {
		return unknownEntries()
	}
	n := sort.Search(len(p.updates), func(i int) bool { return p.updates[i].at > t })
	if idx == 0 {
		// t lies inside the first read: the rows can already hold announcements newer than t. What such an
		// announcement replaced is gone from the rows, so its range is unknown at t; announcements after the read
		// began and up to t are repainted.
		g := p.groups[0]
		entries := p.stateAt(0)
		for _, u := range p.updates[n:] {
			if u.at > g.at {
				break
			}
			entries = paint(entries, unknownRange(u.m))
		}
		first := sort.Search(len(p.updates), func(i int) bool { return p.updates[i].at > g.since })
		for i := first; i < n; i++ {
			entries = paint(entries, entryOf(p.updates[i].m))
		}
		return entries
	}
	if p.cacheValid && p.cacheIdx == idx && p.cacheN == n {
		return p.cache
	}
	// the table the previous group left, plus every announcement up to t, then the ranges the closing group found
	// changed without an announcement: those changed at an unknown instant of this interval.
	entries := p.stateAt(idx - 1)
	lo := sort.Search(len(p.updates), func(i int) bool { return p.updates[i].at > p.groups[idx-1].at })
	for _, u := range p.updates[lo:n] {
		entries = paint(entries, entryOf(u.m))
	}
	for _, row := range p.groups[idx].rows {
		entries = paint(entries, unknownRange(row))
	}
	p.cache, p.cacheIdx, p.cacheN, p.cacheValid = entries, idx, n, true
	return entries
}

// tableAt is the MappingTable ResolveFrames reads for the process k at t. policy carries the symbolication binding.
func (m *mappingEpochs) tableAt(k ProcessKey, t model.MonoNano, policy SymbolPolicy) MappingTable {
	return MappingTable{process: k, entries: m.entriesAt(k, t), policy: policy}
}

// snapshotEvents publishes a map read as mapping events: one row per mapping and the confirmation that closes the
// group, all stamped with the instant the read ended and carrying the instant it began. A row names a module only for
// an approved build and has no path, device or inode; any other range carries the reason it was not named.
func snapshotEvents(t MappingTable, domain ClockDomain, since, at model.MonoNano) []SanitizedEvent {
	t.entries = userEntries(t.entries)
	out := make([]SanitizedEvent, 0, len(t.entries)+1)
	for _, e := range t.entries {
		u := MappingUpdate{Process: t.process, Start: model.Uint64(e.start), End: model.Uint64(e.end), Snapshot: true, Since: since}
		if e.module.ID != "" {
			u.BuildID, u.FileOffset = e.module.BuildID, model.Uint64(e.offset)
		} else if u.Reason = e.reason; u.Reason == "" {
			u.Reason = FrameUnapproved
		}
		out = append(out, SanitizedEvent{Kind: EventMapping, Time: at, Domain: domain, Mapping: &u})
	}
	return append(out, confirmEvent(t.process, domain, since, at))
}

// confirmEvent closes a reconciliation group: the ranges of the group (possibly none) are the only ones that differ
// from what the announcements predicted.
func confirmEvent(process ProcessKey, domain ClockDomain, since, at model.MonoNano) SanitizedEvent {
	return SanitizedEvent{Kind: EventMapping, Time: at, Domain: domain, Mapping: &MappingUpdate{Process: process, Snapshot: true, Confirm: true, Since: since}}
}

// ownerAt is the entry that owns address a, if any.
func ownerAt(entries []mappingEntry, a uint64) (mappingEntry, bool) {
	i := sort.Search(len(entries), func(i int) bool { return entries[i].end > a })
	if i < len(entries) && entries[i].start <= a {
		return entries[i], true
	}
	return mappingEntry{}, false
}

func offsetAt(e mappingEntry, a uint64) uint64 { return e.offset + (a - e.start) }

// diffEntries is the rows of actual that differ from predicted: for every address range whose owner (module and file
// offset, or reason) is not the same, the owner in actual, or an unresolved range when nothing is mapped there any more.
// Adjacent rows with the same owner are merged.
func diffEntries(process ProcessKey, predicted, actual []mappingEntry, since, at model.MonoNano) []MappingUpdate {
	predicted, actual = userEntries(predicted), userEntries(actual)
	points := make([]uint64, 0, 2*(len(predicted)+len(actual)))
	for _, list := range [][]mappingEntry{predicted, actual} {
		for _, e := range list {
			points = append(points, e.start, e.end)
		}
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	var rows []MappingUpdate
	for i := 0; i+1 < len(points); i++ {
		a, b := points[i], points[i+1]
		if a == b {
			continue
		}
		p, pOK := ownerAt(predicted, a)
		q, qOK := ownerAt(actual, a)
		if !pOK && !qOK {
			continue
		}
		if pOK && qOK && p.module.ID == q.module.ID && p.reason == q.reason && (p.module.ID == "" || offsetAt(p, a) == offsetAt(q, a)) {
			continue
		}
		row := MappingUpdate{Process: process, Start: model.Uint64(a), End: model.Uint64(b), Snapshot: true, Since: since}
		switch {
		case !qOK:
			row.Reason = FrameUnresolved
		case q.module.ID != "":
			row.BuildID, row.FileOffset = q.module.BuildID, model.Uint64(offsetAt(q, a))
		default:
			if row.Reason = q.reason; row.Reason == "" {
				row.Reason = FrameUnapproved
			}
		}
		if n := len(rows); n > 0 {
			last := &rows[n-1]
			if uint64(last.End) == a && last.BuildID == row.BuildID && last.Reason == row.Reason && (row.BuildID == "" || uint64(last.FileOffset)+uint64(last.End-last.Start) == uint64(row.FileOffset)) {
				last.End = row.End
				continue
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// userEntries drops what lies above user space (the kernel's fixed vsyscall page is an executable map row on kernels that
// emulate it): no user instruction pointer can be there and a mapping event cannot name it.
func userEntries(entries []mappingEntry) []mappingEntry {
	out := make([]mappingEntry, 0, len(entries))
	for _, e := range entries {
		if e.end <= userSpaceEnd {
			out = append(out, e)
		}
	}
	return out
}
