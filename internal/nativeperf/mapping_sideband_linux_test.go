//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/arynyklas/soundpost/internal/model"
)

// sidebandTask is the thread cpuRecord's samples belong to (pid 70, tid 71).
func sidebandTask() TaskKey {
	return TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 70, TID: 71, ProcessStart: 1, Generation: 1}
}

type mmap2Spec struct {
	pid, tid       uint32
	addr, size, pg uint64
	build          []byte
	maj, min       uint32
	ino            uint64
	prot, flags    uint32
	name           string
	misc           uint16
	at             uint64
	cpu            uint32
}

func defaultMmap2() mmap2Spec {
	return mmap2Spec{pid: 70, tid: 71, addr: 0x7f0000010000, size: 0x2000, pg: 0x4000, build: []byte{0xaa, 0x11, 0xcc, 0x22}, prot: 5, flags: 2, name: "/usr/lib/private-home-dir/libsecret.so", at: 123456, cpu: 2}
}

// mmap2Record lays out PERF_RECORD_MMAP2 as the kernel writes it for TID|TIME|CPU sample ids.
func mmap2Record(s mmap2Spec) []byte {
	name := (len(s.name) + 1 + 7) &^ 7
	size := 72 + name + 24
	b := make([]byte, size)
	o := binary.LittleEndian
	o.PutUint32(b, perfRecordMmap2)
	misc := s.misc | perfMiscUser
	if s.build != nil {
		misc |= perfMiscMmapBuildID
	}
	o.PutUint16(b[4:], misc)
	o.PutUint16(b[6:], uint16(size))
	o.PutUint32(b[8:], s.pid)
	o.PutUint32(b[12:], s.tid)
	o.PutUint64(b[16:], s.addr)
	o.PutUint64(b[24:], s.size)
	o.PutUint64(b[32:], s.pg)
	if s.build != nil {
		b[40] = byte(len(s.build))
		copy(b[44:64], s.build)
	} else {
		o.PutUint32(b[40:], s.maj)
		o.PutUint32(b[44:], s.min)
		o.PutUint64(b[48:], s.ino)
	}
	o.PutUint32(b[64:], s.prot)
	o.PutUint32(b[68:], s.flags)
	copy(b[72:], s.name)
	o.PutUint32(b[size-24:], s.pid)
	o.PutUint32(b[size-20:], s.tid)
	o.PutUint64(b[size-16:], s.at)
	o.PutUint32(b[size-8:], s.cpu)
	return b
}

// lostRecord is PERF_RECORD_LOST with the sample id trailer.
func lostRecord(count, at uint64) []byte {
	b := make([]byte, 48)
	o := binary.LittleEndian
	o.PutUint32(b, perfRecordLost)
	o.PutUint16(b[4:], perfMiscUser)
	o.PutUint16(b[6:], 48)
	o.PutUint64(b[8:], 1)
	o.PutUint64(b[16:], count)
	o.PutUint32(b[24:], 70)
	o.PutUint32(b[28:], 71)
	o.PutUint64(b[32:], at)
	return b
}

func sidebandRing(builds ...string) *Ring {
	r := ringWithMeta(make([]byte, 4096), 0, 0)
	r.task, r.method, r.maxFrames, r.builds = sidebandTask(), MethodSoftwareCPUClock, 128, builds
	return r
}

// push writes a record at the ring's head the way the kernel does (wrapping at the end of the data area).
func push(r *Ring, record []byte) {
	head := atomic.LoadUint64((*uint64)(unsafe.Pointer(&r.meta[1024])))
	for i, b := range record {
		r.data[(int(head)+i)%len(r.data)] = b
	}
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1024])), head+uint64(len(record)))
}

func decodeOne(t *testing.T, r *Ring, spec mmap2Spec) (SanitizedEvent, bool, error) {
	t.Helper()
	return decodeCPURecord(KernelRecordView{first: mmap2Record(spec)}, r)
}

func TestMmap2DecodesAnApprovedMappingAsANumericEvent(t *testing.T) {
	r := sidebandRing("aa11cc22")
	e, ok, err := decodeOne(t, r, defaultMmap2())
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	m := e.Mapping
	if e.Kind != EventMapping || e.Time != 123456 || e.CPU != 2 || e.Task != (TaskKey{}) || m == nil || m.BuildID != "aa11cc22" || m.Reason != "" || m.Start != 0x7f0000010000 || m.End != 0x7f0000012000 || m.FileOffset != 0x4000 || m.Snapshot || m.Process != processOf(sidebandTask()) {
		t.Fatalf("%+v %+v", e, m)
	}
	e.Domain, e.Sequence = ClockDomain{HostID: "host", BootID: "boot"}, 1
	if err = e.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)
	for _, private := range []string{"libsecret", "private-home-dir", "/usr", ".so"} {
		if strings.Contains(string(raw), private) {
			t.Fatalf("the mapped file's name reached the event: %s", raw)
		}
	}
}

// Only an approved build leaves the decoder as a build ID; every other range is announced as the reason it falls under.
func TestMmap2NamesOnlyApprovedBuildsAndClassifiesTheRest(t *testing.T) {
	r := sidebandRing("aa11cc22")
	other := defaultMmap2()
	other.build = []byte{0xde, 0xad, 0xbe, 0xef}
	anon := defaultMmap2()
	anon.build, anon.name, anon.pg = nil, "//anon", anon.addr
	nobuild := defaultMmap2()
	nobuild.build, nobuild.maj, nobuild.min, nobuild.ino = nil, 8, 1, 4242
	for name, tc := range map[string]struct {
		spec   mmap2Spec
		reason FrameReason
	}{"unapproved build": {other, FrameUnapproved}, "anonymous memory": {anon, FrameJITMissing}, "file without a build id": {nobuild, FrameUnapproved}} {
		e, ok, err := decodeOne(t, r, tc.spec)
		if err != nil || !ok || e.Mapping.BuildID != "" || e.Mapping.Reason != tc.reason || e.Mapping.FileOffset != 0 {
			t.Errorf("%s: %+v %v %v", name, e.Mapping, ok, err)
			continue
		}
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "dead") || strings.Contains(string(raw), "4242") {
			t.Errorf("%s: identity leaked: %s", name, raw)
		}
	}
	data := defaultMmap2()
	data.prot = 3
	if _, ok, err := decodeOne(t, r, data); ok || err != nil {
		t.Fatalf("a non-executable mapping produced an event: %v %v", ok, err)
	}
}

func TestMmap2RefusesWhatItCannotAttributeToItsOwnThread(t *testing.T) {
	r := sidebandRing("aa11cc22")
	for name, mutate := range map[string]func(*mmap2Spec){
		"another process": func(s *mmap2Spec) { s.pid++ },
		"another thread":  func(s *mmap2Spec) { s.tid++ },
		"no time":         func(s *mmap2Spec) { s.at = 0 },
		"empty range":     func(s *mmap2Spec) { s.size = 0 },
		"null start":      func(s *mmap2Spec) { s.addr = 0 },
		"beyond user":     func(s *mmap2Spec) { s.addr = 1 << 56 },
		"wrapping range":  func(s *mmap2Spec) { s.size = 1 << 56 },
		"wrapping offset": func(s *mmap2Spec) { s.pg = ^uint64(0) },
		"empty build id":  func(s *mmap2Spec) { s.build = []byte{} },
		"huge build id":   func(s *mmap2Spec) { s.build = make([]byte, 21) },
	} {
		spec := defaultMmap2()
		mutate(&spec)
		if spec.build != nil && len(spec.build) == 21 {
			// a 21-byte build id does not fit the 20 bytes the kernel reserves: lay it out by hand
			b := mmap2Record(defaultMmap2())
			b[40] = 21
			if _, ok, err := decodeCPURecord(KernelRecordView{first: b}, r); ok || !errors.Is(err, ErrRingMalformed) {
				t.Errorf("%s: %v %v", name, ok, err)
			}
			continue
		}
		wantID := name == "another process" || name == "another thread"
		_, ok, err := decodeCPURecord(KernelRecordView{first: mmap2Record(spec)}, r)
		if ok || err == nil || wantID != errors.Is(err, ErrTargetIdentity) {
			t.Errorf("%s: %v %v", name, ok, err)
		}
	}
	good := mmap2Record(defaultMmap2())
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte {
			b = b[:len(b)-8]
			binary.LittleEndian.PutUint16(b[6:], uint16(len(b)))
			return b
		},
		"kernel mode":              func(b []byte) []byte { binary.LittleEndian.PutUint16(b[4:], perfMiscMmapBuildID|1); return b },
		"sample id of another tid": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[len(b)-20:], 99); return b },
		"size beyond the bound":    func(b []byte) []byte { return append(b, make([]byte, 8192)...) },
	} {
		b := mutate(append([]byte(nil), good...))
		if name == "size beyond the bound" {
			binary.LittleEndian.PutUint16(b[6:], 0) // a 16-bit size cannot say it; the view length must agree with the header
		}
		if _, ok, err := decodeCPURecord(KernelRecordView{first: b}, r); ok || err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func drainAll(t *testing.T, r *Ring) []SanitizedEvent {
	t.Helper()
	var out []SanitizedEvent
	for r.tail() != r.head() {
		before := r.tail()
		if err := drainRing(r, func(e SanitizedEvent) error { out = append(out, e); return nil }); err != nil {
			t.Fatal(err)
		}
		if r.tail() == before {
			t.Fatal("drain made no progress")
		}
	}
	return out
}

func sweepAll(t *testing.T, r *Ring) []SanitizedEvent {
	t.Helper()
	events, full, err := sweepRings([]*Ring{r}, ClockDomain{HostID: "host", BootID: "boot"})
	if err != nil || full {
		t.Fatal(full, err)
	}
	return events
}

// A sweep hands out the announcements and overflows already in the ring, in order, without consuming anything; the
// drain that follows emits the samples only, and an announcement written after the sweep is still emitted once.
func TestSidebandSweepIsExactlyOnceAndLeavesTheRingIntact(t *testing.T) {
	r := sidebandRing("aa11cc22")
	sample := cpuRecord(0x1000).first
	late := defaultMmap2()
	late.at, late.addr = 700, 0x7f0000100000
	first := defaultMmap2()
	first.at = 200
	push(r, sample)
	push(r, mmap2Record(first))
	push(r, lostRecord(5, 300))
	push(r, sample)
	tail, head := r.tail(), r.head()
	swept := sweepAll(t, r)
	if len(swept) != 2 || swept[0].Kind != EventMapping || swept[0].Time != 200 || swept[1].Kind != EventLoss || swept[1].Time != 300 || swept[1].Loss.Count != 5 {
		t.Fatalf("swept %+v", swept)
	}
	if r.tail() != tail || r.head() != head {
		t.Fatal("the sweep consumed the ring")
	}
	if again := sweepAll(t, r); len(again) != 0 {
		t.Fatalf("a second sweep handed out %d records again", len(again))
	}
	push(r, mmap2Record(late))
	drained := drainAll(t, r)
	if len(drained) != 3 || drained[0].Kind != EventCPU || drained[1].Kind != EventCPU || drained[2].Kind != EventMapping || drained[2].Time != 700 {
		t.Fatalf("drained %d events: %+v", len(drained), drained)
	}
	if swept = sweepAll(t, r); len(swept) != 0 {
		t.Fatalf("records handed out again after the drain: %+v", swept)
	}
}

// Draining first and sweeping later also hands each announcement out once, and a record that wraps the end of the
// data area is read whole.
func TestSidebandDrainThenSweepAndWrappedRecords(t *testing.T) {
	r := sidebandRing("aa11cc22")
	record := mmap2Record(defaultMmap2())
	// advance head and tail near the end of the data area so every record straddles the wrap
	skip := len(r.data) - 40
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1024])), uint64(skip))
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1032])), uint64(skip))
	for _, at := range []uint64{10, 20, 30} {
		spec := defaultMmap2()
		spec.at = at
		push(r, mmap2Record(spec))
	}
	got := drainAll(t, r)
	if len(got) != 3 || got[0].Time != 10 || got[2].Time != 30 || uint64(len(record))*3 != r.head()-uint64(skip) {
		t.Fatalf("%d events %+v", len(got), got)
	}
	if swept := sweepAll(t, r); len(swept) != 0 {
		t.Fatalf("swept %d after draining", len(swept))
	}
	spec := defaultMmap2()
	spec.at = 40
	push(r, mmap2Record(spec))
	if swept := sweepAll(t, r); len(swept) != 1 || swept[0].Time != 40 {
		t.Fatalf("%+v", swept)
	}
	if got = drainAll(t, r); len(got) != 0 {
		t.Fatalf("an announcement handed out by the sweep was emitted again: %+v", got)
	}
}

// Announcements from many rings are returned oldest first; a ring that holds more than the sweep bound drops the rest
// and says so instead of growing without bound, and the next sweep continues with newer records.
func TestSidebandSweepMergesRingsByTimeAndIsBounded(t *testing.T) {
	a, b := sidebandRing("aa11cc22"), sidebandRing("aa11cc22")
	for _, at := range []uint64{50, 10} {
		spec := defaultMmap2()
		spec.at = at
		push(a, mmap2Record(spec))
	}
	spec := defaultMmap2()
	spec.at = 30
	push(b, mmap2Record(spec))
	events, full, err := sweepRings([]*Ring{a, b}, ClockDomain{HostID: "host", BootID: "boot"})
	if err != nil || full || len(events) != 3 || events[0].Time != 10 || events[1].Time != 30 || events[2].Time != 50 {
		t.Fatalf("%v %v %+v", full, err, events)
	}
	big := sidebandRing("aa11cc22")
	big.data = make([]byte, 1<<20)
	spec = defaultMmap2()
	spec.name = ""
	for i := range sidebandSweepMax + 10 {
		spec.at = uint64(100 + i)
		push(big, mmap2Record(spec))
	}
	events, full, err = sweepRings([]*Ring{big}, ClockDomain{HostID: "host", BootID: "boot"})
	if err != nil || !full || len(events) != sidebandSweepMax {
		t.Fatalf("%v %v %d", full, err, len(events))
	}
	spec.at = 99999
	push(big, mmap2Record(spec))
	events, full, err = sweepRings([]*Ring{big}, ClockDomain{HostID: "host", BootID: "boot"})
	if err != nil || full || len(events) != 1 || events[0].Time != 99999 {
		t.Fatalf("after the overflow: %v %v %d", full, err, len(events))
	}
}

func TestSidebandSweepRefusesAnOverwrittenOrClosedRing(t *testing.T) {
	r := sidebandRing()
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&r.meta[1024])), uint64(len(r.data))+1)
	if _, _, err := sweepRings([]*Ring{r}, ClockDomain{}); !errors.Is(err, ErrRingOverwrite) {
		t.Fatal(err)
	}
	c := sidebandRing()
	c.closed = true
	if _, _, err := sweepRings([]*Ring{c}, ClockDomain{}); !errors.Is(err, ErrAcquisitionClosed) {
		t.Fatal(err)
	}
}

type sweepingSource struct {
	items   []AcquisitionItem
	swept   [][]SanitizedEvent
	full    []bool
	sweepFn func() error
}

func (s *sweepingSource) Next(context.Context) (SanitizedEvent, error) {
	return SanitizedEvent{}, ErrProgressRequired
}
func (s *sweepingSource) Close() error { return nil }
func (s *sweepingSource) NextItem(context.Context) (AcquisitionItem, error) {
	if len(s.items) == 0 {
		return AcquisitionItem{}, ErrSourceComplete
	}
	item := s.items[0]
	s.items = s.items[1:]
	return item, nil
}
func (s *sweepingSource) sweepSideband() ([]SanitizedEvent, bool, error) {
	if s.sweepFn != nil {
		if err := s.sweepFn(); err != nil {
			return nil, false, err
		}
	}
	if len(s.swept) == 0 {
		return nil, false, nil
	}
	out, full := s.swept[0], s.full[0]
	s.swept, s.full = s.swept[1:], s.full[1:]
	return out, full, nil
}

func sidebandSample(at model.MonoNano) AcquisitionItem {
	e := testEvent()
	e.Task = sidebandTask()
	e.Time = at
	e.Domain = ClockDomain{HostID: "host", BootID: "boot"}
	e.Task.BootID = "boot"
	return AcquisitionItem{Event: &e}
}

// The sample a sweep ran for leaves AFTER every announcement the sweep found, so a consumer that stops at that sample
// holds every announcement the kernel had written before it; the source numbers everything it publishes in one sequence.
func TestProfileSourcePublishesSweptMappingsAheadOfTheSampleInOneSequence(t *testing.T) {
	domain := ClockDomain{HostID: "host", BootID: "boot"}
	ann := func(at model.MonoNano, start uint64) SanitizedEvent {
		u := MappingUpdate{Process: processOf(sidebandTask()), Start: model.Uint64(start), End: model.Uint64(start + 0x1000), BuildID: "aa11"}
		return SanitizedEvent{Kind: EventMapping, Time: at, Domain: domain, Mapping: &u}
	}
	snapshot := snapshotEvents(MappingTable{process: processOf(sidebandTask()), entries: []mappingEntry{{start: 0x1000, end: 0x2000, module: SafeModule{ID: moduleIdentity("aa11"), BuildID: "aa11"}}}}, domain, 5, 9)
	src := &sweepingSource{items: []AcquisitionItem{sidebandSample(100), sidebandSample(200)}, swept: [][]SanitizedEvent{{ann(50, 0x10000), ann(60, 0x20000)}, nil}, full: []bool{true, false}}
	s := &ProfileSource{source: src, domain: domain}
	for i := range snapshot {
		s.pending = append(s.pending, AcquisitionItem{Event: &snapshot[i]})
	}
	var got []SanitizedEvent
	for {
		item, err := s.NextItem(context.Background())
		if errors.Is(err, ErrSourceComplete) {
			break
		}
		if err != nil || item.Event == nil {
			t.Fatal(item, err)
		}
		got = append(got, *item.Event)
	}
	kinds := make([]EventKind, len(got))
	for i, e := range got {
		kinds[i] = e.Kind
		if e.Sequence != model.Uint64(i+1) {
			t.Fatalf("event %d has sequence %d", i, e.Sequence)
		}
		if err := e.Validate(); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
	want := []EventKind{EventMapping, EventMapping, EventMapping, EventMapping, EventLoss, EventCPU, EventCPU}
	if len(kinds) != len(want) {
		t.Fatalf("%v", kinds)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("%v, want %v", kinds, want)
		}
	}
	if !got[0].Mapping.Snapshot || got[0].Mapping.Confirm || !got[1].Mapping.Confirm || got[2].Mapping.Snapshot || got[3].Mapping.Snapshot || got[2].Time != 50 || got[4].Loss.Reason != ReasonLoss || got[4].Time != 50 || got[5].Time != 100 {
		t.Fatalf("%+v", got)
	}
}

func TestProfileSourceTreatsASweepFailureLikeASourceFailure(t *testing.T) {
	want := errors.New("ring overwritten")
	src := &sweepingSource{items: []AcquisitionItem{sidebandSample(100)}, sweepFn: func() error { return want }}
	s := &ProfileSource{source: src, domain: ClockDomain{HostID: "host", BootID: "boot"}}
	if item, err := s.NextItem(context.Background()); !errors.Is(err, want) || item.Event != nil {
		t.Fatalf("%v %v", item, err)
	}
}
