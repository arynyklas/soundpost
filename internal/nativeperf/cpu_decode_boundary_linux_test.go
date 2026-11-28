//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"unsafe"
)

var softCtx = DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 128}

func decodeOK(t *testing.T, name string, v KernelRecordView, c DecodeContext) CPUSample {
	t.Helper()
	s, e := decodeCPUSample(v, c)
	if e != nil {
		t.Fatalf("%s: %v", name, e)
	}
	return s
}

func TestDecodeCPUSampleHeaderAndFieldBounds(t *testing.T) {
	good := cpuRecord(0x1000)
	if s := decodeOK(t, "baseline", good, softCtx); s.Truncated != "" || len(s.Callchain) != 1 || s.RequestedHz != 99 {
		t.Fatalf("%+v", s)
	}
	patch := func(f func(b []byte)) KernelRecordView {
		r := cpuRecord(0x1000)
		f(r.first)
		return r
	}
	mutate := map[string]KernelRecordView{
		"not a sample record":       patch(func(b []byte) { binary.LittleEndian.PutUint32(b, 3) }),
		"misc user bit missing":     patch(func(b []byte) { binary.LittleEndian.PutUint16(b[4:], 0) }),
		"misc hypervisor":           patch(func(b []byte) { binary.LittleEndian.PutUint16(b[4:], 3) }),
		"misc guest user":           patch(func(b []byte) { binary.LittleEndian.PutUint16(b[4:], 5) }),
		"misc guest kernel":         patch(func(b []byte) { binary.LittleEndian.PutUint16(b[4:], 4) }),
		"IP zero":                   patch(func(b []byte) { binary.LittleEndian.PutUint64(b[8:], 0) }),
		"IP at 2^56":                patch(func(b []byte) { binary.LittleEndian.PutUint64(b[8:], 1<<56) }),
		"IP kernel":                 patch(func(b []byte) { binary.LittleEndian.PutUint64(b[8:], 0xffff800000000000) }),
		"period zero":               patch(func(b []byte) { binary.LittleEndian.PutUint64(b[40:], 0) }),
		"nonzero reserved word":     patch(func(b []byte) { binary.LittleEndian.PutUint32(b[36:], 1) }),
		"callchain count too small": patch(func(b []byte) { binary.LittleEndian.PutUint64(b[48:], 0) }),
		"callchain count too large": patch(func(b []byte) { binary.LittleEndian.PutUint64(b[48:], 2) }),
	}
	for name, v := range mutate {
		if _, e := decodeCPUSample(v, softCtx); !errors.Is(e, ErrRingMalformed) {
			t.Errorf("%s: %v", name, e)
		}
	}
	// A record shorter than the fixed 56-byte header is malformed even when its own size field agrees.
	short := make([]byte, 48)
	binary.LittleEndian.PutUint32(short, 9)
	binary.LittleEndian.PutUint16(short[4:], 2)
	binary.LittleEndian.PutUint16(short[6:], 48)
	binary.LittleEndian.PutUint64(short[8:], 0x1234) // a valid IP and period: only the missing count word can refuse it
	binary.LittleEndian.PutUint64(short[40:], 1)
	if _, e := decodeCPUSample(KernelRecordView{first: short}, softCtx); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("short record: %v", e)
	}
	// count*8 wraps to 0 for count = 2^61: the bound on count itself must reject it, not only the multiplied size.
	wrap := cpuRecord()
	binary.LittleEndian.PutUint64(wrap.first[48:], 1<<61)
	if _, e := decodeCPUSample(wrap, softCtx); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("wrapping count accepted: %v", e)
	}
	// Accepted edge values.
	edge := patch(func(b []byte) {
		binary.LittleEndian.PutUint64(b[8:], 1<<56-1)
		binary.LittleEndian.PutUint16(b[4:], 0x2002)
	})
	decodeOK(t, "IP at 2^56-1, high misc bits", edge, softCtx)
	for _, frames := range []uint16{0, 129, 200} {
		if _, e := decodeCPUSample(good, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: frames}); !errors.Is(e, ErrRingMalformed) {
			t.Errorf("MaxFrames %d: %v", frames, e)
		}
	}
	decodeOK(t, "MaxFrames 1", good, DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 1})
	if _, e := decodeCPUSample(good, DecodeContext{Method: "bogus", MaxFrames: 128}); !errors.Is(e, ErrInvalid) {
		t.Errorf("unknown method: %v", e)
	}
	if s := decodeOK(t, "cycles", good, DecodeContext{Method: MethodHardwareCycles, MaxFrames: 128}); s.Unit != UnitHardwareCycles || s.Method != MethodHardwareCycles {
		t.Errorf("cycles: %+v", s)
	}
	// A split (wrapped) view decodes identically to a contiguous one.
	whole := cpuRecord(0x1000, 0x2000).first
	split := KernelRecordView{first: whole[:30], second: whole[30:]}
	if a, b := decodeOK(t, "contiguous", KernelRecordView{first: whole}, softCtx), decodeOK(t, "split", split, softCtx); len(a.Callchain) != len(b.Callchain) || a.IP != b.IP || a.Period != b.Period {
		t.Errorf("split view differs: %+v vs %+v", a, b)
	}
	// valid(): size field must equal the real length.
	lie := cpuRecord(0x1000)
	binary.LittleEndian.PutUint16(lie.first[6:], uint16(len(lie.first)+8))
	if _, e := decodeCPUSample(lie, softCtx); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("size field lies: %v", e)
	}
}

func TestDecodeCPUSampleTruncationThresholds(t *testing.T) {
	chain := func(n int) []uint64 {
		out := make([]uint64, n)
		for i := range out {
			out[i] = 0x1000 + uint64(i)
		}
		return out
	}
	for _, tc := range []struct {
		max, n    uint32
		truncated Reason
		frames    int
	}{
		{4, 3, "", 3},
		{4, 4, ReasonTruncated, 4},
		{4, 5, ReasonTruncated, 4},
		{128, 126, "", 126},
		{128, 127, ReasonTruncated, 127},
		{128, 128, ReasonTruncated, 128},
		{128, 129, ReasonTruncated, 128},
		{127, 126, "", 126},
		{127, 127, ReasonTruncated, 127},
	} {
		s := decodeOK(t, "chain", cpuRecord(chain(int(tc.n))...), DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: uint16(tc.max)})
		if s.Truncated != tc.truncated || len(s.Callchain) != tc.frames || !s.valid() {
			t.Errorf("max %d count %d: truncated %q frames %d (want %q %d)", tc.max, tc.n, s.Truncated, len(s.Callchain), tc.truncated, tc.frames)
		}
	}
}

func TestCallchainMarkersAndContexts(t *testing.T) {
	for ip, want := range map[uint64]CallchainContext{
		^uint64(31): ContextHypervisor, ^uint64(127): ContextKernel, ^uint64(511): ContextUser,
		^uint64(2047): ContextGuest, ^uint64(2175): ContextGuestKernel, ^uint64(2559): ContextGuestUser,
	} {
		if got, ok := callchainMarker(ip); !ok || got != want {
			t.Errorf("marker %#x: %q %v", ip, got, ok)
		}
	}
	for _, ip := range []uint64{0, 1, 0x1000, ^uint64(0), ^uint64(32), ^uint64(128), ^uint64(512), ^uint64(2048), ^uint64(2176), ^uint64(2560), ^uint64(4094)} {
		if got, ok := callchainMarker(ip); ok {
			t.Errorf("non-marker %#x classified %q", ip, got)
		}
	}
	for _, ip := range []uint64{0, 1 << 56, 1 << 63, ^uint64(0)} {
		if safeUserIP(ip) {
			t.Errorf("unsafe IP %#x accepted", ip)
		}
	}
	if !safeUserIP(1) || !safeUserIP(1<<56-1) {
		t.Error("edge safe IPs refused")
	}
	user, kernel, guestUser := ^uint64(511), ^uint64(127), ^uint64(2559)
	ips := func(s CPUSample) []uint64 {
		var out []uint64
		for _, f := range s.Callchain {
			if f.IP != 0 {
				out = append(out, uint64(f.IP))
			}
		}
		return out
	}
	contexts := func(s CPUSample) []CallchainContext {
		var out []CallchainContext
		for _, f := range s.Callchain {
			if f.IP == 0 {
				out = append(out, f.Context)
			}
		}
		return out
	}
	// Frames inside a kernel context are never exported, and the chain is marked unresolved; user context resumes.
	s := decodeOK(t, "kernel then user", cpuRecord(kernel, 0x5000, user, 0x6000), softCtx)
	if got := ips(s); len(got) != 1 || got[0] != 0x6000 || s.Truncated != ReasonUnresolved {
		t.Errorf("kernel/user: ips %v truncated %q", got, s.Truncated)
	}
	if got := contexts(s); len(got) != 2 || got[0] != ContextKernel || got[1] != ContextUser {
		t.Errorf("markers recorded %v", got)
	}
	// Guest user frames are not user frames of the target.
	s = decodeOK(t, "guest user", cpuRecord(guestUser, 0x5000), softCtx)
	if len(ips(s)) != 0 || s.Truncated != ReasonUnresolved {
		t.Errorf("guest user exported: %v %q", ips(s), s.Truncated)
	}
	// A kernel-space address resets the context: later canonical addresses stay private until a user marker restores it.
	s = decodeOK(t, "context reset", cpuRecord(0x1000, 0xffff800000001234, 0x2000, user, 0x3000), softCtx)
	if got := ips(s); len(got) != 2 || got[0] != 0x1000 || got[1] != 0x3000 || s.Truncated != ReasonUnresolved {
		t.Errorf("context reset: %v %q", got, s.Truncated)
	}
	// A noncanonical (but not kernel-half) address is dropped without ending the user context.
	s = decodeOK(t, "noncanonical", cpuRecord(0x1000, 1<<56, 0x2000), softCtx)
	if got := ips(s); len(got) != 2 || got[1] != 0x2000 || s.Truncated != ReasonUnresolved {
		t.Errorf("noncanonical: %v %q", got, s.Truncated)
	}
	// An address in [2^62, 2^63) is noncanonical but not a kernel-half address: the user context survives it.
	s = decodeOK(t, "high noncanonical", cpuRecord(0x1000, 1<<62, 0x2000), softCtx)
	if got := ips(s); len(got) != 2 || got[1] != 0x2000 {
		t.Errorf("high noncanonical: %v", got)
	}
	// A zero address in a user context is unresolved, not a frame.
	s = decodeOK(t, "zero", cpuRecord(0x1000, 0, 0x2000), softCtx)
	if got := ips(s); len(got) != 2 || s.Truncated != ReasonUnresolved {
		t.Errorf("zero: %v %q", got, s.Truncated)
	}
	// Truncation outranks unresolved.
	s = decodeOK(t, "truncated and unresolved", cpuRecord(0x1000, 0xffff800000001234, 0x2000), DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 2})
	if s.Truncated != ReasonTruncated {
		t.Errorf("precedence: %q", s.Truncated)
	}
	// Only unresolved frames and no marker: nothing exported, still a valid sample.
	s = decodeOK(t, "all kernel", cpuRecord(kernel, 0x1000), softCtx)
	if len(ips(s)) != 0 || s.Truncated != ReasonUnresolved || !s.valid() {
		t.Errorf("all kernel: %+v", s)
	}
	// No callchain at all.
	s = decodeOK(t, "empty", cpuRecord(), softCtx)
	if len(s.Callchain) != 0 || s.Truncated != ReasonMissingCallchain || !s.valid() {
		t.Errorf("empty: %+v", s)
	}
	// Markers occupy callchain slots: a full chain cannot take another marker or frame.
	s = decodeOK(t, "markers fill the chain", cpuRecord(user, 0x1000, user, 0x2000), DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 3})
	if len(s.Callchain) != 3 || s.Truncated != ReasonTruncated {
		t.Errorf("markers: %d entries, %q", len(s.Callchain), s.Truncated)
	}
	s = decodeOK(t, "marker beyond capacity", cpuRecord(0x1000, 0x2000, user, 0x3000), DecodeContext{Method: MethodSoftwareCPUClock, MaxFrames: 2})
	if len(s.Callchain) != 2 || s.Truncated != ReasonTruncated {
		t.Errorf("marker beyond: %d entries, %q", len(s.Callchain), s.Truncated)
	}
}

func lossRecord(typ uint32, words []uint64, trailer bool, ts uint64, cpu, reserved uint32) KernelRecordView {
	n := 8 + 8*len(words)
	if trailer {
		n += 24
	}
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b, typ)
	binary.LittleEndian.PutUint16(b[6:], uint16(n))
	for i, w := range words {
		binary.LittleEndian.PutUint64(b[8+8*i:], w)
	}
	if trailer {
		binary.LittleEndian.PutUint64(b[n-16:], ts)
		binary.LittleEndian.PutUint32(b[n-8:], cpu)
		binary.LittleEndian.PutUint32(b[n-4:], reserved)
	}
	return KernelRecordView{first: b}
}

func TestDecodeCPULossFieldsAndTrailer(t *testing.T) {
	type tc struct {
		name   string
		typ    uint32
		words  []uint64
		reason Reason
		count  uint64
		time   uint64 // timestamp expected when there is no trailer
	}
	for _, c := range []tc{
		{"lost", 2, []uint64{11, 77}, ReasonLoss, 77, 0},
		{"lost samples", 13, []uint64{88}, ReasonSampleLost, 88, 0},
		{"throttle", 5, []uint64{555, 21, 22}, ReasonThrottle, 0, 555},
		{"unthrottle", 6, []uint64{666, 21, 22}, ReasonUnthrottle, 0, 666},
	} {
		loss, ts, e := decodeCPULoss(lossRecord(c.typ, c.words, false, 0, 0, 0))
		if e != nil || loss.Reason != c.reason || uint64(loss.Count) != c.count || uint64(ts) != c.time {
			t.Errorf("%s: %+v ts %d %v", c.name, loss, ts, e)
		}
		if c.typ == 5 || c.typ == 6 {
			if loss.Throttle == nil || loss.Throttle.EventID != 21 || loss.Throttle.StreamID != 22 || loss.Throttle.Reason != c.reason {
				t.Errorf("%s: throttle evidence %+v", c.name, loss.Throttle)
			}
		}
		// With a sample_id trailer the trailer time is used for loss records; throttles keep their own timestamp.
		loss, ts, e = decodeCPULoss(lossRecord(c.typ, c.words, true, 9999, 3, 0))
		want := uint64(9999)
		if c.typ == 5 || c.typ == 6 {
			want = c.time
		}
		if e != nil || uint64(ts) != want || loss.Reason != c.reason {
			t.Errorf("%s with trailer: %+v ts %d %v", c.name, loss, ts, e)
		}
		if _, _, e = decodeCPULoss(lossRecord(c.typ, c.words, true, 9999, 3, 1)); !errors.Is(e, ErrRingMalformed) {
			t.Errorf("%s: nonzero trailer reserved word: %v", c.name, e)
		}
		wrong := lossRecord(c.typ, append(append([]uint64(nil), c.words...), 0), false, 0, 0, 0)
		if _, _, e = decodeCPULoss(wrong); !errors.Is(e, ErrRingMalformed) {
			t.Errorf("%s: record of the wrong size: %v", c.name, e)
		}
	}
	// An empty loss (count 0) is not a loss event.
	if _, _, e := decodeCPULoss(lossRecord(2, []uint64{1, 0}, false, 0, 0, 0)); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("zero lost count: %v", e)
	}
	if _, _, e := decodeCPULoss(lossRecord(13, []uint64{0}, false, 0, 0, 0)); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("zero lost-sample count: %v", e)
	}
	if _, _, e := decodeCPULoss(lossRecord(99, []uint64{1, 2}, false, 0, 0, 0)); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("unknown type: %v", e)
	}
	if _, _, e := decodeCPULoss(KernelRecordView{first: []byte{2, 0, 0, 0}}); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("invalid view: %v", e)
	}
}

func TestDecodeCPURecordDispatch(t *testing.T) {
	task := TaskKey{BootID: "boot", PIDNamespace: 5, TGID: 70, TID: 71, ProcessStart: 1}
	ring := &Ring{task: task, method: MethodSoftwareCPUClock, maxFrames: 128}
	// cpuRecord carries pid 70 / tid 71 at offset 16 and time 123456 / cpu 3.
	ev, ok, e := decodeCPURecord(cpuRecord(0x1000), ring)
	if e != nil || !ok || ev.Kind != EventCPU || uint64(ev.Time) != 123456 || ev.CPU != 3 || ev.Task != task || ev.CPUEvent == nil || uint64(ev.CPUEvent.IP) != 0x1234 {
		t.Fatalf("sample: %+v %v %v", ev, ok, e)
	}
	for name, wrong := range map[string]TaskKey{
		"other tgid": {BootID: "boot", PIDNamespace: 5, TGID: 71, TID: 71},
		"other tid":  {BootID: "boot", PIDNamespace: 5, TGID: 70, TID: 70},
	} {
		if _, ok, e := decodeCPURecord(cpuRecord(0x1000), &Ring{task: wrong, method: MethodSoftwareCPUClock, maxFrames: 128}); ok || !errors.Is(e, ErrTargetIdentity) {
			t.Errorf("%s: %v %v", name, ok, e)
		}
	}
	if _, ok, e := decodeCPURecord(KernelRecordView{first: []byte{9, 0, 0}}, ring); ok || !errors.Is(e, ErrRingMalformed) {
		t.Errorf("invalid view: %v %v", ok, e)
	}
	// Loss records carry the trailer: time at len-16, CPU at len-8.
	for _, c := range []struct {
		typ   uint32
		words []uint64
		kind  Reason
	}{{2, []uint64{1, 5}, ReasonLoss}, {13, []uint64{5}, ReasonSampleLost}, {5, []uint64{50, 1, 2}, ReasonThrottle}, {6, []uint64{50, 1, 2}, ReasonUnthrottle}} {
		ev, ok, e := decodeCPURecord(lossRecord(c.typ, c.words, true, 4242, 6, 0), ring)
		wantTime := uint64(4242)
		if c.typ == 5 || c.typ == 6 {
			wantTime = 50
		}
		if e != nil || !ok || ev.Kind != EventLoss || ev.Loss == nil || ev.Loss.Reason != c.kind || ev.CPU != 6 || uint64(ev.Time) != wantTime {
			t.Errorf("loss type %d: %+v %v %v", c.typ, ev, ok, e)
		}
		if _, ok, e := decodeCPURecord(lossRecord(c.typ, c.words, false, 0, 0, 0), ring); ok || !errors.Is(e, ErrRingMalformed) {
			t.Errorf("loss type %d without trailer: %v %v", c.typ, ok, e)
		}
		if _, ok, e := decodeCPURecord(lossRecord(c.typ, append(append([]uint64(nil), c.words...), 0), true, 0, 0, 0), ring); ok || !errors.Is(e, ErrRingMalformed) {
			t.Errorf("loss type %d oversized: %v %v", c.typ, ok, e)
		}
	}
	comm := func(n int, misc uint16) KernelRecordView {
		b := make([]byte, n)
		binary.LittleEndian.PutUint32(b, perfRecordComm)
		binary.LittleEndian.PutUint16(b[4:], misc)
		binary.LittleEndian.PutUint16(b[6:], uint16(n))
		return KernelRecordView{first: b}
	}
	if _, ok, e := decodeCPURecord(comm(48, 0), ring); ok || e != nil {
		t.Errorf("comm: %v %v", ok, e)
	}
	if _, ok, e := decodeCPURecord(comm(41, 0), ring); ok || e != nil {
		t.Errorf("minimal comm: %v %v", ok, e)
	}
	if _, ok, e := decodeCPURecord(comm(40, 0), ring); ok || !errors.Is(e, ErrRingMalformed) {
		t.Errorf("short comm: %v %v", ok, e)
	}
	if _, ok, e := decodeCPURecord(comm(48, 1<<13), ring); ok || !errors.Is(e, ErrTargetIdentity) {
		t.Errorf("exec comm: %v %v", ok, e)
	}
	if _, ok, e := decodeCPURecord(comm(48, 1<<12|1<<14), ring); ok || e != nil {
		t.Errorf("neighbouring misc bits treated as exec: %v %v", ok, e)
	}
	forkExit := func(typ uint32, n int) KernelRecordView {
		b := make([]byte, n)
		binary.LittleEndian.PutUint32(b, typ)
		binary.LittleEndian.PutUint16(b[6:], uint16(n))
		return KernelRecordView{first: b}
	}
	for _, typ := range []uint32{perfRecordFork, perfRecordExit} {
		if _, ok, e := decodeCPURecord(forkExit(typ, 56), ring); ok || !errors.Is(e, ErrThreadCoverageChanged) {
			t.Errorf("type %d: %v %v", typ, ok, e)
		}
		for _, n := range []int{48, 64} {
			if _, ok, e := decodeCPURecord(forkExit(typ, n), ring); ok || !errors.Is(e, ErrRingMalformed) {
				t.Errorf("type %d size %d: %v %v", typ, n, ok, e)
			}
		}
	}
	if _, ok, e := decodeCPURecord(forkExit(1, 24), ring); ok || !errors.Is(e, ErrRingMalformed) {
		t.Errorf("unknown record type: %v %v", ok, e)
	}
}

func ringWithMeta(data []byte, tail, head uint64) *Ring {
	meta := make([]byte, 4096)
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&meta[1032])), tail)
	atomic.StoreUint64((*uint64)(unsafe.Pointer(&meta[1024])), head)
	return &Ring{meta: meta, data: data}
}

func TestRingConsumeBoundaries(t *testing.T) {
	record := func(size int) []byte {
		b := make([]byte, size)
		binary.LittleEndian.PutUint16(b[6:], uint16(size))
		for i := 8; i < size; i++ {
			b[i] = byte(i)
		}
		return b
	}
	consume := func(r *Ring) (KernelRecordView, int, error) {
		var got KernelRecordView
		calls := 0
		e := r.consume(func(v KernelRecordView) error { got = v; calls++; return nil })
		return got, calls, e
	}
	// A record filling the whole data area, and one of the minimum size 8, are both valid.
	r := ringWithMeta(make([]byte, 64), 0, 64)
	copy(r.data, record(64))
	if v, n, e := consume(r); e != nil || n != 1 || v.len() != 64 || r.tail() != 64 {
		t.Errorf("full-ring record: %v calls %d len %d tail %d", e, n, v.len(), r.tail())
	}
	r = ringWithMeta(make([]byte, 64), 0, 8)
	copy(r.data, record(8))
	if v, n, e := consume(r); e != nil || n != 1 || v.len() != 8 || r.tail() != 8 {
		t.Errorf("8-byte record: %v calls %d len %d", e, n, v.len())
	}
	// One byte more outstanding than the data area is an overwrite; empty is a no-op.
	r = ringWithMeta(make([]byte, 64), 0, 65)
	if _, n, e := consume(r); !errors.Is(e, ErrRingOverwrite) || n != 0 {
		t.Errorf("overwrite: %v", e)
	}
	r = ringWithMeta(make([]byte, 64), 5, 5)
	if _, n, e := consume(r); e != nil || n != 0 || r.tail() != 5 {
		t.Errorf("empty: %v", e)
	}
	// Fewer than 8 bytes outstanding is a partial header; exactly 8 with a bigger size field is a partial record.
	r = ringWithMeta(make([]byte, 64), 0, 7)
	if _, n, e := consume(r); !errors.Is(e, ErrRingMalformed) || n != 0 {
		t.Errorf("7 bytes: %v", e)
	}
	r = ringWithMeta(make([]byte, 64), 0, 8)
	binary.LittleEndian.PutUint16(r.data[6:], 9)
	if _, n, e := consume(r); !errors.Is(e, ErrRingMalformed) || n != 0 || r.tail() != 0 {
		t.Errorf("size beyond available by one: %v", e)
	}
	// A record claiming more than the data area but less than available cannot exist (available <= len(data)); size 8 is the floor.
	r = ringWithMeta(make([]byte, 64), 0, 16)
	binary.LittleEndian.PutUint16(r.data[6:], 7)
	if _, n, e := consume(r); !errors.Is(e, ErrRingMalformed) || n != 0 {
		t.Errorf("size 7: %v", e)
	}
	// Metadata page or data area missing.
	if _, _, e := consume(&Ring{meta: make([]byte, 1039), data: make([]byte, 64)}); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("short metadata: %v", e)
	}
	if _, _, e := consume(&Ring{meta: make([]byte, 1040), data: nil}); !errors.Is(e, ErrRingMalformed) {
		t.Errorf("no data area: %v", e)
	}
	// A record ending exactly at the end of the data area is a single contiguous slice; one that crosses is split with the right bytes.
	r = ringWithMeta(make([]byte, 64), 56, 64)
	copy(r.data[56:], record(8))
	if v, _, e := consume(r); e != nil || len(v.second) != 0 || len(v.first) != 8 || r.tail() != 64 {
		t.Errorf("record ending at the boundary: %v first %d second %d", e, len(v.first), len(v.second))
	}
	full := record(24)
	r = ringWithMeta(make([]byte, 64), 56, 80)
	copy(r.data[56:], full[:8])
	copy(r.data[:16], full[8:])
	v, _, e := consume(r)
	if e != nil || len(v.first) != 8 || len(v.second) != 16 || r.tail() != 80 {
		t.Fatalf("wrapped record: %v first %d second %d tail %d", e, len(v.first), len(v.second), r.tail())
	}
	for i := range full {
		if v.byteAt(i) != full[i] {
			t.Fatalf("byte %d of the wrapped record: %d != %d", i, v.byteAt(i), full[i])
		}
	}
	// The header itself straddles the end of the data area.
	r = ringWithMeta(make([]byte, 64), 61, 61+16)
	rec := record(16)
	for i, b := range rec {
		r.data[(61+i)%64] = b
	}
	if v, _, e := consume(r); e != nil || v.len() != 16 || v.u16(6) != 16 || r.tail() != 77 {
		t.Errorf("header across the wrap: %v len %d", e, v.len())
	}
	// A closed ring refuses and a double close is harmless.
	r = ringWithMeta(make([]byte, 64), 0, 0)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, _, e := consume(r); !errors.Is(e, ErrAcquisitionClosed) {
		t.Errorf("closed ring: %v", e)
	}
}

func TestDrainRingSkipsIgnoredRecordsAndReportsEvents(t *testing.T) {
	task := TaskKey{BootID: "boot", PIDNamespace: 5, TGID: 70, TID: 71}
	data := make([]byte, 256)
	sample := cpuRecord(0x1000).first
	r := ringWithMeta(data, 0, uint64(len(sample)))
	copy(data, sample)
	r.task, r.method, r.maxFrames = task, MethodSoftwareCPUClock, 128
	var got []SanitizedEvent
	if e := drainRing(r, func(ev SanitizedEvent) error { got = append(got, ev); return nil }); e != nil || len(got) != 1 || got[0].Kind != EventCPU {
		t.Fatalf("sample: %v %v", e, got)
	}
	if r.tail() != uint64(len(sample)) {
		t.Fatal("tail not published after the event was emitted")
	}
	// A comm record is consumed (tail advances) without producing an event.
	comm := make([]byte, 48)
	binary.LittleEndian.PutUint32(comm, perfRecordComm)
	binary.LittleEndian.PutUint16(comm[6:], 48)
	r = ringWithMeta(make([]byte, 256), 0, 48)
	copy(r.data, comm)
	r.task, r.method, r.maxFrames = task, MethodSoftwareCPUClock, 128
	got = nil
	if e := drainRing(r, func(ev SanitizedEvent) error { got = append(got, ev); return nil }); e != nil || len(got) != 0 || r.tail() != 48 {
		t.Fatalf("comm: %v events %d tail %d", e, len(got), r.tail())
	}
	// A failing emit keeps the record borrowed.
	r = ringWithMeta(make([]byte, 256), 0, uint64(len(sample)))
	copy(r.data, sample)
	r.task, r.method, r.maxFrames = task, MethodSoftwareCPUClock, 128
	stop := errors.New("stop")
	if e := drainRing(r, func(SanitizedEvent) error { return stop }); e != stop || r.tail() != 0 {
		t.Fatalf("emit failure: %v tail %d", e, r.tail())
	}
}
