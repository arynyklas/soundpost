//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Boundary tests of the scheduler allowlist decoder (sanitize_linux.go) and the trace-format parser
// (traceformat_linux.go), written against the survivors of the 04.04-C18 mutation battery
// (l4w29-evidence/nativekernel/mutate_sanitize.py): every guard is exercised by a record that violates THAT guard only,
// so a second guard cannot hide the removal of the first.

// schedRec builds one perf sample record of the fixed scheduler ABI (TID TIME CALLCHAIN CPU RAW) as the kernel writes it.
type schedRec struct {
	typ       uint32
	reserved  uint32
	cpu       uint32
	time      uint64
	ips       []uint64
	count     int    // callchain count field; -1 = len(ips)
	rawSize   uint32 // bytes of raw data that exist
	sizeField uint32 // raw size field; 0 = rawSize
	pad       int
	truncate  int // total length override; 0 = natural
	size      int // header size field; 0 = total length
	u32       map[int]uint32
	state     uint64
}

func newSwitchRec(prev, next uint32, state uint64) schedRec {
	return schedRec{typ: perfRecordSample, cpu: 3, time: 5_000, count: -1, rawSize: 60, state: state, u32: map[int]uint32{24: prev, 56: next}}
}

func newWakeRec(pid, targetCPU uint32) schedRec {
	return schedRec{typ: perfRecordSample, cpu: 3, time: 5_000, count: -1, rawSize: 36, u32: map[int]uint32{24: pid, 32: targetCPU}}
}

func (r schedRec) bytes() []byte {
	raw := 44 + 8*len(r.ips)
	n := raw + int(r.rawSize) + r.pad
	if r.truncate > 0 {
		n = r.truncate
	}
	scratch := make([]byte, raw+int(r.rawSize)+r.pad+128)
	le := binary.LittleEndian
	le.PutUint32(scratch, r.typ)
	size := r.size
	if size == 0 {
		size = n
	}
	le.PutUint16(scratch[6:], uint16(size))
	le.PutUint64(scratch[16:], r.time)
	le.PutUint32(scratch[24:], r.cpu)
	le.PutUint32(scratch[28:], r.reserved)
	count := r.count
	if count < 0 {
		count = len(r.ips)
	}
	le.PutUint64(scratch[32:], uint64(count))
	for i, ip := range r.ips {
		le.PutUint64(scratch[40+8*i:], ip)
	}
	field := r.sizeField
	if field == 0 {
		field = r.rawSize
	}
	le.PutUint32(scratch[raw-4:], field)
	for off, v := range r.u32 {
		le.PutUint32(scratch[raw+off:], v)
	}
	if r.rawSize == 60 {
		le.PutUint64(scratch[raw+32:], r.state) // sched_switch prev_state
	}
	return scratch[:n]
}

func schedLayout(t *testing.T, kind SchedulerKind, kernel string) NumericLayout {
	t.Helper()
	l, e := parseTraceFormat(kind, schedulerFormat(kind))
	if e != nil {
		t.Fatal(e)
	}
	l.kernel = kernel
	return l
}

func schedAuth(tids ...uint32) AuthorizedTargets {
	var a AuthorizedTargets
	for _, tid := range tids {
		a.schedulerTasks = append(a.schedulerTasks, cpuThread{task: TaskKey{BootID: "b", PIDNamespace: 1, TGID: 7, TID: tid, ProcessStart: 1, Generation: 1}})
	}
	return a
}

func decodeSched(l NumericLayout, r schedRec, a AuthorizedTargets) (SanitizedEvent, bool, error) {
	return decodeScheduler(KernelRecordView{first: r.bytes()}, l, a)
}

func TestSchedulerDecodeRefusesEachMalformedRecordByItsOwnGuard(t *testing.T) {
	l := schedLayout(t, SchedulerSwitchKind, "6.6")
	a := schedAuth(7)
	if _, ok, e := decodeSched(l, newSwitchRec(7, 999, 1), a); e != nil || !ok {
		t.Fatalf("the unmutated record is refused: %v %v", ok, e)
	}
	base := newSwitchRec(7, 999, 1)
	cases := []struct {
		name string
		edit func(r *schedRec)
	}{
		{"header size field differs from the record length", func(r *schedRec) { r.size = len(r.bytes()) - 8 }},
		{"not a sample record", func(r *schedRec) { r.typ = perfRecordSample + 1 }},
		{"record shorter than the fixed header (40 bytes)", func(r *schedRec) { r.truncate = 40 }},
		{"record one byte short of the fixed header (43 bytes)", func(r *schedRec) { r.truncate = 43 }},
		{"reserved word set", func(r *schedRec) { r.reserved = 1 }},
		{"129 callchain entries", func(r *schedRec) { r.ips = make([]uint64, 129) }},
		{"callchain count one more than fits", func(r *schedRec) { r.count = (len(r.bytes())-44)/8 + 1 }},
		{"raw size field 4", func(r *schedRec) { r.sizeField = 4; r.rawSize = 4 }},
		{"raw size field one below the layout", func(r *schedRec) { r.sizeField = 59; r.rawSize = 59; r.pad = 1 }},
		{"raw size field one below the layout, no padding", func(r *schedRec) { r.sizeField = 59; r.rawSize = 59 }},
		{"raw size field one past the record", func(r *schedRec) { r.sizeField = 61 }},
		{"eight bytes of trailing padding", func(r *schedRec) { r.pad = 8 }},
	}
	for _, c := range cases {
		r := base
		r.u32 = map[int]uint32{24: 7, 56: 999}
		c.edit(&r)
		_, ok, e := decodeSched(l, r, a)
		if ok || !errors.Is(e, ErrRingMalformed) {
			t.Errorf("%s: ok=%v err=%v, want ErrRingMalformed", c.name, ok, e)
		}
	}
}

func TestSchedulerDecodeAcceptsTheLargestWellFormedRecords(t *testing.T) {
	l := schedLayout(t, SchedulerSwitchKind, "6.6")
	a := schedAuth(7)
	r := newSwitchRec(7, 999, 1)
	r.ips = make([]uint64, 128)
	if _, ok, e := decodeSched(l, r, a); e != nil || !ok {
		t.Errorf("128 callchain entries: %v %v", ok, e)
	}
	r = newSwitchRec(7, 999, 1)
	r.pad = 7
	if _, ok, e := decodeSched(l, r, a); e != nil || !ok {
		t.Errorf("seven bytes of padding: %v %v", ok, e)
	}
}

func TestSchedulerDecodeTaskAllowlist(t *testing.T) {
	l := schedLayout(t, SchedulerSwitchKind, "6.6")
	// a switch between tasks nobody authorized is no event
	if _, ok, e := decodeSched(l, newSwitchRec(11, 12, 1), schedAuth(7)); ok || e != nil {
		t.Errorf("foreign switch: ok=%v err=%v", ok, e)
	}
	// the idle task (pid 0) and a pid above the positive int32 range are never tasks, even when "authorized"
	if _, ok, e := decodeSched(l, newSwitchRec(0, 0, 1), schedAuth(0)); ok || e != nil {
		t.Errorf("pid 0: ok=%v err=%v", ok, e)
	}
	if _, ok, e := decodeSched(l, newSwitchRec(1<<31, 1<<31, 1), schedAuth(1<<31)); ok || e != nil {
		t.Errorf("pid 2^31: ok=%v err=%v", ok, e)
	}
	if _, ok, e := decodeSched(l, newSwitchRec(1<<31-1, 1<<31-1, 1), schedAuth(1<<31-1)); !ok || e != nil {
		t.Errorf("pid 2^31-1: ok=%v err=%v", ok, e)
	}
	// authorization is by TID, not by the thread group
	a := schedAuth(7)
	a.schedulerTasks[0].task.TGID = 11
	if _, ok, _ := decodeSched(l, newSwitchRec(11, 12, 1), a); ok {
		t.Errorf("a TGID was matched as a TID")
	}
	// previous and next are read from their own slots
	ev, ok, e := decodeSched(l, newSwitchRec(11, 7, 1), schedAuth(7))
	if e != nil || !ok || ev.Switch.Previous != nil || ev.Switch.Next == nil || ev.Switch.Next.TID != 7 {
		t.Errorf("next-only switch: %+v %v %v", ev.Switch, ok, e)
	}
}

func TestSchedulerDecodeCarriesTimeCPUAndPreviousState(t *testing.T) {
	l := schedLayout(t, SchedulerSwitchKind, "6.6")
	r := newSwitchRec(7, 999, 0x101)
	r.time, r.cpu = 123_456_789, 5
	ev, ok, e := decodeSched(l, r, schedAuth(7))
	if e != nil || !ok || uint64(ev.Time) != 123_456_789 || ev.CPU != 5 || ev.Kind != EventSwitch {
		t.Fatalf("event %+v %v %v", ev, ok, e)
	}
	if uint64(ev.Switch.PreviousState) != 0x101 {
		t.Errorf("previous state %#x was not carried whole", uint64(ev.Switch.PreviousState))
	}
	if !ev.Switch.PreviousStateUnknown || ev.Switch.Preempted {
		t.Errorf("0x101 is neither a known report state nor preemption: %+v", ev.Switch)
	}
}

func TestSchedulerStateIsUnknownOnAKernelWithoutAStateTable(t *testing.T) {
	for _, kernel := range []string{"", "5.15", "6.12", "6.10"} {
		l := schedLayout(t, SchedulerSwitchKind, kernel)
		ev, ok, e := decodeSched(l, newSwitchRec(7, 999, 1), schedAuth(7))
		if e != nil || !ok || !ev.Switch.PreviousStateUnknown {
			t.Errorf("kernel %q: state of a sleeping task claimed known: %+v %v %v", kernel, ev.Switch, ok, e)
		}
	}
	for _, kernel := range []string{"6.1", "6.6"} {
		l := schedLayout(t, SchedulerSwitchKind, kernel)
		ev, _, _ := decodeSched(l, newSwitchRec(7, 999, 1), schedAuth(7))
		if ev.Switch.PreviousStateUnknown {
			t.Errorf("kernel %q: a plain sleep state is unknown", kernel)
		}
	}
}

func TestSchedulerDecodeSwitchOutCallchainRules(t *testing.T) {
	user, kernel := ^uint64(511), ^uint64(127)
	decode := func(maxFrames uint16, ips ...uint64) SchedulerSwitch {
		t.Helper()
		l := schedLayout(t, SchedulerSwitchKind, "6.6")
		l.maxFrames = maxFrames
		r := newSwitchRec(7, 999, 1)
		r.ips = ips
		ev, ok, e := decodeSched(l, r, schedAuth(7))
		if e != nil || !ok {
			t.Fatalf("decode %v %v", ok, e)
		}
		return *ev.Switch
	}
	// a chain that never names its context is kernel context: nothing of it is a user frame
	if s := decode(0, 0x1234); len(s.SwitchOutCallchain) != 0 || s.MissingCallchain != ReasonMissingSwitchCallchain {
		t.Errorf("unmarked chain: %+v", s)
	}
	// user frames carry the address only, never a context label
	s := decode(0, user, 0x1234, 0x2345)
	if len(s.SwitchOutCallchain) != 2 || s.SwitchOutCallchain[0].IP != 0x1234 || s.SwitchOutCallchain[1].IP != 0x2345 || s.SwitchOutCallchain[0].Context != "" || s.MissingCallchain != "" {
		t.Errorf("user chain: %+v", s)
	}
	// an address that cannot be a user frame is unresolved, not a frame
	for name, bad := range map[string]uint64{"zero": 0, "2^56": 1 << 56, "kernel half": 1 << 63} {
		s := decode(0, user, 0x1234, bad)
		if len(s.SwitchOutCallchain) != 1 || s.MissingCallchain != ReasonUnresolved {
			t.Errorf("%s address in a user chain: %+v", name, s)
		}
	}
	// a kernel chain after the user one ends it
	if s := decode(0, user, 0x1234, kernel, 0x5555); len(s.SwitchOutCallchain) != 1 {
		t.Errorf("kernel marker did not end the user frames: %+v", s)
	}
	// the default limit is 127: a chain that fills it is truncated, one entry less is not
	full := []uint64{user}
	for i := range 126 {
		full = append(full, 0x1000+uint64(i))
	}
	if s := decode(0, full...); len(s.SwitchOutCallchain) != 126 || s.MissingCallchain != ReasonTruncated {
		t.Errorf("127 entries at the default limit: %d frames, %q", len(s.SwitchOutCallchain), s.MissingCallchain)
	}
	if s := decode(0, full[:len(full)-1]...); len(s.SwitchOutCallchain) != 125 || s.MissingCallchain != "" {
		t.Errorf("126 entries at the default limit: %d frames, %q", len(s.SwitchOutCallchain), s.MissingCallchain)
	}
	// a configured limit is exact: frames beyond it are dropped and the chain says so
	if s := decode(2, user, 1, 2, 3); len(s.SwitchOutCallchain) != 2 || s.MissingCallchain != ReasonTruncated {
		t.Errorf("limit 2 over 3 frames: %d frames, %q", len(s.SwitchOutCallchain), s.MissingCallchain)
	}
	if s := decode(5, user, 1, 2, 3); len(s.SwitchOutCallchain) != 3 || s.MissingCallchain != "" {
		t.Errorf("limit 5 over a count of 4: %d frames, %q", len(s.SwitchOutCallchain), s.MissingCallchain)
	}
	// the count (marker included) reaching the limit is already reported truncated: nothing proves nothing was cut
	if s := decode(4, user, 1, 2, 3); len(s.SwitchOutCallchain) != 3 || s.MissingCallchain != ReasonTruncated {
		t.Errorf("a count equal to the limit: %d frames, %q", len(s.SwitchOutCallchain), s.MissingCallchain)
	}
	if s := decode(4, user, 1, 2, 3, 4); len(s.SwitchOutCallchain) != 4 || s.MissingCallchain != ReasonTruncated {
		t.Errorf("limit 4 over 4 frames: %d frames, %q", len(s.SwitchOutCallchain), s.MissingCallchain)
	}
}

func TestSchedulerDecodeWakeupSlots(t *testing.T) {
	for _, kind := range []SchedulerKind{SchedulerWakeupKind, SchedulerWakeupNewKind} {
		l := schedLayout(t, kind, "6.6")
		r := newWakeRec(7, 5)
		r.time, r.cpu = 777, 2
		ev, ok, e := decodeSched(l, r, schedAuth(7))
		if e != nil || !ok || ev.Kind != EventWakeup || ev.Wakeup == nil || ev.Wakeup.TargetCPU != 5 || ev.Wakeup.Target.TID != 7 || ev.Task.TID != 7 || uint64(ev.Time) != 777 || ev.CPU != 2 {
			t.Errorf("%s: %+v %v %v", kind, ev, ok, e)
		}
		// pid and target_cpu are read from their own slots
		if _, ok, _ := decodeSched(l, newWakeRec(5, 7), schedAuth(7)); ok {
			t.Errorf("%s: the target CPU was taken for the pid", kind)
		}
		// the target CPU is a positive int32 or the record is malformed
		if _, ok, e := decodeSched(l, newWakeRec(7, 1<<31), schedAuth(7)); ok || !errors.Is(e, ErrRingMalformed) {
			t.Errorf("%s: target CPU 2^31: ok=%v err=%v", kind, ok, e)
		}
		if _, ok, e := decodeSched(l, newWakeRec(7, 1<<31-1), schedAuth(7)); !ok || e != nil {
			t.Errorf("%s: target CPU 2^31-1: ok=%v err=%v", kind, ok, e)
		}
		// a wakeup of somebody else is no event
		if _, ok, e := decodeSched(l, newWakeRec(11, 1), schedAuth(7)); ok || e != nil {
			t.Errorf("%s: foreign wakeup: ok=%v err=%v", kind, ok, e)
		}
		// the raw-size guard of the wakeup layout
		short := newWakeRec(7, 1)
		short.sizeField, short.rawSize, short.pad = 35, 35, 1
		if _, ok, e := decodeSched(l, short, schedAuth(7)); ok || !errors.Is(e, ErrRingMalformed) {
			t.Errorf("%s: raw size 35: ok=%v err=%v", kind, ok, e)
		}
	}
}

func TestSchedulerDecodeRefusesAnUnknownLayoutKind(t *testing.T) {
	l := schedLayout(t, SchedulerSwitchKind, "6.6")
	l.kind = "sched_other"
	if _, ok, e := decodeSched(l, newSwitchRec(7, 999, 1), schedAuth(7)); ok || !errors.Is(e, ErrInvalid) {
		t.Errorf("unknown layout kind: ok=%v err=%v", ok, e)
	}
}

func TestTraceFormatIsStrictAboutEveryLineItReads(t *testing.T) {
	base := string(schedulerFormat(SchedulerSwitchKind))
	prevLine := " field:pid_t prev_pid; offset:24; size:4; signed:1;\n"
	nextLine := " field:pid_t next_pid; offset:56; size:4; signed:1;\n"
	if !strings.Contains(base, prevLine) || !strings.Contains(base, nextLine) {
		t.Fatal("fixture format drifted")
	}
	cases := []struct {
		name   string
		format string
	}{
		{"second name line", base + "name: sched_switch\n"},
		{"name of another event", strings.Replace(base, "name: sched_switch", "name: sched_wakeup", 1)},
		{"no name line", strings.Replace(base, "name: sched_switch\n", "", 1)},
		{"second ID line", base + "ID: 3\n"},
		{"ID 0 then a valid ID", strings.Replace(base, "ID: 1\n", "ID: 0\nID: 5\n", 1)},
		{"ID beyond uint64", strings.Replace(base, "ID: 1\n", "ID: 99999999999999999999999\n", 1)},
		{"ID beyond uint32", strings.Replace(base, "ID: 1\n", "ID: 4294967296\n", 1)},
		{"ID not a number", strings.Replace(base, "ID: 1\n", "ID: x\n", 1)},
		{"ID 0", strings.Replace(base, "ID: 1\n", "ID: 0\n", 1)},
		{"no ID line", strings.Replace(base, "ID: 1\n", "", 1)},
		{"field line with four parts", strings.Replace(base, prevLine, " field:pid_t prev_pid; offset:24; size:4; signed:1\n", 1)},
		{"field declaration of one word", base + " field:weird; offset:0; size:1; signed:0;\n"},
		{"duplicate wanted field", base + prevLine},
		{"numbers without their keys", strings.Replace(base, prevLine, " field:pid_t prev_pid; 24; 4; 1;\n", 1)},
		{"keys out of order", strings.Replace(base, prevLine, " field:pid_t prev_pid; size:4; offset:24; signed:1;\n", 1)},
		{"offset not a number", strings.Replace(base, "offset:24", "offset:x", 1)},
		{"wrong offset", strings.Replace(base, "offset:24", "offset:28", 1)},
		{"wrong size", strings.Replace(base, "pid_t prev_pid; offset:24; size:4", "pid_t prev_pid; offset:24; size:8", 1)},
		{"unsigned", strings.Replace(base, "pid_t prev_pid; offset:24; size:4; signed:1", "pid_t prev_pid; offset:24; size:4; signed:0", 1)},
		{"missing wanted field", strings.Replace(base, nextLine, "", 1)},
		{"longer than 65536 bytes", base + strings.Repeat(" ", 65537-len(base))},
	}
	for _, c := range cases {
		if _, e := parseTraceFormat(SchedulerSwitchKind, []byte(c.format)); !errors.Is(e, ErrInvalid) {
			t.Errorf("%s: accepted (err %v)", c.name, e)
		}
	}
	// the boundary itself and unrelated well-formed fields are accepted
	if _, e := parseTraceFormat(SchedulerSwitchKind, []byte(base+strings.Repeat(" ", 65536-len(base)))); e != nil {
		t.Errorf("exactly 65536 bytes: %v", e)
	}
	if _, e := parseTraceFormat(SchedulerSwitchKind, []byte(base+" field:int other; offset:64; size:4; signed:1;\n")); e != nil {
		t.Errorf("an unrelated field: %v", e)
	}
	if _, e := parseTraceFormat(SchedulerSwitchKind, nil); !errors.Is(e, ErrInvalid) {
		t.Errorf("empty metadata: %v", e)
	}
}

func TestTraceFormatReadsEveryFieldIntoItsOwnSlot(t *testing.T) {
	l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil || l.prev != (numericField{24, 4}) || l.next != (numericField{56, 4}) || l.state != (numericField{32, 8}) || l.rawSize != 60 || l.id != 1 || l.kind != SchedulerSwitchKind {
		t.Fatalf("switch layout %+v %v", l, e)
	}
	for _, kind := range []SchedulerKind{SchedulerWakeupKind, SchedulerWakeupNewKind} {
		w, e := parseTraceFormat(kind, schedulerFormat(kind))
		if e != nil || w.pid != (numericField{24, 4}) || w.cpu != (numericField{32, 4}) || w.rawSize != 36 || w.id != 2 || w.kind != kind {
			t.Fatalf("%s layout %+v %v", kind, w, e)
		}
	}
	if _, e := parseTraceFormat("bogus", []byte("name: bogus\nID: 3\nformat:\n")); !errors.Is(e, ErrInvalid) {
		t.Errorf("an event kind the decoder does not know: %v", e)
	}
}
