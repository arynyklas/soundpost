//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func schedulerFormat(kind SchedulerKind) []byte {
	if kind == SchedulerSwitchKind {
		return []byte("name: sched_switch\nID: 1\nformat:\n field:unsigned short common_type; offset:0; size:2; signed:0;\n field:char prev_comm[16]; offset:8; size:16; signed:1;\n field:pid_t prev_pid; offset:24; size:4; signed:1;\n field:long prev_state; offset:32; size:8; signed:1;\n field:char next_comm[16]; offset:40; size:16; signed:1;\n field:pid_t next_pid; offset:56; size:4; signed:1;\n")
	}
	return []byte("name: " + string(kind) + "\nID: 2\nformat:\n field:char comm[16]; offset:8; size:16; signed:1;\n field:pid_t pid; offset:24; size:4; signed:1;\n field:int target_cpu; offset:32; size:4; signed:1;\n")
}
func TestTraceFormat(t *testing.T) {
	for _, kernel := range []string{"6.1", "6.6"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(kernel+arch, func(t *testing.T) {
				l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
				if e != nil || l.prev.offset != 24 {
					t.Fatal(l, e)
				}
			})
		}
	}
	for _, pair := range [][2]string{{"offset:24", "offset:32"}, {"size:4; signed:1", "size:8; signed:1"}, {"pid_t prev_pid", "char prev_pid"}, {"size:8; signed:1", "size:8; signed:0"}} {
		b := strings.Replace(string(schedulerFormat(SchedulerSwitchKind)), pair[0], pair[1], 1)
		if _, e := parseTraceFormat(SchedulerSwitchKind, []byte(b)); e == nil {
			t.Fatal("accepted incompatible ABI", pair)
		}
	}
}
func TestSchedulerAllowlist(t *testing.T) {
	l, e := parseTraceFormat(SchedulerSwitchKind, schedulerFormat(SchedulerSwitchKind))
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 104)
	binary.LittleEndian.PutUint32(b, 9)
	binary.LittleEndian.PutUint16(b[6:], 104)
	// Fixed scheduler ABI: TID TIME CPU CALLCHAIN RAW; no raw owned staging.
	binary.LittleEndian.PutUint64(b[16:], 55)
	binary.LittleEndian.PutUint32(b[40:], 60)
	copy(b[52:], "SECRET_PREV_COMM")
	binary.LittleEndian.PutUint32(b[68:], 7)
	binary.LittleEndian.PutUint64(b[76:], 1)
	copy(b[84:], "SECRET_NEXT_COMM")
	binary.LittleEndian.PutUint32(b[100:], 8)
	targets := AuthorizedTargets{}
	key := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	targets.schedulerTasks = []cpuThread{{task: key, start: 1}}
	ev, ok, e := decodeScheduler(KernelRecordView{first: b}, l, targets)
	if e != nil || !ok || ev.Switch.Previous == nil || ev.Switch.Next != nil || ev.Switch.MissingCallchain != ReasonMissingSwitchCallchain {
		t.Fatal(ev, ok, e)
	}
	out, _ := json.Marshal(ev)
	if strings.Contains(string(out), "SECRET") {
		t.Fatal("command escaped")
	}
	if _, _, e = decodeScheduler(KernelRecordView{first: b[:90]}, l, targets); e == nil {
		t.Fatal("short accepted")
	}
}
func TestForeignWakeAuthorization(t *testing.T) {
	l, e := parseTraceFormat(SchedulerWakeupKind, schedulerFormat(SchedulerWakeupKind))
	if e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 80)
	binary.LittleEndian.PutUint32(b, 9)
	binary.LittleEndian.PutUint16(b[6:], 80)
	binary.LittleEndian.PutUint32(b[8:], 999)
	binary.LittleEndian.PutUint32(b[12:], 999)
	binary.LittleEndian.PutUint32(b[40:], 36)
	binary.LittleEndian.PutUint32(b[68:], 7)
	key := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	a := AuthorizedTargets{schedulerTasks: []cpuThread{{task: key, start: 1}}}
	ev, ok, e := decodeScheduler(KernelRecordView{first: b}, l, a)
	if e != nil || !ok || ev.Wakeup.Target != key || ev.Task != key {
		t.Fatal(ev, ok, e)
	}
	binary.LittleEndian.PutUint32(b[68:], 999)
	if _, ok, e = decodeScheduler(KernelRecordView{first: b}, l, a); e != nil || ok {
		t.Fatal(ok, e)
	}
}
