//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"encoding/binary"
	"strconv"
	"strings"
)

type SchedulerKind string

const (
	SchedulerSwitchKind    SchedulerKind = "sched_switch"
	SchedulerWakeupKind    SchedulerKind = "sched_wakeup"
	SchedulerWakeupNewKind SchedulerKind = "sched_wakeup_new"
)

type numericField struct{ offset, size int }

// NumericLayout contains no command strings, raw bytes, or tenant selectors.
// The acquisition supports only little-endian 64-bit Linux 6.1/6.6 layouts.
type NumericLayout struct {
	kind                        SchedulerKind
	prev, next, state, pid, cpu numericField
	rawSize                     int
	kernel                      string
	id                          uint64
	maxFrames                   uint16
}

func parseTraceFormat(kind SchedulerKind, metadata []byte) (NumericLayout, error) {
	l := NumericLayout{kind: kind}
	if len(metadata) == 0 || len(metadata) > 65536 || binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		return l, ErrInvalid
	}
	want := map[string]struct {
		typ       string
		off, size int
	}{}
	switch kind {
	case SchedulerSwitchKind:
		want["prev_pid"] = struct {
			typ       string
			off, size int
		}{"pid_t", 24, 4}
		want["next_pid"] = struct {
			typ       string
			off, size int
		}{"pid_t", 56, 4}
		want["prev_state"] = struct {
			typ       string
			off, size int
		}{"long", 32, 8}
		l.rawSize = 60
	case SchedulerWakeupKind, SchedulerWakeupNewKind:
		want["pid"] = struct {
			typ       string
			off, size int
		}{"pid_t", 24, 4}
		want["target_cpu"] = struct {
			typ       string
			off, size int
		}{"int", 32, 4}
		l.rawSize = 36
	default:
		return l, ErrInvalid
	}
	seen := map[string]bool{}
	named := false
	for _, line := range strings.Split(string(metadata), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name:") {
			if named || strings.TrimSpace(strings.TrimPrefix(line, "name:")) != string(kind) {
				return l, ErrInvalid
			}
			named = true
		}
		if strings.HasPrefix(line, "ID:") {
			id, e := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "ID:")), 10, 32)
			if e != nil || id == 0 || l.id != 0 {
				return l, ErrInvalid
			}
			l.id = id
		}
		if !strings.HasPrefix(line, "field:") {
			continue
		}
		parts := strings.Split(line, ";")
		if len(parts) < 5 {
			return l, ErrInvalid
		}
		decl := strings.Fields(strings.TrimPrefix(parts[0], "field:"))
		if len(decl) < 2 {
			return l, ErrInvalid
		}
		name := decl[len(decl)-1]
		spec, ok := want[name]
		if !ok {
			continue
		}
		if seen[name] || strings.Join(decl[:len(decl)-1], " ") != spec.typ {
			return l, ErrInvalid
		}
		seen[name] = true
		values := [3]int{}
		for n, key := range []string{"offset:", "size:", "signed:"} {
			p := strings.TrimSpace(parts[n+1])
			if !strings.HasPrefix(p, key) {
				return l, ErrInvalid
			}
			v, e := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(p, key)))
			if e != nil {
				return l, ErrInvalid
			}
			values[n] = v
		}
		if values[0] != spec.off || values[1] != spec.size || values[2] != 1 {
			return l, ErrInvalid
		}
		f := numericField{spec.off, spec.size}
		switch name {
		case "prev_pid":
			l.prev = f
		case "next_pid":
			l.next = f
		case "prev_state":
			l.state = f
		case "pid":
			l.pid = f
		case "target_cpu":
			l.cpu = f
		}
	}
	if !named || l.id == 0 || len(seen) != len(want) {
		return l, ErrInvalid
	}
	return l, nil
}
