// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

//go:build soundpost_diag

package storage

import (
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// engineMu is Engine.mu of a diagnostic build: a mutex that counts how long each holder held it and how long each acquirer waited
// (decade histograms from 100 us), and notes the slow ones with the call sites of the holder and of the waiter. Engine.mu is the lock
// every ack of every slot group passes (slotMachine.Apply), so a long hold is a freeze of all admissions (L2w20Admission29).
type engineMu struct {
	mu   sync.Mutex
	at   int64          // the holder's acquire time (ns since epoch); written and read under mu
	site atomic.Uintptr // the holder's call site, read by the waiters
}

// emuSlowHold and emuSlowWait are the thresholds above which a hold or a wait is listed with its call sites.
const (
	emuSlowHold = 50 * time.Millisecond
	emuSlowWait = 100 * time.Millisecond
)

var emuEpoch = time.Now()

func emuNow() int64 { return int64(time.Since(emuEpoch)) }

func emuCaller() uintptr {
	var pc [1]uintptr
	if runtime.Callers(3, pc[:]) == 0 {
		return 0
	}
	return pc[0]
}

// emuStats is the process-wide record of every engineMu (a process runs one engine).
var emuStats struct {
	hold, wait [7]atomic.Int64 // <100us, <1ms, <10ms, <100ms, <1s, <10s, >=10s
	holdNS     atomic.Int64
	maxHoldNS  atomic.Int64
	waitNS     atomic.Int64
	maxWaitNS  atomic.Int64
	mu         sync.Mutex
	slow       [64]emuSlowEvent
	slowN      int
}

type emuSlowEvent struct {
	atMS             int64 // wall clock, unix ms, of the end of the hold or of the wait
	kind             string
	took             time.Duration
	site, holderSite uintptr
}

func emuBucket(d int64) int {
	b := 0
	for lim := int64(100 * time.Microsecond); b < 6 && d >= lim; lim *= 10 {
		b++
	}
	return b
}

func emuNoteMax(m *atomic.Int64, d int64) {
	for old := m.Load(); d > old && !m.CompareAndSwap(old, d); old = m.Load() {
	}
}

func emuNoteSlow(kind string, took int64, site, holder uintptr) {
	emuStats.mu.Lock()
	emuStats.slow[emuStats.slowN%len(emuStats.slow)] = emuSlowEvent{atMS: time.Now().UnixMilli(), kind: kind, took: time.Duration(took), site: site, holderSite: holder}
	emuStats.slowN++
	emuStats.mu.Unlock()
}

func (m *engineMu) acquired(pc uintptr) {
	m.at = emuNow()
	m.site.Store(pc)
}

func (m *engineMu) Lock() {
	if m.mu.TryLock() {
		m.acquired(emuCaller())
		return
	}
	pc := emuCaller()
	holder := m.site.Load()
	t0 := emuNow()
	m.mu.Lock()
	m.acquired(pc)
	w := m.at - t0
	emuStats.wait[emuBucket(w)].Add(1)
	emuStats.waitNS.Add(w)
	emuNoteMax(&emuStats.maxWaitNS, w)
	if time.Duration(w) >= emuSlowWait {
		emuNoteSlow("wait", w, pc, holder)
	}
}

func (m *engineMu) TryLock() bool {
	if !m.mu.TryLock() {
		return false
	}
	m.acquired(emuCaller())
	return true
}

func (m *engineMu) Unlock() {
	held := emuNow() - m.at
	pc := m.site.Load()
	m.mu.Unlock()
	emuStats.hold[emuBucket(held)].Add(1)
	emuStats.holdNS.Add(held)
	emuNoteMax(&emuStats.maxHoldNS, held)
	if time.Duration(held) >= emuSlowHold {
		emuNoteSlow("hold", held, pc, 0)
	}
}

func emuSiteName(pc uintptr) string {
	if pc == 0 {
		return ""
	}
	fr, _ := runtime.CallersFrames([]uintptr{pc}).Next()
	name := fr.Function
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name + ":" + strconv.Itoa(fr.Line)
}

// engineMuReport is the diagnostic endpoint's view: the hold and wait histograms and the most recent slow holds and waits.
func engineMuReport() map[string]any {
	hold, wait := make([]int64, 7), make([]int64, 7)
	for i := range hold {
		hold[i], wait[i] = emuStats.hold[i].Load(), emuStats.wait[i].Load()
	}
	emuStats.mu.Lock()
	n := min(emuStats.slowN, len(emuStats.slow))
	events := make([]emuSlowEvent, 0, n)
	for i := emuStats.slowN - n; i < emuStats.slowN; i++ {
		events = append(events, emuStats.slow[i%len(emuStats.slow)])
	}
	total := emuStats.slowN
	emuStats.mu.Unlock()
	slow := make([]map[string]any, 0, len(events))
	for _, ev := range events {
		slow = append(slow, map[string]any{"at_ms": ev.atMS, "kind": ev.kind, "ms": ev.took.Milliseconds(), "site": emuSiteName(ev.site), "holder_site": emuSiteName(ev.holderSite)})
	}
	return map[string]any{
		"buckets": "<100us,<1ms,<10ms,<100ms,<1s,<10s,>=10s",
		"hold":    hold, "wait": wait,
		"hold_ns": emuStats.holdNS.Load(), "max_hold_ns": emuStats.maxHoldNS.Load(),
		"wait_ns": emuStats.waitNS.Load(), "max_wait_ns": emuStats.maxWaitNS.Load(),
		"slow_total": total, "slow": slow,
	}
}
