// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import "sync/atomic"

// appendTimes is where Engine.Append spends its time, summed over the appends of the process (a diagnostic
// build reports it, diag_stats_on.go): atomics only, a few additions per append.
var appendTimes struct {
	appends                   atomic.Uint64
	readNS, checksNS, slotNS  atomic.Uint64 // the slot's ReadIndex; every check before the slot lock; waiting for the slot lock
	proposeNS, proposeMaxNS   atomic.Uint64 // the proposal until it is committed on a quorum and applied here
	ledN, ledNS, fwdN, fwdNS  atomic.Uint64 // the proposals of slots this member led, and of slots it forwarded to the leader
	slotWaitMaxNS             atomic.Uint64
	slotHeldNS, slotHeldMaxNS atomic.Uint64 // the slot lock held (receipt checks, proposal)
}

func addMax(m *atomic.Uint64, v uint64) {
	for {
		cur := m.Load()
		if v <= cur || m.CompareAndSwap(cur, v) {
			return
		}
	}
}
