//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// This file exists only in builds tagged soundpost_faults (the drills and qualification harnesses):
// the released binary is built without the tag, so no consumer of the product can install a fault
// hook (plan 01: store faults injectable only in tests, no consumer-visible bypass).
package storage

// SetFaultHook installs (or, with nil, removes) a fault hook on a running engine: the
// drills and qualification harnesses drive failed syncs, slow applies and refused writes
// through the real engine with it. The hook is consulted at every named injection point
// of the write path, among them the replica journal's "wal_write", "wal_payload_write"
// and "wal_sync" (immediately before the journal write or fsync) and the state machine's
// "before_apply"; the point's work does not start while the hook returns an error, and a
// hook may block to delay it. The hook may be installed or removed at any time,
// concurrently with traffic; it can run under the engine's locks, so it must not call back
// into the Engine.
//
// It is never set by the product's own composition: only a harness that holds the
// Engine installs one, and the engine's own in-package tests keep using the unexported
// field, which takes precedence.
func (e *Engine) SetFaultHook(hook func(point string) error) {
	if hook == nil {
		e.injected.Store(nil)
		return
	}
	e.injected.Store(&hook)
}
