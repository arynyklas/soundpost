//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package storage

import "github.com/arynyklas/soundpost/internal/model"

// CloseDataGroupsForDrill closes the replica groups of the given data slots on a running
// replicated engine, as a lost shard looks to the readers of the node: ReadIndex of each closed
// group answers unavailable, so a read that forbids partial results is refused and one that
// allows them is flagged partial. Like SetFaultHook it exists only in builds tagged
// soundpost_faults; the released binary has no way to do it. It returns how many groups it closed.
func (e *Engine) CloseDataGroupsForDrill(slots []int) (int, error) {
	if e.repl == nil {
		return 0, model.Fail(model.Unavailable)
	}
	closed := 0
	for _, slot := range slots {
		if slot < 0 || slot >= len(e.repl.groups) {
			return closed, model.Fail(model.Invalid)
		}
		if err := e.repl.groups[slot].Close(); err != nil {
			return closed, err
		}
		closed++
	}
	return closed, nil
}
