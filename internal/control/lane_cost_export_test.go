// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import "time"

// LaneCost is the cumulative cost of the admission rounds this store proposed (admission_group.go): what the control lane spent.
type LaneCost struct {
	Rounds, Items, PatchBytes uint64
	Build, Propose, Lock      time.Duration
}

// LaneCostForTest reads the counters of the admission rounds (the same the diagnostic build reports as control.round.*).
func (s *Store) LaneCostForTest() LaneCost {
	r := &s.admissionStats
	return LaneCost{
		Rounds: r.attempts.Load(), Items: r.items.Load(), PatchBytes: r.bytes.Load(),
		Build: time.Duration(r.buildNS.Load()), Propose: time.Duration(r.proposeNS.Load()), Lock: time.Duration(r.lockNS.Load()),
	}
}
