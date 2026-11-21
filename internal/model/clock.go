// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

type ClockDomain struct {
	Host    ID `json:"host"`
	Boot    ID `json:"boot"`
	Runtime ID `json:"runtime"`
}
type TraceClock struct {
	Wall        UnixNano    `json:"wall_ns"`
	Mono        MonoNano    `json:"mono_ns"`
	Domain      ClockDomain `json:"domain"`
	Uncertainty MonoNano    `json:"uncertainty_ns"`
}
