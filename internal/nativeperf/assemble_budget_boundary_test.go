// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"testing"
)

// The observation bound of one assembly is exactly 8192, counted on the observations alone (l4w33 mutation battery A,
// second pass). The error that follows tells which check refused: the bound itself, or what comes after it. A stream of
// exactly 8192 observations passes the bound and fails on the mapping event without a mapping behind it; one more
// observation is refused by the bound before anything else is looked at.
func TestAssembleObservationBoundIsExactly8192(t *testing.T) {
	d, _ := assemblyTask()
	events := make([]SanitizedEvent, 0, 8194)
	for i := range 8192 {
		events = append(events, epochSample(uint64(i+1), 300, 0x10040))
	}
	events = append(events, SanitizedEvent{Kind: EventMapping, Time: 5, Domain: d, Sequence: 9000})
	if _, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), epochLimits(d)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("8192 observations and a mapping event without a mapping: %v, want ErrInvalid (past the bound)", err)
	}
	events = append(events[:8192], epochSample(8193, 300, 0x10040), SanitizedEvent{Kind: EventMapping, Time: 5, Domain: d, Sequence: 9000})
	if _, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), epochLimits(d)); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("8193 observations: %v, want ErrResourceBudget (the bound, not the mapping event)", err)
	}
}

// Every mapping event is charged 128 bytes against the assembly's byte bound, besides the 4 KiB of the chunk and the
// 32 KiB of each observation: a bound one byte under that total is refused.
func TestAssembleChargesEveryMappingEvent128Bytes(t *testing.T) {
	d, _ := assemblyTask()
	events := []SanitizedEvent{epochSample(1, 300, 0x10040)}
	for i := range 2000 {
		events = append(events, snapRow(uint64(10+i), 100, 110, uint64(0x10000+i*0x1000), uint64(0x11000+i*0x1000), 0, libA, ""))
	}
	events = append(events, confirm(3000, 100, 110), confirm(3001, 380, 400))
	l := epochLimits(d)
	l.MaxBytes = 4096 + 32<<10 + 2002*128 - 1
	if _, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), l); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("a bound one byte under what 2002 mapping events and one sample cost: %v, want ErrResourceBudget", err)
	}
}
