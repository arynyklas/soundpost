// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"testing"
)

// Pins for how AssembleProfile uses the mapping epochs (l4w33 mutation battery A).

// More observations than one assembly takes are refused, and the mapping events are bounded on their own: neither is
// an empty success. A mapping event without a mapping fails the assembly even behind a sample.
func TestAssembleRefusesWhatTheEpochsCannotCarry(t *testing.T) {
	d, _ := assemblyTask()
	observations := make([]SanitizedEvent, 8193)
	for i := range observations {
		observations[i] = epochSample(uint64(i+1), 300, 0x10040)
	}
	if _, err := AssembleProfile(context.Background(), observations, nil, assemblyCapability(), epochLimits(d)); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("8193 observations: %v", err)
	}
	mappings := make([]SanitizedEvent, maxMappingEvents+1)
	for i := range mappings {
		mappings[i] = confirm(uint64(i+1), 100, 110)
	}
	if _, err := AssembleProfile(context.Background(), mappings, nil, assemblyCapability(), epochLimits(d)); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("%d mapping events: %v", len(mappings), err)
	}
	bad := []SanitizedEvent{epochSample(1, 300, 0x10040), {Kind: EventMapping, Time: 5, Domain: d, Sequence: 2}}
	if _, err := AssembleProfile(context.Background(), bad, nil, assemblyCapability(), epochLimits(d)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a mapping event without a mapping: %v", err)
	}
}

// The coverage fact of the process a sample belongs to (its frame pointers are absent) reaches the sample's native
// record through the table of its epoch; the facts of another process do not.
func TestAssembleCarriesTheFramePointerCoverageFactOfTheSamplesProcess(t *testing.T) {
	d, _ := assemblyTask()
	events := []SanitizedEvent{
		snapRow(1, 100, 110, 0x10000, 0x20000, 0, libA, ""),
		confirm(2, 100, 110),
		epochSample(3, 300, 0x10040),
		confirm(4, 380, 400),
	}
	run := func(mappings []MappingTable) string {
		l := epochLimits(d)
		l.Mappings = mappings
		c, err := AssembleProfile(context.Background(), events, nil, assemblyCapability(), l)
		if err != nil || len(c.Samples) != 1 || c.Samples[0].Native == nil {
			t.Fatalf("%+v %v", c, err)
		}
		return c.Samples[0].Native.Coverage
	}
	other := epochProcess()
	other.TGID++
	if got := run(nil); got != "" {
		t.Fatalf("coverage %q without any fact", got)
	}
	if got := run([]MappingTable{{process: other, policy: SymbolPolicy{FramePointersAbsent: true}}}); got != "" {
		t.Fatalf("coverage %q from the fact of another process", got)
	}
	if got := run([]MappingTable{{process: other, policy: SymbolPolicy{}}, {process: epochProcess(), policy: SymbolPolicy{FramePointersAbsent: true}}}); got != string(FrameMissing) {
		t.Fatalf("coverage %q, want %q", got, FrameMissing)
	}
}
