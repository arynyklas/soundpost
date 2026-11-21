//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

func TestHostScenariosRunOnlyWhenAskedAndEveryRegisteredOneIsReported(t *testing.T) {
	ran := 0
	registerHostScenario("zz_test_scenario", func(*accept) qual.Row {
		ran++
		return qual.Supported([]string{"ran"}, nil)
	})
	defer delete(hostScenarios, "zz_test_scenario")

	a := &accept{res: &qual.QualificationResult{}}
	a.runHostScenarios()
	if ran != 0 {
		t.Fatal("a host scenario ran without being asked for")
	}
	row, ok := a.res.Scenarios["zz_test_scenario"]
	if !ok || row.State != qual.StateNotRun || !strings.Contains(row.Reason, "--host-scenarios zz_test_scenario") {
		t.Fatalf("an unrequested scenario is not reported as not_run with the flag that runs it: %+v", row)
	}

	a = &accept{o: options{hostScenarios: "zz_test_scenario"}, res: &qual.QualificationResult{}}
	a.runHostScenarios()
	if ran != 1 || a.res.Scenarios["zz_test_scenario"].State != qual.StateSupported {
		t.Fatalf("the requested scenario did not run to its row: ran=%d %+v", ran, a.res.Scenarios["zz_test_scenario"])
	}
}

func TestUnknownHostScenarioIsAUsageError(t *testing.T) {
	if _, err := parseHostScenarios("cpu_hotplug_typo"); err == nil || !strings.Contains(err.Error(), "unknown host scenario") {
		t.Fatalf("an unknown scenario name was accepted: %v", err)
	}
}
