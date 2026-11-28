//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

// A host scenario is an operational scenario beyond the nine required rows (cpu_hotplug, container_modes, pid_reuse,
// python_trampolines, ...). Several change host state (they take a CPU offline, create namespaces or containers), so a run
// exercises them only when asked: --host-scenarios name[,name...]. Each registers itself from its own file's init and
// returns the Row that becomes QualificationResult.Scenarios[name]; a scenario that was not asked for is reported not_run
// with that reason, never silently absent. The release gate requires the ones the manifest names in required_scenarios.
var hostScenarios = map[string]func(a *accept) qual.Row{}

func registerHostScenario(name string, run func(a *accept) qual.Row) {
	if _, dup := hostScenarios[name]; dup || name == "" || strings.ContainsAny(name, ", ") {
		panic("acceptance: invalid or duplicate host scenario " + name)
	}
	hostScenarios[name] = run
}

// hostScenarioNames returns the registered scenario names in order.
func hostScenarioNames() []string {
	names := make([]string, 0, len(hostScenarios))
	for name := range hostScenarios {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// parseHostScenarios validates the --host-scenarios list.
func parseHostScenarios(list string) (map[string]bool, error) {
	asked := map[string]bool{}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, ok := hostScenarios[name]; !ok {
			return nil, fmt.Errorf("unknown host scenario %q (known: %s)", name, strings.Join(hostScenarioNames(), ", "))
		}
		asked[name] = true
	}
	return asked, nil
}

// runHostScenarios exercises the requested scenarios, in name order, and reports every registered one.
func (a *accept) runHostScenarios() {
	asked, err := parseHostScenarios(a.o.hostScenarios)
	if err != nil {
		panic(err) // main validated the list before the run started
	}
	if a.res.Scenarios == nil {
		a.res.Scenarios = map[string]qual.Row{}
	}
	for _, name := range hostScenarioNames() {
		if !asked[name] {
			a.res.Scenarios[name] = qual.Row{State: qual.StateNotRun, Reason: "opt-in host scenario: pass --host-scenarios " + name}
			continue
		}
		a.record("host scenario "+name, true, "")
		a.res.Scenarios[name] = hostScenarios[name](a)
	}
}
