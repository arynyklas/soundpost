// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"strings"
	"testing"
)

// (allSupported is the helper of qual_test.go)

func TestScenarioRowsFollowTheRowStateRules(t *testing.T) {
	r := allSupported()
	r.Scenarios = map[string]Row{"cpu_hotplug": {State: StateSupported}}
	if err := r.Validate(); err == nil || !strings.Contains(err.Error(), "cpu_hotplug") {
		t.Fatalf("a supported scenario without evidence passed validation: %v", err)
	}
	r.Scenarios["cpu_hotplug"] = Supported([]string{"the offlined CPU was reported as topology_changed"}, nil)
	if err := r.Validate(); err != nil {
		t.Fatalf("a supported scenario with evidence is invalid: %v", err)
	}
}

func TestAFailedScenarioFailsTheRunAndAnUnexercisedOneNeverPassesTheGate(t *testing.T) {
	r := allSupported()
	if r.ExitCode() != ExitOK {
		t.Fatalf("baseline exit %d", r.ExitCode())
	}
	r.Scenarios = map[string]Row{"container_modes": Failed("the container capture joined a host task", nil)}
	if got := r.ExitCode(); got != ExitFail {
		t.Fatalf("a failed scenario left the run at exit %d, want %d", got, ExitFail)
	}
	r.Scenarios["container_modes"] = Row{State: StateError, Reason: "the sandbox could not be created"}
	if got := r.ExitCode(); got != ExitFail {
		t.Fatalf("an errored scenario left the run at exit %d, want %d", got, ExitFail)
	}
	r.Scenarios["container_modes"] = Row{State: StateNotRun, Reason: "not requested"}
	if got := r.ExitCode(); got != ExitOK {
		t.Fatalf("an optional scenario that was not run changed the run to exit %d", got)
	}
	lines := ScenarioRequirements(r, []string{"container_modes", "cpu_hotplug"})
	if len(lines) != 2 || !strings.Contains(lines[0], "container_modes") || !strings.Contains(lines[0], "not_run") || !strings.Contains(lines[1], "cpu_hotplug") {
		t.Fatalf("required scenarios not listed exactly: %v", lines)
	}
	r.Scenarios["container_modes"] = Supported([]string{"e"}, nil)
	r.Scenarios["cpu_hotplug"] = Supported([]string{"e"}, nil)
	if lines := ScenarioRequirements(r, []string{"container_modes", "cpu_hotplug"}); len(lines) != 0 {
		t.Fatalf("supported required scenarios still listed: %v", lines)
	}
}

func versionedColumn(rt, version string, ok bool) RuntimeColumn {
	c := RuntimeColumn{Runtime: rt, Arch: "amd64", Build: RuntimeBuild{Runtime: rt, Version: version, Arch: "amd64"},
		Engine: Supported([]string{"e"}, nil), Native: Supported([]string{"n"}, nil), Wait: Supported([]string{"w"}, nil)}
	if !ok {
		c.Wait = Unqualified("database wait not run", nil)
	}
	return c
}

func TestRequiredRuntimeMayNameAMajorMinorAndNoOtherVersionQualifiesIt(t *testing.T) {
	r := allSupported()
	r.Runtimes = []RuntimeColumn{versionedColumn("node", "v22.21.1", true), versionedColumn("python", "3.12.16", true), versionedColumn("python", "3.13.18", false), versionedColumn("bun", "1.3.14", true)}
	got := RuntimeRequirements(r, []string{"node@22", "node@24", "python@3.12", "python@3.13", "python@3.14", "bun"})
	want := []string{"runtime node@24/amd64: not qualified on its own evidence", "runtime python@3.13/amd64: not qualified on its own evidence", "runtime python@3.14/amd64: not qualified on its own evidence"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("requirements = %v, want %v", got, want)
	}
	// "node@2" is not "node@22": a major is matched whole, never as a string prefix of another major or minor
	r.Runtimes = []RuntimeColumn{versionedColumn("node", "v22.21.1", true), versionedColumn("python", "3.14.10", true)}
	if got := RuntimeRequirements(r, []string{"node@2", "python@3.1"}); len(got) != 2 {
		t.Fatalf("a partial major/minor qualified a column: %v", got)
	}
	// an unversioned requirement keeps its meaning: any qualified build of that runtime
	if got := RuntimeRequirements(r, []string{"node"}); len(got) != 0 {
		t.Fatalf("an unversioned requirement lost its meaning: %v", got)
	}
}
