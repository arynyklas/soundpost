//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/fixtures/nativeperf/qual"
)

type shippedRow struct {
	KernelSeries      string          `json:"kernel_series"`
	Arch              string          `json:"arch"`
	KernelBuild       *string         `json:"kernel_build"`
	KernelConfig      json.RawMessage `json:"kernel_config"`
	Toolchain         string          `json:"toolchain"`
	RuntimeBuildFlags *string         `json:"runtime_build_flags"`
	State             string          `json:"state"`
	Qualification     string          `json:"qualification"`
}

func shippedManifest(t *testing.T) []shippedRow {
	t.Helper()
	raw, err := os.ReadFile("../qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Rows []shippedRow `json:"rows"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.Rows
}

// The plan pins "exact kernel builds/configs/toolchain/runtime build flags in the qualification manifest" with evidence source
// links, and every row that a real runner exercised must carry them: lane 4 waves 13-19 ran the 6.1 and 6.6 LTS amd64 series on
// two real kernels (docs/support/native-linux.md), so those rows cannot stay `not_run` with null pins.
func TestShippedManifestPinsTheKernelBuildConfigAndFlagsOfEveryExercisedRow(t *testing.T) {
	digest := regexp.MustCompile(`^[0-9a-f]{64}$`)
	exercisedOnRealRunners := map[string]bool{"6.1 LTS/amd64": false, "6.6 LTS/amd64": false}
	for _, row := range shippedManifest(t) {
		key := row.KernelSeries + "/" + row.Arch
		if _, real := exercisedOnRealRunners[key]; real {
			exercisedOnRealRunners[key] = true
			if row.State == "not_run" {
				t.Errorf("%s was exercised on a real kernel but the manifest still says not_run", key)
			}
		}
		if row.State == "not_run" || row.State == "out_of_release_scope" {
			if row.KernelBuild != nil || row.RuntimeBuildFlags != nil {
				t.Errorf("%s is %s but pins a build: nothing was exercised", key, row.State)
			}
			continue
		}
		if row.KernelBuild == nil || *row.KernelBuild == "" || row.Toolchain == "" || row.RuntimeBuildFlags == nil || *row.RuntimeBuildFlags == "" || row.Qualification == "" {
			t.Errorf("%s (%s): kernel_build, toolchain, runtime_build_flags and the qualification evidence text must all be present", key, row.State)
		}
		var cfg struct {
			Source       string `json:"source"`
			SHA256       string `json:"sha256"`
			PerfEvents   string `json:"config_perf_events"`
			FramePointer string `json:"config_frame_pointer"`
			Ftrace       string `json:"config_ftrace"`
		}
		if err := json.Unmarshal(row.KernelConfig, &cfg); err != nil || cfg.Source == "" || cfg.PerfEvents == "" || cfg.FramePointer == "" || cfg.Ftrace == "" {
			t.Errorf("%s (%s): kernel_config must name its source and the three options the engine depends on: %s", key, row.State, row.KernelConfig)
		}
		if _, real := exercisedOnRealRunners[key]; real && !digest.MatchString(cfg.SHA256) {
			t.Errorf("%s: kernel_config.sha256 %q is not a SHA-256 digest of the config file", key, cfg.SHA256)
		}
	}
	for key, seen := range exercisedOnRealRunners {
		if !seen {
			t.Errorf("manifest has no row for %s", key)
		}
	}
}

// The gate qualifies an LTS row only by its pinned build and config digest: the shipped amd64 rows must be matchable that way
// (the pinned release is a qualified series by the uname -r rule and carries a config digest), and the WSL2 functional row must not be.
func TestShippedLTSRowsAreQualifiableByTheirPinsAndTheWSLRowIsNot(t *testing.T) {
	raw, err := os.ReadFile("../qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, row := range m.Rows {
		release := strings.Fields(row.KernelBuild)
		switch {
		case row.KernelSeries == "6.6" && len(release) > 0:
			if qual.KernelSeries(release[0]) != "" {
				t.Errorf("the WSL2 functional row %q is recognized as the qualified series %q", release[0], qual.KernelSeries(release[0]))
			}
		case row.Arch == "amd64" && strings.HasSuffix(row.KernelSeries, "LTS"):
			if len(release) == 0 || qual.KernelSeries(release[0]) != row.KernelSeries {
				t.Errorf("%s amd64 pins %q, which is not a %s build by the uname -r rule", row.KernelSeries, row.KernelBuild, row.KernelSeries)
			}
			if row.KernelConfig.SHA256 == "" {
				t.Errorf("%s amd64 pins no kernel config digest, so no result can qualify it", row.KernelSeries)
			}
		}
	}
}

// 04.09-C30: the gate must not pass when no result was supplied even if the manifest requires nothing (no LTS matrix rows), so the
// "no results" guard is the only thing standing between an empty run and exit 0. Mutant: `if len(c.Results) == 0 && ...` -> `if false`.
func TestRequireAllWithoutAnyResultNeverExitsZeroEvenForAnEmptyMatrix(t *testing.T) {
	m := write(t, "manifest.json", `{"rows":[],"advertised_fixtures":["cpu"]}`)
	if code, _, stderr := gate(t, "--manifest", m, "--require-all"); code == 0 {
		t.Fatalf("an empty run with an empty matrix exited 0:\n%s", stderr)
	}
}

// 04.09-C29: the shipped manifest is the release gate's input. It names every advertised fixture of both capture modes, the four
// operational scenarios, the versioned runtime columns and the linux/amd64 release scope (decision D10); its arm64 rows say
// out_of_release_scope with that decision (never `not_run`), its exercised amd64 rows pin every required runtime version in their
// build flags, and the text of the exercised rows no longer lists as unexercised what the final runs exercised. Mutants: any of
// the four lists or the scope reverted to the earlier value; an arm64 row back to not_run.
func TestShippedManifestIsTheReleaseGateInput(t *testing.T) {
	raw, err := os.ReadFile("../qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		AdvertisedFixtures []string     `json:"advertised_fixtures"`
		RequiredScenarios  []string     `json:"required_scenarios"`
		RequiredRuntimes   []string     `json:"required_runtimes"`
		ReleasePlatforms   []string     `json:"release_platforms"`
		Rows               []shippedRow `json:"rows"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name      string
		got, want []string
	}{
		{"advertised_fixtures", m.AdvertisedFixtures, []string{"cpu", "fanout16", "fanout64", "cpu_offcpu", "fanout16_offcpu"}},
		{"required_scenarios", m.RequiredScenarios, []string{"cpu_hotplug", "container_modes", "python_trampolines", "runtime_db_wait"}},
		{"required_runtimes", m.RequiredRuntimes, []string{"python@3.12", "python@3.13", "python@3.14", "node@22", "node@24", "bun"}},
		{"release_platforms", m.ReleasePlatforms, []string{"linux/amd64"}},
	} {
		if !slices.Equal(c.got, c.want) {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	versions := regexp.MustCompile(`^(python|node)@(\d+(\.\d+)?)$`)
	stale := []string{"Not exercised: Node 24", "database wait, PID reuse", "CPU hotplug, container modes", "python 3.13/3.14", "native-extension work, trampolines"}
	for _, row := range m.Rows {
		key := row.KernelSeries + "/" + row.Arch
		text := row.Qualification
		if row.RuntimeBuildFlags != nil {
			text += " " + *row.RuntimeBuildFlags
		}
		for _, s := range stale {
			if strings.Contains(text, s) {
				t.Errorf("%s still carries the stale text %q", key, s)
			}
		}
		if !strings.HasSuffix(row.KernelSeries, "LTS") {
			continue
		}
		switch row.Arch {
		case "arm64":
			if row.State != "out_of_release_scope" || !strings.Contains(row.Qualification, "D10") {
				t.Errorf("%s: state %q, qualification %q; want out_of_release_scope citing decision D10", key, row.State, row.Qualification)
			}
		case "amd64":
			if row.RuntimeBuildFlags == nil {
				t.Fatalf("%s pins no runtime build flags", key)
			}
			for _, req := range m.RequiredRuntimes {
				var wantText string
				switch sub := versions.FindStringSubmatch(req); {
				case sub != nil && sub[1] == "python":
					wantText = "CPython " + sub[2] + "."
				case sub != nil:
					wantText = "Node v" + sub[2] + "."
				default:
					wantText = "Bun "
				}
				if !strings.Contains(*row.RuntimeBuildFlags, wantText) {
					t.Errorf("%s: runtime_build_flags do not name the version run for %s (%q missing): %s", key, req, wantText, *row.RuntimeBuildFlags)
				}
			}
		}
	}
	// the gate reads the same file: on its own the manifest puts exactly the two amd64 LTS rows in the matrix and reports the
	// two arm64 rows as out of scope; with no result it can only fail closed on the amd64 rows
	out := t.TempDir() + "/gate.json"
	code, _, stderr := gate(t, "--manifest", "../qualification.json", "--require-all", "--out", out)
	if code != qual.ExitUnexercised {
		t.Fatalf("the shipped manifest without a result exited %d, want %d:\n%s", code, qual.ExitUnexercised, stderr)
	}
	for _, want := range []string{"matrix kernel 6.1 LTS amd64", "matrix kernel 6.6 LTS amd64"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "arm64") {
		t.Errorf("an out-of-scope arm64 row is listed as unqualified:\n%s", stderr)
	}
	var c struct {
		Matrix     []matrixRow `json:"matrix"`
		OutOfScope []matrixRow `json:"out_of_release_scope_rows"`
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Matrix) != 2 || len(c.OutOfScope) != 2 {
		t.Fatalf("matrix %+v, out of scope %+v; want two amd64 and two arm64 rows", c.Matrix, c.OutOfScope)
	}
	for _, row := range c.OutOfScope {
		if row.Arch != "arm64" || row.Qualified || !strings.Contains(row.Reason, "D10") {
			t.Errorf("out-of-scope row %+v", row)
		}
	}
}
