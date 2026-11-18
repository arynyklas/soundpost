//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"regexp"
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
		if row.State == "not_run" {
			if row.KernelBuild != nil || row.RuntimeBuildFlags != nil {
				t.Errorf("%s is not_run but pins a build: nothing was exercised", key)
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
