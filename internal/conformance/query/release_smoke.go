// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// SmokeReportSchema names the document `soundpost-querycheck smoke` writes.
const SmokeReportSchema = "soundpost-smoke-report/1"

// The persisted layouts `soundpost-querycheck smoke --modes` runs.
const (
	SmokeLayoutSingle      = "single"
	SmokeLayoutDistributed = "distributed"
)

// requiredSmokeLayouts are the layouts the smoke report handed to the release
// gate must have run. The gate consumes the report of the single layout (that is
// what tools/qualify feeds it and what the matrix's pinned input-normalization
// identity is computed over); the distributed layout is gated by its own smoke
// row of the campaign. A report that also ran more layouts is accepted.
var requiredSmokeLayouts = []string{SmokeLayoutSingle}

// requiredSmokeCaseFiles are the smoke case files whose steps the persistence,
// isolation and normalization claims rest on (matched by base name).
var requiredSmokeCaseFiles = []string{"persisted-path.json", "profile-cross-products.json"}

// SmokeReport is what the smoke runner observed on a real persisted path. The
// release gate consumes it; it is never synthesized.
type SmokeReport struct {
	Schema        string               `json:"schema"`
	CaseFiles     []string             `json:"case_files"`
	Storage       string               `json:"storage"`
	Control       string               `json:"control"`
	Modes         []string             `json:"modes"`
	ModesNotRun   []string             `json:"modes_not_run"`
	Persistence   []ScenarioOutcome    `json:"persistence"`
	Isolation     []ScenarioOutcome    `json:"isolation"`
	Normalization []NormalizationCheck `json:"normalization"`
	Steps         []ScenarioOutcome    `json:"steps"`
	NotSatisfied  []string             `json:"not_satisfied"`
}

// LoadSmokeReport reads the report written by `soundpost-querycheck smoke
// --report`. A report this code does not fully understand (an unknown field, a
// duplicated key, a second document) is not evidence and is refused.
func LoadSmokeReport(file string) (*SmokeReport, error) {
	s := new(SmokeReport)
	if err := readStrictJSON(file, s); err != nil {
		return nil, err
	}
	return s, nil
}

// problems lists everything that makes the report unfit to support the
// persistence, isolation and normalization claims of a release: it did not run
// on real storage and control, a required layout or case file did not run, a
// step failed, or the run itself recorded an unmet requirement. Every problem is
// listed (the gate never stops at the first).
func (s *SmokeReport) problems() []string {
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf("smoke: "+format, a...)) }
	if s.Schema != SmokeReportSchema {
		add("report schema %q is not %s", s.Schema, SmokeReportSchema)
	}
	if s.Storage != "real" {
		add("ran with storage %q, not real", s.Storage)
	}
	if s.Control != "real" {
		add("ran with control %q, not real", s.Control)
	}
	for _, layout := range requiredSmokeLayouts {
		if !slices.Contains(s.Modes, layout) {
			add("layout %s did not run", layout)
		}
	}
	for _, layout := range s.ModesNotRun {
		add("layout %s is recorded as not run", layout)
	}
	for _, note := range s.NotSatisfied {
		add("requirement NOT satisfied: %s", note)
	}
	if len(s.Steps) == 0 {
		add("report has no steps")
	}
	for _, step := range s.Steps {
		if !step.Passed {
			add("step %s failed: %s", step.Name, step.Detail)
		}
	}
	ran := map[string]bool{}
	for _, file := range s.CaseFiles {
		ran[path.Base(strings.ReplaceAll(file, `\`, "/"))] = true
	}
	for _, file := range requiredSmokeCaseFiles {
		if !ran[file] {
			add("case file %s was not run", file)
		}
	}
	return out
}
