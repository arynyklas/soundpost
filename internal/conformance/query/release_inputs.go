// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/profiles"
)

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

// ProvenanceDecisions verifies every accepted audit file named by
// provenance.json against its recorded digest.
func ProvenanceDecisions(queryDir string) ([]ProvenanceDecision, error) {
	var manifest struct {
		Accepted []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"accepted_audits"`
	}
	if err := ReadJSON(filepath.Join(queryDir, "provenance.json"), &manifest); err != nil {
		return nil, err
	}
	var out []ProvenanceDecision
	for _, a := range manifest.Accepted {
		d := ProvenanceDecision{File: a.Path}
		raw, err := os.ReadFile(filepath.Join(queryDir, filepath.FromSlash(a.Path)))
		switch {
		case err != nil:
			d.Reason = err.Error()
		case sumHex(raw) != a.SHA256:
			d.Reason = "content digest differs from the accepted audit"
		default:
			d.Accepted = true
		}
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provenance.json accepts no audit")
	}
	return out, nil
}

func sumHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// LoadReleaseConfig assembles the gate input from the locked repository
// artifacts. Evidence that does not exist (production bindings, authored case
// runs, Go test observations, smoke results) is left empty so the gate counts
// it as unresolved rather than inventing it.
func LoadReleaseConfig(queryDir, policyPath string, smoke *SmokeReport, seed uint64) (ReleaseConfig, error) {
	var cfg ReleaseConfig
	if err := ReadJSON(policyPath, &cfg.Policy); err != nil {
		return cfg, err
	}
	if err := ReadJSON(filepath.Join(queryDir, "source-lock.json"), &cfg.Lock); err != nil {
		return cfg, err
	}
	cfg.Lock.LedgerPath = filepath.Join(queryDir, "obligations.json")
	ledger, err := Inventory(context.Background(), cfg.Lock)
	if err != nil {
		return cfg, fmt.Errorf("locked inventory: %w", err)
	}
	cfg.Ledger = ledger
	var domains struct {
		Domains []GateDomain `json:"domains"`
	}
	if err = ReadJSON(filepath.Join(queryDir, "gate-domains.json"), &domains); err != nil {
		return cfg, err
	}
	cfg.GateDomains = domains.Domains
	var acceptance struct {
		Bindings []struct {
			ObligationID   string   `json:"obligation_id"`
			Implementation string   `json:"implementation"`
			Cases          []string `json:"cases"`
			GoTests        []string `json:"go_tests"`
		} `json:"production_bindings"`
		Tests []TestObservation `json:"test_observations"`
	}
	if err = ReadJSON(filepath.Join(queryDir, "acceptance.json"), &acceptance); err != nil {
		return cfg, err
	}
	for _, b := range acceptance.Bindings {
		cfg.Bindings = append(cfg.Bindings, Binding{ObligationID: b.ObligationID, Implementation: b.Implementation, Cases: b.Cases, GoTests: b.GoTests})
	}
	cfg.Tests = acceptance.Tests
	manifest, err := LoadReleaseCaseManifest(filepath.Join(queryDir, "release-cases.json"))
	if err != nil {
		return cfg, err
	}
	if cfg.Cases, err = ReleaseCasesFromManifest(cfg.Lock, queryDir, manifest); err != nil {
		return cfg, fmt.Errorf("release cases: %w", err)
	}
	if cfg.Provenance, err = ProvenanceDecisions(queryDir); err != nil {
		return cfg, err
	}
	spec, err := LoadGenerationSpec(filepath.Join(queryDir, "generation.json"))
	if err != nil {
		return cfg, err
	}
	cases, err := generateForRelease(spec, ledger, cfg.GateDomains, seed)
	if err != nil {
		return cfg, err
	}
	cfg.Interaction = Coverage(spec, cases)
	if smoke != nil {
		cfg.Persistence, cfg.Isolation, cfg.Inputs = smoke.Persistence, smoke.Isolation, smoke.Normalization
	}
	return cfg, nil
}

func generateForRelease(spec GenerationSpec, ledger Ledger, domains []GateDomain, seed uint64) ([]Case, error) {
	files, err := profiles.Query()
	if err != nil {
		return nil, err
	}
	registry, err := profile.Load(files)
	if err != nil {
		return nil, err
	}
	return Generate(context.Background(), registry, ledger, seed, GenerationBudget{Spec: spec, Domains: domains})
}
