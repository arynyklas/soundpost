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

// ProvenanceDecisions verifies every accepted audit file named by
// provenance.json against its recorded digest. A path that leaves the query
// directory is refused whatever its digest: the audited bytes live inside it.
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
		local := filepath.FromSlash(a.Path)
		if !filepath.IsLocal(local) {
			d.Reason = "audit path is outside the query directory"
			out = append(out, d)
			continue
		}
		raw, err := os.ReadFile(filepath.Join(queryDir, local))
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
// it as unresolved rather than inventing it. The policy read is the
// content-locked release-policy.json of the lock, whatever path policyPath
// names, and is decoded strictly.
func LoadReleaseConfig(queryDir, policyPath string, smoke *SmokeReport, seeds []uint64) (ReleaseConfig, error) {
	if len(seeds) == 0 {
		return ReleaseConfig{}, fmt.Errorf("at least one generator seed is required")
	}
	var cfg ReleaseConfig
	if err := ReadJSON(filepath.Join(queryDir, "source-lock.json"), &cfg.Lock); err != nil {
		return cfg, err
	}
	if err := readLockedStrict(cfg.Lock, "release-policy.json", policyPath, &cfg.Policy); err != nil {
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
	if cfg.TestEvidence, err = loadGoTestEvidence(queryDir); err != nil {
		return cfg, err
	}
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
	if cfg.Spec, err = LoadGenerationSpec(filepath.Join(queryDir, "generation.json")); err != nil {
		return cfg, err
	}
	for _, seed := range seeds {
		rows, err := PlanGenerated(cfg.Spec, ledger, cfg.GateDomains, seed)
		if err != nil {
			return cfg, fmt.Errorf("seed %d: %w", seed, err)
		}
		cfg.Generated = append(cfg.Generated, GeneratedRun{Seed: seed, Rows: rows})
	}
	cfg.Smoke = smoke
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
