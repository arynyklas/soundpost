// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type GateDomain struct {
	Profile     string       `json:"profile"`
	Gates       []string     `json:"gates"`
	FeatureSets []FeatureSet `json:"feature_sets"`
}
type CaseObservation struct {
	ID       string          `json:"id"`
	Profile  string          `json:"profile"`
	Expected SemanticResult  `json:"expected"`
	Actual   SemanticResult  `json:"actual"`
	Ordering OrderingFreedom `json:"ordering"`
}
type TestObservation struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	Command        string `json:"command"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}
type AcceptanceReport struct {
	Lock        SourceLock        `json:"lock"`
	Ledger      Ledger            `json:"ledger"`
	Bindings    []Binding         `json:"bindings"`
	GateDomains []GateDomain      `json:"gate_domains"`
	Cases       []CaseObservation `json:"cases"`
	Tests       []TestObservation `json:"tests"`
}

// ValidateAcceptance is deliberately stronger than inventory acceptance. No
// pending production binding, absent oracle, uncovered gate domain or missing
// test evidence can become a successful release report.
func ValidateAcceptance(report AcceptanceReport) error {
	if err := ValidateSourceLock(report.Lock); err != nil {
		return err
	}
	if err := ValidateCoverage(report.Ledger, report.Bindings); err != nil {
		return err
	}
	profiles := map[string]SourceProfile{}
	for _, p := range report.Lock.Profiles {
		if p.Artifact == nil || p.Artifact.Path != "sha256:"+p.Artifact.SHA256 || p.Artifact.Adapter != "oci-semantic-json-v1" || p.Artifact.Architecture != "linux/amd64" {
			return fmt.Errorf("missing oracle artifact for %s", p.ID)
		}
		imageHash, e := hex.DecodeString(p.Artifact.SHA256)
		if e != nil || len(imageHash) != 32 {
			return fmt.Errorf("invalid oracle image digest")
		}
		configHash, e := hex.DecodeString(p.Artifact.ConfigurationSHA256)
		if e != nil || len(configHash) != 32 {
			return fmt.Errorf("invalid oracle configuration digest")
		}
		profiles[p.ID] = p
	}
	domains := map[string]bool{}
	for _, domain := range report.GateDomains {
		if _, known := profiles[domain.Profile]; !known || domains[domain.Profile] {
			return fmt.Errorf("unknown or duplicate gate domain %s", domain.Profile)
		}
		if err := ValidateGateClosure(domain.Gates, domain.FeatureSets); err != nil {
			return fmt.Errorf("%s: %w", domain.Profile, err)
		}
		domains[domain.Profile] = true
	}
	if len(domains) != len(profiles) {
		return fmt.Errorf("missing profile gate domains")
	}
	required := map[string]bool{}
	for _, o := range report.Ledger.Obligations {
		if _, ok := profiles[o.Profile]; !ok {
			return fmt.Errorf("unknown obligation profile %s", o.Profile)
		}
		for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
			for _, id := range group {
				required[o.Profile+"\x00"+id] = true
			}
		}
	}
	seen := map[string]bool{}
	observedProfiles := map[string]bool{}
	for _, observation := range report.Cases {
		key := observation.Profile + "\x00" + observation.ID
		if !required[key] || seen[key] {
			return fmt.Errorf("unknown or duplicate observed case %s/%s", observation.Profile, observation.ID)
		}
		p := profiles[observation.Profile]
		identity := observation.Actual.Oracle
		if identity == nil || identity.Profile != p.ID || identity.ImageSHA256 != p.Artifact.SHA256 || identity.ConfigurationSHA256 != p.Artifact.ConfigurationSHA256 {
			return fmt.Errorf("unverified oracle case %s", observation.ID)
		}
		version := strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-")
		if len(identity.Revision) < 7 || !strings.HasPrefix(p.Commit, identity.Revision) || strings.TrimPrefix(identity.Version, "v") != version {
			return fmt.Errorf("oracle build identity mismatch")
		}
		if len(Compare(observation.Expected, observation.Actual, observation.Ordering)) != 0 {
			return fmt.Errorf("semantic mismatch in %s", observation.ID)
		}
		seen[key] = true
		observedProfiles[p.ID] = true
	}
	if len(seen) != len(required) || len(observedProfiles) != len(profiles) {
		return fmt.Errorf("missing required oracle observations")
	}
	tests := map[string]bool{}
	for _, test := range report.Tests {
		hash, err := hex.DecodeString(test.EvidenceSHA256)
		if test.Name == "" || !test.Passed || test.Command == "" || err != nil || len(hash) != 32 || tests[test.Name] {
			return fmt.Errorf("missing or invalid passing test evidence %s", test.Name)
		}
		tests[test.Name] = true
	}
	for _, binding := range report.Bindings {
		for _, name := range binding.GoTests {
			if !tests[name] {
				return fmt.Errorf("unobserved Go test %s", name)
			}
		}
	}
	return nil
}
