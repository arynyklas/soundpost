// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

type GateDomain struct {
	Profile     string       `json:"profile"`
	Gates       []string     `json:"gates"`
	FeatureSets []FeatureSet `json:"feature_sets"`
}

// TestObservation is one recorded Go test run of acceptance.json. It counts as
// evidence only when the go test stream it was hashed over backs it (see
// observedTests).
type TestObservation struct {
	Name           string `json:"name"`
	Passed         bool   `json:"passed"`
	Command        string `json:"command"`
	EvidenceSHA256 string `json:"evidence_sha256"`
}
