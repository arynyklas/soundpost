// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var exactPins = map[string]string{
	"promql-prometheus-3.1.0":  "7086161a93b262aa0949dbf2aba15a5a7b13e0a3",
	"promql-prometheus-3.13.5": "f497435984d1ca1d84cda5ed309387ac2eb1f8f6",
	"logql-loki-3.5.2":         "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7",
}

type Obligation struct {
	ID               string   `json:"id"`
	Kind             string   `json:"kind"`
	Profile          string   `json:"profile"`
	Gate             string   `json:"gate,omitempty"`
	Signature        string   `json:"signature"`
	SemanticRule     string   `json:"semantic_rule"`
	SourceRefs       []string `json:"source_refs"`
	Implementation   string   `json:"implementation"`
	PositiveCases    []string `json:"positive_cases"`
	NegativeCases    []string `json:"negative_cases"`
	InteractionCases []string `json:"interaction_cases"`
}
type Ledger struct {
	ManifestVersion int          `json:"manifest_version"`
	Complete        bool         `json:"complete"`
	Missing         []string     `json:"missing"`
	Obligations     []Obligation `json:"obligations"`
}
type Binding struct {
	ObligationID   string
	Implementation string
	Cases          []string
	GoTests        []string
}
type FeatureSet struct {
	ID            string              `json:"id"`
	Enabled       []string            `json:"enabled"`
	DisabledCases map[string][]string `json:"disabled_cases"`
}
type Artifact struct {
	Path                string   `json:"path"`
	SHA256              string   `json:"sha256"`
	Architecture        string   `json:"architecture"`
	Adapter             string   `json:"adapter"`
	ConfigurationSHA256 string   `json:"configuration_sha256"`
	Args                []string `json:"args"`
}
type SourceProfile struct {
	ID                string    `json:"id"`
	Commit            string    `json:"commit"`
	SourceURL         string    `json:"source_url"`
	SourceSHA256      string    `json:"source_sha256"`
	License           string    `json:"license"`
	ConfigurationPath string    `json:"configuration_path"`
	Artifact          *Artifact `json:"artifact"`
}
type SourceLock struct {
	ManifestVersion int               `json:"manifest_version"`
	Profiles        []SourceProfile   `json:"profiles"`
	LedgerPath      string            `json:"-"`
	LedgerSHA256    string            `json:"ledger_sha256"`
	InventoryFiles  map[string]string `json:"inventory_files"`
	ProfileFiles    map[string]string `json:"profile_files"`
}

func ReadJSON(path string, target any) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, target)
}

// ReadLockedJSON binds the bytes actually consumed, including an alternative
// --cases path, to the named approved inventory artifact.
func ReadLockedJSON(lock SourceLock, key, path string, target any) error {
	want, ok := lock.InventoryFiles[key]
	if !ok || len(want) != 64 {
		return fmt.Errorf("missing content lock for %s", key)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != want {
		return fmt.Errorf("locked content changed: %s", key)
	}
	return json.Unmarshal(raw, target)
}
func validateManifestObligations(profile string, ids []string, ledger Ledger) error {
	expected := map[string]bool{}
	for _, o := range ledger.Obligations {
		if o.Profile == profile {
			expected[o.ID] = true
		}
	}
	if len(ids) != len(expected) {
		return fmt.Errorf("manifest obligation count differs from ledger: %s", profile)
	}
	for _, id := range ids {
		if !expected[id] {
			return fmt.Errorf("unknown or duplicate manifest obligation %s in %s", id, profile)
		}
		delete(expected, id)
	}
	if len(expected) != 0 {
		return fmt.Errorf("missing manifest obligations for %s", profile)
	}
	return nil
}
func ValidateSourceLock(lock SourceLock) error {
	if lock.ManifestVersion != 1 || len(lock.Profiles) != len(exactPins) {
		return fmt.Errorf("source lock must contain all three exact profiles")
	}
	seen := map[string]bool{}
	for _, p := range lock.Profiles {
		if p.Commit == "" || exactPins[p.ID] != p.Commit || seen[p.ID] || len(p.SourceSHA256) != 64 || p.SourceURL == "" || p.License == "" {
			return fmt.Errorf("invalid source lock profile %s", p.ID)
		}
		if _, e := hex.DecodeString(p.SourceSHA256); e != nil {
			return fmt.Errorf("invalid source digest for %s", p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}
func Inventory(ctx context.Context, lock SourceLock) (Ledger, error) {
	if err := ctx.Err(); err != nil {
		return Ledger{}, err
	}
	var l Ledger
	if err := ValidateSourceLock(lock); err != nil {
		return l, err
	}
	raw, err := os.ReadFile(lock.LedgerPath)
	if err != nil {
		return l, err
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != lock.LedgerSHA256 {
		return l, fmt.Errorf("ledger content changed: additions, removals and signatures require audit and relock")
	}
	if err = json.Unmarshal(raw, &l); err != nil {
		return l, err
	}
	if len(lock.InventoryFiles) == 0 {
		return l, fmt.Errorf("missing inventory content locks")
	}
	for name, want := range lock.InventoryFiles {
		if !filepath.IsLocal(name) {
			return l, fmt.Errorf("inventory lock path must be local")
		}
		data, e := os.ReadFile(filepath.Join(filepath.Dir(lock.LedgerPath), name))
		if e != nil {
			return l, e
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != want {
			return l, fmt.Errorf("inventory scope changed: %s requires audit and relock", name)
		}
	}
	if len(lock.ProfileFiles) != len(lock.Profiles) {
		return l, fmt.Errorf("missing profile manifest locks")
	}
	for _, p := range lock.Profiles {
		name := "profiles/query/" + p.ID + ".json"
		want := lock.ProfileFiles[name]
		raw, e := os.ReadFile(filepath.Join(filepath.Dir(lock.LedgerPath), "..", "..", filepath.FromSlash(name)))
		if e != nil {
			return l, e
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			return l, fmt.Errorf("profile configuration/feature registry changed: %s", p.ID)
		}
		var manifest struct {
			ID          string   `json:"id"`
			Complete    bool     `json:"complete"`
			Obligations []string `json:"obligations"`
		}
		if e = json.Unmarshal(raw, &manifest); e != nil {
			return l, e
		}
		if manifest.ID != p.ID || !manifest.Complete {
			return l, fmt.Errorf("unaccepted manifest for %s", p.ID)
		}
		if e = validateManifestObligations(p.ID, manifest.Obligations, l); e != nil {
			return l, e
		}
	}
	seen := map[string]bool{}
	for _, p := range lock.Profiles {
		if exactPins[p.ID] != p.Commit || len(p.SourceSHA256) != 64 || p.License == "" || seen[p.ID] {
			return l, fmt.Errorf("invalid source identity %q", p.ID)
		}
		seen[p.ID] = true
	}
	previous := ""
	for _, o := range l.Obligations {
		if o.ID <= previous || !seen[o.Profile] || len(o.SourceRefs) == 0 {
			return l, fmt.Errorf("invalid or unsorted obligation %q", o.ID)
		}
		previous = o.ID
	}
	if !l.Complete || len(l.Missing) > 0 {
		return l, fmt.Errorf("inventory incomplete: %s", strings.Join(l.Missing, "; "))
	}
	if l.ManifestVersion != 1 || len(l.Obligations) == 0 {
		return l, fmt.Errorf("empty or unknown ledger manifest")
	}
	for _, o := range l.Obligations {
		if o.SemanticRule == "" || strings.Contains(o.SemanticRule, "pending") || strings.HasPrefix(o.Kind, "source-") || o.Kind == "registry-symbol" || o.Kind == "production-symbol" {
			return l, fmt.Errorf("unclassified source discovery is not accepted semantic inventory: %s", o.ID)
		}
	}
	var closure struct {
		Complete bool         `json:"complete"`
		Domains  []GateDomain `json:"domains"`
	}
	if err := ReadJSON(filepath.Join(filepath.Dir(lock.LedgerPath), "gate-domains.json"), &closure); err != nil {
		return l, err
	}
	if !closure.Complete || len(closure.Domains) != len(lock.Profiles) {
		return l, fmt.Errorf("missing accepted feature domains")
	}
	for _, domain := range closure.Domains {
		if err := ValidateGateClosure(domain.Gates, domain.FeatureSets); err != nil {
			return l, fmt.Errorf("%s: %w", domain.Profile, err)
		}
	}
	return l, nil
}
func ValidateCoverage(l Ledger, bindings []Binding) error {
	if !l.Complete || len(l.Missing) > 0 || len(l.Obligations) == 0 {
		return fmt.Errorf("inventory incomplete")
	}
	byID := map[string]Binding{}
	for _, b := range bindings {
		if _, ok := byID[b.ObligationID]; ok {
			return fmt.Errorf("duplicate binding %s", b.ObligationID)
		}
		byID[b.ObligationID] = b
	}
	for _, o := range l.Obligations {
		b, ok := byID[o.ID]
		if !ok || b.Implementation == "" || b.Implementation == "pending" || len(b.GoTests) == 0 {
			return fmt.Errorf("missing obligation binding %s", o.ID)
		}
		for _, name := range b.GoTests {
			if !strings.HasPrefix(name, "Test") || len(name) == 4 {
				return fmt.Errorf("invalid Go test binding %s", name)
			}
		}
		cases := map[string]bool{}
		for _, c := range b.Cases {
			if c == "" || cases[c] {
				return fmt.Errorf("invalid case binding for %s", o.ID)
			}
			cases[c] = true
		}
		for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
			if len(group) == 0 {
				return fmt.Errorf("missing case class %s", o.ID)
			}
			for _, c := range group {
				if !cases[c] {
					return fmt.Errorf("unbound case %s for %s", c, o.ID)
				}
			}
		}
		delete(byID, o.ID)
	}
	if len(byID) > 0 {
		return fmt.Errorf("unknown obligation bindings")
	}
	return nil
}

// ValidateGateClosure enumerates independent boolean gates. Constrained domains
// must first be represented as separate profile configurations, not dropped combinations.
func ValidateGateClosure(gates []string, sets []FeatureSet) error {
	if len(gates) > 20 {
		return fmt.Errorf("gate domain too large for bounded enumeration")
	}
	index := map[string]uint{}
	for i, g := range gates {
		if _, ok := index[g]; ok {
			return fmt.Errorf("duplicate gate")
		}
		index[g] = uint(i)
	}
	masks := map[uint64]bool{}
	ids := map[string]bool{}
	for _, s := range sets {
		if s.ID == "" || ids[s.ID] {
			return fmt.Errorf("invalid feature set ID")
		}
		ids[s.ID] = true
		var mask uint64
		for _, g := range s.Enabled {
			i, ok := index[g]
			if !ok {
				return fmt.Errorf("unknown gate %s", g)
			}
			bit := uint64(1) << i
			if mask&bit != 0 {
				return fmt.Errorf("duplicate enabled gate")
			}
			mask |= bit
		}
		for g, i := range index {
			if mask&(uint64(1)<<i) == 0 {
				cases := s.DisabledCases[g]
				if len(cases) == 0 {
					return fmt.Errorf("disabled gate %s lacks negative cases in %s", g, s.ID)
				}
				for _, c := range cases {
					if c == "" {
						return fmt.Errorf("empty disabled-gate case")
					}
				}
			}
		}
		if masks[mask] {
			return fmt.Errorf("duplicate feature combination")
		}
		masks[mask] = true
	}
	if len(masks) != 1<<len(gates) {
		return fmt.Errorf("missing feature combinations")
	}
	return nil
}
func SortedIDs(l Ledger) []string {
	r := make([]string, len(l.Obligations))
	for i, o := range l.Obligations {
		r[i] = o.ID
	}
	sort.Strings(r)
	return r
}
