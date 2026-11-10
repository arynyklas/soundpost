// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// StaleBits is the Prometheus stale marker. An ordinary NaN never equals it.
const StaleBits = "7ff0000000000002"

// ReleasePolicy is conformance/query/release-policy.json. Every requirement is
// mandatory: a policy that turns one off is rejected, never honoured.
type ReleasePolicy struct {
	Schema               string   `json:"schema"`
	RequireLocked        bool     `json:"require_locked"`
	RequireZeroUnbound   bool     `json:"require_zero_unbound"`
	RequireZeroSkips     bool     `json:"require_zero_skips"`
	RequireZeroMismatch  bool     `json:"require_zero_mismatches"`
	RequireZeroUnrun     bool     `json:"require_zero_unrun"`
	RequireOracle        bool     `json:"require_oracle_observation"`
	RequireLosslessInput bool     `json:"require_lossless_input_normalization"`
	AllProfiles          []string `json:"all_profiles"`
	RequiredPersistence  []string `json:"required_persistence"`
	RequiredIsolation    []string `json:"required_isolation"`
}

func (p ReleasePolicy) Validate() error {
	if p.Schema != "soundpost-query-release-policy/1" {
		return fmt.Errorf("unknown release policy schema")
	}
	if !(p.RequireLocked && p.RequireZeroUnbound && p.RequireZeroSkips && p.RequireZeroMismatch && p.RequireZeroUnrun && p.RequireOracle && p.RequireLosslessInput) {
		return fmt.Errorf("release policy may not weaken a mandatory requirement")
	}
	if len(p.AllProfiles) != len(exactPins) {
		return fmt.Errorf("release policy must name all three pinned profiles")
	}
	for _, id := range p.AllProfiles {
		if _, ok := exactPins[id]; !ok {
			return fmt.Errorf("release policy names unknown profile %s", id)
		}
	}
	if len(p.RequiredPersistence) == 0 || len(p.RequiredIsolation) == 0 {
		return fmt.Errorf("release policy requires persistence and isolation scenarios")
	}
	return nil
}

// ReleaseCase is one authored, profile-specific case. Expected results are per
// profile and never shared between profiles by the gate.
type ReleaseCase struct {
	ID       string          `json:"id"`
	Profile  string          `json:"profile"`
	Input    json.RawMessage `json:"input,omitempty"`
	Expected SemanticResult  `json:"expected"`
	Ordering OrderingFreedom `json:"ordering"`
	Skip     string          `json:"skip,omitempty"`
}

// ExpectedByProfile maps exact profile IDs to independent expected results.
type ExpectedByProfile map[string]SemanticResult

// SplitProfileExpectations turns one version-difference fixture into one case
// per declared profile. Each profile must have its own expectation, no other
// profile may appear, and the copies share no memory.
func SplitProfileExpectations(id string, profiles []string, input json.RawMessage, expected ExpectedByProfile) ([]ReleaseCase, error) {
	if len(profiles) == 0 || len(expected) != len(profiles) {
		return nil, fmt.Errorf("%s: expected observations must be given per declared profile", id)
	}
	var out []ReleaseCase
	for _, p := range profiles {
		e, ok := expected[p]
		if !ok {
			return nil, fmt.Errorf("%s: no independent expectation for %s", id, p)
		}
		raw, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		var copyOf SemanticResult
		if err = json.Unmarshal(raw, &copyOf); err != nil {
			return nil, err
		}
		out = append(out, ReleaseCase{ID: id, Profile: p, Input: input, Expected: copyOf})
	}
	return out, nil
}

// InputRecord is one pre-normalization or post-normalization sample/log input.
// Stale markers are Bits == StaleBits; histograms keep exact integer/bit fields.
type InputRecord struct {
	Kind      string            `json:"kind"`
	Timestamp string            `json:"timestamp"`
	Name      string            `json:"name,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Bits      string            `json:"bits,omitempty"`
	Histogram *Histogram        `json:"histogram,omitempty"`
	Line      string            `json:"line,omitempty"`
}

// NormalizationCheck pairs the inputs as authored with what the product saw
// after its translators/storage round trip.
type NormalizationCheck struct {
	ID         string        `json:"id"`
	Profile    string        `json:"profile"`
	Source     []InputRecord `json:"source"`
	Normalized []InputRecord `json:"normalized"`
}

// ScenarioOutcome is a persisted-path or isolation scenario actually run.
type ScenarioOutcome struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

type ProvenanceDecision struct {
	File     string `json:"file"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// InteractionCoverage is the generator's required-versus-covered accounting.
type InteractionCoverage struct {
	Required int      `json:"required"`
	Covered  int      `json:"covered"`
	Missing  []string `json:"missing,omitempty"`
}

type BuildIdentity struct {
	GoVersion string `json:"go_version"`
	Module    string `json:"module"`
	Revision  string `json:"vcs_revision"`
}

type OracleFunc func(ctx context.Context, profile SourceProfile, c ReleaseCase) (SemanticResult, error)
type OwnFunc func(ctx context.Context, c ReleaseCase) (SemanticResult, error)

type ReleaseConfig struct {
	Policy      ReleasePolicy
	Lock        SourceLock
	Ledger      Ledger
	Bindings    []Binding
	GateDomains []GateDomain
	Cases       []ReleaseCase
	Own         OwnFunc
	Oracle      OracleFunc // nil means no oracle is available
	Tests       []TestObservation
	Inputs      []NormalizationCheck
	Persistence []ScenarioOutcome
	Isolation   []ScenarioOutcome
	Provenance  []ProvenanceDecision
	Interaction InteractionCoverage
}

type MismatchRecord struct {
	Case    string `json:"case"`
	Profile string `json:"profile"`
	Side    string `json:"side"` // owned or oracle
	Field   string `json:"field"`
}

type ResourceStats struct {
	DurationNS     int64  `json:"duration_ns"`
	PeakHeapBytes  uint64 `json:"peak_heap_bytes"`
	TotalAllocated uint64 `json:"total_alloc_bytes"`
	Goroutines     int    `json:"goroutines"`
}

type Report struct {
	Profiles             map[string]string    `json:"profiles"` // id -> commit
	Configs              map[string]string    `json:"configs"`  // id -> oracle configuration digest
	FeatureSets          map[string]int       `json:"feature_sets"`
	Build                BuildIdentity        `json:"build"`
	InputNormalizationID string               `json:"input_normalization_identity"`
	ObligationCount      int                  `json:"obligation_count"`
	BoundCount           int                  `json:"bound_count"`
	UnboundCount         int                  `json:"unbound_count"`
	InteractionRequired  int                  `json:"interactions_required"`
	InteractionCovered   int                  `json:"interactions_covered"`
	RequiredCaseCount    int                  `json:"required_case_count"`
	MatchedCaseCount     int                  `json:"matched_case_count"`
	OracleRuns           int                  `json:"oracle_runs"`
	OracleUnavailable    int                  `json:"oracle_unavailable"`
	OracleUnverified     int                  `json:"oracle_unverified"`
	Mismatches           []MismatchRecord     `json:"mismatches"`
	UnrunCases           []string             `json:"unrun_cases"`
	SkippedCount         int                  `json:"skipped_count"`
	NormalizationLoss    int                  `json:"normalization_loss"`
	UnobservedTests      int                  `json:"unobserved_tests"`
	Provenance           []ProvenanceDecision `json:"provenance"`
	ProvenanceRejected   int                  `json:"provenance_rejected"`
	Persistence          []ScenarioOutcome    `json:"persistence"`
	Isolation            []ScenarioOutcome    `json:"isolation"`
	ScenarioFailures     int                  `json:"scenario_failures"`
	Resources            ResourceStats        `json:"resources"`
	UnresolvedCount      int                  `json:"unresolved_count"`
	Failures             []string             `json:"failures"`
}

// ErrReleaseRejected is returned (wrapped) whenever any count is nonzero.
var ErrReleaseRejected = errors.New("release gate rejected")

func canonical(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// normalizationLoss describes the first difference, or "" when lossless. Any
// change to timestamps, stale bits, histogram integer/bit fields, labels or
// lines is loss, as is a histogram becoming a float or stale becoming NaN.
func normalizationLoss(c NormalizationCheck) string {
	if len(c.Source) == 0 {
		return "no source inputs"
	}
	if len(c.Source) != len(c.Normalized) {
		return fmt.Sprintf("record count %d became %d", len(c.Source), len(c.Normalized))
	}
	for i := range c.Source {
		s, n := c.Source[i], c.Normalized[i]
		if s.Kind == "histogram" && (n.Kind != "histogram" || n.Histogram == nil) {
			return fmt.Sprintf("record %d: histogram lost its native form", i)
		}
		if s.Bits == StaleBits && n.Bits != StaleBits {
			return fmt.Sprintf("record %d: stale marker did not survive", i)
		}
		if canonical(s) != canonical(n) {
			return fmt.Sprintf("record %d changed", i)
		}
	}
	return ""
}

func bindingFault(o Obligation, b Binding, ok bool, passed map[string]bool) (unbound bool, unobserved int) {
	if !ok || b.Implementation == "" || strings.HasPrefix(b.Implementation, "pending") || len(b.GoTests) == 0 {
		return true, 0
	}
	cases := map[string]bool{}
	for _, c := range b.Cases {
		cases[c] = true
	}
	for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
		if len(group) == 0 {
			return true, 0
		}
		for _, c := range group {
			if !cases[c] {
				return true, 0
			}
		}
	}
	for _, name := range b.GoTests {
		if !strings.HasPrefix(name, "Test") || len(name) == 4 {
			return true, 0
		}
		if !passed[name] {
			unobserved++
		}
	}
	return false, unobserved
}

func oracleIdentityOK(p SourceProfile, r SemanticResult) bool {
	id := r.Oracle
	if p.Artifact == nil || id == nil || id.Profile != p.ID || id.ImageSHA256 != p.Artifact.SHA256 || id.ConfigurationSHA256 != p.Artifact.ConfigurationSHA256 {
		return false
	}
	version := strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-")
	return len(id.Revision) >= 7 && strings.HasPrefix(p.Commit, id.Revision) && strings.TrimPrefix(id.Version, "v") == version
}

// ReleaseGate never short-circuits: it counts every unresolved, skipped,
// unbound, unrun and mismatching item so the report is the evidence, and
// returns an error wrapping ErrReleaseRejected when any count is nonzero. An
// oracle failure, a skipped case or a lossy normalization is never a match.
func ReleaseGate(ctx context.Context, cfg ReleaseConfig) (Report, error) {
	started := time.Now()
	rep := Report{Profiles: map[string]string{}, Configs: map[string]string{}, FeatureSets: map[string]int{}, Mismatches: []MismatchRecord{}, UnrunCases: []string{}, Failures: []string{}}
	fail := func(format string, a ...any) { rep.Failures = append(rep.Failures, fmt.Sprintf(format, a...)) }
	if bi, ok := debug.ReadBuildInfo(); ok {
		rep.Build = BuildIdentity{GoVersion: bi.GoVersion, Module: bi.Main.Path}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				rep.Build.Revision = s.Value
			}
		}
	} else {
		rep.Build = BuildIdentity{GoVersion: runtime.Version()}
	}
	if err := cfg.Policy.Validate(); err != nil {
		fail("policy: %v", err)
	}
	if err := ValidateSourceLock(cfg.Lock); err != nil {
		fail("source lock: %v", err)
	}
	sources := map[string]SourceProfile{}
	for _, p := range cfg.Lock.Profiles {
		sources[p.ID] = p
		rep.Profiles[p.ID] = p.Commit
		if p.Artifact == nil || p.Artifact.Path != "sha256:"+p.Artifact.SHA256 || p.Artifact.Adapter != "oci-semantic-json-v1" || p.Artifact.Architecture != "linux/amd64" || len(p.Artifact.ConfigurationSHA256) != 64 {
			fail("profile %s lacks a locked oracle artifact", p.ID)
			continue
		}
		rep.Configs[p.ID] = p.Artifact.ConfigurationSHA256
	}
	for _, id := range cfg.Policy.AllProfiles {
		if _, ok := sources[id]; !ok {
			fail("profile %s is not in the source lock", id)
		}
	}
	// Feature-set closure: every gate combination of every profile.
	domains := map[string]bool{}
	for _, d := range cfg.GateDomains {
		if domains[d.Profile] {
			fail("duplicate gate domain %s", d.Profile)
		}
		domains[d.Profile] = true
		if err := ValidateGateClosure(d.Gates, d.FeatureSets); err != nil {
			fail("%s: %v", d.Profile, err)
		}
		rep.FeatureSets[d.Profile] = len(d.FeatureSets)
	}
	for _, id := range cfg.Policy.AllProfiles {
		if !domains[id] {
			fail("profile %s has no gate domain", id)
		}
	}
	// Obligation bindings.
	passed := map[string]bool{}
	for _, t := range cfg.Tests {
		hash, err := hex.DecodeString(t.EvidenceSHA256)
		if t.Name == "" || !t.Passed || t.Command == "" || err != nil || len(hash) != 32 {
			continue
		}
		passed[t.Name] = true
	}
	if !cfg.Ledger.Complete || len(cfg.Ledger.Missing) > 0 || len(cfg.Ledger.Obligations) == 0 {
		fail("inventory ledger incomplete")
	}
	byID := map[string]Binding{}
	for _, b := range cfg.Bindings {
		if _, dup := byID[b.ObligationID]; dup {
			fail("duplicate binding %s", b.ObligationID)
		}
		byID[b.ObligationID] = b
	}
	known := map[string]bool{}
	type required struct{ profile, id string }
	var needed []required
	seenNeed := map[required]bool{}
	for _, o := range cfg.Ledger.Obligations {
		known[o.ID] = true
		rep.ObligationCount++
		b, ok := byID[o.ID]
		unbound, unobserved := bindingFault(o, b, ok, passed)
		if unbound {
			rep.UnboundCount++
		} else {
			rep.BoundCount++
		}
		rep.UnobservedTests += unobserved
		for _, group := range [][]string{o.PositiveCases, o.NegativeCases, o.InteractionCases} {
			for _, c := range group {
				k := required{o.Profile, c}
				if !seenNeed[k] {
					seenNeed[k] = true
					needed = append(needed, k)
				}
			}
		}
	}
	for id := range byID {
		if !known[id] {
			rep.UnboundCount++
			fail("binding for unknown obligation %s", id)
		}
	}
	// Cases: authored, run against the oracle and the owned evaluator.
	authored := map[required]ReleaseCase{}
	for _, c := range cfg.Cases {
		k := required{c.Profile, c.ID}
		if _, dup := authored[k]; dup {
			fail("duplicate authored case %s/%s", c.Profile, c.ID)
		}
		authored[k] = c
	}
	rep.RequiredCaseCount = len(needed)
	for _, k := range needed {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		c, ok := authored[k]
		if !ok {
			rep.UnrunCases = append(rep.UnrunCases, k.profile+"/"+k.id)
			continue
		}
		if c.Skip != "" {
			rep.SkippedCount++
			rep.UnrunCases = append(rep.UnrunCases, k.profile+"/"+k.id)
			continue
		}
		ok = true
		if cfg.Oracle == nil {
			rep.OracleUnavailable++
			ok = false
		} else if src, known := sources[c.Profile]; !known {
			rep.OracleUnavailable++
			ok = false
		} else {
			rep.OracleRuns++
			ref, err := cfg.Oracle(ctx, src, c)
			switch {
			case err != nil:
				rep.OracleUnavailable++
				ok = false
			case !oracleIdentityOK(src, ref):
				rep.OracleUnverified++
				ok = false
			default:
				for _, m := range Compare(c.Expected, ref, c.Ordering) {
					rep.Mismatches = append(rep.Mismatches, MismatchRecord{c.ID, c.Profile, "oracle", m.Field})
					ok = false
				}
			}
		}
		if cfg.Own == nil {
			ok = false
		} else if got, err := cfg.Own(ctx, c); err != nil {
			rep.Mismatches = append(rep.Mismatches, MismatchRecord{c.ID, c.Profile, "owned", "error: " + err.Error()})
			ok = false
		} else {
			for _, m := range Compare(c.Expected, got, c.Ordering) {
				rep.Mismatches = append(rep.Mismatches, MismatchRecord{c.ID, c.Profile, "owned", m.Field})
				ok = false
			}
		}
		if !ok {
			rep.UnrunCases = append(rep.UnrunCases, k.profile+"/"+k.id)
			continue
		}
		rep.MatchedCaseCount++
	}
	sort.Strings(rep.UnrunCases)
	// Input normalization.
	rep.InputNormalizationID = sha256Hex(canonical(cfg.Inputs))
	if len(cfg.Inputs) == 0 {
		fail("no input normalization checks")
	}
	for _, c := range cfg.Inputs {
		if why := normalizationLoss(c); why != "" {
			rep.NormalizationLoss++
			fail("input normalization %s/%s: %s", c.Profile, c.ID, why)
		}
	}
	// Provenance, persistence, isolation, interactions.
	rep.Provenance = cfg.Provenance
	if len(cfg.Provenance) == 0 {
		fail("no provenance decisions")
	}
	for _, d := range cfg.Provenance {
		if !d.Accepted {
			rep.ProvenanceRejected++
			fail("provenance %s rejected: %s", d.File, d.Reason)
		}
	}
	rep.Persistence, rep.Isolation = cfg.Persistence, cfg.Isolation
	rep.ScenarioFailures += scenarioFailures("persistence", cfg.Policy.RequiredPersistence, cfg.Persistence, fail)
	rep.ScenarioFailures += scenarioFailures("isolation", cfg.Policy.RequiredIsolation, cfg.Isolation, fail)
	rep.InteractionRequired, rep.InteractionCovered = cfg.Interaction.Required, cfg.Interaction.Covered
	if cfg.Interaction.Required == 0 || cfg.Interaction.Covered != cfg.Interaction.Required || len(cfg.Interaction.Missing) > 0 {
		fail("interaction coverage %d of %d", cfg.Interaction.Covered, cfg.Interaction.Required)
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	rep.Resources = ResourceStats{DurationNS: time.Since(started).Nanoseconds(), PeakHeapBytes: mem.HeapSys, TotalAllocated: mem.TotalAlloc, Goroutines: runtime.NumGoroutine()}
	rep.UnresolvedCount = rep.UnboundCount + len(rep.UnrunCases) + rep.SkippedCount + len(rep.Mismatches) + rep.UnobservedTests + rep.OracleUnverified + len(rep.Failures)
	if rep.UnresolvedCount != 0 {
		return rep, fmt.Errorf("%w: %d unresolved (unbound %d, unrun %d, skipped %d, mismatches %d, normalization loss %d)", ErrReleaseRejected, rep.UnresolvedCount, rep.UnboundCount, len(rep.UnrunCases), rep.SkippedCount, len(rep.Mismatches), rep.NormalizationLoss)
	}
	return rep, nil
}

func scenarioFailures(kind string, required []string, got []ScenarioOutcome, fail func(string, ...any)) int {
	by := map[string]ScenarioOutcome{}
	for _, s := range got {
		by[s.Name] = s
	}
	n := 0
	for _, name := range required {
		s, ok := by[name]
		if !ok {
			n++
			fail("%s scenario %s did not run", kind, name)
		} else if !s.Passed {
			n++
			fail("%s scenario %s failed: %s", kind, name, s.Detail)
		}
	}
	return n
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// MarshalReport renders the machine-readable report.
func MarshalReport(r Report) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetIndent("", "  ")
	if err := e.Encode(r); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
