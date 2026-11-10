// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package qualify orchestrates release qualification campaigns. The query
// campaign executes plan 02's locked soundpost-querycheck release and smoke
// commands and verifies the reports they wrote against a required matrix. It
// never compares query semantics, never normalizes inputs and never turns an
// upstream HTTP surface into a product contract: every verdict is read from the
// reports the locked tooling produced.
package qualify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	q "soundpost/internal/conformance/query"
)

// Required layouts of the persisted path.
const (
	LayoutSingle      = "single"
	LayoutDistributed = "distributed"
)

// RequiredLayouts are the persisted layouts every campaign must cover.
var RequiredLayouts = []string{LayoutSingle, LayoutDistributed}

// ErrCampaignRejected is returned (wrapped) unless every required row is verified.
var ErrCampaignRejected = errors.New("query campaign rejected")

// MatrixProfile pins one language profile: its manifest commit, the oracle
// configuration digest and every registered FeatureSet.
type MatrixProfile struct {
	ID            string   `yaml:"id"`
	Commit        string   `yaml:"commit"`
	ConfigSHA256  string   `yaml:"config_sha256"`
	FeatureSetIDs []string `yaml:"feature_sets"`
}

// MatrixRow is one required piece of evidence. Kind "release" binds a profile
// and a seed to a release report; kind "smoke" binds a layout to a smoke report.
// ReportSHA256 optionally pins the report bytes; the campaign always records the
// actual digest.
type MatrixRow struct {
	ID           string `yaml:"id"`
	Kind         string `yaml:"kind"`
	Profile      string `yaml:"profile,omitempty"`
	Seed         uint64 `yaml:"seed,omitempty"`
	Layout       string `yaml:"layout,omitempty"`
	Report       string `yaml:"report"`
	ReportSHA256 string `yaml:"report_sha256,omitempty"`
}

// QueryMatrix is the declarative list of required campaign evidence.
type QueryMatrix struct {
	Schema                     string          `yaml:"schema"`
	Root                       string          `yaml:"root"`
	Tool                       []string        `yaml:"tool,omitempty"`
	Runtime                    string          `yaml:"runtime,omitempty"`
	Policy                     string          `yaml:"policy"`
	ProfilesDir                string          `yaml:"profiles_dir"`
	SmokeCases                 []string        `yaml:"smoke_cases"`
	Seeds                      []uint64        `yaml:"seeds"`
	InputNormalizationIdentity string          `yaml:"input_normalization_identity"`
	Profiles                   []MatrixProfile `yaml:"profiles"`
	Rows                       []MatrixRow     `yaml:"rows"`
}

// LoadQueryMatrix reads a matrix; Root is resolved against the matrix file.
func LoadQueryMatrix(path string) (QueryMatrix, error) {
	var m QueryMatrix
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err = dec.Decode(&m); err != nil {
		return m, fmt.Errorf("%s: %w", path, err)
	}
	if m.Root == "" {
		m.Root = "."
	}
	if !filepath.IsAbs(m.Root) {
		m.Root = filepath.Join(filepath.Dir(path), m.Root)
	}
	return m, nil
}

// Counts aggregates what the verified reports state. Release counts are summed
// over distinct release reports; smoke counts over distinct smoke reports.
type Counts struct {
	Unbound           int `json:"unbound"`
	Unrun             int `json:"unrun"`
	Skipped           int `json:"skipped"`
	Mismatches        int `json:"mismatches"`
	NormalizationLoss int `json:"normalization_loss"`
	OracleUnavailable int `json:"oracle_unavailable"`
	OracleUnverified  int `json:"oracle_unverified"`
	UnobservedTests   int `json:"unobserved_tests"`
	ProvenanceRefused int `json:"provenance_rejected"`
	ScenarioFailures  int `json:"scenario_failures"`
	Unresolved        int `json:"unresolved"`
	FailingSteps      int `json:"failing_steps"`
	NotSatisfied      int `json:"not_satisfied"`
	ModesNotRun       int `json:"modes_not_run"`
}

// RowResult binds one required row to the report that was actually read.
type RowResult struct {
	ID                   string   `json:"id"`
	Kind                 string   `json:"kind"`
	Profile              string   `json:"profile,omitempty"`
	Seed                 uint64   `json:"seed,omitempty"`
	Layout               string   `json:"layout,omitempty"`
	Report               string   `json:"report"`
	ReportSHA256         string   `json:"report_sha256,omitempty"`
	ProfileCommit        string   `json:"profile_commit,omitempty"`
	OracleConfigSHA256   string   `json:"oracle_config_sha256,omitempty"`
	FeatureSets          int      `json:"feature_sets,omitempty"`
	InputNormalizationID string   `json:"input_normalization_identity,omitempty"`
	Build                string   `json:"build,omitempty"`
	ExitCode             *int     `json:"exit_code,omitempty"`
	Verified             bool     `json:"verified"`
	Failures             []string `json:"failures,omitempty"`
}

// CampaignReport maps every required matrix row to a verified actual report.
type CampaignReport struct {
	Schema   string      `json:"schema"`
	Rows     []RowResult `json:"rows"`
	Counts   Counts      `json:"counts"`
	Missing  []string    `json:"missing_evidence"`
	Failures []string    `json:"failures"`
	Verified bool        `json:"verified"`
}

// RunQueryConformance executes the locked smoke (one run per required layout)
// and release (one run per seed) commands, writes their reports under
// artifactDir, and verifies every required row. The returned error wraps
// ErrCampaignRejected unless every required row is verified.
func RunQueryConformance(ctx context.Context, matrix QueryMatrix, artifactDir string) (CampaignReport, error) {
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return CampaignReport{}, err
	}
	exits := map[string]int{}
	// Rows are the source of truth for what must be produced; a missing row is
	// reported by verification, never executed around.
	smokeFor := map[string]string{}
	releaseFor := map[uint64]string{}
	for _, r := range matrix.Rows {
		switch r.Kind {
		case "smoke":
			smokeFor[r.Layout] = r.Report
		case "release":
			releaseFor[r.Seed] = r.Report
		}
	}
	var execErrs []string
	layouts := sortedKeys(smokeFor)
	for _, layout := range layouts {
		out := filepath.Join(artifactDir, smokeFor[layout])
		args := []string{"smoke", "--storage", "real", "--control", "real", "--own-http", "--restart", "--compact",
			"--modes", layout, "--module-root", matrix.Root, "--cases", casesArg(matrix), "--report", out}
		code, err := runTool(ctx, matrix, args, artifactDir)
		if err != nil {
			execErrs = append(execErrs, fmt.Sprintf("smoke %s: %v", layout, err))
		}
		exits["smoke/"+layout] = code
	}
	// Release gates consume the single-layout smoke report: they never accept a
	// synthesized one. Without it the gate runs without scenario evidence.
	smokeReport := ""
	if p, ok := smokeFor[LayoutSingle]; ok {
		if _, err := os.Stat(filepath.Join(artifactDir, p)); err == nil {
			smokeReport = filepath.Join(artifactDir, p)
		}
	}
	var seeds []uint64
	for s := range releaseFor {
		seeds = append(seeds, s)
	}
	sort.Slice(seeds, func(i, j int) bool { return seeds[i] < seeds[j] })
	for _, seed := range seeds {
		out := filepath.Join(artifactDir, releaseFor[seed])
		args := []string{"release", "--policy", matrix.Policy, "--all-profiles", "--all-feature-sets", "--require-locked",
			"--require-zero-unbound", "--require-zero-skips", "--require-zero-mismatches",
			"--seed", strconv.FormatUint(seed, 10), "--report", out}
		if smokeReport != "" {
			args = append(args, "--smoke-report", smokeReport)
		}
		if matrix.Runtime != "" {
			args = append(args, "--runtime", matrix.Runtime)
		}
		code, err := runTool(ctx, matrix, args, artifactDir)
		if err != nil {
			execErrs = append(execErrs, fmt.Sprintf("release seed %d: %v", seed, err))
		}
		exits["release/seed/"+strconv.FormatUint(seed, 10)] = code
	}
	rep := verify(matrix, artifactDir, exits)
	rep.Failures = append(rep.Failures, execErrs...)
	rep.Verified = rep.Verified && len(execErrs) == 0
	return finish(rep, artifactDir)
}

// VerifyQueryEvidence verifies report files already on disk against the matrix
// without running anything. It is what RunQueryConformance applies after running.
func VerifyQueryEvidence(matrix QueryMatrix, artifactDir string) (CampaignReport, error) {
	return finish(verify(matrix, artifactDir, nil), artifactDir)
}

func finish(rep CampaignReport, artifactDir string) (CampaignReport, error) {
	if raw, err := json.MarshalIndent(rep, "", "  "); err == nil {
		if err = os.WriteFile(filepath.Join(artifactDir, "campaign-report.json"), append(raw, '\n'), 0o644); err != nil {
			return rep, err
		}
	}
	if rep.Verified {
		return rep, nil
	}
	return rep, fmt.Errorf("%w: %s", ErrCampaignRejected, rep.Summary())
}

// Summary lists every missing item and every failing row.
func (r CampaignReport) Summary() string {
	var b strings.Builder
	for _, m := range r.Missing {
		fmt.Fprintf(&b, "\nMISSING %s", m)
	}
	for _, f := range r.Failures {
		fmt.Fprintf(&b, "\nFAIL %s", f)
	}
	for _, row := range r.Rows {
		if row.Verified {
			continue
		}
		for _, f := range row.Failures {
			fmt.Fprintf(&b, "\nFAIL %s: %s", row.ID, f)
		}
	}
	c := r.Counts
	fmt.Fprintf(&b, "\nTOTAL unbound %d, unrun %d, skipped %d, mismatches %d, normalization loss %d, unresolved %d, failing steps %d, not satisfied %d, modes not run %d",
		c.Unbound, c.Unrun, c.Skipped, c.Mismatches, c.NormalizationLoss, c.Unresolved, c.FailingSteps, c.NotSatisfied, c.ModesNotRun)
	return b.String()
}

func casesArg(m QueryMatrix) string { return strings.Join(m.SmokeCases, ",") }

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// runTool runs the locked command. A nonzero exit is not an error here: the
// report it wrote is the evidence and the exit code is recorded and checked.
func runTool(ctx context.Context, m QueryMatrix, args []string, dir string) (int, error) {
	tool := m.Tool
	if len(tool) == 0 {
		tool = []string{"go", "run", "./cmd/soundpost-querycheck"}
	}
	cmd := exec.CommandContext(ctx, tool[0], append(append([]string{}, tool[1:]...), args...)...)
	cmd.Dir = m.Root
	// stdout repeats the report file; keep only the run log next to the artifacts.
	name := "run-" + args[0] + "-" + strings.NewReplacer("/", "_", ",", "_").Replace(argValue(args, "--modes", argValue(args, "--seed", ""))) + ".log"
	if f, err := os.Create(filepath.Join(dir, name)); err == nil {
		defer f.Close()
		cmd.Stderr = f
	}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee):
		return ee.ExitCode(), nil
	default:
		return -1, err
	}
}

func argValue(args []string, name, def string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return def
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type policyFile struct {
	AllProfiles        []string `json:"all_profiles"`
	RequiredPersistent []string `json:"required_persistence"`
	RequiredIsolation  []string `json:"required_isolation"`
}

type manifestFile struct {
	ID          string `json:"id"`
	Commit      string `json:"commit"`
	FeatureSets []struct {
		ID string `json:"id"`
	} `json:"feature_sets"`
}

// verify checks the matrix itself against the locked policy and manifests, then
// every row against the report on disk. exits may be nil (files only).
func verify(m QueryMatrix, artifactDir string, exits map[string]int) CampaignReport {
	rep := CampaignReport{Schema: "soundpost-query-campaign/1", Missing: []string{}, Failures: []string{}, Rows: []RowResult{}}
	var policy policyFile
	if err := q.ReadJSON(filepath.Join(m.Root, filepath.FromSlash(m.Policy)), &policy); err != nil {
		rep.Failures = append(rep.Failures, "release policy unreadable: "+err.Error())
		return rep
	}
	if len(policy.AllProfiles) == 0 {
		rep.Failures = append(rep.Failures, "release policy names no profiles")
	}
	if len(m.Seeds) == 0 {
		rep.Missing = append(rep.Missing, "no seeds in the matrix")
	}
	if len(m.SmokeCases) == 0 {
		rep.Missing = append(rep.Missing, "no smoke case files in the matrix")
	}
	// Profiles: every policy profile needs a matrix pin that agrees with the manifest.
	pins := map[string]MatrixProfile{}
	for _, p := range m.Profiles {
		if _, dup := pins[p.ID]; dup {
			rep.Failures = append(rep.Failures, "duplicate profile entry "+p.ID)
		}
		pins[p.ID] = p
	}
	for _, id := range policy.AllProfiles {
		pin, ok := pins[id]
		if !ok {
			rep.Missing = append(rep.Missing, fmt.Sprintf("profile %s has no entry (required by release policy)", id))
			continue
		}
		var mf manifestFile
		if err := q.ReadJSON(filepath.Join(m.Root, filepath.FromSlash(m.ProfilesDir), id+".json"), &mf); err != nil {
			rep.Failures = append(rep.Failures, fmt.Sprintf("profile %s manifest unreadable: %v", id, err))
			continue
		}
		if mf.Commit != pin.Commit {
			rep.Failures = append(rep.Failures, fmt.Sprintf("profile %s commit pin %q differs from manifest %q", id, pin.Commit, mf.Commit))
		}
		have := map[string]bool{}
		for _, fs := range pin.FeatureSetIDs {
			have[fs] = true
		}
		manifestIDs := map[string]bool{}
		for _, fs := range mf.FeatureSets {
			manifestIDs[fs.ID] = true
			if !have[fs.ID] {
				rep.Missing = append(rep.Missing, fmt.Sprintf("profile %s FeatureSet %s is registered in the manifest but absent from the matrix", id, fs.ID))
			}
		}
		for _, fs := range pin.FeatureSetIDs {
			if !manifestIDs[fs] {
				rep.Failures = append(rep.Failures, fmt.Sprintf("profile %s FeatureSet %s in the matrix is not registered in the manifest", id, fs))
			}
		}
	}
	for id := range pins {
		known := false
		for _, p := range policy.AllProfiles {
			known = known || p == id
		}
		if !known {
			rep.Failures = append(rep.Failures, fmt.Sprintf("profile %s is not in the release policy", id))
		}
	}
	// Required rows.
	type key struct {
		kind, profile, layout string
		seed                  uint64
	}
	required := map[key]string{}
	for _, seed := range m.Seeds {
		for _, id := range policy.AllProfiles {
			required[key{kind: "release", profile: id, seed: seed}] = fmt.Sprintf("release/%s/seed/%d", id, seed)
		}
	}
	for _, l := range RequiredLayouts {
		required[key{kind: "smoke", layout: l}] = "smoke/" + l
	}
	seen := map[key]bool{}
	ids := map[string]bool{}
	pathKind := map[string]key{}
	var rows []MatrixRow
	for _, r := range m.Rows {
		k := key{kind: r.Kind, profile: r.Profile, layout: r.Layout, seed: r.Seed}
		if _, ok := required[k]; !ok {
			rep.Failures = append(rep.Failures, fmt.Sprintf("row %q (kind %s profile %q layout %q seed %d) is not a required row", r.ID, r.Kind, r.Profile, r.Layout, r.Seed))
			continue
		}
		if seen[k] || ids[r.ID] {
			rep.Failures = append(rep.Failures, fmt.Sprintf("duplicate row %q for %s", r.ID, required[k]))
			continue
		}
		seen[k], ids[r.ID] = true, true
		pk := key{kind: k.kind, layout: k.layout, seed: k.seed}
		if prev, ok := pathKind[r.Report]; ok && prev != pk {
			rep.Failures = append(rep.Failures, fmt.Sprintf("row %q: report file %s is already bound to a different kind/seed/layout", r.ID, r.Report))
			continue
		}
		pathKind[r.Report] = pk
		rows = append(rows, r)
	}
	var missingKeys []string
	for k, id := range required {
		if !seen[k] {
			missingKeys = append(missingKeys, fmt.Sprintf("row %s (profile %q, seed %d, layout %q): no required row in the matrix", id, k.profile, k.seed, k.layout))
		}
	}
	sort.Strings(missingKeys)
	rep.Missing = append(rep.Missing, missingKeys...)

	distinct := map[string]bool{}
	for _, r := range rows {
		res := RowResult{ID: r.ID, Kind: r.Kind, Profile: r.Profile, Seed: r.Seed, Layout: r.Layout, Report: r.Report}
		exitKey := "smoke/" + r.Layout
		if r.Kind == "release" {
			exitKey = "release/seed/" + strconv.FormatUint(r.Seed, 10)
		}
		if code, ok := exits[exitKey]; ok {
			c := code
			res.ExitCode = &c
		}
		raw, err := os.ReadFile(filepath.Join(artifactDir, r.Report))
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("report file %s absent or unreadable: %v", r.Report, err))
			rep.Rows = append(rep.Rows, res)
			continue
		}
		res.ReportSHA256 = sha(raw)
		if r.ReportSHA256 != "" && r.ReportSHA256 != res.ReportSHA256 {
			res.Failures = append(res.Failures, fmt.Sprintf("report digest mismatch for %s: matrix %s, actual %s", r.Report, r.ReportSHA256, res.ReportSHA256))
		}
		agg := !distinct[exitKey+"|"+r.Report]
		distinct[exitKey+"|"+r.Report] = true
		switch r.Kind {
		case "release":
			verifyRelease(&res, raw, pins[r.Profile], m, exits, agg, &rep.Counts)
		case "smoke":
			verifySmoke(&res, raw, m, policy, agg, &rep.Counts)
		}
		res.Verified = len(res.Failures) == 0
		rep.Rows = append(rep.Rows, res)
	}
	rep.Verified = len(rep.Missing) == 0 && len(rep.Failures) == 0
	for _, r := range rep.Rows {
		rep.Verified = rep.Verified && r.Verified
	}
	return rep
}

func verifyRelease(res *RowResult, raw []byte, pin MatrixProfile, m QueryMatrix, exits map[string]int, aggregate bool, c *Counts) {
	fail := func(f string, a ...any) { res.Failures = append(res.Failures, fmt.Sprintf(f, a...)) }
	var r q.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		fail("report %s is not a parsable release report: %v", res.Report, err)
		return
	}
	if len(r.Profiles) == 0 {
		fail("report %s carries no profiles: not a release report", res.Report)
		return
	}
	p := res.Profile
	commit, ok := r.Profiles[p]
	if !ok {
		fail("report %s has no profile %s (report is for %v): digest pair matrix %s / report absent", res.Report, p, sortedProfileKeys(r.Profiles), pin.ConfigSHA256)
		return
	}
	res.ProfileCommit, res.OracleConfigSHA256, res.FeatureSets = commit, r.Configs[p], r.FeatureSets[p]
	res.InputNormalizationID = r.InputNormalizationID
	res.Build = fmt.Sprintf("%s %s rev %q", r.Build.Module, r.Build.GoVersion, r.Build.Revision)
	if commit != pin.Commit {
		fail("profile %s commit: matrix %s, report %s", p, pin.Commit, commit)
	}
	if r.Configs[p] != pin.ConfigSHA256 {
		fail("profile %s oracle configuration digest mismatch: matrix %s, report %s", p, pin.ConfigSHA256, r.Configs[p])
	}
	if r.FeatureSets[p] != len(pin.FeatureSetIDs) {
		fail("profile %s FeatureSet count: matrix %d, report %d", p, len(pin.FeatureSetIDs), r.FeatureSets[p])
	}
	if m.InputNormalizationIdentity == "" {
		fail("matrix pins no input-normalization identity")
	} else if r.InputNormalizationID != m.InputNormalizationIdentity {
		fail("input-normalization identity: matrix %s, report %s", m.InputNormalizationIdentity, r.InputNormalizationID)
	}
	if r.Build.Module != "soundpost" || r.Build.GoVersion == "" {
		fail("build identity incomplete: %+v", r.Build)
	}
	if len(r.Profiles) != len(m.Profiles) {
		fail("report covers %d profiles, matrix requires %d", len(r.Profiles), len(m.Profiles))
	}
	unrun := len(r.UnrunCases)
	if d := r.RequiredCaseCount - r.MatchedCaseCount; d > unrun {
		unrun = d
	}
	if r.UnboundCount > 0 || r.BoundCount != r.ObligationCount {
		fail("obligations: %d bound of %d, unbound %d", r.BoundCount, r.ObligationCount, r.UnboundCount)
	}
	if unrun > 0 {
		fail("cases: %d unrun (%d matched of %d required)", unrun, r.MatchedCaseCount, r.RequiredCaseCount)
	}
	if r.RequiredCaseCount == 0 || r.ObligationCount == 0 {
		fail("report requires no cases or obligations: empty evidence")
	}
	if r.SkippedCount > 0 {
		fail("skipped %d", r.SkippedCount)
	}
	if len(r.Mismatches) > 0 {
		fail("mismatches %d", len(r.Mismatches))
	}
	if r.NormalizationLoss > 0 {
		fail("normalization loss %d", r.NormalizationLoss)
	}
	if r.OracleUnavailable > 0 || r.OracleUnverified > 0 || r.OracleRuns == 0 {
		fail("oracle observation: runs %d, unavailable %d, unverified %d", r.OracleRuns, r.OracleUnavailable, r.OracleUnverified)
	}
	if r.UnobservedTests > 0 {
		fail("unobserved Go tests %d", r.UnobservedTests)
	}
	if r.ProvenanceRejected > 0 {
		fail("provenance rejected %d", r.ProvenanceRejected)
	}
	if r.ScenarioFailures > 0 {
		fail("scenario failures %d", r.ScenarioFailures)
	}
	if r.InteractionCovered < r.InteractionRequired || r.InteractionRequired == 0 {
		fail("interactions: %d covered of %d required", r.InteractionCovered, r.InteractionRequired)
	}
	if r.UnresolvedCount > 0 {
		fail("unresolved %d", r.UnresolvedCount)
	}
	for _, f := range r.Failures {
		fail("gate failure: %s", f)
	}
	if code, ok := exits["release/seed/"+strconv.FormatUint(res.Seed, 10)]; ok && code != 0 {
		fail("soundpost-querycheck release exited %d", code)
	}
	if aggregate {
		c.Unbound += r.UnboundCount
		c.Unrun += unrun
		c.Skipped += r.SkippedCount
		c.Mismatches += len(r.Mismatches)
		c.NormalizationLoss += r.NormalizationLoss
		c.OracleUnavailable += r.OracleUnavailable
		c.OracleUnverified += r.OracleUnverified
		c.UnobservedTests += r.UnobservedTests
		c.ProvenanceRefused += r.ProvenanceRejected
		c.ScenarioFailures += r.ScenarioFailures
		c.Unresolved += r.UnresolvedCount
	}
}

func verifySmoke(res *RowResult, raw []byte, m QueryMatrix, policy policyFile, aggregate bool, c *Counts) {
	fail := func(f string, a ...any) { res.Failures = append(res.Failures, fmt.Sprintf(f, a...)) }
	var s q.SmokeReport
	if err := json.Unmarshal(raw, &s); err != nil {
		fail("report %s is not a parsable smoke report: %v", res.Report, err)
		return
	}
	if s.Schema != "soundpost-smoke-report/1" {
		fail("report %s schema %q is not a smoke report", res.Report, s.Schema)
		return
	}
	if s.Storage != "real" || s.Control != "real" {
		fail("smoke ran with storage %q control %q, not real", s.Storage, s.Control)
	}
	ran := false
	for _, mode := range s.Modes {
		ran = ran || mode == res.Layout
	}
	if !ran {
		fail("layout %s did not run (modes run %v)", res.Layout, s.Modes)
	}
	for _, mode := range s.ModesNotRun {
		if mode == res.Layout {
			fail("layout %s recorded as not run", res.Layout)
		}
	}
	want := map[string]bool{}
	for _, cf := range m.SmokeCases {
		want[filepath.Base(cf)] = true
	}
	got := map[string]bool{}
	for _, cf := range s.CaseFiles {
		got[filepath.Base(cf)] = true
	}
	for cf := range want {
		if !got[cf] {
			fail("smoke case file %s was not run", cf)
		}
	}
	// A step the runner could not run is Passed=false and listed in NotSatisfied
	// under its own name; that is an unmet requirement, not a failing step.
	failing := 0
	for _, st := range s.Steps {
		if st.Passed {
			continue
		}
		notRun := false
		for _, n := range s.NotSatisfied {
			notRun = notRun || strings.HasPrefix(n, st.Name+": ")
		}
		if !notRun {
			failing++
		}
	}
	if len(s.Steps) == 0 {
		fail("smoke report has no steps")
	}
	if failing > 0 {
		fail("%d failing smoke steps", failing)
	}
	need := func(kind string, required []string, have []q.ScenarioOutcome) {
		by := map[string]bool{}
		for _, o := range have {
			by[o.Name] = o.Passed
		}
		for _, name := range required {
			if p, ok := by[name]; !ok {
				fail("%s scenario %s absent from the smoke report", kind, name)
			} else if !p {
				fail("%s scenario %s failed", kind, name)
			}
		}
	}
	need("persistence", policy.RequiredPersistent, s.Persistence)
	need("isolation", policy.RequiredIsolation, s.Isolation)
	for _, n := range s.NotSatisfied {
		fail("NOT satisfied: %s", n)
	}
	if aggregate {
		c.FailingSteps += failing
		c.NotSatisfied += len(s.NotSatisfied)
		c.ModesNotRun += len(s.ModesNotRun)
	}
}

func sortedProfileKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
