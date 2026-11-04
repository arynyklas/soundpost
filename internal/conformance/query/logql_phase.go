// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"soundpost/internal/query/profile"
)

type LogQLComparison struct {
	ID              string           `json:"id"`
	ProfileIdentity string           `json:"profile_identity"`
	FeatureSet      string           `json:"feature_set"`
	Oracle          *OracleIdentity  `json:"oracle"`
	Owned           LogQLObservation `json:"owned"`
	Reference       LogQLObservation `json:"reference"`
	Mismatches      []Mismatch       `json:"mismatches"`
}
type LogQLHarnessFailure struct {
	Stage         string   `json:"stage"`
	Class         string   `json:"class"`
	Message       string   `json:"message"`
	UnobservedIDs []string `json:"unobserved_ids"`
}
type LogQLPhaseReport struct {
	Phase          string               `json:"phase"`
	Compared       int                  `json:"compared"`
	Failed         int                  `json:"failed"`
	Cases          []LogQLComparison    `json:"cases"`
	Failure        *LogQLHarnessFailure `json:"failure,omitempty"`
	Qualification  string               `json:"qualification"`
	Compiler       string               `json:"reference_compiler"`
	SourceSHA256   string               `json:"reference_source_sha256"`
	TimezoneSHA256 string               `json:"controlled_timezone_sha256,omitempty"`
}

func readLogQLCases(lock SourceLock, path, phase string) ([]LogQLCase, error) {
	var document struct {
		Schema        string      `json:"schema"`
		Phase         string      `json:"phase"`
		Phases        []string    `json:"phases"`
		Copyright     string      `json:"copyright"`
		License       string      `json:"license"`
		Author        string      `json:"author"`
		Authorship    string      `json:"authorship"`
		ClockContract string      `json:"clock_contract"`
		Cases         []LogQLCase `json:"cases"`
	}
	// Strictly decode the bytes that were actually content-locked. A temporary raw
	// value prevents an alternate path from escaping the approved named artifact.
	var raw json.RawMessage
	key := "cases/" + filepath.Base(path)
	if err := ReadLockedJSON(lock, key, path, &raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	if document.Schema != "" && document.Schema != "soundpost-authored-logql-cases-v1" && document.Schema != "soundpost-authored-logql-metric-cases-v1" {
		return nil, fmt.Errorf("unknown authored LogQL case schema")
	}
	wanted := map[string]bool{}
	for _, p := range strings.Split(phase, ",") {
		if p != "syntax" && p != "pipeline" && p != "logql-template" && p != "logql-metric" {
			return nil, fmt.Errorf("unknown LogQL comparison phase")
		}
		wanted[p] = true
	}
	var out []LogQLCase
	seen := map[string]bool{}
	observed := map[string]bool{}
	for _, c := range document.Cases {
		if c.Phase == "" {
			c.Phase = document.Phase
		}
		if !wanted[c.Phase] {
			continue
		}
		if err := validateLogQLCase(c); err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		if seen[c.ID] {
			return nil, fmt.Errorf("duplicate LogQL input row %s", c.ID)
		}
		seen[c.ID] = true
		out = append(out, c)
		observed[c.Phase] = true
	}
	if len(observed) != len(wanted) || len(out) == 0 {
		return nil, fmt.Errorf("requested LogQL phase has no applicable authored rows")
	}
	return out, nil
}
func resolveLogQLProfile(path string, enabled []string) (profile.Profile, error) {
	registry, e := profile.Load(os.DirFS(path))
	if e != nil {
		return profile.Profile{}, e
	}
	var manifest profile.Profile
	if e = ReadJSON(filepath.Join(path, logQLProfile+".json"), &manifest); e != nil {
		return profile.Profile{}, e
	}
	target := append([]string(nil), enabled...)
	sort.Strings(target)
	for i := 1; i < len(target); i++ {
		if target[i] == target[i-1] {
			return profile.Profile{}, fmt.Errorf("duplicate LogQL feature")
		}
	}
	setID := ""
	for _, set := range manifest.FeatureSets {
		candidate := append([]string(nil), set.Enabled...)
		sort.Strings(candidate)
		if logQLFeatureKey(candidate) == logQLFeatureKey(target) {
			if setID != "" {
				return profile.Profile{}, fmt.Errorf("ambiguous LogQL feature set")
			}
			setID = set.ID
		}
	}
	if setID == "" {
		return profile.Profile{}, fmt.Errorf("unregistered LogQL feature combination")
	}
	return registry.Resolve(logQLProfile, setID)
}
func RunLogQLPhase(ctx context.Context, lock SourceLock, casesPath, profilesPath, runtime, phase string) (LogQLPhaseReport, error) {
	report := LogQLPhaseReport{Phase: phase, Qualification: "Development-only actual pinned native Loki parser, pipelines, helpers and evaluator. Only observed rows/selected feature sets qualify. Native error prose is retained, never compared as HTTP parity; unclassified error families fail. No float tolerance, timestamp rounding, hidden labels, output sorting or multiplicity removal. Actual native evaluator sample timestamps retain its millisecond domain; owned values are not rounded. Named TZ uses explicitly controlled Go1.24.5 dataset; stock artifact default-TZ equivalence remains unqualified. Wall-clock observations use declared per-process real brackets, not evaluation time; no injected native clock is claimed."}
	report.Qualification += " Native fixture source stream hashes are computed by actual pinned labels.Hash on original labels; source merge/order/interval/limit are actual native code. Raw native grouped Streams (which lose hashes in engine.readStreams) are authoritative and retained. A global native result representation bridge uses actual iter.NewStreamsIterator; owned selected stored-row sequence is retained separately and is not sorted to conceal cross-stream tied representation differences."
	if e := ValidateSourceLock(lock); e != nil {
		return report, e
	}
	if _, e := Inventory(ctx, lock); e != nil {
		return report, e
	}
	cases, e := readLogQLCases(lock, casesPath, phase)
	if e != nil {
		return report, e
	}
	snapshot, cleanup, e := snapshotEvaluationProfiles(lock, profilesPath)
	if e != nil {
		return report, e
	}
	defer cleanup()
	var source SourceProfile
	for _, p := range lock.Profiles {
		if p.ID == logQLProfile {
			source = p
		}
	}
	if source.Commit != logQLCommit || source.SourceSHA256 != logQLSourceSHA || source.Artifact == nil {
		return report, fmt.Errorf("exact native Loki source/artifact required")
	}
	configuration, e := os.ReadFile(source.ConfigurationPath)
	if e != nil {
		return report, e
	}
	groups := map[string][]LogQLCase{}
	for _, c := range cases {
		enabled := append([]string(nil), c.Enabled...)
		sort.Strings(enabled)
		key := logQLFeatureKey(enabled)
		groups[key] = append(groups[key], c)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		rows := groups[key]
		p, e := resolveLogQLProfile(snapshot, rows[0].Enabled)
		if e != nil {
			return report, e
		}
		in := LogQLInput{Profile: p.ID, Commit: p.Commit, ProfileIdentity: p.Identity, FeatureSet: p.ActiveFeatureSet.ID, ConfigurationHash: p.ConfigurationHash, Enabled: p.ActiveFeatureSet.Enabled, Phase: phase, Cases: rows}
		if in.Lookback, e = logQLConfigurationInt(p, "instant_log_lookback_ns"); e != nil {
			return report, e
		}
		heap, e := logQLConfigurationInt(p, "count_min_sketch_heap_size")
		if e != nil || heap > int64(^uint(0)>>1) {
			return report, fmt.Errorf("invalid sketch heap configuration")
		}
		in.SketchHeap = int(heap)
		for _, c := range rows {
			for key, want := range c.Configuration {
				var actual string
				if json.Unmarshal(p.Configuration[key], &actual) != nil || actual != want {
					return report, fmt.Errorf("case %s configuration %s differs from resolved profile", c.ID, key)
				}
			}
		}
		for _, c := range rows {
			if c.Phase == "logql-template" {
				_, hash, e := loadLogQLLocation(c.Timezone, p)
				if e != nil {
					return report, e
				}
				if hash != "" {
					if in.TimezoneSHA256 != "" && in.TimezoneSHA256 != hash {
						return report, fmt.Errorf("mixed timezone datasets")
					}
					in.TimezoneSHA256 = hash
				}
			}
		}
		// Even UTC templates can call toDateInZone with named zones: bind their helper
		// dataset whenever the parent has selected one in the resolved profile.
		_, configured := p.Configuration["timezone_dataset_sha256"]
		needsDataset := configured
		for _, c := range rows {
			needsDataset = needsDataset || c.Phase == "logql-template"
		}
		if needsDataset {
			_, hash, e := logQLTimezoneDataset(p)
			if e != nil {
				return report, e
			}
			in.TimezoneSHA256 = hash
		}
		payload, e := json.Marshal(struct {
			Phase string      `json:"phase"`
			LogQL *LogQLInput `json:"logql"`
		}{phase, &in})
		if e != nil {
			return report, e
		}
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		actual, e := RunOracle(runCtx, OracleRun{Profile: source, Input: payload, Configuration: configuration, Runtime: runtime})
		cancel()
		if e != nil {
			recordLogQLOracleFailure(&report, cases, e)
			return report, e
		}
		if actual.LogQL == nil || actual.Kind != "logql" {
			return report, fmt.Errorf("missing actual native LogQL batch; rebuild locked development image")
		}
		if e = validateLogQLBatch(*actual.LogQL, in); e != nil {
			return report, e
		}
		report.Compiler = actual.LogQL.Compiler
		report.SourceSHA256 = actual.LogQL.SourceSHA256
		report.TimezoneSHA256 = actual.LogQL.TimezoneSHA256
		for i, c := range rows {
			owned, e := observeOwnedLogQL(ctx, c, p)
			if e != nil {
				return report, e
			}
			reference := actual.LogQL.Observations[i]
			diff := CompareLogQL(reference, owned)
			if c.Clock != nil && reference.Error == nil && owned.Error == nil {
				loc, _, e := loadLogQLLocation(c.Timezone, p)
				if e != nil {
					return report, e
				}
				a, b := reference, owned
				if a.Pipeline != nil {
					a.Output = a.Pipeline.Line
				}
				if b.Pipeline != nil {
					b.Output = b.Pipeline.Line
				}
				if e = compareLogQLClockAt(c, a, b, loc); e != nil {
					diff = append(diff, Mismatch{"clock.observation", "declared real-wall bracket", e.Error()})
				} else {
					filtered := diff[:0]
					for _, m := range diff {
						if m.Field != "output" && m.Field != "pipeline" {
							filtered = append(filtered, m)
						}
					}
					diff = filtered
					if reference.Pipeline != nil && owned.Pipeline != nil {
						a, b := *reference.Pipeline, *owned.Pipeline
						a.Line = ""
						b.Line = ""
						if !reflectLogQLPipeline(a, b) {
							diff = append(diff, Mismatch{"pipeline.except-clock-line", a, b})
						}
					}
				}
			}
			diff = append(diff, checkLogQLExpected(c, owned)...)
			comparison := LogQLComparison{ID: c.ID, ProfileIdentity: p.Identity, FeatureSet: p.ActiveFeatureSet.ID, Oracle: actual.Oracle, Owned: owned, Reference: reference, Mismatches: diff}
			report.Cases = append(report.Cases, comparison)
			report.Compared++
			if len(diff) > 0 {
				report.Failed++
			}
		}
	}
	if report.Compared == 0 || report.Compared != len(cases) {
		return report, fmt.Errorf("unobserved applicable LogQL rows")
	}
	if report.Failed > 0 {
		return report, fmt.Errorf("%d of %d LogQL comparisons failed", report.Failed, report.Compared)
	}
	return report, nil
}
func reflectLogQLPipeline(a, b LogQLPipeline) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func checkLogQLExpected(c LogQLCase, o LogQLObservation) []Mismatch {
	var out []Mismatch
	add := func(field string, want, got any) { out = append(out, Mismatch{field, want, got}) }
	if c.Expected.Accepted != nil && *c.Expected.Accepted != o.Accepted {
		add("authored.accepted", *c.Expected.Accepted, o.Accepted)
	}
	if c.Expected.Type != "" && o.Type != c.Expected.Type {
		add("authored.type", c.Expected.Type, o.Type)
	}
	if c.Expected.Category != "" && (o.Error == nil || o.Error.Category != c.Expected.Category) {
		add("authored.category", c.Expected.Category, o.Error)
	}
	if c.Expected.Retained != nil {
		if o.Pipeline == nil {
			add("authored.pipeline", "required", nil)
			return out
		}
		if *c.Expected.Retained != o.Pipeline.Retained {
			add("authored.retained", *c.Expected.Retained, o.Pipeline.Retained)
		}
		if c.Expected.Line != nil && *c.Expected.Line != o.Pipeline.Line {
			add("authored.line", *c.Expected.Line, o.Pipeline.Line)
		}
		labels := map[string]string{}
		for _, l := range o.Pipeline.Labels {
			labels[l.Name] = l.Value
		}
		for _, l := range c.Expected.LabelsSubset {
			if v, ok := labels[l.Name]; !ok || v != l.Value {
				add("authored.label."+l.Name, l.Value, v)
			}
		}
		for _, name := range c.Expected.AbsentLabels {
			if v, ok := labels[name]; ok {
				add("authored.absent-label."+name, nil, v)
			}
		}
		if c.Expected.UnwrappedBits != nil && (o.Pipeline.Unwrapped == nil || *o.Pipeline.Unwrapped != *c.Expected.UnwrappedBits) {
			add("authored.unwrap", c.Expected.UnwrappedBits, o.Pipeline.Unwrapped)
		}
	}
	return out
}

// ServeLogQLAdapter is the closed typed development adapter route. Native output
// cannot become a result unless every build identity and row has been checked.
func ServeLogQLAdapter(ctx context.Context, profileID string, input *LogQLInput, output io.Writer) error {
	if input == nil || profileID != logQLProfile || input.Profile != profileID || input.Commit != logQLCommit || len(input.Cases) == 0 {
		return fmt.Errorf("missing exact native LogQL input")
	}
	for _, c := range input.Cases {
		if e := validateLogQLCase(c); e != nil {
			return e
		}
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return e
	}
	batch, e := runLogQLNative(ctx, raw)
	if e != nil {
		return e
	}
	if e = validateLogQLBatch(batch, *input); e != nil {
		return e
	}
	return json.NewEncoder(output).Encode(SemanticResult{Kind: "logql", Type: "logql", LogQL: &batch, Oracle: &OracleIdentity{Profile: profileID, Revision: batch.Commit, Version: "3.5.2"}})
}
func logQLConfigurationInt(p profile.Profile, key string) (int64, error) {
	raw, ok := p.Configuration[key]
	if !ok {
		return 0, fmt.Errorf("missing resolved LogQL configuration %s", key)
	}
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return 0, fmt.Errorf("invalid LogQL configuration %s", key)
	}
	n, e := strconv.ParseInt(text, 10, 64)
	if e != nil || strconv.FormatInt(n, 10) != text {
		return 0, fmt.Errorf("invalid LogQL configuration %s", key)
	}
	return n, nil
}
func recordLogQLOracleFailure(report *LogQLPhaseReport, cases []LogQLCase, err error) {
	class := "native-process-failure"
	if strings.Contains(err.Error(), "panic:") {
		class = "native-process-panic"
	}
	failure := &LogQLHarnessFailure{Stage: "native-oracle", Class: class, Message: err.Error()}
	seen := map[string]bool{}
	for _, row := range report.Cases {
		seen[row.ID] = true
	}
	for _, row := range cases {
		if !seen[row.ID] {
			failure.UnobservedIDs = append(failure.UnobservedIDs, row.ID)
		}
	}
	report.Failure = failure
}
