// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"soundpost/internal/model"
	"soundpost/internal/notify"
	"soundpost/internal/query"
	"soundpost/internal/query/syntax"
	"soundpost/profiles"
)

// Parity compares meaningful answers, never counts alone: the exact IEEE bits
// and native histogram of every sample, the exact log lines in engine order, the
// exact lifecycle version and phase of a source condition, the exact decisions
// of the shadow policy twin and the exact unsupported/drop reasons. The queries
// run through the owned query engine (internal/query) over what the owned
// adapters admitted.

// shadowRecipient is the label of the single synthetic recipient the shadow
// policy twin decides for. It is an identity only: it has no address and no
// sender behind it.
const shadowRecipient = "shadow-recipient"

// ShadowSample is one exact sample: time, the IEEE-754 bits of a float value
// as 16 hex digits, or the canonical JSON of a native histogram.
type ShadowSample struct {
	TimeNS    int64  `json:"time_ns"`
	Bits      string `json:"bits,omitempty"`
	Histogram string `json:"histogram,omitempty"`
}

// ShadowSeries is one answer series.
type ShadowSeries struct {
	Labels  map[string]string `json:"labels"`
	Samples []ShadowSample    `json:"samples"`
}

// ShadowLogLine is one answer log entry in engine order.
type ShadowLogLine struct {
	Labels       map[string]string `json:"labels"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	TimeNS       int64             `json:"time_ns"`
	Line         string            `json:"line"`
	Multiplicity uint64            `json:"multiplicity"`
}

// ShadowAnswer is the exact, comparable answer of one query: either an explicit
// unsupported reason (the engine's typed fault code) or the values.
type ShadowAnswer struct {
	Unsupported string          `json:"unsupported,omitempty"`
	String      string          `json:"string,omitempty"`
	Series      []ShadowSeries  `json:"series,omitempty"`
	Lines       []ShadowLogLine `json:"lines,omitempty"`
}

// ShadowQueryCase is one query shape with the legacy system's exact answer. It
// has no project or organization field: a query always runs in the mapped
// project through the destination's read scope.
type ShadowQueryCase struct {
	ID         string       `json:"id"`
	Language   string       `json:"language"`
	Profile    string       `json:"profile"`
	Features   []string     `json:"features"`
	Expression string       `json:"expression"`
	AtNS       int64        `json:"at_ns,omitempty"`
	StartNS    int64        `json:"start_ns,omitempty"`
	EndNS      int64        `json:"end_ns,omitempty"`
	StepNS     int64        `json:"step_ns,omitempty"`
	LogOrder   string       `json:"log_order,omitempty"`
	Expect     ShadowAnswer `json:"expect"`
}

// ShadowConditionExpectation is the legacy lifecycle answer of one condition.
// Freshness is compared only when set.
type ShadowConditionExpectation struct {
	Condition     string `json:"condition"`
	SourceVersion uint64 `json:"source_version"`
	Phase         string `json:"phase"`
	Freshness     string `json:"freshness,omitempty"`
}

// ShadowLegacyDecision is one legacy notification decision in the shadow
// vocabulary. Recipient is empty for the shared queue and shadowRecipient for
// the one synthetic recipient every legacy recipient set maps onto.
type ShadowLegacyDecision struct {
	Condition      string `json:"condition"`
	Kind           string `json:"kind"`
	ImpactRevision uint64 `json:"impact_revision"`
	Ordinal        uint64 `json:"ordinal"`
	Recipient      string `json:"recipient,omitempty"`
	SourceVersion  uint64 `json:"source_version"`
	DedupID        string `json:"dedup_id"`
	Suppression    string `json:"suppression,omitempty"`
}

// ShadowParitySpec is everything compared: query answers, lifecycle answers,
// notification decisions and the exact drop reasons. A nil section is not
// compared.
type ShadowParitySpec struct {
	Queries              []ShadowQueryCase            `json:"queries,omitempty"`
	Conditions           []ShadowConditionExpectation `json:"conditions,omitempty"`
	LegacyDecisions      []ShadowLegacyDecision       `json:"legacy_decisions,omitempty"`
	ExpectedDropReasons  map[string]int               `json:"expected_drop_reasons,omitempty"`
	ExpectedRejectReason map[string]int               `json:"expected_reject_reasons,omitempty"`
}

// ShadowMismatch is one difference: Domain is query, lifecycle, decision or
// ledger; Case is the operator's case ID, condition name or reason; Field is a
// closed name.
type ShadowMismatch struct {
	Domain string `json:"domain"`
	Case   string `json:"case"`
	Field  string `json:"field"`
}

// ShadowParityReport is the parity result. Equal means every compared answer
// matched exactly.
type ShadowParityReport struct {
	QueriesCompared   int              `json:"queries_compared"`
	LifecycleCompared int              `json:"lifecycle_compared"`
	DecisionsCompared int              `json:"decisions_compared"`
	LedgerCompared    int              `json:"ledger_compared"`
	Mismatches        []ShadowMismatch `json:"mismatches"`
}

// Equal reports that nothing differed.
func (r ShadowParityReport) Equal() bool { return len(r.Mismatches) == 0 }

// ---- spec validation ------------------------------------------------------

var shadowProfileID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)

func shadowSpecErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrShadowParitySpec, fmt.Sprintf(format, args...))
}

// shadowFeatureSetID resolves the pinned feature-set ID of a profile whose
// enabled features are exactly the given set. The manifests are the ones
// embedded in the binary, never a loose directory.
func shadowFeatureSetID(profileID string, features []string) (string, error) {
	if !shadowProfileID.MatchString(profileID) {
		return "", shadowSpecErr("profile")
	}
	fsys, err := profiles.Query()
	if err != nil {
		return "", shadowSpecErr("profiles unavailable")
	}
	raw, err := fs.ReadFile(fsys, profileID+".json")
	if err != nil {
		return "", shadowSpecErr("unknown profile")
	}
	var manifest struct {
		FeatureSets []struct {
			ID      string   `json:"id"`
			Enabled []string `json:"enabled"`
		} `json:"feature_sets"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return "", shadowSpecErr("profile manifest")
	}
	want := append([]string(nil), features...)
	sort.Strings(want)
	for _, set := range manifest.FeatureSets {
		have := append([]string(nil), set.Enabled...)
		sort.Strings(have)
		if strings.Join(have, "\x00") == strings.Join(want, "\x00") && len(have) == len(want) {
			return set.ID, nil
		}
	}
	return "", shadowSpecErr("unknown feature set")
}

func (c ShadowQueryCase) validate() error {
	if c.ID == "" || len(c.ID) > 128 || c.Expression == "" || len(c.Expression) > 8192 {
		return shadowSpecErr("query case identity or expression")
	}
	if c.Language != query.LanguagePromQL && c.Language != query.LanguageLogQL {
		return shadowSpecErr("query language")
	}
	if c.LogOrder != "" && c.LogOrder != "forward" && c.LogOrder != "backward" {
		return shadowSpecErr("log order")
	}
	instant := c.AtNS != 0 && c.StartNS == 0 && c.EndNS == 0 && c.StepNS == 0
	ranged := c.AtNS == 0 && c.StartNS < c.EndNS && c.StepNS > 0
	if instant == ranged {
		return shadowSpecErr("evaluation must be exactly one instant or one range")
	}
	if _, err := shadowFeatureSetID(c.Profile, c.Features); err != nil {
		return err
	}
	return nil
}

func (s ShadowParitySpec) validate() error {
	seen := map[string]bool{}
	for _, q := range s.Queries {
		if err := q.validate(); err != nil {
			return err
		}
		if seen[q.ID] {
			return shadowSpecErr("duplicate query case")
		}
		seen[q.ID] = true
	}
	conds := map[string]bool{}
	for _, c := range s.Conditions {
		if c.Condition == "" || conds[c.Condition] {
			return shadowSpecErr("condition expectation")
		}
		conds[c.Condition] = true
		switch c.Freshness {
		case "", "fresh", "stale", "unknown":
		default:
			return shadowSpecErr("condition freshness")
		}
	}
	for _, d := range s.LegacyDecisions {
		if d.Condition == "" || d.Kind == "" || (d.Recipient != "" && d.Recipient != shadowRecipient) {
			return shadowSpecErr("legacy decision")
		}
	}
	for _, m := range []map[string]int{s.ExpectedDropReasons, s.ExpectedRejectReason} {
		for reason, n := range m {
			if reason == "" || n < 0 {
				return shadowSpecErr("expected reason tally")
			}
		}
	}
	return nil
}

// ---- running a query through the owned engine ----------------------------

func shadowLabelMap(l model.Labels) map[string]string {
	out := make(map[string]string, len(l))
	for _, x := range l {
		out[x.Name] = x.Value
	}
	return out
}

func shadowSample(s query.Sample) (ShadowSample, error) {
	out := ShadowSample{TimeNS: int64(s.Time)}
	switch {
	case s.Float != nil && s.Histogram == nil:
		out.Bits = fmt.Sprintf("%016x", uint64(*s.Float))
	case s.Histogram != nil && s.Float == nil:
		raw, err := model.CanonicalJSON(*s.Histogram)
		if err != nil {
			return out, err
		}
		out.Histogram = string(raw)
	default:
		return out, errors.New("sample carries neither or both of float and histogram")
	}
	return out, nil
}

// shadowAnswer evaluates one query case in the destination's mapped project
// through the owned engine and normalizes the typed value. A typed engine
// failure is the explicit Unsupported reason (its fault code), not an error;
// only cancellation and internal faults are returned as errors.
func shadowAnswer(ctx context.Context, d SoundpostDestination, c ShadowQueryCase) (ShadowAnswer, error) {
	if err := c.validate(); err != nil {
		return ShadowAnswer{}, err
	}
	if d.App == nil || d.Reader == nil {
		return ShadowAnswer{}, fmt.Errorf("%w: no query authority", ErrShadowDestination)
	}
	featureSet, err := shadowFeatureSetID(c.Profile, c.Features)
	if err != nil {
		return ShadowAnswer{}, err
	}
	ev := query.Evaluation{Instant: true, Time: model.UnixNano(c.AtNS)}
	if c.AtNS == 0 {
		ev = query.Evaluation{Start: model.UnixNano(c.StartNS), End: model.UnixNano(c.EndNS), Step: model.Int64(c.StepNS)}
	}
	req := query.Request{Language: c.Language, Profile: c.Profile, FeatureSet: featureSet, Expression: c.Expression, Evaluation: ev, Projects: []model.ID{d.Project}}
	if c.Language == query.LanguageLogQL {
		req.LogOrder = c.LogOrder
		if req.LogOrder == "" {
			req.LogOrder = "forward"
		}
	}
	res, err := d.App.Query.Execute(ctx, *d.Reader, req)
	if err != nil {
		if ctx.Err() != nil {
			return ShadowAnswer{}, ctx.Err()
		}
		var language *syntax.LanguageError
		if errors.As(err, &language) {
			// The owned engine's own classification: its code, else its category.
			switch {
			case language.Code != "":
				return ShadowAnswer{Unsupported: language.Code}, nil
			case language.Category != "":
				return ShadowAnswer{Unsupported: "language." + language.Category}, nil
			}
			return ShadowAnswer{Unsupported: "language.unclassified"}, nil
		}
		var fault *model.Fault
		if errors.As(err, &fault) {
			return ShadowAnswer{Unsupported: string(fault.Code)}, nil
		}
		return ShadowAnswer{}, fmt.Errorf("query engine failed (%T)", err)
	}
	if len(res.Projects) != 1 || res.Projects[0].ProjectID != d.Project {
		return ShadowAnswer{}, errors.New("query engine returned an unexpected project set")
	}
	pr := res.Projects[0]
	if pr.Failure != nil {
		return ShadowAnswer{Unsupported: pr.Failure.Code}, nil
	}
	if pr.Value == nil {
		return ShadowAnswer{}, errors.New("query engine returned no value")
	}
	var out ShadowAnswer
	add := func(labels model.Labels, samples ...query.Sample) error {
		s := ShadowSeries{Labels: shadowLabelMap(labels), Samples: []ShadowSample{}}
		for _, x := range samples {
			v, err := shadowSample(x)
			if err != nil {
				return err
			}
			s.Samples = append(s.Samples, v)
		}
		out.Series = append(out.Series, s)
		return nil
	}
	switch pr.Value.Type {
	case query.ValueScalar:
		err = add(nil, pr.Value.Scalar)
	case query.ValueString:
		out.String = pr.Value.String
	case query.ValueVector:
		for _, e := range pr.Value.Vector {
			if err = add(e.Labels, e.Sample); err != nil {
				break
			}
		}
	case query.ValueMatrix:
		for _, s := range pr.Value.Matrix {
			if err = add(s.Labels, s.Samples...); err != nil {
				break
			}
		}
	case query.ValueStreams:
		var entries []query.LogEntry
		for _, s := range pr.Value.Streams {
			entries = append(entries, s.Entries...)
		}
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].Index < entries[j].Index })
		for _, e := range entries {
			line := ShadowLogLine{Labels: shadowLabelMap(e.StreamLabels), TimeNS: int64(e.Time), Line: e.Line, Multiplicity: uint64(e.Multiplicity)}
			if len(e.StructuredMetadata) > 0 {
				line.Metadata = shadowLabelMap(e.StructuredMetadata)
			}
			out.Lines = append(out.Lines, line)
		}
	default:
		err = errors.New("query engine returned an unknown value type")
	}
	if err != nil {
		return ShadowAnswer{}, err
	}
	return out, nil
}

// ---- comparison -------------------------------------------------------------

func shadowLabelKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(m[k])
		b.WriteByte(1)
	}
	return b.String()
}

func shadowSameMap(a, b map[string]string) bool { return shadowLabelKey(a) == shadowLabelKey(b) }

// shadowCompareAnswers compares one expected and one actual answer exactly. An
// unsupported reason replaces the values on either side; series order is not
// meaningful, sample order and log-line order are.
func shadowCompareAnswers(id string, want, got ShadowAnswer) []ShadowMismatch {
	mm := func(field string) ShadowMismatch { return ShadowMismatch{Domain: "query", Case: id, Field: field} }
	if want.Unsupported != got.Unsupported {
		return []ShadowMismatch{mm("unsupported_reason")}
	}
	if want.Unsupported != "" {
		return nil
	}
	var out []ShadowMismatch
	if want.String != got.String {
		out = append(out, mm("string_value"))
	}
	wantSeries, gotSeries := map[string]ShadowSeries{}, map[string]ShadowSeries{}
	keys := map[string]bool{}
	for _, s := range want.Series {
		k := shadowLabelKey(s.Labels)
		wantSeries[k], keys[k] = s, true
	}
	for _, s := range got.Series {
		k := shadowLabelKey(s.Labels)
		gotSeries[k], keys[k] = s, true
	}
	if len(wantSeries) != len(want.Series) || len(gotSeries) != len(got.Series) {
		out = append(out, mm("series_duplicate"))
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	for _, k := range ordered {
		w, wok := wantSeries[k]
		g, gok := gotSeries[k]
		switch {
		case !gok:
			out = append(out, mm("series_missing"))
			continue
		case !wok:
			out = append(out, mm("series_extra"))
			continue
		case len(w.Samples) != len(g.Samples):
			out = append(out, mm("sample_count"))
			continue
		}
		for i := range w.Samples {
			if w.Samples[i].TimeNS != g.Samples[i].TimeNS {
				out = append(out, mm("sample_time"))
			}
			if w.Samples[i].Bits != g.Samples[i].Bits {
				out = append(out, mm("sample_value"))
			}
			if w.Samples[i].Histogram != g.Samples[i].Histogram {
				out = append(out, mm("sample_histogram"))
			}
		}
	}
	if len(want.Lines) != len(got.Lines) {
		return append(out, mm("line_count"))
	}
	for i := range want.Lines {
		w, g := want.Lines[i], got.Lines[i]
		if w.Line != g.Line {
			out = append(out, mm("line_value"))
		}
		if w.TimeNS != g.TimeNS {
			out = append(out, mm("line_time"))
		}
		if !shadowSameMap(w.Labels, g.Labels) {
			out = append(out, mm("line_labels"))
		}
		if !shadowSameMap(w.Metadata, g.Metadata) {
			out = append(out, mm("line_metadata"))
		}
		if w.Multiplicity != g.Multiplicity {
			out = append(out, mm("line_multiplicity"))
		}
	}
	return out
}

// shadowCompareLifecycle compares the legacy lifecycle answer of each listed
// condition with the shadow's exact version, phase and (when stated) freshness.
func shadowCompareLifecycle(want []ShadowConditionExpectation, got []ShadowCondition) []ShadowMismatch {
	byName := map[string]ShadowCondition{}
	for _, c := range got {
		byName[c.Name] = c
	}
	var out []ShadowMismatch
	for _, w := range want {
		mm := func(field string) ShadowMismatch {
			return ShadowMismatch{Domain: "lifecycle", Case: w.Condition, Field: field}
		}
		g, ok := byName[w.Condition]
		if !ok {
			out = append(out, mm("missing_condition"))
			continue
		}
		if w.SourceVersion != g.SourceVersion {
			out = append(out, mm("version"))
		}
		if w.Phase != g.Phase {
			out = append(out, mm("phase"))
		}
		if w.Freshness != "" && w.Freshness != g.Freshness {
			out = append(out, mm("freshness"))
		}
	}
	return out
}

// shadowCompareReasons compares two reason tallies exactly; a zero count is an
// absent count.
func shadowCompareReasons(domain string, want, got map[string]int) []ShadowMismatch {
	keys := map[string]bool{}
	for k, n := range want {
		if n != 0 {
			keys[k] = true
		}
	}
	for k, n := range got {
		if n != 0 {
			keys[k] = true
		}
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	var out []ShadowMismatch
	for _, k := range ordered {
		if want[k] != got[k] {
			out = append(out, ShadowMismatch{Domain: domain, Case: k, Field: "reason_count"})
		}
	}
	return out
}

// shadowCompareDecisions compares the shadow twin's decisions with the legacy
// decisions through the owned notify.CompareParity, so the product's own
// definition of a matching decision is the only one.
func shadowCompareDecisions(entities map[model.ID]string, ids map[string]model.ID, shadow []notify.ShadowDecision, legacy []ShadowLegacyDecision) (int, []ShadowMismatch) {
	recipient := shadowDeriveID("recipient", shadowRecipient)
	var old []notify.LegacyDecision
	for _, l := range legacy {
		id, ok := ids[l.Condition]
		if !ok {
			id = shadowDeriveID("unknown-condition", l.Condition)
			entities[id] = l.Condition
		}
		d := notify.LegacyDecision{Entity: notify.Entity{Kind: notify.EntityCondition, ID: id}, Kind: notify.Kind(l.Kind), ImpactRevision: l.ImpactRevision, Ordinal: l.Ordinal,
			SourceVersion: l.SourceVersion, DedupID: l.DedupID, Suppression: notify.Code(l.Suppression)}
		if l.Recipient != "" {
			r := recipient
			d.Recipient = &r
		}
		old = append(old, d)
	}
	rep := notify.CompareParity(shadow, old)
	var out []ShadowMismatch
	for _, m := range rep.Mismatches {
		out = append(out, ShadowMismatch{Domain: "decision", Case: entities[m.Entity.ID], Field: m.Field})
	}
	return rep.Compared, out
}
