// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/promql"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
)

// EvaluationCase is independently authored fixture input, not a stored oracle
// answer. Durations and timestamps use canonical decimal nanosecond strings.
// Float and histogram variants are mutually exclusive, including zero floats.
//
// UnorderedVector is a comparison marker, never sent to a reference: it is set
// only on instant rows whose reference result order is unspecified (count_values
// emits its groups in Go map-iteration order in both pinned engines). The
// vector is then compared as a multiset of exact series; labels, sample values
// and the number of series stay exact, only their order is free.
type EvaluationCase struct {
	ID              string             `json:"id"`
	Profiles        []string           `json:"profiles"`
	Enabled         []string           `json:"enabled_features"`
	Query           string             `json:"query"`
	Kind            string             `json:"kind"`
	Time            model.UnixNano     `json:"time,omitempty"`
	Start           model.UnixNano     `json:"start,omitempty"`
	End             model.UnixNano     `json:"end,omitempty"`
	Step            int64              `json:"step,string,omitempty"`
	Lookback        int64              `json:"lookback_ns,string,omitempty"`
	SubqueryStep    int64              `json:"subquery_step_ns,string,omitempty"`
	UnorderedVector bool               `json:"unordered_vector,omitempty"`
	Series          []EvaluationSeries `json:"series"`
}
type EvaluationSample struct {
	Time           model.UnixNano         `json:"time"`
	Float          *model.FloatBits       `json:"float_bits,omitempty"`
	Histogram      *model.NativeHistogram `json:"histogram,omitempty"`
	StartTimestamp *model.UnixNano        `json:"start_timestamp_ns,omitempty"`
}

// Start timestamps are input acquisition metadata. Native PromQL result Sample
// exposes no ST field; retain actual C05 scan evidence separately from values.
type EvaluationStartTimestamp struct {
	Project        model.ID        `json:"project"`
	Labels         model.Labels    `json:"labels"`
	Time           model.UnixNano  `json:"time"`
	StartTimestamp *model.UnixNano `json:"start_timestamp_ns"`
}

func cloneEvaluationStartTimestamp(in *model.UnixNano) *model.UnixNano {
	if in == nil {
		return nil
	}
	copy := *in
	return &copy
}

type EvaluationSeries struct {
	Project model.ID           `json:"project,omitempty"`
	Labels  model.Labels       `json:"labels"`
	Samples []EvaluationSample `json:"samples"`
}

func (s EvaluationSeries) MarshalJSON() ([]byte, error) {
	var project *model.ID
	if s.Project != (model.ID{}) {
		project = &s.Project
	}
	return json.Marshal(struct {
		Project *model.ID          `json:"project,omitempty"`
		Labels  model.Labels       `json:"labels"`
		Samples []EvaluationSample `json:"samples"`
	}{project, s.Labels, s.Samples})
}

type EvaluationAnnotation struct {
	ID       string `json:"id,omitempty"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}
type EvaluationError struct {
	Category        string `json:"category"`
	Message         string `json:"message"`
	Start           int    `json:"start"`
	End             int    `json:"end"`
	ID              string `json:"id,omitempty"`
	RangeExposed    bool   `json:"range_exposed"`
	CategoryExposed bool   `json:"category_exposed"`
}
type EvaluationObservation struct {
	ID                  string                     `json:"id"`
	Type                string                     `json:"type"`
	String              string                     `json:"string,omitempty"`
	Series              []EvaluationSeries         `json:"series"`
	Annotations         []EvaluationAnnotation     `json:"annotations"`
	Complete            bool                       `json:"complete"`
	Partial             bool                       `json:"partial"`
	Watermarks          []model.Cursor             `json:"watermarks"`
	ScanStartTimestamps []EvaluationStartTimestamp `json:"scan_input_start_timestamps,omitempty"`
	Error               *EvaluationError           `json:"error,omitempty"`
}
type EvaluationBatch struct {
	Profile           string                  `json:"profile"`
	Commit            string                  `json:"commit"`
	Compiler          string                  `json:"compiler"`
	SourceSHA256      string                  `json:"source_sha256"`
	ProfileIdentity   string                  `json:"profile_identity"`
	FeatureSet        string                  `json:"feature_set"`
	ConfigurationHash string                  `json:"configuration_hash"`
	Observations      []EvaluationObservation `json:"observations"`
}
type evaluationInput struct {
	Profile           string                     `json:"profile"`
	Commit            string                     `json:"commit"`
	ProfileIdentity   string                     `json:"profile_identity"`
	FeatureSet        string                     `json:"feature_set"`
	ConfigurationHash string                     `json:"configuration_hash"`
	Enabled           []string                   `json:"enabled_features"`
	Lookback          int64                      `json:"lookback_ns,string"`
	SubqueryStep      int64                      `json:"subquery_step_ns,string"`
	Cases             []EvaluationCase           `json:"cases"`
	Configuration     map[string]json.RawMessage `json:"configuration"`
	ManifestVersion   int                        `json:"manifest_version"`
}

var evaluationProject = model.ID{15: 1}

// validateUnorderedVector refuses the unordered_vector marker unless the parsed
// query's top-level operation (parentheses aside) is count_values, and refuses
// every explicitly ordered or selecting operation anywhere in the expression: a
// row whose order is specified or whose selection depends on order must never
// get order freedom.
func validateUnorderedVector(c EvaluationCase, p profile.Profile) error {
	if !c.UnorderedVector {
		return nil
	}
	tree, err := promql.Parse(c.Query, p)
	if err != nil {
		return fmt.Errorf("%s: unordered_vector on an unparsable query: %w", c.ID, err)
	}
	root := tree
	for {
		n, ok := root.(*promql.Node)
		if !ok || n.Kind != "paren" || len(n.Children) != 1 {
			break
		}
		root = n.Children[0]
	}
	if n, ok := root.(*promql.Node); !ok || n.Kind != "aggregate" || n.Text != "count_values" {
		return fmt.Errorf("%s: unordered_vector requires a top-level count_values", c.ID)
	}
	forbidden := map[string]bool{"sort": true, "sort_desc": true, "sort_by_label": true, "sort_by_label_desc": true, "topk": true, "bottomk": true, "limitk": true, "limit_ratio": true}
	var walk func(e promql.Expr) error
	walk = func(e promql.Expr) error {
		n, ok := e.(*promql.Node)
		if !ok || n == nil {
			return nil
		}
		if (n.Kind == "call" || n.Kind == "aggregate" || n.Kind == "duration_call") && forbidden[n.Text] {
			return fmt.Errorf("%s: unordered_vector refused, %s orders or selects by order", c.ID, n.Text)
		}
		for _, ch := range n.Children {
			if err := walk(ch); err != nil {
				return err
			}
		}
		for _, ch := range []promql.Expr{n.RangeExpr, n.StepExpr, n.OffsetExpr} {
			if ch != nil {
				if err := walk(ch); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(tree)
}

func validateEvaluationCase(c EvaluationCase) error {
	if c.ID == "" || len(c.Profiles) == 0 || c.Query == "" {
		return fmt.Errorf("unscoped or empty evaluation case")
	}
	if c.Kind != "instant" && c.Kind != "range" {
		return fmt.Errorf("invalid evaluation kind in %s", c.ID)
	}
	if c.Kind == "range" && (c.Step <= 0 || c.End < c.Start) {
		return fmt.Errorf("invalid evaluation grid in %s", c.ID)
	}
	if c.Lookback < 0 || c.SubqueryStep < 0 {
		return fmt.Errorf("negative evaluation duration")
	}
	if c.UnorderedVector && c.Kind != "instant" {
		return fmt.Errorf("unordered_vector applies only to instant rows: %s", c.ID)
	}
	projects := map[model.ID]bool{}
	for _, s := range c.Series {
		project := s.Project
		if project == (model.ID{}) {
			project = evaluationProject
		}
		projects[project] = true
		if err := s.Labels.Validate(); err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
		name := false
		for _, l := range s.Labels {
			if l.Name == "__name__" && l.Value != "" {
				name = true
			}
		}
		if !name {
			return fmt.Errorf("fixture series requires explicit __name__")
		}
		for i, sample := range s.Samples {
			if (sample.Float == nil) == (sample.Histogram == nil) {
				return fmt.Errorf("sample requires exactly one float/histogram variant")
			}
			if i > 0 && sample.Time <= s.Samples[i-1].Time {
				return fmt.Errorf("fixture sample times must strictly increase")
			}
			if sample.Histogram != nil {
				if err := sample.Histogram.Validate(); err != nil {
					return err
				}
			}
		}
	}
	if len(projects) > 1 {
		return fmt.Errorf("evaluation case must be project-partitioned; never aggregate projects")
	}
	return nil
}

func readEvaluationCases(lock SourceLock, paths []string) ([]EvaluationCase, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("evaluation case files required")
	}
	var cases []EvaluationCase
	files := map[string]bool{}
	for _, path := range paths {
		if path == "" {
			return nil, fmt.Errorf("empty evaluation case path")
		}
		key := "cases/" + filepath.Base(path)
		if files[key] {
			return nil, fmt.Errorf("duplicate evaluation case file %s", key)
		}
		files[key] = true
		var raw json.RawMessage
		if err := ReadLockedJSON(lock, key, path, &raw); err != nil {
			return nil, err
		}
		var suite struct {
			Phase string           `json:"phase"`
			Cases []EvaluationCase `json:"cases"`
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&suite); err != nil {
			return nil, err
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, fmt.Errorf("trailing evaluation fixture JSON")
		}
		if suite.Phase != "evaluation" || len(suite.Cases) == 0 {
			return nil, fmt.Errorf("nonempty evaluation phase suite required: %s", path)
		}
		for _, c := range suite.Cases {
			if err := validateEvaluationCase(c); err != nil {
				return nil, err
			}
			cases = append(cases, c)
		}
	}
	return cases, nil
}

func observeOwnedEvaluation(ctx context.Context, c EvaluationCase, p profile.Profile) (EvaluationObservation, error) {
	result := EvaluationObservation{ID: c.ID}
	tree, err := promql.Parse(c.Query, p)
	var typed promql.TypedExpr
	var diagnostics []syntax.Diagnostic
	if err == nil {
		typed, diagnostics, err = promql.Check(tree, p)
	}
	if err == nil {
		evaluation := value.Evaluation{Instant: c.Kind == "instant", Time: c.Time, Start: c.Start, End: c.End, Step: c.Step}
		plan, e := promql.BuildPlan(typed, evaluation, p)
		err = e
		if err == nil {
			// The per-query lookback is the engine's QueryOptions: <=0 inherits, >0 overrides.
			plan = plan.WithQueryOptions(promql.QueryOptions{Lookback: c.Lookback})
			if c.SubqueryStep > 0 {
				plan.SubqueryStep = c.SubqueryStep
			}
			project := evaluationProject
			for _, s := range c.Series {
				if s.Project != (model.ID{}) {
					project = s.Project
					break
				}
			}
			scanner := &InMemoryEvaluationScanner{Project: project, Series: c.Series}
			source := scan.NewMetricSource(scanner, auth.Scope{}, project, storage.ReadFence{AllowPartial: false})
			var actual value.Result
			var notes []syntax.Diagnostic
			actual, notes, err = promql.Evaluate(ctx, plan, source, value.NewBoundedAccount(256<<20))
			diagnostics = append(diagnostics, notes...)
			result.Partial = actual.Partial
			result.Watermarks = append([]model.Cursor(nil), actual.Watermarks...)
			result.Complete = err == nil && !actual.Partial
			result.ScanStartTimestamps = append([]EvaluationStartTimestamp(nil), scanner.StartTimestampObservations...)
			if err == nil {
				result.Type = actual.Type
				result.String = actual.String
				appendSeries := func(s value.Series) {
					out := EvaluationSeries{Project: s.Project, Labels: append(model.Labels(nil), s.Labels...)}
					for _, sample := range s.Samples {
						out.Samples = append(out.Samples, evaluationSample(sample))
					}
					result.Series = append(result.Series, out)
				}
				switch actual.Type {
				case "scalar":
					result.Series = []EvaluationSeries{{Samples: []EvaluationSample{evaluationSample(actual.Scalar)}}}
				case "string":
					result.Series = []EvaluationSeries{{Samples: []EvaluationSample{{Time: actual.Scalar.Time}}}}
				case "vector":
					for _, s := range actual.Vector {
						appendSeries(s)
					}
				case "matrix":
					for _, s := range actual.Matrix {
						appendSeries(s)
					}
				default:
					return result, fmt.Errorf("unobserved owned result type %q", actual.Type)
				}
			}
		}
	}
	for _, d := range diagnostics {
		severity := "warning"
		if strings.HasSuffix(d.Category, "Info") || d.Category == "info" {
			severity = "info"
		}
		result.Annotations = append(result.Annotations, EvaluationAnnotation{ID: d.Category, Severity: severity, Message: d.SafeMessage, Start: d.Range.StartByte, End: d.Range.EndByte})
	}
	if err != nil {
		var language *syntax.LanguageError
		if !errors.As(err, &language) {
			return result, fmt.Errorf("owned evaluation infrastructure failure: %w", err)
		}
		result.Error = &EvaluationError{Category: language.Category, CategoryExposed: true, Message: language.SafeMessage, Start: language.Range.StartByte, End: language.Range.EndByte, ID: language.Code, RangeExposed: language.Category != "execution"}
	}
	return result, nil
}
func evaluationSample(s value.Sample) EvaluationSample {
	// Upstream result Sample has no ST. Keep genuine start metadata in the
	// separate raw scan proof, never fabricate a comparable reference value.
	out := EvaluationSample{Time: s.Time, Histogram: s.Histogram}
	if s.Histogram == nil {
		bits := s.Float
		out.Float = &bits
	}
	return out
}

// CompareEvaluation is exact for language values and ordering. Only zero-length
// histogram slice allocation forms and source-map annotation ordering have
// declared projections; raw observations remain intact. Error IDs come from
// typed owned causes/source-proven native families, never prose equality, and
// genuine native positions remain strict. Input-only ST proof is separate from
// nonexistent native output ST; its actual function consequences stay exact.
func CompareEvaluation(want, got EvaluationObservation) []Mismatch {
	return compareEvaluation(want, got, false)
}

// CompareEvaluationCase is CompareEvaluation with the ordering freedom the case
// declares: for an instant row marked UnorderedVector the vectors are compared
// as multisets of exact series (see EvaluationCase); every other field, and
// every row that is not marked, stays exact including order.
func CompareEvaluationCase(c EvaluationCase, want, got EvaluationObservation) []Mismatch {
	return compareEvaluation(want, got, c.UnorderedVector && c.Kind == "instant")
}

// canonicalEvaluationSeries returns a copy of the series in a canonical order, so
// two vectors holding the same multiset of exact series compare equal.
func canonicalEvaluationSeries(in []EvaluationSeries) []EvaluationSeries {
	if len(in) == 0 {
		return in
	}
	type keyed struct {
		key    string
		series EvaluationSeries
	}
	rows := make([]keyed, len(in))
	for i, s := range in {
		raw, err := json.Marshal(s)
		if err != nil {
			raw = []byte(fmt.Sprintf("%#v", s))
		}
		rows[i] = keyed{string(raw), s}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key < rows[j].key })
	out := make([]EvaluationSeries, len(in))
	for i, r := range rows {
		out[i] = r.series
	}
	return out
}

// withoutComparisonMarkers returns the cases as a reference receives them: the
// comparison-only markers are dropped, so a pinned reference image never sees a
// field it does not know.
func withoutComparisonMarkers(in []EvaluationCase) []EvaluationCase {
	out := make([]EvaluationCase, len(in))
	for i, c := range in {
		c.UnorderedVector = false
		out[i] = c
	}
	return out
}

func compareEvaluation(want, got EvaluationObservation, unorderedVector bool) []Mismatch {
	var out []Mismatch
	add := func(field string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			out = append(out, Mismatch{Field: field, Want: a, Got: b})
		}
	}
	add("id", want.ID, got.ID)
	add("type", want.Type, got.Type)
	add("string", want.String, got.String)
	wantSeries, gotSeries := projectEvaluationSeriesHistograms(want.Series), projectEvaluationSeriesHistograms(got.Series)
	if unorderedVector && want.Type == "vector" && got.Type == "vector" {
		wantSeries, gotSeries = canonicalEvaluationSeries(wantSeries), canonicalEvaluationSeries(gotSeries)
	}
	add("series", wantSeries, gotSeries)
	add("complete", want.Complete, got.Complete)
	add("partial", want.Partial, got.Partial)
	add("watermarks", want.Watermarks, got.Watermarks)
	annotationKeys := func(values []EvaluationAnnotation) []string {
		if len(values) == 0 {
			return nil
		}
		keys := make([]string, 0, len(values))
		for _, a := range values {
			identity := a.ID
			if identity == "" {
				identity = "unclassified:" + a.Message
			}
			keys = append(keys, fmt.Sprintf("%s\x00%s\x00%d\x00%d", identity, a.Severity, a.Start, a.End))
		}
		sort.Strings(keys)
		return keys
	}
	add("annotations", annotationKeys(want.Annotations), annotationKeys(got.Annotations))
	if want.Error == nil || got.Error == nil {
		add("error", want.Error, got.Error)
	} else {
		if want.Error.CategoryExposed {
			add("error.category", want.Error.Category, got.Error.Category)
		}
		if want.Error.ID == "" || got.Error.ID == "" {
			out = append(out, Mismatch{Field: "error.unclassified", Want: want.Error, Got: got.Error})
		} else {
			add("error.id", want.Error.ID, got.Error.ID)
		}
		if want.Error.RangeExposed {
			add("error.start", want.Error.Start, got.Error.Start)
			add("error.end", want.Error.End, got.Error.End)
		}
	}
	return out
}

func validateEvaluationBatch(batch EvaluationBatch, p profile.Profile, cases []EvaluationCase) error {
	compiler := "go1.23.4"
	if p.ID == "promql-prometheus-3.13.5" {
		compiler = "go1.26.10"
	}
	if batch.Profile != p.ID || batch.Commit != p.Commit || batch.Compiler != compiler || batch.ProfileIdentity != p.Identity || batch.FeatureSet != p.ActiveFeatureSet.ID || batch.ConfigurationHash != p.ConfigurationHash {
		return fmt.Errorf("evaluation oracle profile/compiler/configuration identity mismatch")
	}
	if len(batch.Observations) != len(cases) || len(cases) == 0 {
		return fmt.Errorf("missing evaluation oracle observations")
	}
	for i, c := range cases {
		o := batch.Observations[i]
		if o.ID != c.ID {
			return fmt.Errorf("evaluation oracle case identity/order mismatch")
		}
		if o.Error == nil {
			if !o.Complete || o.Partial {
				return fmt.Errorf("native fixture reference did not observe a complete result")
			}
			switch o.Type {
			case "scalar", "string", "vector", "matrix":
			default:
				return fmt.Errorf("missing reference evaluation result type")
			}
		}
	}
	return nil
}
