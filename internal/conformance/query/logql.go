// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/logql"
)

const logQLProfile = "logql-loki-3.5.2"
const logQLCommit = "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"
const logQLSourceSHA = "0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2"

type LogQLEntry struct {
	Timestamp    model.UnixNano     `json:"timestamp_ns"`
	ID           model.ID           `json:"id"`
	Multiplicity model.Uint64       `json:"multiplicity"`
	Line         string             `json:"line"`
	StreamLabels model.Labels       `json:"stream_labels"`
	Metadata     model.Labels       `json:"structured_metadata"`
	Fields       []logql.TypedField `json:"fields"`
}
type LogQLClock struct {
	Kind      string `json:"kind"`
	Layout    string `json:"layout,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Precision string `json:"precision,omitempty"`
}
type LogQLCase struct {
	ID             string            `json:"id"`
	Phase          string            `json:"phase,omitempty"`
	Profiles       []string          `json:"profiles"`
	Enabled        []string          `json:"enabled_features,omitempty"`
	Obligation     string            `json:"obligation,omitempty"`
	BindingScope   string            `json:"binding_scope,omitempty"`
	ConfigIdentity string            `json:"config_identity,omitempty"`
	Configuration  map[string]string `json:"configuration,omitempty"`
	Input          struct {
		Expression string      `json:"expression"`
		Entry      *LogQLEntry `json:"entry,omitempty"`
	} `json:"input,omitempty"`
	Expected struct {
		Accepted      *bool            `json:"accepted,omitempty"`
		Type          string           `json:"type,omitempty"`
		Category      string           `json:"category,omitempty"`
		Retained      *bool            `json:"retained,omitempty"`
		Line          *string          `json:"line,omitempty"`
		LabelsSubset  model.Labels     `json:"labels_subset,omitempty"`
		AbsentLabels  []string         `json:"absent_labels,omitempty"`
		UnwrappedBits *model.FloatBits `json:"unwrapped_bits,omitempty"`
	} `json:"expected,omitempty"`
	Kind          string             `json:"kind,omitempty"`
	Source        string             `json:"source,omitempty"`
	PipelineQuery string             `json:"pipeline_query,omitempty"`
	Line          string             `json:"line,omitempty"`
	Timestamp     model.UnixNano     `json:"timestamp_ns,omitempty"`
	Labels        model.Labels       `json:"labels,omitempty"`
	Fields        []logql.TypedField `json:"fields,omitempty"`
	Timezone      string             `json:"timezone,omitempty"`
	Clock         *LogQLClock        `json:"clock_observation,omitempty"`
	Query         string             `json:"query,omitempty"`
	Time          model.UnixNano     `json:"time_ns,omitempty"`
	Start         model.UnixNano     `json:"start_ns,omitempty"`
	End           model.UnixNano     `json:"end_ns,omitempty"`
	Step          int64              `json:"step_ns,string,omitempty"`
	Interval      int64              `json:"interval_ns,string,omitempty"`
	Direction     string             `json:"direction,omitempty"`
	Limit         model.Uint64       `json:"limit,omitempty"`
	Entries       []LogQLEntry       `json:"entries,omitempty"`
}
type LogQLError struct {
	Semantic        string `json:"semantic"`
	Category        string `json:"category"`
	CategoryExposed bool   `json:"category_exposed"`
	Message         string `json:"message"`
	LanguageDetail  string `json:"language_detail,omitempty"`
	Start           *int   `json:"start_byte,omitempty"`
	End             *int   `json:"end_byte,omitempty"`
}
type LogQLPipeline struct {
	Retained  bool             `json:"retained"`
	Line      string           `json:"line"`
	Labels    model.Labels     `json:"labels"`
	Unwrapped *model.FloatBits `json:"unwrapped_bits,omitempty"`
}
type LogQLStream struct {
	Labels model.Labels `json:"labels"`
	Hash   string       `json:"hash"`
	Values []LogQLValue `json:"values"`
}
type LogQLValue struct {
	Timestamp    string       `json:"timestamp_ns"`
	Bits         string       `json:"float_bits,omitempty"`
	Labels       model.Labels `json:"labels"`
	Line         string       `json:"line,omitempty"`
	ID           string       `json:"id,omitempty"`
	Multiplicity string       `json:"multiplicity,omitempty"`
}
type LogQLObservation struct {
	ID         string         `json:"id"`
	Accepted   bool           `json:"accepted"`
	Type       string         `json:"type"`
	Output     string         `json:"output,omitempty"`
	Pipeline   *LogQLPipeline `json:"pipeline,omitempty"`
	Values     []LogQLValue   `json:"values"`
	Error      *LogQLError    `json:"error,omitempty"`
	RawStreams []LogQLStream  `json:"raw_native_streams,omitempty"`
	StoredRows []LogQLValue   `json:"owned_stored_rows,omitempty"`
	ClockStart string         `json:"clock_start_ns,omitempty"`
	ClockEnd   string         `json:"clock_end_ns,omitempty"`
}
type LogQLInput struct {
	Profile           string      `json:"profile"`
	Commit            string      `json:"commit"`
	ProfileIdentity   string      `json:"profile_identity"`
	FeatureSet        string      `json:"feature_set"`
	ConfigurationHash string      `json:"configuration_hash"`
	Enabled           []string    `json:"enabled_features"`
	Phase             string      `json:"phase"`
	TimezoneSHA256    string      `json:"timezone_sha256,omitempty"`
	Cases             []LogQLCase `json:"cases"`
	Lookback          int64       `json:"lookback_ns,string"`
	SketchHeap        int         `json:"sketch_heap"`
}
type LogQLBatch struct {
	Profile           string             `json:"profile"`
	Commit            string             `json:"commit"`
	Compiler          string             `json:"compiler"`
	Unicode           string             `json:"unicode"`
	SourceSHA256      string             `json:"source_sha256"`
	ProfileIdentity   string             `json:"profile_identity"`
	FeatureSet        string             `json:"feature_set"`
	ConfigurationHash string             `json:"configuration_hash"`
	TimezoneSHA256    string             `json:"timezone_sha256,omitempty"`
	Observations      []LogQLObservation `json:"observations"`
}

func validateLogQLCase(c LogQLCase) error {
	if c.ID == "" || len(c.Profiles) != 1 || c.Profiles[0] != logQLProfile {
		return fmt.Errorf("unscoped LogQL case %q", c.ID)
	}
	switch c.Phase {
	case "syntax", "pipeline":
		if c.Input.Expression == "" {
			return fmt.Errorf("missing LogQL expression")
		}
		if c.Phase == "pipeline" && c.Input.Entry == nil {
			return fmt.Errorf("missing LogQL pipeline entry")
		}
	case "logql-template":
		if c.Source == "" && c.PipelineQuery == "" {
			return fmt.Errorf("missing template source")
		}
		if (c.Kind == "pipeline" || c.Kind == "pipeline_query") && c.PipelineQuery == "" {
			return fmt.Errorf("full pipeline query required")
		}
		if c.Timezone == "" {
			return fmt.Errorf("explicit template timezone required")
		}
	case "logql-metric":
		if c.Query == "" || (c.Kind != "instant" && c.Kind != "range") {
			return fmt.Errorf("missing metric query/kind")
		}
		if c.Kind == "range" && (c.End < c.Start || c.Step < 0) {
			return fmt.Errorf("invalid LogQL grid")
		}
		if c.Direction != "" && c.Direction != "forward" && c.Direction != "backward" {
			return fmt.Errorf("invalid log direction")
		}
	default:
		return fmt.Errorf("unknown LogQL phase %q", c.Phase)
	}
	entries := c.Entries
	if c.Input.Entry != nil {
		entries = append(append([]LogQLEntry(nil), entries...), *c.Input.Entry)
	}
	ids := map[model.ID]bool{}
	for _, e := range entries {
		if e.ID == (model.ID{}) || ids[e.ID] {
			return fmt.Errorf("missing/duplicate LogQL stored row identity")
		}
		ids[e.ID] = true
		if e.Multiplicity == 0 {
			return fmt.Errorf("zero LogQL multiplicity")
		}
		if err := e.StreamLabels.Validate(); err != nil {
			return err
		}
		if err := e.Metadata.Validate(); err != nil {
			return err
		}
	}
	return nil
}
func validateLogQLBatch(b LogQLBatch, in LogQLInput) error {
	if b.Profile != logQLProfile || b.Commit != logQLCommit || b.SourceSHA256 != logQLSourceSHA || b.Compiler != "go1.24.5" || b.Unicode != "15.0.0" || b.ProfileIdentity != in.ProfileIdentity || b.FeatureSet != in.FeatureSet || b.ConfigurationHash != in.ConfigurationHash {
		return fmt.Errorf("native LogQL build/profile identity mismatch")
	}
	if in.TimezoneSHA256 != "" && in.TimezoneSHA256 != b.TimezoneSHA256 {
		return fmt.Errorf("native LogQL timezone dataset mismatch")
	}
	if len(in.Cases) == 0 || len(b.Observations) != len(in.Cases) {
		return fmt.Errorf("missing native LogQL observations")
	}
	seen := map[string]bool{}
	for i, c := range in.Cases {
		o := b.Observations[i]
		if o.ID != c.ID || seen[c.ID] {
			return fmt.Errorf("native LogQL missing/duplicate/reordered row %s", c.ID)
		}
		if !o.Accepted && o.Error == nil {
			return fmt.Errorf("native LogQL row has no actual observation: %s", c.ID)
		}
		if o.Accepted && (o.Type == "" || o.Error != nil) {
			return fmt.Errorf("invalid native LogQL acceptance observation: %s", c.ID)
		}
		seen[c.ID] = true
	}
	return nil
}

// CompareLogQL preserves raw observations. Only source-proven error identity and
// genuinely exposed category/ranges are projected; prose is not an API contract.
func CompareLogQL(want, got LogQLObservation) []Mismatch {
	var out []Mismatch
	add := func(k string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			out = append(out, Mismatch{k, a, b})
		}
	}
	add("accepted", want.Accepted, got.Accepted)
	add("type", want.Type, got.Type)
	if want.Error != nil || got.Error != nil {
		if want.Error == nil || got.Error == nil {
			add("error", want.Error, got.Error)
			return out
		}
		if want.Error.Semantic == "" || got.Error.Semantic == "" {
			out = append(out, Mismatch{"error.unclassified", want.Error, got.Error})
		} else {
			add("error.semantic", want.Error.Semantic, got.Error.Semantic)
		}
		if want.Error.CategoryExposed {
			add("error.category", want.Error.Category, got.Error.Category)
		}
		if want.Error.Start != nil {
			add("error.start", want.Error.Start, got.Error.Start)
		}
		if want.Error.End != nil {
			add("error.end", want.Error.End, got.Error.End)
		}
		return out
	}
	projectedWant, projectedGot := logQLEmptyLabelProjection(want.Values, got.Values)
	add("output", want.Output, got.Output)
	projectedWantPipeline, projectedGotPipeline := logQLEmptyPipelineLabelProjection(want.Pipeline, got.Pipeline)
	add("pipeline", projectedWantPipeline, projectedGotPipeline)
	add("values", projectedWant, projectedGot)
	return out
}

// logQLEmptyPipelineLabelProjection applies the same declared rule to a pipeline
// observation: paired zero-length label sets are one set whether nil or
// allocated-empty. Retention, line, unwrapped bits and every nonempty label are
// compared unchanged, and the raw observations are never mutated.
func logQLEmptyPipelineLabelProjection(want, got *LogQLPipeline) (*LogQLPipeline, *LogQLPipeline) {
	if want == nil || got == nil || len(want.Labels) != 0 || len(got.Labels) != 0 || (want.Labels == nil) == (got.Labels == nil) {
		return want, got
	}
	a, b := *want, *got
	a.Labels, b.Labels = nil, nil
	return &a, &b
}
func logQLFeatureKey(in []string) string { return strings.Join(in, "\x00") }

// Empty labels are the same set whether nil or allocated-empty. Project only
// paired zero-length label sets; retain raw observations and every other byte,
// value, order, timestamp and multiplicity unchanged.
func logQLEmptyLabelProjection(want, got []LogQLValue) ([]LogQLValue, []LogQLValue) {
	if len(want) != len(got) {
		return want, got
	}
	var a, b []LogQLValue
	for i := range want {
		if len(want[i].Labels) == 0 && len(got[i].Labels) == 0 && (want[i].Labels == nil) != (got[i].Labels == nil) {
			if a == nil {
				a = append([]LogQLValue(nil), want...)
				b = append([]LogQLValue(nil), got...)
			}
			a[i].Labels = nil
			b[i].Labels = nil
		}
	}
	if a != nil {
		return a, b
	}
	return want, got
}
