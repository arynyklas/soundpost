// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package query is the owned C06 service layer: authorized execution of the
// owned PromQL and LogQL engines over the C05 scan seam, plus discovery,
// exemplar and formatting services. It never calls an upstream engine and never
// converts a partial scan, a failed project or a missed limit into a complete
// answer.
package query

import (
	"context"
	"encoding/json"
	"errors"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/syntax"
	"soundpost/internal/storage"
	"strings"
	"time"
)

// Scanner is C05's Scan seam, exactly.
type Scanner interface {
	Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error)
}

// Revalidator is C02's scope revalidation.
type Revalidator interface {
	Revalidate(ctx context.Context, scope auth.Scope) error
}

// Registry resolves an immutable pinned profile and registered feature set.
type Registry interface {
	Resolve(id, featureSet string) (profile.Profile, error)
}

// Tickets issues and opens short-lived opaque tokens bound to the issuing
// scope's visibility fingerprint, policy epoch and delete generation. The
// production implementation is *auth.Cache.
type Tickets interface {
	IssueTicket(ctx context.Context, scope auth.Scope, kind string, subject model.ID, state []byte, ttl time.Duration) (string, error)
	OpenTicket(ctx context.Context, scope auth.Scope, kind, token string) (model.ID, []byte, error)
}

// ResultCache is the C02 cache keyed by org, effective visibility, policy epoch,
// delete generation, profile, query and parameters. The production
// implementation is *auth.Cache.
type ResultCache interface {
	Lookup(ctx context.Context, scope auth.Scope, profile, query, params string) (auth.CacheResult, error)
	Store(ctx context.Context, scope auth.Scope, fill auth.CacheFill, value []byte, negative bool) error
}

const (
	LanguagePromQL = "promql"
	LanguageLogQL  = "logql"
)

const (
	CompletenessComplete = "complete"
	CompletenessPartial  = "partial"
	CompletenessStale    = "stale"
)

// Evaluation is either an instant (Instant, Time) or a range (Start, End, Step)
// evaluation; every field of the other form must be zero. Times and the step are
// canonical nanosecond decimal strings on the wire.
type Evaluation struct {
	Instant bool           `json:"instant"`
	Time    model.UnixNano `json:"time"`
	Start   model.UnixNano `json:"start"`
	End     model.UnixNano `json:"end"`
	Step    model.Int64    `json:"step"`
}

// Budget requests per-query resource budgets; zero fields select the service
// defaults and any value above the operator's bound is rejected before work.
type Budget struct {
	TimeoutNS   model.Int64  `json:"timeout_ns"`
	MemoryBytes model.Uint64 `json:"memory_bytes"`
	MaxReturned model.Uint64 `json:"max_returned"`
}

// Request is the C06 query request. Source is only for raw.read scopes: the one
// named restricted source whose logs are read (it is never an authorization
// carrier, the scope must already allow it).
type Request struct {
	Language     string         `json:"language"`
	Profile      string         `json:"profile"`
	Expression   string         `json:"expression"`
	Evaluation   Evaluation     `json:"evaluation"`
	Projects     []model.ID     `json:"projects"`
	FeatureSet   string         `json:"feature_set"`
	Budget       Budget         `json:"budget"`
	MinCursors   []model.Cursor `json:"min_cursors,omitempty"`
	AllowPartial bool           `json:"allow_partial"`
	Source       *model.ID      `json:"source,omitempty"`
	// LogLimit and LogOrder apply to LogQL log-stream queries only. LogLimit is an
	// explicit page size (at most Budget.MaxReturned): the result is exactly the
	// first LogLimit entries of the complete ordered result and Stats.LimitReached
	// says whether more existed. Without it a result larger than the returned
	// budget is a Quota error, never a silently trimmed answer. LogOrder is
	// "backward" (newest first, the default) or "forward".
	LogLimit model.Uint64 `json:"log_limit,omitempty"`
	LogOrder string       `json:"log_order,omitempty"`
}

// SourceRange is a half-open zero-based UTF-8 byte and Unicode rune range.
type SourceRange struct {
	StartByte int `json:"start_byte"`
	EndByte   int `json:"end_byte"`
	StartRune int `json:"start_rune"`
	EndRune   int `json:"end_rune"`
}

func wireRange(r syntax.SourceRange) *SourceRange {
	return &SourceRange{StartByte: r.StartByte, EndByte: r.EndByte, StartRune: r.StartRune, EndRune: r.EndRune}
}

// Diagnostic is one language annotation. Severity is "info" for engine
// categories ending in "Info" and "warning" otherwise; Code is the engine's
// category; SafeMessage is a static message that never contains source text.
type Diagnostic struct {
	Severity    string       `json:"severity"`
	Code        string       `json:"code"`
	SourceRange *SourceRange `json:"source_range,omitempty"`
	SafeMessage string       `json:"safe_message"`
}

// Sample is a lossless evaluated sample. Exactly one of Float (exact IEEE bits)
// and Histogram is present; an ordinary NaN keeps its bits and a stale marker
// is never emitted as a sample.
type Sample struct {
	Time           model.UnixNano         `json:"time"`
	Float          *model.FloatBits       `json:"float,omitempty"`
	Histogram      *model.NativeHistogram `json:"histogram,omitempty"`
	StartTimestamp *model.UnixNano        `json:"start_timestamp,omitempty"`
}

// VectorElement is one instant-vector element with its language labels.
type VectorElement struct {
	Labels model.Labels `json:"labels"`
	Sample Sample       `json:"sample"`
}

// Series is one range-matrix series.
type Series struct {
	Labels  model.Labels `json:"labels"`
	Samples []Sample     `json:"samples"`
}

// LogEntry is one nanosecond log record. Index is the entry's position in the
// language-defined order of the whole project result, so the order survives
// grouping into streams. Stream labels and structured metadata stay separate.
type LogEntry struct {
	Index              model.Uint64   `json:"index"`
	Time               model.UnixNano `json:"time"`
	ID                 model.ID       `json:"id"`
	Source             *model.ID      `json:"source,omitempty"`
	Multiplicity       model.Uint64   `json:"multiplicity"`
	Line               string         `json:"line"`
	StreamLabels       model.Labels   `json:"stream_labels"`
	StructuredMetadata model.Labels   `json:"structured_metadata"`
}

// LogStream groups entries by their resulting language labels, in order of
// first appearance.
type LogStream struct {
	Labels  model.Labels `json:"labels"`
	Entries []LogEntry   `json:"entries"`
}

type ValueType string

const (
	ValueScalar  ValueType = "scalar"
	ValueString  ValueType = "string"
	ValueVector  ValueType = "vector"
	ValueMatrix  ValueType = "matrix"
	ValueStreams ValueType = "streams"
)

// Value is the typed C06 value union Scalar|String|InstantVector|RangeMatrix|
// LogStreams. Exactly the field named by Type is populated.
type Value struct {
	Type    ValueType
	Scalar  Sample
	String  string
	Vector  []VectorElement
	Matrix  []Series
	Streams []LogStream
}

type valueWire struct {
	Type    ValueType        `json:"type"`
	Scalar  *Sample          `json:"scalar,omitempty"`
	String  *string          `json:"string,omitempty"`
	Vector  *[]VectorElement `json:"vector,omitempty"`
	Matrix  *[]Series        `json:"matrix,omitempty"`
	Streams *[]LogStream     `json:"streams,omitempty"`
}

func (v Value) MarshalJSON() ([]byte, error) {
	w := valueWire{Type: v.Type}
	switch v.Type {
	case ValueScalar:
		w.Scalar = &v.Scalar
	case ValueString:
		w.String = &v.String
	case ValueVector:
		if v.Vector == nil {
			v.Vector = []VectorElement{}
		}
		w.Vector = &v.Vector
	case ValueMatrix:
		if v.Matrix == nil {
			v.Matrix = []Series{}
		}
		w.Matrix = &v.Matrix
	case ValueStreams:
		if v.Streams == nil {
			v.Streams = []LogStream{}
		}
		w.Streams = &v.Streams
	default:
		return nil, errors.New("invalid value type")
	}
	return json.Marshal(w)
}

func (v *Value) UnmarshalJSON(raw []byte) error {
	var w valueWire
	if err := model.StrictJSON(raw, &w); err != nil {
		return err
	}
	out := Value{Type: w.Type}
	present := 0
	count := func(ok bool) {
		if ok {
			present++
		}
	}
	count(w.Scalar != nil)
	count(w.String != nil)
	count(w.Vector != nil)
	count(w.Matrix != nil)
	count(w.Streams != nil)
	if present != 1 {
		return errors.New("value union requires exactly one payload")
	}
	switch {
	case w.Type == ValueScalar && w.Scalar != nil:
		out.Scalar = *w.Scalar
	case w.Type == ValueString && w.String != nil:
		out.String = *w.String
	case w.Type == ValueVector && w.Vector != nil:
		out.Vector = *w.Vector
	case w.Type == ValueMatrix && w.Matrix != nil:
		out.Matrix = *w.Matrix
	case w.Type == ValueStreams && w.Streams != nil:
		out.Streams = *w.Streams
	default:
		return errors.New("value payload does not match its type")
	}
	*v = out
	return nil
}

// Stats are actual measured counters, never estimates of dataset size or
// upstream statistics. PeakMemoryBytes is this project's own peak of accounted
// working memory.
type Stats struct {
	ScansStarted    model.Uint64 `json:"scans_started"`
	PagesRead       model.Uint64 `json:"pages_read"`
	RowsRead        model.Uint64 `json:"rows_read"`
	BytesRead       model.Uint64 `json:"bytes_read"`
	SeriesReturned  model.Uint64 `json:"series_returned"`
	SamplesReturned model.Uint64 `json:"samples_returned"`
	LogsReturned    model.Uint64 `json:"logs_returned"`
	PeakMemoryBytes model.Uint64 `json:"peak_memory_bytes"`
	ElapsedNS       model.Int64  `json:"elapsed_ns"`
	Cached          bool         `json:"cached"`
	LimitReached    bool         `json:"limit_reached"`
}

// Failure is the typed reason one project produced no value. It only appears
// when the caller opted into partial results.
type Failure struct {
	Code        string       `json:"code"`
	Category    string       `json:"category,omitempty"`
	SourceRange *SourceRange `json:"source_range,omitempty"`
	SafeMessage string       `json:"safe_message"`
}

// ProjectResult is one project's independent evaluation. Value is nil only when
// Failure is set, and then Completeness is partial.
type ProjectResult struct {
	ProjectID    model.ID       `json:"project_id"`
	Value        *Value         `json:"value"`
	Diagnostics  []Diagnostic   `json:"diagnostics"`
	Watermarks   []model.Cursor `json:"watermarks"`
	Completeness string         `json:"completeness"`
	Stats        Stats          `json:"stats"`
	Failure      *Failure       `json:"failure,omitempty"`
}

// Result holds one project result for each requested project, ordered by
// project ID. Series never combine across projects and no project label is
// ever injected.
type Result struct {
	Projects []ProjectResult `json:"projects"`
}

// Matcher is a label matcher with =, !=, =~ or !~ semantics (a missing label is
// the empty string).
type Matcher struct {
	Name  string `json:"name"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// TimeRange is a raw half-open [Start,End) C05 scan range.
type TimeRange struct {
	Start model.UnixNano `json:"start"`
	End   model.UnixNano `json:"end"`
}

const (
	DiscoverMetricNames = "metric_names"
	DiscoverLabelNames  = "label_names"
	DiscoverLabelValues = "label_values"
	DiscoverTemplates   = "templates"
	DiscoverFields      = "fields"
)

// DiscoveryRequest is the C06 discovery request. Source (raw.read scopes only)
// and Profile/FeatureSet (required only when a matcher is a regular expression)
// are additive optional fields.
type DiscoveryRequest struct {
	Projects   []model.ID `json:"projects"`
	Signal     model.Kind `json:"signal"`
	Kind       string     `json:"kind"`
	Field      string     `json:"field,omitempty"`
	Matchers   []Matcher  `json:"matchers"`
	Time       TimeRange  `json:"time"`
	Limit      uint32     `json:"limit"`
	Cursor     string     `json:"cursor,omitempty"`
	Source     *model.ID  `json:"source,omitempty"`
	Profile    string     `json:"profile,omitempty"`
	FeatureSet string     `json:"feature_set,omitempty"`
}

// Freshness tells exactly what a response was computed from: the merged
// read cuts, whether every shard answered, and whether it came from the cache.
type Freshness struct {
	Completeness string         `json:"completeness"`
	Watermarks   []model.Cursor `json:"watermarks"`
	Cached       bool           `json:"cached"`
}

// DiscoveryResult is one page of sorted distinct names. NextCursor is present
// exactly when More is true; a cursor is authenticated, bound to the caller's
// effective visibility, policy epoch, delete generation and these request
// parameters, and expires after 15 minutes.
type DiscoveryResult struct {
	Items      []string  `json:"items"`
	More       bool      `json:"more"`
	NextCursor string    `json:"next_cursor,omitempty"`
	Freshness  Freshness `json:"freshness"`
}

// ExemplarRequest asks for exemplars attached to the series the expression's
// selectors match during Window.
type ExemplarRequest struct {
	Projects   []model.ID `json:"projects"`
	Profile    string     `json:"profile"`
	FeatureSet string     `json:"feature_set"`
	Expression string     `json:"expression"`
	Window     TimeRange  `json:"window"`
	Limit      uint32     `json:"limit"`
	Cursor     string     `json:"cursor,omitempty"`
}

// Exemplar links one series sample to the trace that produced it.
type Exemplar struct {
	Project model.ID      `json:"project_id"`
	Labels  model.Labels  `json:"labels"`
	Sample  Sample        `json:"sample"`
	Trace   model.ID      `json:"trace_id"`
	Span    *model.SpanID `json:"span_id,omitempty"`
	Record  model.ID      `json:"record_id"`
}

// ExemplarResult is one page ordered by (project, series, time, record).
type ExemplarResult struct {
	Exemplars  []Exemplar `json:"exemplars"`
	More       bool       `json:"more"`
	NextCursor string     `json:"next_cursor,omitempty"`
	Freshness  Freshness  `json:"freshness"`
}

// FormatRequest names the language, pinned profile and registered feature set
// whose grammar formats the expression.
type FormatRequest struct {
	Language   string `json:"language"`
	Profile    string `json:"profile"`
	FeatureSet string `json:"feature_set"`
	Expression string `json:"expression"`
}

// FormatResult is formatted text that parses to the same typed tree.
type FormatResult struct {
	Formatted   string       `json:"formatted"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

func validLanguage(l string) bool { return l == LanguagePromQL || l == LanguageLogQL }

// profileMatchesLanguage rejects a language/profile mismatch before any parse.
func profileMatchesLanguage(language, profileID string) bool {
	return validLanguage(language) && strings.HasPrefix(profileID, language+"-")
}
