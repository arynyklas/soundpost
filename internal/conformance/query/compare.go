// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"reflect"
	"sort"
)

type HistogramSpan struct {
	Offset int32  `json:"offset"`
	Length uint32 `json:"length"`
}

// Integer counts and signed deltas remain canonical decimal strings. Floating
// histogram counts/buckets instead use their exact IEEE bit fields; never cast.
type Histogram struct {
	Kind               string          `json:"kind"`
	Schema             int32           `json:"schema"`
	ResetHint          string          `json:"reset_hint"`
	Count              string          `json:"count,omitempty"`
	CountBits          string          `json:"count_bits,omitempty"`
	ZeroCount          string          `json:"zero_count,omitempty"`
	ZeroCountBits      string          `json:"zero_count_bits,omitempty"`
	ZeroThresholdBits  string          `json:"zero_threshold_bits"`
	SumBits            string          `json:"sum_bits"`
	PositiveSpans      []HistogramSpan `json:"positive_spans"`
	NegativeSpans      []HistogramSpan `json:"negative_spans"`
	PositiveDeltas     []string        `json:"positive_deltas,omitempty"`
	NegativeDeltas     []string        `json:"negative_deltas,omitempty"`
	PositiveBucketBits []string        `json:"positive_bucket_bits,omitempty"`
	NegativeBucketBits []string        `json:"negative_bucket_bits,omitempty"`
	CustomBoundaryBits []string        `json:"custom_boundary_bits,omitempty"`
}
type Value struct {
	Timestamp string            `json:"timestamp"`
	Bits      string            `json:"bits,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Line      string            `json:"line,omitempty"`
	Histogram *Histogram        `json:"histogram,omitempty"`
}
type Diagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type LanguageError struct {
	Code  string `json:"code"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}
type OracleIdentity struct {
	Profile             string `json:"profile"`
	Revision            string `json:"revision"`
	Version             string `json:"version"`
	ImageSHA256         string `json:"image_sha256,omitempty"`
	ConfigurationSHA256 string `json:"configuration_sha256,omitempty"`
}
type SemanticResult struct {
	Kind        string              `json:"kind"`
	Type        string              `json:"type"`
	Values      []Value             `json:"values"`
	Diagnostics []Diagnostic        `json:"diagnostics"`
	Error       *LanguageError      `json:"error,omitempty"`
	Oracle      *OracleIdentity     `json:"oracle,omitempty"`
	Syntax      []SyntaxObservation `json:"syntax,omitempty"`
	Evaluation  *EvaluationBatch    `json:"evaluation,omitempty"`
	LogQL       *LogQLBatch         `json:"logql,omitempty"`
}
type OrderingFreedom struct{ UnorderedVector bool }
type Mismatch struct {
	Field string
	Want  any
	Got   any
}

func Compare(want, got SemanticResult, freedom OrderingFreedom) []Mismatch {
	var out []Mismatch
	add := func(field string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			out = append(out, Mismatch{field, a, b})
		}
	}
	add("kind", want.Kind, got.Kind)
	add("type", want.Type, got.Type)
	add("diagnostics", want.Diagnostics, got.Diagnostics)
	add("error", want.Error, got.Error)
	add("syntax", want.Syntax, got.Syntax)
	add("evaluation", want.Evaluation, got.Evaluation)
	add("logql", want.LogQL, got.LogQL)
	a, b := want.Values, got.Values
	if freedom.UnorderedVector && want.Kind == "vector" && got.Kind == "vector" {
		a = canonicalVector(a)
		b = canonicalVector(b)
	}
	add("values", a, b)
	return out
}
func canonicalVector(values []Value) []Value {
	r := append([]Value(nil), values...)
	sort.SliceStable(r, func(i, j int) bool {
		a, _ := json.Marshal(r[i])
		b, _ := json.Marshal(r[j])
		return string(a) < string(b)
	})
	return r
}
