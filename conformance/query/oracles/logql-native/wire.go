//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import "encoding/json"

type label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type field struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}
type entry struct {
	Timestamp    string  `json:"timestamp_ns"`
	ID           string  `json:"id"`
	Multiplicity string  `json:"multiplicity"`
	Line         string  `json:"line"`
	Labels       []label `json:"stream_labels"`
	Metadata     []label `json:"structured_metadata"`
	Fields       []field `json:"fields"`
}
type clock struct {
	Kind      string `json:"kind"`
	Layout    string `json:"layout,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Precision string `json:"precision,omitempty"`
}
type testCase struct {
	ID             string            `json:"id"`
	Phase          string            `json:"phase"`
	Profiles       []string          `json:"profiles"`
	Enabled        []string          `json:"enabled_features"`
	Obligation     string            `json:"obligation"`
	BindingScope   string            `json:"binding_scope"`
	ConfigIdentity string            `json:"config_identity"`
	Configuration  map[string]string `json:"configuration"`
	Input          struct {
		Expression string `json:"expression"`
		Entry      *entry `json:"entry"`
	} `json:"input"`
	Expected      json.RawMessage `json:"expected"`
	Kind          string          `json:"kind"`
	Source        string          `json:"source"`
	PipelineQuery string          `json:"pipeline_query"`
	Line          string          `json:"line"`
	Timestamp     string          `json:"timestamp_ns"`
	Labels        []label         `json:"labels"`
	Fields        []field         `json:"fields"`
	Timezone      string          `json:"timezone"`
	Clock         *clock          `json:"clock_observation"`
	Query         string          `json:"query"`
	Time          string          `json:"time_ns"`
	Start         string          `json:"start_ns"`
	End           string          `json:"end_ns"`
	Step          string          `json:"step_ns"`
	Interval      string          `json:"interval_ns"`
	Direction     string          `json:"direction"`
	Limit         string          `json:"limit"`
	Entries       []entry         `json:"entries"`
}
type input struct {
	Profile           string     `json:"profile"`
	Commit            string     `json:"commit"`
	ProfileIdentity   string     `json:"profile_identity"`
	FeatureSet        string     `json:"feature_set"`
	ConfigurationHash string     `json:"configuration_hash"`
	Enabled           []string   `json:"enabled_features"`
	Phase             string     `json:"phase"`
	TimezoneSHA256    string     `json:"timezone_sha256"`
	Lookback          string     `json:"lookback_ns"`
	SketchHeap        int        `json:"sketch_heap"`
	Cases             []testCase `json:"cases"`
}
type languageError struct {
	Semantic        string `json:"semantic"`
	Category        string `json:"category"`
	CategoryExposed bool   `json:"category_exposed"`
	Message         string `json:"message"`
	Start           *int   `json:"start_byte,omitempty"`
	End             *int   `json:"end_byte,omitempty"`
}
type pipelineResult struct {
	Retained  bool    `json:"retained"`
	Line      string  `json:"line"`
	Labels    []label `json:"labels"`
	Unwrapped *string `json:"unwrapped_bits,omitempty"`
}
type resultValue struct {
	Timestamp    string  `json:"timestamp_ns"`
	Bits         string  `json:"float_bits,omitempty"`
	Labels       []label `json:"labels"`
	Line         string  `json:"line,omitempty"`
	ID           string  `json:"id,omitempty"`
	Multiplicity string  `json:"multiplicity,omitempty"`
}
type rawStream struct {
	Labels []label       `json:"labels"`
	Hash   string        `json:"hash"`
	Values []resultValue `json:"values"`
}
type observation struct {
	ID         string          `json:"id"`
	Accepted   bool            `json:"accepted"`
	Type       string          `json:"type"`
	Output     string          `json:"output,omitempty"`
	Pipeline   *pipelineResult `json:"pipeline,omitempty"`
	Values     []resultValue   `json:"values"`
	RawStreams []rawStream     `json:"raw_native_streams,omitempty"`
	Error      *languageError  `json:"error,omitempty"`
	ClockStart string          `json:"clock_start_ns,omitempty"`
	ClockEnd   string          `json:"clock_end_ns,omitempty"`
}
type batch struct {
	Profile           string        `json:"profile"`
	Commit            string        `json:"commit"`
	Compiler          string        `json:"compiler"`
	Unicode           string        `json:"unicode"`
	SourceSHA256      string        `json:"source_sha256"`
	ProfileIdentity   string        `json:"profile_identity"`
	FeatureSet        string        `json:"feature_set"`
	ConfigurationHash string        `json:"configuration_hash"`
	TimezoneSHA256    string        `json:"timezone_sha256"`
	Observations      []observation `json:"observations"`
}
