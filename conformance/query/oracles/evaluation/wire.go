//go:build soundpost_evaluation_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Independently authored DEVELOPMENT-ONLY observation driver. Compiled in the
// separately acquired Apache-2.0 Prometheus module, never in Soundpost binaries.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

type nano int64

func (n nano) MarshalJSON() ([]byte, error) { return json.Marshal(strconv.FormatInt(int64(n), 10)) }
func (n *nano) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != text {
		return fmt.Errorf("noncanonical nanoseconds")
	}
	*n = nano(value)
	return nil
}

type bits uint64

func (b bits) MarshalJSON() ([]byte, error) { return json.Marshal(fmt.Sprintf("%016x", uint64(b))) }
func (b *bits) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	value, err := strconv.ParseUint(text, 16, 64)
	if err != nil || len(text) != 16 || fmt.Sprintf("%016x", value) != text {
		return fmt.Errorf("noncanonical FloatBits")
	}
	*b = bits(value)
	return nil
}
func (b bits) number() float64 { return math.Float64frombits(uint64(b)) }
func floatBits(f float64) bits { return bits(math.Float64bits(f)) }

type delta int64

func (d *delta) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != text {
		return fmt.Errorf("noncanonical histogram delta")
	}
	*d = delta(value)
	return nil
}

type absolute uint64

func (a *absolute) UnmarshalJSON(raw []byte) error {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return err
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != text {
		return fmt.Errorf("noncanonical histogram count")
	}
	*a = absolute(value)
	return nil
}

type span struct {
	Offset int32  `json:"offset"`
	Length uint32 `json:"length"`
}
type integerHistogram struct {
	Flavor          string     `json:"flavor"`
	Schema          int32      `json:"schema"`
	ZeroThreshold   bits       `json:"zero_threshold"`
	Sum             bits       `json:"sum"`
	Count           uint64     `json:"count,string"`
	ZeroCount       uint64     `json:"zero_count,string"`
	PositiveSpans   []span     `json:"positive_spans"`
	NegativeSpans   []span     `json:"negative_spans"`
	PositiveBuckets []delta    `json:"positive_buckets"`
	NegativeBuckets []delta    `json:"negative_buckets"`
	PositiveCounts  []absolute `json:"positive_counts,omitempty"`
	NegativeCounts  []absolute `json:"negative_counts,omitempty"`
	ResetHint       string     `json:"reset_hint"`
	CustomBounds    []bits     `json:"custom_bounds,omitempty"`
}
type floatHistogram struct {
	Flavor          string `json:"flavor"`
	Schema          int32  `json:"schema"`
	ZeroThreshold   bits   `json:"zero_threshold"`
	Sum             bits   `json:"sum"`
	Count           bits   `json:"count"`
	ZeroCount       bits   `json:"zero_count"`
	PositiveSpans   []span `json:"positive_spans"`
	NegativeSpans   []span `json:"negative_spans"`
	PositiveBuckets []bits `json:"positive_buckets"`
	NegativeBuckets []bits `json:"negative_buckets"`
	ResetHint       string `json:"reset_hint"`
	CustomBounds    []bits `json:"custom_bounds,omitempty"`
}
type nativeHistogram struct {
	Integer *integerHistogram `json:"integer,omitempty"`
	Float   *floatHistogram   `json:"float,omitempty"`
}
type label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type sample struct {
	Time           nano             `json:"time"`
	Float          *bits            `json:"float_bits,omitempty"`
	Histogram      *nativeHistogram `json:"histogram,omitempty"`
	StartTimestamp *nano            `json:"start_timestamp_ns,omitempty"`
}
type series struct {
	Project string   `json:"project,omitempty"`
	Labels  []label  `json:"labels"`
	Samples []sample `json:"samples"`
}
type fixtureCase struct {
	ID           string   `json:"id"`
	Profiles     []string `json:"profiles"`
	Enabled      []string `json:"enabled_features"`
	Query        string   `json:"query"`
	Kind         string   `json:"kind"`
	Time         nano     `json:"time,omitempty"`
	Start        nano     `json:"start,omitempty"`
	End          nano     `json:"end,omitempty"`
	Step         int64    `json:"step,string,omitempty"`
	Lookback     int64    `json:"lookback_ns,string,omitempty"`
	SubqueryStep int64    `json:"subquery_step_ns,string,omitempty"`
	Series       []series `json:"series"`
}
type input struct {
	Profile           string                     `json:"profile"`
	Commit            string                     `json:"commit"`
	ProfileIdentity   string                     `json:"profile_identity"`
	FeatureSet        string                     `json:"feature_set"`
	ConfigurationHash string                     `json:"configuration_hash"`
	Enabled           []string                   `json:"enabled_features"`
	Lookback          int64                      `json:"lookback_ns,string"`
	SubqueryStep      int64                      `json:"subquery_step_ns,string"`
	Cases             []fixtureCase              `json:"cases"`
	Configuration     map[string]json.RawMessage `json:"configuration"`
	ManifestVersion   int                        `json:"manifest_version"`
}
type annotation struct {
	ID       string `json:"id,omitempty"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Start    int    `json:"start"`
	End      int    `json:"end"`
}
type languageError struct {
	Category        string `json:"category"`
	CategoryExposed bool   `json:"category_exposed"`
	Message         string `json:"message"`
	Start           int    `json:"start"`
	End             int    `json:"end"`
	ID              string `json:"id,omitempty"`
	RangeExposed    bool   `json:"range_exposed"`
}
type watermark struct {
	Group string `json:"group"`
	Index uint64 `json:"index,string"`
}
type observation struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	String      string         `json:"string,omitempty"`
	Series      []series       `json:"series"`
	Annotations []annotation   `json:"annotations"`
	Complete    bool           `json:"complete"`
	Partial     bool           `json:"partial"`
	Watermarks  []watermark    `json:"watermarks"`
	Error       *languageError `json:"error,omitempty"`
}
type batch struct {
	Profile           string        `json:"profile"`
	Commit            string        `json:"commit"`
	Compiler          string        `json:"compiler"`
	SourceSHA256      string        `json:"source_sha256"`
	ProfileIdentity   string        `json:"profile_identity"`
	FeatureSet        string        `json:"feature_set"`
	ConfigurationHash string        `json:"configuration_hash"`
	Observations      []observation `json:"observations"`
}
