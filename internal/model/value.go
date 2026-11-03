// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type FloatBits uint64

func (v FloatBits) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%016x", uint64(v)))
}
func (v *FloatBits) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return e
	}
	n, e := strconv.ParseUint(s, 16, 64)
	if e != nil || len(s) != 16 || fmt.Sprintf("%016x", n) != s {
		return errors.New("invalid float bits")
	}
	*v = FloatBits(n)
	return nil
}

type Label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Labels []Label

func (l Labels) Validate() error {
	for i, v := range l {
		if v.Name == "" || i > 0 && l[i-1].Name >= v.Name {
			return errors.New("labels must be sorted and unique")
		}
	}
	return nil
}

type HistogramSpan struct {
	Offset int32  `json:"offset"`
	Length uint32 `json:"length"`
}
type DeltaBucket int64

func (v DeltaBucket) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatInt(int64(v), 10))
}
func (v *DeltaBucket) UnmarshalJSON(b []byte) error {
	s, e := parseDecimal(b, true)
	if e != nil {
		return e
	}
	n, e := strconv.ParseInt(s, 10, 64)
	*v = DeltaBucket(n)
	return e
}

type IntegerHistogram struct {
	Flavor          string           `json:"flavor"`
	Schema          int32            `json:"schema"`
	ZeroThreshold   FloatBits        `json:"zero_threshold"`
	Sum             FloatBits        `json:"sum"`
	Count           uint64           `json:"count,string"`
	ZeroCount       uint64           `json:"zero_count,string"`
	PositiveSpans   []HistogramSpan  `json:"positive_spans"`
	NegativeSpans   []HistogramSpan  `json:"negative_spans"`
	PositiveBuckets []DeltaBucket    `json:"positive_buckets"`
	NegativeBuckets []DeltaBucket    `json:"negative_buckets"`
	PositiveCounts  []AbsoluteBucket `json:"positive_counts,omitempty"`
	NegativeCounts  []AbsoluteBucket `json:"negative_counts,omitempty"`
	ResetHint       string           `json:"reset_hint"`
	CustomBounds    []FloatBits      `json:"custom_bounds,omitempty"`
}
type FloatHistogram struct {
	Flavor          string          `json:"flavor"`
	Schema          int32           `json:"schema"`
	ZeroThreshold   FloatBits       `json:"zero_threshold"`
	Sum             FloatBits       `json:"sum"`
	Count           FloatBits       `json:"count"`
	ZeroCount       FloatBits       `json:"zero_count"`
	PositiveSpans   []HistogramSpan `json:"positive_spans"`
	NegativeSpans   []HistogramSpan `json:"negative_spans"`
	PositiveBuckets []FloatBits     `json:"positive_buckets"`
	NegativeBuckets []FloatBits     `json:"negative_buckets"`
	ResetHint       string          `json:"reset_hint"`
	CustomBounds    []FloatBits     `json:"custom_bounds,omitempty"`
}
type NativeHistogram struct {
	Integer *IntegerHistogram `json:"integer,omitempty"`
	Float   *FloatHistogram   `json:"float,omitempty"`
}

func (h NativeHistogram) Validate() error {
	if (h.Integer == nil) == (h.Float == nil) {
		return errors.New("histogram requires one variant")
	}
	if h.Integer != nil {
		return h.Integer.validateHistogram()
	}
	return h.Float.validateHistogram()
}
