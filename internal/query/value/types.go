// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Package value contains project-local lossless language execution values.
package value

import (
	"bytes"
	"context"
	"github.com/arynyklas/soundpost/internal/model"
	"sort"
	"sync"
)

const StaleBits model.FloatBits = 0x7ff0000000000002

// Time and all durations are nanoseconds; conversion from C06 happens once.
type Evaluation struct {
	Instant          bool
	Time, Start, End model.UnixNano
	Step             int64
}
type Sample struct {
	Time           model.UnixNano
	Float          model.FloatBits
	Histogram      *model.NativeHistogram
	StartTimestamp *model.UnixNano
}

func (s Sample) Stale() bool {
	if s.Histogram == nil {
		return s.Float == StaleBits
	}
	if h := s.Histogram.Integer; h != nil {
		return h.Sum == StaleBits
	}
	if h := s.Histogram.Float; h != nil {
		return h.Sum == StaleBits
	}
	return false
}
func EqualSample(a, b Sample) bool {
	if a.Time != b.Time || (a.StartTimestamp == nil) != (b.StartTimestamp == nil) {
		return false
	}
	if a.StartTimestamp != nil && *a.StartTimestamp != *b.StartTimestamp {
		return false
	}
	if (a.Histogram == nil) != (b.Histogram == nil) {
		return false
	}
	if a.Histogram != nil {
		return EqualHistogram(*a.Histogram, *b.Histogram)
	}
	return a.Float == b.Float
}

type Series struct {
	Project  model.ID
	Labels   model.Labels
	Samples  []Sample
	DropName bool
}
type Result struct {
	Type       string
	Scalar     Sample
	String     string
	Vector     []Series
	Matrix     []Series
	Logs       []Log
	Partial    bool
	Watermarks []model.Cursor
}
type Account interface {
	Reserve(bytes int64) error
	Release(bytes int64)
	Check(context.Context) error
}

// BoundedAccount is useful to embedded callers and semantic tests. C06 may supply
// its own account with policy revalidation in Check.
type BoundedAccount struct {
	mu          sync.Mutex
	limit, used int64
}

func NewBoundedAccount(limit int64) *BoundedAccount { return &BoundedAccount{limit: limit} }
func (a *BoundedAccount) Reserve(n int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n < 0 || a.limit < 0 || n > a.limit-a.used {
		return model.Fail(model.Quota)
	}
	a.used += n
	return nil
}
func (a *BoundedAccount) Release(n int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n >= 0 {
		a.used -= n
		if a.used < 0 {
			a.used = 0
		}
	}
}
func (a *BoundedAccount) Check(ctx context.Context) error { return ctx.Err() }
func (a *BoundedAccount) Used() int64                     { a.mu.Lock(); defer a.mu.Unlock(); return a.used }
func SampleBytes(s Sample) int64 {
	n := int64(48)
	if s.StartTimestamp != nil {
		n += 8
	}
	if s.Histogram != nil {
		n += HistogramBytes(*s.Histogram)
	}
	return n
}
func SeriesBytes(s Series) int64 {
	n := int64(80 + len(s.Labels)*32)
	for _, l := range s.Labels {
		n += int64(len(l.Name) + len(l.Value))
	}
	for _, p := range s.Samples {
		n += SampleBytes(p)
	}
	return n
}
func ResultBytes(r Result) int64 {
	n := int64(96 + len(r.String) + len(r.Watermarks)*24)
	if r.Type == "scalar" {
		n += SampleBytes(r.Scalar)
	}
	for _, s := range r.Vector {
		n += SeriesBytes(s)
	}
	for _, s := range r.Matrix {
		n += SeriesBytes(s)
	}
	for _, l := range r.Logs {
		n += LogBytes(l)
	}
	return n
}

// InheritMetadata never infers completeness from the presence of output rows.
// Same-group read cuts merge by their minimum safe index, never their maximum.
func InheritMetadata(result *Result, inputs ...Result) {
	hasCursors := len(result.Watermarks) > 0
	for _, input := range inputs {
		result.Partial = result.Partial || input.Partial
		hasCursors = hasCursors || len(input.Watermarks) > 0
	}
	if !hasCursors {
		result.Watermarks = nil
		return
	}
	groups := make(map[model.ID]uint64, len(result.Watermarks))
	merge := func(cursors []model.Cursor) {
		for _, c := range cursors {
			index, ok := groups[c.Group]
			if !ok || uint64(c.Index) < index {
				groups[c.Group] = uint64(c.Index)
			}
		}
	}
	merge(result.Watermarks)
	for _, input := range inputs {
		merge(input.Watermarks)
	}
	if len(groups) == 0 {
		result.Watermarks = nil
		return
	}
	result.Watermarks = make([]model.Cursor, 0, len(groups))
	for group, index := range groups {
		result.Watermarks = append(result.Watermarks, model.Cursor{Group: group, Index: model.Uint64(index)})
	}
	sort.Slice(result.Watermarks, func(i, j int) bool {
		return bytes.Compare(result.Watermarks[i].Group[:], result.Watermarks[j].Group[:]) < 0
	})
}
