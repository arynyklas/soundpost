//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/grafana/loki/v3/pkg/iter"
	"github.com/grafana/loki/v3/pkg/logproto"
	native "github.com/grafana/loki/v3/pkg/logql"
	nlog "github.com/grafana/loki/v3/pkg/logql/log"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/grafana/loki/v3/pkg/util/validation"
)

type oracleLimits struct{ variants bool }

func (oracleLimits) MaxQuerySeries(context.Context, string) int                        { return 5000000 }
func (oracleLimits) MaxQueryRange(context.Context, string) time.Duration               { return 0 }
func (oracleLimits) QueryTimeout(context.Context, string) time.Duration                { return time.Minute }
func (oracleLimits) BlockedQueries(context.Context, string) []*validation.BlockedQuery { return nil }
func (l oracleLimits) EnableMultiVariantQueries(string) bool                           { return l.variants }

type fixtureQuerier struct{ entries []entry }

// Source stream identity uses the ACTUAL pinned native labels.Hash over original
// labels, even when pipeline stages mutate query-visible labels. Native merge
// iterators, not this driver, choose cross-stream ordering before limits.
func (q *fixtureQuerier) SelectLogs(ctx context.Context, p native.SelectLogParams) (iter.EntryIterator, error) {
	selector, e := p.LogSelector()
	if e != nil {
		return nil, e
	}
	pipeline, e := selector.Pipeline()
	if e != nil {
		return nil, e
	}
	groups := map[string]int{}
	var streams []logproto.Stream
	for _, r := range q.entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		ts, e := number(r.Timestamp)
		if e != nil {
			return nil, e
		}
		at := time.Unix(0, ts)
		if at.Before(p.Start) || !at.Before(p.End) {
			continue
		}
		ls := nativeLabels(r.Labels)
		if !matches(selector, ls) {
			continue
		}
		line, lr, ok := pipeline.ForStream(ls).ProcessString(ts, r.Line, metadata(r.Metadata)...)
		if !ok {
			continue
		}
		n, e := strconv.ParseUint(r.Multiplicity, 10, 64)
		if e != nil || n == 0 || n > 5000000 {
			return nil, fmt.Errorf("invalid native row multiplicity")
		}
		key := ls.String() + "\x00" + lr.String()
		index, exists := groups[key]
		if !exists {
			index = len(streams)
			groups[key] = index
			streams = append(streams, logproto.Stream{Labels: lr.String(), Hash: ls.Hash()})
		}
		for j := uint64(0); j < n; j++ {
			streams[index].Entries = append(streams[index].Entries, logproto.Entry{Timestamp: at, Line: line})
		}
	}
	for i := range streams {
		entries := streams[i].Entries
		sort.SliceStable(entries, func(a, b int) bool {
			if p.Direction == logproto.BACKWARD {
				return entries[a].Timestamp.After(entries[b].Timestamp)
			}
			return entries[a].Timestamp.Before(entries[b].Timestamp)
		})
	}
	return iter.NewStreamsIterator(streams, p.Direction), nil
}
func (q *fixtureQuerier) SelectSamples(ctx context.Context, p native.SelectSampleParams) (iter.SampleIterator, error) {
	if p.SampleQueryRequest == nil || p.Plan == nil {
		return nil, fmt.Errorf("missing native sample AST")
	}
	var extractors []nlog.SampleExtractor
	var selector syntax.LogSelectorExpr
	var e error
	switch expr := p.Plan.AST.(type) {
	case syntax.SampleExpr:
		extractors, e = expr.Extractors()
		if e == nil {
			selector, e = expr.Selector()
		}
	case syntax.VariantsExpr:
		extractors, e = expr.Extractors()
		selector = expr.LogRange().Left
	default:
		return nil, fmt.Errorf("unhandled native sample AST %T", p.Plan.AST)
	}
	if e != nil {
		return nil, e
	}
	groups := map[string]int{}
	var series []logproto.Series
	var unique uint64
	for _, r := range q.entries {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		ts, e := number(r.Timestamp)
		if e != nil {
			return nil, e
		}
		at := time.Unix(0, ts)
		if at.Before(p.Start) || !at.Before(p.End) {
			continue
		}
		ls := nativeLabels(r.Labels)
		if !matches(selector, ls) {
			continue
		}
		n, e := strconv.ParseUint(r.Multiplicity, 10, 64)
		if e != nil || n == 0 || n > 5000000 {
			return nil, fmt.Errorf("invalid native sample multiplicity")
		}
		for _, extractor := range extractors {
			v, lr, ok := extractor.ForStream(ls).ProcessString(ts, r.Line, metadata(r.Metadata)...)
			if !ok {
				continue
			}
			key := ls.String() + "\x00" + lr.String()
			index, exists := groups[key]
			if !exists {
				index = len(series)
				groups[key] = index
				series = append(series, logproto.Series{Labels: lr.String(), StreamHash: ls.Hash()})
			}
			for j := uint64(0); j < n; j++ {
				unique++
				series[index].Samples = append(series[index].Samples, logproto.Sample{Timestamp: ts, Value: v, Hash: unique})
			}
		}
	}
	for i := range series {
		samples := series[i].Samples
		sort.SliceStable(samples, func(a, b int) bool { return samples[a].Timestamp < samples[b].Timestamp })
	}
	return iter.NewMultiSeriesIterator(series), nil
}

// Compile-time interface assertions catch source/API drift at the pinned build.
var _ native.Querier = (*fixtureQuerier)(nil)
var _ native.Limits = oracleLimits{}
