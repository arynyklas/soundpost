//go:build soundpost_logql_oracle

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
// Development driver only: actual upstream imports are confined to this source
// build. This program is never linked into any Soundpost production binary.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"strconv"
	"time"
	"unicode"

	"github.com/grafana/dskit/user"
	"github.com/grafana/loki/v3/pkg/iter"
	"github.com/grafana/loki/v3/pkg/logproto"
	native "github.com/grafana/loki/v3/pkg/logql"
	nlog "github.com/grafana/loki/v3/pkg/logql/log"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/grafana/loki/v3/pkg/logqlmodel"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql"
)

var compiledProfile, compiledCommit, compiledSourceSHA256 string

const profileID = "logql-loki-3.5.2"
const commit = "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"
const sourceSHA = "0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2"

func number(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || strconv.FormatInt(n, 10) != s {
		return 0, fmt.Errorf("noncanonical nanoseconds")
	}
	return n, nil
}
func nativeLabels(in []label) labels.Labels {
	b := labels.NewBuilder(labels.EmptyLabels())
	for _, l := range in {
		b.Set(l.Name, l.Value)
	}
	return b.Labels()
}
func wireLabels(in labels.Labels) []label {
	var out []label
	in.Range(func(l labels.Label) { out = append(out, label{l.Name, l.Value}) })
	return out
}
func metadata(in []label) []labels.Label {
	out := make([]labels.Label, len(in))
	for i, l := range in {
		out[i] = labels.Label{Name: l.Name, Value: l.Value}
	}
	return out
}
func matches(selector syntax.LogSelectorExpr, in labels.Labels) bool {
	for _, m := range selector.Matchers() {
		if !m.Matches(in.Get(m.Name)) {
			return false
		}
	}
	return true
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	// The pinned upstream parser prints a "syntax error: …" line to os.Stdout for
	// every rejected expression. Stdout carries exactly one JSON result, so route
	// everything upstream prints to stderr and keep the real stdout for the result.
	jsonOut := os.Stdout
	os.Stdout = os.Stderr
	if compiledProfile != profileID || compiledCommit != commit || compiledSourceSHA256 != sourceSHA || runtime.Version() != "go1.24.5" || unicode.Version != "15.0.0" {
		return fmt.Errorf("native source/compiler provenance mismatch")
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, (16<<20)+1))
	decoder.DisallowUnknownFields()
	var in input
	if e := decoder.Decode(&in); e != nil {
		return e
	}
	if e := decoder.Decode(new(any)); e != io.EOF {
		return fmt.Errorf("trailing native input")
	}
	if in.Profile != profileID || in.Commit != commit || in.ProfileIdentity == "" || in.FeatureSet == "" || in.ConfigurationHash == "" || len(in.Cases) == 0 {
		return fmt.Errorf("missing pinned native batch identity")
	}
	raw, e := os.ReadFile("/oracle-zoneinfo.zip")
	if e != nil {
		return e
	}
	hash := sha256.Sum256(raw)
	zoneSHA := hex.EncodeToString(hash[:])
	if in.TimezoneSHA256 != "" && in.TimezoneSHA256 != zoneSHA {
		return fmt.Errorf("controlled native timezone dataset hash mismatch")
	}
	// Explicit dataset selection, independent of the stock artifact's default TZ.
	if e = os.Setenv("ZONEINFO", "/oracle-zoneinfo.zip"); e != nil {
		return e
	}
	time.Local = time.UTC
	out := batch{Profile: profileID, Commit: commit, Compiler: runtime.Version(), Unicode: unicode.Version, SourceSHA256: sourceSHA, ProfileIdentity: in.ProfileIdentity, FeatureSet: in.FeatureSet, ConfigurationHash: in.ConfigurationHash, TimezoneSHA256: zoneSHA}
	seen := map[string]bool{}
	for _, c := range in.Cases {
		if c.ID == "" || seen[c.ID] {
			return fmt.Errorf("missing/duplicate native case ID")
		}
		seen[c.ID] = true
		o, e := observe(context.Background(), in, c)
		if e != nil {
			return fmt.Errorf("%s: %w", c.ID, e)
		}
		out.Observations = append(out.Observations, o)
	}
	return json.NewEncoder(jsonOut).Encode(out)
}
func observe(ctx context.Context, in input, c testCase) (observation, error) {
	expression := c.Input.Expression
	if c.Phase == "logql-template" {
		expression = c.PipelineQuery
	}
	if c.Phase == "logql-metric" {
		expression = c.Query
	}
	o := observation{ID: c.ID}
	reject := func(err error) (observation, error) { o.Error = projectError(err, expression); return o, nil }
	if c.Phase == "logql-template" && c.Kind != "pipeline" && c.Kind != "pipeline_query" {
		ts, e := number(c.Timestamp)
		if e != nil {
			return o, e
		}
		data := map[string]any{}
		for _, f := range c.Fields {
			d := json.NewDecoder(bytes.NewReader(f.Value))
			d.UseNumber()
			var v any
			if e = d.Decode(&v); e != nil {
				return o, e
			}
			if n, ok := v.(json.Number); ok {
				v, e = strconv.ParseInt(string(n), 10, 64)
				if e != nil {
					return o, e
				}
			}
			data[f.Name] = v
		}
		for _, l := range c.Labels {
			data[l.Name] = l.Value
		}
		// Match native root map typing when the fixture supplies only string labels.
		var root any = data
		allStrings := true
		for _, v := range data {
			if _, ok := v.(string); !ok {
				allStrings = false
			}
		}
		if allStrings {
			m := map[string]string{}
			for k, v := range data {
				m[k] = v.(string)
			}
			root = m
		}
		if c.Timezone == "UTC" || c.Timezone == "" {
			time.Local = time.UTC
		} else {
			location, e := time.LoadLocation(c.Timezone)
			if e != nil {
				return o, e
			}
			time.Local = location
		}
		o.ClockStart = strconv.FormatInt(time.Now().UnixNano(), 10)
		text, phase, e := nlog.SoundpostNativeTemplate(c.Source, c.Line, ts, root)
		o.ClockEnd = strconv.FormatInt(time.Now().UnixNano(), 10)
		if e != nil {
			o.Error = &languageError{Semantic: nativeTemplateSemantic(phase, e), Category: "template", CategoryExposed: true, Message: e.Error()}
			return o, nil
		}
		o.Accepted = true
		o.Type = "template"
		o.Output = text
		return o, nil
	}
	expr, e := syntax.ParseExpr(expression)
	if e != nil {
		return reject(e)
	}
	if e = nativeBuild(expr); e != nil {
		return reject(e)
	}
	o.Type = expressionType(expr)
	if c.Phase == "syntax" {
		o.Accepted = true
		return o, nil
	}
	if c.Phase == "pipeline" || c.Phase == "logql-template" {
		row := c.Input.Entry
		if c.Phase == "logql-template" {
			row = &entry{Timestamp: c.Timestamp, Multiplicity: "1", Line: c.Line, Labels: c.Labels, Fields: c.Fields}
			if c.Timezone == "UTC" {
				time.Local = time.UTC
			} else {
				loc, e := time.LoadLocation(c.Timezone)
				if e != nil {
					return o, e
				}
				time.Local = loc
			}
		}
		if row == nil {
			return o, fmt.Errorf("missing native pipeline entry")
		}
		ts, e := number(row.Timestamp)
		if e != nil {
			return o, e
		}
		var selector syntax.LogSelectorExpr
		switch t := expr.(type) {
		case syntax.LogSelectorExpr:
			selector = t
		case syntax.SampleExpr:
			selector, e = t.Selector()
		default:
			return o, fmt.Errorf("no native pipeline selector")
		}
		if e != nil {
			return reject(e)
		}
		pipeline, e := selector.Pipeline()
		if e != nil {
			return reject(e)
		}
		ls := nativeLabels(row.Labels)
		retained := matches(selector, ls)
		o.ClockStart = strconv.FormatInt(time.Now().UnixNano(), 10)
		result := &pipelineResult{}
		if retained {
			text, lr, ok := pipeline.ForStream(ls).ProcessString(ts, row.Line, metadata(row.Metadata)...)
			retained = ok
			if ok {
				result.Retained = true
				result.Line = text
				result.Labels = wireLabels(lr.Labels())
			}
		}
		// Unwrap lives in the native sample extractor rather than the log Pipeline.
		unwrapped := false
		expr.Walk(func(node syntax.Expr) {
			if r, ok := node.(*syntax.RangeAggregationExpr); ok && r.Left.Unwrap != nil {
				unwrapped = true
			}
		})
		if unwrapped && retained {
			sample, ok := expr.(syntax.SampleExpr)
			if !ok {
				return o, fmt.Errorf("unwrap without native sample expression")
			}
			extractors, e := sample.Extractors()
			if e != nil {
				return reject(e)
			}
			if len(extractors) != 1 {
				return o, fmt.Errorf("pipeline unwrap requires exactly one native extractor")
			}
			v, labels, ok := extractors[0].ForStream(ls).ProcessString(ts, row.Line, metadata(row.Metadata)...)
			if !ok {
				result = &pipelineResult{}
			} else {
				result.Labels = wireLabels(labels.Labels())
				bits := fmt.Sprintf("%016x", math.Float64bits(v))
				result.Unwrapped = &bits
			}
		}
		o.ClockEnd = strconv.FormatInt(time.Now().UnixNano(), 10)
		o.Pipeline = result
		o.Accepted = true
		return o, nil
	}
	start, e := number(c.Start)
	if e != nil {
		return o, e
	}
	end, e := number(c.End)
	if e != nil {
		return o, e
	}
	step, e := number(c.Step)
	if e != nil {
		return o, e
	}
	interval, e := number(c.Interval)
	if e != nil {
		return o, e
	}
	if c.Kind == "instant" {
		start, e = number(c.Time)
		if e != nil {
			return o, e
		}
		end = start
		step = 0
	}
	limit := uint64(0)
	if c.Limit != "" {
		limit, e = strconv.ParseUint(c.Limit, 10, 32)
		if e != nil {
			return o, e
		}
	}
	direction := logproto.FORWARD
	if c.Direction == "backward" {
		direction = logproto.BACKWARD
	}
	params, e := native.NewLiteralParams(c.Query, time.Unix(0, start), time.Unix(0, end), time.Duration(step), time.Duration(interval), direction, uint32(limit), nil, nil)
	if e != nil {
		return reject(e)
	}
	lookback, e := number(in.Lookback)
	if e != nil || in.Lookback == "" {
		return o, fmt.Errorf("missing native evaluator configuration")
	}
	limits := oracleLimits{variants: false}
	for _, g := range in.Enabled {
		if g == "multi-variant-queries" {
			limits.variants = true
		}
	}
	result, e := executeNativeMetric(user.InjectOrgID(ctx, "soundpost-conformance"), in, params, c.Entries, native.EngineOpts{MaxLookBackPeriod: time.Duration(lookback), MaxCountMinSketchHeapSize: in.SketchHeap}, limits)
	if e != nil {
		return reject(e)
	}
	o.Accepted = true
	o.Type = string(result.Data.Type())
	var projectionError error
	add := func(ls labels.Labels, t int64, f float64) {
		if t > math.MaxInt64/1000000 || t < math.MinInt64/1000000 {
			projectionError = fmt.Errorf("actual native milliseconds outside representable nanosecond domain")
			return
		}
		o.Values = append(o.Values, resultValue{Timestamp: strconv.FormatInt(t*1000000, 10), Bits: fmt.Sprintf("%016x", math.Float64bits(f)), Labels: wireLabels(ls)})
	}
	switch data := result.Data.(type) {
	case promql.Scalar:
		add(labels.EmptyLabels(), data.T, data.V)
	case promql.Vector:
		for _, s := range data {
			if s.H != nil {
				return o, fmt.Errorf("unexpected native histogram")
			}
			add(s.Metric, s.T, s.F)
		}
	case promql.Matrix:
		for _, s := range data {
			if len(s.Histograms) > 0 {
				return o, fmt.Errorf("unexpected native histograms")
			}
			for _, p := range s.Floats {
				add(s.Metric, p.T, p.F)
			}
		}
	case logqlmodel.Streams:
		for _, s := range data {
			ls, e := syntax.ParseLabels(s.Labels)
			if e != nil {
				return o, e
			}
			raw := rawStream{Labels: wireLabels(ls), Hash: strconv.FormatUint(s.Hash, 10)}
			for _, r := range s.Entries {
				raw.Values = append(raw.Values, resultValue{Timestamp: strconv.FormatInt(r.Timestamp.UnixNano(), 10), Line: r.Line, Labels: wireLabels(ls), Multiplicity: "1"})
			}
			o.RawStreams = append(o.RawStreams, raw)
		}
		// readStreams has already applied native source ordering, interval and limit.
		// Retain that authoritative grouped result above. This bridge invokes the
		// actual native iterator over its result representation; no dedup is used.
		ordered := iter.NewStreamsIterator([]logproto.Stream(data), direction)
		defer ordered.Close()
		for ordered.Next() {
			r := ordered.At()
			ls, e := syntax.ParseLabels(ordered.Labels())
			if e != nil {
				return o, e
			}
			o.Values = append(o.Values, resultValue{Timestamp: strconv.FormatInt(r.Timestamp.UnixNano(), 10), Line: r.Line, Labels: wireLabels(ls), Multiplicity: "1"})
		}
		if e = ordered.Err(); e != nil {
			return o, e
		}
	default:
		return o, fmt.Errorf("unhandled actual native result %T", data)
	}
	if projectionError != nil {
		return o, projectionError
	}
	return o, nil
}
func expressionType(expr syntax.Expr) string {
	switch expr.(type) {
	case *syntax.LiteralExpr:
		return "scalar"
	case syntax.SampleExpr:
		return "vector"
	case syntax.LogSelectorExpr:
		return "streams"
	case syntax.VariantsExpr:
		return "vector"
	default:
		return "unclassified"
	}
}
func nativeBuild(expr syntax.Expr) error {
	switch e := expr.(type) {
	case syntax.SampleExpr:
		_, err := e.Extractors()
		return err
	case syntax.VariantsExpr:
		_, err := e.Extractors()
		return err
	case syntax.LogSelectorExpr:
		_, err := e.Pipeline()
		return err
	default:
		return fmt.Errorf("unhandled actual native AST %T", expr)
	}
}
