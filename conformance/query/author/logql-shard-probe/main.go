//go:build soundpost_logql_shard_probe

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Development driver only: actual upstream imports are confined to this source build.
// It observes three things of the pinned Loki 3.5.2 sources that the fixture driver of
// the OCI oracle cannot reach, because that driver feeds the engine one iterator below
// every merge and never shards:
//
//   - gating: which strings of a shard_aggregations list the real ShardMapper accepts
//     (NewShardMapper), per mappable query, and whether approx_topk evaluates;
//   - frontend: the real sharded evaluation (ShardMapper + DownstreamEngine) of a raw
//     log query whose two shard inputs hold the same entries (replicas);
//   - merge: the real querier-side merge iterators (NewMergeEntryIterator,
//     NewMergeSampleIterator) and the sort iterators over two inputs.
//
// It reads the authored cases (conformance/query/cases/logql-shard-replica-probe.json)
// on stdin and writes the observations on stdout. No expectation is authored here.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/log"
	"github.com/grafana/dskit/user"
	"github.com/grafana/loki/v3/pkg/iter"
	"github.com/grafana/loki/v3/pkg/logproto"
	native "github.com/grafana/loki/v3/pkg/logql"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	"github.com/grafana/loki/v3/pkg/logqlmodel"
	"github.com/grafana/loki/v3/pkg/logqlmodel/stats"
	"github.com/grafana/loki/v3/pkg/util/validation"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/model/labels"
)

var compiledProfile, compiledCommit, compiledSourceSHA256 string

const profileID = "logql-loki-3.5.2"
const commit = "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7"
const sourceSHA = "0db690662744694667c031a81d3e20cdd3a68a387a8050c8096bebbdf2ff8db2"

type gateQuery struct {
	ID    string `json:"id"`
	Kind  string `json:"kind"`
	Query string `json:"query"`
}
type gateList struct {
	ID    string   `json:"id"`
	Names []string `json:"names"`
}
type entry struct {
	TS   string `json:"ts"`
	Host string `json:"host"`
	Line string `json:"line"`
}
type fixture struct {
	ID     string    `json:"id"`
	Inputs [][]entry `json:"inputs"`
}
type sample struct {
	TS    string  `json:"ts"`
	Host  string  `json:"host"`
	Value float64 `json:"value"`
	Hash  string  `json:"hash"`
}
type sampleFixture struct {
	ID     string     `json:"id"`
	Inputs [][]sample `json:"inputs"`
}
type frontendCase struct {
	ID        string `json:"id"`
	Fixture   string `json:"fixture"`
	Direction string `json:"direction"`
	Limit     uint32 `json:"limit"`
}
type mergeCase struct {
	ID        string `json:"id"`
	Fixture   string `json:"fixture"`
	Direction string `json:"direction"`
	Mode      string `json:"mode"`
}
type sampleMergeCase struct {
	ID      string `json:"id"`
	Fixture string `json:"fixture"`
	Mode    string `json:"mode"`
}
type cases struct {
	Schema    string `json:"schema"`
	Copyright string `json:"copyright"`
	License   string `json:"license"`
	Author    string `json:"author"`
	Gating    struct {
		Queries []gateQuery `json:"queries"`
		Lists   []gateList  `json:"lists"`
	} `json:"gating"`
	Fixtures       []fixture         `json:"fixtures"`
	SampleFixtures []sampleFixture   `json:"sample_fixtures"`
	Frontend       []frontendCase    `json:"frontend"`
	Merges         []mergeCase       `json:"merges"`
	SampleMerges   []sampleMergeCase `json:"sample_merges"`
}

type gateObs struct {
	List        string `json:"list"`
	Query       string `json:"query"`
	Noop        bool   `json:"noop"`
	Downstreams int    `json:"downstreams"`
	Error       string `json:"error,omitempty"`
	Evaluated   *bool  `json:"evaluated,omitempty"`
	EvalError   string `json:"eval_error,omitempty"`
}
type outEntry struct {
	TS     string `json:"ts"`
	Labels string `json:"labels"`
	Hash   string `json:"hash"`
	Line   string `json:"line"`
}
type outStream struct {
	Labels  string     `json:"labels"`
	Hash    string     `json:"hash"`
	Entries []outEntry `json:"entries"`
}
type frontendObs struct {
	ID      string      `json:"id"`
	Error   string      `json:"error,omitempty"`
	Streams []outStream `json:"streams"`
	Flat    []outEntry  `json:"flat"`
}
type mergeObs struct {
	ID      string     `json:"id"`
	Entries []outEntry `json:"entries"`
	Error   string     `json:"error,omitempty"`
}
type outSample struct {
	TS     string `json:"ts"`
	Labels string `json:"labels"`
	Hash   string `json:"hash"`
	Value  string `json:"value_bits"`
	Sample string `json:"sample_hash"`
}
type sampleMergeObs struct {
	ID      string      `json:"id"`
	Samples []outSample `json:"samples"`
	Error   string      `json:"error,omitempty"`
}
type batch struct {
	Profile      string           `json:"profile"`
	Commit       string           `json:"commit"`
	Compiler     string           `json:"compiler"`
	SourceSHA256 string           `json:"source_sha256"`
	Gating       []gateObs        `json:"gating"`
	Frontend     []frontendObs    `json:"frontend"`
	Merges       []mergeObs       `json:"merges"`
	SampleMerges []sampleMergeObs `json:"sample_merges"`
}

type probeLimits struct{}

func (probeLimits) MaxQuerySeries(context.Context, string) int                        { return 5000000 }
func (probeLimits) MaxQueryRange(context.Context, string) time.Duration               { return 0 }
func (probeLimits) QueryTimeout(context.Context, string) time.Duration                { return time.Minute }
func (probeLimits) BlockedQueries(context.Context, string) []*validation.BlockedQuery { return nil }
func (probeLimits) EnableMultiVariantQueries(string) bool                             { return false }

var _ native.Limits = probeLimits{}

func number(s string) int64 {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("noncanonical nanoseconds %q", s))
	}
	return n
}

func streamLabels(host string) labels.Labels {
	return labels.FromStrings("app", "api", "host", host)
}

// groupStreams groups one input by host, in first-seen order, entries ordered by the
// direction (stable), the order a store hands an iterator over.
func groupStreams(in []entry, direction logproto.Direction) []logproto.Stream {
	index := map[string]int{}
	var streams []logproto.Stream
	for _, e := range in {
		ls := streamLabels(e.Host)
		i, ok := index[e.Host]
		if !ok {
			i = len(streams)
			index[e.Host] = i
			streams = append(streams, logproto.Stream{Labels: ls.String(), Hash: ls.Hash()})
		}
		streams[i].Entries = append(streams[i].Entries, logproto.Entry{Timestamp: time.Unix(0, number(e.TS)), Line: e.Line})
	}
	for i := range streams {
		es := streams[i].Entries
		sort.SliceStable(es, func(a, b int) bool {
			if direction == logproto.BACKWARD {
				return es[a].Timestamp.After(es[b].Timestamp)
			}
			return es[a].Timestamp.Before(es[b].Timestamp)
		})
	}
	return streams
}

type inputQuerier struct{ entries []entry }

func (q *inputQuerier) SelectLogs(_ context.Context, p native.SelectLogParams) (iter.EntryIterator, error) {
	var kept []entry
	for _, e := range q.entries {
		at := time.Unix(0, number(e.TS))
		if at.Before(p.Start) || !at.Before(p.End) {
			continue
		}
		kept = append(kept, e)
	}
	return iter.NewStreamsIterator(groupStreams(kept, p.Direction), p.Direction), nil
}

// SelectSamples feeds the engine the samples of the entries through the extractors of the
// plan, as the oracle driver does (one sample per entry, a unique sample hash).
func (q *inputQuerier) SelectSamples(_ context.Context, p native.SelectSampleParams) (iter.SampleIterator, error) {
	if p.SampleQueryRequest == nil || p.Plan == nil {
		return nil, fmt.Errorf("missing native sample AST")
	}
	expr, ok := p.Plan.AST.(syntax.SampleExpr)
	if !ok {
		return nil, fmt.Errorf("unhandled native sample AST %T", p.Plan.AST)
	}
	extractors, err := expr.Extractors()
	if err != nil {
		return nil, err
	}
	groups := map[string]int{}
	var series []logproto.Series
	var unique uint64
	for _, e := range q.entries {
		ts := number(e.TS)
		at := time.Unix(0, ts)
		if at.Before(p.Start) || !at.Before(p.End) {
			continue
		}
		ls := streamLabels(e.Host)
		for _, extractor := range extractors {
			v, lr, ok := extractor.ForStream(ls).ProcessString(ts, e.Line)
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
			unique++
			series[index].Samples = append(series[index].Samples, logproto.Sample{Timestamp: ts, Value: v, Hash: unique})
		}
	}
	for i := range series {
		samples := series[i].Samples
		sort.SliceStable(samples, func(a, b int) bool { return samples[a].Timestamp < samples[b].Timestamp })
	}
	return iter.NewMultiSeriesIterator(series), nil
}

var _ native.Querier = (*inputQuerier)(nil)

// shardDownstream evaluates the i-th downstream query of a sharded plan on the i-th
// input of the fixture: the engine below the merge sees one shard's input.
type shardDownstream struct {
	opts   native.EngineOpts
	inputs [][]entry
}

func (d shardDownstream) Downstreamer(context.Context) native.Downstreamer { return d }
func (d shardDownstream) Downstream(ctx context.Context, queries []native.DownstreamQuery, acc native.Accumulator) ([]logqlmodel.Result, error) {
	if len(queries) != len(d.inputs) {
		return nil, fmt.Errorf("%d downstream queries for %d shard inputs", len(queries), len(d.inputs))
	}
	for index, query := range queries {
		engine := native.NewEngine(d.opts, &inputQuerier{entries: d.inputs[index]}, probeLimits{}, nil)
		result, err := engine.Query(query.Params).Exec(ctx)
		if err != nil {
			return nil, err
		}
		if err = acc.Accumulate(ctx, result, index); err != nil {
			return nil, err
		}
	}
	return acc.Result(), nil
}

var _ native.Downstreamable = shardDownstream{}
var _ native.Downstreamer = shardDownstream{}

func hashString(h uint64) string { return strconv.FormatUint(h, 10) }

func observeGate(names []string, list gateList, q gateQuery) gateObs {
	o := gateObs{List: list.ID, Query: q.ID}
	mapper := native.NewShardMapper(native.NewPowerOfTwoStrategy(native.ConstantShards(2)), native.NewShardMapperMetrics(prometheus.NewRegistry()), names)
	expr, err := syntax.ParseExpr(q.Query)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	noop, _, mapped, err := mapper.Parse(expr)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	o.Noop = noop
	o.Downstreams = strings.Count(mapped.String(), "downstream<")
	if q.Kind != "approx_topk" {
		return o
	}
	// approx_topk is a frontend operation: the engine alone refuses it, the zero-shard
	// planner of the real frontend evaluates it only when the string switch enabled it.
	ctx := user.InjectOrgID(context.Background(), "soundpost-conformance")
	opts := native.EngineOpts{MaxLookBackPeriod: 30 * time.Second, MaxCountMinSketchHeapSize: 10000}
	in := []entry{{TS: "1000000000", Host: "a", Line: "n=1"}, {TS: "1500000000", Host: "b", Line: "n=2"}}
	params, err := native.NewLiteralParams(q.Query, time.Unix(0, 2000000000), time.Unix(0, 2000000000), 0, 0, logproto.FORWARD, 0, nil, nil)
	if err != nil {
		o.EvalError = err.Error()
		return o
	}
	zero := native.NewShardMapper(native.NewPowerOfTwoStrategy(native.ConstantShards(0)), native.NewShardMapperMetrics(prometheus.NewRegistry()), names)
	_, _, zeroMapped, err := zero.Parse(params.GetExpression())
	ok := false
	if err == nil {
		front := native.NewDownstreamEngine(opts, shardDownstream{opts: opts, inputs: [][]entry{in}}, probeLimits{}, log.NewNopLogger())
		_, err = front.Query(ctx, native.ParamsWithExpressionOverride{Params: params, ExpressionOverride: zeroMapped}).Exec(ctx)
		ok = err == nil
	}
	o.Evaluated = &ok
	if err != nil {
		o.EvalError = err.Error()
	}
	return o
}

func flat(streams []logproto.Stream, direction logproto.Direction) ([]outEntry, error) {
	ordered := iter.NewStreamsIterator(streams, direction)
	defer ordered.Close()
	var out []outEntry
	for ordered.Next() {
		e := ordered.At()
		out = append(out, outEntry{TS: strconv.FormatInt(e.Timestamp.UnixNano(), 10), Labels: ordered.Labels(), Hash: hashString(ordered.StreamHash()), Line: e.Line})
	}
	return out, ordered.Err()
}

func directionOf(s string) logproto.Direction {
	if s == "backward" {
		return logproto.BACKWARD
	}
	return logproto.FORWARD
}

func observeFrontend(c frontendCase, f fixture) frontendObs {
	o := frontendObs{ID: c.ID}
	direction := directionOf(c.Direction)
	ctx := user.InjectOrgID(context.Background(), "soundpost-conformance")
	opts := native.EngineOpts{MaxLookBackPeriod: 30 * time.Second, MaxCountMinSketchHeapSize: 10000}
	const query = `{app="api"}`
	params, err := native.NewLiteralParams(query, time.Unix(0, 0), time.Unix(0, 60e9), time.Second, 0, direction, c.Limit, nil, nil)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	mapper := native.NewShardMapper(native.NewPowerOfTwoStrategy(native.ConstantShards(len(f.Inputs))), native.NewShardMapperMetrics(prometheus.NewRegistry()), nil)
	_, _, mapped, err := mapper.Parse(params.GetExpression())
	if err != nil {
		o.Error = err.Error()
		return o
	}
	if n := strings.Count(mapped.String(), "downstream<"); n != len(f.Inputs) {
		o.Error = fmt.Sprintf("the mapper produced %d downstream queries for %d shard inputs", n, len(f.Inputs))
		return o
	}
	front := native.NewDownstreamEngine(opts, shardDownstream{opts: opts, inputs: f.Inputs}, probeLimits{}, log.NewNopLogger())
	result, err := front.Query(ctx, native.ParamsWithExpressionOverride{Params: params, ExpressionOverride: mapped}).Exec(ctx)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	streams, ok := result.Data.(logqlmodel.Streams)
	if !ok {
		o.Error = fmt.Sprintf("unexpected result %T", result.Data)
		return o
	}
	for _, s := range streams {
		os := outStream{Labels: s.Labels, Hash: hashString(s.Hash)}
		for _, e := range s.Entries {
			os.Entries = append(os.Entries, outEntry{TS: strconv.FormatInt(e.Timestamp.UnixNano(), 10), Labels: s.Labels, Hash: hashString(s.Hash), Line: e.Line})
		}
		o.Streams = append(o.Streams, os)
	}
	o.Flat, err = flat([]logproto.Stream(streams), direction)
	if err != nil {
		o.Error = err.Error()
	}
	return o
}

func drain(it iter.EntryIterator) ([]outEntry, error) {
	defer it.Close()
	var out []outEntry
	for it.Next() {
		e := it.At()
		out = append(out, outEntry{TS: strconv.FormatInt(e.Timestamp.UnixNano(), 10), Labels: it.Labels(), Hash: hashString(it.StreamHash()), Line: e.Line})
	}
	return out, it.Err()
}

func observeMerge(c mergeCase, f fixture) mergeObs {
	o := mergeObs{ID: c.ID}
	direction := directionOf(c.Direction)
	_, ctx := stats.NewContext(context.Background())
	inputs := func(n int) []iter.EntryIterator {
		var out []iter.EntryIterator
		for i := 0; i < n && i < len(f.Inputs); i++ {
			out = append(out, iter.NewStreamsIterator(groupStreams(f.Inputs[i], direction), direction))
		}
		return out
	}
	var it iter.EntryIterator
	switch c.Mode {
	case "merge-all":
		it = iter.NewMergeEntryIterator(ctx, inputs(len(f.Inputs)), direction)
	case "merge-first":
		it = iter.NewMergeEntryIterator(ctx, inputs(1), direction)
	case "sort-all":
		it = iter.NewSortEntryIterator(inputs(len(f.Inputs)), direction)
	default:
		o.Error = "unknown mode " + c.Mode
		return o
	}
	var err error
	o.Entries, err = drain(it)
	if err != nil {
		o.Error = err.Error()
	}
	return o
}

func seriesOf(in []sample) []logproto.Series {
	index := map[string]int{}
	var series []logproto.Series
	for _, s := range in {
		ls := streamLabels(s.Host)
		i, ok := index[s.Host]
		if !ok {
			i = len(series)
			index[s.Host] = i
			series = append(series, logproto.Series{Labels: ls.String(), StreamHash: ls.Hash()})
		}
		hash, err := strconv.ParseUint(s.Hash, 10, 64)
		if err != nil {
			panic(err)
		}
		series[i].Samples = append(series[i].Samples, logproto.Sample{Timestamp: number(s.TS), Value: s.Value, Hash: hash})
	}
	for i := range series {
		ss := series[i].Samples
		sort.SliceStable(ss, func(a, b int) bool { return ss[a].Timestamp < ss[b].Timestamp })
	}
	return series
}

func observeSampleMerge(c sampleMergeCase, f sampleFixture) sampleMergeObs {
	o := sampleMergeObs{ID: c.ID}
	_, ctx := stats.NewContext(context.Background())
	inputs := func(n int) []iter.SampleIterator {
		var out []iter.SampleIterator
		for i := 0; i < n && i < len(f.Inputs); i++ {
			out = append(out, iter.NewMultiSeriesIterator(seriesOf(f.Inputs[i])))
		}
		return out
	}
	var it iter.SampleIterator
	switch c.Mode {
	case "merge-all":
		it = iter.NewMergeSampleIterator(ctx, inputs(len(f.Inputs)))
	case "merge-first":
		it = iter.NewMergeSampleIterator(ctx, inputs(1))
	case "sort-all":
		it = iter.NewSortSampleIterator(inputs(len(f.Inputs)))
	default:
		o.Error = "unknown mode " + c.Mode
		return o
	}
	defer it.Close()
	for it.Next() {
		s := it.At()
		o.Samples = append(o.Samples, outSample{TS: strconv.FormatInt(s.Timestamp, 10), Labels: it.Labels(), Hash: hashString(it.StreamHash()), Value: fmt.Sprintf("%016x", math.Float64bits(s.Value)), Sample: hashString(s.Hash)})
	}
	if err := it.Err(); err != nil {
		o.Error = err.Error()
	}
	return o
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// The pinned upstream parser prints "syntax error" lines to stdout: keep the one
	// JSON result on the real stdout and send everything upstream prints to stderr.
	jsonOut := os.Stdout
	os.Stdout = os.Stderr
	if compiledProfile != profileID || compiledCommit != commit || compiledSourceSHA256 != sourceSHA {
		return fmt.Errorf("native source provenance mismatch")
	}
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 16<<20))
	decoder.DisallowUnknownFields()
	var in cases
	if err := decoder.Decode(&in); err != nil {
		return err
	}
	fixtures := map[string]fixture{}
	for _, f := range in.Fixtures {
		fixtures[f.ID] = f
	}
	sampleFixtures := map[string]sampleFixture{}
	for _, f := range in.SampleFixtures {
		sampleFixtures[f.ID] = f
	}
	out := batch{Profile: profileID, Commit: commit, Compiler: runtime.Version(), SourceSHA256: sourceSHA}
	for _, l := range in.Gating.Lists {
		for _, q := range in.Gating.Queries {
			out.Gating = append(out.Gating, observeGate(l.Names, l, q))
		}
	}
	for _, c := range in.Frontend {
		f, ok := fixtures[c.Fixture]
		if !ok {
			return fmt.Errorf("%s: unknown fixture", c.ID)
		}
		out.Frontend = append(out.Frontend, observeFrontend(c, f))
	}
	for _, c := range in.Merges {
		f, ok := fixtures[c.Fixture]
		if !ok {
			return fmt.Errorf("%s: unknown fixture", c.ID)
		}
		out.Merges = append(out.Merges, observeMerge(c, f))
	}
	for _, c := range in.SampleMerges {
		f, ok := sampleFixtures[c.Fixture]
		if !ok {
			return fmt.Errorf("%s: unknown sample fixture", c.ID)
		}
		out.SampleMerges = append(out.SampleMerges, observeSampleMerge(c, f))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := jsonOut.Write(buf.Bytes())
	return err
}
