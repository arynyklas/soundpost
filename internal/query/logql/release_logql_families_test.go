// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"encoding/json"
	"math"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The expectations in this file are written by hand from the obligation rule
// text (ledger rule, ASCII/Unicode/IEEE arithmetic, Go standard library
// documentation); none of them is copied from an engine or oracle output.

func relLabels(kv ...string) model.Labels {
	ls := make(model.Labels, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		ls = append(ls, model.Label{Name: kv[i], Value: kv[i+1]})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Name < ls[j].Name })
	return ls
}
func relHas(ls model.Labels, name string) bool {
	for _, l := range ls {
		if l.Name == name {
			return true
		}
	}
	return false
}
func relRow(id byte, at int64, line string, kv ...string) scan.LogRow {
	r := metricRow(id, at, line)
	r.Record.StreamLabels = relLabels(kv...)
	return r
}
func relMeta(r scan.LogRow, name, text string) scan.LogRow {
	var s model.Scalar
	raw, _ := json.Marshal(text)
	if err := json.Unmarshal(raw, &s); err != nil {
		panic(err)
	}
	r.Record.Metadata = map[string]model.Scalar{name: s}
	return r
}
func relEntry(line string, kv ...string) LogEntry {
	e := entry(line)
	e.StreamLabels = relLabels(kv...)
	return e
}
func relKey(ls model.Labels) string {
	var parts []string
	for _, l := range ls {
		parts = append(parts, l.Name+"="+l.Value)
	}
	return strings.Join(parts, ",")
}

// relEval evaluates a metric query; rows are the whole fixture, windows are cut by the source.
func relEval(t *testing.T, q string, rows []scan.LogRow, e value.Evaluation) (value.Result, error) {
	t.Helper()
	a := value.NewBoundedAccount(64 << 20)
	r, _, err := Evaluate(context.Background(), metricPlan(t, q, e), &metricSource{rows: rows}, a)
	return r, err
}
func relInstant(t *testing.T, q string, rows []scan.LogRow) map[string]float64 {
	t.Helper()
	r, err := relEval(t, q, rows, value.Evaluation{Instant: true, Time: 2e9})
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	out := map[string]float64{}
	for _, s := range r.Vector {
		for _, sample := range s.Samples {
			out[relKey(s.Labels)] = math.Float64frombits(uint64(sample.Float))
		}
	}
	return out
}
func relWant(t *testing.T, q string, got, want map[string]float64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v want %v", q, got, want)
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Fatalf("%s: got %v want %v", q, got, want)
		}
	}
}

// Counts at t=2s over (0,2s]: api/a=2, api/b=1, web/a=3, web/c=1.
func relFixture() []scan.LogRow {
	return []scan.LogRow{
		relRow(1, 1e9, "n=1", "app", "api", "host", "a"), relRow(2, 15e8, "n=2", "app", "api", "host", "a"), relRow(3, 1e9, "n=3", "app", "api", "host", "b"),
		relRow(4, 5e8, "n=4", "app", "web", "host", "a"), relRow(5, 12e8, "n=5", "app", "web", "host", "a"), relRow(6, 18e8, "n=6", "app", "web", "host", "a"),
		relRow(7, 11e8, "n=7", "app", "web", "host", "c"),
	}
}

const (
	relAPI = `count_over_time({app="api"}[2s])`
	relWEB = `count_over_time({app="web"}[2s])`
)

func TestReleaseLogQLBinaryMatchingAndSetOperators(t *testing.T) {
	rows := relFixture()
	// on() selects the join label; unmatched identities vanish.
	q := `sum by (host) (` + relAPI + `) / on(host) sum by (host) (` + relWEB + `)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"host=a": 2.0 / 3.0})
	// bool comparison emits 0/1 and keeps the many (left) side's labels through group_left.
	q = relAPI + ` < bool on(host) group_left sum by (host) (` + relWEB + `)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 1})
	q = relAPI + ` > bool on(host) group_left sum by (host) (` + relWEB + `)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 0})
	// A filtering comparison retains the left value, a bool comparison emits 0 or 1.
	q = relAPI + ` > 1`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 2})
	q = relAPI + ` > bool 1`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 1, "app=api,host=b": 0})
	// Scalar operand orientation is significant: sum(api)=3.
	q = `10 / sum(` + relAPI + `)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"": 10.0 / 3.0})
	q = `sum(` + relAPI + `) / 10`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"": 0.3})
	// Two api series share app=api: the match on(app) is many-to-many and fails.
	q = relAPI + ` + on(app) ` + relWEB
	if _, err := relEval(t, q, rows, value.Evaluation{Instant: true, Time: 2e9}); err == nil {
		t.Fatal("ambiguous many-to-many match evaluated")
	}
	// Both group directions together are not a valid modifier.
	if _, err := parseCheck(t, relAPI+` + on(host) group_left group_right `+relWEB, testProfile(t)); err == nil {
		t.Fatal("group_left group_right accepted")
	}

	// Set operators select by identity and never do arithmetic.
	q = relAPI + ` and on(host) ` + relWEB
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 2})
	q = relAPI + ` unless on(host) ` + relWEB
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=b": 1})
	q = `sum by (host) (` + relAPI + `) or sum by (host) (` + relWEB + `)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"host=a": 2, "host=b": 1, "host=c": 1})
	for _, bad := range []string{relAPI + ` and 1`, `1 or ` + relAPI, `vector(1) unless 2`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil || languageCode(t, err) != "binary.set-invalid" {
			t.Fatalf("%s: set operator with a scalar operand: %v", bad, err)
		}
	}
}

func TestReleaseLogQLVectorAndLabelReplace(t *testing.T) {
	rows := relFixture()
	q := `vector(3)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"": 3})
	r, err := relEval(t, q, rows, value.Evaluation{Start: 1e9, End: 3e9, Step: 1e9})
	if err != nil || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 3 || len(r.Matrix[0].Labels) != 0 {
		t.Fatalf("vector range: %+v %v", r.Matrix, err)
	}
	for i, s := range r.Matrix[0].Samples {
		if s.Time != model.UnixNano(int64(i+1)*1e9) || math.Float64frombits(uint64(s.Float)) != 3 {
			t.Fatalf("vector sample %d: %+v", i, s)
		}
	}
	q = `sum(` + relAPI + `) + on() vector(10)`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"": 13})
	for _, bad := range []string{`vector({app="api"})`, `vector()`, `vector(1,2)`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}

	// A whole-string match expands captures into the destination; a nonmatch keeps labels.
	q = `label_replace(` + relAPI + `, "h", "host-$1", "host", "(.*)")`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,h=host-a,host=a": 2, "app=api,h=host-b,host=b": 1})
	q = `label_replace(` + relAPI + `, "h", "host-$1", "host", "(x)")`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 2, "app=api,host=b": 1})
	// The regex covers the whole value: the empty regex matches only an empty source, never "a".
	q = `label_replace(` + relAPI + `, "h", "z", "host", "")`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a": 2, "app=api,host=b": 1})
	// A missing source label is the empty string, which "" matches.
	q = `label_replace(` + relAPI + `, "z", "x", "missing", "")`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"app=api,host=a,z=x": 2, "app=api,host=b,z=x": 1})
	q = `sum by (h) (label_replace(` + relAPI + `, "h", "$1", "host", "(a|b)"))`
	relWant(t, q, relInstant(t, q, rows), map[string]float64{"h=a": 2, "h=b": 1})
	for _, bad := range []string{
		`label_replace(` + relAPI + `, "h", "$1", "host", "(")`,
		`label_replace(` + relAPI + `, "1h", "$1", "host", "(.*)")`,
	} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestReleaseLogQLRangeWindowsAndTimeGrid(t *testing.T) {
	rows := []scan.LogRow{relRow(1, 0, "a", "app", "api"), relRow(2, 1e9, "b", "app", "api"), relRow(3, 15e8, "c", "app", "api"), relRow(4, 17e8, "d", "app", "api"), relRow(5, 4e9, "e", "app", "api")}
	// Windows are (t-offset-range, t-offset]: t=2s -> (-1s,1s]: {0,1s}=2; t=3s -> (0,2s]: {1s,1.5s,1.7s}=3;
	// t=4s -> (1s,3s]: {1.5s,1.7s}=2; t=5s -> (2s,4s]: {4s}=1. The grid is requested start..end inclusive.
	r, err := relEval(t, `count_over_time({app="api"}[2s] offset 1s)`, rows, value.Evaluation{Start: 2e9, End: 5e9, Step: 1e9})
	if err != nil || len(r.Matrix) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	want := []float64{2, 3, 2, 1}
	if len(r.Matrix[0].Samples) != 4 {
		t.Fatalf("grid points: %+v", r.Matrix[0].Samples)
	}
	for i, s := range r.Matrix[0].Samples {
		if s.Time != model.UnixNano(int64(i+2)*1e9) || math.Float64frombits(uint64(s.Float)) != want[i] {
			t.Fatalf("grid point %d: time %d value %g, want %ds %g", i, s.Time, math.Float64frombits(uint64(s.Float)), i+2, want[i])
		}
	}
	// The end grid point is included only when the step reaches it.
	r, err = relEval(t, `count_over_time({app="api"}[2s])`, rows, value.Evaluation{Start: 2e9, End: 45e8, Step: 1e9})
	if err != nil || len(r.Matrix) != 1 || len(r.Matrix[0].Samples) != 3 {
		t.Fatalf("end not reached by the step: %+v %v", r.Matrix, err)
	}
	// Nanosecond inclusion: left-open at 0, right-closed at 2s, 1ns after the end excluded.
	edge := []scan.LogRow{relRow(1, 0, "a", "app", "api"), relRow(2, 1, "b", "app", "api"), relRow(3, 2e9, "c", "app", "api"), relRow(4, 2e9+1, "d", "app", "api")}
	q := `sum(count_over_time({app="api"}[2s]))`
	relWant(t, q, relInstant(t, q, edge), map[string]float64{"": 2})
	for _, bad := range []string{`count_over_time({app="api"} offset 1s [2s])`, `count_over_time({app="api"}[2s] offset)`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
}

func TestReleaseLogQLFirstLastAndSampleIdentity(t *testing.T) {
	same := []scan.LogRow{relRow(1, 1e9, "n=5", "app", "api"), relRow(2, 1e9, "n=9", "app", "api"), relRow(3, 1e9, "n=7", "app", "api")}
	// Equal timestamps carry no value tie-break: first is the first encountered, last the last.
	q := `first_over_time({app="api"}|logfmt|unwrap n[2s])`
	relWant(t, q, relInstant(t, q, same), map[string]float64{"app=api": 5})
	q = `last_over_time({app="api"}|logfmt|unwrap n[2s])`
	relWant(t, q, relInstant(t, q, same), map[string]float64{"app=api": 7})
	// Across streams the earlier timestamp comes first whatever the stream.
	cross := []scan.LogRow{relRow(1, 2e9, "n=1", "app", "api", "host", "a"), relRow(2, 1e9, "n=2", "app", "api", "host", "b")}
	q = `first_over_time({app="api"}|logfmt|unwrap n[3s]) by (app)`
	relWant(t, q, relInstant(t, q, cross), map[string]float64{"app=api": 2})
	q = `last_over_time({app="api"}|logfmt|unwrap n[3s]) by (app)`
	relWant(t, q, relInstant(t, q, cross), map[string]float64{"app=api": 1})
	// Equal timestamps across streams merge by ascending stream hash (the XXH64 vectors are
	// checked in TestReleaseLogQLEntryMergeTieBreaksByStreamHash), not by arrival order.
	hashOf := func(host string) uint64 {
		return metricXXH64(metricStreamHashBytes(nil, relLabels("app", "api", "host", host)))
	}
	low, high := "a", "c"
	if hashOf("c") < hashOf("a") {
		low, high = "c", "a"
	}
	val := map[string]string{low: "n=5", high: "n=100"}
	for _, arrival := range [][2]string{{low, high}, {high, low}} {
		tied := []scan.LogRow{relRow(1, 1e9, val[arrival[0]], "app", "api", "host", arrival[0]), relRow(2, 1e9, val[arrival[1]], "app", "api", "host", arrival[1])}
		q = `first_over_time({app="api"}|logfmt|unwrap n[2s]) by (app)`
		relWant(t, q, relInstant(t, q, tied), map[string]float64{"app=api": 5})
		q = `last_over_time({app="api"}|logfmt|unwrap n[2s]) by (app)`
		relWant(t, q, relInstant(t, q, tied), map[string]float64{"app=api": 100})
	}
	// Value or text equality is not sample identity: three equal records are three samples.
	dup := []scan.LogRow{relRow(1, 1e9, "n=2", "app", "api"), relRow(2, 1e9, "n=2", "app", "api"), relRow(3, 1e9, "n=2", "app", "api")}
	q = `count_over_time({app="api"}[2s])`
	relWant(t, q, relInstant(t, q, dup), map[string]float64{"app=api": 3})
	q = `sum_over_time({app="api"}|logfmt|unwrap n[2s])`
	relWant(t, q, relInstant(t, q, dup), map[string]float64{"app=api": 6})
	// A record of multiplicity m is m samples.
	multi := relRow(1, 1e9, "n=2", "app", "api")
	multi.Multiplicity = 4
	q = `sum_over_time({app="api"}|logfmt|unwrap n[2s])`
	relWant(t, q, relInstant(t, q, []scan.LogRow{multi}), map[string]float64{"app=api": 8})
}

func relLogs(t *testing.T, q string, rows []scan.LogRow, e value.Evaluation, order LogOrder, limit uint64, interval int64) []value.Log {
	t.Helper()
	a := value.NewBoundedAccount(64 << 20)
	r, err := EvaluateLogsInterval(context.Background(), metricPlan(t, q, e), &metricSource{rows: rows}, order, limit, interval, a)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return r.Logs
}
func relLines(logs []value.Log) string {
	var parts []string
	for _, l := range logs {
		for n := model.Uint64(0); n < l.Multiplicity; n++ {
			parts = append(parts, l.Line)
		}
	}
	return strings.Join(parts, ",")
}

func TestReleaseLogQLLogOrderLimitAndInterval(t *testing.T) {
	rows := []scan.LogRow{
		relRow(1, 1e9, "a1", "app", "api", "host", "a"), relRow(2, 1e9, "b1", "app", "api", "host", "b"), relRow(3, 2e9, "a2", "app", "api", "host", "a"),
		relRow(4, 2e9, "b2", "app", "api", "host", "b"), relRow(5, 3e9, "c1", "app", "api", "host", "c"),
	}
	e := value.Evaluation{Start: 0, End: 5e9, Step: 1e9}
	// The limit is global across streams: exactly three entries, newest first when backward.
	logs := relLogs(t, `{app="api"}`, rows, e, Backward, 3, 0)
	if len(logs) != 3 || logs[0].Line != "c1" || logs[1].Timestamp != 2e9 || logs[2].Timestamp != 2e9 || logs[1].Line == logs[2].Line {
		t.Fatalf("backward limit 3: %s", relLines(logs))
	}
	logs = relLogs(t, `{app="api"}`, rows, e, Forward, 2, 0)
	if got := relLines(logs); len(logs) != 2 || (got != "a1,b1" && got != "b1,a1") || logs[0].Timestamp != 1e9 || logs[1].Timestamp != 1e9 {
		t.Fatalf("forward limit 2: %s", got)
	}
	if logs = relLogs(t, `{app="api"}`, rows, e, Forward, 0, 0); len(logs) != 0 {
		t.Fatalf("limit 0 returned %d entries", len(logs))
	}
	// Entries removed by the pipeline never consume the limit.
	filtered := []scan.LogRow{
		relRow(1, 1e9, "n=1", "app", "api", "host", "a"), relRow(2, 12e8, "n=2", "app", "api", "host", "b"), relRow(3, 2e9, "n=0", "app", "api", "host", "a"),
		relRow(4, 3e9, "n=3", "app", "api", "host", "a"), relRow(5, 4e9, "n=4", "app", "api", "host", "c"),
	}
	if got := relLines(relLogs(t, `{app="api"}|logfmt|n>1`, filtered, e, Forward, 2, 0)); got != "n=2,n=3" {
		t.Fatalf("filtered limit: %s", got)
	}
	// Interval sampling measures distance from the last emitted entry, inclusively:
	// 1s (kept), 1s (distance 0), 2s (distance exactly 1s kept), 2s (0), 3s (1s kept).
	logs = relLogs(t, `{app="api"}`, rows, e, Forward, 10, 1e9)
	if len(logs) != 3 || logs[0].Timestamp != 1e9 || logs[1].Timestamp != 2e9 || logs[2].Timestamp != 3e9 {
		t.Fatalf("interval 1s: %s", relLines(logs))
	}
	// Nanosecond timestamps survive untouched.
	ns := []scan.LogRow{relRow(1, 1000000001, "x", "app", "api"), relRow(2, 1000000002, "y", "app", "api")}
	logs = relLogs(t, `{app="api"}`, ns, e, Forward, 10, 0)
	if len(logs) != 2 || logs[0].Timestamp != 1000000001 || logs[1].Timestamp != 1000000002 {
		t.Fatalf("nanosecond timestamps: %+v", logs)
	}
	// A metric query ignores the log limit: both series come back.
	r, err := relEval(t, `rate({app="api"}[2s])`, rows, value.Evaluation{Instant: true, Time: 2e9})
	if err != nil || len(r.Vector) != 2 {
		t.Fatalf("metric query was limited: %d series %v", len(r.Vector), err)
	}
}

// XXH64 reference vectors (published): the stream hash that breaks cross-stream timestamp ties is built on it.
func TestReleaseLogQLEntryMergeTieBreaksByStreamHash(t *testing.T) {
	for _, v := range []struct {
		in   string
		want uint64
	}{{"", 0xEF46DB3751D8E999}, {"a", 0xD24EC4F1A98C6E5B}, {"abc", 0x44BC2CF5AD770999}} {
		if got := metricXXH64([]byte(v.in)); got != v.want {
			t.Fatalf("XXH64(%q)=%016x want %016x", v.in, got, v.want)
		}
	}
	a, b := relLabels("app", "api", "host", "a"), relLabels("app", "api", "host", "b")
	hash := func(ls model.Labels) uint64 { return metricXXH64(metricStreamHashBytes(nil, ls)) }
	first, second := "A", "B"
	if hash(b) < hash(a) {
		first, second = "B", "A"
	}
	mk := func(id byte, line string, ls model.Labels) PipelineResult {
		return PipelineResult{Retained: true, Entry: LogEntry{ID: model.ID{id}, Timestamp: 1000, Multiplicity: 1, Line: line}, Labels: ls, OriginalStreamLabels: ls}
	}
	rowsAB := []PipelineResult{mk(1, "A", a), mk(2, "B", b)}
	for _, order := range []LogOrder{Forward, Backward} {
		// Equal timestamps order by ascending stream hash in either direction, and not by arrival.
		for _, rows := range [][]PipelineResult{rowsAB, {rowsAB[1], rowsAB[0]}} {
			if got := releaseMerged(t, order, 10, rows...); len(got) != 2 || got[0] != first || got[1] != second {
				t.Fatalf("%s: %v, want %s then %s", order, got, first, second)
			}
		}
	}
	// Equal text in different streams never collapses, and a limit counts every entry.
	same := []PipelineResult{mk(1, "same", a), mk(2, "same", b)}
	if got := releaseMerged(t, Forward, 10, same...); len(got) != 2 {
		t.Fatalf("equal lines in two streams collapsed: %v", got)
	}
	if got := releaseMerged(t, Forward, 1, same...); len(got) != 1 {
		t.Fatalf("limit 1 returned %v", got)
	}
	// Without a stream hash the label string orders the tie.
	bare := func(id byte, line string, ls model.Labels) PipelineResult {
		return PipelineResult{Retained: true, Entry: LogEntry{ID: model.ID{id}, Timestamp: 1000, Multiplicity: 1, Line: line}, Labels: ls}
	}
	if got := releaseMerged(t, Forward, 10, bare(1, "B", b), bare(2, "A", a)); len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("label order without a hash: %v", got)
	}
}

func TestReleaseLogQLSelectorsAndStructuredMetadata(t *testing.T) {
	rows := []scan.LogRow{
		relRow(1, 1e9, "x", "app", "api", "host", "a"), relRow(2, 11e8, "y", "app", "api", "host", "ab"), relRow(3, 12e8, "z", "app", "api"), relRow(4, 13e8, "w", "app", "web", "host", "a"),
	}
	e := value.Evaluation{Start: 0, End: 3e9, Step: 1e9}
	// Regex matching is whole-value; the empty alternative also selects a missing label.
	if got := relLines(relLogs(t, `{app="api", host=~"a|"}`, rows, e, Forward, 10, 0)); got != "x,z" {
		t.Fatalf("whole-value regex: %s", got)
	}
	if got := relLines(relLogs(t, `{app="api", host!~"a"}`, rows, e, Forward, 10, 0)); got != "y,z" {
		t.Fatalf("negated regex: %s", got)
	}
	if got := relLines(relLogs(t, `{app="api", host!=""}`, rows, e, Forward, 10, 0)); got != "x,y" {
		t.Fatalf("missing label equals empty: %s", got)
	}
	for _, bad := range []string{`{app=~".*"}`, `{app!="x"}`, `{app=~"a*"}`, `{host=""}`} {
		if _, err := parseCheck(t, bad, testProfile(t)); err == nil || languageCode(t, err) != "selector.empty-compatible" {
			t.Fatalf("%s: selector accepting empty everywhere: %v", bad, err)
		}
	}
	// Structured metadata is not a stream selector dimension; it is visible to the pipeline.
	meta := []scan.LogRow{relMeta(relRow(1, 1e9, "hello", "app", "api"), "trace", "abc"), relMeta(relRow(2, 12e8, "other", "app", "api"), "trace", "def")}
	if got := relLines(relLogs(t, `{app="api", trace="abc"}`, meta, e, Forward, 10, 0)); got != "" {
		t.Fatalf("metadata promoted to the selector: %s", got)
	}
	if got := relLines(relLogs(t, `{app="api"}|trace="abc"`, meta, e, Forward, 10, 0)); got != "hello" {
		t.Fatalf("metadata filter: %s", got)
	}
	// Grouping by a metadata label separates the series by its value.
	q := `sum by (trace) (count_over_time({app="api"}[2s]))`
	relWant(t, q, relInstant(t, q, meta), map[string]float64{"trace=abc": 1, "trace=def": 1})
	// Categories stay distinct on the entry itself and the pipeline sees the value.
	e1 := relEntry("hello", "app", "api")
	e1.StructuredMetadata = relLabels("trace", "abc")
	if r := run(t, `{app="api"}|trace="abc"`, e1); !r.Retained || lookup(r.Labels, "trace") != "abc" {
		t.Fatalf("metadata invisible to pipeline: %+v", r)
	}
	if r := run(t, `{app="api"}|trace="zzz"`, e1); r.Retained {
		t.Fatal("metadata mismatch retained")
	}
}

func TestReleaseLogQLVariantsAndShardCapabilityDomain(t *testing.T) {
	rows := relFixture()
	const variants = `variants(count_over_time({app="api"}[2s]),bytes_over_time({app="api"}[2s])) of ({app="api"}[2s])`
	disabled := testProfile(t)
	typed, err := parseCheck(t, variants, disabled)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, disabled); err == nil {
		t.Fatal("variants evaluated with the gate off")
	}
	on := profileWithGate(t, "multi-variant-queries")
	typed, err = parseCheck(t, variants, on)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, on)
	if err != nil {
		t.Fatal(err)
	}
	a := value.NewBoundedAccount(64 << 20)
	r, _, err := Evaluate(context.Background(), plan, &metricSource{rows: rows}, a)
	if err != nil {
		t.Fatal(err)
	}
	// api/a has 2 lines of 3 bytes, api/b one of 3 bytes: the variants keep distinct identities.
	var got []float64
	seen := map[string]bool{}
	for _, s := range r.Vector {
		seen[relKey(s.Labels)] = true
		got = append(got, math.Float64frombits(uint64(s.Samples[0].Float)))
	}
	sort.Float64s(got)
	if len(seen) != 4 || len(got) != 4 || got[0] != 1 || got[1] != 2 || got[2] != 3 || got[3] != 6 {
		t.Fatalf("variants lost identity or values: series=%v values=%v", seen, got)
	}

	// approx_topk is an explicit capability: shard capabilities never imply it.
	shardOnly := profileWithGate(t, "shard-first_over_time")
	typed, err = parseCheck(t, `approx_topk(1,`+relAPI+`)`, shardOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, shardOnly); err == nil {
		t.Fatal("shard capability enabled approx_topk")
	}
	approx := profileWithGate(t, "approx_topk")
	typed, err = parseCheck(t, `approx_topk(1,`+relAPI+`)`, approx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, approx); err != nil {
		t.Fatalf("approx_topk capability rejected: %v", err)
	}
	// The capability also needs a positive integer k and forbids grouping.
	for _, bad := range []string{`approx_topk(0,` + relAPI + `)`, `approx_topk(1.5,` + relAPI + `)`, `approx_topk by (app) (1,` + relAPI + `)`} {
		if _, err = parseCheck(t, bad, approx); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	// A shard capability only selects an execution strategy: results are the exact operation's.
	for _, gate := range []string{"shard-first_over_time", "shard-last_over_time", "shard-quantile_over_time"} {
		p := profileWithGate(t, gate)
		for _, q := range []string{`first_over_time({app="api"}|logfmt|unwrap n[2s])`, `last_over_time({app="api"}|logfmt|unwrap n[2s])`, `quantile_over_time(0.5,{app="api"}|logfmt|unwrap n[2s])`} {
			typed, err := parseCheck(t, q, p)
			if err != nil {
				t.Fatalf("%s with %s: %v", q, gate, err)
			}
			plan, err := BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p)
			if err != nil {
				t.Fatalf("%s with %s: %v", q, gate, err)
			}
			acct := value.NewBoundedAccount(64 << 20)
			res, _, err := Evaluate(context.Background(), plan, &metricSource{rows: rows}, acct)
			if err != nil {
				t.Fatal(err)
			}
			want, err := relEval(t, q, rows, value.Evaluation{Instant: true, Time: 2e9})
			if err != nil || len(res.Vector) != len(want.Vector) || len(res.Vector) != 2 {
				t.Fatalf("%s with %s: %v vs %v (%v)", q, gate, res.Vector, want.Vector, err)
			}
		}
	}
}

// The evaluator reads streams back without their hash (as the pinned engine does), so equal-time
// entries of different streams order by label string in both directions, never by arrival, while
// entries of one stream keep their encounter order.
func TestReleaseLogQLEntryMergeInEnginePathOrdersTiesByLabels(t *testing.T) {
	rows := []scan.LogRow{
		relRow(1, 1e9, "C", "app", "api", "host", "c"), relRow(2, 1e9, "x", "app", "api", "host", "a"), relRow(3, 1e9, "B", "app", "api", "host", "b"),
		relRow(4, 1e9, "same", "app", "api", "host", "a"), relRow(5, 2e9, "late", "app", "api", "host", "c"),
		// {app="api", host="a"} sorts before {app="api"}: ',' < '}' in the label string.
		relRow(6, 25e8, "Q", "app", "api"), relRow(7, 25e8, "P", "app", "api", "host", "a"),
	}
	e := value.Evaluation{Start: 0, End: 3e9, Step: 1e9}
	if got := relLines(relLogs(t, `{app="api"}`, rows, e, Forward, 10, 0)); got != "x,same,B,C,late,P,Q" {
		t.Fatalf("forward: %s", got)
	}
	if got := relLines(relLogs(t, `{app="api"}`, rows, e, Backward, 10, 0)); got != "P,Q,late,x,same,B,C" {
		t.Fatalf("backward: %s", got)
	}
	if got := relLines(relLogs(t, `{app="api"}`, rows, e, Backward, 3, 0)); got != "P,Q,late" {
		t.Fatalf("backward limit: %s", got)
	}
}
