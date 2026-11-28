// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func floatBits(v uint64) *model.FloatBits { f := model.FloatBits(v); return &f }

// decodeTestPages are encoded pages of every shape a typed decoder meets: plain metric rows (labels, none,
// an empty set), rows with a start timestamp and no value, a histogram and an exemplar (generic decoder
// only), and log rows (generic decoder only; their scalars take the canonical-text path).
func decodeTestPages(t testing.TB) map[string][]byte {
	t.Helper()
	res := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "inst-1"}
	project, source := model.NewID(), model.NewID()
	cursor := model.Cursor{Group: model.NewID(), Index: 7}
	start := model.UnixNano(40)
	var trace model.ID = model.NewID()
	metric := func(i int, mp model.MetricPoint) model.Record {
		return model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: model.UnixNano(1000 + i%9), Resource: res, Payload: model.Payload{Metric: &mp}}
	}
	scalar := func(raw string) model.Scalar {
		var s model.Scalar
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	build := func(rows []model.Record) []byte {
		b, err := encodePage(recordsPage(rows, project, source, cursor))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	pages := map[string][]byte{}
	var plain, mixed, odd, logs []model.Record
	for i := range pageRows {
		labels := model.Labels{{Name: "route", Value: fmt.Sprintf("r%d", i%7)}}
		switch i % 5 {
		case 3:
			labels = nil
		case 4:
			labels = model.Labels{}
		}
		plain = append(plain, metric(i, model.MetricPoint{Name: fmt.Sprintf("app_m%d", i%5), Labels: labels, SampleKind: "float", Value: floatBits(uint64(i) * 0x9e3779b97f4a7c15), Unit: "1", Type: "counter"}))
		mp := model.MetricPoint{Name: "app_m0", Labels: model.Labels{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}, SampleKind: "float", Value: floatBits(1), Unit: "1", Type: "gauge"}
		if i%3 == 0 {
			mp.Value, mp.StartTimestamp = nil, &start
		}
		mixed = append(mixed, metric(i, mp))
		op := model.MetricPoint{Name: "app_m1", SampleKind: "float", Value: floatBits(2), Unit: "1", Type: "gauge"}
		if i == 70 {
			op.ExemplarTrace = &trace
		}
		odd = append(odd, metric(i, op))
		logs = append(logs, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: model.UnixNano(500 + i), Resource: res, Payload: model.Payload{Log: &model.LogRecord{Severity: "info", TemplateID: "t", TemplateRevision: 1,
			Fields:       map[string]model.Scalar{"count": scalar(fmt.Sprint(i)), "ok": scalar("true"), "name": scalar(`"a b"`), "esc": scalar(`"x\ny<"`), "none": scalar("null"), "neg": scalar("-3")},
			Line:         fmt.Sprintf("line %d", i),
			StreamLabels: model.Labels{{Name: "route", Value: "r1"}}, Metadata: map[string]model.Scalar{}, SourceClass: "structured"}}})
	}
	var varied, plainLogs []model.Record
	ts, span, run := model.UnixNano(77), model.SpanID{1, 2, 3, 4, 5, 6, 7, 8}, model.NewID()
	for i := range 40 {
		l := &model.LogRecord{Severity: "warn", TemplateID: fmt.Sprintf("t%d", i%3), TemplateRevision: model.Revision(i), Line: fmt.Sprintf("v %d", i), SourceClass: "raw"}
		if i%2 == 0 {
			l.Timestamp, l.Trace, l.Span, l.Run = &ts, &trace, &span, &run
			l.StreamLabels = model.Labels{{Name: "a", Value: "1"}, {Name: "route", Value: fmt.Sprintf("r%d", i%4)}}
			l.Fields = map[string]model.Scalar{"k": scalar("1")}
		}
		if i%3 == 0 {
			l.StreamLabels = model.Labels{}
			l.Metadata = map[string]model.Scalar{"m": scalar(`"x"`)}
		}
		varied = append(varied, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: model.UnixNano(600 + i), Resource: res, Payload: model.Payload{Log: l}})
		plainLogs = append(plainLogs, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: model.UnixNano(700 + i), Resource: res, Payload: model.Payload{Log: &model.LogRecord{Severity: "info", Line: "plain", StreamLabels: model.Labels{{Name: "route", Value: "r1"}}}}})
	}
	var canonical []model.Record
	for i := range pageRows {
		canonical = append(canonical, model.Record{ID: model.NewID(), Kind: model.Log, ObservedAt: model.UnixNano(800 + i), Resource: res, Payload: model.Payload{Log: &model.LogRecord{Severity: "info", TemplateID: "t", TemplateRevision: 1,
			Fields:       map[string]model.Scalar{"count": scalar(fmt.Sprint(i)), "ok": scalar("true"), "name": scalar(`"abc"`), "none": scalar("null"), "neg": scalar("-3")},
			Line:         fmt.Sprintf("line %d", i),
			StreamLabels: model.Labels{{Name: "route", Value: "r1"}}, Metadata: map[string]model.Scalar{}, SourceClass: "structured"}}})
	}
	pages["logs_varied"], pages["logs_plain"], pages["logs_canonical"] = build(varied), build(plainLogs), build(canonical)
	pages["plain"], pages["mixed"], pages["exemplar"], pages["logs"] = build(plain), build(mixed), build(odd), build(logs)
	pages["one"] = build(plain[:1])
	return pages
}

// A typed decoder builds exactly what the generic decoder builds, for every shape of page, with and
// without the resource and payload columns.
func TestTypedPageDecodersEqualTheGenericDecoder(t *testing.T) {
	defer func(v bool) { pageFastDecode = v }(pageFastDecode)
	for name, b := range decodeTestPages(t) {
		for _, cols := range [][2]bool{{true, true}, {false, true}, {true, false}, {false, false}} {
			pageFastDecode = false
			want, err := decodePageColumns(b, cols[0], cols[1])
			if err != nil {
				t.Fatalf("%s %v: generic decoder: %v", name, cols, err)
			}
			pageFastDecode = true
			got, err := decodePageColumns(b, cols[0], cols[1])
			if err != nil {
				t.Fatalf("%s %v: typed decoders: %v", name, cols, err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %v: the typed decoders built another page than the generic decoder", name, cols)
			}
		}
	}
}

// A decode of a metric page by the typed decoders allocates a fraction of what the generic decoder
// does (the reflection walk made a value of its own for most of the values of a row).
func TestMetricPageDecodeAllocatesAFractionOfTheGenericDecode(t *testing.T) {
	defer func(v bool) { pageFastDecode = v }(pageFastDecode)
	b := decodeTestPages(t)["plain"]
	run := func() float64 {
		return testing.AllocsPerRun(20, func() {
			if _, err := decodePageColumns(b, false, true); err != nil {
				t.Fatal(err)
			}
		})
	}
	pageFastDecode = false
	generic := run()
	pageFastDecode = true
	typed := run()
	t.Logf("allocations of one 128-row metric page decode: generic %.0f, typed %.0f", generic, typed)
	if typed*4 > generic {
		t.Fatalf("the typed decode allocates %.0f times, the generic one %.0f: want at most a quarter", typed, generic)
	}
}

// A decode of a log page by the typed decoders allocates at most half of what the generic decoder does
// (logs were 17 of the 27 CPU seconds of page decode in the 24 h log class of the gate mix).
func TestLogPageDecodeAllocatesAtMostHalfOfTheGenericDecode(t *testing.T) {
	defer func(v bool) { pageFastDecode = v }(pageFastDecode)
	b := decodeTestPages(t)["logs_canonical"]
	run := func() float64 {
		return testing.AllocsPerRun(20, func() {
			if _, err := decodePageColumns(b, false, true); err != nil {
				t.Fatal(err)
			}
		})
	}
	pageFastDecode = false
	generic := run()
	pageFastDecode = true
	typed := run()
	t.Logf("allocations of one 128-row log page decode: generic %.0f, typed %.0f", generic, typed)
	if typed*2 > generic {
		t.Fatalf("the typed decode allocates %.0f times, the generic one %.0f: want at most half", typed, generic)
	}
}

// ScalarFromCanonical agrees with Scalar.UnmarshalJSON wherever it answers.
func TestScalarFromCanonicalAgreesWithUnmarshal(t *testing.T) {
	for _, raw := range []string{"null", "true", "false", "0", "-0", "-1", "01", "9223372036854775807", "9223372036854775808", "1.5", "1e3", `""`, `"a"`, `"a b"`, `"x\ny"`, `"é"`, `"<"`, `"&"`, `"\u003c"`, `"`, "", "-", "tru", `"a"b"`} {
		got, ok := model.ScalarFromCanonical(raw)
		if !ok {
			continue
		}
		var want model.Scalar
		if err := json.Unmarshal([]byte(raw), &want); err != nil {
			t.Fatalf("%q: fast path accepts what UnmarshalJSON refuses: %v", raw, err)
		}
		if got != want {
			t.Fatalf("%q: fast path %v, UnmarshalJSON %v", raw, got, want)
		}
	}
}
