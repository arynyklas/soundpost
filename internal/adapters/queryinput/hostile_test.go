// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Hostile-input review of the translators (ledger 02.08#14). The tests here build
// their wire bytes by hand (protobuf field numbers, text, JSON) instead of going
// through the decoders' own helpers, so a decoder defect cannot hide in a shared
// encoder. Each finding test states the property a hostile or merely unusual
// sender must not be able to break.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// ---- hand-built wire encoders ----

type hsPB struct{ b []byte }

func (w *hsPB) tag(num, wt uint64) { w.b = binary.AppendUvarint(w.b, num<<3|wt) }
func (w *hsPB) varint(num, v uint64) {
	w.tag(num, 0)
	w.b = binary.AppendUvarint(w.b, v)
}
func (w *hsPB) fixed64(num, v uint64) {
	w.tag(num, 1)
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
}
func (w *hsPB) bytes(num uint64, p []byte) {
	w.tag(num, 2)
	w.b = binary.AppendUvarint(w.b, uint64(len(p)))
	w.b = append(w.b, p...)
}
func (w *hsPB) msg(num uint64, f func(*hsPB)) {
	var in hsPB
	f(&in)
	w.bytes(num, in.b)
}

func hsPacked(vals ...uint64) []byte {
	var b []byte
	for _, v := range vals {
		b = binary.AppendUvarint(b, v)
	}
	return b
}

func hsZZ(v int64) uint64 { return uint64(v<<1) ^ uint64(v>>63) }

// hsSyms is a remote-write v2 symbol table (index 0 is the empty string).
type hsSyms struct {
	list  []string
	index map[string]uint64
}

func newHSSyms() *hsSyms { return &hsSyms{list: []string{""}, index: map[string]uint64{"": 0}} }

func (s *hsSyms) ref(v string) uint64 {
	if i, ok := s.index[v]; ok {
		return i
	}
	s.index[v] = uint64(len(s.list))
	s.list = append(s.list, v)
	return s.index[v]
}

// request assembles an io.prometheus.write.v2.Request: symbols (field 4), series (field 5).
func (s *hsSyms) request(series ...[]byte) []byte {
	var w hsPB
	for _, v := range s.list {
		w.bytes(4, []byte(v))
	}
	for _, ts := range series {
		w.bytes(5, ts)
	}
	return w.b
}

const hsTS = 1_700_000_000_000 // milliseconds, inside the fixture profile's bounds

func hsSample(w *hsPB, bits uint64, tsMS int64) {
	w.msg(2, func(m *hsPB) {
		m.fixed64(1, bits)
		m.varint(2, uint64(tsMS))
	})
}

func hsDecodeRW(f *fixture, v WireVersion, plain []byte, cfg InputProfile) ([]model.Batch, error) {
	return DecodeRemoteWrite(f.ctx, f.grant(), v, bytes.NewReader(snappyEncode(plain)), cfg)
}

// hsRW turns the semantic JSON of conformance/query/fixtures/adapters into plain protobuf.
func hsRW(t testing.TB, text string) []byte {
	t.Helper()
	var in semRW
	if err := json.Unmarshal([]byte(text), &in); err != nil {
		t.Fatal(err)
	}
	return encodeRW(t, in)
}

func hsProjection(t testing.TB, batches []model.Batch) []string {
	t.Helper()
	return sortedProjection(t, projectBatches(t, batches))
}

// hsRetained is the heap that stays reachable after run returns (its result is kept alive).
func hsRetained(run func() any) uint64 {
	runtime.GC()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	out := run()
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(out)
	if after.HeapAlloc < before.HeapAlloc {
		return 0
	}
	return after.HeapAlloc - before.HeapAlloc
}

// ---- F01: remote-write v2 label references ----

// A repeated uint32 field may arrive packed, unpacked or split over several
// fields; every legal encoding of one series must decode to the same labels. A
// reference that cannot be paired must be refused, never ignored: silently
// dropping a label merges distinct series into one.
func TestHostileRemoteWriteV2LabelReferencesAcrossFields(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	cfg.Exemplars = ExemplarsTraceLink
	series := func(encode func(ts *hsPB, s *hsSyms)) []byte {
		s := newHSSyms()
		var ts hsPB
		encode(&ts, s)
		hsSample(&ts, 0x3ff0000000000000, hsTS)
		return s.request(ts.b)
	}
	pairs := func(s *hsSyms) []uint64 {
		return []uint64{s.ref("__name__"), s.ref("hs_labels"), s.ref("job"), s.ref("api"), s.ref("region"), s.ref("eu")}
	}
	want, err := hsDecodeRW(f, RemoteWriteV2, series(func(ts *hsPB, s *hsSyms) { ts.bytes(1, hsPacked(pairs(s)...)) }), cfg)
	if err != nil || len(want) != 1 || len(want[0].Records[0].Payload.Metric.Labels) != 2 {
		t.Fatalf("packed baseline: %v %v", want, err)
	}
	variants := map[string]func(ts *hsPB, s *hsSyms){
		"name pair packed, the rest unpacked": func(ts *hsPB, s *hsSyms) {
			p := pairs(s)
			ts.bytes(1, hsPacked(p[:2]...))
			for _, r := range p[2:] {
				ts.varint(1, r)
			}
		},
		"every reference unpacked": func(ts *hsPB, s *hsSyms) {
			for _, r := range pairs(s) {
				ts.varint(1, r)
			}
		},
		"one packed run split in the middle of a pair": func(ts *hsPB, s *hsSyms) {
			p := pairs(s)
			ts.bytes(1, hsPacked(p[:3]...))
			ts.bytes(1, hsPacked(p[3:]...))
		},
	}
	for name, encode := range variants {
		t.Run(name, func(t *testing.T) {
			got, err := hsDecodeRW(f, RemoteWriteV2, series(encode), cfg)
			if err != nil {
				t.Fatalf("a legal encoding of the same series was refused: %v", err)
			}
			if g, w := hsProjection(t, got), hsProjection(t, want); !reflect.DeepEqual(g, w) {
				t.Fatalf("labels were silently lost or changed:\n got %v\nwant %v", g, w)
			}
		})
	}
	t.Run("an unpacked reference above uint32 is refused", func(t *testing.T) {
		body := series(func(ts *hsPB, s *hsSyms) {
			ts.bytes(1, hsPacked(pairs(s)...))
			ts.varint(1, 1<<40)
		})
		if _, err := hsDecodeRW(f, RemoteWriteV2, body, cfg); reasonOf(err) != ReasonMalformed {
			t.Fatalf("an unusable label reference was ignored instead of refused: %v", err)
		}
	})
	t.Run("exemplar label references unpacked", func(t *testing.T) {
		build := func(unpacked bool) []byte {
			return series(func(ts *hsPB, s *hsSyms) {
				ts.bytes(1, hsPacked(pairs(s)...))
				ex := []uint64{s.ref("trace_id"), s.ref("0af7651916cd43dd8448eb211c80319c")}
				ts.msg(4, func(m *hsPB) {
					if unpacked {
						for _, r := range ex {
							m.varint(1, r)
						}
					} else {
						m.bytes(1, hsPacked(ex...))
					}
					m.fixed64(2, 0x3ff0000000000000)
					m.varint(3, hsTS)
				})
			})
		}
		packed, err := hsDecodeRW(f, RemoteWriteV2, build(false), cfg)
		if err != nil || packed[0].Records[0].Payload.Metric.ExemplarTrace == nil {
			t.Fatalf("packed exemplar baseline: %v", err)
		}
		got, err := hsDecodeRW(f, RemoteWriteV2, build(true), cfg)
		if err != nil {
			t.Fatalf("unpacked exemplar references refused: %v", err)
		}
		if g, w := hsProjection(t, got), hsProjection(t, packed); !reflect.DeepEqual(g, w) {
			t.Fatalf("exemplar link lost:\n got %v\nwant %v", g, w)
		}
	})
}

// ---- F02: series identity key ----

// Two different label sets must never share a series key. NUL is a legal byte in
// a label value (it is valid UTF-8), so a NUL-separated key can be forged: the
// series {a="x\0b\0y"} and {a="x", b="y"} would collide and a legitimate request
// carrying both would be refused as a "conflicting duplicate".
func TestHostileSeriesKeyWithNULBytes(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	slot := func(labels model.Labels) uint16 {
		rec := model.Record{Kind: model.Metric, Payload: model.Payload{Metric: &model.MetricPoint{Name: "hs_nul", Labels: labels}}}
		s, err := model.OwnerSlot(f.org, f.project, f.source, cfg.Producer, rec)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	tail := ""
	for i := 0; i < 16384 && tail == ""; i++ {
		v := fmt.Sprintf("t%d", i)
		a := model.Labels{{Name: "a", Value: "x\x00b\x00y"}, {Name: "z", Value: v}}
		b := model.Labels{{Name: "a", Value: "x"}, {Name: "b", Value: "y"}, {Name: "z", Value: v}}
		if slot(a) == slot(b) {
			tail = v
		}
	}
	if tail == "" {
		t.Fatal("no pair of colliding series that share an owner slot")
	}
	plain := hsRW(t, fmt.Sprintf(`{"version":1,"timeseries":[
	 {"label_pairs":[["__name__","hs_nul"],["a","x\u0000b\u0000y"],["z",%q]],"samples":[{"bits":"3ff0000000000000","timestamp_ms":"1700000000000"}]},
	 {"label_pairs":[["__name__","hs_nul"],["a","x"],["b","y"],["z",%q]],"samples":[{"bits":"3ff0000000000000","timestamp_ms":"1700000000000"}]}]}`, tail, tail))
	batches, err := hsDecodeRW(f, RemoteWriteV1, plain, cfg)
	if err != nil {
		t.Fatalf("two distinct series were treated as one: %v", err)
	}
	n := 0
	for _, b := range batches {
		n += len(b.Records)
	}
	if n != 2 {
		t.Fatalf("%d records, want 2", n)
	}
}

// ---- F03: OpenMetrics seconds to nanoseconds ----

func TestHostileOpenMetricsTimestampWrapAround(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	cfg.MinTimestamp, cfg.MaxTimestamp = model.UnixNano(math.MinInt64), model.UnixNano(math.MaxInt64)
	decode := func(ts string) ([]model.Batch, error) {
		return DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader("# TYPE x gauge\nx 1 "+ts+"\n# EOF\n"), cfg)
	}
	for _, tc := range []struct {
		ts   string
		want model.UnixNano
	}{
		{"9223372036.854775807", math.MaxInt64},
		{"-9223372036.854775808", math.MinInt64},
		{"0", 0},
		{"-0", 0},
		{"-0.000000001", -1},
	} {
		b, err := decode(tc.ts)
		if err != nil || len(b) != 1 || b[0].Records[0].ObservedAt != tc.want {
			t.Errorf("%s: want ObservedAt %d, got %v %v", tc.ts, tc.want, b, err)
		}
	}
	for _, ts := range []string{"9223372036.854775808", "9223372036.999999999", "-9223372036.854775809", "-9223372036.999999999", "9223372037", "-9223372037"} {
		b, err := decode(ts)
		if reasonOf(err) != ReasonTimestampRange {
			got := model.UnixNano(0)
			if len(b) > 0 {
				got = b[0].Records[0].ObservedAt
			}
			t.Errorf("%s accepted as %d (err %v); it is outside the int64 nanosecond range", ts, got, err)
		}
	}
}

// ---- F04: native histogram spans ----

func hsHistRW(t testing.TB, schema int, spans string, buckets, bounds int) []byte {
	t.Helper()
	deltas := make([]string, buckets)
	for i := range deltas {
		deltas[i] = "0"
	}
	if buckets > 0 {
		deltas[0] = "1"
	}
	custom := make([]string, bounds)
	for i := range custom {
		custom[i] = fmt.Sprintf("%016x", math.Float64bits(float64(i+1)))
	}
	raw, err := json.Marshal(map[string]any{"version": 2, "timeseries": []any{map[string]any{
		"labels": map[string]string{"__name__": "hs_hist", "job": "api"},
		"histograms": []any{map[string]any{
			"count_int": strconv.Itoa(buckets), "sum_bits": "3ff0000000000000", "schema": schema,
			"positive_spans": json.RawMessage(spans), "positive_deltas": deltas, "custom_values_bits": custom,
			"timestamp_ms": "1700000000000",
		}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return hsRW(t, string(raw))
}

// A custom-bucket histogram addresses bucket i with bound i (the last bucket is
// +Inf). Spans that reach past the bounds, or start below bucket zero, describe
// buckets that do not exist: the query layer indexes the bound list with the
// span index, so such a histogram must never be stored.
func TestHostileHistogramSpansAndCustomBounds(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	for _, tc := range []struct {
		name    string
		schema  int
		spans   string
		buckets int
		bounds  int
		ok      bool
	}{
		{"custom: spans end exactly on the +Inf bucket", -53, "[[0,3]]", 3, 2, true},
		{"custom: an offset and spans that reach the +Inf bucket", -53, "[[1,2]]", 2, 2, true},
		{"custom: only the +Inf bucket, no bounds", -53, "[[0,1]]", 1, 0, true},
		{"custom: one bucket past the +Inf bucket", -53, "[[1,3]]", 3, 2, false},
		{"custom: offset far beyond the bounds", -53, "[[5,1]]", 1, 1, false},
		{"custom: negative first offset", -53, "[[-1,2]]", 2, 3, false},
		{"custom: two buckets without any bound", -53, "[[0,2]]", 2, 0, false},
		{"exponential: the running bucket index overflows int32", 3, "[[2147483647,1],[1,1]]", 2, 0, false},
		{"exponential: ordinary offsets, first one negative", 3, "[[-3,2],[1,1]]", 3, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := hsDecodeRW(f, RemoteWriteV2, hsHistRW(t, tc.schema, tc.spans, tc.buckets, tc.bounds), cfg)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("a valid histogram was refused: %v", err)
			case !tc.ok && reasonOf(err) != ReasonMalformed:
				t.Fatalf("a histogram with impossible bucket indices was accepted or mis-typed: %v", err)
			}
		})
	}
}

// ---- F05: output amplification ----

// The label set of a series is repeated by every one of its points, so the
// canonical output of a request is not proportional to its input: a few
// kilobytes of label text times a few thousand samples is hundreds of megabytes
// to marshal, normalize and admit. The output of one request is bounded by a
// multiple of the decoded-size limit.
func TestHostileOutputAmplification(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	cfg.Limits.MaxCompressedBytes = 1 << 20
	cfg.Limits.MaxDecodedBytes = 1 << 20
	wide := func() map[string]string {
		l := map[string]string{}
		for i := range 40 {
			l[fmt.Sprintf("l%02d", i)] = strings.Repeat("v", 1000)
		}
		return l
	}
	t.Run("remote write v1", func(t *testing.T) {
		build := func(samples int) []byte {
			var pairs [][2]string
			pairs = append(pairs, [2]string{"__name__", "hs_wide"})
			for i := range 40 {
				pairs = append(pairs, [2]string{fmt.Sprintf("l%02d", i), strings.Repeat("v", 1000)})
			}
			var sm []map[string]string
			for i := range samples {
				sm = append(sm, map[string]string{"bits": "3ff0000000000000", "timestamp_ms": strconv.Itoa(hsTS + i)})
			}
			raw, err := json.Marshal(map[string]any{"version": 1, "timeseries": []any{map[string]any{"label_pairs": pairs, "samples": sm}}})
			if err != nil {
				t.Fatal(err)
			}
			return hsRW(t, string(raw))
		}
		if _, err := hsDecodeRW(f, RemoteWriteV1, build(12), cfg); err != nil {
			t.Fatalf("a request within the budget was refused: %v", err)
		}
		plain := build(600)
		if int64(len(plain)) > cfg.Limits.MaxDecodedBytes/16 {
			t.Fatalf("test setup: the request is %d bytes", len(plain))
		}
		if _, err := hsDecodeRW(f, RemoteWriteV1, plain, cfg); reasonOf(err) != ReasonTooLarge {
			t.Fatalf("a %d byte request that expands to tens of megabytes of records was accepted: %v", len(plain), err)
		}
	})
	t.Run("loki push", func(t *testing.T) {
		build := func(entries int) []byte {
			var values [][]string
			for range entries {
				values = append(values, []string{"1700000000123456789", "x"})
			}
			raw, err := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": wide(), "values": values}}})
			if err != nil {
				t.Fatal(err)
			}
			return raw
		}
		if _, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(build(12)), cfg); err != nil {
			t.Fatalf("a push within the budget was refused: %v", err)
		}
		body := build(600)
		if _, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), cfg); reasonOf(err) != ReasonTooLarge {
			t.Fatalf("a %d byte push that expands to tens of megabytes of records was accepted: %v", len(body), err)
		}
	})
}

// ---- F06: symbol-table reuse ----

// A v2 symbol can be referenced any number of times. Every reference must share
// the symbol's string: converting the bytes again per reference multiplies the
// request's memory by the reference count (here 30x for a 48 KB request).
func TestHostileSymbolReuseMemory(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	s := newHSSyms()
	big := s.ref(strings.Repeat("v", 2000))
	var series [][]byte
	for i := range 300 {
		refs := []uint64{s.ref("__name__"), s.ref(fmt.Sprintf("hs_sym_%03d", i))}
		for j := range 30 {
			refs = append(refs, s.ref(fmt.Sprintf("l%02d", j)), big)
		}
		var ts hsPB
		ts.bytes(1, hsPacked(refs...))
		hsSample(&ts, 0x3ff0000000000000, hsTS)
		series = append(series, ts.b)
	}
	plain := s.request(series...)
	retained := hsRetained(func() any {
		b, err := hsDecodeRW(f, RemoteWriteV2, plain, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return b
	})
	if retained > 6<<20 {
		t.Fatalf("a %d byte request retains %d bytes of decoded records (every reference of the 2000 byte symbol was copied)", len(plain), retained)
	}
}

// ---- F07: structured-metadata field list ----

// The field list comes from a request header and was rebuilt into two maps for
// every record: a header of thousands of names turns every log line into
// thousands of map insertions.
func TestHostileLokiMetadataFieldList(t *testing.T) {
	f := newFixture(t)
	body := lokiBodyNoMetadata("alpha")
	decode := func(n int) error {
		cfg := f.profile()
		fields := []string{"tenant"}
		for i := 1; i < n; i++ {
			fields = append(fields, fmt.Sprintf("f%d", i))
		}
		cfg.Loki.MetadataFields = fields
		_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), cfg)
		return err
	}
	if err := decode(64); err != nil {
		t.Fatalf("64 declared metadata fields refused: %v", err)
	}
	for _, n := range []int{65, 5000} {
		if err := decode(n); reasonOf(err) != ReasonProfile {
			t.Errorf("%d declared metadata fields accepted or mis-typed: %v", n, err)
		}
	}
}

// ---- F08: OpenMetrics duplicate label names ----

func TestHostileOpenMetricsDuplicateLabelHiddenByEmptyValue(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	decode := func(line string) error {
		_, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader("# TYPE x gauge\n"+line+"\n# EOF\n"), cfg)
		return err
	}
	for _, line := range []string{
		`x{a="1",a=""} 1 1700000000`,
		`x{a="",a="1"} 1 1700000000`,
		`x{a="",a=""} 1 1700000000`,
	} {
		if err := decode(line); reasonOf(err) != ReasonDuplicateLabel {
			t.Errorf("%s: a label name that appears twice was accepted: %v", line, err)
		}
	}
	if err := decode(`x{a="",b=""} 1 1700000000`); err != nil {
		t.Errorf("two distinct empty labels are legal and dropped: %v", err)
	}
}

// ---- F09: JSON null is not an empty string ----

func TestHostileLokiJSONNullIsNotAnEmptyString(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	push := func(entry string) error {
		body := `{"streams":[{"stream":{"app":"web","region":"eu"},"values":[` + entry + `]}]}`
		_, err := DecodeLokiPush(f.ctx, f.grant(), strings.NewReader(body), cfg)
		return err
	}
	if err := push(`["1700000000123456789","alpha",{"tenant":"t1"}]`); err != nil {
		t.Fatalf("control entry: %v", err)
	}
	for name, entry := range map[string]string{
		"null line":                `["1700000000123456789",null]`,
		"null structured metadata": `["1700000000123456789","alpha",{"tenant":null}]`,
	} {
		if err := push(entry); reasonOf(err) != ReasonMalformed {
			t.Errorf("%s was coerced to an empty string: %v", name, err)
		}
	}
}

// ---- F10: request identity ----

// A batch identifier names one request: the same bytes under another resource,
// unit or log mapping produce different records, so they must not share the
// identifier (the receipt ledger would answer the second with a conflict, and a
// sender that treats 4xx as final would drop the batch).
func TestHostileRequestIdentityCoversContent(t *testing.T) {
	f := newFixture(t)
	base := f.profile()
	rw := snappyEncode(hsRW(t, `{"version":1,"timeseries":[{"labels":{"__name__":"hs_ident","job":"api"},"samples":[{"bits":"3ff0000000000000","timestamp_ms":"1700000000000"}]}]}`))
	lokiBody := lokiBodyNoMetadata("alpha")
	decodeRW := func(c InputProfile) ([]model.ID, []model.ID) {
		b, err := DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV1, bytes.NewReader(rw), c)
		if err != nil {
			t.Fatal(err)
		}
		return identitiesOf(b)
	}
	decodeLoki := func(c InputProfile) ([]model.ID, []model.ID) {
		b, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(lokiBody), c)
		if err != nil {
			t.Fatal(err)
		}
		return identitiesOf(b)
	}
	sameBatches, sameRecords := decodeRW(base)
	again, againRecords := decodeRW(base)
	if !reflect.DeepEqual(sameBatches, again) || !reflect.DeepEqual(sameRecords, againRecords) {
		t.Fatal("the identical request changed identifiers")
	}
	distinct := func(name string, a, b []model.ID) {
		t.Helper()
		if reflect.DeepEqual(a, b) {
			t.Errorf("%s: two different requests share identifiers %v", name, a)
		}
	}
	other := base
	other.Resource.Instance = "inst-2"
	b, r := decodeRW(other)
	distinct("resource instance (batch)", sameBatches, b)
	distinct("resource instance (record)", sameRecords, r)
	other = base
	other.Resource.Service = model.ID{0xee, 1}
	b, r = decodeRW(other)
	distinct("resource service (batch)", sameBatches, b)
	distinct("resource service (record)", sameRecords, r)
	other = base
	other.DefaultUnit = "s"
	b, r = decodeRW(other)
	distinct("default unit (batch)", sameBatches, b)
	distinct("default unit (record)", sameRecords, r)

	lokiBatches, lokiRecords := decodeLoki(base)
	for name, mutate := range map[string]func(*InputProfile){
		"template":        func(p *InputProfile) { p.Loki.TemplateID = "migrated.line" },
		"template rev":    func(p *InputProfile) { p.Loki.TemplateRevision = 2 },
		"line field":      func(p *InputProfile) { p.Loki.LineField = "msg" },
		"metadata fields": func(p *InputProfile) { p.Loki.MetadataFields = nil },
	} {
		other = base
		mutate(&other)
		b, r = decodeLoki(other)
		distinct("loki "+name+" (batch)", lokiBatches, b)
		distinct("loki "+name+" (record)", lokiRecords, r)
	}
}

// ---- F11: OpenMetrics descriptor maps ----

// Families and _created lines are kept in maps that only the body size bounded.
func TestHostileOpenMetricsFamilyAndCreatedCaps(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	cfg.Limits.MaxSeries = 5
	var sb strings.Builder
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&sb, "# TYPE f%d gauge\n", i)
	}
	sb.WriteString("f6 1 1700000000\n# EOF\n")
	if _, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(sb.String()), cfg); reasonOf(err) != ReasonLimit {
		t.Errorf("six declared families with a series limit of five: %v", err)
	}
	sb.Reset()
	sb.WriteString("# TYPE c counter\nc_total{l=\"1\"} 1 1700000000\n")
	for i := 1; i <= 6; i++ {
		fmt.Fprintf(&sb, "c_created{l=\"%d\"} 1699999000\n", i)
	}
	sb.WriteString("# EOF\n")
	if _, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(sb.String()), cfg); reasonOf(err) != ReasonLimit {
		t.Errorf("six created timestamps with a series limit of five: %v", err)
	}
}

// ---- F12: cancellation granularity ----

// hsGapCtx never cancels; it records the allocation counter every time the
// decoder asks whether it should stop.
type hsGapCtx struct {
	context.Context
	marks []uint64
}

func (c *hsGapCtx) Err() error {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	c.marks = append(c.marks, ms.Mallocs)
	return nil
}

// A client that disconnects must stop costing CPU promptly. The per-record
// phases of a decode (record construction, normalization, batching) each have
// to ask the context; the work between two questions stays bounded.
func TestHostileCancellationGranularity(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	const points = 20000
	var sm []map[string]string
	for i := range points {
		sm = append(sm, map[string]string{"bits": "3ff0000000000000", "timestamp_ms": strconv.Itoa(hsTS + i)})
	}
	raw, err := json.Marshal(map[string]any{"version": 1, "timeseries": []any{map[string]any{"labels": map[string]string{"__name__": "hs_gap", "job": "api"}, "samples": sm}}})
	if err != nil {
		t.Fatal(err)
	}
	body := snappyEncode(hsRW(t, string(raw)))
	grant := f.grant()
	gc := &hsGapCtx{Context: f.ctx}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	batches, err := DecodeRemoteWrite(gc, grant, RemoteWriteV1, bytes.NewReader(body), cfg)
	runtime.ReadMemStats(&after)
	if err != nil || len(batches) == 0 {
		t.Fatalf("decode: %d batches, %v", len(batches), err)
	}
	marks := append([]uint64{before.Mallocs}, gc.marks...)
	marks = append(marks, after.Mallocs)
	var maxGap uint64
	for i := 1; i < len(marks); i++ {
		if g := marks[i] - marks[i-1]; g > maxGap {
			maxGap = g
		}
	}
	if maxGap > 600_000 {
		t.Fatalf("%d allocations between two cancellation checks (%d checks for %d records); a cancelled request keeps burning CPU", maxGap, len(gc.marks), points)
	}
}

// ---- F13: batch size budget versus admission-time growth ----

// Admission renders the template into every log record (a second copy of the
// line), so a batch that fits the 4 MiB limit before admission can exceed it
// after. The split must leave room, or a valid push of 4 KiB lines is refused
// with 413 after earlier children were admitted.
func TestHostileLogBatchGrowth(t *testing.T) {
	f := newFixture(t)
	rawSource, rawOwner := model.NewID(), model.NewID()
	f.command("create_user", auth.AdminPayload{ID: rawOwner, Email: "raw-growth@example.test", Password: "raw growth password long 2026"})
	f.command("membership", auth.AdminPayload{UserID: rawOwner, Enabled: true})
	rawConfig, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Restricted: true, Readers: []model.ID{rawOwner}, Enabled: true})
	f.command("source_policy", auth.AdminPayload{ID: rawSource, Config: rawConfig})
	rawPolicy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log},
		Templates: []model.LogTemplate{{ID: "raw.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{{Name: "line", Type: "string", MaxBytes: 4096, Sensitivity: "restricted_raw"}}}},
		Resources: model.ResourceRegistry{Services: []model.ID{f.resource.Service}, Environments: []model.ID{f.resource.Environment}, Builds: []model.ID{f.resource.Build}, Instances: []string{f.resource.Instance}},
		Labels:    map[string][]string{"app": {"web"}, "region": {"eu"}}, RetentionDays: map[model.Kind]uint32{model.Log: 7},
		MaxBytes: 64 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()),
		RawOwner: &rawOwner, RawRationale: "batch growth test", RawMaxBytes: 4096,
	}
	cred := f.onboard(rawSource, rawPolicy)
	grant, err := f.ps.ResolveSource(f.ctx, cred, f.project, rawSource, 1)
	if err != nil {
		t.Fatal(err)
	}
	cfg := f.profile()
	cfg.Source = rawSource
	cfg.Loki = LokiMapping{Encoding: EncodingJSON, TemplateID: "raw.line", TemplateRevision: 1, LineField: "line"}
	line := strings.Repeat("a", 4096)
	var values [][]string
	for i := range 512 {
		values = append(values, []string{strconv.Itoa(1_700_000_000_123_456_789 + i), line})
	}
	body, err := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"app": "web", "region": "eu"}, "values": values}}})
	if err != nil {
		t.Fatal(err)
	}
	batches, err := DecodeLokiPush(f.ctx, grant, bytes.NewReader(body), cfg)
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	for i, b := range batches {
		records += len(b.Records)
		if _, err := policy.Normalize(grant, b); err != nil {
			t.Errorf("batch %d (%d records) fits the decoder's budget but admission refuses it: %v", i, len(b.Records), err)
		}
	}
	if records != 512 {
		t.Fatalf("%d records decoded, want 512", records)
	}
}
