// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Tables of hostile wire inputs, one expectation per guard: the exact typed
// reason (and, where the detail is a stable part of the contract, the detail)
// of the refusal. Every row is a request a sender can really put on the wire;
// none of them may panic, none may be admitted, and the refusal never carries
// input content.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/model"
)

type hsRow struct {
	name   string
	body   []byte
	cfg    func(*InputProfile)
	reason Reason // "" = must decode
	detail string // "" = not asserted
}

func (r hsRow) check(t *testing.T, f *fixture, decode func(InputProfile, []byte) ([]model.Batch, error)) {
	t.Helper()
	cfg := f.profile()
	if r.cfg != nil {
		r.cfg(&cfg)
	}
	batches, err := decode(cfg, r.body)
	if r.reason == "" {
		if err != nil || len(batches) == 0 {
			t.Fatalf("a valid request failed: %d batches, %v", len(batches), err)
		}
		return
	}
	got, detail := detailOf(err)
	if got != r.reason || (r.detail != "" && detail != r.detail) {
		t.Fatalf("got reason %q detail %q (err %v, %d batches), want reason %q detail %q", got, detail, err, len(batches), r.reason, r.detail)
	}
	if len(batches) != 0 {
		t.Fatalf("a refused request returned %d batches", len(batches))
	}
}

func hsPackedZ(vals ...int64) []byte {
	var b []byte
	for _, v := range vals {
		b = binary.AppendUvarint(b, hsZZ(v))
	}
	return b
}

// ---- remote write v1 ----

func hsV1Labels(ts *hsPB, labels ...[2]string) {
	for _, l := range labels {
		ts.msg(1, func(m *hsPB) {
			m.bytes(1, []byte(l[0]))
			m.bytes(2, []byte(l[1]))
		})
	}
}

func hsV1Req(series ...func(ts *hsPB)) []byte {
	var w hsPB
	for _, s := range series {
		w.msg(1, s)
	}
	return w.b
}

func hsV1One(labels ...[2]string) func(ts *hsPB) {
	return func(ts *hsPB) {
		hsV1Labels(ts, labels...)
		hsSample(ts, 0x3ff0000000000000, hsTS)
	}
}

func TestHostileRemoteWriteV1Table(t *testing.T) {
	f := newFixture(t)
	name := [2]string{"__name__", "hs_table"}
	one := hsV1One(name)
	raw := func(tag func(*hsPB), tail ...byte) []byte {
		var w hsPB
		tag(&w)
		w.b = append(w.b, tail...)
		return w.b
	}
	cfgSmall := func(mut func(*Limits)) func(*InputProfile) { return func(p *InputProfile) { mut(&p.Limits) } }

	rows := []hsRow{
		{name: "control: one sample", body: hsV1Req(one)},
		{name: "empty request", body: nil, reason: ReasonMalformed, detail: "empty_request"},
		{name: "unknown WriteRequest field", body: raw(func(w *hsPB) { w.varint(2, 7) }), reason: ReasonUnrepresentable, detail: "write_request_field"},
		{name: "timeseries as a varint", body: raw(func(w *hsPB) { w.varint(1, 7) }), reason: ReasonUnrepresentable, detail: "write_request_field"},
		{name: "truncated tag varint", body: []byte{0x80}, reason: ReasonMalformed, detail: "wire"},
		{name: "field number zero", body: []byte{0x00, 0x01}, reason: ReasonMalformed, detail: "wire"},
		{name: "fixed32 wire type", body: raw(func(w *hsPB) { w.tag(1, 5) }, 0, 0, 0, 0), reason: ReasonUnrepresentable, detail: "wire_type"},
		{name: "start-group wire type", body: raw(func(w *hsPB) { w.tag(1, 3) }), reason: ReasonUnrepresentable, detail: "wire_type"},
		{name: "length beyond the buffer", body: []byte{0x0a, 0x7f, 'a'}, reason: ReasonMalformed, detail: "wire"},
		{name: "length 2^63", body: raw(func(w *hsPB) { w.tag(1, 2) }, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01), reason: ReasonMalformed, detail: "wire"},
		{name: "eleven byte varint", body: bytes.Repeat([]byte{0xff}, 11), reason: ReasonMalformed, detail: "wire"},
		{name: "sample without a timestamp", body: hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, name)
			ts.msg(2, func(m *hsPB) { m.fixed64(1, 0x3ff0000000000000) })
		}), reason: ReasonTimestampRange, detail: "sample"},
		{name: "millisecond timestamp past int64 nanoseconds", body: hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, name)
			hsSample(ts, 0x3ff0000000000000, 9_223_372_036_855)
		}), reason: ReasonTimestampRange, detail: "sample"},
		{name: "negative timestamp", body: hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, name)
			ts.msg(2, func(m *hsPB) {
				m.fixed64(1, 0x3ff0000000000000)
				m.varint(2, math.MaxUint64)
			})
		}), reason: ReasonTimestampRange, detail: "sample"},
		{name: "sample field of an unknown number", body: hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, name)
			ts.msg(2, func(m *hsPB) { m.varint(9, 1) })
		}), reason: ReasonUnrepresentable, detail: "sample_field"},
		{name: "label name above the byte limit", body: hsV1Req(hsV1One(name, [2]string{strings.Repeat("a", 257), "v"})), reason: ReasonLimit, detail: "label_name"},
		{name: "label value above the byte limit", body: hsV1Req(hsV1One(name, [2]string{"job", strings.Repeat("v", 2049)})), reason: ReasonLimit, detail: "label_value"},
		{name: "label value that is not UTF-8", body: hsV1Req(hsV1One(name, [2]string{"job", "\xff"})), reason: ReasonMalformed, detail: "label_value_utf8"},
		{name: "label name that is not UTF-8", body: hsV1Req(hsV1One(name, [2]string{"j\xffb", "v"})), reason: ReasonMalformed, detail: "label_name_utf8"},
		{name: "66 labels", body: hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, name)
			for i := range 65 {
				hsV1Labels(ts, [2]string{fmt.Sprintf("l%02d", i), "v"})
			}
			hsSample(ts, 0x3ff0000000000000, hsTS)
		}), reason: ReasonLimit, detail: "label_count"},
		{name: "empty label value", body: hsV1Req(hsV1One(name, [2]string{"job", ""})), reason: ReasonMalformed, detail: "empty_label_value"},
		{name: "no __name__", body: hsV1Req(hsV1One([2]string{"job", "api"})), reason: ReasonInvalidName, detail: "metric_name"},
		{name: "two __name__", body: hsV1Req(hsV1One(name, [2]string{"__name__", "other"})), reason: ReasonInvalidName, detail: "metric_name"},
		{name: "metric name starting with a digit", body: hsV1Req(hsV1One([2]string{"__name__", "9bad"})), reason: ReasonInvalidName, detail: "metric_name"},
		{name: "label name with a dash", body: hsV1Req(hsV1One(name, [2]string{"a-b", "v"})), reason: ReasonInvalidName, detail: "label_name"},
		{name: "label named job twice", body: hsV1Req(hsV1One(name, [2]string{"job", "a"}, [2]string{"job", "b"})), reason: ReasonDuplicateLabel},
		{name: "series without samples", body: hsV1Req(func(ts *hsPB) { hsV1Labels(ts, name) }), reason: ReasonMalformed, detail: "empty_series"},
		{name: "three series with a limit of two", body: hsV1Req(one, one, one), cfg: cfgSmall(func(l *Limits) { l.MaxSeries = 2 }), reason: ReasonLimit, detail: "series"},
		{name: "four samples with a limit of three", body: hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, name)
			for i := range 4 {
				hsSample(ts, 0x3ff0000000000000, hsTS+int64(i))
			}
		}), cfg: cfgSmall(func(l *Limits) { l.MaxSamples = 3 }), reason: ReasonLimit, detail: "samples"},
		{name: "wire body above the compressed limit", body: hsV1Req(one), cfg: cfgSmall(func(l *Limits) { l.MaxCompressedBytes = 8 }), reason: ReasonTooLarge, detail: "body"},
		{name: "metadata help above 4096 bytes", body: append(hsV1Req(one), func() []byte {
			var w hsPB
			w.msg(3, func(m *hsPB) {
				m.bytes(2, []byte("hs_table"))
				m.bytes(4, bytes.Repeat([]byte("h"), 4097))
			})
			return w.b
		}()...), reason: ReasonLimit, detail: "metadata_help"},
		{name: "metadata type out of range for its series", body: append(hsV1Req(one), func() []byte {
			var w hsPB
			w.msg(3, func(m *hsPB) {
				m.varint(1, 99)
				m.bytes(2, []byte("hs_table"))
			})
			return w.b
		}()...), reason: ReasonUnrepresentable, detail: "metric_type"},
		{name: "conflicting metadata for one family", body: append(hsV1Req(one), func() []byte {
			var w hsPB
			w.msg(3, func(m *hsPB) { m.varint(1, 1); m.bytes(2, []byte("hs_table")) })
			w.msg(3, func(m *hsPB) { m.varint(1, 2); m.bytes(2, []byte("hs_table")) })
			return w.b
		}()...), reason: ReasonConflict, detail: "metadata"},
		{name: "metadata without a family", body: func() []byte {
			var w hsPB
			w.msg(3, func(m *hsPB) { m.varint(1, 1) })
			return w.b
		}(), reason: ReasonMalformed, detail: "metadata_family"},
		{name: "metadata field of an unknown number", body: func() []byte {
			var w hsPB
			w.msg(3, func(m *hsPB) { m.bytes(2, []byte("x")); m.varint(3, 1) })
			return w.b
		}(), reason: ReasonUnrepresentable, detail: "metadata_field"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, plain []byte) ([]model.Batch, error) {
				return hsDecodeRW(f, RemoteWriteV1, plain, cfg)
			})
		})
	}
}

// ---- native histograms (remote write v1 encoding) ----

func TestHostileNativeHistogramTable(t *testing.T) {
	f := newFixture(t)
	bits := math.Float64bits
	hist := func(parts ...func(*hsPB)) []byte {
		return hsV1Req(func(ts *hsPB) {
			hsV1Labels(ts, [2]string{"__name__", "hs_hist"})
			var h hsPB
			for _, p := range parts {
				p(&h)
			}
			h.varint(15, hsTS)
			ts.bytes(4, h.b)
		})
	}
	cnt := func(n uint64) func(*hsPB) { return func(h *hsPB) { h.varint(1, n) } }
	fcnt := func(v float64) func(*hsPB) { return func(h *hsPB) { h.fixed64(2, bits(v)) } }
	sum := func(h *hsPB) { h.fixed64(3, bits(1)) }
	schema := func(s int64) func(*hsPB) { return func(h *hsPB) { h.varint(4, hsZZ(s)) } }
	zeroThreshold := func(v uint64) func(*hsPB) { return func(h *hsPB) { h.fixed64(5, v) } }
	pspan := func(off int64, n uint64) func(*hsPB) {
		return func(h *hsPB) {
			h.msg(11, func(s *hsPB) {
				s.varint(1, hsZZ(off))
				s.varint(2, n)
			})
		}
	}
	pdeltas := func(d ...int64) func(*hsPB) { return func(h *hsPB) { h.bytes(12, hsPackedZ(d...)) } }
	pcounts := func(v ...uint64) func(*hsPB) {
		return func(h *hsPB) {
			var b []byte
			for _, x := range v {
				b = binary.LittleEndian.AppendUint64(b, x)
			}
			h.bytes(13, b)
		}
	}
	reset := func(v uint64) func(*hsPB) { return func(h *hsPB) { h.varint(14, v) } }
	valid := []func(*hsPB){cnt(3), sum, schema(0), pspan(0, 2), pdeltas(2, -1)}
	with := func(extra ...func(*hsPB)) []byte { return hist(append(append([]func(*hsPB){}, valid...), extra...)...) }
	small := func(buckets int) func(*InputProfile) {
		return func(p *InputProfile) { p.Limits.MaxBuckets = buckets }
	}
	rows := []hsRow{
		{name: "control: integer histogram", body: with()},
		{name: "control: float histogram", body: hist(fcnt(3), sum, schema(0), pspan(0, 2), pcounts(bits(2), bits(1)))},
		{name: "negative bucket count through a delta", body: hist(cnt(3), sum, schema(0), pspan(0, 2), pdeltas(1, -2)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "span length above the bucket count", body: hist(cnt(3), sum, schema(0), pspan(0, 3), pdeltas(2, -1)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "span length below the bucket count", body: hist(cnt(3), sum, schema(0), pspan(0, 1), pdeltas(2, -1)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "schema 9", body: hist(cnt(3), sum, schema(9), pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "schema"},
		{name: "schema -5", body: hist(cnt(3), sum, schema(-5), pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "schema"},
		{name: "schema -52", body: hist(cnt(3), sum, schema(-52), pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "schema"},
		{name: "schema above int32", body: hist(cnt(3), sum, func(h *hsPB) { h.varint(4, hsZZ(1<<31)) }, pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "schema"},
		{name: "count below the bucket total", body: hist(cnt(1), sum, schema(0), pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "integer and float count", body: with(fcnt(3)), reason: ReasonMalformed, detail: "histogram_count"},
		{name: "no count", body: hist(sum, schema(0), pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "histogram_count"},
		{name: "float count with integer deltas", body: hist(fcnt(3), sum, schema(0), pspan(0, 2), pdeltas(2, -1)), reason: ReasonMalformed, detail: "histogram_representation"},
		{name: "integer count with float buckets", body: hist(cnt(3), sum, schema(0), pspan(0, 2), pcounts(bits(2), bits(1))), reason: ReasonMalformed, detail: "histogram_representation"},
		{name: "reset hint 4", body: with(reset(4)), reason: ReasonMalformed, detail: "reset_hint"},
		{name: "zero threshold NaN", body: with(zeroThreshold(0x7ff8000000000001)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "zero threshold negative", body: with(zeroThreshold(bits(-1))), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "zero threshold infinite", body: with(zeroThreshold(bits(math.Inf(1)))), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "schema given twice", body: with(schema(0)), reason: ReasonMalformed, detail: "histogram_repeated_field"},
		{name: "unknown histogram field 18", body: with(func(h *hsPB) { h.varint(18, 1) }), reason: ReasonUnrepresentable, detail: "histogram_field"},
		{name: "custom values in v1", body: with(func(h *hsPB) { h.bytes(16, make([]byte, 8)) }), reason: ReasonUnrepresentable, detail: "custom_buckets_in_v1"},
		{name: "packed deltas with a truncated varint", body: hist(cnt(3), sum, schema(0), pspan(0, 2), func(h *hsPB) { h.bytes(12, []byte{0x80}) }), reason: ReasonMalformed, detail: "packed_varint"},
		{name: "packed doubles of seven bytes", body: hist(fcnt(3), sum, schema(0), pspan(0, 1), func(h *hsPB) { h.bytes(13, make([]byte, 7)) }), reason: ReasonMalformed, detail: "packed_double"},
		{name: "float bucket NaN", body: hist(fcnt(3), sum, schema(0), pspan(0, 1), pcounts(0x7ff8000000000001)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "float buckets above the count", body: hist(fcnt(1), sum, schema(0), pspan(0, 1), pcounts(bits(2))), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "float count NaN", body: hist(func(h *hsPB) { h.fixed64(2, 0x7ff8000000000001) }, sum, schema(0)), reason: ReasonMalformed, detail: "histogram_shape"},
		{name: "five deltas with a limit of four", body: hist(cnt(5), sum, schema(0), pspan(0, 5), pdeltas(1, 0, 0, 0, 0)), cfg: small(4), reason: ReasonLimit, detail: "histogram_buckets"},
		{name: "three spans with a limit of two", body: hist(cnt(3), sum, schema(0), pspan(0, 1), pspan(1, 1), pspan(1, 1), pdeltas(1, 0, 0)), cfg: small(2), reason: ReasonLimit, detail: "histogram_spans"},
		{name: "span offset below int32", body: hist(cnt(3), sum, schema(0), func(h *hsPB) {
			h.msg(11, func(s *hsPB) {
				s.varint(1, hsZZ(-1<<31-1))
				s.varint(2, 2)
			})
		}, pdeltas(2, -1)), reason: ReasonMalformed, detail: "span_offset"},
		{name: "span length above uint32", body: hist(cnt(3), sum, schema(0), func(h *hsPB) {
			h.msg(11, func(s *hsPB) {
				s.varint(1, 0)
				s.varint(2, 1<<32)
			})
		}, pdeltas(2, -1)), reason: ReasonMalformed, detail: "span_length"},
		{name: "span field of an unknown number", body: with(func(h *hsPB) { h.msg(11, func(s *hsPB) { s.varint(3, 1) }) }), reason: ReasonUnrepresentable, detail: "span_field"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, plain []byte) ([]model.Batch, error) {
				return hsDecodeRW(f, RemoteWriteV1, plain, cfg)
			})
		})
	}
	t.Run("a stale histogram marker becomes a stale float sample", func(t *testing.T) {
		stale := hist(cnt(0), func(h *hsPB) { h.fixed64(3, 0x7ff0000000000002) }, schema(0))
		b, err := hsDecodeRW(f, RemoteWriteV1, stale, f.profile())
		if err != nil || len(b) != 1 {
			t.Fatalf("%v", err)
		}
		m := b[0].Records[0].Payload.Metric
		if m.SampleKind != "stale" || m.Value == nil || uint64(*m.Value) != 0x7ff0000000000002 || m.Histogram != nil {
			t.Fatalf("stale marker decoded as %+v", m)
		}
	})
	t.Run("NaN and infinity bits survive in histogram sums and float samples", func(t *testing.T) {
		for _, v := range []uint64{0x7ff8000000000123, 0x7ff0000000000000, 0xfff0000000000000, 0x8000000000000000, 0x7ff0000000000001} {
			body := hsV1Req(func(ts *hsPB) {
				hsV1Labels(ts, [2]string{"__name__", "hs_bits"})
				hsSample(ts, v, hsTS)
			})
			b, err := hsDecodeRW(f, RemoteWriteV1, body, f.profile())
			if err != nil {
				t.Fatalf("%x: %v", v, err)
			}
			if got := uint64(*b[0].Records[0].Payload.Metric.Value); got != v {
				t.Fatalf("bits %x came back as %x", v, got)
			}
		}
	})
}

// ---- remote write v2 symbol table ----

func TestHostileRemoteWriteV2Table(t *testing.T) {
	f := newFixture(t)
	series := func(s *hsSyms, labels ...string) func(ts *hsPB) {
		return func(ts *hsPB) {
			var refs []uint64
			for _, l := range labels {
				refs = append(refs, s.ref(l))
			}
			ts.bytes(1, hsPacked(refs...))
			hsSample(ts, 0x3ff0000000000000, hsTS)
		}
	}
	traceLink := func(p *InputProfile) { p.Exemplars = ExemplarsTraceLink }
	exemplar := func(refs func(s *hsSyms) []byte) func(s *hsSyms, ts *hsPB) {
		return func(s *hsSyms, ts *hsPB) {
			ts.msg(4, func(m *hsPB) {
				m.bytes(1, refs(s))
				m.fixed64(2, 0x3ff0000000000000)
				m.varint(3, hsTS)
			})
		}
	}
	build := func(mut func(s *hsSyms, ts *hsPB)) []byte {
		s := newHSSyms()
		var ts hsPB
		series(s, "__name__", "hs_v2")(&ts)
		if mut != nil {
			mut(s, &ts)
		}
		return s.request(ts.b)
	}
	rows := []hsRow{
		{name: "control", body: build(nil)},
		{name: "series without any symbols", body: func() []byte {
			var w hsPB
			w.bytes(5, []byte{})
			return w.b
		}(), reason: ReasonMalformed, detail: "symbols_prefix"},
		{name: "first symbol not empty", body: func() []byte {
			var w hsPB
			w.bytes(4, []byte("x"))
			w.bytes(5, []byte{})
			return w.b
		}(), reason: ReasonMalformed, detail: "symbols_prefix"},
		{name: "reference outside the table", body: build(func(s *hsSyms, ts *hsPB) { ts.bytes(1, hsPacked(s.ref("job"), 9999)) }), reason: ReasonMalformed, detail: "symbol_ref"},
		{name: "odd reference count", body: build(func(s *hsSyms, ts *hsPB) { ts.bytes(1, hsPacked(s.ref("job"))) }), reason: ReasonMalformed, detail: "symbol_ref_pairs"},
		{name: "reference above uint32", body: build(func(s *hsSyms, ts *hsPB) { ts.bytes(1, hsPacked(s.ref("job"), 1<<33)) }), reason: ReasonMalformed, detail: "symbol_ref"},
		{name: "reserved timeseries field 6", body: build(func(s *hsSyms, ts *hsPB) { ts.varint(6, 1) }), reason: ReasonUnrepresentable, detail: "timeseries_field"},
		{name: "request field of an unknown number", body: func() []byte {
			var w hsPB
			w.varint(2, 1)
			return w.b
		}(), reason: ReasonUnrepresentable, detail: "request_field"},
		{name: "label name symbol above the byte limit", body: build(func(s *hsSyms, ts *hsPB) {
			ts.bytes(1, hsPacked(s.ref(strings.Repeat("a", 257)), s.ref("v")))
		}), reason: ReasonLimit, detail: "label_name"},
		{name: "label value symbol that is not UTF-8", body: build(func(s *hsSyms, ts *hsPB) {
			ts.bytes(1, hsPacked(s.ref("job"), s.ref("\xff")))
		}), reason: ReasonMalformed, detail: "label_value_utf8"},
		{name: "label value that is the empty symbol", body: build(func(s *hsSyms, ts *hsPB) { ts.bytes(1, hsPacked(s.ref("job"), 0)) }), reason: ReasonMalformed, detail: "empty_label_value"},
		{name: "more symbols than the limits can address", body: build(func(s *hsSyms, ts *hsPB) {
			for i := range 8 {
				s.ref(fmt.Sprintf("unused%d", i))
			}
		}), cfg: func(p *InputProfile) { p.Limits.MaxSeries, p.Limits.MaxLabels = 1, 1 }, reason: ReasonLimit, detail: "symbols"},
		{name: "metadata help reference outside the table", body: build(func(s *hsSyms, ts *hsPB) {
			ts.msg(5, func(m *hsPB) { m.varint(3, 9999) })
		}), reason: ReasonMalformed, detail: "symbol_ref"},
		{name: "metadata type 99", body: build(func(s *hsSyms, ts *hsPB) {
			ts.msg(5, func(m *hsPB) { m.varint(1, 99) })
		}), reason: ReasonUnrepresentable, detail: "metric_type"},
		{name: "metadata given twice", body: build(func(s *hsSyms, ts *hsPB) {
			ts.msg(5, func(m *hsPB) { m.varint(1, 1) })
			ts.msg(5, func(m *hsPB) { m.varint(1, 1) })
		}), reason: ReasonMalformed, detail: "timeseries_metadata"},
		{name: "metadata help above 4096 bytes", body: build(func(s *hsSyms, ts *hsPB) {
			ts.msg(5, func(m *hsPB) { m.varint(3, s.ref(strings.Repeat("h", 4097))) })
		}), reason: ReasonLimit, detail: "metadata_help"},
		{name: "gauge histogram metadata on a float series", body: build(func(s *hsSyms, ts *hsPB) {
			ts.msg(5, func(m *hsPB) { m.varint(1, 4) })
		}), reason: ReasonUnrepresentable, detail: "gauge_histogram_float_series"},
		{name: "control: exemplar", body: build(exemplar(func(s *hsSyms) []byte {
			return hsPacked(s.ref("trace_id"), s.ref("0af7651916cd43dd8448eb211c80319c"))
		})), cfg: traceLink},
		{name: "exemplar label value that is not UTF-8", body: build(exemplar(func(s *hsSyms) []byte {
			return hsPacked(s.ref("trace_id"), s.ref("\xff"))
		})), cfg: traceLink, reason: ReasonMalformed, detail: "exemplar_label_value_utf8"},
		{name: "exemplar label name above the byte limit", body: build(exemplar(func(s *hsSyms) []byte {
			return hsPacked(s.ref(strings.Repeat("a", 257)), s.ref("v"))
		})), cfg: traceLink, reason: ReasonLimit, detail: "exemplar_label_name"},
		{name: "exemplar label value above the byte limit", body: build(exemplar(func(s *hsSyms) []byte {
			return hsPacked(s.ref("trace_id"), s.ref(strings.Repeat("v", 2049)))
		})), cfg: traceLink, reason: ReasonLimit, detail: "exemplar_label_value"},
		{name: "exemplar with an odd reference count", body: build(exemplar(func(s *hsSyms) []byte {
			return hsPacked(s.ref("trace_id"))
		})), cfg: traceLink, reason: ReasonMalformed, detail: "symbol_ref_pairs"},
		{name: "exemplar reference outside the table", body: build(exemplar(func(s *hsSyms) []byte {
			return hsPacked(s.ref("trace_id"), 9999)
		})), cfg: traceLink, reason: ReasonMalformed, detail: "symbol_ref"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, plain []byte) ([]model.Batch, error) {
				return hsDecodeRW(f, RemoteWriteV2, plain, cfg)
			})
		})
	}
}

// ---- OpenMetrics ----

func TestHostileOpenMetricsTable(t *testing.T) {
	f := newFixture(t)
	const hdr = "# TYPE x gauge\n"
	om := func(body string) []byte { return []byte(body) }
	limits := func(mut func(*Limits)) func(*InputProfile) { return func(p *InputProfile) { mut(&p.Limits) } }
	traceLink := func(p *InputProfile) { p.Exemplars = ExemplarsTraceLink }
	utf8Names := func(p *InputProfile) { p.Names = NamesUTF8 }
	const trace = "0af7651916cd43dd8448eb211c80319c"
	rows := []hsRow{
		{name: "control", body: om(hdr + "x 1 1700000000\n# EOF\n")},
		{name: "byte order mark", body: om("\ufeff" + hdr + "x 1 1700000000\n# EOF\n"), reason: ReasonInvalidName, detail: "metric_name"},
		{name: "NUL byte", body: om(hdr + "x\x00 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "control_character"},
		{name: "carriage return", body: om("# TYPE x gauge\r\nx 1 1700000000\r\n# EOF\r\n"), reason: ReasonMalformed, detail: "control_character"},
		{name: "invalid UTF-8", body: om(hdr + "x{a=\"\xff\"} 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "utf8"},
		{name: "content after EOF", body: om(hdr + "x 1 1700000000\n# EOF\nx 2 1700000001\n"), reason: ReasonMalformed, detail: "content_after_eof"},
		{name: "blank line", body: om(hdr + "\nx 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "blank_line"},
		{name: "no samples", body: om("# EOF\n"), reason: ReasonMalformed, detail: "no_samples"},
		{name: "value above float64", body: om(hdr + "x 1e999 1700000000\n# EOF\n"), reason: ReasonUnrepresentable, detail: "value_out_of_float64_range"},
		{name: "lower case nan", body: om(hdr + "x nan 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "value"},
		{name: "hexadecimal value", body: om(hdr + "x 0x10 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "value"},
		{name: "underscore in a value", body: om(hdr + "x 1_000 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "value"},
		{name: "unsigned Inf", body: om(hdr + "x Inf 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "value"},
		{name: "exponent in a timestamp", body: om(hdr + "x 1 1e9\n# EOF\n"), reason: ReasonMalformed, detail: "timestamp"},
		{name: "sign without digits in a timestamp", body: om(hdr + "x 1 -\n# EOF\n"), reason: ReasonMalformed, detail: "timestamp"},
		{name: "timestamp past int64 nanoseconds", body: om(hdr + "x 1 99999999999\n# EOF\n"), reason: ReasonTimestampRange, detail: "timestamp"},
		{name: "timestamp before the bound", body: om(hdr + "x 1 -1\n# EOF\n"), reason: ReasonTimestampRange, detail: "observed_at"},
		{name: "four labels with a limit of two", body: om(hdr + "x{a=\"1\",b=\"2\",c=\"3\",d=\"4\"} 1 1700000000\n# EOF\n"), cfg: limits(func(l *Limits) { l.MaxLabels = 2 }), reason: ReasonLimit, detail: "label_count"},
		{name: "label value above the limit", body: om(hdr + "x{a=\"12345\"} 1 1700000000\n# EOF\n"), cfg: limits(func(l *Limits) { l.MaxLabelValueBytes = 4 }), reason: ReasonLimit, detail: "label_value_bytes"},
		{name: "unknown escape", body: om(hdr + "x{a=\"\\q\"} 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "label_escape"},
		{name: "unterminated label value", body: om(hdr + "x{a=\"1} 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "label_unterminated"},
		{name: "label without a value", body: om(hdr + "x{a} 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "label_syntax"},
		{name: "sample without a value", body: om(hdr + "x{a=\"1\"}\n# EOF\n"), reason: ReasonMalformed, detail: "missing_value"},
		{name: "line above the maximum", body: om("# HELP x " + strings.Repeat("a", 200000) + "\n# EOF\n"), cfg: func(p *InputProfile) { p.Help = HelpDiscard }, reason: ReasonLimit, detail: "line_bytes"},
		{name: "counter NaN", body: om("# TYPE c counter\nc_total NaN 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "counter_nan"},
		{name: "family declared after its samples", body: om(hdr + "x 1 1700000000\n# TYPE x counter\n# EOF\n"), reason: ReasonMalformed, detail: "family_redeclared"},
		{name: "interleaved families", body: om("# TYPE a gauge\na 1 1700000000\n# TYPE b gauge\nb 1 1700000000\na 2 1700000001\n# EOF\n"), reason: ReasonMalformed, detail: "interleaved_family"},
		{name: "exemplar on a gauge", body: om(hdr + "x 1 1700000000 # {trace_id=\"" + trace + "\"} 1\n# EOF\n"), cfg: traceLink, reason: ReasonMalformed, detail: "exemplar_placement"},
		{name: "exemplar labels above 128 runes", body: om("# TYPE c counter\nc_total 1 1700000000 # {trace_id=\"" + trace + "\",pad=\"" + strings.Repeat("a", 100) + "\"} 1\n# EOF\n"), cfg: traceLink, reason: ReasonMalformed, detail: "exemplar_label_runes"},
		{name: "exemplar trace id of the wrong length", body: om("# TYPE c counter\nc_total 1 1700000000 # {trace_id=\"abc\"} 1\n# EOF\n"), cfg: traceLink, reason: ReasonUnrepresentable, detail: "exemplar_trace_id"},
		{name: "exemplar without a trace id", body: om("# TYPE c counter\nc_total 1 1700000000 # {foo=\"bar\"} 1\n# EOF\n"), cfg: traceLink, reason: ReasonUnrepresentable, detail: "exemplar_without_trace_id"},
		{name: "exemplar with an all-zero trace id", body: om("# TYPE c counter\nc_total 1 1700000000 # {trace_id=\"" + strings.Repeat("0", 32) + "\"} 1\n# EOF\n"), cfg: traceLink, reason: ReasonMalformed, detail: "metric_encoding"},
		{name: "exemplar with an all-zero span id", body: om("# TYPE c counter\nc_total 1 1700000000 # {trace_id=\"" + trace + "\",span_id=\"" + strings.Repeat("0", 16) + "\"} 1\n# EOF\n"), cfg: traceLink, reason: ReasonMalformed, detail: "metric_encoding"},
		{name: "created timestamp given twice", body: om("# TYPE c counter\nc_total 1 1700000000\nc_created 1699999000\nc_created 1699999001\n# EOF\n"), reason: ReasonMalformed, detail: "duplicate_created"},
		{name: "unit with a tab", body: om("# TYPE x gauge\n# UNIT x a\tb\nx 1 1700000000\n# EOF\n"), reason: ReasonMalformed, detail: "unit"},
		{name: "comment without a kind", body: om("# \n# EOF\n"), reason: ReasonMalformed, detail: "comment"},
		{name: "unknown comment kind", body: om("# NOTE x y\n# EOF\n"), reason: ReasonMalformed, detail: "comment"},
		{name: "quoted label name", body: om(hdr + "x{\"a.b\"=\"1\"} 1 1700000000\n# EOF\n"), reason: ReasonUnrepresentable, detail: "quoted_name"},
		{name: "quoted label name under UTF-8 names", body: om(hdr + "x{\"a.b\"=\"1\"} 1 1700000000\n# EOF\n"), cfg: utf8Names, reason: ReasonUnrepresentable, detail: "quoted_name"},
		{name: "quoted metric name in braces", body: om("{\"a.b\"} 1 1700000000\n# EOF\n"), reason: ReasonUnrepresentable, detail: "quoted_name"},
		{name: "quoted metric name in braces under UTF-8 names", body: om("{\"a.b\"} 1 1700000000\n# EOF\n"), cfg: utf8Names, reason: ReasonUnrepresentable, detail: "quoted_name"},
		{name: "quoted metric name before the value under UTF-8 names", body: om("\"a.b\" 1 1700000000\n# EOF\n"), cfg: utf8Names, reason: ReasonUnrepresentable, detail: "quoted_name"},
		{name: "quoted metric name in a descriptor under UTF-8 names", body: om("# TYPE \"a.b\" gauge\n# EOF\n"), cfg: utf8Names, reason: ReasonUnrepresentable, detail: "quoted_name"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, body []byte) ([]model.Batch, error) {
				return DecodeOpenMetrics(f.ctx, f.grant(), bytes.NewReader(body), cfg)
			})
		})
	}
}

// ---- Loki push ----

func hsLokiJSON(streams ...string) []byte {
	return []byte(`{"streams":[` + strings.Join(streams, ",") + `]}`)
}

func hsLokiStream(labels string, entries ...string) string {
	return `{"stream":` + labels + `,"values":[` + strings.Join(entries, ",") + `]}`
}

func TestHostileLokiJSONTable(t *testing.T) {
	f := newFixture(t)
	labels := `{"app":"web","region":"eu"}`
	entry := func(ts, line string) string { return `["` + ts + `","` + line + `"]` }
	const at = "1700000000123456789"
	good := hsLokiStream(labels, entry(at, "alpha"))
	limits := func(mut func(*Limits)) func(*InputProfile) { return func(p *InputProfile) { mut(&p.Limits) } }
	rows := []hsRow{
		{name: "control", body: hsLokiJSON(good)},
		{name: "not JSON", body: []byte("streams"), reason: ReasonMalformed, detail: "json"},
		{name: "top level array", body: []byte(`[]`), reason: ReasonMalformed, detail: "json_shape"},
		{name: "unknown top level field", body: []byte(`{"streams":[],"x":1}`), reason: ReasonMalformed, detail: "json_shape"},
		{name: "unknown stream field", body: hsLokiJSON(`{"stream":` + labels + `,"values":[],"x":1}`), reason: ReasonMalformed, detail: "json_shape"},
		{name: "duplicate key", body: []byte(`{"streams":[],"streams":[]}`), reason: ReasonMalformed, detail: "json"},
		{name: "depth 100", body: []byte(strings.Repeat("[", 100) + strings.Repeat("]", 100)), reason: ReasonMalformed, detail: "json"},
		{name: "invalid UTF-8 in a line", body: []byte(`{"streams":[{"stream":` + labels + `,"values":[["` + at + `","` + "\xff" + `"]]}]}`), reason: ReasonMalformed, detail: "json"},
		{name: "lone surrogate escape", body: []byte(`{"streams":[{"stream":` + labels + `,"values":[["` + at + `","\ud800"]]}]}`), reason: ReasonMalformed, detail: "json"},
		{name: "second document", body: []byte(`{"streams":[]}{}`), reason: ReasonMalformed, detail: "json"},
		{name: "no streams", body: hsLokiJSON(), reason: ReasonMalformed, detail: "empty_request"},
		{name: "two streams with a limit of one", body: hsLokiJSON(good, good), cfg: limits(func(l *Limits) { l.MaxStreams = 1 }), reason: ReasonLimit, detail: "streams"},
		{name: "three entries with a limit of two", body: hsLokiJSON(hsLokiStream(labels, entry(at, "a"), entry(at, "b"), entry(at, "c"))), cfg: limits(func(l *Limits) { l.MaxSamples = 2 }), reason: ReasonLimit, detail: "entries"},
		{name: "entry of one element", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`"]`)), reason: ReasonMalformed, detail: "entry_shape"},
		{name: "entry of four elements", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",{},1]`)), reason: ReasonMalformed, detail: "entry_shape"},
		{name: "entry that is an object", body: hsLokiJSON(hsLokiStream(labels, `{"ts":1}`)), reason: ReasonMalformed, detail: "json_shape"},
		{name: "timestamp as a number", body: hsLokiJSON(hsLokiStream(labels, `[1700000000123456789,"x"]`)), reason: ReasonMalformed, detail: "entry_types"},
		{name: "signed timestamp", body: hsLokiJSON(hsLokiStream(labels, entry("-1", "x"))), reason: ReasonMalformed, detail: "timestamp"},
		{name: "timestamp of 20 digits", body: hsLokiJSON(hsLokiStream(labels, entry("12345678901234567890", "x"))), reason: ReasonMalformed, detail: "timestamp"},
		{name: "timestamp past int64", body: hsLokiJSON(hsLokiStream(labels, entry("9999999999999999999", "x"))), reason: ReasonTimestampRange, detail: "timestamp"},
		{name: "timestamp before the bound", body: hsLokiJSON(hsLokiStream(labels, entry("5", "x"))), reason: ReasonTimestampRange, detail: "entry_timestamp"},
		{name: "empty stream labels", body: hsLokiJSON(hsLokiStream(`{}`, entry(at, "x"))), reason: ReasonMalformed, detail: "stream_labels"},
		{name: "empty stream label value", body: hsLokiJSON(hsLokiStream(`{"app":""}`, entry(at, "x"))), reason: ReasonMalformed, detail: "empty_stream_label_value"},
		{name: "stream label name with a space", body: hsLokiJSON(hsLokiStream(`{"a b":"c"}`, entry(at, "x"))), reason: ReasonInvalidName, detail: "label_name"},
		{name: "stream label named __name__", body: hsLokiJSON(hsLokiStream(`{"__name__":"c"}`, entry(at, "x"))), reason: ReasonInvalidName, detail: "label_name"},
		{name: "three stream labels with a limit of two", body: hsLokiJSON(hsLokiStream(`{"a":"1","b":"2","c":"3"}`, entry(at, "x"))), cfg: limits(func(l *Limits) { l.MaxLabels = 2 }), reason: ReasonLimit, detail: "label_count"},
		{name: "line of 4097 bytes", body: hsLokiJSON(hsLokiStream(labels, entry(at, strings.Repeat("a", 4097)))), reason: ReasonTooLarge, detail: "line_bytes"},
		{name: "structured metadata value of 4097 bytes", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",{"tenant":"`+strings.Repeat("t", 4097)+`"}]`)), reason: ReasonTooLarge, detail: "structured_metadata_bytes"},
		{name: "structured metadata key that is not declared", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",{"other":"t"}]`)), reason: ReasonUnrepresentable, detail: "structured_metadata_key"},
		{name: "structured metadata that is not an object", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",["t"]]`)), reason: ReasonMalformed, detail: "structured_metadata"},
		{name: "structured metadata value that is a number", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",{"tenant":1}]`)), reason: ReasonMalformed, detail: "structured_metadata"},
		{name: "structured metadata that is null", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",null]`)), reason: ReasonMalformed, detail: "structured_metadata"},
		{name: "structured metadata value that is null", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`","a",{"tenant":null}]`)), reason: ReasonMalformed, detail: "structured_metadata"},
		{name: "line that is null", body: hsLokiJSON(hsLokiStream(labels, `["`+at+`",null]`)), reason: ReasonMalformed, detail: "entry_types"},
		{name: "timestamp that is null", body: hsLokiJSON(hsLokiStream(labels, `[null,"x"]`)), reason: ReasonMalformed, detail: "entry_types"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, body []byte) ([]model.Batch, error) {
				cfg.Loki.Encoding = EncodingJSON
				return DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), cfg)
			})
		})
	}
	t.Run("gzip with trailing bytes after the member", func(t *testing.T) {
		cfg := f.profile()
		cfg.Loki.Encoding = EncodingJSONGzip
		body := append(gz(hsLokiJSON(good)), 0x01, 0x02, 0x03)
		if _, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), cfg); reasonOf(err) != ReasonCompression {
			t.Fatalf("%v", err)
		}
	})
	t.Run("gzip member followed by a second member", func(t *testing.T) {
		cfg := f.profile()
		cfg.Loki.Encoding = EncodingJSONGzip
		body := append(gz([]byte(`{"streams":[`+good)), gz([]byte(`]}`))...)
		batches, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), cfg)
		if err != nil || len(batches) != 1 {
			t.Fatalf("a multi-member gzip body is one body: %d batches, %v", len(batches), err)
		}
	})
}

func hsLokiEntry(sec uint64, nanos uint64, line string, md ...[2]string) func(*hsPB) {
	return func(e *hsPB) {
		e.msg(1, func(ts *hsPB) {
			ts.varint(1, sec)
			if nanos != 0 {
				ts.varint(2, nanos)
			}
		})
		e.bytes(2, []byte(line))
		for _, m := range md {
			e.msg(3, func(p *hsPB) {
				p.bytes(1, []byte(m[0]))
				p.bytes(2, []byte(m[1]))
			})
		}
	}
}

func hsLokiPush(streams ...func(*hsPB)) []byte {
	var w hsPB
	for _, s := range streams {
		w.msg(1, s)
	}
	return w.b
}

func hsLokiProtoStream(labels string, entries ...func(*hsPB)) func(*hsPB) {
	return func(s *hsPB) {
		s.bytes(1, []byte(labels))
		for _, e := range entries {
			s.msg(2, e)
		}
	}
}

func TestHostileLokiProtobufTable(t *testing.T) {
	f := newFixture(t)
	const labels = `{app="web", region="eu"}`
	ok := hsLokiEntry(1700000000, 123456789, "alpha")
	limits := func(mut func(*Limits)) func(*InputProfile) { return func(p *InputProfile) { mut(&p.Limits) } }
	rows := []hsRow{
		{name: "control", body: hsLokiPush(hsLokiProtoStream(labels, ok))},
		{name: "push request field of an unknown number", body: func() []byte { var w hsPB; w.varint(2, 1); return w.b }(), reason: ReasonUnrepresentable, detail: "push_request_field"},
		{name: "stream labels that are not UTF-8", body: hsLokiPush(hsLokiProtoStream("{app=\"\xff\"}", ok)), reason: ReasonMalformed, detail: "stream_labels_utf8"},
		{name: "stream labels without braces", body: hsLokiPush(hsLokiProtoStream(`app="web"`, ok)), reason: ReasonMalformed, detail: "stream_labels"},
		{name: "stream labels with a repeated name", body: hsLokiPush(hsLokiProtoStream(`{app="web", app="web"}`, ok)), reason: ReasonDuplicateLabel},
		{name: "stream label value without a closing quote", body: hsLokiPush(hsLokiProtoStream(`{app="web}`, ok)), reason: ReasonMalformed, detail: "stream_labels"},
		{name: "stream labels followed by text", body: hsLokiPush(hsLokiProtoStream(`{app="web"} x`, ok)), reason: ReasonMalformed, detail: "stream_labels"},
		{name: "three stream labels with a limit of one", body: hsLokiPush(hsLokiProtoStream(`{a="1", b="2", c="3"}`, ok)), cfg: limits(func(l *Limits) { l.MaxLabels = 1 }), reason: ReasonLimit, detail: "label_count"},
		{name: "stream without a label field", body: hsLokiPush(func(s *hsPB) { s.msg(2, ok) }), reason: ReasonMalformed, detail: "stream_labels"},
		{name: "stream field of an unknown number", body: hsLokiPush(func(s *hsPB) { hsLokiProtoStream(labels, ok)(s); s.varint(4, 1) }), reason: ReasonUnrepresentable, detail: "stream_field"},
		{name: "entry without a timestamp", body: hsLokiPush(hsLokiProtoStream(labels, func(e *hsPB) { e.bytes(2, []byte("alpha")) })), reason: ReasonTimestampRange, detail: "entry_timestamp"},
		{name: "nanoseconds of one second", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(1700000000, 1_000_000_000, "alpha"))), reason: ReasonTimestampRange, detail: "entry_timestamp"},
		{name: "negative seconds", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(math.MaxUint64, 0, "alpha"))), reason: ReasonTimestampRange, detail: "entry_timestamp"},
		{name: "seconds past int64 nanoseconds", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(9_223_372_037, 0, "alpha"))), reason: ReasonTimestampRange, detail: "entry_timestamp"},
		{name: "timestamp field repeated", body: hsLokiPush(hsLokiProtoStream(labels, func(e *hsPB) {
			e.msg(1, func(ts *hsPB) { ts.varint(1, 1700000000); ts.varint(1, 1700000001) })
			e.bytes(2, []byte("alpha"))
		})), reason: ReasonMalformed, detail: "timestamp"},
		{name: "parsed labels field", body: hsLokiPush(hsLokiProtoStream(labels, func(e *hsPB) {
			hsLokiEntry(1700000000, 0, "alpha")(e)
			e.msg(4, func(p *hsPB) { p.bytes(1, []byte("a")) })
		})), reason: ReasonUnrepresentable, detail: "parsed_labels"},
		{name: "structured metadata key given twice", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(1700000000, 0, "alpha", [2]string{"tenant", "t1"}, [2]string{"tenant", "t1"}))), reason: ReasonDuplicateLabel, detail: "structured_metadata"},
		{name: "structured metadata key that is not declared", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(1700000000, 0, "alpha", [2]string{"other", "t1"}))), reason: ReasonUnrepresentable, detail: "structured_metadata_key"},
		{name: "structured metadata pair of an unknown field", body: hsLokiPush(hsLokiProtoStream(labels, func(e *hsPB) {
			hsLokiEntry(1700000000, 0, "alpha")(e)
			e.msg(3, func(p *hsPB) { p.varint(3, 1) })
		})), reason: ReasonMalformed, detail: "label_pair"},
		{name: "line that is not UTF-8", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(1700000000, 0, "\xff"))), reason: ReasonMalformed, detail: "line_utf8"},
		{name: "line of 4097 bytes", body: hsLokiPush(hsLokiProtoStream(labels, hsLokiEntry(1700000000, 0, strings.Repeat("a", 4097)))), reason: ReasonTooLarge, detail: "line_bytes"},
		{name: "two streams with a limit of one", body: hsLokiPush(hsLokiProtoStream(labels, ok), hsLokiProtoStream(labels, ok)), cfg: limits(func(l *Limits) { l.MaxStreams = 1 }), reason: ReasonLimit, detail: "streams"},
		{name: "three entries with a limit of two", body: hsLokiPush(hsLokiProtoStream(labels, ok, ok, ok)), cfg: limits(func(l *Limits) { l.MaxSamples = 2 }), reason: ReasonLimit, detail: "entries"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, plain []byte) ([]model.Batch, error) {
				cfg.Loki.Encoding = EncodingProtobufSnappy
				return DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(snappyEncode(plain)), cfg)
			})
		})
	}
}

// ---- condition webhook ----

func TestHostileConditionsTable(t *testing.T) {
	f := newFixture(t)
	const at = "1700000000000000000"
	ev := func(extra string) string {
		return `{"condition":"c","epoch":"e","event_time_ns":"` + at + `","status":"firing","severity":"info","labels":{}` + extra + `}`
	}
	body := func(events ...string) []byte {
		return []byte(`{"version":1,"events":[` + strings.Join(events, ",") + `]}`)
	}
	links := func(n int) string {
		var l []string
		for i := range n {
			l = append(l, fmt.Sprintf(`"%032x"`, i+1))
		}
		return `,"links":[` + strings.Join(l, ",") + `]`
	}
	rows := []hsRow{
		{name: "control", body: body(ev(""))},
		{name: "three events with a limit of two", body: body(ev(""), ev(""), ev("")), cfg: func(p *InputProfile) { p.Limits.MaxSamples = 2 }, reason: ReasonLimit, detail: "events"},
		{name: "65 links", body: body(ev(links(65))), reason: ReasonLimit, detail: "links"},
		{name: "64 links", body: body(ev(links(64)))},
		{name: "event before the bound", body: body(`{"condition":"c","epoch":"e","event_time_ns":"5","status":"firing","severity":"info","labels":{}}`), reason: ReasonTimestampRange, detail: "event_time_ns"},
		{name: "event time above int64", body: body(`{"condition":"c","epoch":"e","event_time_ns":"9223372036854775808","status":"firing","severity":"info","labels":{}}`), reason: ReasonMalformed, detail: "event_time_ns"},
		{name: "label name with a space", body: body(`{"condition":"c","epoch":"e","event_time_ns":"` + at + `","status":"firing","severity":"info","labels":{"a b":"c"}}`), reason: ReasonInvalidName, detail: "label_name"},
		{name: "condition name of 129 bytes", body: body(`{"condition":"` + strings.Repeat("c", 129) + `","epoch":"e","event_time_ns":"` + at + `","status":"firing","severity":"info","labels":{}}`), reason: ReasonMalformed, detail: "condition"},
		{name: "repeated link", body: body(ev(`,"links":["` + strings.Repeat("a", 32) + `","` + strings.Repeat("a", 32) + `"]`)), reason: ReasonMalformed, detail: "link"},
		{name: "all-zero link", body: body(ev(`,"links":["` + strings.Repeat("0", 32) + `"]`)), reason: ReasonMalformed, detail: "link"},
		{name: "unknown version", body: []byte(`{"version":2,"events":[]}`), reason: ReasonUnrepresentable, detail: "schema_version"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			r.check(t, f, func(cfg InputProfile, b []byte) ([]model.Batch, error) {
				return DecodeConditions(f.ctx, f.grant(), bytes.NewReader(b), cfg)
			})
		})
	}
}
