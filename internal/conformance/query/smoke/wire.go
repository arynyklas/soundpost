// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// The encoders below write the published sender wire formats (Prometheus
// remote-write v1/v2 protobuf under snappy, OpenMetrics text, Loki push JSON,
// the conditions webhook JSON) from authored logical records. They are the
// sender side of the adapter smoke: the decoder under test is the production
// queryinput package, never a copy of it.

type pbw struct{ b []byte }

func (w *pbw) tag(num, wt uint64) { w.b = binary.AppendUvarint(w.b, num<<3|wt) }
func (w *pbw) varint(num, v uint64) {
	w.tag(num, 0)
	w.b = binary.AppendUvarint(w.b, v)
}
func (w *pbw) sint(num uint64, v int64) { w.varint(num, uint64(v<<1)^uint64(v>>63)) }
func (w *pbw) fixed64(num, v uint64) {
	w.tag(num, 1)
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
}
func (w *pbw) bytes(num uint64, p []byte) {
	w.tag(num, 2)
	w.b = binary.AppendUvarint(w.b, uint64(len(p)))
	w.b = append(w.b, p...)
}
func (w *pbw) msg(num uint64, f func(*pbw)) {
	var inner pbw
	f(&inner)
	w.bytes(num, inner.b)
}
func (w *pbw) packedSint(num uint64, vs []int64) {
	if len(vs) == 0 {
		return
	}
	var inner []byte
	for _, v := range vs {
		inner = binary.AppendUvarint(inner, uint64(v<<1)^uint64(v>>63))
	}
	w.bytes(num, inner)
}
func (w *pbw) packedDouble(num uint64, bits []uint64) {
	if len(bits) == 0 {
		return
	}
	var inner []byte
	for _, v := range bits {
		inner = binary.LittleEndian.AppendUint64(inner, v)
	}
	w.bytes(num, inner)
}

// snappyBlock encodes src as a snappy block of literals only (valid by the
// published format description).
func snappyBlock(src []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(src)))
	for len(src) > 0 {
		n := min(len(src), 60000)
		switch {
		case n <= 60:
			out = append(out, byte(n-1)<<2)
		case n <= 256:
			out = append(out, 60<<2, byte(n-1))
		default:
			out = append(out, 61<<2, byte((n-1)&0xff), byte((n-1)>>8))
		}
		out = append(out, src[:n]...)
		src = src[n:]
	}
	return out
}

// wireSample is one logical sample or native histogram of a series.
type wireSample struct {
	TimeMS int64
	Bits   uint64
	Hist   *model.NativeHistogram
}

type wireSeries struct {
	Name    string
	Labels  map[string]string
	Samples []wireSample
}

func sortedLabelNames(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func resetHintCode(h string) uint64 {
	switch h {
	case "reset":
		return 1
	case "not_reset":
		return 2
	case "gauge":
		return 3
	}
	return 0
}

// encodeHistogram writes one prometheus.Histogram / io.prometheus.write.v2
// Histogram message from the native model.
func encodeHistogram(h *model.NativeHistogram, tsMS int64) []byte {
	var w pbw
	spans := func(num uint64, in []model.HistogramSpan) {
		for _, s := range in {
			w.msg(num, func(m *pbw) {
				if s.Offset != 0 {
					m.sint(1, int64(s.Offset))
				}
				m.varint(2, uint64(s.Length))
			})
		}
	}
	bits := func(in []model.FloatBits) []uint64 {
		out := make([]uint64, len(in))
		for i, v := range in {
			out[i] = uint64(v)
		}
		return out
	}
	deltas := func(in []model.DeltaBucket) []int64 {
		out := make([]int64, len(in))
		for i, v := range in {
			out[i] = int64(v)
		}
		return out
	}
	if ih := h.Integer; ih != nil {
		w.varint(1, uint64(ih.Count))
		w.fixed64(3, uint64(ih.Sum))
		w.sint(4, int64(ih.Schema))
		w.fixed64(5, uint64(ih.ZeroThreshold))
		w.varint(6, uint64(ih.ZeroCount))
		spans(8, ih.NegativeSpans)
		w.packedSint(9, deltas(ih.NegativeBuckets))
		spans(11, ih.PositiveSpans)
		w.packedSint(12, deltas(ih.PositiveBuckets))
		w.varint(14, resetHintCode(ih.ResetHint))
		w.varint(15, uint64(tsMS))
		w.packedDouble(16, bits(ih.CustomBounds))
		return w.b
	}
	fh := h.Float
	w.fixed64(2, uint64(fh.Count))
	w.fixed64(3, uint64(fh.Sum))
	w.sint(4, int64(fh.Schema))
	w.fixed64(5, uint64(fh.ZeroThreshold))
	w.fixed64(7, uint64(fh.ZeroCount))
	spans(8, fh.NegativeSpans)
	w.packedDouble(10, bits(fh.NegativeBuckets))
	spans(11, fh.PositiveSpans)
	w.packedDouble(13, bits(fh.PositiveBuckets))
	w.varint(14, resetHintCode(fh.ResetHint))
	w.varint(15, uint64(tsMS))
	w.packedDouble(16, bits(fh.CustomBounds))
	return w.b
}

func rwLabels(s wireSeries) (names []string) {
	names = append(names, "__name__")
	names = append(names, sortedLabelNames(s.Labels)...)
	return names
}

// remoteWriteV1Body is a prometheus.WriteRequest (snappy-framed by the caller).
func remoteWriteV1Body(series []wireSeries) []byte {
	var req pbw
	for _, s := range series {
		req.msg(1, func(ts *pbw) {
			for _, n := range rwLabels(s) {
				v := s.Name
				if n != "__name__" {
					v = s.Labels[n]
				}
				ts.msg(1, func(l *pbw) { l.bytes(1, []byte(n)); l.bytes(2, []byte(v)) })
			}
			for _, sm := range s.Samples {
				if sm.Hist != nil {
					continue
				}
				ts.msg(2, func(m *pbw) { m.fixed64(1, sm.Bits); m.varint(2, uint64(sm.TimeMS)) })
			}
			for _, sm := range s.Samples {
				if sm.Hist != nil {
					ts.bytes(4, encodeHistogram(sm.Hist, sm.TimeMS))
				}
			}
		})
	}
	return req.b
}

// remoteWriteV2Body is an io.prometheus.write.v2.Request.
func remoteWriteV2Body(series []wireSeries) []byte {
	var req pbw
	symbols := []string{""}
	index := map[string]uint64{"": 0}
	sym := func(s string) uint64 {
		if i, ok := index[s]; ok {
			return i
		}
		index[s] = uint64(len(symbols))
		symbols = append(symbols, s)
		return index[s]
	}
	var encoded [][]byte
	for _, s := range series {
		var ts pbw
		var refs []byte
		for _, n := range rwLabels(s) {
			v := s.Name
			if n != "__name__" {
				v = s.Labels[n]
			}
			refs = binary.AppendUvarint(refs, sym(n))
			refs = binary.AppendUvarint(refs, sym(v))
		}
		ts.bytes(1, refs)
		for _, sm := range s.Samples {
			if sm.Hist == nil {
				ts.msg(2, func(m *pbw) { m.fixed64(1, sm.Bits); m.varint(2, uint64(sm.TimeMS)) })
			}
		}
		for _, sm := range s.Samples {
			if sm.Hist != nil {
				ts.bytes(3, encodeHistogram(sm.Hist, sm.TimeMS))
			}
		}
		encoded = append(encoded, ts.b)
	}
	for _, sy := range symbols {
		req.bytes(4, []byte(sy))
	}
	for _, e := range encoded {
		req.bytes(5, e)
	}
	return req.b
}

// openMetricsBody renders float samples as an OpenMetrics text exposition. A
// family named *_total is a counter, anything else a gauge.
func openMetricsBody(series []wireSeries) []byte {
	var b strings.Builder
	families := map[string][]wireSeries{}
	var order []string
	for _, s := range series {
		fam := s.Name
		if strings.HasSuffix(fam, "_total") {
			fam = strings.TrimSuffix(fam, "_total")
		}
		if _, ok := families[fam]; !ok {
			order = append(order, fam)
		}
		families[fam] = append(families[fam], s)
	}
	for _, fam := range order {
		typ := "gauge"
		if families[fam][0].Name != fam {
			typ = "counter"
		}
		fmt.Fprintf(&b, "# TYPE %s %s\n", fam, typ)
		for _, s := range families[fam] {
			var labels []string
			for _, k := range sortedLabelNames(s.Labels) {
				labels = append(labels, k+`="`+s.Labels[k]+`"`)
			}
			for _, sm := range s.Samples {
				fmt.Fprintf(&b, "%s{%s} %s %d.%03d\n", s.Name, strings.Join(labels, ","), openMetricsFloat(math.Float64frombits(sm.Bits)), sm.TimeMS/1000, sm.TimeMS%1000)
			}
		}
	}
	b.WriteString("# EOF\n")
	return []byte(b.String())
}

func openMetricsFloat(f float64) string {
	switch {
	case math.IsInf(f, 1):
		return "+Inf"
	case math.IsInf(f, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

type wireLine struct {
	TimeNS int64
	Line   string
}

type wireStream struct {
	Labels map[string]string
	Lines  []wireLine
}

func lokiPushBody(streams []wireStream) []byte {
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	}
	var req struct {
		Streams []stream `json:"streams"`
	}
	for _, s := range streams {
		out := stream{Stream: s.Labels}
		for _, l := range s.Lines {
			out.Values = append(out.Values, []string{strconv.FormatInt(l.TimeNS, 10), l.Line})
		}
		req.Streams = append(req.Streams, out)
	}
	raw, err := json.Marshal(req)
	check(err)
	return raw
}

type wireCondition struct {
	Condition string
	Epoch     string
	Sequence  uint64
	TimeNS    int64
	Status    string
	Severity  string
	Labels    map[string]string
}

func conditionsBody(events []wireCondition) []byte {
	type event struct {
		Condition string            `json:"condition"`
		Epoch     string            `json:"epoch"`
		Sequence  string            `json:"sequence"`
		EventNS   string            `json:"event_time_ns"`
		Status    string            `json:"status"`
		Severity  string            `json:"severity"`
		Labels    map[string]string `json:"labels"`
		Links     []string          `json:"links"`
	}
	var req struct {
		Version int     `json:"version"`
		Events  []event `json:"events"`
	}
	req.Version = 1
	for _, e := range events {
		labels := e.Labels
		if labels == nil {
			labels = map[string]string{}
		}
		req.Events = append(req.Events, event{Condition: e.Condition, Epoch: e.Epoch, Sequence: strconv.FormatUint(e.Sequence, 10), EventNS: strconv.FormatInt(e.TimeNS, 10), Status: e.Status, Severity: e.Severity, Labels: labels, Links: []string{}})
	}
	raw, err := json.Marshal(req)
	check(err)
	return raw
}
