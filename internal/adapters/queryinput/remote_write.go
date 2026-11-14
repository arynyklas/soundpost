// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// Field numbers follow the published Apache-2.0 prometheus.WriteRequest and
// io.prometheus.write.v2.Request schemas; the decoder below is independently
// authored and imports no upstream module.

// DecodeRemoteWrite decodes one snappy-block-compressed remote-write request into
// per-slot batches. Unknown protobuf fields, unrepresentable kinds and any
// malformed or oversized input are rejected with a typed *Error before any batch
// is returned.
func DecodeRemoteWrite(ctx context.Context, grant policy.SourceGrant, version WireVersion, input io.Reader, cfg InputProfile) ([]ingest.Batch, error) {
	format := fmtRWv1
	switch version {
	case RemoteWriteV1:
	case RemoteWriteV2:
		format = fmtRWv2
	default:
		return nil, fail(fmtRWv1, ReasonProfile, "wire_version")
	}
	if err := cfg.validate(format); err != nil {
		return nil, err
	}
	cfg, err := bind(format, grant, cfg)
	if err != nil {
		return nil, err
	}
	if err := ctxErr(format, ctx); err != nil {
		return nil, err
	}
	body, err := readBounded(format, input, cfg.Limits.MaxCompressedBytes)
	if err != nil {
		return nil, err
	}
	plain, err := snappyDecode(format, body, cfg.Limits.MaxDecodedBytes)
	if err != nil {
		return nil, err
	}
	d := &rwDecoder{ctx: ctx, format: format, v: version, cfg: cfg}
	a := &assembler{format: format, cfg: cfg, request: requestDigest(format, cfg, plain)}
	d.a = a
	if version == RemoteWriteV1 {
		err = d.parseV1(plain)
	} else {
		err = d.parseV2(plain)
	}
	if err != nil {
		return nil, err
	}
	return a.finish(ctx)
}

func readBounded(format string, r io.Reader, max int64) ([]byte, error) {
	if r == nil {
		return nil, fail(format, ReasonMalformed, "no_input")
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fail(format, ReasonMalformed, "read")
	}
	if int64(len(b)) > max {
		return nil, fail(format, ReasonTooLarge, "body")
	}
	return b, nil
}

// ---- snappy block decoder (own implementation of the published block format) ----

func snappyDecode(format string, src []byte, max int64) ([]byte, error) {
	bad := func() error { return fail(format, ReasonCompression, "snappy") }
	dlen, n := binary.Uvarint(src)
	if n <= 0 {
		return nil, bad()
	}
	if dlen > uint64(max) {
		return nil, fail(format, ReasonTooLarge, "decoded_body")
	}
	// A copy element expands at most 64 bytes from 3 input bytes, so a declared
	// length above 22x the input cannot be honest; reject before allocating.
	if dlen > uint64(len(src))*22 {
		return nil, bad()
	}
	src = src[n:]
	dst := make([]byte, dlen)
	d := 0
	for len(src) > 0 {
		tag := src[0]
		src = src[1:]
		var length, offset int
		switch tag & 3 {
		case 0:
			l := int(tag >> 2)
			if l >= 60 {
				extra := l - 59
				if len(src) < extra {
					return nil, bad()
				}
				l = 0
				for i := range extra {
					l |= int(src[i]) << (8 * i)
				}
				src = src[extra:]
			}
			length = l + 1
			if length < 0 || length > len(src) || length > len(dst)-d {
				return nil, bad()
			}
			copy(dst[d:], src[:length])
			d += length
			src = src[length:]
			continue
		case 1:
			if len(src) < 1 {
				return nil, bad()
			}
			length = 4 + int(tag>>2)&7
			offset = int(tag>>5)<<8 | int(src[0])
			src = src[1:]
		case 2:
			if len(src) < 2 {
				return nil, bad()
			}
			length = 1 + int(tag>>2)
			offset = int(binary.LittleEndian.Uint16(src))
			src = src[2:]
		default:
			if len(src) < 4 {
				return nil, bad()
			}
			length = 1 + int(tag>>2)
			o := binary.LittleEndian.Uint32(src)
			if o > uint32(len(dst)) {
				return nil, bad()
			}
			offset = int(o)
			src = src[4:]
		}
		if offset <= 0 || offset > d || length > len(dst)-d {
			return nil, bad()
		}
		for i := range length { // overlapping copies replicate bytes, so copy forward one at a time
			dst[d+i] = dst[d-offset+i]
		}
		d += length
	}
	if d != len(dst) {
		return nil, bad()
	}
	return dst, nil
}

// ---- protobuf wire reader ----

type pbField struct {
	num uint64
	wt  uint8
	v   uint64 // varint or fixed64 value
	b   []byte // length-delimited payload, a subslice of the input
}

var errPB = fail("protobuf", ReasonMalformed, "wire")

func pbWalk(b []byte, fn func(pbField) error) error {
	for len(b) > 0 {
		tag, n := binary.Uvarint(b)
		if n <= 0 {
			return errPB
		}
		b = b[n:]
		f := pbField{num: tag >> 3, wt: uint8(tag & 7)}
		if f.num == 0 || f.num > 1<<29-1 {
			return errPB
		}
		switch f.wt {
		case 0:
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return errPB
			}
			f.v = v
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return errPB
			}
			f.v = binary.LittleEndian.Uint64(b)
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) {
				return errPB
			}
			f.b = b[n : n+int(l)]
			b = b[n+int(l):]
		default: // fixed32, groups: no field of either schema uses them
			return fail("protobuf", ReasonUnrepresentable, "wire_type")
		}
		if err := fn(f); err != nil {
			return err
		}
	}
	return nil
}

func zigzag(v uint64) int64 { return int64(v>>1) ^ -int64(v&1) }

// ---- decoder state ----

type rwDecoder struct {
	ctx      context.Context
	format   string
	v        WireVersion
	cfg      InputProfile
	a        *assembler
	series   int
	points   int
	unusedMD int
}

func (d *rwDecoder) bad(detail string) error { return fail(d.format, ReasonMalformed, detail) }
func (d *rwDecoder) unrep(detail string) error {
	return fail(d.format, ReasonUnrepresentable, detail)
}

func (d *rwDecoder) str(f pbField, max int, what string) (string, error) {
	if f.wt != 2 {
		return "", d.bad(what)
	}
	if len(f.b) > max {
		return "", fail(d.format, ReasonLimit, what)
	}
	if !utf8.Valid(f.b) {
		return "", d.bad(what + "_utf8")
	}
	return string(f.b), nil
}

type rwSample struct {
	bits  uint64
	ts    int64
	start int64
}

type rwExemplar struct {
	labels []model.Label
	ts     int64
}

type rwHist struct {
	countInt, zeroInt     uint64
	countFloat, zeroFloat uint64
	hasCI, hasCF          bool
	hasZI, hasZF          bool
	sum, zeroThreshold    uint64
	schema                int32
	negSpans, posSpans    []model.HistogramSpan
	negDeltas, posDeltas  []int64
	negCounts, posCounts  []uint64
	custom                []uint64
	reset                 uint64
	ts, start             int64
}

type rwSeries struct {
	labels    model.Labels
	samples   []rwSample
	hists     []rwHist
	exemplars []rwExemplar
	hasMeta   bool
	mtype     uint64
	help      string
	unit      string
}

func (d *rwDecoder) tick() error {
	d.points++
	if d.points > d.cfg.Limits.MaxSamples {
		return fail(d.format, ReasonLimit, "samples")
	}
	if d.points&1023 == 0 {
		return ctxErr(d.format, d.ctx)
	}
	return nil
}

func (d *rwDecoder) parseSample(b []byte) (rwSample, error) {
	var s rwSample
	var sv, st, ss bool
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wt == 1 && !sv:
			s.bits, sv = f.v, true
		case f.num == 2 && f.wt == 0 && !st:
			s.ts, st = int64(f.v), true
		case f.num == 3 && f.wt == 0 && !ss && d.v == RemoteWriteV2:
			s.start, ss = int64(f.v), true
		case f.num <= 3:
			return d.bad("sample")
		default:
			return d.unrep("sample_field")
		}
		return nil
	})
	return s, err
}

func (d *rwDecoder) parseLabelV1(b []byte) (model.Label, error) {
	var l model.Label
	var sn, sv bool
	err := pbWalk(b, func(f pbField) error {
		var err error
		switch {
		case f.num == 1 && !sn:
			l.Name, err = d.str(f, d.cfg.Limits.MaxLabelNameBytes, "label_name")
			sn = true
		case f.num == 2 && !sv:
			l.Value, err = d.str(f, d.cfg.Limits.MaxLabelValueBytes, "label_value")
			sv = true
		case f.num <= 2:
			return d.bad("label")
		default:
			return d.unrep("label_field")
		}
		return err
	})
	return l, err
}

func (d *rwDecoder) parseExemplarV1(b []byte) (rwExemplar, error) {
	var e rwExemplar
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wt == 2:
			if len(e.labels) >= d.cfg.Limits.MaxLabels {
				return fail(d.format, ReasonLimit, "exemplar_labels")
			}
			l, err := d.parseLabelV1(f.b)
			e.labels = append(e.labels, l)
			return err
		case f.num == 2 && f.wt == 1: // exemplar value is discarded by the profile (see ExemplarMode)
		case f.num == 3 && f.wt == 0:
			e.ts = int64(f.v)
		case f.num <= 3:
			return d.bad("exemplar")
		default:
			return d.unrep("exemplar_field")
		}
		return nil
	})
	return e, err
}

func (d *rwDecoder) parseExemplarV2(b []byte, symbols [][]byte) (rwExemplar, error) {
	var e rwExemplar
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1:
			refs, err := d.refs(f)
			if err != nil {
				return err
			}
			if len(e.labels)*2+len(refs) > 2*d.cfg.Limits.MaxLabels {
				return fail(d.format, ReasonLimit, "exemplar_labels")
			}
			for i := 0; i+1 < len(refs); i += 2 {
				if refs[i] >= uint64(len(symbols)) || refs[i+1] >= uint64(len(symbols)) {
					return d.bad("symbol_ref")
				}
				n, v := symbols[refs[i]], symbols[refs[i+1]]
				if len(n) > d.cfg.Limits.MaxLabelNameBytes || len(v) > d.cfg.Limits.MaxLabelValueBytes {
					return fail(d.format, ReasonLimit, "exemplar_label_bytes")
				}
				e.labels = append(e.labels, model.Label{Name: string(n), Value: string(v)})
			}
		case f.num == 2 && f.wt == 1:
		case f.num == 3 && f.wt == 0:
			e.ts = int64(f.v)
		case f.num <= 3:
			return d.bad("exemplar")
		default:
			return d.unrep("exemplar_field")
		}
		return nil
	})
	return e, err
}

// refs decodes a repeated uint32 field, packed or not, bounded by the label limit.
func (d *rwDecoder) refs(f pbField) ([]uint64, error) {
	limit := 2*d.cfg.Limits.MaxLabels + 2
	var out []uint64
	switch f.wt {
	case 0:
		return []uint64{f.v}, nil
	case 2:
		b := f.b
		for len(b) > 0 {
			v, n := binary.Uvarint(b)
			if n <= 0 || v > 1<<32-1 {
				return nil, d.bad("symbol_ref")
			}
			if len(out) >= limit {
				return nil, fail(d.format, ReasonLimit, "label_count")
			}
			out = append(out, v)
			b = b[n:]
		}
		if len(out)%2 != 0 {
			return nil, d.bad("symbol_ref_pairs")
		}
		return out, nil
	}
	return nil, d.bad("symbol_ref")
}

func (d *rwDecoder) parseSpan(b []byte) (model.HistogramSpan, error) {
	var s model.HistogramSpan
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wt == 0:
			o := zigzag(f.v)
			if o < -1<<31 || o > 1<<31-1 {
				return d.bad("span_offset")
			}
			s.Offset = int32(o)
		case f.num == 2 && f.wt == 0:
			if f.v > 1<<32-1 {
				return d.bad("span_length")
			}
			s.Length = uint32(f.v)
		case f.num <= 2:
			return d.bad("span")
		default:
			return d.unrep("span_field")
		}
		return nil
	})
	return s, err
}

// packed accumulates a repeated scalar field in packed or unpacked form, capping
// the total element count at the histogram bucket limit before any append.
func (d *rwDecoder) packedVarint(f pbField, dst *[]int64) error {
	max := d.cfg.Limits.MaxBuckets
	switch f.wt {
	case 0:
		if len(*dst) >= max {
			return fail(d.format, ReasonLimit, "histogram_buckets")
		}
		*dst = append(*dst, zigzag(f.v))
	case 2:
		b := f.b
		for len(b) > 0 {
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return d.bad("packed_varint")
			}
			if len(*dst) >= max {
				return fail(d.format, ReasonLimit, "histogram_buckets")
			}
			*dst = append(*dst, zigzag(v))
			b = b[n:]
		}
	default:
		return d.bad("packed_varint")
	}
	return nil
}

func (d *rwDecoder) packedDouble(f pbField, dst *[]uint64) error {
	max := d.cfg.Limits.MaxBuckets
	switch f.wt {
	case 1:
		if len(*dst) >= max {
			return fail(d.format, ReasonLimit, "histogram_buckets")
		}
		*dst = append(*dst, f.v)
	case 2:
		if len(f.b)%8 != 0 {
			return d.bad("packed_double")
		}
		if len(*dst)+len(f.b)/8 > max {
			return fail(d.format, ReasonLimit, "histogram_buckets")
		}
		for b := f.b; len(b) > 0; b = b[8:] {
			*dst = append(*dst, binary.LittleEndian.Uint64(b))
		}
	default:
		return d.bad("packed_double")
	}
	return nil
}

func (d *rwDecoder) parseHistogram(b []byte) (rwHist, error) {
	var h rwHist
	var seen [18]bool
	once := func(f pbField) error {
		if f.num < uint64(len(seen)) {
			if seen[f.num] && f.num != 8 && f.num != 9 && f.num != 10 && f.num != 11 && f.num != 12 && f.num != 13 && f.num != 16 {
				return d.bad("histogram_repeated_field")
			}
			seen[f.num] = true
		}
		return nil
	}
	err := pbWalk(b, func(f pbField) error {
		if err := once(f); err != nil {
			return err
		}
		switch {
		case f.num == 1 && f.wt == 0:
			h.countInt, h.hasCI = f.v, true
		case f.num == 2 && f.wt == 1:
			h.countFloat, h.hasCF = f.v, true
		case f.num == 3 && f.wt == 1:
			h.sum = f.v
		case f.num == 4 && f.wt == 0:
			s := zigzag(f.v)
			if s < -1<<31 || s > 1<<31-1 {
				return d.bad("schema")
			}
			h.schema = int32(s)
		case f.num == 5 && f.wt == 1:
			h.zeroThreshold = f.v
		case f.num == 6 && f.wt == 0:
			h.zeroInt, h.hasZI = f.v, true
		case f.num == 7 && f.wt == 1:
			h.zeroFloat, h.hasZF = f.v, true
		case (f.num == 8 || f.num == 11) && f.wt == 2:
			spans := &h.negSpans
			if f.num == 11 {
				spans = &h.posSpans
			}
			if len(*spans) >= d.cfg.Limits.MaxBuckets {
				return fail(d.format, ReasonLimit, "histogram_spans")
			}
			s, err := d.parseSpan(f.b)
			*spans = append(*spans, s)
			return err
		case f.num == 9:
			return d.packedVarint(f, &h.negDeltas)
		case f.num == 12:
			return d.packedVarint(f, &h.posDeltas)
		case f.num == 10:
			return d.packedDouble(f, &h.negCounts)
		case f.num == 13:
			return d.packedDouble(f, &h.posCounts)
		case f.num == 14 && f.wt == 0:
			h.reset = f.v
		case f.num == 15 && f.wt == 0:
			h.ts = int64(f.v)
		case f.num == 16:
			if d.v == RemoteWriteV1 {
				return d.unrep("custom_buckets_in_v1")
			}
			return d.packedDouble(f, &h.custom)
		case f.num == 17 && f.wt == 0 && d.v == RemoteWriteV2:
			h.start = int64(f.v)
		case f.num <= 17 && f.num != 0:
			return d.bad("histogram")
		default:
			return d.unrep("histogram_field")
		}
		return nil
	})
	return h, err
}

// ---- v1 ----

func (d *rwDecoder) parseV1(b []byte) error {
	var rawSeries, rawMeta [][]byte
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wt == 2:
			if len(rawSeries) >= d.cfg.Limits.MaxSeries {
				return fail(d.format, ReasonLimit, "series")
			}
			rawSeries = append(rawSeries, f.b)
		case f.num == 3 && f.wt == 2:
			if len(rawMeta) >= d.cfg.Limits.MaxSeries {
				return fail(d.format, ReasonLimit, "metadata")
			}
			rawMeta = append(rawMeta, f.b)
		default:
			return d.unrep("write_request_field")
		}
		return nil
	})
	if err != nil {
		return err
	}
	type meta struct {
		typ        uint64
		help, unit string
		used       bool
	}
	metadata := map[string]*meta{}
	for _, raw := range rawMeta {
		m := &meta{}
		var family string
		var sf, sy bool
		err := pbWalk(raw, func(f pbField) error {
			var err error
			switch {
			case f.num == 1 && f.wt == 0 && !sy:
				m.typ, sy = f.v, true
			case f.num == 2 && !sf:
				family, err = d.str(f, 1024, "metadata_family")
				sf = true
			case f.num == 4:
				m.help, err = d.str(f, 4096, "metadata_help")
			case f.num == 5:
				m.unit, err = d.str(f, 64, "metadata_unit")
			default:
				return d.unrep("metadata_field")
			}
			return err
		})
		if err != nil {
			return err
		}
		if family == "" {
			return d.bad("metadata_family")
		}
		if prev, ok := metadata[family]; ok && (prev.typ != m.typ || prev.help != m.help || prev.unit != m.unit) {
			return fail(d.format, ReasonConflict, "metadata")
		}
		metadata[family] = m
	}
	for _, raw := range rawSeries {
		s, err := d.parseSeriesV1(raw)
		if err != nil {
			return err
		}
		name, rest := splitName(s.labels)
		if m := lookupMeta(metadata, name); m != nil {
			s.hasMeta, s.mtype, s.help, s.unit = true, m.typ, m.help, m.unit
			m.used = true
		}
		if err := d.emitSeries(name, rest, s); err != nil {
			return err
		}
	}
	for _, m := range metadata {
		if !m.used {
			d.a.report.add(ReportMetadataUnused, 1)
		}
	}
	return nil
}

func lookupMeta[T any](m map[string]*T, name string) *T {
	if v, ok := m[name]; ok {
		return v
	}
	for _, suffix := range []string{"_bucket", "_count", "_sum", "_total", "_created"} {
		if len(name) > len(suffix) && name[len(name)-len(suffix):] == suffix {
			if v, ok := m[name[:len(name)-len(suffix)]]; ok {
				return v
			}
		}
	}
	return nil
}

func (d *rwDecoder) parseSeriesV1(b []byte) (rwSeries, error) {
	var s rwSeries
	err := pbWalk(b, func(f pbField) error {
		if f.wt != 2 {
			return d.bad("timeseries")
		}
		switch f.num {
		case 1:
			if len(s.labels) > d.cfg.Limits.MaxLabels {
				return fail(d.format, ReasonLimit, "label_count")
			}
			l, err := d.parseLabelV1(f.b)
			s.labels = append(s.labels, l)
			return err
		case 2:
			if err := d.tick(); err != nil {
				return err
			}
			sm, err := d.parseSample(f.b)
			s.samples = append(s.samples, sm)
			return err
		case 3:
			if len(s.exemplars) >= d.cfg.Limits.MaxBuckets {
				return fail(d.format, ReasonLimit, "exemplars")
			}
			e, err := d.parseExemplarV1(f.b)
			s.exemplars = append(s.exemplars, e)
			return err
		case 4:
			if err := d.tick(); err != nil {
				return err
			}
			h, err := d.parseHistogram(f.b)
			s.hists = append(s.hists, h)
			return err
		}
		return d.unrep("timeseries_field")
	})
	return s, err
}

// ---- v2 ----

func (d *rwDecoder) parseV2(b []byte) error {
	var symbols, rawSeries [][]byte
	maxSymbols := d.cfg.Limits.MaxSeries*(2*d.cfg.Limits.MaxLabels+2) + 1
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 4 && f.wt == 2:
			if len(symbols) >= maxSymbols {
				return fail(d.format, ReasonLimit, "symbols")
			}
			symbols = append(symbols, f.b)
		case f.num == 5 && f.wt == 2:
			if len(rawSeries) >= d.cfg.Limits.MaxSeries {
				return fail(d.format, ReasonLimit, "series")
			}
			rawSeries = append(rawSeries, f.b)
		default:
			return d.unrep("request_field")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(rawSeries) > 0 && (len(symbols) == 0 || len(symbols[0]) != 0) {
		return d.bad("symbols_prefix")
	}
	for _, raw := range rawSeries {
		s, err := d.parseSeriesV2(raw, symbols)
		if err != nil {
			return err
		}
		name, rest := splitName(s.labels)
		if err := d.emitSeries(name, rest, s); err != nil {
			return err
		}
	}
	return nil
}

func (d *rwDecoder) parseSeriesV2(b []byte, symbols [][]byte) (rwSeries, error) {
	var s rwSeries
	var haveMeta bool
	sym := func(ref uint64, max int, what string) (string, error) {
		if ref >= uint64(len(symbols)) {
			return "", d.bad("symbol_ref")
		}
		if len(symbols[ref]) > max {
			return "", fail(d.format, ReasonLimit, what)
		}
		if !utf8.Valid(symbols[ref]) {
			return "", d.bad(what + "_utf8")
		}
		return string(symbols[ref]), nil
	}
	err := pbWalk(b, func(f pbField) error {
		switch f.num {
		case 1:
			refs, err := d.refs(f)
			if err != nil {
				return err
			}
			if len(s.labels)+len(refs)/2 > d.cfg.Limits.MaxLabels+1 {
				return fail(d.format, ReasonLimit, "label_count")
			}
			for i := 0; i+1 < len(refs); i += 2 {
				n, err := sym(refs[i], d.cfg.Limits.MaxLabelNameBytes, "label_name")
				if err != nil {
					return err
				}
				v, err := sym(refs[i+1], d.cfg.Limits.MaxLabelValueBytes, "label_value")
				if err != nil {
					return err
				}
				s.labels = append(s.labels, model.Label{Name: n, Value: v})
			}
			return nil
		case 2:
			if f.wt != 2 {
				return d.bad("timeseries")
			}
			if err := d.tick(); err != nil {
				return err
			}
			sm, err := d.parseSample(f.b)
			s.samples = append(s.samples, sm)
			return err
		case 3:
			if f.wt != 2 {
				return d.bad("timeseries")
			}
			if err := d.tick(); err != nil {
				return err
			}
			h, err := d.parseHistogram(f.b)
			s.hists = append(s.hists, h)
			return err
		case 4:
			if f.wt != 2 {
				return d.bad("timeseries")
			}
			if len(s.exemplars) >= d.cfg.Limits.MaxBuckets {
				return fail(d.format, ReasonLimit, "exemplars")
			}
			e, err := d.parseExemplarV2(f.b, symbols)
			s.exemplars = append(s.exemplars, e)
			return err
		case 5:
			if f.wt != 2 || haveMeta {
				return d.bad("timeseries_metadata")
			}
			haveMeta = true
			s.hasMeta = true
			return pbWalk(f.b, func(m pbField) error {
				var err error
				switch {
				case m.num == 1 && m.wt == 0:
					s.mtype = m.v
				case m.num == 3 && m.wt == 0:
					s.help, err = sym(m.v, 4096, "metadata_help")
				case m.num == 4 && m.wt == 0:
					s.unit, err = sym(m.v, 64, "metadata_unit")
				default:
					return d.unrep("metadata_field")
				}
				return err
			})
		}
		return d.unrep("timeseries_field") // includes reserved field 6
	})
	return s, err
}

// ---- shared emission ----

func splitName(in model.Labels) (string, model.Labels) {
	name := ""
	rest := make(model.Labels, 0, len(in))
	for _, l := range in {
		if l.Name == "__name__" {
			if name != "" || l.Value == "" {
				return "", nil
			}
			name = l.Value
			continue
		}
		rest = append(rest, l)
	}
	return name, rest
}

type rwPoint struct {
	ms int64
	m  model.MetricPoint
}

func (d *rwDecoder) metricType(s rwSeries, histogram bool) (string, error) {
	if !s.hasMeta {
		if histogram {
			return "histogram", nil
		}
		return "unknown", nil
	}
	// v1 MetricMetadata.MetricType and v2 Metadata.MetricType share these numbers.
	switch s.mtype {
	case 0:
		if histogram {
			return "histogram", nil
		}
		return "unknown", nil
	case 1:
		return "counter", nil
	case 2:
		return "gauge", nil
	case 3:
		return "histogram", nil
	case 4:
		if histogram {
			return "histogram", nil // gauge flavor travels in the histogram itself
		}
		return "", d.unrep("gauge_histogram_float_series")
	case 5:
		d.a.report.add(ReportTypeMappedUnknown, 1)
		return "unknown", nil
	}
	return "", d.unrep("metric_type")
}

func (d *rwDecoder) emitSeries(name string, rest model.Labels, s rwSeries) error {
	if name == "" {
		return fail(d.format, ReasonInvalidName, "metric_name")
	}
	for _, l := range rest {
		if l.Value == "" {
			return d.bad("empty_label_value")
		}
	}
	if len(s.samples) > 0 && len(s.hists) > 0 {
		return d.bad("samples_and_histograms")
	}
	if len(s.samples) == 0 && len(s.hists) == 0 {
		if len(s.exemplars) > 0 {
			return d.unrep("exemplar_only_series")
		}
		return d.bad("empty_series")
	}
	if len(s.exemplars) > 0 && d.cfg.Exemplars == ExemplarsReject {
		return d.unrep("exemplar")
	}
	if len(s.hists) > 0 && d.cfg.Histograms == HistogramsReject {
		return d.unrep("native_histogram")
	}
	d.series++
	labels, err := cleanLabels(d.format, rest, d.cfg, &d.a.report)
	if err != nil {
		return err
	}
	if !validMetricName(name, d.cfg.Names, 1024) {
		return fail(d.format, ReasonInvalidName, "metric_name")
	}
	if s.help != "" {
		if d.cfg.Help == HelpReject {
			return d.unrep("help_text")
		}
		d.a.report.add(ReportHelpDiscarded, 1)
	}
	unit := d.cfg.unit()
	if s.unit != "" {
		if !safeUnit(s.unit) {
			return d.bad("unit")
		}
		unit = s.unit
	}
	typ, err := d.metricType(s, len(s.hists) > 0)
	if err != nil {
		return err
	}
	points := make([]rwPoint, 0, len(s.samples)+len(s.hists))
	base := model.MetricPoint{Name: name, Labels: labels, Unit: unit, Type: typ}
	for _, sm := range s.samples {
		m := base
		bits := model.FloatBits(sm.bits)
		m.Value = &bits
		m.SampleKind = "float"
		if sm.bits == staleBits {
			m.SampleKind = "stale"
		}
		if err := d.start(&m, sm.start); err != nil {
			return err
		}
		points = append(points, rwPoint{sm.ts, m})
	}
	for _, h := range s.hists {
		m := base
		m.Labels = labels
		stale, err := d.histogram(&m, h)
		if err != nil {
			return err
		}
		if stale {
			d.a.report.add(ReportStaleHistogramAsStale, 1)
		}
		if err := d.start(&m, h.start); err != nil {
			return err
		}
		points = append(points, rwPoint{h.ts, m})
	}
	if err := d.attachExemplars(points, s.exemplars); err != nil {
		return err
	}
	for _, p := range points {
		ts, ok := msToNano(p.ms)
		if !ok || !inBounds(d.cfg, ts) {
			return fail(d.format, ReasonTimestampRange, "sample")
		}
		rec, err := newMetricRecord(d.format, p.m, ts, d.cfg)
		if err != nil {
			return err
		}
		d.a.add(rec)
	}
	return nil
}

func (d *rwDecoder) start(m *model.MetricPoint, startMS int64) error {
	if startMS == 0 {
		return nil
	}
	ns, ok := msToNano(startMS)
	if !ok || !inBounds(d.cfg, ns) {
		return fail(d.format, ReasonTimestampRange, "start_timestamp")
	}
	m.StartTimestamp = &ns
	return nil
}

func (d *rwDecoder) attachExemplars(points []rwPoint, ex []rwExemplar) error {
	assigned := make([]bool, len(points))
	for _, e := range ex {
		var trace, span string
		for _, l := range e.labels {
			switch l.Name {
			case "trace_id":
				trace = l.Value
			case "span_id":
				span = l.Value
			}
		}
		if trace == "" {
			return d.unrep("exemplar_without_trace_id")
		}
		tb, err := hex.DecodeString(trace)
		if err != nil || len(tb) != 16 {
			return d.unrep("exemplar_trace_id")
		}
		var sb []byte
		if span != "" {
			sb, err = hex.DecodeString(span)
			if err != nil || len(sb) != 8 {
				return d.unrep("exemplar_span_id")
			}
		}
		idx := -1
		for i := range points {
			if points[i].ms == e.ts {
				if idx >= 0 {
					return d.unrep("exemplar_ambiguous_point")
				}
				idx = i
			}
		}
		if idx < 0 && d.v == RemoteWriteV2 && len(points) == 1 {
			idx = 0
		}
		if idx < 0 {
			return d.unrep("exemplar_without_point")
		}
		if assigned[idx] {
			return d.unrep("multiple_exemplars_per_point")
		}
		assigned[idx] = true
		var id model.ID
		copy(id[:], tb)
		points[idx].m.ExemplarTrace = &id
		if sb != nil {
			var sp model.SpanID
			copy(sp[:], sb)
			points[idx].m.ExemplarSpan = &sp
		}
		d.a.report.add(ReportExemplarDetailDiscarded, 1)
	}
	return nil
}

// histogram converts the wire histogram to the native model and reports whether
// it was a stale marker, which is represented as a stale float sample.
func (d *rwDecoder) histogram(m *model.MetricPoint, h rwHist) (bool, error) {
	if h.hasCI == h.hasCF {
		return false, d.bad("histogram_count")
	}
	if h.hasCI && (h.hasZF || len(h.posCounts) > 0 || len(h.negCounts) > 0) ||
		h.hasCF && (h.hasZI || len(h.posDeltas) > 0 || len(h.negDeltas) > 0) {
		return false, d.bad("histogram_representation")
	}
	var hint, flavor string
	switch h.reset {
	case 0:
		hint, flavor = "unknown", "counter"
	case 1:
		hint, flavor = "reset", "counter"
	case 2:
		hint, flavor = "not_reset", "counter"
	case 3:
		hint, flavor = "gauge", "gauge"
	default:
		return false, d.bad("reset_hint")
	}
	if h.schema < -4 && h.schema != -53 || h.schema > 8 {
		return false, d.bad("schema")
	}
	spans := func(in []model.HistogramSpan) []model.HistogramSpan {
		return append(make([]model.HistogramSpan, 0, len(in)), in...)
	}
	bounds := func(in []uint64) []model.FloatBits {
		out := make([]model.FloatBits, len(in))
		for i, v := range in {
			out[i] = model.FloatBits(v)
		}
		return out
	}
	empty := len(h.posSpans)+len(h.negSpans)+len(h.posDeltas)+len(h.negDeltas)+len(h.posCounts)+len(h.negCounts) == 0
	if h.sum == staleBits && empty && h.zeroThreshold == 0 && h.schema == 0 {
		cnt := h.countInt
		if h.hasCF {
			cnt = h.countFloat
		}
		if cnt == 0 {
			bits := model.FloatBits(staleBits)
			*m = model.MetricPoint{Name: m.Name, Labels: m.Labels, Unit: m.Unit, Type: m.Type, SampleKind: "stale", Value: &bits}
			return true, nil
		}
	}
	var nh model.NativeHistogram
	if h.hasCI {
		ih := &model.IntegerHistogram{
			Flavor: flavor, Schema: h.schema, ZeroThreshold: model.FloatBits(h.zeroThreshold), Sum: model.FloatBits(h.sum),
			Count: model.Uint64(h.countInt), ZeroCount: model.Uint64(h.zeroInt),
			PositiveSpans: spans(h.posSpans), NegativeSpans: spans(h.negSpans),
			PositiveBuckets: make([]model.DeltaBucket, len(h.posDeltas)), NegativeBuckets: make([]model.DeltaBucket, len(h.negDeltas)),
			ResetHint: hint,
		}
		for i, v := range h.posDeltas {
			ih.PositiveBuckets[i] = model.DeltaBucket(v)
		}
		for i, v := range h.negDeltas {
			ih.NegativeBuckets[i] = model.DeltaBucket(v)
		}
		if len(h.custom) > 0 {
			ih.CustomBounds = bounds(h.custom)
		}
		nh.Integer = ih
		m.SampleKind = "integer_histogram"
	} else {
		fh := &model.FloatHistogram{
			Flavor: flavor, Schema: h.schema, ZeroThreshold: model.FloatBits(h.zeroThreshold), Sum: model.FloatBits(h.sum),
			Count: model.FloatBits(h.countFloat), ZeroCount: model.FloatBits(h.zeroFloat),
			PositiveSpans: spans(h.posSpans), NegativeSpans: spans(h.negSpans),
			PositiveBuckets: bounds(h.posCounts), NegativeBuckets: bounds(h.negCounts),
			ResetHint: hint,
		}
		if len(h.custom) > 0 {
			fh.CustomBounds = bounds(h.custom)
		}
		nh.Float = fh
		m.SampleKind = "float_histogram"
	}
	if err := nh.Validate(); err != nil {
		return false, d.bad("histogram_shape")
	}
	m.Histogram = &nh
	m.Value = nil
	return false, nil
}

// newMetricRecord wraps a point into a record whose ID is derived from the series,
// timestamp and exact point content, so a retried request regenerates identical
// IDs and identical duplicates collapse while conflicting ones stay distinct.
func newMetricRecord(format string, m model.MetricPoint, ts model.UnixNano, cfg InputProfile) (model.Record, error) {
	raw, err := model.CanonicalJSON(m)
	if err != nil {
		return model.Record{}, fail(format, ReasonMalformed, "metric_encoding")
	}
	id := deriveID("metric", []byte(seriesKey(m.Name, m.Labels)), u64bytes(uint64(ts)), raw)
	res := cfg.Resource
	if res.Labels == nil {
		res.Labels = model.Labels{}
	}
	return model.Record{ID: id, Kind: model.Metric, ObservedAt: ts, Resource: res, Payload: model.Payload{Metric: &m}}, nil
}
