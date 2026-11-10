// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
	"unicode/utf8"

	"soundpost/internal/ingest"
	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// DecodeLokiPush decodes one Loki push body (JSON, gzip JSON or snappy protobuf,
// per cfg.Loki.Encoding) into per-slot batches. Every entry becomes one log
// record bound to the profile's registered template: the line fills
// cfg.Loki.LineField, stream labels stay stream labels, structured metadata keys
// must be declared in cfg.Loki.MetadataFields. Entries are never deduplicated by
// timestamp or line: each carries an ordinal-derived identity, so a retried
// request regenerates identical IDs and distinct equal-time entries survive.
// Whether a raw line is admitted at all is decided by the source policy when the
// returned batches go through policy.Normalize; the decoder cannot widen it.
func DecodeLokiPush(ctx context.Context, grant policy.SourceGrant, input io.Reader, cfg InputProfile) ([]ingest.Batch, error) {
	const format = fmtLoki
	if err := cfg.validate(format); err != nil {
		return nil, err
	}
	if err := cfg.validateLoki(format); err != nil {
		return nil, err
	}
	cfg, err := bind(format, grant, cfg)
	if err != nil {
		return nil, err
	}
	if err := ctxErr(format, ctx); err != nil {
		return nil, err
	}
	wire, err := readBounded(format, input, cfg.Limits.MaxCompressedBytes)
	if err != nil {
		return nil, err
	}
	var plain []byte
	switch cfg.Loki.Encoding {
	case EncodingJSON:
		if int64(len(wire)) > cfg.Limits.MaxDecodedBytes {
			return nil, fail(format, ReasonTooLarge, "decoded_body")
		}
		plain = wire
	case EncodingJSONGzip:
		zr, err := gzip.NewReader(bytes.NewReader(wire))
		if err != nil {
			return nil, fail(format, ReasonCompression, "gzip")
		}
		plain, err = io.ReadAll(io.LimitReader(zr, cfg.Limits.MaxDecodedBytes+1))
		if err != nil {
			return nil, fail(format, ReasonCompression, "gzip")
		}
		if int64(len(plain)) > cfg.Limits.MaxDecodedBytes {
			return nil, fail(format, ReasonTooLarge, "decoded_body")
		}
	case EncodingProtobufSnappy:
		plain, err = snappyDecode(format, wire, cfg.Limits.MaxDecodedBytes)
		if err != nil {
			return nil, err
		}
	}
	l := &lokiDecoder{ctx: ctx, cfg: cfg, allowed: map[string]bool{}}
	for _, f := range cfg.Loki.MetadataFields {
		l.allowed[f] = true
	}
	l.a = &assembler{format: format, cfg: cfg, request: requestDigest(format+"/"+string(cfg.Loki.Encoding), cfg, plain)}
	if cfg.Loki.Encoding == EncodingProtobufSnappy {
		err = l.parseProto(plain)
	} else {
		err = l.parseJSON(plain)
	}
	if err != nil {
		return nil, err
	}
	return l.a.finish(ctx)
}

type lokiDecoder struct {
	ctx     context.Context
	cfg     InputProfile
	a       *assembler
	allowed map[string]bool
	streams int
	entries int
}

func (l *lokiDecoder) bad(detail string) error { return fail(fmtLoki, ReasonMalformed, detail) }
func (l *lokiDecoder) unrep(detail string) error {
	return fail(fmtLoki, ReasonUnrepresentable, detail)
}

type lokiStreamJSON struct {
	Stream map[string]string   `json:"stream"`
	Values [][]json.RawMessage `json:"values"`
}

func (l *lokiDecoder) parseJSON(body []byte) error {
	if model.ValidateJSON(body) != nil {
		return l.bad("json")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req struct {
		Streams []lokiStreamJSON `json:"streams"`
	}
	if err := dec.Decode(&req); err != nil {
		return l.bad("json_shape")
	}
	if _, err := dec.Token(); err != io.EOF {
		return l.bad("json_trailing")
	}
	if len(req.Streams) > l.cfg.Limits.MaxStreams {
		return fail(fmtLoki, ReasonLimit, "streams")
	}
	for _, s := range req.Streams {
		labels := make(model.Labels, 0, len(s.Stream))
		for k, v := range s.Stream {
			labels = append(labels, model.Label{Name: k, Value: v})
		}
		sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
		if err := l.beginStream(&labels); err != nil {
			return err
		}
		for _, v := range s.Values {
			if len(v) < 2 || len(v) > 3 {
				return l.bad("entry_shape")
			}
			var tsStr, line string
			if json.Unmarshal(v[0], &tsStr) != nil || json.Unmarshal(v[1], &line) != nil {
				return l.bad("entry_types")
			}
			ts, err := l.nanos(tsStr)
			if err != nil {
				return err
			}
			var md []model.Label
			if len(v) == 3 {
				var m map[string]string
				if json.Unmarshal(v[2], &m) != nil {
					return l.bad("structured_metadata")
				}
				for k, val := range m {
					md = append(md, model.Label{Name: k, Value: val})
				}
				sort.Slice(md, func(i, j int) bool { return md[i].Name < md[j].Name })
			}
			if err := l.entry(labels, ts, line, md); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *lokiDecoder) beginStream(labels *model.Labels) error {
	l.streams++
	if l.streams > l.cfg.Limits.MaxStreams {
		return fail(fmtLoki, ReasonLimit, "streams")
	}
	if len(*labels) == 0 {
		return l.bad("stream_labels")
	}
	for _, x := range *labels {
		if x.Value == "" {
			return l.bad("empty_stream_label_value")
		}
	}
	clean, err := cleanLabels(fmtLoki, *labels, l.cfg, &l.a.report)
	if err != nil {
		return err
	}
	*labels = clean
	return nil
}

func (l *lokiDecoder) nanos(s string) (int64, error) {
	if s == "" || len(s) > 19 {
		return 0, l.bad("timestamp")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, l.bad("timestamp")
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fail(fmtLoki, ReasonTimestampRange, "timestamp")
	}
	return v, nil
}

func (l *lokiDecoder) entry(labels model.Labels, ts int64, line string, md []model.Label) error {
	l.entries++
	if l.entries > l.cfg.Limits.MaxSamples {
		return fail(fmtLoki, ReasonLimit, "entries")
	}
	if l.entries&1023 == 0 {
		if err := ctxErr(fmtLoki, l.ctx); err != nil {
			return err
		}
	}
	at := model.UnixNano(ts)
	if !inBounds(l.cfg, at) {
		return fail(fmtLoki, ReasonTimestampRange, "entry_timestamp")
	}
	if !utf8.ValidString(line) {
		return l.bad("line_utf8")
	}
	if len(line) > l.cfg.Limits.MaxLineBytes {
		return fail(fmtLoki, ReasonTooLarge, "line_bytes")
	}
	lineScalar, err := newScalar(line)
	if err != nil {
		return l.bad("line")
	}
	fields := map[string]model.Scalar{l.cfg.Loki.LineField: lineScalar}
	metadata := map[string]model.Scalar{}
	for _, m := range md {
		if !l.allowed[m.Name] {
			return l.unrep("structured_metadata_key")
		}
		if !utf8.ValidString(m.Value) {
			return l.bad("structured_metadata_utf8")
		}
		if len(m.Value) > l.cfg.Limits.MaxLineBytes {
			return fail(fmtLoki, ReasonTooLarge, "structured_metadata_bytes")
		}
		sc, err := newScalar(m.Value)
		if err != nil {
			return l.bad("structured_metadata")
		}
		fields[m.Name] = sc
		metadata[m.Name] = sc
	}
	res := l.cfg.Resource
	if res.Labels == nil {
		res.Labels = model.Labels{}
	}
	l.a.add(model.Record{
		ID:         deriveID("log", l.a.request[:], u64bytes(uint64(l.entries))),
		Kind:       model.Log,
		ObservedAt: at,
		Resource:   res,
		Payload: model.Payload{Log: &model.LogRecord{
			Timestamp:        &at,
			TemplateID:       l.cfg.Loki.TemplateID,
			TemplateRevision: l.cfg.Loki.TemplateRevision,
			Fields:           fields,
			StreamLabels:     labels,
			Metadata:         metadata,
		}},
	})
	return nil
}

func jsonString(s string) ([]byte, error) { return json.Marshal(s) }

// ---- protobuf (logproto.PushRequest) ----

func (l *lokiDecoder) parseProto(b []byte) error {
	var raw [][]byte
	err := pbWalk(b, func(f pbField) error {
		if f.num != 1 || f.wt != 2 {
			return l.unrep("push_request_field")
		}
		if len(raw) >= l.cfg.Limits.MaxStreams {
			return fail(fmtLoki, ReasonLimit, "streams")
		}
		raw = append(raw, f.b)
		return nil
	})
	if err != nil {
		return err
	}
	for _, s := range raw {
		if err := l.parseProtoStream(s); err != nil {
			return err
		}
	}
	return nil
}

func (l *lokiDecoder) parseProtoStream(b []byte) error {
	var labelStr string
	var haveLabels bool
	var entries [][]byte
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wt == 2 && !haveLabels:
			if !utf8.Valid(f.b) {
				return l.bad("stream_labels_utf8")
			}
			labelStr, haveLabels = string(f.b), true
		case f.num == 2 && f.wt == 2:
			if len(entries) >= l.cfg.Limits.MaxSamples {
				return fail(fmtLoki, ReasonLimit, "entries")
			}
			entries = append(entries, f.b)
		case f.num == 3 && f.wt == 0: // stream hash: derived by the sender, carries no data
		default:
			return l.unrep("stream_field")
		}
		return nil
	})
	if err != nil {
		return err
	}
	labels, err := l.parseLabelString(labelStr)
	if err != nil {
		return err
	}
	if err := l.beginStream(&labels); err != nil {
		return err
	}
	for _, e := range entries {
		var ts int64
		var line string
		var md []model.Label
		var haveTS, haveLine bool
		err := pbWalk(e, func(f pbField) error {
			switch {
			case f.num == 1 && f.wt == 2 && !haveTS:
				haveTS = true
				v, err := l.parseTimestamp(f.b)
				ts = v
				return err
			case f.num == 2 && f.wt == 2 && !haveLine:
				haveLine = true
				if len(f.b) > l.cfg.Limits.MaxLineBytes {
					return fail(fmtLoki, ReasonTooLarge, "line_bytes")
				}
				line = string(f.b)
			case f.num == 3 && f.wt == 2:
				if len(md) >= len(l.allowed)+1 {
					return l.unrep("structured_metadata_key")
				}
				var p model.Label
				var sn, sv bool
				err := pbWalk(f.b, func(m pbField) error {
					switch {
					case m.num == 1 && m.wt == 2 && !sn:
						sn = true
						p.Name = string(m.b)
					case m.num == 2 && m.wt == 2 && !sv:
						sv = true
						if len(m.b) > l.cfg.Limits.MaxLineBytes {
							return fail(fmtLoki, ReasonTooLarge, "structured_metadata_bytes")
						}
						p.Value = string(m.b)
					default:
						return l.bad("label_pair")
					}
					return nil
				})
				md = append(md, p)
				return err
			case f.num == 4:
				return l.unrep("parsed_labels")
			default:
				return l.unrep("entry_field")
			}
			return nil
		})
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, m := range md {
			if seen[m.Name] {
				return fail(fmtLoki, ReasonDuplicateLabel, "structured_metadata")
			}
			seen[m.Name] = true
		}
		sort.Slice(md, func(i, j int) bool { return md[i].Name < md[j].Name })
		if err := l.entry(labels, ts, line, md); err != nil {
			return err
		}
	}
	return nil
}

func (l *lokiDecoder) parseTimestamp(b []byte) (int64, error) {
	var sec, nanos int64
	var ss, sn bool
	err := pbWalk(b, func(f pbField) error {
		switch {
		case f.num == 1 && f.wt == 0 && !ss:
			ss, sec = true, int64(f.v)
		case f.num == 2 && f.wt == 0 && !sn:
			sn, nanos = true, int64(f.v)
		default:
			return l.bad("timestamp")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	if nanos < 0 || nanos > 999_999_999 || sec < 0 || sec > (math.MaxInt64-nanos)/1_000_000_000 {
		return 0, fail(fmtLoki, ReasonTimestampRange, "entry_timestamp")
	}
	return sec*1_000_000_000 + nanos, nil
}

// parseLabelString parses `{name="value", ...}` with Go-quoted values.
func (l *lokiDecoder) parseLabelString(s string) (model.Labels, error) {
	var out model.Labels
	i := 0
	skip := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	skip()
	if i >= len(s) || s[i] != '{' {
		return nil, l.bad("stream_labels")
	}
	i++
	skip()
	if i < len(s) && s[i] == '}' {
		i++
		skip()
		if i != len(s) {
			return nil, l.bad("stream_labels")
		}
		return out, nil
	}
	for {
		skip()
		start := i
		for i < len(s) && s[i] != '=' && s[i] != ' ' {
			i++
		}
		name := s[start:i]
		skip()
		if name == "" || i >= len(s) || s[i] != '=' {
			return nil, l.bad("stream_labels")
		}
		i++
		skip()
		q, err := strconv.QuotedPrefix(s[i:])
		if err != nil {
			return nil, l.bad("stream_labels")
		}
		v, err := strconv.Unquote(q)
		if err != nil {
			return nil, l.bad("stream_labels")
		}
		i += len(q)
		if len(out) >= l.cfg.Limits.MaxLabels+1 {
			return nil, fail(fmtLoki, ReasonLimit, "label_count")
		}
		out = append(out, model.Label{Name: name, Value: v})
		skip()
		if i >= len(s) {
			return nil, l.bad("stream_labels")
		}
		if s[i] == '}' {
			i++
			skip()
			if i != len(s) {
				return nil, l.bad("stream_labels")
			}
			return out, nil
		}
		if s[i] != ',' {
			return nil, l.bad("stream_labels")
		}
		i++
	}
}
