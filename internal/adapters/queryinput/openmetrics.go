// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// DecodeOpenMetrics parses one OpenMetrics text exposition (which must end with
// "# EOF") into per-slot batches. Supported: counter, gauge, histogram, summary
// and unknown families, # UNIT, # HELP (per profile), _created start timestamps
// and trace-linked exemplars (per profile). gaugehistogram, info and stateset
// families, quoted UTF-8 names and sub-nanosecond timestamps are rejected as
// unrepresentable; integer sample values that float64 cannot hold exactly are
// rejected rather than rounded.
func DecodeOpenMetrics(ctx context.Context, grant policy.SourceGrant, input io.Reader, cfg InputProfile) ([]ingest.Batch, error) {
	const format = fmtOpenMetrics
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
	body, err := readBounded(format, input, cfg.Limits.MaxDecodedBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(body) {
		return nil, fail(format, ReasonMalformed, "utf8")
	}
	p := &omParser{ctx: ctx, cfg: cfg, fams: map[string]*omFamily{}, created: map[string]int64{}, seen: map[string]bool{}}
	a := &assembler{format: format, cfg: cfg, request: requestDigest(format, cfg, body)}
	p.a = a
	if err := p.parse(body); err != nil {
		return nil, err
	}
	if err := p.emit(); err != nil {
		return nil, err
	}
	return a.finish(ctx)
}

type omFamily struct {
	name    string
	typ     string
	unit    string
	declare bool
}

func (f *omFamily) has(n string) bool {
	switch f.typ {
	case "counter":
		return n == f.name+"_total" || n == f.name+"_created"
	case "histogram":
		return n == f.name+"_bucket" || n == f.name+"_count" || n == f.name+"_sum" || n == f.name+"_created"
	case "summary":
		return n == f.name || n == f.name+"_count" || n == f.name+"_sum" || n == f.name+"_created"
	}
	return n == f.name
}

type omSample struct {
	fam      *omFamily
	name     string
	labels   model.Labels
	bits     uint64
	ts       int64
	trace    *model.ID
	span     *model.SpanID
	hasEx    bool
	startKey string
}

type omParser struct {
	ctx     context.Context
	cfg     InputProfile
	a       *assembler
	fams    map[string]*omFamily
	cur     *omFamily
	samples []omSample
	created map[string]int64 // family\x00labels -> ns
	seen    map[string]bool
	mapped  map[*omFamily]bool
}

func (p *omParser) bad(detail string) error { return fail(fmtOpenMetrics, ReasonMalformed, detail) }
func (p *omParser) unrep(detail string) error {
	return fail(fmtOpenMetrics, ReasonUnrepresentable, detail)
}

func (p *omParser) parse(body []byte) error {
	maxLine := p.cfg.Limits.MaxLabels*(p.cfg.Limits.MaxLabelNameBytes+p.cfg.Limits.MaxLabelValueBytes+8) + 1024
	eof := false
	n := 0
	for len(body) > 0 {
		var line []byte
		if i := bytes.IndexByte(body, '\n'); i >= 0 {
			line, body = body[:i], body[i+1:]
		} else {
			line, body = body, nil
		}
		n++
		if n&1023 == 0 {
			if err := ctxErr(fmtOpenMetrics, p.ctx); err != nil {
				return err
			}
		}
		if eof {
			return p.bad("content_after_eof")
		}
		if len(line) > maxLine {
			return fail(fmtOpenMetrics, ReasonLimit, "line_bytes")
		}
		if bytes.IndexByte(line, '\r') >= 0 || bytes.IndexByte(line, 0) >= 0 {
			return p.bad("control_character")
		}
		if len(line) == 0 {
			return p.bad("blank_line")
		}
		s := string(line)
		if s == "# EOF" {
			eof = true
			continue
		}
		if strings.HasPrefix(s, "#") {
			if err := p.meta(s); err != nil {
				return err
			}
			continue
		}
		if err := p.sample(s); err != nil {
			return err
		}
	}
	if !eof {
		return p.bad("missing_eof")
	}
	return nil
}

func (p *omParser) meta(s string) error {
	parts := strings.SplitN(s, " ", 4)
	if len(parts) < 3 || parts[0] != "#" {
		return p.bad("comment")
	}
	kind, name := parts[1], parts[2]
	rest := ""
	if len(parts) == 4 {
		rest = parts[3]
	}
	switch kind {
	case "TYPE":
		if len(parts) != 4 || !validMetricName(name, p.cfg.Names, 1024) {
			return p.bad("type_line")
		}
		if _, dup := p.fams[name]; dup {
			return p.bad("family_redeclared")
		}
		switch rest {
		case "counter", "gauge", "histogram", "summary", "unknown":
		case "gaugehistogram", "info", "stateset":
			return p.unrep("metric_type_" + rest)
		default:
			return p.bad("metric_type")
		}
		f := &omFamily{name: name, typ: rest, declare: true}
		p.fams[name] = f
		p.cur = f
	case "UNIT":
		if p.cur == nil || p.cur.name != name || len(parts) < 3 {
			return p.bad("unit_line")
		}
		if rest != "" && !safeUnit(rest) {
			return p.bad("unit")
		}
		p.cur.unit = rest
	case "HELP":
		if p.cur == nil || p.cur.name != name {
			return p.bad("help_line")
		}
		if p.cfg.Help == HelpReject {
			return p.unrep("help_text")
		}
		p.a.report.add(ReportHelpDiscarded, 1)
	default:
		return p.bad("comment")
	}
	return nil
}

func (p *omParser) family(name string) (*omFamily, error) {
	if p.cur != nil && p.cur.has(name) {
		return p.cur, nil
	}
	if _, exists := p.fams[name]; exists {
		return nil, p.bad("interleaved_family")
	}
	f := &omFamily{name: name, typ: "unknown"}
	p.fams[name] = f
	p.cur = f
	return f, nil
}

func (p *omParser) sample(s string) error {
	i := 0
	for i < len(s) && s[i] != '{' && s[i] != ' ' {
		i++
	}
	name := s[:i]
	if !validMetricName(name, p.cfg.Names, 1024) {
		return fail(fmtOpenMetrics, ReasonInvalidName, "metric_name")
	}
	var labels model.Labels
	rest := s[i:]
	if strings.HasPrefix(rest, "{") {
		var err error
		labels, rest, err = p.labels(rest[1:])
		if err != nil {
			return err
		}
	}
	if !strings.HasPrefix(rest, " ") {
		return p.bad("missing_value")
	}
	rest = rest[1:]
	valTok, rest := cut(rest)
	bits, err := p.value(valTok)
	if err != nil {
		return err
	}
	var tsTok, exTok string
	hasEx := false
	if rest != "" {
		rest = rest[1:] // cut leaves the separating space in place
		if strings.HasPrefix(rest, "# ") {
			hasEx, exTok = true, rest[2:]
		} else {
			tsTok, rest = cut(rest)
			if rest != "" {
				rest = rest[1:]
				if !strings.HasPrefix(rest, "# ") {
					return p.bad("trailing_content")
				}
				hasEx, exTok = true, rest[2:]
			}
		}
	}
	fam, err := p.family(name)
	if err != nil {
		return err
	}
	// _created lines carry the family start timestamp, not a sample.
	if fam.typ != "unknown" && fam.typ != "gauge" && name == fam.name+"_created" {
		if hasEx {
			return p.bad("exemplar_on_created")
		}
		sec, err := p.seconds(valTok)
		if err != nil {
			return err
		}
		clean, err := cleanLabels(fmtOpenMetrics, withoutBucketLabels(labels), p.cfg, &p.a.report)
		if err != nil {
			return err
		}
		key := fam.name + "\x00" + seriesKey("", clean)
		if _, dup := p.created[key]; dup {
			return p.bad("duplicate_created")
		}
		p.created[key] = sec
		return nil
	}
	if math.IsNaN(math.Float64frombits(bits)) && fam.typ == "counter" {
		return p.bad("counter_nan")
	}
	smp := omSample{fam: fam, name: name, labels: labels, bits: bits}
	if tsTok == "" {
		if p.cfg.DefaultTimestamp == 0 {
			return p.bad("missing_timestamp")
		}
		smp.ts = int64(p.cfg.DefaultTimestamp)
	} else {
		ts, err := p.seconds(tsTok)
		if err != nil {
			return err
		}
		smp.ts = ts
	}
	if hasEx {
		allowed := fam.typ == "counter" && name == fam.name+"_total" || fam.typ == "histogram" && name == fam.name+"_bucket"
		if !allowed {
			return p.bad("exemplar_placement")
		}
		if p.cfg.Exemplars == ExemplarsReject {
			return p.unrep("exemplar")
		}
		if err := p.exemplar(exTok, &smp); err != nil {
			return err
		}
	}
	if len(p.samples) >= p.cfg.Limits.MaxSamples {
		return fail(fmtOpenMetrics, ReasonLimit, "samples")
	}
	if !p.seen[name+"\x00"+labelSig(labels)] {
		if len(p.seen) >= p.cfg.Limits.MaxSeries {
			return fail(fmtOpenMetrics, ReasonLimit, "series")
		}
		p.seen[name+"\x00"+labelSig(labels)] = true
	}
	p.samples = append(p.samples, smp)
	return nil
}

func labelSig(l model.Labels) string {
	var b strings.Builder
	for _, x := range l {
		b.WriteString(x.Name)
		b.WriteByte(0)
		b.WriteString(x.Value)
		b.WriteByte(1)
	}
	return b.String()
}

func withoutBucketLabels(in model.Labels) model.Labels {
	out := make(model.Labels, 0, len(in))
	for _, l := range in {
		if l.Name != "le" && l.Name != "quantile" {
			out = append(out, l)
		}
	}
	return out
}

func cut(s string) (string, string) {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i:]
	}
	return s, ""
}

// labels parses `name="value",...}` and returns the remainder after '}'.
func (p *omParser) labels(s string) (model.Labels, string, error) {
	var out model.Labels
	if strings.HasPrefix(s, "}") {
		return out, s[1:], nil
	}
	for {
		eq := strings.IndexByte(s, '=')
		if eq <= 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			return nil, "", p.bad("label_syntax")
		}
		name := s[:eq]
		var val strings.Builder
		j := eq + 2
		closed := false
		for j < len(s) {
			c := s[j]
			if c == '\\' {
				if j+1 >= len(s) {
					return nil, "", p.bad("label_escape")
				}
				switch s[j+1] {
				case '\\', '"':
					val.WriteByte(s[j+1])
				case 'n':
					val.WriteByte('\n')
				default:
					return nil, "", p.bad("label_escape")
				}
				j += 2
				continue
			}
			if c == '"' {
				closed = true
				j++
				break
			}
			val.WriteByte(c)
			if val.Len() > p.cfg.Limits.MaxLabelValueBytes {
				return nil, "", fail(fmtOpenMetrics, ReasonLimit, "label_value_bytes")
			}
			j++
		}
		if !closed {
			return nil, "", p.bad("label_unterminated")
		}
		if len(out) >= p.cfg.Limits.MaxLabels+1 {
			return nil, "", fail(fmtOpenMetrics, ReasonLimit, "label_count")
		}
		out = append(out, model.Label{Name: name, Value: val.String()})
		if j >= len(s) {
			return nil, "", p.bad("label_unterminated")
		}
		if s[j] == '}' {
			return out, s[j+1:], nil
		}
		if s[j] != ',' {
			return nil, "", p.bad("label_syntax")
		}
		s = s[j+1:]
	}
}

func (p *omParser) exemplar(s string, smp *omSample) error {
	if !strings.HasPrefix(s, "{") {
		return p.bad("exemplar_syntax")
	}
	labels, rest, err := p.labels(s[1:])
	if err != nil {
		return err
	}
	runes := 0
	var trace, span string
	for _, l := range labels {
		runes += utf8.RuneCountInString(l.Name) + utf8.RuneCountInString(l.Value)
		switch l.Name {
		case "trace_id":
			trace = l.Value
		case "span_id":
			span = l.Value
		}
	}
	if runes > 128 {
		return p.bad("exemplar_label_runes")
	}
	if !strings.HasPrefix(rest, " ") {
		return p.bad("exemplar_value")
	}
	valTok, rest := cut(rest[1:])
	if _, err := p.value(valTok); err != nil {
		return err
	}
	if rest != "" {
		tok, more := cut(rest[1:])
		if more != "" {
			return p.bad("exemplar_trailing")
		}
		if _, err := p.seconds(tok); err != nil {
			return err
		}
	}
	if trace == "" {
		return p.unrep("exemplar_without_trace_id")
	}
	tb, err := hex.DecodeString(trace)
	if err != nil || len(tb) != 16 {
		return p.unrep("exemplar_trace_id")
	}
	var id model.ID
	copy(id[:], tb)
	smp.trace = &id
	if span != "" {
		sb, err := hex.DecodeString(span)
		if err != nil || len(sb) != 8 {
			return p.unrep("exemplar_span_id")
		}
		var sp model.SpanID
		copy(sp[:], sb)
		smp.span = &sp
	}
	smp.hasEx = true
	p.a.report.add(ReportExemplarDetailDiscarded, 1)
	return nil
}

// value parses an OpenMetrics number to exact float64 bits. Integer tokens that
// float64 cannot represent exactly are rejected, not rounded.
func (p *omParser) value(tok string) (uint64, error) {
	switch tok {
	case "NaN":
		return math.Float64bits(math.NaN()), nil
	case "+Inf":
		return math.Float64bits(math.Inf(1)), nil
	case "-Inf":
		return math.Float64bits(math.Inf(-1)), nil
	}
	if tok == "" {
		return 0, p.bad("value")
	}
	integer := true
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= '0' && c <= '9':
		case (c == '-' || c == '+') && (i == 0 || tok[i-1] == 'e' || tok[i-1] == 'E'):
			if i > 0 {
				integer = false
			}
		case c == '.' || c == 'e' || c == 'E':
			integer = false
		default:
			return 0, p.bad("value")
		}
	}
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil || math.IsInf(f, 0) {
		if err != nil && strings.Contains(err.Error(), "syntax") {
			return 0, p.bad("value")
		}
		return 0, p.unrep("value_out_of_float64_range")
	}
	if integer {
		digits := strings.TrimLeft(tok, "+-")
		u, perr := strconv.ParseUint(digits, 10, 64)
		if perr != nil {
			return 0, p.unrep("integer_not_exact_float64")
		}
		if u > 1<<53 {
			g := float64(u)
			if g >= 18446744073709551616.0 || uint64(g) != u {
				return 0, p.unrep("integer_not_exact_float64")
			}
		}
	}
	return math.Float64bits(f), nil
}

// seconds parses a decimal-seconds timestamp to exact nanoseconds.
func (p *omParser) seconds(tok string) (int64, error) {
	neg := false
	s := tok
	if strings.HasPrefix(s, "-") {
		neg, s = true, s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" || len(whole) > 19 {
		return 0, p.bad("timestamp")
	}
	for _, part := range []string{whole, frac} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return 0, p.bad("timestamp")
			}
		}
	}
	frac = strings.TrimRight(frac, "0")
	if len(frac) > 9 {
		return 0, p.unrep("timestamp_sub_nanosecond")
	}
	sec, err := strconv.ParseInt(whole, 10, 64)
	if err != nil || sec > math.MaxInt64/1_000_000_000 {
		return 0, fail(fmtOpenMetrics, ReasonTimestampRange, "timestamp")
	}
	var fr int64
	if frac != "" {
		fr, _ = strconv.ParseInt(frac+strings.Repeat("0", 9-len(frac)), 10, 64)
	}
	ns := sec*1_000_000_000 + fr
	if neg {
		ns = -ns
	}
	return ns, nil
}

func (p *omParser) emit() error {
	if len(p.samples) == 0 {
		return p.bad("no_samples")
	}
	matched := map[string]bool{}
	for i := range p.samples {
		s := &p.samples[i]
		if i&1023 == 0 {
			if err := ctxErr(fmtOpenMetrics, p.ctx); err != nil {
				return err
			}
		}
		labels, err := cleanLabels(fmtOpenMetrics, s.labels, p.cfg, &p.a.report)
		if err != nil {
			return err
		}
		unit := p.cfg.unit()
		if s.fam.unit != "" {
			unit = s.fam.unit
		}
		typ := s.fam.typ
		if typ == "summary" {
			typ = "unknown"
			if p.mapped == nil {
				p.mapped = map[*omFamily]bool{}
			}
			if !p.mapped[s.fam] {
				p.mapped[s.fam] = true
				p.a.report.add(ReportTypeMappedUnknown, 1)
			}
		}
		bits := model.FloatBits(s.bits)
		m := model.MetricPoint{Name: s.name, Labels: labels, SampleKind: "float", Value: &bits, Unit: unit, Type: typ, ExemplarTrace: s.trace, ExemplarSpan: s.span}
		if s.fam.typ == "counter" || s.fam.typ == "histogram" || s.fam.typ == "summary" {
			key := s.fam.name + "\x00" + seriesKey("", withoutBucketLabels(labels))
			if ns, ok := p.created[key]; ok {
				v := model.UnixNano(ns)
				m.StartTimestamp = &v
				matched[key] = true
			}
		}
		rec, err := newMetricRecord(fmtOpenMetrics, m, model.UnixNano(s.ts), p.cfg)
		if err != nil {
			return err
		}
		p.a.add(rec)
	}
	for key := range p.created {
		if matched[key] {
			p.a.report.add(ReportCreatedApplied, 1)
		} else {
			p.a.report.add(ReportCreatedUnmatched, 1)
		}
	}
	return nil
}
