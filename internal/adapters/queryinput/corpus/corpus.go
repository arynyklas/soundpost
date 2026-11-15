// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package corpus

// The input-normalization corpus runner: the single implementation shared by
// `soundpost-querycheck normalize` and the package tests. It builds semantic
// corpus rows into real wire bytes (encoders follow the published schemas by
// field number only), runs the real translators against a throwaway real
// application, and compares the projected records / error reason / report
// counts with each row's `expected` exactly.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

const (
	corpusMinTimestamp = model.UnixNano(1_600_000_000_000_000_000)
	corpusMaxTimestamp = model.UnixNano(1_800_000_000_000_000_000)

	// Corpus floors: a shrunken corpus must not pass.
	CorpusMinRows     = 30
	CorpusMinPositive = 7
	CorpusMinNegative = 20
)

// ---- real application harness: control plane, auth, source onboarding ----

// Harness is a throwaway real application with one onboarded structured source.
type Harness struct {
	Ctx      context.Context
	App      *appcore.App
	Actor    auth.Credential
	Org      model.ID
	Project  model.ID
	Source   model.ID
	Resource model.Resource
	Cred     auth.SourceCredential
	PS       *policy.Service // fixed clock: grants never expire during a run
}

func newScalarOrErr(s string) (model.Scalar, error) {
	var out model.Scalar
	raw, err := json.Marshal(s)
	if err != nil {
		return out, err
	}
	return out, out.UnmarshalJSON(raw)
}

func harnessPolicy(res model.Resource) (model.SourcePolicy, error) {
	mk := func(s string) (model.Scalar, error) { return newScalarOrErr(s) }
	alpha, err := mk("alpha")
	if err != nil {
		return model.SourcePolicy{}, err
	}
	beta, err := mk("beta")
	if err != nil {
		return model.SourcePolicy{}, err
	}
	t1, err := mk("t1")
	if err != nil {
		return model.SourcePolicy{}, err
	}
	line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: []model.Scalar{alpha, beta}}
	tenant := model.TemplateField{Name: "tenant", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{t1}}
	return model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log},
		Templates: []model.LogTemplate{
			{ID: "migrated.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line}},
			{ID: "migrated.meta", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line, tenant}},
		},
		Resources: model.ResourceRegistry{Services: []model.ID{res.Service}, Environments: []model.ID{res.Environment}, Builds: []model.ID{res.Build}, Instances: []string{res.Instance}},
		Labels: map[string][]string{
			"job": {"api", "worker"}, "le": {"0.5", "+Inf"}, "app": {"web"}, "region": {"eu", "us"},
		},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7, model.Log: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
	}, nil
}

// OpenHarness opens a real application under dir and onboards the fixture source.
func OpenHarness(ctx context.Context, dir string) (*Harness, error) {
	app, err := appcore.Open(dir)
	if err != nil {
		return nil, err
	}
	h, err := bootstrapHarness(ctx, app)
	if err != nil {
		app.Close()
		return nil, err
	}
	return h, nil
}

func bootstrapHarness(ctx context.Context, app *appcore.App) (*Harness, error) {
	token, err := app.Control.BootstrapToken()
	if err != nil {
		return nil, err
	}
	session, err := app.Auth.Bootstrap(ctx, token, "adapters-owner@example.test", "adapter fixture password 2026")
	if err != nil {
		return nil, err
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		return nil, err
	}
	h := &Harness{Ctx: ctx, App: app, Actor: actor, Org: model.NewID(), Project: model.NewID(), Source: model.NewID()}
	if err = h.Command("create_org", auth.AdminPayload{Name: "adapters"}); err != nil {
		return nil, err
	}
	if err = h.Command("create_project", auth.AdminPayload{ID: h.Project, Name: "adapters"}); err != nil {
		return nil, err
	}
	h.Resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "inst-1", Labels: model.Labels{}}
	pol, err := harnessPolicy(h.Resource)
	if err != nil {
		return nil, err
	}
	if h.Cred, err = h.Onboard(h.Source, pol); err != nil {
		return nil, err
	}
	fixed := time.Now()
	h.PS, err = policy.New(app.Auth, func() time.Time { return fixed })
	if err != nil {
		return nil, err
	}
	return h, nil
}

// Close releases the application.
func (h *Harness) Close() error { return h.App.Close() }

func (h *Harness) Command(kind string, p auth.AdminPayload) error {
	var rev model.Revision
	h.App.Control.View(h.Ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
	p.Reason = "adapter fixture"
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = h.App.Auth.AdminCommand(h.Ctx, h.Actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: h.Org, Kind: kind, Payload: raw})
	return err
}

func (h *Harness) Onboard(source model.ID, p model.SourcePolicy) (auth.SourceCredential, error) {
	issued, err := h.App.Auth.OnboardSource(h.Ctx, h.Actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: h.Org, Project: h.Project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: p, Reason: "adapter fixture"})
	if err != nil {
		return auth.SourceCredential{}, err
	}
	return h.App.Auth.AuthenticateSource(h.Ctx, issued.Credential, "", false)
}

// grant resolves a long-lived (fixed clock) grant for the fixture source.
func (h *Harness) Grant() (policy.SourceGrant, error) {
	return h.PS.ResolveSource(h.Ctx, h.Cred, h.Project, h.Source, 1)
}

func (h *Harness) Profile() InputProfile {
	return InputProfile{
		Project: h.Project, Source: h.Source, Producer: model.ID{0xaa, 1}, PolicyRevision: 1, Resource: h.Resource,
		Limits: DefaultLimits(), MinTimestamp: corpusMinTimestamp, MaxTimestamp: corpusMaxTimestamp, DefaultTimestamp: 1_700_000_005_000_000_000,
		Names: NamesStrict, OutOfOrder: OutOfOrderSort, Histograms: HistogramsPreserve, Exemplars: ExemplarsReject, Help: HelpReject,
		Loki: LokiMapping{Encoding: EncodingJSON, TemplateID: "migrated.meta", TemplateRevision: 1, LineField: "line", MetadataFields: []string{"tenant"}},
	}
}

// ---- wire encoders ----

type pbw struct{ b []byte }

func (w *pbw) tag(num, wt uint64) { w.b = binary.AppendUvarint(w.b, num<<3|wt) }
func (w *pbw) varint(num, v uint64) {
	w.tag(num, 0)
	w.b = binary.AppendUvarint(w.b, v)
}
func (w *pbw) fixed64(num, v uint64) {
	w.tag(num, 1)
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
}
func (w *pbw) bytes(num uint64, b []byte) {
	w.tag(num, 2)
	w.b = binary.AppendUvarint(w.b, uint64(len(b)))
	w.b = append(w.b, b...)
}
func (w *pbw) msg(num uint64, f func(*pbw)) {
	var inner pbw
	f(&inner)
	w.bytes(num, inner.b)
}
func zz(v int64) uint64 { return uint64(v<<1) ^ uint64(v>>63) }
func (w *pbw) packedSint(num uint64, vals []int64) {
	var inner pbw
	for _, v := range vals {
		inner.b = binary.AppendUvarint(inner.b, zz(v))
	}
	w.bytes(num, inner.b)
}
func (w *pbw) packedBits(num uint64, vals []uint64) {
	var inner pbw
	for _, v := range vals {
		inner.b = binary.LittleEndian.AppendUint64(inner.b, v)
	}
	w.bytes(num, inner.b)
}
func (w *pbw) packedUint(num uint64, vals []uint64) {
	var inner pbw
	for _, v := range vals {
		inner.b = binary.AppendUvarint(inner.b, v)
	}
	w.bytes(num, inner.b)
}

// SnappyEncode is a small block-format encoder (literals plus 2-byte-offset copies).
func SnappyEncode(src []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(src)))
	table := map[uint32]int{}
	lit := func(b []byte) {
		for len(b) > 0 {
			n := min(len(b), 256)
			if n <= 60 {
				out = append(out, byte(n-1)<<2)
			} else {
				out = append(out, 60<<2, byte(n-1))
			}
			out = append(out, b[:n]...)
			b = b[n:]
		}
	}
	start, i := 0, 0
	for i+4 <= len(src) {
		key := binary.LittleEndian.Uint32(src[i:])
		cand, ok := table[key]
		table[key] = i
		if !ok || i-cand >= 65536 || i-cand <= 0 {
			i++
			continue
		}
		n := 4
		for n < 64 && i+n < len(src) && src[cand+n] == src[i+n] {
			n++
		}
		lit(src[start:i])
		out = append(out, byte(n-1)<<2|2, byte(i-cand), byte((i-cand)>>8))
		i += n
		start = i
	}
	lit(src[start:])
	return out
}

func Gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// ---- semantic fixtures (conformance/query/fixtures/adapters) ----

type semSample struct {
	Bits    string `json:"bits"`
	TS      string `json:"timestamp_ms"`
	StartMS string `json:"start_timestamp_ms"`
}
type semExemplar struct {
	Labels map[string]string `json:"labels"`
	Value  string            `json:"value_bits"`
	TS     string            `json:"timestamp_ms"`
}
type semHist struct {
	CountInt       *string    `json:"count_int"`
	CountFloat     *string    `json:"count_float_bits"`
	ZeroInt        *string    `json:"zero_count_int"`
	ZeroFloat      *string    `json:"zero_count_float_bits"`
	Sum            string     `json:"sum_bits"`
	ZeroThreshold  string     `json:"zero_threshold_bits"`
	Schema         int64      `json:"schema"`
	PositiveSpans  [][2]int64 `json:"positive_spans"`
	PositiveDeltas []string   `json:"positive_deltas"`
	PositiveCounts []string   `json:"positive_counts_bits"`
	NegativeSpans  [][2]int64 `json:"negative_spans"`
	NegativeDeltas []string   `json:"negative_deltas"`
	NegativeCounts []string   `json:"negative_counts_bits"`
	Custom         []string   `json:"custom_values_bits"`
	Reset          uint64     `json:"reset_hint"`
	TS             string     `json:"timestamp_ms"`
	StartMS        string     `json:"start_timestamp_ms"`
}
type semSeriesMeta struct {
	Type string `json:"type"`
	Unit string `json:"unit"`
	Help string `json:"help"`
}
type semSeries struct {
	Labels     map[string]string `json:"labels"`
	LabelPairs [][2]string       `json:"label_pairs"`
	Metadata   *semSeriesMeta    `json:"metadata"`
	Samples    []semSample       `json:"samples"`
	Exemplars  []semExemplar     `json:"exemplars"`
	Histograms []semHist         `json:"histograms"`
}
type semV1Meta struct {
	Type   string `json:"type"`
	Family string `json:"family"`
	Help   string `json:"help"`
	Unit   string `json:"unit"`
}
type SemRW struct {
	Version    int         `json:"version"`
	Metadata   []semV1Meta `json:"metadata"`
	Timeseries []semSeries `json:"timeseries"`
}
type SemLoki struct {
	Streams []struct {
		Labels  map[string]string `json:"labels"`
		Entries []struct {
			TS       string            `json:"ts_ns"`
			Line     string            `json:"line"`
			Metadata map[string]string `json:"metadata"`
		} `json:"entries"`
	} `json:"streams"`
}

var metricTypes = map[string]uint64{"unspecified": 0, "counter": 1, "gauge": 2, "histogram": 3, "gauge_histogram": 4, "summary": 5, "info": 6, "stateset": 7}

// encoder accumulates the first conversion error so encoders stay linear.
type encoder struct{ err error }

func (e *encoder) fail(format string, a ...any) {
	if e.err == nil {
		e.err = fmt.Errorf(format, a...)
	}
}
func (e *encoder) u64(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		e.fail("bad u64 %q", s)
	}
	return v
}
func (e *encoder) i64(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		e.fail("bad i64 %q", s)
	}
	return v
}
func (e *encoder) bits(s string) uint64 {
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		e.fail("bad bits %q", s)
	}
	return v
}
func (e *encoder) bitsList(in []string) []uint64 {
	out := make([]uint64, len(in))
	for i, s := range in {
		out[i] = e.bits(s)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	k := make([]string, 0, len(m))
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

func (e *encoder) hist(h semHist, v WireVersion) []byte {
	var w pbw
	if h.CountInt != nil {
		w.varint(1, e.u64(*h.CountInt))
	}
	if h.CountFloat != nil {
		w.fixed64(2, e.bits(*h.CountFloat))
	}
	w.fixed64(3, e.bits(h.Sum))
	w.varint(4, zz(h.Schema))
	if h.ZeroThreshold != "" {
		w.fixed64(5, e.bits(h.ZeroThreshold))
	}
	if h.ZeroInt != nil {
		w.varint(6, e.u64(*h.ZeroInt))
	}
	if h.ZeroFloat != nil {
		w.fixed64(7, e.bits(*h.ZeroFloat))
	}
	spans := func(num uint64, in [][2]int64) {
		for _, s := range in {
			w.msg(num, func(m *pbw) {
				m.varint(1, zz(s[0]))
				m.varint(2, uint64(s[1]))
			})
		}
	}
	deltas := func(num uint64, in []string) {
		if len(in) == 0 {
			return
		}
		vals := make([]int64, len(in))
		for i, s := range in {
			vals[i] = e.i64(s)
		}
		w.packedSint(num, vals)
	}
	spans(8, h.NegativeSpans)
	deltas(9, h.NegativeDeltas)
	if len(h.NegativeCounts) > 0 {
		w.packedBits(10, e.bitsList(h.NegativeCounts))
	}
	spans(11, h.PositiveSpans)
	deltas(12, h.PositiveDeltas)
	if len(h.PositiveCounts) > 0 {
		w.packedBits(13, e.bitsList(h.PositiveCounts))
	}
	if h.Reset != 0 {
		w.varint(14, h.Reset)
	}
	w.varint(15, uint64(e.i64(h.TS)))
	if len(h.Custom) > 0 {
		w.packedBits(16, e.bitsList(h.Custom))
	}
	if v == RemoteWriteV2 && h.StartMS != "" {
		w.varint(17, uint64(e.i64(h.StartMS)))
	}
	return w.b
}

func (s semSeries) pairs() [][2]string {
	if s.LabelPairs != nil {
		return s.LabelPairs
	}
	var out [][2]string
	for _, k := range sortedKeys(s.Labels) {
		out = append(out, [2]string{k, s.Labels[k]})
	}
	return out
}

func EncodeRemoteWrite(in SemRW) ([]byte, error) {
	var e encoder
	var w pbw
	if in.Version == 1 {
		for _, s := range in.Timeseries {
			w.msg(1, func(ts *pbw) {
				for _, p := range s.pairs() {
					ts.msg(1, func(l *pbw) {
						l.bytes(1, []byte(p[0]))
						l.bytes(2, []byte(p[1]))
					})
				}
				for _, sm := range s.Samples {
					ts.msg(2, func(m *pbw) {
						m.fixed64(1, e.bits(sm.Bits))
						m.varint(2, uint64(e.i64(sm.TS)))
					})
				}
				for _, x := range s.Exemplars {
					ts.msg(3, func(m *pbw) {
						for _, k := range sortedKeys(x.Labels) {
							m.msg(1, func(l *pbw) {
								l.bytes(1, []byte(k))
								l.bytes(2, []byte(x.Labels[k]))
							})
						}
						m.fixed64(2, e.bits(x.Value))
						m.varint(3, uint64(e.i64(x.TS)))
					})
				}
				for _, h := range s.Histograms {
					ts.bytes(4, e.hist(h, RemoteWriteV1))
				}
			})
		}
		for _, md := range in.Metadata {
			w.msg(3, func(m *pbw) {
				if md.Type != "unspecified" && md.Type != "" {
					m.varint(1, metricTypes[md.Type])
				}
				m.bytes(2, []byte(md.Family))
				if md.Help != "" {
					m.bytes(4, []byte(md.Help))
				}
				if md.Unit != "" {
					m.bytes(5, []byte(md.Unit))
				}
			})
		}
		return w.b, e.err
	}
	symbols := []string{""}
	index := map[string]uint64{"": 0}
	ref := func(s string) uint64 {
		if i, ok := index[s]; ok {
			return i
		}
		index[s] = uint64(len(symbols))
		symbols = append(symbols, s)
		return index[s]
	}
	var series [][]byte
	for _, s := range in.Timeseries {
		var ts pbw
		var refs []uint64
		for _, p := range s.pairs() {
			refs = append(refs, ref(p[0]), ref(p[1]))
		}
		ts.packedUint(1, refs)
		for _, sm := range s.Samples {
			ts.msg(2, func(m *pbw) {
				m.fixed64(1, e.bits(sm.Bits))
				m.varint(2, uint64(e.i64(sm.TS)))
				if sm.StartMS != "" {
					m.varint(3, uint64(e.i64(sm.StartMS)))
				}
			})
		}
		for _, h := range s.Histograms {
			ts.bytes(3, e.hist(h, RemoteWriteV2))
		}
		for _, x := range s.Exemplars {
			var er []uint64
			for _, k := range sortedKeys(x.Labels) {
				er = append(er, ref(k), ref(x.Labels[k]))
			}
			ts.msg(4, func(m *pbw) {
				m.packedUint(1, er)
				m.fixed64(2, e.bits(x.Value))
				m.varint(3, uint64(e.i64(x.TS)))
			})
		}
		if s.Metadata != nil {
			ts.msg(5, func(m *pbw) {
				if s.Metadata.Type != "unspecified" && s.Metadata.Type != "" {
					m.varint(1, metricTypes[s.Metadata.Type])
				}
				m.varint(3, ref(s.Metadata.Help))
				m.varint(4, ref(s.Metadata.Unit))
			})
		}
		series = append(series, ts.b)
	}
	for _, s := range symbols {
		w.bytes(4, []byte(s))
	}
	for _, s := range series {
		w.bytes(5, s)
	}
	return w.b, e.err
}

func LokiJSON(in SemLoki) []byte {
	type entry = []any
	var streams []map[string]any
	for _, s := range in.Streams {
		var values []entry
		for _, e := range s.Entries {
			v := entry{e.TS, e.Line}
			if e.Metadata != nil {
				v = append(v, e.Metadata)
			}
			values = append(values, v)
		}
		streams = append(streams, map[string]any{"stream": s.Labels, "values": values})
	}
	raw, _ := json.Marshal(map[string]any{"streams": streams})
	return raw
}

func EncodeLokiProto(in SemLoki) ([]byte, error) {
	var e encoder
	var w pbw
	for _, s := range in.Streams {
		w.msg(1, func(sm *pbw) {
			label := "{"
			for i, k := range sortedKeys(s.Labels) {
				if i > 0 {
					label += ", "
				}
				label += k + "=" + strconv.Quote(s.Labels[k])
			}
			sm.bytes(1, []byte(label+"}"))
			for _, en := range s.Entries {
				sm.msg(2, func(m *pbw) {
					ns := e.i64(en.TS)
					m.msg(1, func(ts *pbw) {
						ts.varint(1, uint64(ns/1_000_000_000))
						if ns%1_000_000_000 != 0 {
							ts.varint(2, uint64(ns%1_000_000_000))
						}
					})
					m.bytes(2, []byte(en.Line))
					for _, k := range sortedKeys(en.Metadata) {
						m.msg(3, func(l *pbw) {
							l.bytes(1, []byte(k))
							l.bytes(2, []byte(en.Metadata[k]))
						})
					}
				})
			}
		})
	}
	return w.b, e.err
}

// ---- corpus ----

// CorpusCase is one row of conformance/query/cases/input-normalization.json.
type CorpusCase struct {
	ID       string          `json:"id"`
	Format   string          `json:"format"`
	Fixture  string          `json:"fixture"`
	Inline   json.RawMessage `json:"inline"`
	Encoding string          `json:"encoding"`
	Profile  map[string]any  `json:"profile"`
	Expected struct {
		Records []any             `json:"records"`
		Report  map[string]uint64 `json:"report"`
		Error   *struct {
			Reason string `json:"reason"`
		} `json:"error"`
	} `json:"expected"`
	BindingScope string `json:"binding_scope"`
}

// ParseCorpus decodes the corpus document.
func ParseCorpus(raw []byte) ([]CorpusCase, error) {
	var doc struct {
		Cases []CorpusCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc.Cases, nil
}

// semantic returns the semantic input; fixture paths resolve under queryDir/fixtures.
func (c CorpusCase) Semantic(queryDir string) ([]byte, error) {
	if c.Fixture != "" {
		return os.ReadFile(filepath.Join(queryDir, "fixtures", filepath.FromSlash(c.Fixture)))
	}
	return c.Inline, nil
}

func (h *Harness) ProfileFor(c CorpusCase) (InputProfile, error) {
	p := h.Profile()
	for k, v := range c.Profile {
		switch k {
		case "exemplars", "help", "histograms":
			s, ok := v.(string)
			if !ok {
				return p, fmt.Errorf("profile override %q is not a string", k)
			}
			switch k {
			case "exemplars":
				p.Exemplars = ExemplarMode(s)
			case "help":
				p.Help = HelpMode(s)
			default:
				p.Histograms = HistogramMode(s)
			}
		case "max_line_bytes":
			n, ok := v.(float64)
			if !ok {
				return p, fmt.Errorf("profile override %q is not a number", k)
			}
			p.Limits.MaxLineBytes = int(n)
		default:
			return p, fmt.Errorf("unknown profile override %q", k)
		}
	}
	if c.Encoding != "" {
		p.Loki.Encoding = Encoding(c.Encoding)
	}
	return p, nil
}

// wire turns the case's semantic input into the real wire bytes for its format.
func (c CorpusCase) Wire(queryDir string, enc Encoding) ([]byte, error) {
	sem, err := c.Semantic(queryDir)
	if err != nil {
		return nil, err
	}
	switch c.Format {
	case "openmetrics":
		if c.Fixture != "" {
			return sem, nil
		}
		var in struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(sem, &in); err != nil {
			return nil, err
		}
		return []byte(in.Text), nil
	case "remote_write_v1", "remote_write_v2":
		var in SemRW
		if err := json.Unmarshal(sem, &in); err != nil {
			return nil, err
		}
		raw, err := EncodeRemoteWrite(in)
		if err != nil {
			return nil, err
		}
		return SnappyEncode(raw), nil
	case "loki_push":
		var in SemLoki
		if err := json.Unmarshal(sem, &in); err != nil {
			return nil, err
		}
		switch enc {
		case EncodingJSON:
			return LokiJSON(in), nil
		case EncodingJSONGzip:
			return Gz(LokiJSON(in)), nil
		default:
			raw, err := EncodeLokiProto(in)
			if err != nil {
				return nil, err
			}
			return SnappyEncode(raw), nil
		}
	}
	return nil, fmt.Errorf("unknown format %q", c.Format)
}

func (h *Harness) Decode(c CorpusCase, cfg InputProfile, body []byte) ([]model.Batch, error) {
	g, err := h.Grant()
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(body)
	switch c.Format {
	case "openmetrics":
		return DecodeOpenMetrics(h.Ctx, g, r, cfg)
	case "remote_write_v1":
		return DecodeRemoteWrite(h.Ctx, g, RemoteWriteV1, r, cfg)
	case "remote_write_v2":
		return DecodeRemoteWrite(h.Ctx, g, RemoteWriteV2, r, cfg)
	default:
		return DecodeLokiPush(h.Ctx, g, r, cfg)
	}
}

// ---- projection: the authored comparison form of normalized records ----

func projectLabels(l model.Labels) map[string]any {
	out := map[string]any{}
	for _, x := range l {
		out[x.Name] = x.Value
	}
	return out
}

func projectSpans(in []model.HistogramSpan) [][2]int64 {
	out := make([][2]int64, 0, len(in))
	for _, s := range in {
		out = append(out, [2]int64{int64(s.Offset), int64(s.Length)})
	}
	return out
}

func hexBits(v model.FloatBits) string { return fmt.Sprintf("%016x", uint64(v)) }

func hexList(in []model.FloatBits) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, hexBits(v))
	}
	return out
}

func project(rec model.Record) map[string]any {
	switch {
	case rec.Payload.Metric != nil:
		m := rec.Payload.Metric
		p := map[string]any{"kind": "metric", "ts": strconv.FormatInt(int64(rec.ObservedAt), 10), "name": m.Name, "labels": projectLabels(m.Labels), "sample": m.SampleKind, "unit": m.Unit, "type": m.Type}
		if m.Value != nil {
			p["bits"] = hexBits(*m.Value)
		}
		if m.StartTimestamp != nil {
			p["start"] = strconv.FormatInt(int64(*m.StartTimestamp), 10)
		}
		if m.ExemplarTrace != nil {
			p["trace"] = hex.EncodeToString(m.ExemplarTrace[:])
		}
		if m.ExemplarSpan != nil {
			p["span"] = hex.EncodeToString(m.ExemplarSpan[:])
		}
		if h := m.Histogram; h != nil {
			hp := map[string]any{}
			if ih := h.Integer; ih != nil {
				pd, nd := make([]string, 0), make([]string, 0)
				for _, d := range ih.PositiveBuckets {
					pd = append(pd, strconv.FormatInt(int64(d), 10))
				}
				for _, d := range ih.NegativeBuckets {
					nd = append(nd, strconv.FormatInt(int64(d), 10))
				}
				hp = map[string]any{"flavor": ih.Flavor, "reset": ih.ResetHint, "schema": ih.Schema, "count": strconv.FormatUint(uint64(ih.Count), 10), "zero_count": strconv.FormatUint(uint64(ih.ZeroCount), 10),
					"sum": hexBits(ih.Sum), "zero_threshold": hexBits(ih.ZeroThreshold),
					"positive": map[string]any{"spans": projectSpans(ih.PositiveSpans), "deltas": pd}, "negative": map[string]any{"spans": projectSpans(ih.NegativeSpans), "deltas": nd}}
				if len(ih.CustomBounds) > 0 {
					hp["custom"] = hexList(ih.CustomBounds)
				}
			} else if fh := h.Float; fh != nil {
				hp = map[string]any{"flavor": fh.Flavor, "reset": fh.ResetHint, "schema": fh.Schema, "count": hexBits(fh.Count), "zero_count": hexBits(fh.ZeroCount),
					"sum": hexBits(fh.Sum), "zero_threshold": hexBits(fh.ZeroThreshold),
					"positive": map[string]any{"spans": projectSpans(fh.PositiveSpans), "counts": hexList(fh.PositiveBuckets)}, "negative": map[string]any{"spans": projectSpans(fh.NegativeSpans), "counts": hexList(fh.NegativeBuckets)}}
				if len(fh.CustomBounds) > 0 {
					hp["custom"] = hexList(fh.CustomBounds)
				}
			}
			p["hist"] = hp
		}
		return p
	case rec.Payload.Log != nil:
		l := rec.Payload.Log
		fields, md := map[string]any{}, map[string]any{}
		for k, v := range l.Fields {
			fields[k] = v.Text()
		}
		for k, v := range l.Metadata {
			md[k] = v.Text()
		}
		return map[string]any{"kind": "log", "ts": strconv.FormatInt(int64(rec.ObservedAt), 10), "stream": projectLabels(l.StreamLabels), "template": fmt.Sprintf("%s@%d", l.TemplateID, l.TemplateRevision), "fields": fields, "metadata": md}
	}
	return map[string]any{"kind": "unsupported"}
}

// CanonicalJSON round-trips through JSON so numbers and maps compare structurally.
func CanonicalJSON(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	err = json.Unmarshal(raw, &out)
	return out, err
}

func SortedProjection(list []any) ([]string, error) {
	out := make([]string, len(list))
	for i, v := range list {
		c, err := CanonicalJSON(v)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		out[i] = string(raw)
	}
	sort.Strings(out)
	return out, nil
}

func ProjectRecords(batches []model.Batch) []any {
	var out []any
	for _, b := range batches {
		for _, r := range b.Records {
			out = append(out, project(r))
		}
	}
	return out
}

func ReasonOf(err error) Reason {
	var qe *Error
	if errors.As(err, &qe) {
		return qe.Reason
	}
	return ""
}

// ---- runner ----

// CaseOutcome is the decoded result of one row.
type CaseOutcome struct {
	Batches []model.Batch
	Report  NormalizationReport
	Err     error
}

// RunCase decodes one corpus row; queryDir is the conformance/query directory.
func (h *Harness) RunCase(queryDir string, c CorpusCase) (CaseOutcome, error) {
	cfg, err := h.ProfileFor(c)
	if err != nil {
		return CaseOutcome{}, err
	}
	var out CaseOutcome
	cfg.Report = func(r NormalizationReport) { out.Report = r }
	body, err := c.Wire(queryDir, cfg.Loki.Encoding)
	if err != nil {
		return CaseOutcome{}, err
	}
	out.Batches, out.Err = h.Decode(c, cfg, body)
	return out, nil
}

// CheckCase runs one row and compares it to `expected` exactly. It returns the
// row outcome and a non-nil error describing the first mismatch (nil = match).
func (h *Harness) CheckCase(queryDir string, c CorpusCase) (CaseOutcome, error) {
	if !strings.Contains(c.BindingScope, "authored from the format specifications") {
		return CaseOutcome{}, fmt.Errorf("row lacks honest binding_scope: %q", c.BindingScope)
	}
	out, err := h.RunCase(queryDir, c)
	if err != nil {
		return out, err
	}
	if want := c.Expected.Error; want != nil {
		if out.Err == nil {
			return out, fmt.Errorf("accepted input that must be rejected as %s", want.Reason)
		}
		if got := ReasonOf(out.Err); got != Reason(want.Reason) {
			return out, fmt.Errorf("reason %q want %q (%v)", got, want.Reason, out.Err)
		}
		var fault *model.Fault
		if !errors.As(out.Err, &fault) || fault.Code == "" {
			return out, fmt.Errorf("rejection is not a typed model fault: %v", out.Err)
		}
		return out, nil
	}
	if out.Err != nil {
		return out, fmt.Errorf("unexpected rejection: %w", out.Err)
	}
	want, err := SortedProjection(c.Expected.Records)
	if err != nil {
		return out, err
	}
	got, err := SortedProjection(ProjectRecords(out.Batches))
	if err != nil {
		return out, err
	}
	if !reflect.DeepEqual(want, got) {
		return out, fmt.Errorf("input mismatch: want %d records %v, got %d records %v", len(want), want, len(got), got)
	}
	wantReport, gotReport := c.Expected.Report, out.Report.Counts
	if wantReport == nil {
		wantReport = map[string]uint64{}
	}
	if gotReport == nil {
		gotReport = map[string]uint64{}
	}
	if !reflect.DeepEqual(wantReport, gotReport) {
		return out, fmt.Errorf("report %v want %v", gotReport, wantReport)
	}
	// Every decoded batch must be admissible under the real source policy.
	grant, err := h.Grant()
	if err != nil {
		return out, err
	}
	for _, b := range out.Batches {
		if len(b.Records) == 0 || len(b.Records) > 512 {
			return out, fmt.Errorf("batch size %d", len(b.Records))
		}
		if _, err := policy.Normalize(grant, b); err != nil {
			return out, fmt.Errorf("decoded batch is not admissible: %w", err)
		}
		for _, r := range b.Records {
			slot, _ := model.OwnerSlot(h.Org, h.Project, h.Source, b.Producer, r)
			if slot != b.RouteSlot {
				return out, fmt.Errorf("batch spans more than one owner slot")
			}
		}
	}
	return out, nil
}

// CorpusRow is the per-case result in the report.
type CorpusRow struct {
	ID       string            `json:"id"`
	Format   string            `json:"format"`
	Outcome  string            `json:"outcome"` // "records" or "error"
	Records  int               `json:"records"`
	Reason   string            `json:"reason,omitempty"`
	Counts   map[string]uint64 `json:"report_counts,omitempty"`
	Match    bool              `json:"match"`
	Mismatch string            `json:"mismatch,omitempty"`
}

// CorpusReport is the machine-readable result of RunCorpus.
type CorpusReport struct {
	Cases      int         `json:"cases"`
	Positive   int         `json:"positive"`
	Negative   int         `json:"negative"`
	Records    int         `json:"records"`
	Matched    int         `json:"matched"`
	Mismatched int         `json:"mismatched"`
	Rows       []CorpusRow `json:"rows"`
	Mismatches []string    `json:"mismatches"`
}

// RunCorpus executes every row of the (already lock-verified) corpus bytes
// against the real translators in a throwaway real application whose temporary
// directory is removed before return. queryDir is the conformance/query dir
// used to resolve `fixture` references. It returns an error when any row does
// not match its `expected` exactly or a corpus floor is violated; the report is
// always populated.
func RunCorpus(ctx context.Context, queryDir string, raw []byte) (CorpusReport, error) {
	var rep CorpusReport
	cases, err := ParseCorpus(raw)
	if err != nil {
		return rep, err
	}
	dir, err := os.MkdirTemp("", "soundpost-normalize-")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(dir)
	h, err := OpenHarness(ctx, dir)
	if err != nil {
		return rep, err
	}
	defer h.Close()
	rep.Rows = make([]CorpusRow, 0, len(cases))
	for _, c := range cases {
		row := CorpusRow{ID: c.ID, Format: c.Format, Outcome: "records"}
		if c.Expected.Error != nil {
			row.Outcome = "error"
			rep.Negative++
		} else {
			rep.Positive++
		}
		out, cerr := h.CheckCase(queryDir, c)
		if out.Err != nil {
			row.Reason = string(ReasonOf(out.Err))
		}
		for _, b := range out.Batches {
			row.Records += len(b.Records)
		}
		row.Counts = out.Report.Counts
		rep.Records += row.Records
		if cerr != nil {
			row.Mismatch = cerr.Error()
			rep.Mismatched++
			rep.Mismatches = append(rep.Mismatches, c.ID+": "+cerr.Error())
		} else {
			row.Match = true
			rep.Matched++
		}
		rep.Rows = append(rep.Rows, row)
	}
	rep.Cases = len(cases)
	if rep.Mismatches == nil {
		rep.Mismatches = []string{}
	}
	if rep.Cases < CorpusMinRows || rep.Positive < CorpusMinPositive || rep.Negative < CorpusMinNegative {
		return rep, fmt.Errorf("corpus floor: %d rows (positive %d, negative %d); need >= %d/%d/%d", rep.Cases, rep.Positive, rep.Negative, CorpusMinRows, CorpusMinPositive, CorpusMinNegative)
	}
	if rep.Mismatched > 0 {
		return rep, fmt.Errorf("%d of %d corpus rows do not match expected", rep.Mismatched, rep.Cases)
	}
	return rep, nil
}
