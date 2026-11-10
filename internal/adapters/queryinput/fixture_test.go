// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"soundpost/internal/appcore"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"soundpost/internal/storage"
)

// ---- real application fixture: control plane, auth, source onboarding, storage ----

type fixture struct {
	t        *testing.T
	ctx      context.Context
	app      *appcore.App
	actor    auth.Credential
	org      model.ID
	project  model.ID
	source   model.ID
	resource model.Resource
	cred     auth.SourceCredential
	ps       *policy.Service // fixed clock: grants never expire inside a test
	reader   *auth.Scope
}

const (
	testMin = model.UnixNano(1_600_000_000_000_000_000)
	testMax = model.UnixNano(1_800_000_000_000_000_000)
)

func scalar(t testing.TB, s string) model.Scalar {
	t.Helper()
	v, err := newScalar(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func structuredPolicy(t testing.TB, res model.Resource) model.SourcePolicy {
	line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: []model.Scalar{scalar(t, "alpha"), scalar(t, "beta")}}
	tenant := model.TemplateField{Name: "tenant", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalar(t, "t1")}}
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
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	token, err := app.Control.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	session, err := app.Auth.Bootstrap(ctx, token, "adapters-owner@example.test", "adapter fixture password 2026")
	if err != nil {
		t.Fatal(err)
	}
	actor, err := app.Auth.Authenticate(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, ctx: ctx, app: app, actor: actor, org: model.NewID(), project: model.NewID(), source: model.NewID()}
	f.command("create_org", auth.AdminPayload{Name: "adapters"})
	f.command("create_project", auth.AdminPayload{ID: f.project, Name: "adapters"})
	f.resource = model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "inst-1", Labels: model.Labels{}}
	f.cred = f.onboard(f.source, structuredPolicy(t, f.resource))
	fixed := time.Now()
	f.ps, err = policy.New(app.Auth, func() time.Time { return fixed })
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) command(kind string, p auth.AdminPayload) {
	f.t.Helper()
	var rev model.Revision
	f.app.Control.View(f.ctx, func(st model.ControlState) error { rev = st.Revision; return nil })
	p.Reason = "adapter fixture"
	raw, _ := json.Marshal(p)
	if _, err := f.app.Auth.AdminCommand(f.ctx, f.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: f.org, Kind: kind, Payload: raw}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) onboard(source model.ID, p model.SourcePolicy) auth.SourceCredential {
	f.t.Helper()
	issued, err := f.app.Auth.OnboardSource(f.ctx, f.actor, auth.SourceOnboarding{CommandID: model.NewID(), Org: f.org, Project: f.project, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: p, Reason: "adapter fixture"})
	if err != nil {
		f.t.Fatal(err)
	}
	cred, err := f.app.Auth.AuthenticateSource(f.ctx, issued.Credential, "", false)
	if err != nil {
		f.t.Fatal(err)
	}
	return cred
}

// grant resolves a long-lived (fixed clock) grant for the fixture source.
func (f *fixture) grant() policy.SourceGrant {
	f.t.Helper()
	g, err := f.ps.ResolveSource(f.ctx, f.cred, f.project, f.source, 1)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

// liveGrant is a real-clock grant for the production ingest service.
func (f *fixture) liveGrant(batch model.Batch) policy.SourceGrant {
	f.t.Helper()
	g, err := f.app.Ingest.ResolveSource(f.ctx, f.cred, batch)
	if err != nil {
		f.t.Fatal(err)
	}
	return g
}

func (f *fixture) profile() InputProfile {
	return InputProfile{
		Project: f.project, Source: f.source, Producer: model.ID{0xaa, 1}, PolicyRevision: 1, Resource: f.resource,
		Limits: DefaultLimits(), MinTimestamp: testMin, MaxTimestamp: testMax, DefaultTimestamp: 1_700_000_005_000_000_000,
		Names: NamesStrict, OutOfOrder: OutOfOrderSort, Histograms: HistogramsPreserve, Exemplars: ExemplarsReject, Help: HelpReject,
		Loki: LokiMapping{Encoding: EncodingJSON, TemplateID: "migrated.meta", TemplateRevision: 1, LineField: "line", MetadataFields: []string{"tenant"}},
	}
}

func (f *fixture) readerScope() auth.Scope {
	f.t.Helper()
	if f.reader != nil {
		return *f.reader
	}
	user := model.NewID()
	f.command("create_user", auth.AdminPayload{ID: user, Email: "adapter-reader@example.test", Password: "reader password long 2026"})
	f.command("membership", auth.AdminPayload{UserID: user, Enabled: true})
	f.command("grant", auth.AdminPayload{UserID: user, ProjectID: f.project, Enabled: true, Permissions: []string{string(auth.Read)}})
	login, err := f.app.Auth.Login(f.ctx, "adapter-reader@example.test", "reader password long 2026", "")
	if err != nil {
		f.t.Fatal(err)
	}
	reader, err := f.app.Auth.Authenticate(f.ctx, login.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	scope, err := f.app.Auth.Authorize(f.ctx, reader, f.org, []model.ID{f.project}, auth.Read)
	if err != nil {
		f.t.Fatal(err)
	}
	f.reader = &scope
	return scope
}

type stored struct {
	ts      model.UnixNano
	payload model.Payload
}

func (f *fixture) scan(kind model.Kind) []stored {
	f.t.Helper()
	rows, err := f.app.Storage.Scan(f.ctx, f.readerScope(), storage.ScanRequest{Projects: []model.ID{f.project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []stored
	for {
		page, err := rows.Next(f.ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			f.t.Fatal(err)
		}
		for i := range page.Len() {
			out = append(out, stored{ts: page.ObservedTimes[i], payload: page.Values[i]})
		}
	}
	return out
}

// ---- wire encoders (test side only; they follow the published schemas) ----

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

// snappyEncode is a small block-format encoder (literals plus 2-byte-offset copies).
func snappyEncode(src []byte) []byte {
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

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// ---- semantic fixtures (conformance/query/fixtures/adapters) and the corpus ----

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
type semRW struct {
	Version    int         `json:"version"`
	Metadata   []semV1Meta `json:"metadata"`
	Timeseries []semSeries `json:"timeseries"`
}
type semLoki struct {
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

func u64(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		t.Fatalf("bad u64 %q", s)
	}
	return v
}
func i64(t testing.TB, s string) int64 {
	t.Helper()
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		t.Fatalf("bad i64 %q", s)
	}
	return v
}
func bits(t testing.TB, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		t.Fatalf("bad bits %q", s)
	}
	return v
}
func bitsList(t testing.TB, in []string) []uint64 {
	out := make([]uint64, len(in))
	for i, s := range in {
		out[i] = bits(t, s)
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

func (h semHist) encode(t testing.TB, v WireVersion) []byte {
	var w pbw
	if h.CountInt != nil {
		w.varint(1, u64(t, *h.CountInt))
	}
	if h.CountFloat != nil {
		w.fixed64(2, bits(t, *h.CountFloat))
	}
	w.fixed64(3, bits(t, h.Sum))
	w.varint(4, zz(h.Schema))
	if h.ZeroThreshold != "" {
		w.fixed64(5, bits(t, h.ZeroThreshold))
	}
	if h.ZeroInt != nil {
		w.varint(6, u64(t, *h.ZeroInt))
	}
	if h.ZeroFloat != nil {
		w.fixed64(7, bits(t, *h.ZeroFloat))
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
			vals[i] = i64(t, s)
		}
		w.packedSint(num, vals)
	}
	spans(8, h.NegativeSpans)
	deltas(9, h.NegativeDeltas)
	if len(h.NegativeCounts) > 0 {
		w.packedBits(10, bitsList(t, h.NegativeCounts))
	}
	spans(11, h.PositiveSpans)
	deltas(12, h.PositiveDeltas)
	if len(h.PositiveCounts) > 0 {
		w.packedBits(13, bitsList(t, h.PositiveCounts))
	}
	if h.Reset != 0 {
		w.varint(14, h.Reset)
	}
	w.varint(15, uint64(i64(t, h.TS)))
	if len(h.Custom) > 0 {
		w.packedBits(16, bitsList(t, h.Custom))
	}
	if v == RemoteWriteV2 && h.StartMS != "" {
		w.varint(17, uint64(i64(t, h.StartMS)))
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

func encodeRW(t testing.TB, in semRW) []byte {
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
						m.fixed64(1, bits(t, sm.Bits))
						m.varint(2, uint64(i64(t, sm.TS)))
					})
				}
				for _, e := range s.Exemplars {
					ts.msg(3, func(m *pbw) {
						for _, k := range sortedKeys(e.Labels) {
							m.msg(1, func(l *pbw) {
								l.bytes(1, []byte(k))
								l.bytes(2, []byte(e.Labels[k]))
							})
						}
						m.fixed64(2, bits(t, e.Value))
						m.varint(3, uint64(i64(t, e.TS)))
					})
				}
				for _, h := range s.Histograms {
					ts.bytes(4, h.encode(t, RemoteWriteV1))
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
		return w.b
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
				m.fixed64(1, bits(t, sm.Bits))
				m.varint(2, uint64(i64(t, sm.TS)))
				if sm.StartMS != "" {
					m.varint(3, uint64(i64(t, sm.StartMS)))
				}
			})
		}
		for _, h := range s.Histograms {
			ts.bytes(3, h.encode(t, RemoteWriteV2))
		}
		for _, e := range s.Exemplars {
			var er []uint64
			for _, k := range sortedKeys(e.Labels) {
				er = append(er, ref(k), ref(e.Labels[k]))
			}
			ts.msg(4, func(m *pbw) {
				m.packedUint(1, er)
				m.fixed64(2, bits(t, e.Value))
				m.varint(3, uint64(i64(t, e.TS)))
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
	return w.b
}

func lokiJSON(in semLoki) []byte {
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

func lokiProto(t testing.TB, in semLoki) []byte {
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
			for _, e := range s.Entries {
				sm.msg(2, func(en *pbw) {
					ns := i64(t, e.TS)
					en.msg(1, func(ts *pbw) {
						ts.varint(1, uint64(ns/1_000_000_000))
						if ns%1_000_000_000 != 0 {
							ts.varint(2, uint64(ns%1_000_000_000))
						}
					})
					en.bytes(2, []byte(e.Line))
					for _, k := range sortedKeys(e.Metadata) {
						en.msg(3, func(l *pbw) {
							l.bytes(1, []byte(k))
							l.bytes(2, []byte(e.Metadata[k]))
						})
					}
				})
			}
		})
	}
	return w.b
}

type corpusCase struct {
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

func repoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "conformance", "query", "source-lock.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found")
		}
		dir = parent
	}
}

func loadCorpus(t testing.TB) []corpusCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "conformance", "query", "cases", "input-normalization.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []corpusCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func (c corpusCase) semantic(t testing.TB) []byte {
	t.Helper()
	if c.Fixture != "" {
		raw, err := os.ReadFile(filepath.Join(repoRoot(t), "conformance", "query", "fixtures", filepath.FromSlash(c.Fixture)))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return c.Inline
}

func (f *fixture) profileFor(c corpusCase) InputProfile {
	p := f.profile()
	for k, v := range c.Profile {
		switch k {
		case "exemplars":
			p.Exemplars = ExemplarMode(v.(string))
		case "help":
			p.Help = HelpMode(v.(string))
		case "histograms":
			p.Histograms = HistogramMode(v.(string))
		case "max_line_bytes":
			p.Limits.MaxLineBytes = int(v.(float64))
		default:
			f.t.Fatalf("unknown profile override %q", k)
		}
	}
	if c.Encoding != "" {
		p.Loki.Encoding = Encoding(c.Encoding)
	}
	return p
}

// wire turns the case's semantic input into the real wire bytes for its format.
func (c corpusCase) wire(t testing.TB, enc Encoding) []byte {
	sem := c.semantic(t)
	switch c.Format {
	case "openmetrics":
		if c.Fixture != "" {
			return sem
		}
		var in struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(sem, &in); err != nil {
			t.Fatal(err)
		}
		return []byte(in.Text)
	case "remote_write_v1", "remote_write_v2":
		var in semRW
		if err := json.Unmarshal(sem, &in); err != nil {
			t.Fatal(err)
		}
		return snappyEncode(encodeRW(t, in))
	case "loki_push":
		var in semLoki
		if err := json.Unmarshal(sem, &in); err != nil {
			t.Fatal(err)
		}
		switch enc {
		case EncodingJSON:
			return lokiJSON(in)
		case EncodingJSONGzip:
			return gz(lokiJSON(in))
		default:
			return snappyEncode(lokiProto(t, in))
		}
	}
	t.Fatalf("unknown format %q", c.Format)
	return nil
}

func (f *fixture) decode(c corpusCase, cfg InputProfile, body []byte) ([]model.Batch, error) {
	g := f.grant()
	r := bytes.NewReader(body)
	switch c.Format {
	case "openmetrics":
		return DecodeOpenMetrics(f.ctx, g, r, cfg)
	case "remote_write_v1":
		return DecodeRemoteWrite(f.ctx, g, RemoteWriteV1, r, cfg)
	case "remote_write_v2":
		return DecodeRemoteWrite(f.ctx, g, RemoteWriteV2, r, cfg)
	default:
		return DecodeLokiPush(f.ctx, g, r, cfg)
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

// canonical round-trips through JSON so numbers and maps compare structurally.
func canonical(t testing.TB, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func sortedProjection(t testing.TB, list []any) []string {
	out := make([]string, len(list))
	for i, v := range list {
		raw, err := json.Marshal(canonical(t, v))
		if err != nil {
			t.Fatal(err)
		}
		out[i] = string(raw)
	}
	sort.Strings(out)
	return out
}

func projectBatches(t testing.TB, batches []model.Batch) []any {
	var out []any
	for _, b := range batches {
		for _, r := range b.Records {
			out = append(out, project(r))
		}
	}
	return out
}
