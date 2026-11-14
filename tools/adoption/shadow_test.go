// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// ---- synthetic fixture: isolated in-process destination, no customer data ----

const (
	shadowTestSource  = "legacy-source-alpha" // synthetic label, never a real system
	shadowTestVersion = "legacy-2.7.1"
	shadowT0ms        = int64(1_700_000_000_000)
	shadowT0ns        = shadowT0ms * 1_000_000
)

type shadowFx struct {
	t    *testing.T
	ctx  context.Context
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	sp   model.SourcePolicy
	m    SourceMapping
	p    ShadowPolicy
	dest SoundpostDestination
	ids  shadowIDs
}

func shadowTestScalar(t testing.TB, s string) model.Scalar {
	t.Helper()
	var v model.Scalar
	if err := v.UnmarshalJSON([]byte(strconv.Quote(s))); err != nil {
		t.Fatal(err)
	}
	return v
}

func shadowTestSourcePolicy(t testing.TB, res model.Resource) model.SourcePolicy {
	line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 64, Sensitivity: "metadata", Values: []model.Scalar{shadowTestScalar(t, "alpha"), shadowTestScalar(t, "beta")}}
	tenant := model.TemplateField{Name: "tenant", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{shadowTestScalar(t, "t1")}}
	return model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log},
		Templates:     []model.LogTemplate{{ID: "migrated.meta", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line, tenant}}, shadowTestFileTemplates(t)[0]},
		Resources:     model.ResourceRegistry{Services: []model.ID{res.Service}, Environments: []model.ID{res.Environment}, Builds: []model.ID{res.Build}, Instances: []string{res.Instance}},
		Labels:        map[string][]string{"job": {"api", "worker"}, "le": {"0.5", "+Inf"}, "app": {"web"}, "region": {"eu", "us"}, "source": {"app"}},
		RetentionDays: map[model.Kind]uint32{model.Metric: 7, model.Log: 7}, MaxBytes: 64 << 20, MaxSeries: 1000,
	}
}

func shadowTestFileTemplates(t testing.TB) []model.LogTemplate {
	unit := model.TemplateField{Name: "unit", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{shadowTestScalar(t, "alpha"), shadowTestScalar(t, "beta")}}
	return []model.LogTemplate{{ID: "svc.started", Revision: 1, Line: "service started unit {unit}", Severity: "info", Fields: []model.TemplateField{unit}}}
}

func shadowTestAdapters(t testing.TB) []ShadowAdapterDeclaration {
	return []ShadowAdapterDeclaration{
		{Kind: ShadowAdapterRemoteWriteV1, Version: "remote-write-1.0", Features: []string{"float_samples", "stale_markers", "native_histograms"}},
		{Kind: ShadowAdapterOpenMetrics, Version: "openmetrics-1.0", Features: []string{"counter", "gauge"}},
		{Kind: ShadowAdapterLokiPush, Version: "loki-push-3.5", Features: []string{"stream_labels", "structured_metadata", "duplicate_lines_preserved"},
			Loki: &ShadowLokiBinding{Encoding: "json", TemplateID: "migrated.meta", TemplateRevision: 1, LineField: "line", MetadataFields: []string{"tenant"}}},
		{Kind: ShadowAdapterConditions, Version: "condition-feed-2", Features: []string{"sequence_ordering"}},
		{Kind: ShadowAdapterLogFile, Version: "file-source-2.1", Features: []string{"templated_lines", "unmatched_lines_dropped_by_reason", "duplicate_lines_preserved"},
			File: &ShadowFileBinding{Name: "app", StreamLabels: map[string]string{"source": "app"}, Templates: shadowTestFileTemplates(t), TimeLayout: "2006-01-02T15:04:05Z07:00"}},
	}
}

func newShadowFx(t *testing.T) *shadowFx {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	fx := &shadowFx{t: t, ctx: context.Background(), pub: pub, priv: priv}
	res := model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "inst-1", Labels: model.Labels{}}
	fx.sp = shadowTestSourcePolicy(t, res)
	digest, err := ShadowSourcePolicyDigest(fx.sp)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	unsigned := SourceMapping{
		SchemaVersion: shadowSchemaVersion, OriginalSource: shadowTestSource, OriginalVersion: shadowTestVersion,
		Org: model.NewID().String(), Project: model.NewID().String(), Source: model.NewID().String(),
		PolicyRevision: 1, SourcePolicySHA256: digest,
		Resource:       ShadowResource{Service: res.Service.String(), Environment: res.Environment.String(), Build: res.Build.String(), Instance: res.Instance},
		MinTimestampNS: 1_600_000_000_000_000_000, MaxTimestampNS: 1_800_000_000_000_000_000,
		Adapters:      shadowTestAdapters(t),
		NotBeforeUnix: now.Add(-time.Hour).Unix(), NotAfterUnix: now.Add(24 * time.Hour).Unix(),
	}
	fx.m = fx.sign(unsigned)
	fx.p = ShadowPolicy{SchemaVersion: shadowSchemaVersion, TrustedKeys: []ShadowTrustedKey{{ID: "k1", PublicKey: pubB64(pub)}},
		AllowedOriginalSources: []string{shadowTestSource}, MaxDeliveries: 1000, MaxBodyBytes: 1 << 20}
	fx.ids, err = shadowParseIDs(fx.m)
	if err != nil {
		t.Fatal(err)
	}
	dest, closeDest, err := ShadowProvision(fx.ctx, filepath.Join(t.TempDir(), "dest"), fx.m, fx.sp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeDest() })
	fx.dest = dest
	return fx
}

func pubB64(pub ed25519.PublicKey) string {
	return shadowB64(pub)
}

func (fx *shadowFx) sign(m SourceMapping) SourceMapping {
	fx.t.Helper()
	out, err := ShadowSignMapping(fx.priv, "k1", m)
	if err != nil {
		fx.t.Fatal(err)
	}
	return out
}

func (fx *shadowFx) deliver(adapter, id string, body []byte) {
	fx.dest.Feed.Deliveries = append(fx.dest.Feed.Deliveries, ShadowDelivery{ID: id, OriginalSource: shadowTestSource, Adapter: adapter, ReceivedAtNS: shadowT0ns + 5_000_000_000, Body: body})
}

func (fx *shadowFx) run() (ShadowReport, error) {
	fx.t.Helper()
	return RunShadow(fx.ctx, fx.m, fx.dest, fx.p)
}

// clone is an independent mapping, policy and feed over the same provisioned
// destination: refusal tests need no second instance.
func (fx *shadowFx) clone() *shadowFx {
	c := *fx
	c.m.Adapters = append([]ShadowAdapterDeclaration(nil), fx.m.Adapters...)
	for i := range c.m.Adapters {
		c.m.Adapters[i].Features = append([]string(nil), fx.m.Adapters[i].Features...)
	}
	c.p.TrustedKeys = append([]ShadowTrustedKey(nil), fx.p.TrustedKeys...)
	c.p.AllowedOriginalSources = append([]string(nil), fx.p.AllowedOriginalSources...)
	c.dest.Feed = ShadowFeed{}
	return &c
}

func (fx *shadowFx) mustRun() ShadowReport {
	fx.t.Helper()
	r, err := fx.run()
	if err != nil {
		fx.t.Fatalf("run: %v", err)
	}
	return r
}

// ---- wire encoders (test side; they follow the published remote-write schema) ----

type shadowPB struct{ b []byte }

func (w *shadowPB) tag(num, wt uint64) { w.b = binary.AppendUvarint(w.b, num<<3|wt) }
func (w *shadowPB) varint(num, v uint64) {
	w.tag(num, 0)
	w.b = binary.AppendUvarint(w.b, v)
}
func (w *shadowPB) fixed64(num, v uint64) {
	w.tag(num, 1)
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
}
func (w *shadowPB) bytes(num uint64, b []byte) {
	w.tag(num, 2)
	w.b = binary.AppendUvarint(w.b, uint64(len(b)))
	w.b = append(w.b, b...)
}
func (w *shadowPB) msg(num uint64, f func(*shadowPB)) {
	var inner shadowPB
	f(&inner)
	w.bytes(num, inner.b)
}
func shadowZZ(v int64) uint64 { return uint64(v<<1) ^ uint64(v>>63) }

// shadowSnappy encodes a snappy block of literals only (valid, uncompressed).
func shadowSnappy(src []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(len(src)))
	for len(src) > 0 {
		n := min(len(src), 256)
		if n <= 60 {
			out = append(out, byte(n-1)<<2)
		} else {
			out = append(out, 60<<2, byte(n-1))
		}
		out = append(out, src[:n]...)
		src = src[n:]
	}
	return out
}

type shadowTestHist struct {
	float         bool
	count, zero   uint64 // integer histogram
	countF, zeroF float64
	sum           float64
	spans         [][2]int64
	deltas        []int64
	counts        []float64
	tsMS          int64
}

func (h shadowTestHist) encode() []byte {
	var w shadowPB
	if h.float {
		w.fixed64(2, math.Float64bits(h.countF))
	} else {
		w.varint(1, h.count)
	}
	w.fixed64(3, math.Float64bits(h.sum))
	w.varint(4, shadowZZ(0))
	w.fixed64(5, math.Float64bits(0))
	if h.float {
		w.fixed64(7, math.Float64bits(h.zeroF))
	} else {
		w.varint(6, h.zero)
	}
	for _, s := range h.spans {
		w.msg(11, func(m *shadowPB) {
			m.varint(1, shadowZZ(s[0]))
			m.varint(2, uint64(s[1]))
		})
	}
	if h.float {
		var inner shadowPB
		for _, c := range h.counts {
			inner.b = binary.LittleEndian.AppendUint64(inner.b, math.Float64bits(c))
		}
		w.bytes(13, inner.b)
	} else {
		var inner shadowPB
		for _, d := range h.deltas {
			inner.b = binary.AppendUvarint(inner.b, shadowZZ(d))
		}
		w.bytes(12, inner.b)
	}
	w.varint(15, uint64(h.tsMS))
	return w.b
}

type shadowTestSample struct {
	tsMS int64
	bits uint64
}

type shadowTestSeries struct {
	labels  [][2]string
	samples []shadowTestSample
	hists   []shadowTestHist
}

const shadowStaleBits = uint64(0x7ff0000000000002)

func shadowRW(series ...shadowTestSeries) []byte {
	var w shadowPB
	for _, s := range series {
		w.msg(1, func(ts *shadowPB) {
			for _, p := range s.labels {
				ts.msg(1, func(l *shadowPB) {
					l.bytes(1, []byte(p[0]))
					l.bytes(2, []byte(p[1]))
				})
			}
			for _, sm := range s.samples {
				ts.msg(2, func(m *shadowPB) {
					m.fixed64(1, sm.bits)
					m.varint(2, uint64(sm.tsMS))
				})
			}
			for _, h := range s.hists {
				ts.bytes(4, h.encode())
			}
		})
	}
	return shadowSnappy(w.b)
}

func shadowF(v float64) uint64 { return math.Float64bits(v) }

func shadowLabels(name, job string) [][2]string {
	return [][2]string{{"__name__", name}, {"job", job}}
}

func shadowLoki(lines ...string) []byte {
	var values [][]any
	for _, l := range lines {
		values = append(values, []any{"1700000000123456789", l, map[string]string{"tenant": "t1"}})
	}
	raw, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"app": "web", "region": "eu"}, "values": values}}})
	return raw
}

func shadowCond(name string, seq uint64, status string, atOffsetS int64) ShadowConditionInput {
	return ShadowConditionInput{Condition: name, Epoch: "epoch-1", Sequence: seq, AtNS: shadowT0ns + atOffsetS*1_000_000_000, Status: status, Severity: "major", Labels: map[string]string{"team": "core"}}
}

func shadowCondBody(events ...ShadowConditionInput) []byte {
	raw, _ := json.Marshal(map[string]any{"events": events})
	return raw
}

func shadowInstant(id, expr string, atMS int64, expect ShadowAnswer) ShadowQueryCase {
	return ShadowQueryCase{ID: id, Language: "promql", Profile: "promql-prometheus-3.1.0", Features: []string{}, Expression: expr, AtNS: atMS * 1_000_000, Expect: expect}
}

func shadowLogRange(id, expr string, expect ShadowAnswer) ShadowQueryCase {
	return ShadowQueryCase{ID: id, Language: "logql", Profile: "logql-loki-3.5.2", Features: []string{}, Expression: expr,
		StartNS: 1_700_000_000_000_000_000, EndNS: 1_700_000_001_000_000_000, StepNS: 1_000_000_000, LogOrder: "forward", Expect: expect}
}

func shadowMismatchFields(r ShadowParityReport) map[string]int {
	out := map[string]int{}
	for _, m := range r.Mismatches {
		out[m.Domain+"/"+m.Field]++
	}
	return out
}

// ---- the three named tests ----

func TestShadowCannotSendNormalNotifications(t *testing.T) {
	var hits atomic.Int64
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer legacy.Close()

	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "d1", shadowCondBody(shadowCond("disk-full", 1, "firing", 0)))

	// Every attempt to enable a sender, normal delivery or raw acceptance is an
	// explicit refusal, never ignored, and nothing is admitted.
	refusals := []struct {
		name   string
		mutate func(*ShadowPolicy)
		want   error
	}{
		{"external delivery flag", func(p *ShadowPolicy) { p.ExternalDelivery = true }, ErrShadowExternalDelivery},
		{"enabled sender endpoint", func(p *ShadowPolicy) { p.EnabledSenders = []string{legacy.URL} }, ErrShadowExternalDelivery},
		{"enabled empty sender", func(p *ShadowPolicy) { p.EnabledSenders = []string{""} }, ErrShadowExternalDelivery},
		{"raw source acceptance", func(p *ShadowPolicy) { p.AcceptRawSources = true }, ErrShadowRawSource},
		{"disable legacy sender", func(p *ShadowPolicy) { p.DisableLegacySenders = true }, ErrShadowLegacySender},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			pol := fx.p
			c.mutate(&pol)
			r, err := RunShadow(fx.ctx, fx.m, fx.dest, pol)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if r.Records.Received != 0 || r.Deliveries.Received != 0 || len(r.Ledger) != 0 {
				t.Fatalf("a refused policy processed deliveries: %+v", r.Records)
			}
		})
	}

	// A policy file that names a sender field the schema does not have is refused too.
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"senders":["`+legacy.URL+`"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var parsed ShadowPolicy
	if err := shadowReadJSON(path, &parsed); err == nil {
		t.Fatal("unknown sender field was silently ignored")
	}

	// A valid no-send run decides what the product would send, and sends nothing.
	rep := fx.mustRun()
	if rep.NormalDeliveriesSent != 0 || rep.ExternalSendAttempts != 0 {
		t.Fatalf("sends recorded: %+v", rep)
	}
	if rep.Decisions.Total == 0 || rep.Decisions.WouldDeliver == 0 {
		t.Fatalf("a major firing condition must produce would-deliver decisions: %+v", rep.Decisions)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the legacy sender endpoint received %d requests", n)
	}
}

func TestSourceRetryLateRecoveryPreservesVersion(t *testing.T) {
	fx := newShadowFx(t)
	name := "disk-full"
	fx.deliver(ShadowAdapterConditions, "d1", shadowCondBody(shadowCond(name, 1, "firing", 0)))
	fx.deliver(ShadowAdapterConditions, "d2", shadowCondBody(shadowCond(name, 3, "firing", 20)))
	// The delayed v2 recovered arrives after v3 firing, and is retried.
	fx.deliver(ShadowAdapterConditions, "d3", shadowCondBody(shadowCond(name, 2, "recovered", 10)))
	fx.deliver(ShadowAdapterConditions, "d4", shadowCondBody(shadowCond(name, 3, "firing", 20)))
	fx.deliver(ShadowAdapterConditions, "d5", shadowCondBody(shadowCond(name, 2, "recovered", 10)))
	// A conflicting replay of an accepted (epoch, sequence) is rejected, not merged.
	fx.deliver(ShadowAdapterConditions, "d6", shadowCondBody(shadowCond(name, 3, "recovered", 20)))

	rep := fx.mustRun()
	if len(rep.Conditions) != 1 {
		t.Fatalf("conditions: %+v", rep.Conditions)
	}
	c := rep.Conditions[0]
	if c.Name != name || c.SourceVersion != 3 || c.Phase != "firing" || c.Accepted != 2 {
		t.Fatalf("the delayed v2 recovered overwrote the v3 firing state: %+v", c)
	}
	if rep.Decisions.Kinds["recovery"] != 0 || rep.Decisions.Kinds["open"] != 1 {
		t.Fatalf("a late recovery produced a decision or the open was lost: %+v", rep.Decisions.Kinds)
	}
	want := map[string]int{shadowReasonLateVersion: 2, shadowReasonDuplicateEvent: 1, shadowReasonConflictingReplay: 1}
	if !reflect.DeepEqual(rep.Records.DroppedByReason, want) || rep.Records.Received != 6 || rep.Records.Admitted != 2 || rep.Records.Dropped != 4 || !rep.Reconciled {
		t.Fatalf("ledger: %+v reconciled=%v", rep.Records, rep.Reconciled)
	}

	// A fresh v4 recovered is a real recovery and does move the state.
	fx.deliver(ShadowAdapterConditions, "d7", shadowCondBody(shadowCond(name, 4, "recovered", 30)))
	rep = fx.mustRun()
	c = rep.Conditions[0]
	if c.SourceVersion != 4 || c.Phase != "recovered" || rep.Decisions.Kinds["recovery"] != 1 {
		t.Fatalf("a newer recovery must apply: %+v %+v", c, rep.Decisions.Kinds)
	}

	// Parity against the legacy answer: the legacy v3-firing answer matches; a
	// naive last-delivered-wins answer (v2 recovered) is a lifecycle mismatch.
	fx.dest.Feed.Deliveries = fx.dest.Feed.Deliveries[:6]
	rep = fx.mustRun()
	fx.dest.Feed.Parity = &ShadowParitySpec{Conditions: []ShadowConditionExpectation{{Condition: name, SourceVersion: 3, Phase: "firing", Freshness: "fresh"}}}
	if r := fx.mustRun(); !r.Parity.Equal() || r.Parity.LifecycleCompared != 1 {
		t.Fatalf("parity: %+v", r.Parity)
	}
	fx.dest.Feed.Parity = &ShadowParitySpec{Conditions: []ShadowConditionExpectation{{Condition: name, SourceVersion: 2, Phase: "recovered", Freshness: "fresh"}}}
	r := fx.mustRun()
	if got := shadowMismatchFields(r.Parity); got["lifecycle/version"] != 1 || got["lifecycle/phase"] != 1 || len(r.Parity.Mismatches) != 2 {
		t.Fatalf("overwritten legacy answer must mismatch on version and phase: %+v", r.Parity.Mismatches)
	}

	// Decision-level parity: mirror the shadow decisions as the legacy stream.
	var legacy []ShadowLegacyDecision
	for i, d := range rep.Decisions.Items {
		legacy = append(legacy, ShadowLegacyDecision{Condition: d.Condition, Kind: d.Kind, ImpactRevision: d.ImpactRevision, Ordinal: d.Ordinal, Recipient: d.Recipient, SourceVersion: d.SourceVersion, DedupID: fmt.Sprintf("legacy-%d", i), Suppression: d.Suppression})
	}
	if len(legacy) == 0 {
		t.Fatal("no shadow decisions to compare")
	}
	fx.dest.Feed.Parity = &ShadowParitySpec{LegacyDecisions: legacy}
	if r := fx.mustRun(); !r.Parity.Equal() || r.Parity.DecisionsCompared != len(legacy) {
		t.Fatalf("mirrored legacy decisions must match: %+v", r.Parity)
	}
	// A legacy that also sent a recovery at v2 is only_legacy, a wrong version is source_version.
	wrong := append([]ShadowLegacyDecision(nil), legacy...)
	wrong = append(wrong, ShadowLegacyDecision{Condition: name, Kind: "recovery", ImpactRevision: 1, Ordinal: 1, SourceVersion: 2, DedupID: "legacy-late"})
	fx.dest.Feed.Parity = &ShadowParitySpec{LegacyDecisions: wrong}
	if got := shadowMismatchFields(fx.mustRun().Parity); got["decision/only_legacy"] == 0 {
		t.Fatalf("legacy recovery must be flagged: %v", got)
	}
	skew := append([]ShadowLegacyDecision(nil), legacy...)
	skew[0].SourceVersion++
	fx.dest.Feed.Parity = &ShadowParitySpec{LegacyDecisions: skew}
	if got := shadowMismatchFields(fx.mustRun().Parity); got["decision/source_version"] == 0 {
		t.Fatalf("version skew must be flagged: %v", got)
	}
}

func TestAdapterDoesNotDropHistogramOrStale(t *testing.T) {
	fx := newShadowFx(t)
	intHist := shadowTestHist{count: 4, zero: 1, sum: 10.5, spans: [][2]int64{{0, 2}}, deltas: []int64{1, 1}, tsMS: shadowT0ms}
	floatHist := shadowTestHist{float: true, countF: 6, zeroF: 1, sum: 7.5, spans: [][2]int64{{0, 2}}, counts: []float64{2, 3}, tsMS: shadowT0ms}
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw-1", shadowRW(
		shadowTestSeries{labels: shadowLabels("requests_total", "api"), samples: []shadowTestSample{{shadowT0ms + 123, shadowF(12)}, {shadowT0ms + 1123, shadowStaleBits}}},
		shadowTestSeries{labels: shadowLabels("latency", "api"), hists: []shadowTestHist{intHist}},
		shadowTestSeries{labels: shadowLabels("size_distribution", "worker"), hists: []shadowTestHist{floatHist}},
	))
	// Duplicate log lines: two equal records and one distinct, at the same instant.
	fx.deliver(ShadowAdapterLokiPush, "loki-1", shadowLoki("alpha", "alpha", "beta"))
	rep := fx.mustRun()
	if rep.Semantics.NativeHistogramsAdmitted != 2 || rep.Semantics.StaleMarkersAdmitted != 1 || rep.Semantics.DuplicateLogLinesPreserved != 1 {
		t.Fatalf("declared source semantics were dropped: %+v (records %+v, deliveries %+v)", rep.Semantics, rep.Records, rep.Deliveries)
	}
	// 1 float + 1 stale + 2 histograms + 3 log lines, nothing dropped.
	if rep.Records.Received != 7 || rep.Records.Admitted != 7 || rep.Records.Dropped != 0 || !rep.Reconciled {
		t.Fatalf("records: %+v", rep.Records)
	}

	// The owned query engine answers over what was admitted.
	beforeStale := shadowInstant("before-stale", "requests_total", shadowT0ms+500, ShadowAnswer{})
	afterStale := shadowInstant("after-stale", "requests_total", shadowT0ms+2000, ShadowAnswer{})
	hist := shadowInstant("hist", "latency", shadowT0ms+500, ShadowAnswer{})
	hcount := shadowInstant("hcount", "histogram_count(latency)", shadowT0ms+500, ShadowAnswer{})
	logs := shadowLogRange("logs", `{app="web"}`, ShadowAnswer{})
	ans := map[string]ShadowAnswer{}
	for _, c := range []ShadowQueryCase{beforeStale, afterStale, hist, hcount, logs} {
		a, err := shadowAnswer(fx.ctx, fx.dest, c)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		ans[c.ID] = a
	}
	if s := ans["before-stale"].Series; len(s) != 1 || len(s[0].Samples) != 1 || s[0].Samples[0].Bits != "4028000000000000" {
		t.Fatalf("value before the stale marker: %+v", ans["before-stale"])
	}
	if len(ans["after-stale"].Series) != 0 || ans["after-stale"].Unsupported != "" {
		t.Fatalf("the stale marker was dropped: the series is still visible: %+v", ans["after-stale"])
	}
	hs := ans["hist"].Series
	if len(hs) != 1 || len(hs[0].Samples) != 1 || hs[0].Samples[0].Histogram == "" {
		t.Fatalf("native histogram was dropped or flattened: %+v", ans["hist"])
	}
	// The owned PromQL engine evaluates a native histogram as a float histogram.
	var nh model.NativeHistogram
	if err := json.Unmarshal([]byte(hs[0].Samples[0].Histogram), &nh); err != nil || nh.Float == nil || nh.Float.Count != model.FloatBits(shadowF(4)) || nh.Float.ZeroCount != model.FloatBits(shadowF(1)) || nh.Float.Sum != model.FloatBits(shadowF(10.5)) {
		t.Fatalf("native histogram content: %v %+v", err, nh)
	}
	if s := ans["hcount"].Series; len(s) != 1 || len(s[0].Samples) != 1 || s[0].Samples[0].Bits != fmt.Sprintf("%016x", shadowF(4)) {
		t.Fatalf("histogram_count: %+v", ans["hcount"])
	}
	lines := ans["logs"].Lines
	if len(lines) != 3 {
		t.Fatalf("duplicate log lines were collapsed or lost: %+v", lines)
	}
	same := 0
	for _, l := range lines {
		if l.Line == "alpha" {
			same++
		}
	}
	if same != 2 {
		t.Fatalf("equal-time equal-line records were merged: %+v", lines)
	}

	// The same answers are the parity contract: exact bits, exact histogram, exact lines.
	beforeStale.Expect, afterStale.Expect, hist.Expect, hcount.Expect, logs.Expect = ans["before-stale"], ans["after-stale"], ans["hist"], ans["hcount"], ans["logs"]
	fx.dest.Feed.Parity = &ShadowParitySpec{Queries: []ShadowQueryCase{beforeStale, afterStale, hist, hcount, logs}}
	if r := fx.mustRun(); !r.Parity.Equal() || r.Parity.QueriesCompared != 5 {
		t.Fatalf("parity: %+v", r.Parity)
	}

	// An adapter that does not declare native_histograms refuses them explicitly.
	fx2 := fx.clone()
	m := fx2.m
	m.Adapters = shadowTestAdapters(t)
	m.Adapters[0].Features = []string{"float_samples", "stale_markers"}
	fx2.m = fx2.sign(m)
	fx2.deliver(ShadowAdapterRemoteWriteV1, "rw-h", shadowRW(shadowTestSeries{labels: shadowLabels("latency", "api"), hists: []shadowTestHist{intHist}}))
	r2 := fx2.mustRun()
	if r2.Semantics.NativeHistogramsAdmitted != 0 || r2.Deliveries.Rejected != 1 {
		t.Fatalf("undeclared native histogram feature accepted: %+v %+v", r2.Semantics, r2.Deliveries)
	}
	if !reflect.DeepEqual(r2.Deliveries.RejectedByReason, map[string]int{shadowDecodePrefix + "unrepresentable": 1}) {
		t.Fatalf("the adapter must refuse the undeclared native histogram itself: %+v", r2.Deliveries.RejectedByReason)
	}
	// Stale markers need their own declaration.
	fx3 := fx.clone()
	m = fx3.m
	m.Adapters = shadowTestAdapters(t)
	m.Adapters[0].Features = []string{"float_samples", "native_histograms"}
	fx3.m = fx3.sign(m)
	fx3.deliver(ShadowAdapterRemoteWriteV1, "rw-s", shadowRW(shadowTestSeries{labels: shadowLabels("requests_total", "api"), samples: []shadowTestSample{{shadowT0ms, shadowF(1)}, {shadowT0ms + 1000, shadowStaleBits}}}))
	r3 := fx3.mustRun()
	if r3.Semantics.StaleMarkersAdmitted != 0 || r3.Deliveries.RejectedByReason[shadowReasonUndeclaredFeature] != 1 {
		t.Fatalf("undeclared stale marker feature accepted: %+v %+v", r3.Semantics, r3.Deliveries)
	}
}

// ---- boundary tests of our own ----

func TestShadowUnknownRawSourceFailsPolicy(t *testing.T) {
	fx := newShadowFx(t)
	good := shadowRW(shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms, shadowF(3)}}})
	fx.deliver(ShadowAdapterRemoteWriteV1, "ok", good)
	fx.dest.Feed.Deliveries = append(fx.dest.Feed.Deliveries,
		ShadowDelivery{ID: "rogue", OriginalSource: "rogue-source", Adapter: ShadowAdapterRemoteWriteV1, ReceivedAtNS: shadowT0ns, Body: good},
		ShadowDelivery{ID: "undeclared", OriginalSource: shadowTestSource, Adapter: "otlp_grpc", ReceivedAtNS: shadowT0ns, Body: good},
		ShadowDelivery{ID: "empty-source", OriginalSource: "", Adapter: ShadowAdapterRemoteWriteV1, ReceivedAtNS: shadowT0ns, Body: good},
	)
	rep, err := fx.run()
	if !errors.Is(err, ErrShadowPolicyFailed) {
		t.Fatalf("an unmapped source must fail policy explicitly, got %v", err)
	}
	if rep.Deliveries.RejectedByReason[shadowReasonUnmappedSource] != 2 || rep.Deliveries.RejectedByReason[shadowReasonUndeclaredAdapter] != 1 || rep.Deliveries.Rejected != 3 {
		t.Fatalf("explicit reasons missing: %+v", rep.Deliveries)
	}
	if !reflect.DeepEqual(rep.PolicyViolations, []string{shadowReasonUndeclaredAdapter, shadowReasonUnmappedSource}) {
		t.Fatalf("violations: %v", rep.PolicyViolations)
	}
	if rep.Records.Admitted != 1 || rep.Records.Received != 1 || !rep.Reconciled {
		t.Fatalf("only the mapped delivery may be admitted: %+v", rep.Records)
	}
	if rep.Public().PolicyViolations != 2 {
		t.Fatalf("public violation count: %+v", rep.Public())
	}

	// A destination that accepts raw sources is refused up front.
	raw := fx.clone()
	raw.dest.SourcePolicyClass = "restricted_raw"
	if _, err := raw.run(); !errors.Is(err, ErrShadowRawSource) {
		t.Fatalf("raw destination: %v", err)
	}
	// A mapped source the policy does not allow is refused.
	deny := fx.clone()
	deny.p.AllowedOriginalSources = []string{"someone-else"}
	if _, err := deny.run(); !errors.Is(err, ErrShadowPolicy) {
		t.Fatalf("source outside the allow list: %v", err)
	}
	deny.p.AllowedOriginalSources = nil
	if _, err := deny.run(); !errors.Is(err, ErrShadowPolicy) {
		t.Fatalf("empty allow list: %v", err)
	}
}

func TestShadowMappingIsSignedAndVerifiedBeforeUse(t *testing.T) {
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "d1", shadowCondBody(shadowCond("c", 1, "firing", 0)))
	if _, err := fx.run(); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	tampers := map[string]func(*SourceMapping){
		"original source":  func(m *SourceMapping) { m.OriginalSource = "other" },
		"original version": func(m *SourceMapping) { m.OriginalVersion = "legacy-9" },
		"org":              func(m *SourceMapping) { m.Org = model.NewID().String() },
		"project":          func(m *SourceMapping) { m.Project = model.NewID().String() },
		"source":           func(m *SourceMapping) { m.Source = model.NewID().String() },
		"policy revision":  func(m *SourceMapping) { m.PolicyRevision = 2 },
		"policy digest":    func(m *SourceMapping) { m.SourcePolicySHA256 = strings.Repeat("0", 64) },
		"instance":         func(m *SourceMapping) { m.Resource.Instance = "inst-2" },
		"min timestamp":    func(m *SourceMapping) { m.MinTimestampNS++ },
		"max timestamp":    func(m *SourceMapping) { m.MaxTimestampNS++ },
		"adapter version":  func(m *SourceMapping) { m.Adapters[0].Version = "remote-write-1.1" },
		"adapter feature":  func(m *SourceMapping) { m.Adapters[1].Features = append(m.Adapters[1].Features, "summary") },
		"validity":         func(m *SourceMapping) { m.NotAfterUnix += 3600 },
		"key id":           func(m *SourceMapping) { m.KeyID = "k2" },
		"drop adapter":     func(m *SourceMapping) { m.Adapters = m.Adapters[1:] },
	}
	for name, mutate := range tampers {
		t.Run("tamper "+name, func(t *testing.T) {
			m := fx.m
			m.Adapters = append([]ShadowAdapterDeclaration(nil), fx.m.Adapters...)
			for i := range m.Adapters {
				m.Adapters[i].Features = append([]string(nil), fx.m.Adapters[i].Features...)
			}
			mutate(&m)
			rep, err := RunShadow(fx.ctx, m, fx.dest, fx.p)
			if !errors.Is(err, ErrShadowMapping) {
				t.Fatalf("tampered mapping accepted: %v", err)
			}
			if rep.Records.Received != 0 || len(rep.Ledger) != 0 {
				t.Fatal("a refused mapping was used")
			}
		})
	}
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, err := ShadowSignMapping(otherPriv, "k1", fx.m)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*shadowFx){
		"unsigned":        func(f *shadowFx) { f.m.Signature = "" },
		"bad hex":         func(f *shadowFx) { f.m.Signature = "zz" },
		"short signature": func(f *shadowFx) { f.m.Signature = f.m.Signature[:10] },
		"wrong key":       func(f *shadowFx) { f.m = forged },
		"unknown key":     func(f *shadowFx) { f.p.TrustedKeys[0].ID = "k9" },
		"empty trusted key id": func(f *shadowFx) {
			f.p.TrustedKeys[0].ID = ""
			m, err := ShadowSignMapping(f.priv, "", f.m)
			if err != nil {
				t.Fatal(err)
			}
			f.m = m
		},
		"no trusted keys": func(f *shadowFx) { f.p.TrustedKeys = nil },
		"malformed key":   func(f *shadowFx) { f.p.TrustedKeys[0].PublicKey = "AAAA" },
		"expired":         func(f *shadowFx) { f.p.Clock = func() time.Time { return time.Now().Add(48 * time.Hour) } },
		"not yet valid":   func(f *shadowFx) { f.p.Clock = func() time.Time { return time.Now().Add(-48 * time.Hour) } },
		"schema version":  func(f *shadowFx) { f.m.SchemaVersion = 2; f.m = f.sign(f.m) },
		"bad project id":  func(f *shadowFx) { f.m.Project = "nothex"; f.m = f.sign(f.m) },
		"zero org":        func(f *shadowFx) { f.m.Org = model.ID{}.String(); f.m = f.sign(f.m) },
		"empty validity":  func(f *shadowFx) { f.m.NotBeforeUnix, f.m.NotAfterUnix = 0, 0; f.m = f.sign(f.m) },
		"inverted validity": func(f *shadowFx) {
			f.m.NotBeforeUnix, f.m.NotAfterUnix = f.m.NotAfterUnix, f.m.NotBeforeUnix
			f.m = f.sign(f.m)
		},
		"inverted bounds": func(f *shadowFx) {
			f.m.MinTimestampNS, f.m.MaxTimestampNS = f.m.MaxTimestampNS, f.m.MinTimestampNS
			f.m = f.sign(f.m)
		},
		"equal bounds": func(f *shadowFx) {
			f.m.MaxTimestampNS = f.m.MinTimestampNS
			f.m = f.sign(f.m)
		},
		"zero minimum": func(f *shadowFx) {
			f.m.MinTimestampNS = 0
			f.m = f.sign(f.m)
		},
		"short digest": func(f *shadowFx) {
			f.m.SourcePolicySHA256 = "abcd"
			f.m = f.sign(f.m)
		},
		"non hex digest": func(f *shadowFx) {
			f.m.SourcePolicySHA256 = strings.Repeat("z", 64)
			f.m = f.sign(f.m)
		},
		"zero policy revision": func(f *shadowFx) {
			f.m.PolicyRevision = 0
			f.m = f.sign(f.m)
		},
		"empty instance": func(f *shadowFx) {
			f.m.Resource.Instance = ""
			f.m = f.sign(f.m)
		},
		"zero service": func(f *shadowFx) {
			f.m.Resource.Service = model.ID{}.String()
			f.m = f.sign(f.m)
		},
		"validity ends at not-before": func(f *shadowFx) {
			f.m.NotAfterUnix = f.m.NotBeforeUnix
			f.m = f.sign(f.m)
		},
		"empty source":     func(f *shadowFx) { f.m.OriginalSource = ""; f.m = f.sign(f.m) },
		"wildcard version": func(f *shadowFx) { f.m.OriginalVersion = "*"; f.m = f.sign(f.m) },
		"empty version":    func(f *shadowFx) { f.m.OriginalVersion = ""; f.m = f.sign(f.m) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := fx.clone()
			mutate(f)
			if _, err := f.run(); !errors.Is(err, ErrShadowMapping) {
				t.Fatalf("refusal expected, got %v", err)
			}
		})
	}
}

func TestShadowDestinationMustMatchMapping(t *testing.T) {
	fx := newShadowFx(t)
	cases := map[string]func(*SoundpostDestination){
		"org":       func(d *SoundpostDestination) { d.Org = model.NewID() },
		"project":   func(d *SoundpostDestination) { d.Project = model.NewID() },
		"source":    func(d *SoundpostDestination) { d.Source = model.NewID() },
		"revision":  func(d *SoundpostDestination) { d.PolicyRevision = 2 },
		"digest":    func(d *SoundpostDestination) { d.SourcePolicySHA256 = strings.Repeat("a", 64) },
		"no app":    func(d *SoundpostDestination) { d.App = nil },
		"no reader": func(d *SoundpostDestination) { d.Reader = nil },
		"no source": func(d *SoundpostDestination) { d.Credential = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			d := fx.dest
			mutate(&d)
			if _, err := RunShadow(fx.ctx, fx.m, d, fx.p); !errors.Is(err, ErrShadowDestination) {
				t.Fatalf("destination mismatch accepted: %v", err)
			}
		})
	}
	// The provisioner refuses a source policy other than the one the mapping binds,
	// and an existing directory.
	other := fx.sp
	other.MaxSeries++
	if _, _, err := ShadowProvision(fx.ctx, filepath.Join(t.TempDir(), "x"), fx.m, other); !errors.Is(err, ErrShadowDestination) {
		t.Fatalf("policy swap: %v", err)
	}
	if _, _, err := ShadowProvision(fx.ctx, t.TempDir(), fx.m, fx.sp); !errors.Is(err, ErrShadowDestination) {
		t.Fatalf("existing directory: %v", err)
	}
}

func TestShadowAdapterDeclarationsAreVersionedAndNeverGeneric(t *testing.T) {
	loki := &ShadowLokiBinding{Encoding: "json", TemplateID: "migrated.meta", TemplateRevision: 1, LineField: "line", MetadataFields: []string{"tenant"}}
	fileBinding := &ShadowFileBinding{Name: "app", StreamLabels: map[string]string{"source": "app"}, Templates: shadowTestFileTemplates(t)}
	bad := map[string][]ShadowAdapterDeclaration{
		"empty version":          {{Kind: ShadowAdapterOpenMetrics, Version: "", Features: []string{"gauge"}}},
		"star version":           {{Kind: ShadowAdapterOpenMetrics, Version: "*", Features: []string{"gauge"}}},
		"partial wildcard":       {{Kind: ShadowAdapterOpenMetrics, Version: "1.*", Features: []string{"gauge"}}},
		"any version":            {{Kind: ShadowAdapterOpenMetrics, Version: "any", Features: []string{"gauge"}}},
		"latest version":         {{Kind: ShadowAdapterOpenMetrics, Version: "latest", Features: []string{"gauge"}}},
		"compatible":             {{Kind: ShadowAdapterOpenMetrics, Version: "compatible", Features: []string{"gauge"}}},
		"no digit":               {{Kind: ShadowAdapterOpenMetrics, Version: "openmetrics", Features: []string{"gauge"}}},
		"spaces":                 {{Kind: ShadowAdapterOpenMetrics, Version: "1.0 beta", Features: []string{"gauge"}}},
		"no features":            {{Kind: ShadowAdapterOpenMetrics, Version: "1.0"}},
		"empty features":         {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{}}},
		"wildcard feature":       {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"*"}}},
		"all feature":            {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"all"}}},
		"unknown feature":        {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"native_histograms"}}},
		"duplicate feature":      {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"gauge", "gauge"}}},
		"generic kind":           {{Kind: "generic", Version: "1.0", Features: []string{"gauge"}}},
		"empty kind":             {{Kind: "", Version: "1.0", Features: []string{"gauge"}}},
		"duplicate kind":         {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"gauge"}}, {Kind: ShadowAdapterOpenMetrics, Version: "1.1", Features: []string{"gauge"}}},
		"loki unbound":           {{Kind: ShadowAdapterLokiPush, Version: "3.5", Features: []string{"stream_labels"}}},
		"loki bad encoding":      {{Kind: ShadowAdapterLokiPush, Version: "3.5", Features: []string{"stream_labels"}, Loki: &ShadowLokiBinding{Encoding: "xml", TemplateID: "t", TemplateRevision: 1, LineField: "line"}}},
		"loki no template":       {{Kind: ShadowAdapterLokiPush, Version: "3.5", Features: []string{"stream_labels"}, Loki: &ShadowLokiBinding{Encoding: "json", LineField: "line"}}},
		"binding on other":       {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"gauge"}, Loki: loki}},
		"loki revision zero":     {{Kind: ShadowAdapterLokiPush, Version: "3.5", Features: []string{"stream_labels"}, Loki: &ShadowLokiBinding{Encoding: "json", TemplateID: "t", LineField: "line"}}},
		"loki repeated metadata": {{Kind: ShadowAdapterLokiPush, Version: "3.5", Features: []string{"stream_labels"}, Loki: &ShadowLokiBinding{Encoding: "json", TemplateID: "t", TemplateRevision: 1, LineField: "line", MetadataFields: []string{"tenant", "tenant"}}}},
		"loki empty metadata":    {{Kind: ShadowAdapterLokiPush, Version: "3.5", Features: []string{"stream_labels"}, Loki: &ShadowLokiBinding{Encoding: "json", TemplateID: "t", TemplateRevision: 1, LineField: "line", MetadataFields: []string{""}}}},
		"file binding on other":  {{Kind: ShadowAdapterOpenMetrics, Version: "1.0", Features: []string{"gauge"}, File: fileBinding}},
		"loki binding on file":   {{Kind: ShadowAdapterLogFile, Version: "1.0", Features: []string{"templated_lines"}, File: fileBinding, Loki: loki}},
		"file unbound":           {{Kind: ShadowAdapterLogFile, Version: "1.0", Features: []string{"templated_lines"}}},
		"file bad name":          {{Kind: ShadowAdapterLogFile, Version: "1.0", Features: []string{"templated_lines"}, File: &ShadowFileBinding{Name: "Bad Name", Templates: fileBinding.Templates}}},
		"file no templates":      {{Kind: ShadowAdapterLogFile, Version: "1.0", Features: []string{"templated_lines"}, File: &ShadowFileBinding{Name: "app"}}},
		"file bad time layout":   {{Kind: ShadowAdapterLogFile, Version: "1.0", Features: []string{"templated_lines"}, File: &ShadowFileBinding{Name: "app", Templates: fileBinding.Templates, TimeLayout: "not a layout"}}},
		"file unknown feature":   {{Kind: ShadowAdapterLogFile, Version: "1.0", Features: []string{"native_histograms"}, File: fileBinding}},
		"latest suffix":          {{Kind: ShadowAdapterOpenMetrics, Version: "2.0-latest", Features: []string{"gauge"}}},
		"any prefix":             {{Kind: ShadowAdapterOpenMetrics, Version: "any-1", Features: []string{"gauge"}}},
		"x component":            {{Kind: ShadowAdapterOpenMetrics, Version: "1.x", Features: []string{"gauge"}}},
		"too long":               {{Kind: ShadowAdapterOpenMetrics, Version: "1" + strings.Repeat("0", 64), Features: []string{"gauge"}}},
		"no adapters":            {},
	}
	base := newShadowFx(t)
	for name, list := range bad {
		t.Run(name, func(t *testing.T) {
			fx := base.clone()
			m := fx.m
			m.Adapters = list
			fx.m = fx.sign(m)
			rep, err := fx.run()
			if !errors.Is(err, ErrShadowAdapter) {
				t.Fatalf("generic or empty declaration accepted: %v", err)
			}
			if rep.Records.Received != 0 {
				t.Fatal("a refused declaration was used")
			}
		})
	}
	good := []ShadowAdapterDeclaration{{Kind: ShadowAdapterOpenMetrics, Version: "openmetrics-1.0", Features: []string{"gauge"}}}
	fx := base.clone()
	m := fx.m
	m.Adapters = good
	fx.m = fx.sign(m)
	if _, err := fx.run(); err != nil {
		t.Fatalf("a specific declaration must be accepted: %v", err)
	}
}

func TestShadowLedgerReconcilesPerReasonWithProvenance(t *testing.T) {
	fx := newShadowFx(t)
	series := shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms + 100, shadowF(1)}, {shadowT0ms + 200, shadowF(2)}}}
	body := shadowRW(series)
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw-1", body)
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw-1", body) // retry after an ambiguous ACK
	// Identical points inside one delivery collapse and are counted, not lost.
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw-2", shadowRW(shadowTestSeries{labels: shadowLabels("other_depth", "api"), samples: []shadowTestSample{{shadowT0ms, shadowF(5)}, {shadowT0ms, shadowF(5)}}}))
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw-bad", []byte("not snappy"))
	// A label the source policy does not allow is a policy drop with a reason.
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw-label", shadowRW(shadowTestSeries{labels: [][2]string{{"__name__", "scoped"}, {"project", model.NewID().String()}}, samples: []shadowTestSample{{shadowT0ms, shadowF(1)}}}))
	fx.deliver(ShadowAdapterLokiPush, "loki-1", shadowLoki("alpha", "beta"))
	fx.deliver(ShadowAdapterLokiPush, "loki-2", shadowLoki("not-an-approved-value"))
	fx.deliver(ShadowAdapterConditions, "c-1", shadowCondBody(shadowCond("a", 1, "firing", 0), shadowCond("a", 1, "firing", 0), shadowCond("b", 1, "bogus-status", 0)))
	fx.deliver(ShadowAdapterConditions, "c-bad", []byte("{"))
	rep, err := fx.run()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Reconciled {
		t.Fatalf("not reconciled: %+v", rep)
	}
	// Recompute every total independently from the ledger rows.
	byReason, admitted, received := map[string]int{}, 0, 0
	perAdapter := map[string]int{}
	for _, e := range rep.Ledger {
		if e.Kind == "delivery" {
			continue
		}
		received++
		perAdapter[e.Adapter]++
		if e.Outcome == "admitted" {
			admitted++
			if e.Reason != "" {
				t.Fatalf("admitted row with a reason: %+v", e)
			}
			continue
		}
		if e.Outcome != "dropped" || e.Reason == "" {
			t.Fatalf("row without outcome or reason: %+v", e)
		}
		byReason[e.Reason]++
	}
	if received != rep.Records.Received || admitted != rep.Records.Admitted || !reflect.DeepEqual(byReason, rep.Records.DroppedByReason) {
		t.Fatalf("report disagrees with ledger: %+v vs received=%d admitted=%d %v", rep.Records, received, admitted, byReason)
	}
	sum := 0
	for _, n := range rep.Records.DroppedByReason {
		sum += n
	}
	if rep.Records.Received != rep.Records.Admitted+sum || sum != rep.Records.Dropped {
		t.Fatalf("admitted+dropped != received: %+v", rep.Records)
	}
	for kind, n := range perAdapter {
		c := rep.PerAdapter[kind]
		if c.Received != n || c.Received != c.Admitted+c.Dropped {
			t.Fatalf("per adapter %s: %+v want received %d", kind, c, n)
		}
	}
	// Exact expectations by reason.
	if rep.Records.DroppedByReason[shadowReasonDuplicateRetry] != 2 || rep.Records.DroppedByReason[shadowReasonExactDuplicate] != 1 {
		t.Fatalf("duplicate reasons: %v", rep.Records.DroppedByReason)
	}
	if rep.Records.DroppedByReason[shadowReasonDuplicateEvent] != 1 || rep.Records.DroppedByReason[shadowReasonInvalidEvent] != 1 {
		t.Fatalf("condition reasons: %v", rep.Records.DroppedByReason)
	}
	admissionDrops := 0
	for reason, n := range rep.Records.DroppedByReason {
		if strings.HasPrefix(reason, shadowAdmissionPrefix) {
			admissionDrops += n
		}
	}
	if admissionDrops < 2 {
		t.Fatalf("policy drops for the unallowed label and the unapproved log value: %v", rep.Records.DroppedByReason)
	}
	if rep.Deliveries.Received != 9 || rep.Deliveries.Rejected != 2 || rep.Deliveries.Accepted != 7 || rep.Deliveries.RejectedByReason[shadowReasonMalformedBody] != 1 {
		t.Fatalf("deliveries: %+v", rep.Deliveries)
	}
	dl := 0
	for _, e := range rep.Ledger {
		if e.Kind == "delivery" {
			dl++
		}
	}
	if dl != rep.Deliveries.Rejected {
		t.Fatalf("delivery ledger rows %d", dl)
	}

	// Provenance and dedup identity: a retried record has the same dedup ID as
	// the record it duplicates; distinct records have distinct IDs.
	byDedup := map[string][]ShadowLedgerEntry{}
	for _, e := range rep.Ledger {
		if e.Seq <= 0 || e.OriginalSource != shadowTestSource || e.OriginalVersion != shadowTestVersion || e.DeliveryID == "" || e.Adapter == "" || e.AdapterVersion == "" || len(e.DedupID) != 64 {
			t.Fatalf("incomplete provenance: %+v", e)
		}
		byDedup[e.DedupID] = append(byDedup[e.DedupID], e)
	}
	retried := 0
	for _, rows := range byDedup {
		for _, r := range rows {
			if r.Reason == shadowReasonDuplicateRetry {
				retried++
				if rows[0].Outcome != "admitted" || rows[0].DeliveryID != "rw-1" {
					t.Fatalf("retry does not point at the admitted original: %+v", rows)
				}
			}
		}
	}
	if retried != 2 {
		t.Fatalf("retried rows %d", retried)
	}
	if rep.LedgerDigest == "" || len(rep.LedgerDigest) != 64 {
		t.Fatalf("ledger digest %q", rep.LedgerDigest)
	}
	// The ledger is deterministic for equal input on the same mapping.
	again := fx.mustRunAllowViolations()
	if again.LedgerDigest != rep.LedgerDigest {
		t.Fatal("the ledger digest is not stable across replays of the same feed")
	}
}

func (fx *shadowFx) mustRunAllowViolations() ShadowReport {
	fx.t.Helper()
	r, err := fx.run()
	if err != nil && !errors.Is(err, ErrShadowPolicyFailed) {
		fx.t.Fatal(err)
	}
	return r
}

func TestShadowRetriesAreIdempotentInStorage(t *testing.T) {
	fx := newShadowFx(t)
	body := shadowRW(shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms + 100, shadowF(1)}, {shadowT0ms + 200, shadowF(2)}}})
	for range 3 {
		fx.deliver(ShadowAdapterRemoteWriteV1, "rw", body)
	}
	rep := fx.mustRun()
	if rep.Records.Admitted != 2 || rep.Records.DroppedByReason[shadowReasonDuplicateRetry] != 4 || rep.Records.Received != 6 || rep.BatchesSubmitted != 1 {
		t.Fatalf("records: %+v", rep.Records)
	}
	a, err := shadowAnswer(fx.ctx, fx.dest, shadowInstant("n", "count_over_time(queue_depth[5m])", shadowT0ms+1000, ShadowAnswer{}))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Series) != 1 || a.Series[0].Samples[0].Bits != fmt.Sprintf("%016x", shadowF(2)) {
		t.Fatalf("retries changed what is stored: %+v", a)
	}
}

func TestShadowLabelsNeverGrantScopeOrReadAccess(t *testing.T) {
	fx := newShadowFx(t)
	other := model.NewID().String()
	fx.deliver(ShadowAdapterRemoteWriteV1, "claim", shadowRW(shadowTestSeries{labels: [][2]string{{"__name__", "claims"}, {"project", other}, {"org", other}}, samples: []shadowTestSample{{shadowT0ms, shadowF(1)}}}))
	rep := fx.mustRun()
	if rep.Records.Admitted != 0 || rep.Records.Dropped != 1 {
		t.Fatalf("a telemetry label naming another project must not be admitted: %+v", rep.Records)
	}
	// Queries only ever name the mapped project; there is no way to name another.
	for _, c := range reflect.VisibleFields(reflect.TypeOf(ShadowQueryCase{})) {
		if strings.Contains(strings.ToLower(c.Name), "project") || strings.Contains(strings.ToLower(c.Name), "org") {
			t.Fatalf("query case can name a scope: %s", c.Name)
		}
	}
	// An empty store answers nothing for the label-claimed series.
	a, err := shadowAnswer(fx.ctx, fx.dest, shadowInstant("claims", "claims", shadowT0ms+500, ShadowAnswer{}))
	if err != nil || len(a.Series) != 0 {
		t.Fatalf("label-claimed data is readable: %+v %v", a, err)
	}
}

func TestShadowReconcileDetectsImbalance(t *testing.T) {
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "c", shadowCondBody(shadowCond("a", 1, "firing", 0), shadowCond("a", 1, "firing", 0)))
	good := fx.mustRun()
	if err := shadowReconcile(good); err != nil {
		t.Fatalf("a consistent report must reconcile: %v", err)
	}
	clone := func() ShadowReport {
		raw, _ := json.Marshal(good)
		var r ShadowReport
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	bad := map[string]func(*ShadowReport){
		"admitted inflated": func(r *ShadowReport) { r.Records.Admitted++ },
		"received inflated": func(r *ShadowReport) { r.Records.Received++ },
		"dropped lowered":   func(r *ShadowReport) { r.Records.Dropped-- },
		"reason moved": func(r *ShadowReport) {
			r.Records.DroppedByReason["other"]++
			r.Records.DroppedByReason[shadowReasonDuplicateEvent]--
		},
		"reason removed": func(r *ShadowReport) { delete(r.Records.DroppedByReason, shadowReasonDuplicateEvent) },
		"per adapter received": func(r *ShadowReport) {
			c := r.PerAdapter[ShadowAdapterConditions]
			c.Received++
			r.PerAdapter[ShadowAdapterConditions] = c
		},
		"per adapter admitted": func(r *ShadowReport) {
			c := r.PerAdapter[ShadowAdapterConditions]
			c.Admitted--
			r.PerAdapter[ShadowAdapterConditions] = c
		},
		"ledger row removed":    func(r *ShadowReport) { r.Ledger = r.Ledger[1:] },
		"ledger outcome flip":   func(r *ShadowReport) { r.Ledger[0].Outcome = "dropped"; r.Ledger[0].Reason = "x" },
		"ledger reason cleared": func(r *ShadowReport) { r.Ledger[len(r.Ledger)-1].Reason = "" },
		"unknown outcome":       func(r *ShadowReport) { r.Ledger[0].Outcome = "lost" },
		"delivery tally":        func(r *ShadowReport) { r.Deliveries.Received++ },
		"delivery reason":       func(r *ShadowReport) { r.Deliveries.Rejected++; r.Deliveries.Accepted-- },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			r := clone()
			mutate(&r)
			if err := shadowReconcile(r); !errors.Is(err, ErrShadowReconcile) {
				t.Fatalf("imbalance accepted: %v", err)
			}
		})
	}
}

func TestShadowParityComparesExactAnswersNotCounts(t *testing.T) {
	bits := func(v float64) string { return fmt.Sprintf("%016x", shadowF(v)) }
	series := func(name string, ts int64, b string) ShadowSeries {
		return ShadowSeries{Labels: map[string]string{"__name__": name, "job": "api"}, Samples: []ShadowSample{{TimeNS: ts, Bits: b}}}
	}
	base := ShadowAnswer{Series: []ShadowSeries{series("a", 1, bits(1)), series("b", 1, bits(2))}}
	field := func(w, g ShadowAnswer) map[string]int {
		out := map[string]int{}
		for _, m := range shadowCompareAnswers("q", w, g) {
			if m.Domain != "query" || m.Case != "q" {
				t.Fatalf("mismatch identity: %+v", m)
			}
			out[m.Field]++
		}
		return out
	}
	if got := field(base, base); len(got) != 0 {
		t.Fatalf("equal answers: %v", got)
	}
	reordered := ShadowAnswer{Series: []ShadowSeries{base.Series[1], base.Series[0]}}
	if got := field(base, reordered); len(got) != 0 {
		t.Fatalf("series order is not meaningful: %v", got)
	}
	// Same count of series, one value differs in the last bit.
	ulp := ShadowAnswer{Series: []ShadowSeries{series("a", 1, bits(1)), series("b", 1, bits(math.Nextafter(2, 3)))}}
	if got := field(base, ulp); got["sample_value"] != 1 || len(got) != 1 {
		t.Fatalf("ulp difference: %v", got)
	}
	// NaN payloads are exact: the stale-marker bits are not an ordinary NaN.
	nanA := ShadowAnswer{Series: []ShadowSeries{series("a", 1, "7ff8000000000001")}}
	nanB := ShadowAnswer{Series: []ShadowSeries{series("a", 1, "7ff0000000000002")}}
	if got := field(nanA, nanB); got["sample_value"] != 1 {
		t.Fatalf("NaN payload difference: %v", got)
	}
	if got := field(base, ShadowAnswer{Series: []ShadowSeries{series("a", 2, bits(1)), series("b", 1, bits(2))}}); got["sample_time"] != 1 || len(got) != 1 {
		t.Fatalf("time difference: %v", got)
	}
	if got := field(base, ShadowAnswer{Series: base.Series[:1]}); got["series_missing"] != 1 || len(got) != 1 {
		t.Fatalf("missing series: %v", got)
	}
	if got := field(base, ShadowAnswer{Series: append(append([]ShadowSeries{}, base.Series...), series("c", 1, bits(3)))}); got["series_extra"] != 1 || len(got) != 1 {
		t.Fatalf("extra series: %v", got)
	}
	two := base
	two.Series = []ShadowSeries{{Labels: base.Series[0].Labels, Samples: []ShadowSample{{TimeNS: 1, Bits: bits(1)}, {TimeNS: 2, Bits: bits(1)}}}, base.Series[1]}
	if got := field(base, two); got["sample_count"] != 1 {
		t.Fatalf("sample count: %v", got)
	}
	h1 := ShadowAnswer{Series: []ShadowSeries{{Labels: map[string]string{"__name__": "h"}, Samples: []ShadowSample{{TimeNS: 1, Histogram: `{"integer":{"count":"4"}}`}}}}}
	h2 := ShadowAnswer{Series: []ShadowSeries{{Labels: map[string]string{"__name__": "h"}, Samples: []ShadowSample{{TimeNS: 1, Histogram: `{"integer":{"count":"5"}}`}}}}}
	if got := field(h1, h2); got["sample_histogram"] != 1 || len(got) != 1 {
		t.Fatalf("histogram difference: %v", got)
	}
	if got := field(h1, base); got["series_missing"] == 0 {
		t.Fatalf("histogram vs float: %v", got)
	}
	// Explicit unsupported reasons are compared exactly and replace values.
	un := ShadowAnswer{Unsupported: "invalid"}
	if got := field(un, un); len(got) != 0 {
		t.Fatalf("same unsupported: %v", got)
	}
	if got := field(un, ShadowAnswer{Unsupported: "unsupported"}); got["unsupported_reason"] != 1 || len(got) != 1 {
		t.Fatalf("unsupported reason: %v", got)
	}
	if got := field(un, base); got["unsupported_reason"] != 1 {
		t.Fatalf("expected unsupported but got values: %v", got)
	}
	if got := field(base, un); got["unsupported_reason"] != 1 {
		t.Fatalf("expected values but got unsupported: %v", got)
	}
	// Log lines: order, content, time, labels, multiplicity.
	line := func(s string, ts int64) ShadowLogLine {
		return ShadowLogLine{Labels: map[string]string{"app": "web"}, TimeNS: ts, Line: s, Multiplicity: 1}
	}
	logs := ShadowAnswer{Lines: []ShadowLogLine{line("a", 1), line("a", 1), line("b", 2)}}
	if got := field(logs, logs); len(got) != 0 {
		t.Fatalf("equal logs: %v", got)
	}
	if got := field(logs, ShadowAnswer{Lines: logs.Lines[:2]}); got["line_count"] != 1 {
		t.Fatalf("collapsed duplicate line: %v", got)
	}
	if got := field(logs, ShadowAnswer{Lines: []ShadowLogLine{line("a", 1), line("b", 2), line("a", 1)}}); got["line_value"] == 0 {
		t.Fatalf("line order: %v", got)
	}
	skewT := []ShadowLogLine{line("a", 1), line("a", 3), line("b", 2)}
	if got := field(logs, ShadowAnswer{Lines: skewT}); got["line_time"] != 1 {
		t.Fatalf("line time: %v", got)
	}
	lab := []ShadowLogLine{line("a", 1), line("a", 1), line("b", 2)}
	lab[0].Labels = map[string]string{"app": "api"}
	if got := field(logs, ShadowAnswer{Lines: lab}); got["line_labels"] != 1 {
		t.Fatalf("line labels: %v", got)
	}
	mult := []ShadowLogLine{line("a", 1), line("a", 1), line("b", 2)}
	mult[2].Multiplicity = 2
	if got := field(logs, ShadowAnswer{Lines: mult}); got["line_multiplicity"] != 1 {
		t.Fatalf("multiplicity: %v", got)
	}
	if got := field(ShadowAnswer{String: "x"}, ShadowAnswer{String: "y"}); got["string_value"] != 1 {
		t.Fatalf("string: %v", got)
	}

	// Lifecycle answers: version, phase, freshness, missing condition.
	state := []ShadowCondition{{Name: "a", SourceVersion: 3, Phase: "firing", Freshness: "fresh"}}
	lf := func(want []ShadowConditionExpectation) map[string]int {
		out := map[string]int{}
		for _, m := range shadowCompareLifecycle(want, state) {
			out[m.Field]++
		}
		return out
	}
	if got := lf([]ShadowConditionExpectation{{Condition: "a", SourceVersion: 3, Phase: "firing", Freshness: "fresh"}}); len(got) != 0 {
		t.Fatalf("lifecycle equal: %v", got)
	}
	if got := lf([]ShadowConditionExpectation{{Condition: "a", SourceVersion: 3, Phase: "firing"}}); len(got) != 0 {
		t.Fatalf("freshness is optional: %v", got)
	}
	if got := lf([]ShadowConditionExpectation{{Condition: "a", SourceVersion: 2, Phase: "firing"}}); got["version"] != 1 || len(got) != 1 {
		t.Fatalf("lifecycle version: %v", got)
	}
	if got := lf([]ShadowConditionExpectation{{Condition: "a", SourceVersion: 3, Phase: "recovered"}}); got["phase"] != 1 || len(got) != 1 {
		t.Fatalf("lifecycle phase: %v", got)
	}
	if got := lf([]ShadowConditionExpectation{{Condition: "a", SourceVersion: 3, Phase: "firing", Freshness: "stale"}}); got["freshness"] != 1 || len(got) != 1 {
		t.Fatalf("lifecycle freshness: %v", got)
	}
	if got := lf([]ShadowConditionExpectation{{Condition: "zzz", SourceVersion: 1, Phase: "firing"}}); got["missing_condition"] != 1 {
		t.Fatalf("missing condition: %v", got)
	}
	// Reason tallies are exact in both directions.
	rs := shadowCompareReasons("ledger", map[string]int{"a": 1, "b": 2}, map[string]int{"a": 1, "b": 3, "c": 1})
	if len(rs) != 2 {
		t.Fatalf("reason mismatches: %+v", rs)
	}
	if rs := shadowCompareReasons("ledger", map[string]int{"a": 1}, map[string]int{"a": 1}); len(rs) != 0 {
		t.Fatalf("equal reasons: %+v", rs)
	}
	if rs := shadowCompareReasons("ledger", map[string]int{"a": 1, "z": 0}, map[string]int{"a": 1}); len(rs) != 0 {
		t.Fatalf("zero counts are absent counts: %+v", rs)
	}
}

func TestShadowParityRunsQueriesThroughTheOwnedEngine(t *testing.T) {
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw", shadowRW(shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms + 100, shadowF(7)}}}))
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw", shadowRW(shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms + 100, shadowF(7)}}}))
	want := ShadowAnswer{Series: []ShadowSeries{{Labels: map[string]string{"__name__": "queue_depth", "job": "api"}, Samples: []ShadowSample{{TimeNS: (shadowT0ms + 500) * 1_000_000, Bits: fmt.Sprintf("%016x", shadowF(7))}}}}}
	ok := shadowInstant("depth", "queue_depth", shadowT0ms+500, want)
	broken := shadowInstant("broken", "sum(", shadowT0ms+500, ShadowAnswer{Unsupported: "language.syntax"})
	fx.dest.Feed.Parity = &ShadowParitySpec{Queries: []ShadowQueryCase{ok, broken},
		ExpectedDropReasons: map[string]int{shadowReasonDuplicateRetry: 1}}
	rep := fx.mustRun()
	if !rep.Parity.Equal() || rep.Parity.QueriesCompared != 2 || rep.Parity.LedgerCompared == 0 {
		t.Fatalf("parity: %+v", rep.Parity)
	}
	// One flipped bit, a wrong unsupported reason and a wrong drop tally.
	ok.Expect.Series[0].Samples[0].Bits = fmt.Sprintf("%016x", shadowF(7)+1)
	broken.Expect.Unsupported = "unsupported"
	fx.dest.Feed.Parity = &ShadowParitySpec{Queries: []ShadowQueryCase{ok, broken}, ExpectedDropReasons: map[string]int{shadowReasonDuplicateRetry: 2}, ExpectedRejectReason: map[string]int{"x": 1}}
	got := shadowMismatchFields(fx.mustRun().Parity)
	want2 := map[string]int{"query/sample_value": 1, "query/unsupported_reason": 1, "ledger/reason_count": 2}
	if !reflect.DeepEqual(got, want2) {
		t.Fatalf("mismatches %v, want %v", got, want2)
	}
	// Specs that cannot be evaluated are refused before anything is replayed.
	bad := map[string]ShadowQueryCase{
		"unknown language": {ID: "a", Language: "sql", Profile: "promql-prometheus-3.1.0", Features: []string{}, Expression: "x", AtNS: 1},
		"unknown profile":  {ID: "a", Language: "promql", Profile: "promql-9", Features: []string{}, Expression: "x", AtNS: 1},
		"unknown features": {ID: "a", Language: "promql", Profile: "promql-prometheus-3.1.0", Features: []string{"no-such-feature"}, Expression: "x", AtNS: 1},
		"empty id":         {ID: "", Language: "promql", Profile: "promql-prometheus-3.1.0", Features: []string{}, Expression: "x", AtNS: 1},
		"empty expression": {ID: "a", Language: "promql", Profile: "promql-prometheus-3.1.0", Features: []string{}, AtNS: 1},
		"no evaluation":    {ID: "a", Language: "promql", Profile: "promql-prometheus-3.1.0", Features: []string{}, Expression: "x"},
		"mixed evaluation": {ID: "a", Language: "promql", Profile: "promql-prometheus-3.1.0", Features: []string{}, Expression: "x", AtNS: 1, StartNS: 1, EndNS: 2, StepNS: 1},
		"bad range":        {ID: "a", Language: "logql", Profile: "logql-loki-3.5.2", Features: []string{}, Expression: "x", StartNS: 5, EndNS: 2, StepNS: 1},
	}
	for name, c := range bad {
		t.Run(name, func(t *testing.T) {
			fx.dest.Feed.Parity = &ShadowParitySpec{Queries: []ShadowQueryCase{c}}
			rep, err := fx.run()
			if !errors.Is(err, ErrShadowParitySpec) || rep.Records.Received != 0 {
				t.Fatalf("bad spec accepted: %v", err)
			}
		})
	}
	dup := &ShadowParitySpec{Queries: []ShadowQueryCase{ok, ok}}
	fx.dest.Feed.Parity = dup
	if _, err := fx.run(); !errors.Is(err, ErrShadowParitySpec) {
		t.Fatalf("duplicate case IDs: %v", err)
	}
}

func TestShadowLimitsAndCancellation(t *testing.T) {
	fx := newShadowFx(t)
	fx.p.MaxBodyBytes = 64
	fx.deliver(ShadowAdapterConditions, "big", shadowCondBody(shadowCond("a", 1, "firing", 0), shadowCond("b", 1, "firing", 0)))
	rep := fx.mustRun()
	if rep.Deliveries.RejectedByReason[shadowReasonBodyTooLarge] != 1 || rep.Records.Received != 0 {
		t.Fatalf("oversize body: %+v", rep.Deliveries)
	}
	// The body limit is inclusive: exactly MaxBodyBytes is processed, one less is not.
	body := shadowCondBody(shadowCond("a", 1, "firing", 0))
	edge := fx.clone()
	edge.deliver(ShadowAdapterConditions, "edge", body)
	edge.p.MaxBodyBytes = len(body)
	if r := edge.mustRun(); r.Deliveries.Rejected != 0 || r.Records.Admitted != 1 {
		t.Fatalf("a body of exactly the limit was refused: %+v", r.Deliveries)
	}
	edge.p.MaxBodyBytes = len(body) - 1
	if r := edge.mustRun(); r.Deliveries.RejectedByReason[shadowReasonBodyTooLarge] != 1 {
		t.Fatalf("a body over the limit was processed: %+v", r.Deliveries)
	}
	fx = fx.clone()
	fx.p.MaxBodyBytes = 1 << 20
	fx.p.MaxDeliveries = 2
	for i := range 4 {
		fx.deliver(ShadowAdapterConditions, fmt.Sprintf("d%d", i), shadowCondBody(shadowCond("a", uint64(i+1), "firing", int64(i))))
	}
	rep = fx.mustRun()
	if rep.Deliveries.Received != 4 || rep.Deliveries.RejectedByReason[shadowReasonDeliveryLimit] != 2 || rep.Records.Admitted != 2 || !rep.Reconciled {
		t.Fatalf("delivery limit: %+v %+v", rep.Deliveries, rep.Records)
	}
	cx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunShadow(cx, fx.m, fx.dest, fx.p); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run: %v", err)
	}
	for _, bad := range []func(*ShadowPolicy){
		func(p *ShadowPolicy) { p.SchemaVersion = 0 },
		func(p *ShadowPolicy) { p.MaxDeliveries = 0 },
		func(p *ShadowPolicy) { p.MaxDeliveries = shadowMaxDeliveries + 1 },
		func(p *ShadowPolicy) { p.MaxBodyBytes = 0 },
		func(p *ShadowPolicy) { p.MaxBodyBytes = shadowMaxBodyCeiling + 1 },
	} {
		p := fx.p
		bad(&p)
		if _, err := RunShadow(context.Background(), fx.m, fx.dest, p); !errors.Is(err, ErrShadowPolicy) {
			t.Fatalf("bad policy accepted: %v", err)
		}
	}
}

func TestShadowPublicSummaryIsClosedAndDerivedFromTheReport(t *testing.T) {
	typ := reflect.TypeOf(ShadowPublicSummary{})
	for i := range typ.NumField() {
		switch typ.Field(i).Type.Kind() {
		case reflect.Int, reflect.Bool:
		default:
			t.Fatalf("public field %s is %s: only counters and booleans are publishable", typ.Field(i).Name, typ.Field(i).Type)
		}
	}
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "c", shadowCondBody(shadowCond("secret-condition-name", 1, "firing", 0), shadowCond("secret-condition-name", 1, "firing", 0)))
	fx.deliver(ShadowAdapterConditions, "bad", []byte("{"))
	fx.dest.Feed.Parity = &ShadowParitySpec{Conditions: []ShadowConditionExpectation{{Condition: "secret-condition-name", SourceVersion: 9, Phase: "firing"}}}
	rep := fx.mustRun()
	pub := rep.Public()
	want := ShadowPublicSummary{SchemaVersion: 1, AdapterCount: 5, DeliveriesReceived: 2, DeliveriesRejected: 1, RecordsReceived: 2, RecordsAdmitted: 1, RecordsDropped: 1,
		Reconciled: true, ParityCases: 1, ParityMismatches: 1}
	if pub != want {
		t.Fatalf("public summary %+v want %+v", pub, want)
	}
	raw, _ := json.Marshal(pub)
	for _, secret := range []string{"secret-condition-name", shadowTestSource, shadowTestVersion, "team"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("public summary leaks %q", secret)
		}
	}
}

func TestShadowDuplicateIsNotConfusedWithLateEvent(t *testing.T) {
	fx := newShadowFx(t)
	name := "queue-stuck"
	// v3 firing; then a late v2 recovered that carries the SAME event time as v3
	// (clock-equal producers): it is late history, not a duplicate of v3.
	fx.deliver(ShadowAdapterConditions, "d1", shadowCondBody(shadowCond(name, 3, "firing", 20)))
	fx.deliver(ShadowAdapterConditions, "d2", shadowCondBody(shadowCond(name, 2, "recovered", 20)))
	fx.deliver(ShadowAdapterConditions, "d3", shadowCondBody(shadowCond(name, 3, "firing", 20)))
	rep := fx.mustRun()
	if rep.Records.Received != 3 || rep.Records.Admitted != 1 || rep.Records.DroppedByReason[shadowReasonLateVersion] != 1 || rep.Records.DroppedByReason[shadowReasonDuplicateEvent] != 1 || rep.Records.Dropped != 2 {
		t.Fatalf("classification: %+v", rep.Records)
	}
	if c := rep.Conditions[0]; c.SourceVersion != 3 || c.Phase != "firing" || c.Accepted != 1 {
		t.Fatalf("state: %+v", c)
	}
}

func TestShadowFileSourceUsesTheOwnedSourceAdapter(t *testing.T) {
	fx := newShadowFx(t)
	file := "2023-11-14T22:13:20Z service started unit alpha\n" +
		"2023-11-14T22:13:20Z service started unit alpha\n" + // an equal line is a distinct record
		"2023-11-14T22:13:21Z service started unit beta\n" +
		"2023-11-14T22:13:22Z service started unit gamma\n" + // value the source policy never approved
		"2023-11-14T22:13:23Z free text that matches no registered template\n"
	fx.deliver(ShadowAdapterLogFile, "file-1", []byte(file))
	fx.deliver(ShadowAdapterLogFile, "file-1", []byte(file)) // the same recording delivered again
	// A different recording is new data even though its record ordinals equal the first's.
	fx.deliver(ShadowAdapterLogFile, "file-2", []byte("2023-11-14T22:13:30Z service started unit beta\n2023-11-14T22:13:31Z service started unit alpha\n"))
	rep := fx.mustRun()
	want := map[string]int{shadowSourcePrefix + "unapproved_value": 2, shadowSourcePrefix + "unknown_template": 2, shadowReasonDuplicateRetry: 3}
	if rep.Records.Received != 12 || rep.Records.Admitted != 5 || !reflect.DeepEqual(rep.Records.DroppedByReason, want) || !rep.Reconciled {
		t.Fatalf("file ledger: %+v reconciled=%v", rep.Records, rep.Reconciled)
	}
	if rep.Semantics.DuplicateLogLinesPreserved != 1 {
		t.Fatalf("equal lines were merged or lost: %+v", rep.Semantics)
	}
	if rep.BatchesSubmitted != 2 {
		t.Fatalf("the retried recording was resubmitted: %d batches", rep.BatchesSubmitted)
	}
	// Every line is stored as the owned source typed it: through the owned query engine.
	ask := ShadowQueryCase{ID: "file", Language: "logql", Profile: "logql-loki-3.5.2", Features: []string{}, Expression: `{source="app"}`,
		StartNS: 1_700_000_000_000_000_000, EndNS: 1_700_000_060_000_000_000, StepNS: 1_000_000_000, LogOrder: "forward"}
	a, err := shadowAnswer(fx.ctx, fx.dest, ask)
	if err != nil || len(a.Lines) != 5 {
		t.Fatalf("stored lines: %v %+v", err, a)
	}
	if a.Lines[0].Line != a.Lines[1].Line || a.Lines[0].TimeNS != 1_700_000_000_000_000_000 || a.Lines[2].TimeNS != 1_700_000_001_000_000_000 {
		t.Fatalf("lines or times changed: %+v", a.Lines)
	}
	// Bodies the file source cannot take whole are rejected before anything is written.
	fx.dest.Feed.Deliveries = nil
	fx.deliver(ShadowAdapterLogFile, "no-newline", []byte("2023-11-14T22:13:20Z service started unit alpha"))
	fx.deliver(ShadowAdapterLogFile, "too-long", bytes.Repeat([]byte("2023-11-14T22:13:20Z service started unit alpha\n"), shadowMaxFileLines+1))
	fx.deliver(ShadowAdapterLogFile, "empty", nil)
	rep = fx.mustRun()
	if rep.Deliveries.RejectedByReason[shadowReasonMalformedBody] != 2 || rep.Deliveries.RejectedByReason[shadowReasonFileTooLong] != 1 || rep.Records.Received != 0 {
		t.Fatalf("deliveries: %+v", rep.Deliveries)
	}
	// The limit is inclusive.
	fx.dest.Feed.Deliveries = nil
	fx.deliver(ShadowAdapterLogFile, "max", bytes.Repeat([]byte("2023-11-14T22:13:20Z service started unit beta\n"), shadowMaxFileLines))
	if rep = fx.mustRun(); rep.Deliveries.Rejected != 0 || rep.Records.Received != shadowMaxFileLines {
		t.Fatalf("a file of exactly the line limit: %+v %+v", rep.Deliveries, rep.Records)
	}
}

func TestShadowRejectsInvalidConditionEvents(t *testing.T) {
	fx := newShadowFx(t)
	ok := shadowCond("a", 1, "firing", 0)
	empty, noEpoch, negative, control := ok, ok, ok, ok
	empty.Condition = ""
	noEpoch.Epoch = ""
	negative.AtNS = -1
	control.Condition = "bad\nname"
	status := ok
	status.Status = "exploding"
	severity := ok
	severity.Severity = ""
	fx.deliver(ShadowAdapterConditions, "bad", shadowCondBody(empty, noEpoch, negative, control, status, severity))
	rep := fx.mustRun()
	if rep.Records.Received != 6 || rep.Records.Admitted != 0 || rep.Records.DroppedByReason[shadowReasonInvalidEvent] != 6 || len(rep.Conditions) > 1 {
		t.Fatalf("invalid events: %+v %+v", rep.Records, rep.Conditions)
	}
	// An event list over the limit is rejected, exactly the limit is processed.
	fx.dest.Feed.Deliveries = nil
	var many []ShadowConditionInput
	for i := range shadowMaxCondEvents + 1 {
		many = append(many, shadowCond("a", uint64(i+1), "firing", int64(i)))
	}
	fx.deliver(ShadowAdapterConditions, "many", shadowCondBody(many...))
	fx.deliver(ShadowAdapterConditions, "edge", shadowCondBody(many[:shadowMaxCondEvents]...))
	fx.p.MaxBodyBytes = shadowMaxBodyCeiling
	rep = fx.mustRun()
	if rep.Deliveries.RejectedByReason[shadowReasonMalformedBody] != 1 || rep.Records.Received != shadowMaxCondEvents || rep.Records.Admitted != shadowMaxCondEvents {
		t.Fatalf("event limit: %+v %+v", rep.Deliveries, rep.Records)
	}
	// A body with unknown fields or trailing data is malformed, never partially applied.
	fx.dest.Feed.Deliveries = nil
	fx.deliver(ShadowAdapterConditions, "unknown", []byte(`{"events":[{"condition":"a","epoch":"e","sequence":1,"at_ns":1,"status":"firing","severity":"major","extra":1}]}`))
	fx.deliver(ShadowAdapterConditions, "trailing", append(shadowCondBody(ok), []byte(" {}")...))
	fx.deliver(ShadowAdapterConditions, "none", []byte(`{"events":[]}`))
	if rep = fx.mustRun(); rep.Deliveries.RejectedByReason[shadowReasonMalformedBody] != 3 || rep.Records.Received != 0 {
		t.Fatalf("malformed bodies: %+v", rep.Deliveries)
	}
}

func TestShadowFailedReconciliationFailsTheRun(t *testing.T) {
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "c", shadowCondBody(shadowCond("a", 1, "firing", 0)))
	defer func(old func(ShadowReport) error) { shadowReconcileHook = old }(shadowReconcileHook)
	shadowReconcileHook = func(ShadowReport) error { return fmt.Errorf("%w: forced", ErrShadowReconcile) }
	rep, err := fx.run()
	if !errors.Is(err, ErrShadowReconcile) || rep.Reconciled {
		t.Fatalf("a report that does not reconcile must fail the run: %v reconciled=%v", err, rep.Reconciled)
	}
}

func TestShadowDecisionSummaryCountsSuppressionExactly(t *testing.T) {
	id := shadowDeriveID("c")
	rcpt := shadowDeriveID("r")
	entity := notify.Entity{Kind: notify.EntityCondition, ID: id}
	got := shadowSummarize([]notify.ShadowDecision{
		{Entity: entity, Kind: notify.KindOpen, ImpactRevision: 1, Ordinal: 1, Recipient: &rcpt, SourceVersion: 3},
		{Entity: entity, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 2, SourceVersion: 3, Suppression: notify.CodeMaintenance},
		{Entity: entity, Kind: notify.KindReminder, ImpactRevision: 1, Ordinal: 3, SourceVersion: 4, Suppression: notify.CodeMaintenance},
	}, map[model.ID]string{id: "cond-a"})
	if got.Total != 3 || got.WouldDeliver != 1 || !reflect.DeepEqual(got.Suppressed, map[string]int{string(notify.CodeMaintenance): 2}) || !reflect.DeepEqual(got.Kinds, map[string]int{"open": 1, "reminder": 2}) {
		t.Fatalf("summary: %+v", got)
	}
	if got.Items[0].Recipient != shadowRecipient || got.Items[1].Recipient != "" || got.Items[0].Condition != "cond-a" || got.Items[2].SourceVersion != 4 || got.Items[1].Suppression != string(notify.CodeMaintenance) {
		t.Fatalf("items: %+v", got.Items)
	}
}

func TestShadowReaderScopeMustBeTheMappedProject(t *testing.T) {
	fx, other := newShadowFx(t), newShadowFx(t)
	d := fx.dest
	d.Reader = other.dest.Reader // read access to another org and project
	if _, err := RunShadow(fx.ctx, fx.m, d, fx.p); !errors.Is(err, ErrShadowDestination) {
		t.Fatalf("foreign read scope accepted: %v", err)
	}
}

func TestShadowReconcileChecksEachInvariantOnItsOwn(t *testing.T) {
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "c", shadowCondBody(shadowCond("a", 1, "firing", 0), shadowCond("a", 1, "firing", 0)))
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw", shadowRW(shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms, shadowF(1)}}}))
	good := fx.mustRun()
	clone := func() ShadowReport {
		raw, _ := json.Marshal(good)
		var r ShadowReport
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	bad := map[string]func(*ShadowReport){
		// Received moved between adapters: totals, sums and the ledger still agree.
		"adapter received moved": func(r *ShadowReport) {
			a, b := r.PerAdapter[ShadowAdapterConditions], r.PerAdapter[ShadowAdapterRemoteWriteV1]
			a.Received--
			b.Received++
			r.PerAdapter[ShadowAdapterConditions], r.PerAdapter[ShadowAdapterRemoteWriteV1] = a, b
		},
		// Outcomes swapped between adapters: every sum and every total still agrees.
		"adapter outcomes swapped": func(r *ShadowReport) {
			a, b := r.PerAdapter[ShadowAdapterConditions], r.PerAdapter[ShadowAdapterRemoteWriteV1]
			a.Admitted, a.Dropped, a.DroppedByReason = 2, 0, map[string]int{}
			b.Admitted, b.Dropped, b.DroppedByReason = 0, 1, map[string]int{shadowReasonDuplicateEvent: 1}
			r.PerAdapter[ShadowAdapterConditions], r.PerAdapter[ShadowAdapterRemoteWriteV1] = a, b
		},
		"admitted row carries a reason": func(r *ShadowReport) {
			for i := range r.Ledger {
				if r.Ledger[i].Outcome == "admitted" {
					r.Ledger[i].Reason = "x"
					return
				}
			}
		},
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			r := clone()
			mutate(&r)
			if err := shadowReconcile(r); !errors.Is(err, ErrShadowReconcile) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestShadowFileAndSourceCallsAreReadOnly(t *testing.T) {
	// The owned sources package also contains a scraper that dials out; the shadow
	// tools may use only its file reading and batch building.
	allowed := map[string]bool{"Read": true, "BuildBatches": true, "Identity": true, "SourcePolicy": true, "KindFile": true, "ClassStructured": true,
		"FileSpec": true, "StartBeginning": true, "Checkpoint": true, "AsError": true}
	for _, name := range []string{"shadow.go", "parity.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "sources" && !allowed[sel.Sel.Name] {
					t.Errorf("%s uses sources.%s", name, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

func TestShadowSourcesImportNoNetworkOrProcessPackage(t *testing.T) {
	forbidden := func(path string) bool {
		return path == "net" || strings.HasPrefix(path, "net/") || path == "os/exec" || path == "syscall" || path == "plugin"
	}
	for _, name := range []string{"shadow.go", "parity.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); forbidden(p) {
				t.Fatalf("%s imports %s: the shadow path must not be able to send", name, p)
			}
		}
	}
}

func TestShadowCLIEndToEnd(t *testing.T) {
	fx := newShadowFx(t)
	fx.deliver(ShadowAdapterConditions, "c1", shadowCondBody(shadowCond("cli-condition-name", 1, "firing", 0)))
	fx.deliver(ShadowAdapterRemoteWriteV1, "rw", shadowRW(shadowTestSeries{labels: shadowLabels("queue_depth", "api"), samples: []shadowTestSample{{shadowT0ms + 100, shadowF(7)}}}))
	fx.dest.Feed.Parity = &ShadowParitySpec{Conditions: []ShadowConditionExpectation{{Condition: "cli-condition-name", SourceVersion: 1, Phase: "firing"}}}
	dir := t.TempDir()
	write := func(name string, v any) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	mapping, policyPath := write("mapping.json", fx.m), write("policy.json", fx.p)
	sourcePolicy, capture := write("source-policy.json", fx.sp), write("capture.json", fx.dest.Feed)
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatal(err)
	}
	args := func(report, summary string) []string {
		return []string{"--mapping", mapping, "--policy", policyPath, "--source-policy", sourcePolicy, "--capture", capture, "--workdir", work, "--report", report, "--public-summary", summary}
	}
	report, summary := filepath.Join(dir, "report.json"), filepath.Join(dir, "summary.json")
	if err := runShadow(context.Background(), args(report, summary)); err != nil {
		t.Fatal(err)
	}
	var rep ShadowReport
	if err := shadowReadJSON(report, &rep); err != nil || rep.Records.Admitted != 2 || !rep.Reconciled || !rep.Parity.Equal() {
		t.Fatalf("report: %v %+v", err, rep.Records)
	}
	var pub ShadowPublicSummary
	if err := shadowReadJSON(summary, &pub); err != nil || pub.RecordsAdmitted != 2 || pub.CustomerAcceptance {
		t.Fatalf("summary: %v %+v", err, pub)
	}
	raw, _ := os.ReadFile(summary)
	if bytes.Contains(raw, []byte("cli-condition-name")) || bytes.Contains(raw, []byte(shadowTestSource)) {
		t.Fatal("public summary leaks private labels")
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Fatalf("scratch destination left behind: %v", left)
	}
	// Outputs are exclusive: an existing report is never overwritten.
	if err := runShadow(context.Background(), args(report, filepath.Join(dir, "summary2.json"))); err == nil {
		t.Fatal("existing report overwritten")
	}

	// A policy that tries to enable a sender is refused before anything runs.
	bad := fx.p
	bad.ExternalDelivery = true
	badPath := write("policy-bad.json", bad)
	r2, s2 := filepath.Join(dir, "r2.json"), filepath.Join(dir, "s2.json")
	a := args(r2, s2)
	a[3] = badPath
	if err := runShadow(context.Background(), a); !errors.Is(err, ErrShadowExternalDelivery) {
		t.Fatalf("sender-enabling policy: %v", err)
	}
	for _, p := range []string{r2, s2} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s written for a refused policy", p)
		}
	}
	// An unsigned mapping is refused before provisioning.
	unsigned := fx.m
	unsigned.Signature = ""
	a = args(r2, s2)
	a[1] = write("mapping-unsigned.json", unsigned)
	if err := runShadow(context.Background(), a); !errors.Is(err, ErrShadowMapping) {
		t.Fatalf("unsigned mapping: %v", err)
	}
	// Unknown fields and missing flags fail closed.
	if err := runShadow(context.Background(), []string{"--mapping", mapping}); err == nil {
		t.Fatal("missing flags accepted")
	}
	// A deliveries file naming an unmapped source fails the run, keeps the
	// private evidence and emits no public summary.
	fx.dest.Feed.Deliveries = append(fx.dest.Feed.Deliveries, ShadowDelivery{ID: "rogue", OriginalSource: "rogue", Adapter: ShadowAdapterConditions, Body: shadowCondBody(shadowCond("x", 1, "firing", 0))})
	rogue := write("capture-rogue.json", fx.dest.Feed)
	r3, s3 := filepath.Join(dir, "r3.json"), filepath.Join(dir, "s3.json")
	a = args(r3, s3)
	a[7] = rogue
	if err := runShadow(context.Background(), a); !errors.Is(err, ErrShadowPolicyFailed) {
		t.Fatalf("rogue capture: %v", err)
	}
	if _, err := os.Stat(r3); err != nil {
		t.Fatal("private evidence of the failed run was not kept")
	}
	if _, err := os.Stat(s3); err == nil {
		t.Fatal("public summary emitted for a failed run")
	}
}
