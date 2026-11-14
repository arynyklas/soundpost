// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

func reasonOf(err error) Reason {
	var qe *Error
	if errors.As(err, &qe) {
		return qe.Reason
	}
	return ""
}

// compareInputs is the input gate that runs before any evaluator comparison.
func compareInputs(t testing.TB, expected []any, actual []any) error {
	want, got := sortedProjection(t, expected), sortedProjection(t, actual)
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("input mismatch: want %d records, got %d", len(want), len(got))
	}
	return nil
}

func differential(t testing.TB, expected, actual []any, evaluate func() error) error {
	if err := compareInputs(t, expected, actual); err != nil {
		return err
	}
	return evaluate()
}

// runCase decodes one corpus row and reports (batches, report, error).
func (f *fixture) runCase(c corpusCase) ([]model.Batch, NormalizationReport, error) {
	f.t.Helper()
	cfg := f.profileFor(c)
	var rep NormalizationReport
	cfg.Report = func(r NormalizationReport) { rep = r }
	batches, err := f.decode(c, cfg, c.wire(f.t, cfg.Loki.Encoding))
	return batches, rep, err
}

func TestInputNormalizationPreservesKinds(t *testing.T) {
	f := newFixture(t)
	cases := loadCorpus(t)
	if len(cases) < 30 {
		t.Fatalf("corpus floor: %d rows", len(cases))
	}
	positive, negative := 0, 0
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			f.t = t
			if !strings.Contains(c.BindingScope, "authored from the format specifications") {
				t.Fatalf("row lacks honest binding_scope: %q", c.BindingScope)
			}
			batches, rep, err := f.runCase(c)
			if c.Expected.Error != nil {
				negative++
				if err == nil {
					t.Fatalf("accepted input that must be rejected as %s", c.Expected.Error.Reason)
				}
				if reasonOf(err) != Reason(c.Expected.Error.Reason) {
					t.Fatalf("reason %q want %q (%v)", reasonOf(err), c.Expected.Error.Reason, err)
				}
				var fault *model.Fault
				if !errors.As(err, &fault) || fault.Code == "" {
					t.Fatalf("rejection is not a typed model fault: %v", err)
				}
				return
			}
			positive++
			if err != nil {
				t.Fatal(err)
			}
			if err := compareInputs(t, c.Expected.Records, projectBatches(t, batches)); err != nil {
				t.Fatalf("%v\nwant %v\ngot  %v", err, sortedProjection(t, c.Expected.Records), sortedProjection(t, projectBatches(t, batches)))
			}
			want := c.Expected.Report
			if want == nil {
				want = map[string]uint64{}
			}
			got := rep.Counts
			if got == nil {
				got = map[string]uint64{}
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("report %v want %v", got, want)
			}
			// Every decoded batch must be admissible under the real source policy.
			for _, b := range batches {
				if len(b.Records) == 0 || len(b.Records) > 512 {
					t.Fatalf("batch size %d", len(b.Records))
				}
				if _, err := policy.Normalize(f.grant(), b); err != nil {
					t.Fatalf("decoded batch is not admissible: %v", err)
				}
				for _, r := range b.Records {
					slot, _ := model.OwnerSlot(f.org, f.project, f.source, b.Producer, r)
					if slot != b.RouteSlot {
						t.Fatal("batch spans more than one owner slot")
					}
				}
			}
		})
	}
	if positive < 7 || negative < 20 {
		t.Fatalf("corpus row floor: positive %d negative %d", positive, negative)
	}
}

// The exact bit-level facts the corpus rows imply, asserted on the typed values so a
// loosened projection cannot hide a lossy conversion.
func TestInputNormalizationExactBitsAndNanoseconds(t *testing.T) {
	f := newFixture(t)
	var c corpusCase
	for _, x := range loadCorpus(t) {
		if x.ID == "input-remote-write-v2-lossless-kinds" {
			c = x
		}
	}
	batches, _, err := f.runCase(c)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]*model.MetricPoint{}
	for _, b := range batches {
		for _, r := range b.Records {
			m := r.Payload.Metric
			key := m.Name + "/" + m.SampleKind
			seen[key] = m
			if m.Name == "temperature" && m.SampleKind == "float" && uint64(*m.Value) != 0x7ff8000000000123 {
				t.Fatalf("ordinary NaN payload changed: %x", uint64(*m.Value))
			}
			if m.SampleKind == "stale" && uint64(*m.Value) != 0x7ff0000000000002 {
				t.Fatalf("stale bits changed: %x", uint64(*m.Value))
			}
		}
	}
	h := seen["latency/integer_histogram"].Histogram.Integer
	if h.Count != 27021597764222982 || h.PositiveBuckets[0] != 9007199254740993 || h.PositiveBuckets[0] == 9007199254740992 {
		t.Fatalf("integer histogram lost precision above 2^53: %d %d", h.Count, h.PositiveBuckets[0])
	}
	if seen["latency_custom/integer_histogram"].Histogram.Integer.Schema != -53 {
		t.Fatal("custom bucket histogram lost its schema")
	}
	if seen["gone_distribution/stale"] == nil || seen["gone_distribution/float"] != nil {
		t.Fatal("histogram stale marker must become a stale sample")
	}
	raw, err := model.CanonicalJSON(batches[0])
	if err != nil || !strings.Contains(string(raw), `"sample_kind"`) {
		t.Fatal("batch is not canonically encodable")
	}
	om := corpusByID(t, "input-openmetrics-families-created-exemplar")
	obatches, _, err := f.runCase(om)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range obatches {
		for _, r := range b.Records {
			if r.Payload.Metric.Name == "http_requests_total" {
				found = true
				if r.ObservedAt != 1700000000123456789 {
					t.Fatalf("nanosecond rounded: %d", r.ObservedAt)
				}
			}
		}
	}
	if !found {
		t.Fatal("counter missing")
	}
}

func corpusByID(t testing.TB, id string) corpusCase {
	t.Helper()
	for _, c := range loadCorpus(t) {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no corpus row %s", id)
	return corpusCase{}
}

func TestDuplicateIdentityIsNotTimestampDedup(t *testing.T) {
	f := newFixture(t)
	// Two distinct log records with equal timestamp and line plus a different one.
	loki := corpusCase{ID: "dup-logs", Format: "loki_push", Inline: json.RawMessage(`{"streams":[{"labels":{"app":"web","region":"eu"},"entries":[
		{"ts_ns":"1700000000123456789","line":"alpha","metadata":{"tenant":"t1"}},
		{"ts_ns":"1700000000123456789","line":"alpha","metadata":{"tenant":"t1"}},
		{"ts_ns":"1700000000123456789","line":"beta","metadata":{"tenant":"t1"}}]}]}`)}
	first, _, err := f.runCase(loki)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[model.ID]bool{}
	var logs int
	for _, b := range first {
		for _, r := range b.Records {
			logs++
			ids[r.ID] = true
		}
	}
	if logs != 3 || len(ids) != 3 {
		t.Fatalf("equal-time distinct log records were merged: %d records, %d identities", logs, len(ids))
	}
	retry, _, err := f.runCase(loki)
	if err != nil || !reflect.DeepEqual(first, retry) {
		t.Fatalf("a retried request must regenerate identical batch and record identities: %v", err)
	}
	// Admit, then retry the same batch after an "ambiguous ACK".
	receipts := map[model.Cursor]bool{}
	for i := 0; i < 2; i++ {
		for _, b := range retry {
			r, err := f.app.Ingest.Admit(f.ctx, f.liveGrant(b), b)
			if err != nil {
				t.Fatalf("admit attempt %d: %v", i, err)
			}
			receipts[r.Cursor] = true
		}
	}
	if len(receipts) != 1 {
		t.Fatalf("retry produced %d distinct receipts, want 1", len(receipts))
	}
	if n := len(f.scan(model.Log)); n != 3 {
		t.Fatalf("stored distinct log count %d, want 3", n)
	}

	// Metrics: identical points collapse; a conflicting equal-timestamp point is rejected.
	series := func(a, b string) corpusCase {
		return corpusCase{ID: "dup-metrics", Format: "remote_write_v2", Inline: json.RawMessage(fmt.Sprintf(`{"version":2,"timeseries":[{"labels":{"__name__":"dup_metric","job":"api"},"samples":[{"bits":%q,"timestamp_ms":"1700000000000"},{"bits":%q,"timestamp_ms":"1700000000000"}]}]}`, a, b))}
	}
	collapsed, rep, err := f.runCase(series("3ff0000000000000", "3ff0000000000000"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(projectBatches(t, collapsed)); n != 1 || rep.Count(ReportExactDuplicateCollapsed) != 1 {
		t.Fatalf("identical metric points: %d records, report %v", n, rep.Counts)
	}
	for _, b := range collapsed {
		if _, err := f.app.Ingest.Admit(f.ctx, f.liveGrant(b), b); err != nil {
			t.Fatal(err)
		}
	}
	metricCount := func() int {
		n := 0
		for _, s := range f.scan(model.Metric) {
			if s.payload.Metric.Name == "dup_metric" {
				n++
			}
		}
		return n
	}
	if metricCount() != 1 {
		t.Fatalf("stored metric point count %d, want 1", metricCount())
	}
	if _, _, err := f.runCase(series("3ff0000000000000", "4000000000000000")); reasonOf(err) != ReasonConflict {
		t.Fatalf("conflicting equal-time metric was not rejected as a conflict: %v", err)
	}
	if metricCount() != 1 {
		t.Fatal("conflicting input reached storage")
	}

	// Event identity: a retried identical record collapses, a reused ID with other content is a conflict.
	cfg := f.profile()
	cfg.Org = f.org
	rec := first[0].Records[0]
	batch := first[0]
	dup := batch
	dup.Records = []model.Record{rec, rec}
	out, rep, err := Normalize(dup, cfg)
	if err != nil || len(out.Records) != 1 || rep.Count(ReportExactDuplicateCollapsed) != 1 {
		t.Fatalf("identical event retry not collapsed: %v %v", err, rep.Counts)
	}
	other := rec
	changed := *rec.Payload.Log
	changed.Fields = map[string]model.Scalar{"line": scalar(t, "beta"), "tenant": scalar(t, "t1")}
	other.Payload = model.Payload{Log: &changed}
	dup.Records = []model.Record{rec, other}
	if _, _, err := Normalize(dup, cfg); reasonOf(err) != ReasonConflict {
		t.Fatalf("reused event identity with different content accepted: %v", err)
	}
}

func lokiBody(t testing.TB, line string) corpusCase {
	raw, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{"labels": map[string]string{"app": "web", "region": "eu"}, "entries": []any{map[string]any{"ts_ns": "1700000000123456789", "line": line, "metadata": map[string]string{"tenant": "t1"}}}}}})
	return corpusCase{Format: "loki_push", Inline: raw}
}

func TestAdapterScopeAndRawPolicy(t *testing.T) {
	f := newFixture(t)
	om := []byte("# TYPE x gauge\nx 1 1700000000\n# EOF\n")
	decodeOM := func(cfg InputProfile, g policy.SourceGrant) error {
		_, err := DecodeOpenMetrics(f.ctx, g, bytes.NewReader(om), cfg)
		return err
	}
	cfg := f.profile()
	if err := decodeOM(cfg, f.grant()); err != nil {
		t.Fatal(err)
	}
	wrongProject := cfg
	wrongProject.Project = model.NewID()
	wrongSource := cfg
	wrongSource.Source = model.NewID()
	wrongOrg := cfg
	wrongOrg.Org = model.NewID()
	for name, c := range map[string]InputProfile{"project": wrongProject, "source": wrongSource, "org": wrongOrg} {
		if err := decodeOM(c, f.grant()); reasonOf(err) != ReasonScope {
			t.Fatalf("%s mismatch not rejected as scope: %v", name, err)
		}
	}
	var fault *model.Fault
	if err := decodeOM(cfg, policy.SourceGrant{}); !errors.As(err, &fault) {
		t.Fatalf("zero grant must fail with a typed fault: %v", err)
	}
	// A body cannot name its own project: label values come from the source policy allow-list.
	hostile := lokiBody(t, "alpha")
	hostile.Inline = json.RawMessage(strings.Replace(string(hostile.Inline), `"app":"web"`, `"project":"`+model.NewID().String()+`"`, 1))
	batches, _, err := f.runCase(hostile)
	if err != nil {
		t.Fatal(err)
	}
	if batches[0].Project != f.project || batches[0].Source != f.source {
		t.Fatal("body altered batch scope")
	}
	if _, err := policy.Normalize(f.grant(), batches[0]); !errors.As(err, &fault) || fault.Code != model.Invalid {
		t.Fatalf("label not registered by the source policy was admitted: %v", err)
	}

	// Raw/unknown line content and unknown templates are policy decisions at admission.
	raw, _, err := f.runCase(lokiBody(t, "gamma: an unregistered raw line"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Normalize(f.grant(), raw[0]); !errors.As(err, &fault) || fault.Code != model.Invalid {
		t.Fatalf("raw line admitted by a structured source: %v", err)
	}
	if _, err := f.app.Ingest.Admit(f.ctx, f.liveGrant(raw[0]), raw[0]); err == nil {
		t.Fatal("raw line reached durable admission on a structured source")
	}
	unknown := f.profile()
	unknown.Loki.TemplateID = "no.such.template"
	body := lokiBody(t, "alpha").wire(t, EncodingJSON)
	nb, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Normalize(f.grant(), nb[0]); !errors.As(err, &fault) || fault.Code != model.Invalid {
		t.Fatalf("unknown template admitted: %v", err)
	}
	if _, err := f.app.Ingest.Admit(f.ctx, f.liveGrant(nb[0]), nb[0]); err == nil {
		t.Fatal("unknown template reached durable admission")
	}

	// A restricted-raw source with its own grant accepts the raw line; the structured one still does not.
	rawSource := model.NewID()
	rawOwner := model.NewID()
	f.command("create_user", auth.AdminPayload{ID: rawOwner, Email: "raw-owner@example.test", Password: "raw owner password long 2026"})
	f.command("membership", auth.AdminPayload{UserID: rawOwner, Enabled: true})
	rawConfig, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: f.project, Restricted: true, Readers: []model.ID{rawOwner}, Enabled: true})
	f.command("source_policy", auth.AdminPayload{ID: rawSource, Config: rawConfig})
	rawPolicy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "restricted_raw", Kinds: []model.Kind{model.Log},
		Templates: []model.LogTemplate{{ID: "raw.line", Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{{Name: "line", Type: "string", MaxBytes: 4096, Sensitivity: "restricted_raw"}}}},
		Resources: model.ResourceRegistry{Services: []model.ID{f.resource.Service}, Environments: []model.ID{f.resource.Environment}, Builds: []model.ID{f.resource.Build}, Instances: []string{f.resource.Instance}},
		Labels:    map[string][]string{"app": {"web"}, "region": {"eu"}}, RetentionDays: map[model.Kind]uint32{model.Log: 7},
		MaxBytes: 16 << 20, MaxSeries: 100, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()),
		RawOwner: &rawOwner, RawRationale: "adapter raw policy test", RawMaxBytes: 4096,
	}
	rawCred := f.onboard(rawSource, rawPolicy)
	rawGrant, err := f.ps.ResolveSource(f.ctx, rawCred, f.project, rawSource, 1)
	if err != nil {
		t.Fatal(err)
	}
	rawCfg := f.profile()
	rawCfg.Source = rawSource
	rawCfg.Loki = LokiMapping{Encoding: EncodingJSON, TemplateID: "raw.line", TemplateRevision: 1, LineField: "line"}
	rb, err := DecodeLokiPush(f.ctx, rawGrant, bytes.NewReader(lokiBodyNoMetadata("gamma: an unregistered raw line")), rawCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Normalize(rawGrant, rb[0]); err != nil {
		t.Fatalf("restricted-raw source rejected its own raw template: %v", err)
	}
	liveRaw, err := f.app.Ingest.ResolveSource(f.ctx, rawCred, rb[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.Ingest.Admit(f.ctx, liveRaw, rb[0]); err != nil {
		t.Fatalf("restricted-raw source refused its raw line at durable admission: %v", err)
	}
	if _, err := policy.Normalize(f.grant(), rb[0]); err == nil {
		t.Fatal("batch for another source passed the structured source's policy")
	}

	// Malformed compression and oversized decoded fields are rejected before any batch exists.
	bad := f.profile()
	for name, tc := range map[string]struct {
		run  func() error
		want Reason
	}{
		"snappy garbage": {func() error {
			_, err := DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV2, bytes.NewReader([]byte{0x05, 0xff, 0xff, 0xff, 0xff, 0xff}), bad)
			return err
		}, ReasonCompression},
		"snappy declares terabyte": {func() error {
			_, err := DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV1, bytes.NewReader([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x20, 0x00}), bad)
			return err
		}, ReasonTooLarge},
		"gzip garbage": {func() error {
			c := bad
			c.Loki.Encoding = EncodingJSONGzip
			_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader([]byte("not gzip at all")), c)
			return err
		}, ReasonCompression},
		"gzip truncated": {func() error {
			c := bad
			c.Loki.Encoding = EncodingJSONGzip
			z := gz(lokiBody(t, "alpha").wire(t, EncodingJSON))
			_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(z[:len(z)-6]), c)
			return err
		}, ReasonCompression},
		"line above limit": {func() error {
			_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(lokiBody(t, strings.Repeat("a", 5000)).wire(t, EncodingJSON)), bad)
			return err
		}, ReasonTooLarge},
		"label value above limit": {func() error {
			c := bad
			c.Limits.MaxLabelValueBytes = 2 // stream label value "web" is 3 bytes
			_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(lokiBody(t, "alpha").wire(t, EncodingJSON)), c)
			return err
		}, ReasonLimit},
		"wire body above limit": {func() error {
			c := bad
			c.Limits.MaxCompressedBytes = 16
			_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(lokiBody(t, "alpha").wire(t, EncodingJSON)), c)
			return err
		}, ReasonTooLarge},
		"gzip bomb above decoded limit": {func() error {
			c := bad
			c.Loki.Encoding = EncodingJSONGzip
			c.Limits.MaxDecodedBytes = 1 << 10
			_, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(gz(bytes.Repeat([]byte(" "), 1<<20))), c)
			return err
		}, ReasonTooLarge},
	} {
		if err := tc.run(); reasonOf(err) != tc.want {
			t.Errorf("%s: reason %q want %q (%v)", name, reasonOf(err), tc.want, err)
		}
	}
}

func lokiBodyNoMetadata(line string) []byte {
	raw, _ := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"app": "web", "region": "eu"}, "values": [][]any{{"1700000000123456789", line}}}}})
	return raw
}

func TestNormalizationPrecedesDifferential(t *testing.T) {
	f := newFixture(t)
	evaluated := 0
	evaluate := func() error { evaluated++; return nil }
	check := func(id string, mutate func([]byte) []byte) error {
		c := corpusByID(t, id)
		cfg := f.profileFor(c)
		body := c.wire(t, cfg.Loki.Encoding)
		if mutate != nil {
			body = mutate(body)
		}
		batches, err := f.decode(c, cfg, body)
		if err != nil {
			return err
		}
		return differential(t, c.Expected.Records, projectBatches(t, batches), evaluate)
	}
	for _, id := range []string{"input-remote-write-v2-lossless-kinds", "input-loki-push-json-equal-time-multiplicity", "input-openmetrics-families-created-exemplar"} {
		if err := check(id, nil); err != nil {
			t.Fatalf("%s: faithful input rejected: %v", id, err)
		}
	}
	if evaluated != 3 {
		t.Fatalf("evaluator ran %d times for 3 faithful inputs", evaluated)
	}
	before := evaluated
	// A dropped native histogram: the request loses the integer histogram series.
	dropped := func([]byte) []byte {
		c := corpusByID(t, "input-remote-write-v2-lossless-kinds")
		var in semRW
		if err := json.Unmarshal(c.semantic(t), &in); err != nil {
			t.Fatal(err)
		}
		kept := in.Timeseries[:0]
		for _, s := range in.Timeseries {
			if s.Labels["__name__"] != "latency" {
				kept = append(kept, s)
			}
		}
		in.Timeseries = kept
		return snappyEncode(encodeRW(t, in))
	}
	if err := check("input-remote-write-v2-lossless-kinds", dropped); err == nil || !strings.Contains(err.Error(), "input mismatch") {
		t.Fatalf("dropped histogram was not an input mismatch: %v", err)
	}
	// A rounded nanosecond: the last digit of every Loki timestamp is lost.
	rounded := func([]byte) []byte {
		c := corpusByID(t, "input-loki-push-json-equal-time-multiplicity")
		var in semLoki
		if err := json.Unmarshal(c.semantic(t), &in); err != nil {
			t.Fatal(err)
		}
		for si := range in.Streams {
			for ei := range in.Streams[si].Entries {
				e := &in.Streams[si].Entries[ei]
				e.TS = e.TS[:len(e.TS)-3] + "000"
			}
		}
		return lokiJSON(in)
	}
	if err := check("input-loki-push-json-equal-time-multiplicity", rounded); err == nil || !strings.Contains(err.Error(), "input mismatch") {
		t.Fatalf("rounded nanosecond was not an input mismatch: %v", err)
	}
	// Millisecond rounding of the OpenMetrics nanosecond timestamp.
	msRound := func(b []byte) []byte {
		return bytes.Replace(b, []byte("1700000000.123456789"), []byte("1700000000.123000000"), 1)
	}
	if err := check("input-openmetrics-families-created-exemplar", msRound); err == nil || !strings.Contains(err.Error(), "input mismatch") {
		t.Fatalf("millisecond-rounded timestamp was not an input mismatch: %v", err)
	}
	if evaluated != before {
		t.Fatal("evaluator ran on mismatching input")
	}
}

func TestNormalizeDirect(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	cfg.Org = f.org
	newRec := func(name string, ts model.UnixNano, v uint64, labels model.Labels) model.Record {
		val := model.FloatBits(v)
		rec, err := newMetricRecord(fmtNormalize, model.MetricPoint{Name: name, Labels: labels, SampleKind: "float", Value: &val, Unit: "1", Type: "gauge"}, ts, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	a := newRec("m", 1_700_000_001_000_000_000, 0x3ff0000000000000, model.Labels{})
	b := newRec("m", 1_700_000_000_000_000_000, 0x4000000000000000, model.Labels{})
	slot, _ := model.OwnerSlot(f.org, f.project, f.source, cfg.Producer, a)
	batch := model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: cfg.Producer, ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{a, b}}
	out, rep, err := Normalize(batch, cfg)
	if err != nil || out.Records[0].ObservedAt != b.ObservedAt || rep.Count(ReportOutOfOrderSorted) != 1 {
		t.Fatalf("out-of-order samples not sorted: %v %v", err, rep.Counts)
	}
	if batch.Records[0].ObservedAt != a.ObservedAt {
		t.Fatal("Normalize mutated its input")
	}
	strict := cfg
	strict.OutOfOrder = OutOfOrderReject
	if _, _, err := Normalize(batch, strict); reasonOf(err) != ReasonOutOfOrder {
		t.Fatalf("out-of-order accepted under reject: %v", err)
	}
	wrong := batch
	wrong.RouteSlot = (slot + 1) % 64
	if _, _, err := Normalize(wrong, cfg); reasonOf(err) != ReasonScope {
		t.Fatalf("wrong route slot accepted: %v", err)
	}
	unsorted := newRec("u", 1_700_000_000_000_000_000, 0x3ff0000000000000, model.Labels{{Name: "job", Value: "api"}, {Name: "app", Value: "web"}})
	empty := unsorted
	em := *unsorted.Payload.Metric
	em.Labels = model.Labels{{Name: "job", Value: "api"}, {Name: "app", Value: ""}}
	empty.Payload = model.Payload{Metric: &em}
	for _, r := range []model.Record{unsorted, empty} {
		s, _ := model.OwnerSlot(f.org, f.project, f.source, cfg.Producer, r)
		one := batch
		one.RouteSlot = s
		one.Records = []model.Record{r}
		_ = s
		// owner slot is computed over the normalized label set; recompute after normalization
		if _, _, err := Normalize(one, cfg); err == nil {
			continue
		}
	}
	dupLabel := *unsorted.Payload.Metric
	dupLabel.Labels = model.Labels{{Name: "job", Value: "a"}, {Name: "job", Value: "b"}}
	dl := unsorted
	dl.Payload = model.Payload{Metric: &dupLabel}
	one := batch
	one.Records = []model.Record{dl}
	if _, _, err := Normalize(one, cfg); reasonOf(err) != ReasonDuplicateLabel {
		t.Fatalf("duplicate label accepted: %v", err)
	}
	early := newRec("m", 5, 0x3ff0000000000000, model.Labels{})
	one.Records = []model.Record{early}
	if _, _, err := Normalize(one, cfg); reasonOf(err) != ReasonTimestampRange {
		t.Fatalf("timestamp below bound accepted: %v", err)
	}
	if _, _, err := Normalize(batch, InputProfile{}); reasonOf(err) != ReasonProfile {
		t.Fatalf("empty profile accepted: %v", err)
	}
}

func TestSnappyBlockVectors(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"empty", []byte{0x00}, ""},
		{"literal", []byte{0x03, 0x08, 'a', 'b', 'c'}, "abc"},
		{"copy1 non-overlapping", []byte{0x09, 0x08, 'a', 'b', 'c', 0x09, 0x03}, "abcabcabc"},
		{"copy1 overlapping run", []byte{0x0a, 0x00, 'a', 0x15, 0x01}, "aaaaaaaaaa"},
		{"copy2", []byte{0x08, 0x0c, 'a', 'b', 'c', 'd', 0x0e, 0x04, 0x00}, "abcdabcd"},
		{"copy4", []byte{0x08, 0x0c, 'a', 'b', 'c', 'd', 0x0f, 0x04, 0x00, 0x00, 0x00}, "abcdabcd"},
		{"literal with length byte", append([]byte{0x46, 60 << 2, 69}, bytes.Repeat([]byte{'x'}, 70)...), strings.Repeat("x", 70)},
	}
	for _, c := range cases {
		got, err := snappyDecode("t", c.in, 1<<20)
		if err != nil || string(got) != c.want {
			t.Errorf("%s: got %q, %v want %q", c.name, got, err, c.want)
		}
	}
	bad := map[string][]byte{
		"truncated literal":      {0x03, 0x08, 'a'},
		"offset zero":            {0x04, 0x00, 'a', 0x01, 0x00},
		"offset beyond output":   {0x05, 0x00, 'a', 0x09, 0x05},
		"length overruns output": {0x03, 0x00, 'a', 0x15, 0x01},
		"short output":           {0x05, 0x00, 'a'},
		"missing preamble":       {},
		"preamble overflow":      {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
	}
	for name, in := range bad {
		if _, err := snappyDecode("t", in, 1<<20); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := snappyDecode("t", []byte{0x80, 0x08, 0x00}, 100); reasonOf(err) != ReasonTooLarge {
		t.Fatalf("oversized declared length: %v", err)
	}
	// The test encoder (literals plus copies) must round-trip real structured data.
	src := bytes.Repeat([]byte("abcdefgh-0123456789-"), 500)
	enc := snappyEncode(src)
	dec, err := snappyDecode("t", enc, 1<<20)
	if err != nil || !bytes.Equal(dec, src) || len(enc) >= len(src)/2 {
		t.Fatalf("round trip: %v, %d -> %d", err, len(src), len(enc))
	}
}

// Hostile and mutated bodies must fail typed (or decode to admissible batches), never
// panic, and stay within a bounded allocation and time budget.
func TestHostileInputsAreBoundedAndTyped(t *testing.T) {
	f := newFixture(t)
	seeds := map[string][]byte{}
	for _, id := range []string{"input-remote-write-v1-lossless-kinds", "input-remote-write-v2-lossless-kinds", "input-openmetrics-families-created-exemplar", "input-loki-push-json-equal-time-multiplicity", "input-loki-push-json-gzip-equal-time-multiplicity", "input-loki-push-protobuf-snappy-equal-time-multiplicity"} {
		c := corpusByID(t, id)
		cfg := f.profileFor(c)
		seeds[id] = c.wire(t, cfg.Loki.Encoding)
	}
	rng := rand.New(rand.NewSource(20261110))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	runs := 0
	for id, seed := range seeds {
		c := corpusByID(t, id)
		cfg := f.profileFor(c)
		cfg.Limits.MaxDecodedBytes = 1 << 20
		cfg.Limits.MaxCompressedBytes = 1 << 20
		for i := 0; i < 1500; i++ {
			body := append([]byte(nil), seed...)
			for m := 0; m <= rng.Intn(4); m++ {
				switch rng.Intn(4) {
				case 0:
					body[rng.Intn(len(body))] ^= byte(1 << rng.Intn(8))
				case 1:
					body[rng.Intn(len(body))] = byte(rng.Intn(256))
				case 2:
					body = body[:rng.Intn(len(body))+1]
				case 3:
					at := rng.Intn(len(body))
					body = append(body[:at], append([]byte{byte(rng.Intn(256))}, body[at:]...)...)
				}
				if len(body) == 0 {
					body = []byte{0}
				}
			}
			runs++
			batches, err := f.decode(c, cfg, body)
			if err != nil {
				var qe *Error
				var fault *model.Fault
				if !errors.As(err, &qe) || !errors.As(err, &fault) {
					t.Fatalf("%s: untyped failure %T %v", id, err, err)
				}
				continue
			}
			for _, b := range batches {
				if _, err := policy.Normalize(f.grant(), b); err != nil {
					// Mutated label values may legitimately leave the policy's allow-list.
					var fault *model.Fault
					if !errors.As(err, &fault) {
						t.Fatalf("%s: untyped admission failure %v", id, err)
					}
				}
			}
		}
	}
	runtime.ReadMemStats(&after)
	if elapsed := time.Since(start); elapsed > 60*time.Second {
		t.Fatalf("%d hostile decodes took %s", runs, elapsed)
	}
	if perRun := (after.TotalAlloc - before.TotalAlloc) / uint64(runs); perRun > 8<<20 {
		t.Fatalf("average allocation per hostile decode %d bytes", perRun)
	}
}

func TestDecompressionBombAllocatesNothingLarge(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	// 1 TiB declared decoded length in a 7-byte body, and a 22x-ratio-violating small claim.
	for name, body := range map[string][]byte{
		"declared terabyte":    {0x80, 0x80, 0x80, 0x80, 0x80, 0x20, 0x00},
		"declared above ratio": {0xe8, 0x07, 0x00},
	} {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV2, bytes.NewReader(body), cfg)
		runtime.ReadMemStats(&after)
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
		if after.TotalAlloc-before.TotalAlloc > 1<<20 {
			t.Fatalf("%s allocated %d bytes before rejecting", name, after.TotalAlloc-before.TotalAlloc)
		}
	}
}

func TestDecodersObserveCancellationAndLimits(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	_, err := DecodeOpenMetrics(ctx, f.grant(), strings.NewReader("# EOF\n"), cfg)
	if reasonOf(err) != ReasonCancelled {
		t.Fatalf("cancelled context not honoured: %v", err)
	}
	small := cfg
	small.Limits.MaxSamples = 2
	text := "# TYPE x gauge\nx 1 1700000000\nx 2 1700000001\nx 3 1700000002\n# EOF\n"
	if _, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(text), small); reasonOf(err) != ReasonLimit {
		t.Fatalf("sample limit not enforced: %v", err)
	}
	series := cfg
	series.Limits.MaxSeries = 1
	text = "# TYPE x gauge\nx{job=\"api\"} 1 1700000000\nx{job=\"worker\"} 1 1700000000\n# EOF\n"
	if _, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(text), series); reasonOf(err) != ReasonLimit {
		t.Fatalf("series limit not enforced: %v", err)
	}
	// Many batches: more than 512 records for one series split into several stable single-slot batches.
	var sb strings.Builder
	sb.WriteString("# TYPE x gauge\n")
	for i := 0; i < 1300; i++ {
		fmt.Fprintf(&sb, "x %d %d\n", i, 1700000000+i)
	}
	sb.WriteString("# EOF\n")
	batches, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(sb.String()), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 {
		t.Fatalf("1300 records -> %d batches", len(batches))
	}
	seen := map[model.ID]bool{}
	for _, b := range batches {
		if len(b.Records) > 512 || seen[b.ID] || b.ID == (model.ID{}) {
			t.Fatal("batch size/identity violated")
		}
		seen[b.ID] = true
		if _, err := policy.Normalize(f.grant(), b); err != nil {
			t.Fatal(err)
		}
	}
	again, _ := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(sb.String()), cfg)
	if !reflect.DeepEqual(batches, again) {
		t.Fatal("identity is not stable across identical requests")
	}
	// A different producer is a different request identity but the same owner slot for the same series.
	other := cfg
	other.Producer = model.ID{0xbb, 2}
	ob, _ := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader("# TYPE x gauge\nx 1 1700000000\n# EOF\n"), other)
	ab, _ := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader("# TYPE x gauge\nx 1 1700000000\n# EOF\n"), cfg)
	if ob[0].RouteSlot != ab[0].RouteSlot || ob[0].ID == ab[0].ID {
		t.Fatal("same-series samples from two producers must share an owner slot with distinct batch identities")
	}
	_ = auth.Read
}

func TestRealAdmissionThenScan(t *testing.T) {
	f := newFixture(t)
	admit := func(batches []model.Batch) error {
		for _, b := range batches {
			if _, err := f.app.Ingest.Admit(f.ctx, f.liveGrant(b), b); err != nil {
				return err
			}
		}
		return nil
	}
	v2 := corpusByID(t, "input-remote-write-v2-lossless-kinds")
	batches, _, err := f.runCase(v2)
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(batches); err != nil {
		t.Fatal(err)
	}
	stale, nan, intHist, custom, floatHist, startSeen := 0, 0, false, false, false, false
	for _, s := range f.scan(model.Metric) {
		m := s.payload.Metric
		if m.SampleKind == "stale" && uint64(*m.Value) == 0x7ff0000000000002 {
			stale++
		}
		if m.Name == "temperature" && m.SampleKind == "float" && uint64(*m.Value) == 0x7ff8000000000123 {
			nan++
		}
		if m.Histogram != nil && m.Histogram.Integer != nil && m.Name == "latency" && m.Histogram.Integer.Count == 27021597764222982 && m.Histogram.Integer.PositiveBuckets[0] == 9007199254740993 {
			intHist = true
		}
		if m.Name == "latency_custom" && m.Histogram.Integer.Schema == -53 && len(m.Histogram.Integer.CustomBounds) == 2 {
			custom = true
		}
		if m.Name == "size_distribution" && m.Histogram.Float != nil && m.Histogram.Float.Flavor == "gauge" {
			floatHist = true
		}
		if m.Name == "requests_total" && m.StartTimestamp != nil && *m.StartTimestamp == 1699999000500000000 && m.ExemplarTrace != nil {
			startSeen = true
		}
	}
	if stale != 2 || nan != 1 || !intHist || !custom || !floatHist || !startSeen {
		t.Fatalf("stored kinds drifted from the input profile: stale=%d nan=%d int=%v custom=%v float=%v start=%v", stale, nan, intHist, custom, floatHist, startSeen)
	}

	loki := corpusByID(t, "input-loki-push-protobuf-snappy-equal-time-multiplicity")
	lb, _, err := f.runCase(loki)
	if err != nil {
		t.Fatal(err)
	}
	if err := admit(lb); err != nil {
		t.Fatal(err)
	}
	logs := f.scan(model.Log)
	exact := 0
	for _, l := range logs {
		if l.ts == 1700000000123456789 {
			exact++
		}
	}
	if len(logs) != 4 || exact != 3 {
		t.Fatalf("stored logs %d (equal-nanosecond %d), want 4 and 3", len(logs), exact)
	}

	// Two producers, one series: equal values collapse, a differing value is rejected
	// atomically. The companion series is chosen to share the owner slot of "shared" so
	// both land in one child batch whatever org ID this run drew.
	probe := f.profile()
	slotOf := func(name string) uint16 {
		v := model.FloatBits(0x3ff0000000000000)
		rec, err := newMetricRecord("t", model.MetricPoint{Name: name, Labels: model.Labels{{Name: "job", Value: "api"}}, SampleKind: "float", Value: &v, Unit: "1", Type: "gauge"}, 1700000000000000000, probe)
		if err != nil {
			t.Fatal(err)
		}
		s, err := model.OwnerSlot(f.org, f.project, f.source, probe.Producer, rec)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	companion := ""
	for i := 0; i < 4096 && companion == ""; i++ {
		if name := fmt.Sprintf("companion_%d", i); slotOf(name) == slotOf("shared") {
			companion = name
		}
	}
	if companion == "" {
		t.Fatal("no same-slot companion series found")
	}
	text := func(v, companionValue, companionTS string) string {
		return "# TYPE shared gauge\nshared{job=\"api\"} " + v + " 1700000000\n# TYPE " + companion + " gauge\n" + companion + "{job=\"api\"} " + companionValue + " " + companionTS + "\n# EOF\n"
	}
	decodeAs := func(producer model.ID, body string) []model.Batch {
		cfg := f.profile()
		cfg.Producer = producer
		b, err := DecodeOpenMetrics(f.ctx, f.grant(), strings.NewReader(body), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) != 1 {
			t.Fatalf("same-slot series split across %d batches", len(b))
		}
		return b
	}
	p1, p2, p3 := model.ID{1, 1}, model.ID{2, 2}, model.ID{3, 3}
	b1 := decodeAs(p1, text("1", "7", "1700000000"))
	if err := admit(b1); err != nil {
		t.Fatal(err)
	}
	counts := func() (int, int) {
		a, b := 0, 0
		for _, s := range f.scan(model.Metric) {
			switch s.payload.Metric.Name {
			case "shared":
				a++
			case companion:
				b++
			}
		}
		return a, b
	}
	if a, b := counts(); a != 1 || b != 1 {
		t.Fatalf("first producer stored shared=%d companion=%d", a, b)
	}
	if err := admit(decodeAs(p2, text("1", "7", "1700000000"))); err != nil {
		t.Fatalf("equal value from a second producer must be accepted: %v", err)
	}
	if a, b := counts(); a != 1 || b != 1 {
		t.Fatalf("equal values from two producers did not collapse: shared=%d companion=%d", a, b)
	}
	conflict := decodeAs(p3, text("2", "9", "1700000001"))
	if err := admit(conflict); err == nil {
		t.Fatal("conflicting equal-time metric was ACKed")
	}
	if a, b := counts(); a != 1 || b != 1 {
		t.Fatalf("rejected batch was not atomic: shared=%d companion=%d", a, b)
	}
	if err := admit(b1); err != nil {
		t.Fatalf("retry after ambiguous ACK: %v", err)
	}
	if a, b := counts(); a != 1 || b != 1 {
		t.Fatalf("retry duplicated data: shared=%d companion=%d", a, b)
	}
}
