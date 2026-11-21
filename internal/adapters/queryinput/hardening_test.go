// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

// Regression tests added with the fixes of the 02.08#14 hostile-input review.
// The review's own finding tests are in hostile_test.go and hostile_table_test.go;
// these cover what a finding fix introduced or what its test could not see.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/model"
)

// Normalize is a decoder-independent entry point: a batch built by hand is held
// to the same rule as a decoded request, because a histogram that names a bucket
// outside the bound list is read by indexing that list.
func TestNormalizeRefusesAHistogramThatNamesBucketsThatDoNotExist(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	cfg.Org = f.org
	build := func(spans []model.HistogramSpan, buckets, bounds int) model.Batch {
		t.Helper()
		custom := make([]model.FloatBits, bounds)
		for i := range custom {
			custom[i] = model.FloatBits(0x3ff0000000000000 + uint64(i)<<32)
		}
		deltas := make([]model.DeltaBucket, buckets)
		deltas[0] = 1
		h := &model.IntegerHistogram{Flavor: "counter", Schema: -53, ResetHint: "unknown", Count: model.Uint64(buckets), Sum: 0x3ff0000000000000,
			PositiveSpans: spans, PositiveBuckets: deltas, CustomBounds: custom}
		point := model.MetricPoint{Name: "hs_norm_hist", Labels: model.Labels{{Name: "job", Value: "api"}}, SampleKind: "integer_histogram",
			Histogram: &model.NativeHistogram{Integer: h}, Unit: "1", Type: "histogram"}
		rec, err := newMetricRecord(fmtNormalize, point, 1_700_000_000_000_000_000, cfg)
		if err != nil {
			t.Fatal(err)
		}
		slot, err := model.OwnerSlot(f.org, f.project, f.source, cfg.Producer, rec)
		if err != nil {
			t.Fatal(err)
		}
		return model.Batch{Version: 1, Project: f.project, Source: f.source, Producer: cfg.Producer, ID: model.NewID(), PolicyRevision: cfg.PolicyRevision, RouteSlot: slot, Records: []model.Record{rec}}
	}
	if _, _, err := Normalize(build([]model.HistogramSpan{{Offset: 0, Length: 3}}, 3, 2), cfg); err != nil {
		t.Fatalf("spans that end on the +Inf bucket were refused: %v", err)
	}
	for name, b := range map[string]model.Batch{
		"a span past the +Inf bucket":  build([]model.HistogramSpan{{Offset: 1, Length: 3}}, 3, 2),
		"a negative first offset":      build([]model.HistogramSpan{{Offset: -1, Length: 2}}, 2, 3),
		"buckets without any bound":    build([]model.HistogramSpan{{Offset: 0, Length: 2}}, 2, 0),
		"an offset far beyond bounds":  build([]model.HistogramSpan{{Offset: 5, Length: 1}}, 1, 1),
		"a second span past the bound": build([]model.HistogramSpan{{Offset: 0, Length: 1}, {Offset: 2, Length: 1}}, 2, 2),
	} {
		if _, _, err := Normalize(b, cfg); reasonOf(err) != ReasonMalformed {
			t.Errorf("%s was accepted or mis-typed: %v", name, err)
		}
	}
}

// maxGap runs decode under a context that never cancels and reports the largest
// number of allocations between two of its cancellation checks (the start and the
// end of the run count as checks) and how many checks it made.
func maxGap(t *testing.T, decode func(ctx context.Context) error) (uint64, int) {
	t.Helper()
	gc := &hsGapCtx{Context: context.Background()}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := decode(gc)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	marks := append([]uint64{before.Mallocs}, gc.marks...)
	marks = append(marks, after.Mallocs)
	var gap uint64
	for i := 1; i < len(marks); i++ {
		if g := marks[i] - marks[i-1]; g > gap {
			gap = g
		}
	}
	return gap, len(gc.marks)
}

// Every decoder, not only remote write, must ask the context at least every few
// thousand records through every phase (parse, record construction,
// normalization, batching): a client that disconnected must stop costing CPU.
func TestEveryDecoderAsksForCancellationOften(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	const records = 15000
	var om strings.Builder
	om.WriteString("# TYPE hs_gap gauge\n")
	for i := range records {
		fmt.Fprintf(&om, "hs_gap{job=\"api\"} %d %d\n", i, 1_700_000_000+i)
	}
	om.WriteString("# EOF\n")
	values := make([][]string, records)
	for i := range values {
		values[i] = []string{strconv.Itoa(1_700_000_000_123_456_789 + i), "alpha"}
	}
	pushBody, err := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"app": "web", "region": "eu"}, "values": values}}})
	if err != nil {
		t.Fatal(err)
	}
	events := make([]string, records)
	for i := range events {
		events[i] = fmt.Sprintf(`{"condition":"hs-gap","epoch":"e1","sequence":"%d","event_time_ns":"1700000000123456789","status":"firing","severity":"info","labels":{},"links":[]}`, i+1)
	}
	hook := `{"version":1,"events":[` + strings.Join(events, ",") + `]}`
	for name, decode := range map[string]func(ctx context.Context) error{
		"openmetrics": func(ctx context.Context) error {
			_, err := DecodeOpenMetrics(ctx, f.grant(), strings.NewReader(om.String()), cfg)
			return err
		},
		"loki push": func(ctx context.Context) error {
			_, err := DecodeLokiPush(ctx, f.grant(), bytes.NewReader(pushBody), cfg)
			return err
		},
		"conditions": func(ctx context.Context) error {
			_, err := DecodeConditions(ctx, f.grant(), strings.NewReader(hook), cfg)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if gap, checks := maxGap(t, decode); gap > 600_000 {
				t.Fatalf("%d allocations between two cancellation checks (%d checks for %d records)", gap, checks, records)
			}
		})
	}
}

// The structured-metadata field list is a property of the request, not of a
// record: declaring 64 fields must not make each log line cost more than
// declaring one.
func TestLokiMetadataFieldsAreNotRebuiltPerRecord(t *testing.T) {
	f := newFixture(t)
	const entries = 3000
	values := make([][]string, entries)
	for i := range values {
		values[i] = []string{strconv.Itoa(1_700_000_000_123_456_789 + i), "alpha"}
	}
	body, err := json.Marshal(map[string]any{"streams": []any{map[string]any{"stream": map[string]string{"app": "web", "region": "eu"}, "values": values}}})
	if err != nil {
		t.Fatal(err)
	}
	allocated := func(fields int) uint64 {
		cfg := f.profile()
		cfg.Loki.MetadataFields = []string{"tenant"}
		for i := 1; i < fields; i++ {
			cfg.Loki.MetadataFields = append(cfg.Loki.MetadataFields, fmt.Sprintf("field%02d", i))
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if _, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(body), cfg); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc
	}
	few, many := allocated(1), allocated(64)
	if many > few+few/4 {
		t.Fatalf("%d log lines allocate %d bytes with 1 declared metadata field and %d with 64: the field list is rebuilt per record", entries, few, many)
	}
}

// The output budget charges each record an estimate of its canonical size before
// the record is marshaled. The estimate has to be an upper bound (an
// underestimate would let a request expand past the budget) and not absurdly
// loose (an overestimate would refuse requests the limits advertise).
func TestRecordCostIsAnUpperBoundOfTheCanonicalSize(t *testing.T) {
	f := newFixture(t)
	checked := 0
	check := func(name string, r model.Record) {
		t.Helper()
		raw, err := model.CanonicalJSON(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cost := RecordCost(&r); cost < int64(len(raw)) || cost > 3*int64(len(raw)) {
			t.Errorf("%s: estimated %d bytes for a record that encodes to %d", name, cost, len(raw))
		}
		checked++
	}
	for _, c := range loadCorpus(t) {
		if c.Expected.Error != nil {
			continue
		}
		batches, _, err := f.runCase(c)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		for _, b := range batches {
			for _, r := range b.Records {
				check(c.ID, r)
			}
		}
	}
	cfg := f.profile()
	at := model.UnixNano(1_700_000_000_000_000_000)
	one := model.FloatBits(0x3ff0000000000000)
	trace, span := model.ID{0xaa, 1}, model.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	var wide model.Labels
	for i := range 64 {
		wide = append(wide, model.Label{Name: fmt.Sprintf("label_%02d%s", i, strings.Repeat("n", 90)), Value: strings.Repeat("v", 1000)})
	}
	rec, err := newMetricRecord(fmtNormalize, model.MetricPoint{Name: "hs_cost_wide", Labels: wide, SampleKind: "float", Value: &one, StartTimestamp: &at,
		Unit: "1", Type: "counter", ExemplarTrace: &trace, ExemplarSpan: &span}, at, cfg)
	if err != nil {
		t.Fatal(err)
	}
	check("a metric with every optional field and 64 wide labels", rec)
	bounds := make([]model.FloatBits, 999)
	for i := range bounds {
		bounds[i] = model.FloatBits(math.Float64bits(float64(i + 1)))
	}
	deltas := make([]model.DeltaBucket, 1000)
	for i := range deltas {
		deltas[i] = -(1<<62 + 12345)
	}
	deltas[0] = 1<<62 + 12345
	hist := &model.IntegerHistogram{Flavor: "counter", Schema: -53, ResetHint: "unknown", Count: model.Uint64(math.MaxUint64), Sum: one,
		PositiveSpans: []model.HistogramSpan{{Offset: 0, Length: 1000}}, PositiveBuckets: deltas, CustomBounds: bounds}
	rec, err = newMetricRecord(fmtNormalize, model.MetricPoint{Name: "hs_cost_hist", Labels: model.Labels{{Name: "job", Value: "api"}}, SampleKind: "integer_histogram",
		Histogram: &model.NativeHistogram{Integer: hist}, Unit: "1", Type: "histogram"}, at, cfg)
	if err != nil {
		t.Fatal(err)
	}
	check("a custom-bucket histogram of 1000 buckets with 19 digit counts", rec)
	longLines, err := json.Marshal(map[string]any{"streams": []any{map[string]any{
		"stream": map[string]string{"app": "web", "region": "eu"},
		"values": [][]any{{"1700000000123456789", strings.Repeat("l", 4096), map[string]string{"tenant": strings.Repeat("m", 4096)}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	logs, err := DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(longLines), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range logs {
		for _, r := range b.Records {
			check("a log record with a 4096 byte line and a 4096 byte metadata value", r)
		}
	}
	if checked < 30 {
		t.Fatalf("only %d records were compared", checked)
	}
}

// What shapes a request's records is part of its identity: the same bytes under
// another resource, unit or mapping are other records and must not share a batch
// identifier. What a format never reads is not, so a retried request keeps its
// identity when an unrelated setting changed, and the order of a set (the declared
// metadata fields) changes nothing.
func TestRequestIdentityTracksOnlyWhatShapesTheRecords(t *testing.T) {
	f := newFixture(t)
	base := f.profile()
	om := []byte("# TYPE hs_id gauge\nhs_id 1 1700000000\n# EOF\n")
	series := `[{"labels":{"__name__":"hs_id","job":"api"},"samples":[{"bits":"3ff0000000000000","timestamp_ms":"1700000000000"}]}]`
	rw1 := snappyEncode(hsRW(t, `{"version":1,"timeseries":`+series+`}`))
	rw2 := snappyEncode(hsRW(t, `{"version":2,"timeseries":`+series+`}`))
	push := lokiBodyNoMetadata("alpha")
	hook := []byte(`{"version":1,"events":[{"condition":"hs-id","epoch":"e1","sequence":"1","event_time_ns":"1700000000123456789","status":"firing","severity":"info","labels":{},"links":[]}]}`)
	formats := map[string]func(InputProfile) ([]model.Batch, error){
		"openmetrics": func(c InputProfile) ([]model.Batch, error) {
			return DecodeOpenMetrics(f.ctx, f.grant(), bytes.NewReader(om), c)
		},
		"remote write v1": func(c InputProfile) ([]model.Batch, error) {
			return DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV1, bytes.NewReader(rw1), c)
		},
		"remote write v2": func(c InputProfile) ([]model.Batch, error) {
			return DecodeRemoteWrite(f.ctx, f.grant(), RemoteWriteV2, bytes.NewReader(rw2), c)
		},
		"loki push": func(c InputProfile) ([]model.Batch, error) {
			return DecodeLokiPush(f.ctx, f.grant(), bytes.NewReader(push), c)
		},
		"conditions": func(c InputProfile) ([]model.Batch, error) {
			return DecodeConditions(f.ctx, f.grant(), bytes.NewReader(hook), c)
		},
	}
	batchIDs := func(format string, c InputProfile) []model.ID {
		t.Helper()
		batches, err := formats[format](c)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		ids, _ := identitiesOf(batches)
		return ids
	}
	for _, v := range []struct {
		name    string
		mutate  func(*InputProfile)
		changes []string // the formats whose identifiers must change; every other format keeps them
	}{
		{"resource instance", func(p *InputProfile) { p.Resource.Instance = "inst-2" }, []string{"openmetrics", "remote write v1", "remote write v2", "loki push", "conditions"}},
		{"resource label", func(p *InputProfile) { p.Resource.Labels = model.Labels{{Name: "job", Value: "api"}} }, []string{"openmetrics", "remote write v1", "remote write v2", "loki push", "conditions"}},
		{"default unit", func(p *InputProfile) { p.DefaultUnit = "s" }, []string{"openmetrics", "remote write v1", "remote write v2"}},
		{"default timestamp", func(p *InputProfile) { p.DefaultTimestamp++ }, []string{"openmetrics"}},
		{"loki template", func(p *InputProfile) { p.Loki.TemplateID = "migrated.line" }, []string{"loki push"}},
		{"loki template revision", func(p *InputProfile) { p.Loki.TemplateRevision = 2 }, []string{"loki push"}},
		{"loki line field", func(p *InputProfile) { p.Loki.LineField = "msg" }, []string{"loki push"}},
		{"loki metadata field names", func(p *InputProfile) { p.Loki.MetadataFields = []string{"other"} }, []string{"loki push"}},
		{"loki metadata field count", func(p *InputProfile) { p.Loki.MetadataFields = []string{"tenant", "other"} }, []string{"loki push"}},
	} {
		t.Run(v.name, func(t *testing.T) {
			changed := base
			v.mutate(&changed)
			for format := range formats {
				differs := false
				for _, c := range v.changes {
					differs = differs || c == format
				}
				got := !reflect.DeepEqual(batchIDs(format, base), batchIDs(format, changed))
				if got != differs {
					t.Errorf("%s: identifiers changed = %v, want %v", format, got, differs)
				}
			}
		})
	}
	forward, backward := base, base
	forward.Loki.MetadataFields = []string{"tenant", "other"}
	backward.Loki.MetadataFields = []string{"other", "tenant"}
	if !reflect.DeepEqual(batchIDs("loki push", forward), batchIDs("loki push", backward)) {
		t.Error("the order of the declared metadata fields changed the identifiers")
	}
}

// A request that is spread over many owner slots asks about cancellation for
// every slot: once before its records are normalized, once when they are
// normalized and once per batch it is cut into.
func TestEverySlotOfARequestAsksForCancellation(t *testing.T) {
	f := newFixture(t)
	series := make([]func(*hsPB), 300)
	for i := range series {
		series[i] = hsV1One([2]string{"__name__", fmt.Sprintf("hs_slot_%03d", i)})
	}
	gc := &hsGapCtx{Context: f.ctx}
	batches, err := DecodeRemoteWrite(gc, f.grant(), RemoteWriteV1, bytes.NewReader(snappyEncode(hsV1Req(series...))), f.profile())
	if err != nil {
		t.Fatal(err)
	}
	if len(batches) < 32 {
		t.Fatalf("test setup: only %d owner slots", len(batches))
	}
	if want := 3 * len(batches); len(gc.marks) < want {
		t.Fatalf("%d cancellation checks for %d slots, want at least %d", len(gc.marks), len(batches), want)
	}
}

// The references of a series (or exemplar) are bounded by the label limit before
// any of them is kept: a series that names hundreds of thousands of labels is
// refused after the first few, not after they were all gathered and paired.
func TestRemoteWriteV2LabelReferenceFloodIsRefusedEarly(t *testing.T) {
	f := newFixture(t)
	cfg := f.profile()
	s := newHSSyms()
	one := s.ref("a")
	flood := func(encode func(ts *hsPB, refs []uint64), exemplar bool) []byte {
		refs := make([]uint64, 400_000)
		for i := range refs {
			refs[i] = one
		}
		var ts hsPB
		if exemplar {
			ts.bytes(1, hsPacked(s.ref("__name__"), s.ref("hs_flood")))
			hsSample(&ts, 0x3ff0000000000000, hsTS)
			ts.msg(4, func(m *hsPB) { encode(m, refs) })
		} else {
			encode(&ts, refs)
			hsSample(&ts, 0x3ff0000000000000, hsTS)
		}
		return s.request(ts.b)
	}
	packed := func(ts *hsPB, refs []uint64) { ts.bytes(1, hsPacked(refs...)) }
	unpacked := func(ts *hsPB, refs []uint64) {
		for _, r := range refs {
			ts.varint(1, r)
		}
	}
	cfg.Exemplars = ExemplarsTraceLink
	for name, body := range map[string][]byte{
		"series, packed":     flood(packed, false),
		"series, unpacked":   flood(unpacked, false),
		"exemplar, packed":   flood(packed, true),
		"exemplar, unpacked": flood(unpacked, true),
	} {
		t.Run(name, func(t *testing.T) {
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := hsDecodeRW(f, RemoteWriteV2, body, cfg)
			runtime.ReadMemStats(&after)
			if reasonOf(err) != ReasonLimit {
				t.Fatalf("400000 label references were not refused as a limit: %v", err)
			}
			if used := after.TotalAlloc - before.TotalAlloc; used > 6<<20 {
				t.Fatalf("the refusal allocated %d bytes: the references were gathered before the limit applied", used)
			}
		})
	}
}

// The request digest is the root of every deterministic batch and record
// identifier, so it is what lets a retried request find its receipts: a silent
// change of its layout would strand the retries of a sender across an upgrade.
// These values pin it. A deliberate change (a new input, a new domain) updates
// them together with the decision that every identifier moves once.
func TestRequestDigestIsPinned(t *testing.T) {
	p := InputProfile{
		Project: model.ID{1}, Source: model.ID{2}, Producer: model.ID{3}, PolicyRevision: 7,
		Resource:    model.Resource{Service: model.ID{4}, Environment: model.ID{5}, Build: model.ID{6}, Instance: "inst-1", Labels: model.Labels{}},
		DefaultUnit: "s", DefaultTimestamp: 1_700_000_005_000_000_000,
		Loki: LokiMapping{Encoding: EncodingJSON, TemplateID: "t", TemplateRevision: 3, LineField: "line", MetadataFields: []string{"b", "a"}},
	}
	body := []byte("pinned body")
	for _, c := range []struct{ format, want string }{
		{"openmetrics", "5966824d531524de01976fd838da75e347e6330522ee253ec502295f95f51ede"},
		{"remote_write_v1", "397c5b2a105fa9888fc23bfb7a2ad0171ea1f22f2a7795a9a60b7712eed403e6"},
		{"remote_write_v2", "c2682f5d90d420468e1532328c6b19faee18c1d7bf16444db0a72f3bc17c7719"},
		{"loki_push/json", "a2792a8b0ad50ee8d67fb63558aebe19719806fab0fb8679e3a177af9ee03bd1"},
		{"condition_webhook", "252d3da558cace2e3e39b0ad39c23556322c8bf049863fcd2b7300af9051cc84"},
	} {
		got := RequestDigest(c.format, p, body)
		if hex.EncodeToString(got[:]) != c.want {
			t.Errorf("%s: digest %x, pinned %q", c.format, got, c.want)
		}
	}
}
