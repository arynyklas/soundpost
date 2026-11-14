// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// ---- fixtures ----

func floatBits(v float64) *model.FloatBits {
	b := model.FloatBits(math.Float64bits(v))
	return &b
}

func element(id string, v float64) query.VectorElement {
	return query.VectorElement{Labels: model.Labels{{Name: "__name__", Value: dcMetric}, {Name: "batch", Value: id}}, Sample: query.Sample{Time: 1, Float: floatBits(v)}}
}

// countElement is a count_over_time series: the engine drops the metric name there.
func countElement(id string, v float64) query.VectorElement {
	e := element(id, v)
	e.Labels = e.Labels[1:]
	return e
}

func answer(t *testing.T, completeness string, failure *query.Failure, value *query.Value, projects int) []byte {
	t.Helper()
	var result query.Result
	for range projects {
		result.Projects = append(result.Projects, query.ProjectResult{ProjectID: model.NewID(), Value: value, Completeness: completeness, Failure: failure})
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func vector(elements ...query.VectorElement) *query.Value {
	return &query.Value{Type: query.ValueVector, Vector: elements}
}

func drillBatch(t *testing.T, value float64) model.Batch {
	t.Helper()
	id := model.NewID()
	record := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Payload: model.Payload{Metric: &model.MetricPoint{
		Name: dcMetric, Labels: model.Labels{{Name: "batch", Value: id.String()}}, SampleKind: "float", Value: floatBits(value), Unit: "1", Type: "gauge"}}}
	return model.Batch{Version: 1, ID: id, Records: []model.Record{record}}
}

// ---- digests: what a reader must retrieve ----

func TestDCDigestCoversIdAndExactValueBits(t *testing.T) {
	base := dcDigest("a", math.Float64bits(1.25))
	if base != dcDigest("a", math.Float64bits(1.25)) {
		t.Fatal("the digest is not deterministic")
	}
	if base == dcDigest("b", math.Float64bits(1.25)) {
		t.Fatal("a different batch id has the same digest")
	}
	if base == dcDigest("a", math.Float64bits(1.2500000000000002)) {
		t.Fatal("one ulp of value difference is not detected")
	}
	if dcDigest("a", math.Float64bits(math.Copysign(0, -1))) == dcDigest("a", 0) {
		t.Fatal("negative zero and zero are the same data")
	}
}

func TestDCBatchSemanticsAgreeWithReadBack(t *testing.T) {
	b := drillBatch(t, 7.25)
	id, digest, err := dcBatchSemantics(b)
	if err != nil {
		t.Fatal(err)
	}
	read, err := dcVectorDigests(answer(t, query.CompletenessComplete, nil, vector(element(id, 7.25)), 1))
	if err != nil {
		t.Fatal(err)
	}
	if read[id] != digest {
		t.Fatalf("the digest of the sent batch %s and of the data read back %s differ", digest, read[id])
	}
	wrong, err := dcVectorDigests(answer(t, query.CompletenessComplete, nil, vector(element(id, 7.5)), 1))
	if err != nil {
		t.Fatal(err)
	}
	if wrong[id] == digest {
		t.Fatal("a different value was read back and the digest still equals the acknowledged one")
	}
}

func TestDCBatchSemanticsRejectsAnythingThatIsNotOneDrillRecord(t *testing.T) {
	good := drillBatch(t, 1)
	two := good
	two.Records = append(append([]model.Record(nil), good.Records...), good.Records[0])
	otherLabel := drillBatch(t, 1)
	otherLabel.Records[0].Payload.Metric.Labels = model.Labels{{Name: "batch", Value: "not-the-batch-id"}}
	renamed := drillBatch(t, 1)
	renamed.Records[0].Payload.Metric.Name = "other"
	noValue := drillBatch(t, 1)
	noValue.Records[0].Payload.Metric.Value = nil
	twoLabels := drillBatch(t, 1)
	twoLabels.Records[0].Payload.Metric.Labels = append(twoLabels.Records[0].Payload.Metric.Labels, model.Label{Name: "z", Value: "1"})
	for name, b := range map[string]model.Batch{"two records": two, "label is not the batch id": otherLabel, "other metric": renamed, "no value": noValue, "two labels": twoLabels, "no records": {ID: good.ID}} {
		if _, _, err := dcBatchSemantics(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- reading back ----

func TestDCVectorDigestsAreExactPerId(t *testing.T) {
	raw := answer(t, query.CompletenessComplete, nil, vector(element("a", 1.25), element("b", 2.25)), 1)
	got, err := dcVectorDigests(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["a"] != dcDigest("a", math.Float64bits(1.25)) || got["b"] != dcDigest("b", math.Float64bits(2.25)) {
		t.Fatalf("digests: %v", got)
	}
	if empty, err := dcVectorDigests(answer(t, query.CompletenessComplete, nil, vector(), 1)); err != nil || len(empty) != 0 {
		t.Fatalf("an empty complete vector is an empty read back, not an error: %v %v", empty, err)
	}
}

func TestDCVectorDigestsRefuseEverythingThatIsNotACompleteExactAnswer(t *testing.T) {
	hist := element("a", 1)
	hist.Sample.Float = nil
	noLabel := query.VectorElement{Sample: query.Sample{Float: floatBits(1)}}
	extra := element("a", 1)
	extra.Labels = append(extra.Labels, model.Label{Name: "service", Value: "x"})
	otherMetric := element("a", 1)
	otherMetric.Labels[0].Value = "some_other_metric"
	nameOnly := element("a", 1)
	nameOnly.Labels = nameOnly.Labels[:1]
	cases := map[string][]byte{
		"partial":        answer(t, query.CompletenessPartial, nil, vector(element("a", 1)), 1),
		"stale":          answer(t, query.CompletenessStale, nil, vector(element("a", 1)), 1),
		"typed failure":  answer(t, query.CompletenessComplete, &query.Failure{Code: "unavailable"}, vector(element("a", 1)), 1),
		"two projects":   answer(t, query.CompletenessComplete, nil, vector(element("a", 1)), 2),
		"no project":     answer(t, query.CompletenessComplete, nil, vector(element("a", 1)), 0),
		"scalar":         answer(t, query.CompletenessComplete, nil, &query.Value{Type: query.ValueScalar, Scalar: query.Sample{Float: floatBits(1)}}, 1),
		"duplicate id":   answer(t, query.CompletenessComplete, nil, vector(element("a", 1), element("a", 2)), 1),
		"no batch label": answer(t, query.CompletenessComplete, nil, vector(noLabel), 1),
		"extra label":    answer(t, query.CompletenessComplete, nil, vector(extra), 1),
		"other metric":   answer(t, query.CompletenessComplete, nil, vector(otherMetric), 1),
		"name only":      answer(t, query.CompletenessComplete, nil, vector(nameOnly), 1),
		"not a float":    answer(t, query.CompletenessComplete, nil, vector(hist), 1),
		"not json":       []byte("<html>"),
	}
	for name, raw := range cases {
		if got, err := dcVectorDigests(raw); err == nil {
			t.Errorf("%s: accepted as %v", name, got)
		}
	}
}

func TestDCSampleCountsAndVerifyCounts(t *testing.T) {
	counts, err := dcSampleCounts(answer(t, query.CompletenessComplete, nil, vector(countElement("a", 1), countElement("b", 2)), 1))
	if err != nil || counts["a"] != 1 || counts["b"] != 2 {
		t.Fatalf("counts: %v %v", counts, err)
	}
	acks := []Ack{{ID: "a"}, {ID: "b"}}
	if err := dcVerifyCounts(counts, acks); err == nil || !strings.Contains(err.Error(), "b=2") {
		t.Fatalf("a batch stored twice was not detected: %v", err)
	}
	if err := dcVerifyCounts(map[string]uint64{"a": 1}, acks); err == nil || !strings.Contains(err.Error(), "b=0") {
		t.Fatalf("a batch stored zero times was not detected: %v", err)
	}
	if err := dcVerifyCounts(map[string]uint64{"a": 1, "b": 1}, acks); err != nil {
		t.Fatalf("exactly one copy each was refused: %v", err)
	}
	for name, v := range map[string]float64{"fraction": 1.5, "negative": -1, "infinite": math.Inf(1), "nan": math.NaN()} {
		if _, err := dcSampleCounts(answer(t, query.CompletenessComplete, nil, vector(countElement("a", v)), 1)); err == nil {
			t.Errorf("%s: accepted as a count", name)
		}
	}
	if _, err := dcSampleCounts(answer(t, query.CompletenessPartial, nil, vector(countElement("a", 1)), 1)); err == nil {
		t.Error("a partial count answer was accepted")
	}
	if _, err := dcSampleCounts(answer(t, query.CompletenessComplete, nil, vector(element("a", 1)), 1)); err == nil {
		t.Error("a count series that still carries the metric name was accepted")
	}
}

func TestDCUnknownRetainedAndIdenticalMembers(t *testing.T) {
	if got := dcUnknownRetained(map[string]string{"a": "x", "z": "y"}, map[string]bool{"a": true}); len(got) != 1 || got[0] != "z" {
		t.Fatalf("unknown ids: %v", got)
	}
	same := map[uint64]map[string]string{1: {"a": "x"}, 2: {"a": "x"}, 3: {"a": "x"}}
	if err := dcIdenticalMembers(same); err != nil {
		t.Fatalf("identical members refused: %v", err)
	}
	for name, members := range map[string]map[uint64]map[string]string{
		"one member lacks an id":       {1: {"a": "x", "b": "y"}, 2: {"a": "x", "b": "y"}, 3: {"a": "x"}},
		"one member holds another one": {1: {"a": "x"}, 2: {"a": "x"}, 3: {"b": "x"}},
		"one member differs in data":   {1: {"a": "x"}, 2: {"a": "x"}, 3: {"a": "DIFFERENT"}},
		"first member differs":         {1: {"a": "DIFFERENT"}, 2: {"a": "x"}, 3: {"a": "x"}},
	} {
		if err := dcIdenticalMembers(members); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---- classifying an ingest attempt ----

func receiptJSON(id model.ID, index uint64) []byte {
	raw, _ := json.Marshal(model.Receipt{Version: 1, BatchID: id, Cursor: model.Cursor{Group: model.NewID(), Index: model.Uint64(index)}})
	return raw
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestDCClassifyIngest(t *testing.T) {
	id, other := model.NewID(), model.NewID()
	typed := func(code string, retryable bool) []byte {
		raw, _ := json.Marshal(map[string]any{"code": code, "retryable": retryable, "detail": code})
		return raw
	}
	refused := &url.Error{Op: "Post", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
	cases := []struct {
		name    string
		status  int
		body    []byte
		err     error
		want    dcVerdict
		contain string
	}{
		{"acknowledged", 200, receiptJSON(id, 5), nil, dcAcked, ""},
		{"200 for another batch", 200, receiptJSON(other, 5), nil, dcMalformed, ""},
		{"200 without a cursor", 200, receiptJSON(id, 0), nil, dcMalformed, ""},
		{"200 empty body", 200, nil, nil, dcMalformed, ""},
		{"200 with html", 200, []byte("<html>"), nil, dcMalformed, ""},
		{"typed unavailable", 503, typed("unavailable", true), nil, dcTypedRefusal, "unavailable"},
		{"typed timeout", 503, typed("timeout", true), nil, dcTypedRefusal, "timeout"},
		{"typed stale", 503, typed("stale", true), nil, dcTypedRefusal, "stale"},
		{"503 not retryable", 503, typed("unavailable", false), nil, dcMalformed, ""},
		{"503 corrupt is not a quorum refusal", 503, typed("corrupt", true), nil, dcMalformed, ""},
		{"503 without a body", 503, nil, nil, dcMalformed, ""},
		{"503 html", 503, []byte("<html>busy</html>"), nil, dcMalformed, ""},
		{"429", 429, typed("quota", true), nil, dcRejected, "429_quota"},
		{"422 invalid", 422, typed("invalid", false), nil, dcRejected, "422_invalid"},
		{"401", 401, typed("unauthenticated", false), nil, dcRejected, "401"},
		{"500 with an attacker-shaped body", 500, []byte(`{"code":"Not A Token!"}`), nil, dcRejected, "unknown"},
		{"connection refused", 0, nil, refused, dcTransport, "connection_refused"},
		{"timeout", 0, nil, &url.Error{Op: "Post", Err: timeoutError{}}, dcTransport, "timeout"},
		{"eof", 0, nil, &url.Error{Op: "Post", Err: io.EOF}, dcTransport, "eof"},
		{"unknown transport error", 0, nil, errors.New("something"), dcTransport, "transport_error"},
		{"an answer does not hide a transport error", 200, receiptJSON(id, 5), refused, dcTransport, ""},
	}
	for _, c := range cases {
		got, detail, receipt := dcClassifyIngest(c.status, c.body, c.err, id)
		if got != c.want {
			t.Errorf("%s: verdict %s (%s), want %s", c.name, got, detail, c.want)
		}
		if !strings.Contains(detail, c.contain) {
			t.Errorf("%s: detail %q lacks %q", c.name, detail, c.contain)
		}
		if got == dcAcked && receipt.BatchID != id {
			t.Errorf("%s: acknowledged without the receipt", c.name)
		}
		if got != dcAcked && receipt.BatchID != (model.ID{}) {
			t.Errorf("%s: a receipt escaped a non-acknowledgement", c.name)
		}
	}
}

func TestDCServedCompleteIsTrueOnlyForACompleteAnswer(t *testing.T) {
	ok := answer(t, query.CompletenessComplete, nil, vector(element("a", 1)), 1)
	if complete, _ := dcServedComplete(200, ok, nil); !complete {
		t.Fatal("a complete answer was not recognised")
	}
	for name, c := range map[string]struct {
		status int
		raw    []byte
		err    error
	}{
		"stale":                           {200, answer(t, query.CompletenessStale, nil, vector(element("a", 1)), 1), nil},
		"partial":                         {200, answer(t, query.CompletenessPartial, nil, vector(element("a", 1)), 1), nil},
		"failure":                         {200, answer(t, query.CompletenessComplete, &query.Failure{Code: "x"}, vector(element("a", 1)), 1), nil},
		"503":                             {503, ok, nil},
		"500":                             {500, ok, nil},
		"transport":                       {0, nil, errors.New("reset")},
		"not json":                        {200, []byte("{"), nil},
		"transport hides a complete body": {200, ok, errors.New("reset")},
	} {
		if complete, why := dcServedComplete(c.status, c.raw, c.err); complete {
			t.Errorf("%s: served as complete (%s)", name, why)
		}
	}
	if _, why := dcServedComplete(409, []byte(`{"code":"stale","retryable":true}`), nil); why != "status_409_stale" {
		t.Errorf("the closed fault code of a refused read is not reported: %q", why)
	}
	if _, why := dcServedComplete(500, []byte(`{"code":"Not A Token!"}`), nil); why != "status_500_unknown" {
		t.Errorf("an unsafe code reached the detail: %q", why)
	}
}

// ---- retries and timing ----

func TestDCVerifyRetriesRequiresIdenticalBodiesAndAnAcknowledgement(t *testing.T) {
	acks := []Ack{{ID: "a"}, {ID: "b"}}
	ok := []dcSent{{ID: "a", Member: 1, BodyHash: "h1", Verdict: dcTransport}, {ID: "a", Member: 2, BodyHash: "h1", Verdict: dcAcked}, {ID: "b", Member: 3, BodyHash: "h2", Verdict: dcAcked}}
	if err := dcVerifyRetries(ok, acks); err != nil {
		t.Fatalf("a retry with the identical body was refused: %v", err)
	}
	changed := []dcSent{{ID: "a", Member: 1, BodyHash: "h1", Verdict: dcTypedRefusal}, {ID: "a", Member: 2, BodyHash: "CHANGED", Verdict: dcAcked}, {ID: "b", Member: 3, BodyHash: "h2", Verdict: dcAcked}}
	if err := dcVerifyRetries(changed, acks); err == nil {
		t.Fatal("a refused batch retried with a different body was accepted")
	}
	abandoned := []dcSent{{ID: "a", Member: 1, BodyHash: "h1", Verdict: dcTypedRefusal}, {ID: "b", Member: 3, BodyHash: "h2", Verdict: dcAcked}}
	if err := dcVerifyRetries(abandoned, acks[1:]); err == nil {
		t.Fatal("a refused batch that was never acknowledged was accepted")
	}
	if err := dcVerifyRetries(abandoned, acks); err != nil {
		t.Fatalf("a refused batch that the ledger acknowledges was refused: %v", err)
	}
}

func TestDCAckTimes(t *testing.T) {
	t0 := time.Unix(1000, 0)
	ms := time.Millisecond
	times := []dcAckTime{
		{ID: "a", Started: t0.Add(-2 * time.Second), At: t0.Add(-time.Second)},
		{ID: "b", Started: t0.Add(3*time.Second - ms), At: t0.Add(3 * time.Second)},
		{ID: "c", Started: t0.Add(2*time.Second - ms), At: t0.Add(2 * time.Second)},
		{ID: "d", Started: t0.Add(9*time.Second - ms), At: t0.Add(9 * time.Second)},
		// in flight when the fault happened, completed right after it: proves nothing
		{ID: "e", Started: t0.Add(-ms), At: t0.Add(ms)},
	}
	if d, ok := dcFirstAckAfter(times, t0); !ok || d != 2*time.Second {
		t.Fatalf("first ack after (only requests started after the fault count): %v %v", d, ok)
	}
	if _, ok := dcFirstAckAfter(times, t0.Add(time.Hour)); ok {
		t.Fatal("an acknowledgement before the fault counted as one after it")
	}
	if _, ok := dcFirstAckAfter(nil, t0); ok {
		t.Fatal("no acknowledgement reported as one")
	}
	if n := dcAcksBetween(times, t0, t0.Add(3*time.Second)); n != 3 {
		t.Fatalf("acks in (t0, t0+3s]: %d", n)
	}
	if n := dcAcksBetween(times, t0, time.Time{}); n != 4 {
		t.Fatalf("acks after t0: %d", n)
	}
	if n := dcAcksStartedAfter(times, t0); n != 3 {
		t.Fatalf("acks started after t0 (in-flight and earlier requests excluded): %d", n)
	}
	if n := dcAcksStartedAfter(times, time.Time{}); n != 5 {
		t.Fatalf("a zero time counts every request: %d", n)
	}
	if !dcAckedAfter(times, "b", t0) || dcAckedAfter(times, "a", t0) || dcAckedAfter(times, "zz", t0) {
		t.Fatal("dcAckedAfter")
	}
}

func TestDCLedgerHas(t *testing.T) {
	acks := []Ack{{ID: "a"}}
	if !dcLedgerHas(acks, "a") || dcLedgerHas(acks, "b") {
		t.Fatal("dcLedgerHas")
	}
}

func TestDCProcState(t *testing.T) {
	for stat, want := range map[string]byte{
		"123 (soundpost) T 1 123 123 0 -1 ":     'T',
		"123 (soundpost) S 1 123 123 0 -1 ":     'S',
		"123 (a b) c) R 1 123":                  'R',
		"123 (weird name (with parens)) t 1 2 ": 't',
	} {
		got, err := dcProcState(stat)
		if err != nil || got != want {
			t.Errorf("%q: %c %v, want %c", stat, got, err, want)
		}
	}
	for _, bad := range []string{"", "123", "123 (x)", "123 (x)T"} {
		if _, err := dcProcState(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestDCSameCursorAndSafeToken(t *testing.T) {
	if !dcSameCursor(map[uint64]uint64{1: 7, 2: 7, 3: 7}, 3) {
		t.Fatal("equal cursors refused")
	}
	if dcSameCursor(map[uint64]uint64{1: 7, 2: 7, 3: 8}, 3) || dcSameCursor(map[uint64]uint64{1: 7, 2: 7}, 3) || dcSameCursor(nil, 0) {
		t.Fatal("different or missing cursors accepted")
	}
	for in, want := range map[string]string{"no_quorum": "no_quorum", "": "unknown", "Has Space": "unknown", "x\ny": "unknown", strings.Repeat("a", 40): "unknown"} {
		if got := dcSafeToken(in); got != want {
			t.Errorf("dcSafeToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- the reconciliation of a read back against the ledger ----

func TestDCReadBackThroughTheLedgerDetectsOneWrongValueOneMissingIdAndOneDuplicate(t *testing.T) {
	var led Ledger
	var raw []model.Batch
	for i := range 4 {
		b := drillBatch(t, float64(i)+0.25)
		id, digest, err := dcBatchSemantics(b)
		if err != nil {
			t.Fatal(err)
		}
		if err = led.Record(Ack{ID: id, Group: "g", Index: uint64(i + 1), Digest: digest}); err != nil {
			t.Fatal(err)
		}
		raw = append(raw, b)
	}
	elements := func(skip int, wrong int) []query.VectorElement {
		var out []query.VectorElement
		for i, b := range raw {
			if i == skip {
				continue
			}
			v := float64(i) + 0.25
			if i == wrong {
				v += 1
			}
			out = append(out, element(b.ID.String(), v))
		}
		return out
	}
	read := func(els []query.VectorElement) map[string]string {
		m, err := dcVectorDigests(answer(t, query.CompletenessComplete, nil, vector(els...), 1))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if _, err := Reconcile(&led, read(elements(-1, -1))); err != nil {
		t.Fatalf("exact read back refused: %v", err)
	}
	var rerr *ReconcileError
	if _, err := Reconcile(&led, read(elements(2, -1))); !errors.As(err, &rerr) || len(rerr.Missing) != 1 {
		t.Fatalf("a missing id was not detected: %v", err)
	}
	if _, err := Reconcile(&led, read(elements(-1, 1))); !errors.As(err, &rerr) || len(rerr.Mismatched) != 1 {
		t.Fatalf("a wrong value was not detected: %v", err)
	}
}

// ---- the per-member verification of a whole cluster ----

type fakeCluster struct {
	rep    *Report
	issued map[string]bool
	data   map[uint64]map[string]string
	counts map[uint64]map[string]uint64
	errs   map[uint64]error
}

func newFakeCluster(t *testing.T) *fakeCluster {
	t.Helper()
	f := &fakeCluster{rep: &Report{}, issued: map[string]bool{}, data: map[uint64]map[string]string{}, counts: map[uint64]map[string]uint64{}, errs: map[uint64]error{}}
	for _, id := range []string{"a", "b", "c"} {
		digest := dcDigest(id, math.Float64bits(float64(len(id))+0.25))
		if err := f.rep.Ledger().Record(Ack{ID: id, Group: "g", Index: uint64(len(f.issued) + 1), Digest: digest}); err != nil {
			t.Fatal(err)
		}
		f.issued[id] = true
		for _, m := range dcMembers {
			if f.data[m.id] == nil {
				f.data[m.id], f.counts[m.id] = map[string]string{}, map[string]uint64{}
			}
			f.data[m.id][id], f.counts[m.id][id] = digest, 1
		}
	}
	return f
}

func (f *fakeCluster) read(member uint64) (map[string]string, map[string]uint64, error) {
	return f.data[member], f.counts[member], f.errs[member]
}

func (f *fakeCluster) failed() []string {
	var out []string
	for _, c := range f.rep.Checks {
		if !c.OK {
			out = append(out, c.Name)
		}
	}
	return out
}

func TestDCVerifyWithAcceptsThreeIdenticalExactMembers(t *testing.T) {
	f := newFakeCluster(t)
	got, err := dcVerifyWith(f.read, f.issued, f.rep, "p")
	if err != nil || len(got) != 3 || len(f.failed()) != 0 {
		t.Fatalf("a correct cluster was refused: %v %v %v", got, err, f.failed())
	}
	if len(f.rep.Checks) != 3*3+1 {
		t.Fatalf("expected three checks per member plus the identity check, got %d: %+v", len(f.rep.Checks), f.rep.Checks)
	}
}

func TestDCVerifyWithDetectsEachWayOneMemberCanBeWrong(t *testing.T) {
	cases := map[string]struct {
		mutate func(f *fakeCluster)
		check  string
	}{
		"one member lacks an acknowledged id":  {func(f *fakeCluster) { delete(f.data[2], "b") }, "p_member_2_exact_reconciliation"},
		"one member holds other content":       {func(f *fakeCluster) { f.data[3]["c"] = dcDigest("c", 99) }, "p_member_3_exact_reconciliation"},
		"one member stored a batch twice":      {func(f *fakeCluster) { f.counts[1]["a"] = 2 }, "p_member_1_no_duplicate_data"},
		"one member stored a batch zero times": {func(f *fakeCluster) { f.counts[2]["a"] = 0 }, "p_member_2_no_duplicate_data"},
		"one member holds an id never issued":  {func(f *fakeCluster) { f.data[3]["zzz"] = "x" }, "p_member_3_no_unknown_ids"},
		"one member cannot be read":            {func(f *fakeCluster) { f.data[2], f.errs[2] = nil, errors.New("down") }, "p_member_2_readable"},
	}
	for name, c := range cases {
		f := newFakeCluster(t)
		c.mutate(f)
		if _, err := dcVerifyWith(f.read, f.issued, f.rep, "p"); err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		found := false
		for _, n := range f.failed() {
			found = found || n == c.check
		}
		if !found {
			t.Errorf("%s: the failing check %s was not recorded, failed: %v", name, c.check, f.failed())
		}
	}
}

func TestDCVerifyWithRequiresIdenticalMembersEvenWhenEachReconciles(t *testing.T) {
	f := newFakeCluster(t)
	// "d" was issued but never acknowledged: reconciliation tolerates a committed-but-unacknowledged
	// batch, but one member retaining it and the others not is a divergence.
	f.issued["d"] = true
	f.data[3]["d"], f.counts[3]["d"] = dcDigest("d", 1), 1
	if _, err := dcVerifyWith(f.read, f.issued, f.rep, "p"); err == nil {
		t.Fatal("members that retain different data were accepted")
	}
	if got := f.failed(); len(got) != 1 || got[0] != "p_members_identical" {
		t.Fatalf("only the identity check should fail, failed: %v", got)
	}
}
