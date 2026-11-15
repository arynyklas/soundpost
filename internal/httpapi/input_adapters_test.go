// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// ---- test-side wire encoders (they follow the published schemas) ----

type pb struct{ b []byte }

func (w *pb) tag(num, wt uint64) { w.b = binary.AppendUvarint(w.b, num<<3|wt) }
func (w *pb) varint(num, v uint64) {
	w.tag(num, 0)
	w.b = binary.AppendUvarint(w.b, v)
}
func (w *pb) fixed64(num, v uint64) {
	w.tag(num, 1)
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
}
func (w *pb) bytes(num uint64, p []byte) {
	w.tag(num, 2)
	w.b = binary.AppendUvarint(w.b, uint64(len(p)))
	w.b = append(w.b, p...)
}
func (w *pb) msg(num uint64, f func(*pb)) {
	var inner pb
	f(&inner)
	w.bytes(num, inner.b)
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

// remoteWriteV1 is a prometheus.WriteRequest with one sample per metric name.
func remoteWriteV1(names []string, tsMS int64, value float64) []byte {
	var req pb
	for _, name := range names {
		req.msg(1, func(ts *pb) {
			ts.msg(1, func(l *pb) { l.bytes(1, []byte("__name__")); l.bytes(2, []byte(name)) })
			ts.msg(1, func(l *pb) { l.bytes(1, []byte("job")); l.bytes(2, []byte("api")) })
			ts.msg(2, func(s *pb) { s.fixed64(1, math.Float64bits(value)); s.varint(2, uint64(tsMS)) })
		})
	}
	return req.b
}

// remoteWriteV2 is an io.prometheus.write.v2.Request with one sample per name.
func remoteWriteV2(names []string, tsMS int64, value float64) []byte {
	var req pb
	symbols := []string{"", "__name__", "job", "api"}
	index := map[string]uint64{}
	for i, s := range symbols {
		index[s] = uint64(i)
	}
	for _, n := range names {
		index[n] = uint64(len(symbols))
		symbols = append(symbols, n)
	}
	for _, s := range symbols {
		req.bytes(4, []byte(s))
	}
	for _, name := range names {
		req.msg(5, func(ts *pb) {
			var refs []byte
			for _, r := range []uint64{index["__name__"], index[name], index["job"], index["api"]} {
				refs = binary.AppendUvarint(refs, r)
			}
			ts.bytes(1, refs)
			ts.msg(2, func(s *pb) { s.fixed64(1, math.Float64bits(value)); s.varint(2, uint64(tsMS)) })
		})
	}
	return req.b
}

// lokiJSON pushes `perStream` entries to each of the given streams, all at the
// same nanosecond, so equal-time lines are legitimately distinct records.
func lokiJSON(t testing.TB, shards []string, ns int64, lines ...string) []byte {
	t.Helper()
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	}
	var req struct {
		Streams []stream `json:"streams"`
	}
	for _, shard := range shards {
		s := stream{Stream: map[string]string{"shard": shard}}
		for _, l := range lines {
			s.Values = append(s.Values, []string{strconv.FormatInt(ns, 10), l})
		}
		req.Streams = append(req.Streams, s)
	}
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// ---- environment ----

// lossyAdmitter wraps the real C03 admission and, for chosen admission
// numbers, makes the child durable and then loses the response: the sender
// saw a failure for data that is already stored.
type lossyAdmitter struct {
	inner httpapi.InputAdmitter
	mu    sync.Mutex
	calls int
	lose  map[int]bool
	lost  int
}

func (l *lossyAdmitter) ResolveSource(ctx context.Context, c ingest.SourceCredential, b ingest.Batch) (ingest.SourceGrant, error) {
	return l.inner.ResolveSource(ctx, c, b)
}
func (l *lossyAdmitter) Admit(ctx context.Context, g ingest.SourceGrant, b ingest.Batch) (ingest.Receipt, error) {
	receipt, err := l.inner.Admit(ctx, g, b)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if err == nil && l.lose[l.calls] {
		l.lost++
		return ingest.Receipt{}, model.Fail(model.Unavailable)
	}
	return receipt, err
}
func (l *lossyAdmitter) arm(calls ...int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls, l.lost, l.lose = 0, 0, map[int]bool{}
	for _, c := range calls {
		l.lose[c] = true
	}
}

type adapterEnv struct {
	*isoEnv
	srv    *httptest.Server
	adm    *lossyAdmitter
	org    model.ID
	p1, p2 model.ID
	s1, s2 sourceFixture
	reader person
	shards []string
}

const adapterTemplateLine = "migrated.line"

func newAdapterEnv(t *testing.T, cfg httpapi.InputAdapterConfig) *adapterEnv {
	t.Helper()
	base := newIsoEnv(t)
	e := &adapterEnv{isoEnv: base, p1: model.NewID(), p2: model.NewID()}
	e.org = base.org("adapters", e.p1, e.p2)
	for i := range 80 {
		e.shards = append(e.shards, fmt.Sprintf("s%02d", i))
	}
	policy := func() model.SourcePolicy {
		line := model.TemplateField{Name: "line", Type: "string", MaxBytes: 16, Sensitivity: "metadata", Values: []model.Scalar{scalarOf(t, "alpha"), scalarOf(t, "beta")}}
		return model.SourcePolicy{
			Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Metric, model.Log, model.Condition},
			Templates:     []model.LogTemplate{{ID: adapterTemplateLine, Revision: 1, Line: "{line}", Severity: "info", Fields: []model.TemplateField{line}}},
			Labels:        map[string][]string{"job": {"api"}, "shard": e.shards},
			RetentionDays: map[model.Kind]uint32{model.Metric: 7, model.Log: 7, model.Condition: 7}, MaxBytes: 64 << 20, MaxSeries: 5000,
		}
	}
	ids1 := sharedIDs{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID()}
	ids2 := sharedIDs{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID()}
	e.s1 = base.onboard(e.org, e.p1, model.NewID(), ids1, policy(), auth.SourcePolicyConfig{ProjectID: e.p1, Enabled: true})
	e.s2 = base.onboard(e.org, e.p2, model.NewID(), ids2, policy(), auth.SourcePolicyConfig{ProjectID: e.p2, Enabled: true})
	e.reader = base.user(e.org, "adapter-reader@example.test")
	base.grant(e.org, e.reader, e.p1, true, auth.Read)
	base.grant(e.org, e.reader, e.p2, true, auth.Read)
	e.adm = &lossyAdmitter{inner: base.app.Ingest, lose: map[int]bool{}}
	e.srv = httptest.NewTLSServer(httpapi.NewServer("", base.app.Auth, nil, func(mux *http.ServeMux) {
		httpapi.RegisterInputAdapterRoutes(mux, base.app.Auth, e.adm, cfg)
	}).Handler)
	t.Cleanup(e.srv.Close)
	return e
}

func scalarOf(t testing.TB, s string) model.Scalar {
	t.Helper()
	var v model.Scalar
	if err := json.Unmarshal([]byte(strconv.Quote(s)), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

type adapterReply struct {
	Status   int
	Header   http.Header
	Body     []byte
	Adapter  string `json:"adapter"`
	Admitted int    `json:"admitted"`
	Failed   int    `json:"failed"`
	Code     string `json:"code"`
	Retry    bool   `json:"retryable"`
	Children []struct {
		BatchID   string `json:"batch_id"`
		RouteSlot int    `json:"route_slot"`
		Records   int    `json:"records"`
		Status    string `json:"status"`
		Receipt   *struct {
			BatchID string `json:"batch_id"`
			Cursor  struct {
				Group string `json:"group"`
				Index any    `json:"index"`
			} `json:"cursor"`
		} `json:"receipt"`
		Fault *struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
		} `json:"fault"`
	} `json:"children"`
}

func (e *adapterEnv) post(t *testing.T, path, credential string, header map[string]string, body []byte) adapterReply {
	t.Helper()
	req, err := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := adapterReply{Status: resp.StatusCode, Header: resp.Header, Body: raw}
	_ = json.Unmarshal(raw, &out)
	return out
}

func lokiHeaders() map[string]string {
	return map[string]string{"Content-Type": "application/json", "X-Soundpost-Template": adapterTemplateLine, "X-Soundpost-Template-Revision": "1"}
}

func rwHeaders(v2 bool) map[string]string {
	ct := "application/x-protobuf"
	if v2 {
		ct += ";proto=io.prometheus.write.v2.Request"
	}
	return map[string]string{"Content-Type": ct, "Content-Encoding": "snappy"}
}

// count reads every stored row of one signal in one project through a real
// reader scope, the way a person's query would.
func (e *adapterEnv) count(t *testing.T, project model.ID, kind model.Kind) int {
	t.Helper()
	scope, err := e.scope(e.reader, e.org, project, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := e.app.Storage.Scan(e.ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for {
		page, err := rows.Next(e.ctx)
		if err == io.EOF {
			return n
		}
		if err != nil {
			t.Fatal(err)
		}
		n += page.Len()
	}
}

// conditionIDs reads the condition identities stored in one project.
func (e *adapterEnv) conditionIDs(t *testing.T, project model.ID) map[model.ID]bool {
	t.Helper()
	scope, err := e.scope(e.reader, e.org, project, auth.Read)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := e.app.Storage.Scan(e.ctx, scope, storage.ScanRequest{Projects: []model.ID{project}, Signal: model.Condition, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[model.ID]bool{}
	for {
		page, err := rows.Next(e.ctx)
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		for i := range page.Len() {
			out[page.Values[i].Condition.Condition] = true
		}
	}
}

func (r adapterReply) ids() []string {
	out := make([]string, len(r.Children))
	for i, c := range r.Children {
		out[i] = c.BatchID
	}
	return out
}

// TestInputAdapterPartialRetryAndScope loses the response of one child batch of
// a multi-child Loki push, retries the source request and proves: the sender is
// not ACKed while a child receipt is missing, the retry reuses the child
// identities, no logical data is duplicated (log lines at one nanosecond are
// distinct records, so a changed identity would double them), and neither the
// credential's project nor a header can steer data into another project.
func TestInputAdapterPartialRetryAndScope(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	now := time.Now().UnixNano() - int64(time.Minute)
	body := lokiJSON(t, e.shards, now, "alpha", "alpha", "beta")
	const entries = 80 * 3

	e.adm.arm(2) // the 2nd child is admitted durably, then its response is lost
	first := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if e.adm.lost != 1 {
		t.Fatalf("test setup: %d lost responses, want 1", e.adm.lost)
	}
	if len(first.Children) < 3 {
		t.Fatalf("a push over 80 streams must span several owner slots, got %d children: %s", len(first.Children), first.Body)
	}
	if first.Status != 503 || first.Header.Get("Retry-After") == "" || !first.Retry || first.Failed != 1 || first.Admitted != len(first.Children)-1 {
		t.Fatalf("a lost child receipt must not be ACKed and must be retryable: status=%d retry-after=%q admitted=%d failed=%d body=%s", first.Status, first.Header.Get("Retry-After"), first.Admitted, first.Failed, first.Body)
	}
	if first.Children[1].Status != "failed" || first.Children[1].Fault == nil || !first.Children[1].Fault.Retryable || first.Children[1].Receipt != nil {
		t.Fatalf("child 2 must report the lost receipt as a retryable fault: %s", first.Body)
	}
	for i, c := range first.Children {
		if i != 1 && (c.Status != "admitted" || c.Receipt == nil || c.Receipt.BatchID != c.BatchID) {
			t.Fatalf("child %d must carry its own durable receipt: %s", i, first.Body)
		}
	}
	if got := e.count(t, e.p1, model.Log); got != entries {
		t.Fatalf("every child is durable after the partial attempt (the lost one included): %d logs, want %d", got, entries)
	}

	e.adm.arm()
	retry := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if retry.Status != 200 || retry.Failed != 0 || retry.Admitted != len(first.Children) {
		t.Fatalf("retry of the same source request must be ACKed with every receipt: status=%d %s", retry.Status, retry.Body)
	}
	if fmt.Sprint(retry.ids()) != fmt.Sprint(first.ids()) {
		t.Fatalf("child identities changed between attempts:\n first %v\n retry %v", first.ids(), retry.ids())
	}
	for i, c := range retry.Children {
		if c.Status != "admitted" || c.Receipt == nil || c.Receipt.BatchID != c.BatchID {
			t.Fatalf("retry child %d has no matching receipt: %s", i, retry.Body)
		}
		if i != 1 && first.Children[i].Receipt != nil && (c.Receipt.Cursor.Group != first.Children[i].Receipt.Cursor.Group || fmt.Sprint(c.Receipt.Cursor.Index) != fmt.Sprint(first.Children[i].Receipt.Cursor.Index)) {
			t.Fatalf("retry child %d got a new durable position instead of its original receipt: %s vs %s", i, first.Body, retry.Body)
		}
	}
	if got := e.count(t, e.p1, model.Log); got != entries {
		t.Fatalf("retry duplicated logical data: %d logs, want %d", got, entries)
	}

	// Scope: nothing reached the other project, whatever the request claims.
	if got := e.count(t, e.p2, model.Log); got != 0 {
		t.Fatalf("project %s received %d logs from another project's credential", e.p2, got)
	}
	steer := lokiHeaders()
	steer["X-Soundpost-Project"] = e.p2.String()
	steer["X-Soundpost-Source"] = e.s2.ID.String()
	if r := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, steer, body); r.Status != 403 {
		t.Fatalf("a source header must be refused outright, got %d %s", r.Status, r.Body)
	}
	steer = lokiHeaders()
	steer["X-Soundpost-Service"] = model.NewID().String() // not a service this source may emit
	if r := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, steer, body); r.Status < 400 || r.Status >= 500 || r.Admitted != 0 {
		t.Fatalf("an unregistered resource must be refused before admission, got %d %s", r.Status, r.Body)
	}
	if got := e.count(t, e.p1, model.Log) + e.count(t, e.p2, model.Log); got != entries {
		t.Fatalf("refused requests changed stored data: %d logs", got)
	}

	// The second project's own credential writes only its own project, with its own child identities.
	other := e.post(t, "/adapters/v1/loki/push", e.s2.Credential, lokiHeaders(), body)
	if other.Status != 200 {
		t.Fatalf("second project push: %d %s", other.Status, other.Body)
	}
	if got := e.count(t, e.p2, model.Log); got != entries {
		t.Fatalf("second project holds %d logs, want %d", got, entries)
	}
	if got := e.count(t, e.p1, model.Log); got != entries {
		t.Fatalf("first project changed to %d logs", got)
	}
	for _, id := range other.ids() {
		for _, own := range first.ids() {
			if id == own {
				t.Fatalf("child identity %s is shared across projects", id)
			}
		}
	}
}

// TestInputAdapterRemoteWriteAndRefusals covers the remote-write bridge (v1 and
// v2 request bodies, v2 written-count headers) and the requests the bridge
// must refuse without storing anything.
func TestInputAdapterRemoteWriteAndRefusals(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	nowMS := time.Now().UnixMilli() - 60000
	names := make([]string, 70)
	for i := range names {
		names[i] = fmt.Sprintf("bridge_metric_%02d", i)
	}
	v1 := e.post(t, "/adapters/v1/prometheus/write", e.s1.Credential, rwHeaders(false), snappyBlock(remoteWriteV1(names, nowMS, 1)))
	if v1.Status != 200 || v1.Failed != 0 || len(v1.Children) < 2 || v1.Admitted != len(v1.Children) {
		t.Fatalf("remote-write v1: %d %s", v1.Status, v1.Body)
	}
	if v1.Header.Get("X-Prometheus-Remote-Write-Samples-Written") != "" {
		t.Fatalf("a v1 reply must not carry v2 written-count headers: %v", v1.Header)
	}
	if got := e.count(t, e.p1, model.Metric); got != len(names) {
		t.Fatalf("v1 stored %d points, want %d", got, len(names))
	}
	v2 := e.post(t, "/adapters/v1/prometheus/write", e.s1.Credential, rwHeaders(true), snappyBlock(remoteWriteV2(names[:5], nowMS+1000, 2)))
	if v2.Status != 200 || v2.Header.Get("X-Prometheus-Remote-Write-Samples-Written") != "5" || v2.Header.Get("X-Prometheus-Remote-Write-Histograms-Written") != "0" {
		t.Fatalf("remote-write v2: %d %v %s", v2.Status, v2.Header, v2.Body)
	}
	if got := e.count(t, e.p1, model.Metric); got != len(names)+5 {
		t.Fatalf("v2 stored %d points in total, want %d", got, len(names)+5)
	}
	if got := e.count(t, e.p2, model.Metric); got != 0 {
		t.Fatalf("other project holds %d points", got)
	}

	stored := e.count(t, e.p1, model.Metric)
	good := snappyBlock(remoteWriteV1(names[:3], nowMS+2000, 3))
	big := bytes.Repeat([]byte{0}, 5<<20)
	refusals := []struct {
		name   string
		cred   string
		header map[string]string
		body   []byte
		want   int
	}{
		{"no credential", "", rwHeaders(false), good, 403},
		{"wrong credential", "not-a-source-credential-at-all", rwHeaders(false), good, 403},
		{"cookie", e.s1.Credential, map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy", "Cookie": "__Host-soundpost=x"}, good, 403},
		{"browser origin", e.s1.Credential, map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy", "Origin": "https://example.test"}, good, 403},
		{"wrong media type", e.s1.Credential, map[string]string{"Content-Type": "text/plain", "Content-Encoding": "snappy"}, good, 415},
		{"unknown proto", e.s1.Credential, map[string]string{"Content-Type": "application/x-protobuf;proto=io.prometheus.write.v3.Request", "Content-Encoding": "snappy"}, good, 415},
		{"no snappy", e.s1.Credential, map[string]string{"Content-Type": "application/x-protobuf"}, good, 415},
		{"malformed snappy", e.s1.Credential, rwHeaders(false), []byte{0x05, 0x10, 'a'}, 422},
		{"declared length beyond limits", e.s1.Credential, rwHeaders(false), []byte{0xff, 0xff, 0xff, 0xff, 0x0f, 0x00}, 413},
		{"oversized", e.s1.Credential, rwHeaders(false), big, 413},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			r := e.post(t, "/adapters/v1/prometheus/write", c.cred, c.header, c.body)
			if r.Status != c.want || r.Admitted != 0 || len(r.Children) != 0 {
				t.Fatalf("status %d want %d, admitted=%d: %s", r.Status, c.want, r.Admitted, r.Body)
			}
		})
	}
	if got := e.count(t, e.p1, model.Metric); got != stored {
		t.Fatalf("refused requests stored data: %d points, want %d", got, stored)
	}
	// Loki push refuses an unmapped template: a policy with templates and no header names none.
	r := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, map[string]string{"Content-Type": "application/json", "X-Soundpost-Template": adapterTemplateLine}, lokiJSON(t, e.shards[:1], time.Now().UnixNano()-int64(time.Minute), "alpha"))
	if r.Status != 422 {
		t.Fatalf("template without revision: %d %s", r.Status, r.Body)
	}
	// A GET is not a route.
	resp, err := e.srv.Client().Get(e.srv.URL + "/adapters/v1/prometheus/write")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET status %d", resp.StatusCode)
	}
}

// conditionsBody builds a condition webhook body from event objects.
func conditionsBody(events ...string) []byte {
	return []byte(`{"version":1,"events":[` + strings.Join(events, ",") + `]}`)
}

func conditionEvent(name, epoch string, seq int, at int64, status, severity string) string {
	return fmt.Sprintf(`{"condition":%q,"epoch":%q,"sequence":"%d","event_time_ns":"%d","status":%q,"severity":%q,"labels":{"job":"api"},"links":[]}`, name, epoch, seq, at, status, severity)
}

func conditionHeaders() map[string]string {
	return map[string]string{"Content-Type": "application/json"}
}

// TestInputAdapterConditionsWebhook proves the condition webhook admits only the
// closed, versioned schema as C04 condition records, derives stable identities
// that are bound to the authenticated project and source, treats a retry as
// idempotent, rejects a conflicting replay of one event, and refuses every
// out-of-schema body without storing anything.
func TestInputAdapterConditionsWebhook(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	at := time.Now().UnixNano() - int64(time.Minute)
	good := conditionsBody(
		conditionEvent("checkout-latency", "boot-1", 1, at, "firing", "critical"),
		conditionEvent("checkout-latency", "boot-1", 2, at+1, "recovered", "critical"),
		conditionEvent("disk-full", "boot-1", 1, at, "unknown", "warning"),
	)
	first := e.post(t, "/adapters/v1/conditions", e.s1.Credential, conditionHeaders(), good)
	if first.Status != 200 || first.Failed != 0 || first.Admitted == 0 || first.Adapter != "conditions" {
		t.Fatalf("condition webhook: %d %s", first.Status, first.Body)
	}
	if got := e.count(t, e.p1, model.Condition); got != 3 {
		t.Fatalf("stored %d condition events, want 3", got)
	}
	retry := e.post(t, "/adapters/v1/conditions", e.s1.Credential, conditionHeaders(), good)
	if retry.Status != 200 || fmt.Sprint(retry.ids()) != fmt.Sprint(first.ids()) {
		t.Fatalf("retry must be ACKed with the same child identities: %d first=%v retry=%v", retry.Status, first.ids(), retry.ids())
	}
	if got := e.count(t, e.p1, model.Condition); got != 3 {
		t.Fatalf("retry duplicated condition events: %d", got)
	}
	// An identical event repeated inside one request collapses; a different event under the same
	// (condition, epoch, sequence) is a conflict and nothing of that request is admitted.
	same := conditionEvent("dup-cond", "boot-1", 1, at, "firing", "error")
	if r := e.post(t, "/adapters/v1/conditions", e.s1.Credential, conditionHeaders(), conditionsBody(same, same)); r.Status != 200 {
		t.Fatalf("identical repeated event: %d %s", r.Status, r.Body)
	}
	if got := e.count(t, e.p1, model.Condition); got != 4 {
		t.Fatalf("identical repeated event stored %d, want 4 in total", got)
	}
	conflict := conditionsBody(conditionEvent("conflict-cond", "boot-1", 7, at, "firing", "error"), conditionEvent("conflict-cond", "boot-1", 7, at, "recovered", "error"))
	if r := e.post(t, "/adapters/v1/conditions", e.s1.Credential, conditionHeaders(), conflict); r.Status != 409 || r.Admitted != 0 {
		t.Fatalf("conflicting replay of one event: %d %s", r.Status, r.Body)
	}
	if got := e.count(t, e.p1, model.Condition); got != 4 {
		t.Fatalf("a rejected request stored data: %d", got)
	}

	// The same body from the other project's source: own identities, own project only.
	other := e.post(t, "/adapters/v1/conditions", e.s2.Credential, conditionHeaders(), good)
	if other.Status != 200 || e.count(t, e.p2, model.Condition) != 3 || e.count(t, e.p1, model.Condition) != 4 {
		t.Fatalf("other project: %d p2=%d p1=%d", other.Status, e.count(t, e.p2, model.Condition), e.count(t, e.p1, model.Condition))
	}
	for _, id := range other.ids() {
		for _, own := range first.ids() {
			if id == own {
				t.Fatalf("child identity %s shared across projects", id)
			}
		}
	}

	// The same condition names in two projects are two different conditions: identities are bound to the source.
	one, two := e.conditionIDs(t, e.p1), e.conditionIDs(t, e.p2)
	if len(two) != 2 || len(one) != 3 {
		t.Fatalf("condition identities: p1=%d (want 3: two names plus dup-cond) p2=%d (want 2)", len(one), len(two))
	}
	for id := range two {
		if one[id] {
			t.Fatalf("condition identity %s is shared across projects", id)
		}
	}

	cases := []struct {
		name string
		body string
		want int
	}{
		{"unknown event field", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[],"description":"free text"}]}`, 422},
		{"unknown top field", `{"version":1,"note":"x","events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"version 2", `{"version":2,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 415},
		{"no events", `{"version":1,"events":[]}`, 422},
		{"paging status", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"paging","severity":"info","labels":{},"links":[]}]}`, 422},
		{"pending status is not admissible", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"pending","severity":"info","labels":{},"links":[]}]}`, 422},
		{"unknown severity", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"page","labels":{},"links":[]}]}`, 422},
		{"unsafe condition name", `{"version":1,"events":[{"condition":"a b\n","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"unsafe epoch", `{"version":1,"events":[{"condition":"a","epoch":"","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"zero sequence", `{"version":1,"events":[{"condition":"a","epoch":"e","sequence":"0","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"non canonical sequence", `{"version":1,"events":[{"condition":"a","epoch":"e","sequence":"01","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"numeric sequence", `{"version":1,"events":[{"condition":"a","epoch":"e","sequence":5,"event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"time as number", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":%d,"status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"time in the far future", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"9000000000000000000","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"unapproved label", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{"team":"payments"},"links":[]}]}`, 422},
		{"bad link", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":["not-an-id"]}]}`, 422},
		{"duplicate key", `{"version":1,"events":[{"condition":"a","condition":"b","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]}`, 422},
		{"trailing data", `{"version":1,"events":[{"condition":"a","epoch":"e","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}]} {}`, 422},
		{"not json", `condition firing`, 422},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := c.body
			if strings.Contains(body, "%d") {
				body = fmt.Sprintf(body, at)
			}
			r := e.post(t, "/adapters/v1/conditions", e.s1.Credential, conditionHeaders(), []byte(body))
			if r.Status != c.want || r.Admitted != 0 {
				t.Fatalf("status %d want %d admitted=%d: %s", r.Status, c.want, r.Admitted, r.Body)
			}
		})
	}
	for name, h := range map[string]map[string]string{
		"wrong media type": {"Content-Type": "text/plain"},
		"gzip":             {"Content-Type": "application/json", "Content-Encoding": "gzip"},
	} {
		if r := e.post(t, "/adapters/v1/conditions", e.s1.Credential, h, good); r.Status != 415 {
			t.Fatalf("%s: status %d %s", name, r.Status, r.Body)
		}
	}
	if got := e.count(t, e.p1, model.Condition); got != 4 {
		t.Fatalf("refused requests stored data: %d condition events, want 4", got)
	}
}

// TestInputAdapterRefusesBrowserSources: a browser source credential
// (X-Soundpost-Source + Origin) can emit through the ingest route but the bridge
// routes are for server-side senders and refuse it, on every bridge route.
func TestInputAdapterRefusesBrowserSources(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	source := model.NewID()
	ids := sharedIDs{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID()}
	const origin = "https://app.example.test"
	rawCfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: e.p1, Enabled: true, Origins: []string{origin}})
	e.cmd(e.org, "source_policy", auth.AdminPayload{ID: source, Config: rawCfg})
	policy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Condition},
		Resources:     model.ResourceRegistry{Services: []model.ID{ids.Service}, Environments: []model.ID{ids.Environment}, Builds: []model.ID{ids.Build}, Instances: []string{"opaque-instance"}},
		Labels:        map[string][]string{"job": {"api"}},
		RetentionDays: map[model.Kind]uint32{model.Condition: 7}, MaxBytes: 1 << 20, MaxSeries: 100,
	}
	issued, err := e.app.Auth.OnboardSource(e.ctx, e.actor.Cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: e.org, Project: e.p1, Source: source, Browser: true, Origins: []string{origin}, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "adapter browser source"})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UnixNano() - int64(time.Minute)
	body := conditionsBody(conditionEvent("browser-cond", "boot-1", 1, at, "firing", "info"))
	for _, path := range []string{"/adapters/v1/conditions", "/adapters/v1/loki/push", "/adapters/v1/prometheus/write"} {
		r := e.post(t, path, "", map[string]string{"Content-Type": "application/json", "X-Soundpost-Source": issued.Credential, "Origin": origin}, body)
		if r.Status != 403 || r.Admitted != 0 {
			t.Fatalf("%s: a browser source credential must be refused, got %d %s", path, r.Status, r.Body)
		}
	}
	if got := e.count(t, e.p1, model.Condition); got != 0 {
		t.Fatalf("a refused browser source stored %d condition events", got)
	}
}

// logSlot is the owner slot of a one-label log stream in a project.
func (e *adapterEnv) logSlot(t *testing.T, project model.ID, source model.ID, shard string) int {
	t.Helper()
	rec := model.Record{Kind: model.Log, Payload: model.Payload{Log: &model.LogRecord{StreamLabels: model.Labels{{Name: "shard", Value: shard}}}}}
	slot, err := model.OwnerSlot(e.org, project, source, model.NewID(), rec)
	if err != nil {
		t.Fatal(err)
	}
	return int(slot)
}

// TestInputAdapterMixedChildFailuresPreferRetryable: when one child fails for a
// final reason (an unapproved label value) and another only lost its response,
// the sender is told to retry: answering with the final status would make it
// drop a request whose other child it could still deliver.
func TestInputAdapterMixedChildFailuresPreferRetryable(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	bogus, bogusSlot := "", 0
	for i := 0; bogus == ""; i++ {
		if i > 4000 {
			t.Fatal("no unapproved stream name lands in a low owner slot")
		}
		name := fmt.Sprintf("bogus%d", i)
		if slot := e.logSlot(t, e.p1, e.s1.ID, name); slot <= 20 {
			bogus, bogusSlot = name, slot
		}
	}
	var good []string
	for _, s := range e.shards {
		if len(good) < 6 && e.logSlot(t, e.p1, e.s1.ID, s) > bogusSlot {
			good = append(good, s)
		}
	}
	if len(good) < 6 {
		t.Fatalf("only %d registered streams sort after the unapproved stream's slot %d", len(good), bogusSlot)
	}
	now := time.Now().UnixNano() - int64(time.Minute)
	body := lokiJSON(t, append([]string{bogus}, good...), now, "alpha")
	e.adm.arm(2) // child 1 is the unapproved stream (final failure); child 2's response is lost
	r := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), body)
	if len(r.Children) < 3 || r.Status != 503 || !r.Retry || r.Failed != 2 || r.Children[0].Fault == nil || r.Children[0].Fault.Retryable || r.Children[1].Fault == nil || !r.Children[1].Fault.Retryable {
		t.Fatalf("a retryable child failure must decide the status: %d %s", r.Status, r.Body)
	}
}

// TestInputAdapterResourceSelection: the resource of a request is the only
// registered one or an explicit header; several registered services without a
// header are ambiguous and refused, a header naming an unregistered one is
// refused by the source policy.
func TestInputAdapterResourceSelection(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	source := model.NewID()
	svcA, svcB, env, build := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	rawCfg, _ := json.Marshal(auth.SourcePolicyConfig{ProjectID: e.p1, Enabled: true})
	e.cmd(e.org, "source_policy", auth.AdminPayload{ID: source, Config: rawCfg})
	policy := model.SourcePolicy{
		Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.Condition},
		Resources:     model.ResourceRegistry{Services: []model.ID{svcA, svcB}, Environments: []model.ID{env}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}},
		Labels:        map[string][]string{"job": {"api"}},
		RetentionDays: map[model.Kind]uint32{model.Condition: 7}, MaxBytes: 1 << 20, MaxSeries: 100,
	}
	issued, err := e.app.Auth.OnboardSource(e.ctx, e.actor.Cred, auth.SourceOnboarding{CommandID: model.NewID(), Org: e.org, Project: e.p1, Source: source, Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "adapter resource selection"})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UnixNano() - int64(time.Minute)
	body := conditionsBody(conditionEvent("resource-cond", "boot-1", 1, at, "firing", "info"))
	if r := e.post(t, "/adapters/v1/conditions", issued.Credential, conditionHeaders(), body); r.Status != 422 || r.Admitted != 0 {
		t.Fatalf("two registered services and no header are ambiguous: %d %s", r.Status, r.Body)
	}
	pick := conditionHeaders()
	pick["X-Soundpost-Service"] = svcB.String()
	if r := e.post(t, "/adapters/v1/conditions", issued.Credential, pick, body); r.Status != 200 {
		t.Fatalf("an explicit registered service: %d %s", r.Status, r.Body)
	}
	pick["X-Soundpost-Service"] = model.NewID().String()
	if r := e.post(t, "/adapters/v1/conditions", issued.Credential, pick, body); r.Status < 400 || r.Status >= 500 || r.Admitted != 0 {
		t.Fatalf("an unregistered service: %d %s", r.Status, r.Body)
	}
	other := conditionHeaders()
	other["X-Soundpost-Service"] = svcA.String()
	second := conditionsBody(conditionEvent("resource-cond", "boot-1", 2, at+1, "recovered", "info"))
	if r := e.post(t, "/adapters/v1/conditions", issued.Credential, other, second); r.Status != 200 {
		t.Fatalf("the other registered service: %d %s", r.Status, r.Body)
	}
	if got := e.count(t, e.p1, model.Condition); got != 2 {
		t.Fatalf("stored %d condition events, want 2 (one per service)", got)
	}
}
