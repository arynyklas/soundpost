// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

// Hostile-input review of the input bridge (ledger 02.08#14): what a sender that
// is authenticated but hostile, or merely sloppy, can make the bridge do.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

// hsPost is e.post with repeated header lines allowed.
func hsPost(t *testing.T, e *adapterEnv, path, credential string, headers [][2]string, body []byte) adapterReply {
	t.Helper()
	req, err := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	for _, h := range headers {
		req.Header.Add(h[0], h[1])
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

func hsGzip(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	w.Close()
	return buf.Bytes()
}

// A source whose policy does not permit a signal cannot make the bridge read,
// decompress and parse a body of that signal: the refusal precedes the decode.
func TestInputAdapterRefusesAnUnpermittedSignalBeforeDecoding(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	ids := sharedIDs{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID()}
	src := e.source(e.org, e.p1, ids, []model.Kind{model.Condition})
	garbage := []byte("this is neither snappy nor json")
	for _, c := range []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{"remote write", "/adapters/v1/prometheus/write", rwHeaders(false)},
		{"remote write v2", "/adapters/v1/prometheus/write", rwHeaders(true)},
		{"loki push", "/adapters/v1/loki/push", lokiHeaders()},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.post(t, c.path, src.Credential, c.headers, garbage)
			if r.Status != 403 || r.Admitted != 0 {
				t.Fatalf("a source that may not emit this signal got %d (%s); the body must not even be decoded", r.Status, r.Body)
			}
		})
	}
	at := time.Now().UnixNano() - int64(time.Minute)
	body := conditionsBody(fmt.Sprintf(`{"condition":"kind-gate","epoch":"e1","sequence":"1","event_time_ns":"%d","status":"firing","severity":"info","labels":{},"links":[]}`, at))
	if r := e.post(t, "/adapters/v1/conditions", src.Credential, conditionHeaders(), body); r.Status != 200 {
		t.Fatalf("the permitted signal must still pass: %d %s", r.Status, r.Body)
	}
}

func hsV1Series(w *pb, labels [][2]string, tsMS int64) {
	w.msg(1, func(ts *pb) {
		for _, l := range labels {
			ts.msg(1, func(m *pb) {
				m.bytes(1, []byte(l[0]))
				m.bytes(2, []byte(l[1]))
			})
		}
		ts.msg(2, func(s *pb) {
			s.fixed64(1, math.Float64bits(1))
			s.varint(2, uint64(tsMS))
		})
	})
}

// A request that the source policy would refuse in part must write nothing: the
// children are checked against the policy before the first one is admitted, so
// a sender that corrects the request and sends it again cannot double what the
// first attempt stored.
func TestInputAdapterRejectedRequestWritesNothing(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	now := time.Now().UnixNano() - int64(time.Minute)

	t.Run("loki push with one unregistered stream among 80 registered ones", func(t *testing.T) {
		shards := append(append([]string{}, e.shards...), "unregistered-shard")
		r := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), lokiJSON(t, shards, now, "alpha", "beta"))
		if r.Status < 400 || r.Status >= 500 || r.Admitted != 0 {
			t.Fatalf("status %d admitted %d: %s", r.Status, r.Admitted, r.Body)
		}
		if got := e.count(t, e.p1, model.Log); got != 0 {
			t.Fatalf("a rejected request stored %d log records", got)
		}
	})
	t.Run("remote write with one series carrying an unregistered label value", func(t *testing.T) {
		var req pb
		nowMS := now / 1_000_000
		for i := range 70 {
			hsV1Series(&req, [][2]string{{"__name__", fmt.Sprintf("atomic_metric_%02d", i)}, {"job", "api"}}, nowMS)
		}
		hsV1Series(&req, [][2]string{{"__name__", "atomic_metric_evil"}, {"job", "not-registered"}}, nowMS)
		r := e.post(t, "/adapters/v1/prometheus/write", e.s1.Credential, rwHeaders(false), snappyBlock(req.b))
		if r.Status < 400 || r.Status >= 500 || r.Admitted != 0 {
			t.Fatalf("status %d admitted %d: %s", r.Status, r.Admitted, r.Body)
		}
		if got := e.count(t, e.p1, model.Metric); got != 0 {
			t.Fatalf("a rejected request stored %d metric points", got)
		}
	})
	t.Run("a corrected request is stored exactly once", func(t *testing.T) {
		shards := append([]string{}, e.shards[:5]...)
		r := e.post(t, "/adapters/v1/loki/push", e.s1.Credential, lokiHeaders(), lokiJSON(t, shards, now, "alpha"))
		if r.Status != 200 || e.count(t, e.p1, model.Log) != 5 {
			t.Fatalf("status %d logs %d", r.Status, e.count(t, e.p1, model.Log))
		}
	})
}

// Hostile bodies of every route and encoding are client errors: never a panic,
// never a 5xx, never a stored record.
func TestInputAdapterHostileBodiesAreTypedClientErrors(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	var nested strings.Builder
	for range 200 {
		nested.WriteByte('[')
	}
	bomb := hsGzip(bytes.Repeat([]byte(" "), 20<<20))
	var tagZero pb
	tagZero.varint(0, 1)
	var wire5 pb
	wire5.tag(1, 5)
	wire5.b = append(wire5.b, 0, 0, 0, 0)
	var bigLen pb
	bigLen.tag(1, 2)
	bigLen.b = append(bigLen.b, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01)
	var unknownField pb
	unknownField.varint(2, 7)
	var overlong pb
	overlong.tag(1, 2)
	overlong.b = append(overlong.b, bytes.Repeat([]byte{0xff}, 11)...)

	type hostile struct {
		name    string
		path    string
		headers map[string]string
		body    []byte
	}
	loki := func(extra map[string]string) map[string]string {
		h := lokiHeaders()
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	cases := []hostile{
		{"rw empty", "/adapters/v1/prometheus/write", rwHeaders(false), nil},
		{"rw snappy empty block", "/adapters/v1/prometheus/write", rwHeaders(false), []byte{0x00}},
		{"rw snappy truncated literal", "/adapters/v1/prometheus/write", rwHeaders(false), []byte{0x20, 0xfc, 0x7f}},
		{"rw protobuf field zero", "/adapters/v1/prometheus/write", rwHeaders(false), snappyBlock(tagZero.b)},
		{"rw protobuf fixed32", "/adapters/v1/prometheus/write", rwHeaders(false), snappyBlock(wire5.b)},
		{"rw protobuf length 2^63", "/adapters/v1/prometheus/write", rwHeaders(false), snappyBlock(bigLen.b)},
		{"rw protobuf 11 byte varint", "/adapters/v1/prometheus/write", rwHeaders(false), snappyBlock(overlong.b)},
		{"rw protobuf unknown request field", "/adapters/v1/prometheus/write", rwHeaders(false), snappyBlock(unknownField.b)},
		{"rw v2 as v1 bytes", "/adapters/v1/prometheus/write", rwHeaders(true), snappyBlock(remoteWriteV1([]string{"hostile_v1_as_v2"}, time.Now().UnixMilli()-60000, 1))},
		{"rw v1 as v2 bytes", "/adapters/v1/prometheus/write", rwHeaders(false), snappyBlock(remoteWriteV2([]string{"hostile_v2_as_v1"}, time.Now().UnixMilli()-60000, 1))},
		{"rw random bytes", "/adapters/v1/prometheus/write", rwHeaders(false), []byte("\x9f\x01\x42\x13\x77\xee\x00\x00\x91\x28\xaa")},
		{"loki json empty", "/adapters/v1/loki/push", lokiHeaders(), nil},
		{"loki json object", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{}`)},
		{"loki json array", "/adapters/v1/loki/push", lokiHeaders(), []byte(`[]`)},
		{"loki json null", "/adapters/v1/loki/push", lokiHeaders(), []byte(`null`)},
		{"loki json no streams", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{"streams":[]}`)},
		{"loki json depth 200", "/adapters/v1/loki/push", lokiHeaders(), []byte(nested.String())},
		{"loki json invalid utf-8", "/adapters/v1/loki/push", lokiHeaders(), []byte("{\"streams\":[{\"stream\":{\"shard\":\"s00\"},\"values\":[[\"1\",\"\xff\"]]}]}")},
		{"loki json lone surrogate", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{"streams":[{"stream":{"shard":"s00"},"values":[["1","\ud800"]]}]}`)},
		{"loki json duplicate key", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{"streams":[],"streams":[]}`)},
		{"loki json trailing document", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{"streams":[]}{"streams":[]}`)},
		{"loki json entry not an array", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{"streams":[{"stream":{"shard":"s00"},"values":[{"ts":1}]}]}`)},
		{"loki json timestamp overflow", "/adapters/v1/loki/push", lokiHeaders(), []byte(`{"streams":[{"stream":{"shard":"s00"},"values":[["99999999999999999999","x"]]}]}`)},
		{"loki gzip not gzip", "/adapters/v1/loki/push", loki(map[string]string{"Content-Encoding": "gzip"}), []byte(`{"streams":[]}`)},
		{"loki gzip truncated", "/adapters/v1/loki/push", loki(map[string]string{"Content-Encoding": "gzip"}), hsGzip([]byte(`{"streams":[]}`))[:12]},
		{"loki gzip bomb", "/adapters/v1/loki/push", loki(map[string]string{"Content-Encoding": "gzip"}), bomb},
		{"loki protobuf garbage", "/adapters/v1/loki/push", loki(map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy"}), []byte("garbage that is no snappy block")},
		{"loki protobuf field zero", "/adapters/v1/loki/push", loki(map[string]string{"Content-Type": "application/x-protobuf", "Content-Encoding": "snappy"}), snappyBlock(tagZero.b)},
		{"conditions object", "/adapters/v1/conditions", conditionHeaders(), []byte(`{}`)},
		{"conditions depth 200", "/adapters/v1/conditions", conditionHeaders(), []byte(nested.String())},
		{"conditions wrong types", "/adapters/v1/conditions", conditionHeaders(), []byte(`{"version":"1","events":{}}`)},
		{"conditions events null", "/adapters/v1/conditions", conditionHeaders(), []byte(`{"version":1,"events":null}`)},
		{"conditions huge sequence", "/adapters/v1/conditions", conditionHeaders(), conditionsBody(`{"condition":"a","epoch":"e","sequence":"18446744073709551616","event_time_ns":"1","status":"firing","severity":"info","labels":{},"links":[]}`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.post(t, c.path, e.s1.Credential, c.headers, c.body)
			if r.Status < 400 || r.Status >= 500 || r.Admitted != 0 || len(r.Children) != 0 {
				t.Fatalf("status %d admitted %d children %d: %s", r.Status, r.Admitted, len(r.Children), r.Body)
			}
		})
	}
	for _, kind := range []model.Kind{model.Metric, model.Log, model.Condition} {
		if got := e.count(t, e.p1, kind); got != 0 {
			t.Fatalf("hostile bodies stored %d %s records", got, kind)
		}
	}
}

// Header confusion: a request that names its encoding or media type twice is not
// understood the way either line says, so it is refused rather than decoded by
// the first line alone.
func TestInputAdapterRepeatedContentHeadersAreRefused(t *testing.T) {
	e := newAdapterEnv(t, httpapi.InputAdapterConfig{})
	nowMS := time.Now().UnixMilli() - 60000
	rw := snappyBlock(remoteWriteV1([]string{"header_confusion_metric"}, nowMS, 1))
	lokiPlain := lokiJSON(t, e.shards[:1], time.Now().UnixNano()-int64(time.Minute), "alpha")
	at := time.Now().UnixNano() - int64(time.Minute)
	cond := conditionsBody(conditionEvent("header-confusion", "e1", 1, at, "firing", "info"))
	type req struct {
		name    string
		path    string
		headers [][2]string
		body    []byte
		want    int
	}
	lokiH := [][2]string{{"Content-Type", "application/json"}, {"X-Soundpost-Template", adapterTemplateLine}, {"X-Soundpost-Template-Revision", "1"}}
	cases := []req{
		{"rw single headers", "/adapters/v1/prometheus/write", [][2]string{{"Content-Type", "application/x-protobuf"}, {"Content-Encoding", "snappy"}}, rw, 200},
		{"rw encoding named twice", "/adapters/v1/prometheus/write", [][2]string{{"Content-Type", "application/x-protobuf"}, {"Content-Encoding", "snappy"}, {"Content-Encoding", "gzip"}}, rw, 415},
		{"rw media type named twice", "/adapters/v1/prometheus/write", [][2]string{{"Content-Type", "application/x-protobuf"}, {"Content-Type", "text/plain"}, {"Content-Encoding", "snappy"}}, rw, 415},
		{"loki single headers", "/adapters/v1/loki/push", lokiH, lokiPlain, 200},
		{"loki encoding named twice", "/adapters/v1/loki/push", append(append([][2]string{}, lokiH...), [2]string{"Content-Encoding", "identity"}, [2]string{"Content-Encoding", "gzip"}), lokiPlain, 415},
		{"loki media type named twice", "/adapters/v1/loki/push", append(append([][2]string{}, lokiH...), [2]string{"Content-Type", "application/x-protobuf"}), lokiPlain, 415},
		{"conditions single header", "/adapters/v1/conditions", [][2]string{{"Content-Type", "application/json"}}, cond, 200},
		{"conditions media type named twice", "/adapters/v1/conditions", [][2]string{{"Content-Type", "application/json"}, {"Content-Type", "application/json"}}, cond, 415},
		{"conditions encoding named twice", "/adapters/v1/conditions", [][2]string{{"Content-Type", "application/json"}, {"Content-Encoding", "identity"}, {"Content-Encoding", "identity"}}, cond, 415},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := hsPost(t, e, c.path, e.s1.Credential, c.headers, c.body)
			if r.Status != c.want {
				t.Fatalf("status %d want %d: %s", r.Status, c.want, r.Body)
			}
		})
	}
}
