// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"compress/gzip"
	"github.com/arynyklas/soundpost/internal/model"
	"strings"
	"testing"
)

// Replacing bounded decoding with json.Unmarshal loses these atomic denials.
func TestAdmissionAtomicPolicyAndLimits(t *testing.T) {
	for _, raw := range []string{`{"version":1,"version":1}`, "{\"version\":1,\"x\":\"\xff\"}", `{"version":1,"records":[{"kind":"unknown"}]}`, `{"version":1,"records":[{"kind":"metric","payload":{"log":{}}}]}`} {
		if _, e := Decode(bytes.NewBufferString(raw), ""); e == nil {
			t.Fatal("invalid admitted")
		}
	}
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	z.Write([]byte(strings.Repeat(" ", 4*1024*1024+1)))
	z.Close()
	if _, e := Decode(&b, "gzip"); e == nil {
		t.Fatal("gzip expansion admitted")
	}
	raw := `{"version":1,"records":[` + strings.Repeat(`{},`, 512) + `{}]}`
	if _, e := Decode(strings.NewReader(raw), ""); e == nil {
		t.Fatal("513 records admitted")
	}
}
func TestOwnerRoutingAndConcurrentMetricConflict(t *testing.T) {
	org, p, s, a, b := model.NewID(), model.NewID(), model.NewID(), model.NewID(), model.NewID()
	v := model.FloatBits(0x7ff0000000000002)
	r := model.Record{Kind: model.Metric, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", Labels: model.Labels{{Name: "method", Value: "GET"}}, SampleKind: "stale", Value: &v}}}
	x, e := model.OwnerSlot(org, p, s, a, r)
	if e != nil {
		t.Fatal(e)
	}
	y, e := model.OwnerSlot(org, p, s, b, r)
	if e != nil || x != y {
		t.Fatal("producer changed canonical metric owner")
	}
}
