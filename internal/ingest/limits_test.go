// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"soundpost/internal/model"
	"strings"
	"testing"
)

func TestExactCompressedExpandedAndRecordLimits(t *testing.T) {
	bits := model.FloatBits(0x3ff0000000000000)
	batch := model.Batch{Version: 1, Project: model.NewID(), Source: model.NewID(), Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "instance"}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", SampleKind: "float", Value: &bits, Unit: "1", Type: "counter"}}}}}
	raw, e := json.Marshal(batch)
	if e != nil {
		t.Fatal(e)
	}
	expanded := append(append([]byte(nil), raw...), bytes.Repeat([]byte{' '}, (4<<20)-len(raw))...)
	if _, e = Decode(bytes.NewReader(expanded), ""); e != nil {
		t.Fatal("exact 4-MiB uncompressed body denied", e)
	}
	var zipped bytes.Buffer
	z := gzip.NewWriter(&zipped)
	z.Write(expanded)
	z.Close()
	if _, e = Decode(&zipped, "gzip"); e != nil {
		t.Fatal("exact expanded gzip limit denied", e)
	}
	assertLarge := func(raw []byte, encoding string) {
		t.Helper()
		_, e := Decode(bytes.NewReader(raw), encoding)
		var fault *model.Fault
		if !errors.As(e, &fault) || fault.Code != model.TooLarge {
			t.Fatalf("limit did not return too_large: %v", e)
		}
	}
	assertLarge(append(expanded, ' '), "")
	assertLarge(make([]byte, (1<<20)+1), "gzip")
	record, _ := json.Marshal(batch.Records[0])
	prefix := string(record[:len(record)-1]) + `,"extension":"`
	suffix := `"}`
	exact := prefix + strings.Repeat("x", (256<<10)-len(prefix)-len(suffix)) + suffix
	var wire map[string]json.RawMessage
	json.Unmarshal(raw, &wire)
	wire["records"] = json.RawMessage("[" + exact + "]")
	atLimit, _ := json.Marshal(wire)
	if _, e = Decode(bytes.NewReader(atLimit), ""); e != nil {
		t.Fatal("exact record limit denied", e)
	}
	wire["records"] = json.RawMessage("[" + prefix + strings.Repeat("x", (256<<10)+1-len(prefix)-len(suffix)) + suffix + "]")
	overLimit, _ := json.Marshal(wire)
	assertLarge(overLimit, "")
}
