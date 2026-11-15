// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.08-W4: the batch's top level is a closed schema; an unknown or differently cased field is refused as invalid.
func TestDecodeRefusesUnknownTopLevelBatchFields(t *testing.T) {
	bits := model.FloatBits(0x3ff0000000000000)
	batch := model.Batch{Version: 1, Project: model.NewID(), Source: model.NewID(), Producer: model.NewID(), ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "instance"}, Payload: model.Payload{Metric: &model.MetricPoint{Name: "requests", SampleKind: "float", Value: &bits, Unit: "1", Type: "counter"}}}}}
	raw, e := json.Marshal(batch)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Decode(bytes.NewReader(raw), ""); e != nil {
		t.Fatalf("control: the closed schema refused a valid batch: %v", e)
	}
	for name, mutate := range map[string]func(map[string]json.RawMessage){
		"unknown":  func(w map[string]json.RawMessage) { w["extra"] = json.RawMessage(`1`) },
		"cased":    func(w map[string]json.RawMessage) { w["Version"] = w["version"]; delete(w, "version") },
		"smuggled": func(w map[string]json.RawMessage) { w["route"] = json.RawMessage(`{"slot":1}`) },
	} {
		var wire map[string]json.RawMessage
		if e = json.Unmarshal(raw, &wire); e != nil {
			t.Fatal(e)
		}
		mutate(wire)
		body, _ := json.Marshal(wire)
		_, e = Decode(bytes.NewReader(body), "")
		var fault *model.Fault
		if !errors.As(e, &fault) || fault.Code != model.Invalid {
			t.Fatalf("%s: not refused as invalid: %v", name, e)
		}
	}
}
