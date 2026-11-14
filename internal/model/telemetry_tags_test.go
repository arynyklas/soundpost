// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"testing"
)

func TestScalarNullIsNotStringAndStaleTagIsExact(t *testing.T) {
	var null Scalar
	json.Unmarshal([]byte(`null`), &null)
	if validField(null, TemplateField{Type: "string", MaxBytes: 4}) {
		t.Fatal("null accepted as empty string")
	}
	if null.Text() != "null" {
		t.Fatal("null template field did not render its typed literal")
	}
	service, environment, build := NewID(), NewID(), NewID()
	policy := SourcePolicy{Kinds: []Kind{Metric}, Resources: ResourceRegistry{Services: []ID{service}, Environments: []ID{environment}, Builds: []ID{build}, Instances: []string{"instance"}}}
	value := FloatBits(0x7ff8000000000001)
	point := MetricPoint{Name: "metric", Labels: Labels{}, SampleKind: "float", Value: &value, Type: "gauge", Unit: "1"}
	record := Record{ID: NewID(), Kind: Metric, ObservedAt: 1, Resource: Resource{Service: service, Environment: environment, Build: build, Instance: "instance"}, Payload: Payload{Metric: &point}}
	if e := ValidateRecord(&record, policy); e != nil {
		t.Fatal("ordinary NaN payload rejected", e)
	}
	value = FloatBits(0x7ff0000000000002)
	if ValidateRecord(&record, policy) == nil {
		t.Fatal("stale bits accepted with float tag")
	}
	point.SampleKind = "stale"
	if e := ValidateRecord(&record, policy); e != nil {
		t.Fatal("stale marker rejected", e)
	}
}
