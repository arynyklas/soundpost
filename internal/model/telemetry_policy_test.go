// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"testing"
)

func TestRegisteredUTF8LabelsAndExactTemplateFieldBytes(t *testing.T) {
	var value Scalar
	if e := json.Unmarshal([]byte(`"abc"`), &value); e != nil {
		t.Fatal(e)
	}
	serviceID, environmentID, buildID := NewID(), NewID(), NewID()
	policy := SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []Kind{Log, Metric}, MaxBytes: 1 << 20, MaxSeries: 100, Resources: ResourceRegistry{Services: []ID{serviceID}, Environments: []ID{environmentID}, Builds: []ID{buildID}, Instances: []string{"instance"}}, Labels: map[string][]string{"名字": {"值"}}, RetentionDays: map[Kind]uint32{Log: 14, Metric: 30}, Templates: []LogTemplate{{ID: "test", Revision: 1, Line: "{code}", Severity: "info", Fields: []TemplateField{{Name: "code", Type: "string", MaxBytes: 3, Sensitivity: "metadata", Values: []Scalar{value}}}}}}
	if e := ValidateSourcePolicy(policy); e != nil {
		t.Fatal("valid C01 labels/field boundary denied", e)
	}
	resource := Resource{Service: serviceID, Environment: environmentID, Build: buildID, Instance: "instance", Labels: Labels{}}
	record := Record{ID: NewID(), Kind: Log, ObservedAt: 1, Resource: resource, Payload: Payload{Log: &LogRecord{TemplateID: "test", TemplateRevision: 1, Fields: map[string]Scalar{"code": value}, StreamLabels: Labels{{Name: "名字", Value: "值"}}, Metadata: map[string]Scalar{}}}}
	if e := ValidateRecord(&record, policy); e != nil || record.Payload.Log.Line != "abc" {
		t.Fatal("registered exact UTF-8 field/labels lost", e)
	}
	var tooLong Scalar
	json.Unmarshal([]byte(`"abcd"`), &tooLong)
	record.Payload.Log.Fields["code"] = tooLong
	if ValidateRecord(&record, policy) == nil {
		t.Fatal("field byte cap ignored")
	}
}
