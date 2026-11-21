// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"math"
	"testing"
)

func TestMetricStartTimestampRetainsNativePrecisionAndPresence(t *testing.T) {
	service, environment, build := NewID(), NewID(), NewID()
	policy := SourcePolicy{Kinds: []Kind{Metric}, Resources: ResourceRegistry{Services: []ID{service}, Environments: []ID{environment}, Builds: []ID{build}, Instances: []string{"instance"}}}
	value := FloatBits(0x3ff0000000000000)
	for _, start := range []int64{math.MinInt64, -9007199254740993, 0, 9007199254740993, math.MaxInt64} {
		t.Run(stringMustJSON(start), func(t *testing.T) {
			timestamp := UnixNano(start)
			original := Record{ID: NewID(), Kind: Metric, ObservedAt: 17, Resource: Resource{Service: service, Environment: environment, Build: build, Instance: "instance", Labels: Labels{}}, Payload: Payload{Metric: &MetricPoint{Name: "counter", Labels: Labels{}, SampleKind: "float", Value: &value, StartTimestamp: &timestamp, Unit: "1", Type: "counter"}}}
			if err := ValidateRecord(&original, policy); err != nil {
				t.Fatalf("exact native start timestamp denied: %v", err)
			}
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var restored Record
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.Payload.Metric.StartTimestamp == nil || int64(*restored.Payload.Metric.StartTimestamp) != start || restored.ObservedAt != 17 {
				t.Fatal("start metadata lost precision, presence, or replaced observation time")
			}
		})
	}
	var absent MetricPoint
	if err := json.Unmarshal([]byte(`{"name":"counter","labels":[],"sample_kind":"float","value":"3ff0000000000000","unit":"1","type":"counter"}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.StartTimestamp != nil {
		t.Fatal("absent native metadata fabricated epoch zero")
	}
	for _, invalid := range []string{`0`, `9007199254740993`, `"9223372036854775808"`, `"-9223372036854775809"`, `"01"`, `"-0"`, `"1.0"`} {
		var point MetricPoint
		if json.Unmarshal([]byte(`{"start_timestamp_ns":`+invalid+`}`), &point) == nil {
			t.Fatalf("noncanonical or overflowing native timestamp accepted: %s", invalid)
		}
	}
}

func stringMustJSON(value int64) string { raw, _ := json.Marshal(value); return string(raw) }
