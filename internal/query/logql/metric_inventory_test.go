// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEveryLogQLMetricInventoryBinding(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/query/audits/logql.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct{ Obligations []struct{ ID, Kind string } }
	if err = json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile("../../../conformance/query/cases/logql-metrics-order.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Schema string
		Cases  []struct {
			ID, Phase, Obligation, Query string
			Profiles                     []string
			Configuration                map[string]string
			ConfigurationIdentity        string `json:"config_identity"`
		}
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != "soundpost-authored-logql-metric-cases-v1" {
		t.Fatal("metric schema identity changed")
	}
	bindings := map[string]bool{}
	ids := map[string]bool{}
	for _, c := range fixture.Cases {
		if c.ID == "" || ids[c.ID] || c.Phase != "logql-metric" || c.Query == "" || len(c.Profiles) != 1 || c.Profiles[0] != "logql-loki-3.5.2" || c.ConfigurationIdentity == "" || c.Configuration["count_min_sketch_heap_size"] != "10000" || c.Configuration["instant_log_lookback_ns"] != "30000000000" {
			t.Fatalf("unbound metric case identity: %+v", c)
		}
		ids[c.ID] = true
		bindings[c.Obligation] = true
	}
	count := 0
	for _, o := range inventory.Obligations {
		switch o.Kind {
		case "range-aggregation", "vector-aggregation", "binary-operator", "binary", "gated-query", "function":
			count++
			if !bindings[o.ID] {
				t.Fatalf("missing metric execution/oracle fixture for %s", o.ID)
			}
		}
	}
	if count == 0 {
		t.Fatal("empty factual metric inventory")
	}
}
