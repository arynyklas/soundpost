// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"testing"
)

func TestNativeResourceAndErrorBuildIDsRejectAliases(t *testing.T) {
	baseline := []byte(`{"id":"dddddddddddddddddddddddddddddddd","kind":"error","observed_at_ns":"1","resource":{"service_id":"11111111111111111111111111111111","environment_id":"22222222222222222222222222222222","build_id":"33333333333333333333333333333333","instance_pseudonym":"approved-opaque-instance","labels":[]},"payload":{"occurrence_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","exception_class":"TypeError","mechanism":"manual","frames":[],"code":null,"build_id":"33333333333333333333333333333333","handled":true,"fatal":false}}`)
	var positive Record
	if e := json.Unmarshal(baseline, &positive); e != nil {
		t.Fatal("canonical nonzero identities denied", e)
	}
	for _, bad := range []string{"service", "build", "00000000000000000000000000000000", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "111"} {
		for _, field := range []string{"service_id", "environment_id", "build_id"} {
			var wire map[string]json.RawMessage
			json.Unmarshal(baseline, &wire)
			var resource map[string]json.RawMessage
			json.Unmarshal(wire["resource"], &resource)
			resource[field], _ = json.Marshal(bad)
			wire["resource"], _ = json.Marshal(resource)
			raw, _ := json.Marshal(wire)
			var record Record
			if json.Unmarshal(raw, &record) == nil {
				t.Fatalf("noncanonical %s accepted", field)
			}
		}
		var wire map[string]json.RawMessage
		json.Unmarshal(baseline, &wire)
		var payload map[string]json.RawMessage
		json.Unmarshal(wire["payload"], &payload)
		payload["build_id"], _ = json.Marshal(bad)
		wire["payload"], _ = json.Marshal(payload)
		raw, _ := json.Marshal(wire)
		var record Record
		if json.Unmarshal(raw, &record) == nil {
			t.Fatal("noncanonical error build accepted")
		}
	}
}
