// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import (
	"encoding/json"
	"os"
	"soundpost/internal/query/profile"
	"testing"
)

func TestAuthoredSignatureArityTypeAndGateCases(t *testing.T) {
	b, err := os.ReadFile("../../../conformance/query/cases/promql-syntax.json")
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Cases []struct {
			ID       string   `json:"id"`
			Profiles []string `json:"profiles"`
			Enabled  []string `json:"enabled_features"`
			Input    struct {
				Expression string `json:"expression"`
			} `json:"input"`
			Expected struct {
				Accepted bool      `json:"accepted"`
				Type     ValueType `json:"type"`
			} `json:"expected"`
		}
	}
	if err = json.Unmarshal(b, &suite); err != nil {
		t.Fatal(err)
	}
	if len(suite.Cases) < 380 {
		t.Fatal("missing authored signature cases")
	}
	for _, tc := range suite.Cases {
		t.Run(tc.ID, func(t *testing.T) {
			p := testProfile()
			p.ID = tc.Profiles[0]
			if p.ID == "promql-prometheus-3.1.0" {
				p.Commit = "7086161a93b262aa0949dbf2aba15a5a7b13e0a3"
			}
			p.ActiveFeatureSet = profile.FeatureSet{ID: "explicit-test-features", Enabled: tc.Enabled}
			e, err := Parse(tc.Input.Expression, p)
			var v TypedExpr
			if err == nil {
				v, _, err = Check(e, p)
			}
			if !tc.Expected.Accepted {
				if err == nil {
					t.Fatal("negative accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if v.Type != tc.Expected.Type {
				t.Fatalf("got %s want %s", v.Type, tc.Expected.Type)
			}
			formatted := Format(e)
			r, err := Parse(formatted, p)
			if err != nil {
				t.Fatalf("formatted %s: %v", formatted, err)
			}
			v2, _, err := Check(r, p)
			if err != nil || v2.Type != v.Type || Format(r) != formatted {
				t.Fatalf("formatted typed meaning changed: %v", err)
			}
		})
	}
}
