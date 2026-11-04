// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"encoding/json"
	"os"
	"soundpost/internal/model"
	"soundpost/internal/query/profile"
	"soundpost/internal/query/value"
	"testing"
)

func testProfile(t *testing.T) profile.Profile {
	t.Helper()
	r, e := profile.Load(os.DirFS("../../../profiles/query"))
	if e != nil {
		t.Fatal(e)
	}
	p, e := r.Resolve("logql-loki-3.5.2", "features-ef306c4e3aff8e4e9f5fb90595bb4f4b13f3de438c78ba73db83d9eb088e79eb")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func testPlan(t *testing.T, source string) PipelinePlan {
	t.Helper()
	p := testProfile(t)
	e, err := Parse(source, p)
	if err != nil {
		t.Fatal(err)
	}
	typed, _, err := Check(e, p)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildPlan(typed, value.Evaluation{}, p)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Pipeline != nil {
		return *plan.Pipeline
	}
	if len(plan.Pipelines) != 1 {
		t.Fatal("expected one log pipeline")
	}
	return plan.Pipelines[0]
}
func TestEveryLogQLProductionAndStage(t *testing.T) {
	p := testProfile(t)
	valid := []string{
		`{app="api"}`, `{app=~".+",region!="west",zone!~"dev.*"}`,
		`{app="api"} |= "request" or "response" != "health" |~ "[0-9]+" !~ "debug" |> "<_> done <_>" !> "<_> lost <_>"`,
		`{app="api"} |= ip("192.0.2.0/24") != ip("2001:db8::1")`,
		`{app="api"} | json | n="2"`, `{app="api"} | json code="response.code",first="items[0]"`,
		`{app="api"} | logfmt --strict --keep-empty code="status", user`,
		`{app="api"} | regexp "(?P<code>[0-9]+)" | pattern "<level> <_> <message>" | unpack`,
		`{app="api"} | n>=2 and (elapsed>1ms or size<=2KiB) | remote=ip("192.0.2.1-192.0.2.8")`,
		`{app="api"} | line_format "{{ __line__ }}" | label_format new=old,copy="{{ .level }}" | drop old,level="debug" | keep new,copy | decolorize`,
		`rate({app="api"}[5m])`, `sum by (service) (rate({app="api"} | json [5m]))`,
		`rate({app="api"}[5m]|json offset 1m)`, `rate(({app="api"}|json)[5m] offset -1m)`,
		`sum_over_time({app="api"} | json | unwrap bytes(size) | __error__="" [5m] offset 1m)`,
		`quantile_over_time(0.9,{app="api"}|unwrap duration_seconds(elapsed)[1m]) by (app)`,
		`vector(2) + on(app) group_left(zone) rate({app="api"}[1m])`,
		`label_replace(vector(1),"new","$1","old","(.*)")`, `1 + 2 * 3 ^ 2`,
	}
	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			e, err := Parse(s, p)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = Check(e, p); err != nil {
				t.Fatal(err)
			}
		})
	}
	invalid := []string{`{}`, `{app=~".*"}`, `{app="api"}|regexp "["`, `{app="api"}|regexp "(x)"`, `{app="api"}|json x="a["`, `{app="api"}|label_format x=y,x=z`, `{app="api"}|label_format __error__="x"`, `{app="api"}|=ip("not-an-address")`, `rate({app="api"})`, `sum_over_time({app="api"}[1m])`, `count_over_time({app="api"}|unwrap n[1m])`, `{app="api"}|unwrap n`}
	for _, s := range invalid {
		t.Run("invalid:"+s, func(t *testing.T) {
			e, err := Parse(s, p)
			if err == nil {
				_, _, err = Check(e, p)
			}
			if err == nil {
				t.Fatal("accepted invalid expression")
			}
		})
	}
}
func TestInventoryRowsHaveAuthoredSyntaxBindings(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/query/audits/logql.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct{ Obligations []struct{ ID, Kind string } }
	if err = json.Unmarshal(raw, &inventory); err != nil {
		t.Fatal(err)
	}
	if len(inventory.Obligations) != 140 {
		t.Fatalf("factual inventory changed: %d", len(inventory.Obligations))
	}
	bindings := map[string]bool{}
	for _, c := range authoredCases(t) {
		if c.Phase == "syntax" && c.Obligation != "" {
			bindings[c.Obligation] = true
		}
	}
	for _, row := range inventory.Obligations {
		if row.ID == "" || row.Kind == "" || !bindings[row.ID] {
			t.Fatalf("missing authored syntax binding: %s", row.ID)
		}
	}
}

type authoredCase struct {
	ID, Phase, Obligation string
	Enabled               []string `json:"enabled_features"`
	Input                 struct {
		Expression string
		Entry      struct {
			Timestamp          model.UnixNano `json:"timestamp_ns"`
			ID                 model.ID
			Multiplicity       model.Uint64
			Line               string
			StreamLabels       model.Labels `json:"stream_labels"`
			StructuredMetadata model.Labels `json:"structured_metadata"`
			Fields             []TypedField `json:"fields"`
		}
	}
	Expected struct {
		Accepted, Retained   bool
		Type, Category, Line string
		LabelsSubset         model.Labels     `json:"labels_subset"`
		AbsentLabels         []string         `json:"absent_labels"`
		UnwrappedBits        *model.FloatBits `json:"unwrapped_bits"`
	}
}

func authoredCases(t *testing.T) []authoredCase {
	t.Helper()
	raw, err := os.ReadFile("../../../conformance/query/cases/logql-syntax-pipeline.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct{ Cases []authoredCase }
	if err = json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Cases
}
func TestEveryLogQLAuthoredSyntaxBinding(t *testing.T) {
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	for _, c := range authoredCases(t) {
		if c.Phase != "syntax" {
			continue
		}
		t.Run(c.ID, func(t *testing.T) {
			p := base
			found := false
			for _, f := range base.FeatureSets {
				if len(f.Enabled) != len(c.Enabled) {
					continue
				}
				ok := true
				for _, n := range c.Enabled {
					has := false
					for _, g := range f.Enabled {
						has = has || n == g
					}
					ok = ok && has
				}
				if ok {
					p, err = registry.Resolve(base.ID, f.ID)
					if err != nil {
						t.Fatal(err)
					}
					found = true
					break
				}
			}
			if !found {
				t.Fatal("unregistered feature combination")
			}
			e, err := Parse(c.Input.Expression, p)
			var checked TypedExpr
			if err == nil {
				checked, _, err = Check(e, p)
			}
			if (err == nil) != c.Expected.Accepted {
				t.Fatalf("acceptance=%v: %v", err == nil, err)
			}
			if err == nil && string(checked.Type) != c.Expected.Type {
				t.Fatalf("type=%s want=%s", checked.Type, c.Expected.Type)
			}
		})
	}
}
func TestEveryLogQLProfileGateCombination(t *testing.T) {
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	for _, set := range base.FeatureSets {
		p, err := registry.Resolve(base.ID, set.ID)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ source, gate string }{{"approx_topk(3,vector(1))", "approx_topk"}, {`variants(rate({app="api"}[1m])) of ({app="api"}[1m])`, "multi-variant-queries"}} {
			// Syntax acceptance is gate-independent; the gate is applied when planning.
			typed, err := parseCheck(t, tc.source, p)
			if err != nil {
				t.Fatalf("gate=%s set=%s syntax rejected: %v", tc.gate, set.ID, err)
			}
			_, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p)
			if (err == nil) != enabled(p, tc.gate) {
				t.Fatalf("gate=%s set=%s err=%v", tc.gate, set.ID, err)
			}
		}
	}
}
