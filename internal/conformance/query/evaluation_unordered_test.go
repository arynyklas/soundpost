// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
)

func countValuesObservation(rows ...[2]any) EvaluationObservation {
	out := EvaluationObservation{ID: "x", Type: "vector", Complete: true}
	for _, r := range rows {
		bits := model.FloatBits(math.Float64bits(float64(r[1].(int))))
		out.Series = append(out.Series, EvaluationSeries{
			Project: evaluationProject,
			Labels:  model.Labels{{Name: "v", Value: r[0].(string)}},
			Samples: []EvaluationSample{{Time: 20e9, Float: &bits}},
		})
	}
	return out
}

func unorderedCase(marked bool) EvaluationCase {
	return EvaluationCase{ID: "x", Profiles: []string{"promql-prometheus-3.13.5"}, Query: `count_values("v", nanp)`, Kind: "instant", Time: 20e9, UnorderedVector: marked}
}

// The references emit count_values groups in Go map-iteration order, so a marked row accepts any order of the
// same exact series and nothing else.
func TestUnorderedVectorAcceptsEveryOrderOfTheSameSeries(t *testing.T) {
	want := countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2}, [2]any{"3", 1})
	for _, got := range []EvaluationObservation{
		countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2}, [2]any{"3", 1}),
		countValuesObservation([2]any{"NaN", 2}, [2]any{"3", 1}, [2]any{"1", 1}),
		countValuesObservation([2]any{"3", 1}, [2]any{"1", 1}, [2]any{"NaN", 2}),
	} {
		if diff := CompareEvaluationCase(unorderedCase(true), want, got); len(diff) != 0 {
			t.Fatalf("marked row rejected a reordering: %#v", diff)
		}
	}
}

func TestUnorderedVectorStillRejectsAWrongLabelValueCountOrSeriesSet(t *testing.T) {
	want := countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2}, [2]any{"3", 1})
	for name, got := range map[string]EvaluationObservation{
		"label text":        countValuesObservation([2]any{"1", 1}, [2]any{"nan", 2}, [2]any{"3", 1}),
		"label text +Inf":   countValuesObservation([2]any{"1", 1}, [2]any{"Inf", 2}, [2]any{"3", 1}),
		"count":             countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 1}, [2]any{"3", 1}),
		"count swapped":     countValuesObservation([2]any{"1", 2}, [2]any{"NaN", 1}, [2]any{"3", 1}),
		"missing series":    countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2}),
		"extra series":      countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2}, [2]any{"3", 1}, [2]any{"4", 1}),
		"duplicate vs real": countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2}, [2]any{"NaN", 2}),
		"empty":             countValuesObservation(),
	} {
		t.Run(name, func(t *testing.T) {
			if diff := CompareEvaluationCase(unorderedCase(true), want, got); len(diff) == 0 {
				t.Fatal("marked row accepted a different set of series")
			}
		})
	}
	// The multiset keeps multiplicity: {a,a,b} is not {a,b,b}.
	a, b := [2]any{"1", 1}, [2]any{"2", 1}
	if diff := CompareEvaluationCase(unorderedCase(true), countValuesObservation(a, a, b), countValuesObservation(a, b, b)); len(diff) == 0 {
		t.Fatal("multiset comparison lost multiplicity")
	}
}

func TestUnmarkedVectorsStayOrderExact(t *testing.T) {
	want := countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2})
	got := countValuesObservation([2]any{"NaN", 2}, [2]any{"1", 1})
	if diff := CompareEvaluationCase(unorderedCase(false), want, got); len(diff) == 0 {
		t.Fatal("an unmarked row accepted a reordered vector")
	}
	if diff := CompareEvaluation(want, got); len(diff) == 0 {
		t.Fatal("CompareEvaluation accepted a reordered vector")
	}
	// The marker frees order only: a marked row still compares every other field, and a range row never uses it.
	other := countValuesObservation([2]any{"1", 1}, [2]any{"NaN", 2})
	other.Annotations = []EvaluationAnnotation{{ID: "X", Severity: "warning", Start: 1, End: 2}}
	if diff := CompareEvaluationCase(unorderedCase(true), want, other); len(diff) == 0 {
		t.Fatal("marked row ignored an annotation difference")
	}
	ranged := unorderedCase(true)
	ranged.Kind = "range"
	if diff := CompareEvaluationCase(ranged, want, got); len(diff) == 0 {
		t.Fatal("a range row used the unordered marker")
	}
}

func TestUnorderedMarkerIsInstantOnlyAndNeverSentToAReference(t *testing.T) {
	ranged := unorderedCase(true)
	ranged.Kind, ranged.Start, ranged.End, ranged.Step = "range", 5e9, 15e9, 5e9
	if err := validateEvaluationCase(ranged); err == nil || !strings.Contains(err.Error(), "unordered_vector") {
		t.Fatalf("range row with the marker: %v", err)
	}
	marked := unorderedCase(true)
	cases := withoutComparisonMarkers([]EvaluationCase{marked})
	if cases[0].UnorderedVector || !marked.UnorderedVector {
		t.Fatal("marker stripping must copy, not alias")
	}
	raw, err := json.Marshal(evaluationInput{Cases: cases})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "unordered_vector") {
		t.Fatalf("the marker reached the reference request: %s", raw)
	}
	if raw, _ = json.Marshal(marked); !strings.Contains(string(raw), `"unordered_vector":true`) {
		t.Fatalf("the marker is lost from the authored case: %s", raw)
	}
}

func resolveUnorderedTestProfile(t *testing.T, experimental bool) profile.Profile {
	t.Helper()
	const id = "promql-prometheus-3.13.5"
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest profile.Profile
	if err = ReadJSON("../../../profiles/query/"+id+".json", &manifest); err != nil {
		t.Fatal(err)
	}
	for _, set := range manifest.FeatureSets {
		has := false
		for _, e := range set.Enabled {
			has = has || e == "promql-experimental-functions"
		}
		if has == experimental {
			p, err := registry.Resolve(id, set.ID)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatalf("no feature set with experimental=%v", experimental)
	return profile.Profile{}
}

// The marker may only sit on a row whose top-level operation is count_values and that contains no sort or
// selecting operation; everything else keeps exact order.
func TestUnorderedMarkerRequiresATopLevelCountValuesWithoutOrderingOperations(t *testing.T) {
	plain, experimental := resolveUnorderedTestProfile(t, false), resolveUnorderedTestProfile(t, true)
	accepted := []string{`count_values("v", nanp)`, `(count_values("v", nanp))`, `count_values by (job) ("v", nanp)`, `count_values without (i) ("v", nanp)`}
	for _, q := range accepted {
		c := unorderedCase(true)
		c.Query = q
		if err := validateUnorderedVector(c, plain); err != nil {
			t.Errorf("%s rejected: %v", q, err)
		}
	}
	rejected := []string{
		`sort(nanp)`, `sort_desc(nanp)`, `sort_by_label(nanp, "i")`, `sort_by_label_desc(nanp, "i")`,
		`topk(2, nanp)`, `bottomk(2, nanp)`, `limitk(2, nanp)`, `limit_ratio(0.5, nanp)`,
		`sum(nanp)`, `nanp`, `count_values("v", nanp) * 2`, `1`,
		`count_values("v", sort(nanp))`, `count_values("v", topk(2, nanp))`, `count_values("v", limitk(2, nanp))`,
		`count_values("v", sort_by_label(nanp, "i"))`, `count_values("v", nanp +` + ` sort_desc(nanp))`,
		`count_values(`,
	}
	for _, q := range rejected {
		for _, p := range []profile.Profile{plain, experimental} {
			c := unorderedCase(true)
			c.Query = q
			if err := validateUnorderedVector(c, p); err == nil {
				t.Errorf("%s accepted with the marker", q)
			}
		}
	}
	// An unmarked row is never constrained.
	c := unorderedCase(false)
	c.Query = `sort(nanp)`
	if err := validateUnorderedVector(c, plain); err != nil {
		t.Fatal(err)
	}
}
