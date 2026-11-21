// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"testing"
)

func TestEvaluationComparesTypedErrorFamilyNotRawOrSafeProse(t *testing.T) {
	reference := EvaluationObservation{ID: "arity", Error: &EvaluationError{Category: "parse-error", CategoryExposed: false, Message: `1:1: parse error: expected 2 argument(s) in call to "clamp_min", got 1`, ID: "function.arity", Start: 0, End: 12, RangeExposed: true}}
	owned := EvaluationObservation{ID: "arity", Error: &EvaluationError{Category: "type", CategoryExposed: true, Message: "invalid function argument count", ID: "function.arity", Start: 0, End: 12, RangeExposed: true}}
	if mismatches := CompareEvaluation(reference, owned); len(mismatches) != 0 {
		t.Fatalf("unexposed native stage or prose compared: %+v", mismatches)
	}
	owned.Error.ID = "function.argument-type"
	if len(CompareEvaluation(reference, owned)) == 0 {
		t.Fatal("different typed failure families collapsed")
	}
	owned.Error.ID = "function.arity"
	owned.Error.End++
	if len(CompareEvaluation(reference, owned)) == 0 {
		t.Fatal("genuine exposed end range discarded")
	}
	owned.Error.End = reference.Error.End
	owned.Error.Start++
	if len(CompareEvaluation(reference, owned)) == 0 {
		t.Fatal("genuine exposed start range discarded")
	}
	owned.Error.Start = reference.Error.Start
	reference.Error.Category = "execution"
	reference.Error.CategoryExposed = true
	if len(CompareEvaluation(reference, owned)) == 0 {
		t.Fatal("genuinely exposed category discarded")
	}
}

func TestEvaluationUnknownErrorFamilyNeverPassesByEqualText(t *testing.T) {
	reference := EvaluationObservation{ID: "unknown", Error: &EvaluationError{Category: "parse-error", Message: "identical unclassified message"}}
	owned := reference
	if len(CompareEvaluation(reference, owned)) == 0 {
		t.Fatal("unknown errors passed because raw messages were equal")
	}
}

func TestEvaluationOwnedErrorConsumesTypedOriginCode(t *testing.T) {
	p := evaluationProfile(t)
	got, err := observeOwnedEvaluation(context.Background(), EvaluationCase{ID: "unknown-call", Query: "soundpost_missing_function(1)", Kind: "instant"}, p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Error == nil || got.Error.ID != "function.unknown" || !got.Error.CategoryExposed {
		t.Fatalf("actual owned typed cause not observed: %+v", got.Error)
	}
}
