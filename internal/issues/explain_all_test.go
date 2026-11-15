// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
)

// ExplainAll is Explain for the whole project: the same stored evaluations, only
// for issues that have any, under the same authorization, and as a copy.
func TestExplainAllIsExplainForEveryIssueThatHasAnEvaluation(t *testing.T) {
	f := newFx(t)
	f.apply(f.ev(1, f.A, 50), f.ev(2, f.A, 51))
	f.resolve(1, f.B)
	f.apply(f.ev(1, f.A, 120)) // after the boundary, on a release that is not the fix: evaluated
	one, two := f.issueFor(1), f.issueFor(2)
	if len(f.explain(one)) == 0 {
		t.Fatal("fixture: no stored evaluation")
	}
	all, e := f.svc.ExplainAll(context.Background(), f.writer, f.project)
	if e != nil {
		t.Fatal(e)
	}
	if len(all) != 1 || !reflect.DeepEqual(all[one.ID], f.explain(one)) {
		t.Fatalf("ExplainAll = %+v, want exactly the evaluations of the one issue that has them", all)
	}
	if _, ok := all[two.ID]; ok {
		t.Fatal("an issue with no evaluation was listed")
	}
	// A copy: changing the answer does not change the next read.
	all[one.ID][0].Reopened = !all[one.ID][0].Reopened
	if again, _ := f.svc.ExplainAll(context.Background(), f.writer, f.project); reflect.DeepEqual(again, all) {
		t.Fatal("ExplainAll aliases the stored record")
	}
	// Authorization is Explain's: no scope, no answer.
	if _, e = f.svc.ExplainAll(context.Background(), auth.Scope{}, f.project); e == nil {
		t.Fatal("an empty scope read the evaluations")
	}
}
