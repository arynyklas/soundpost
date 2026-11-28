// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func rec(ts string) InputRecord { return InputRecord{Kind: "float", Timestamp: ts} }

func TestShrinksListsEveryOneStepSmallerCandidateInAFixedOrder(t *testing.T) {
	r1, r2 := rec("1"), rec("2")
	got := shrinks(Case{ID: "k", Kind: "valid", Expression: "a b", Input: []InputRecord{r1, r2}})
	want := []Case{
		{ID: "k", Kind: "valid", Expression: "a b", Input: []InputRecord{r2}},
		{ID: "k", Kind: "valid", Expression: "a b", Input: []InputRecord{r1}},
		{ID: "k", Kind: "valid", Expression: "a ", Input: []InputRecord{r1, r2}},
		{ID: "k", Kind: "valid", Expression: "ab", Input: []InputRecord{r1, r2}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shrinks of %q:\n got %+v\nwant %+v", "a b", got, want)
	}
	// Truncation stops after '(' ',' ' ' and ')' and always after the last rune.
	var exprs []string
	for _, c := range shrinks(Case{Expression: "f(x, y)"}) {
		exprs = append(exprs, c.Expression)
	}
	if want := []string{"f(x, y", "f(x, ", "f(x,", "f(", "f(x,y)"}; !reflect.DeepEqual(exprs, want) {
		t.Fatalf("shrinks of f(x, y): %q, want %q", exprs, want)
	}
	exprs = nil
	for _, c := range shrinks(Case{Expression: "a) b"}) {
		exprs = append(exprs, c.Expression)
	}
	if want := []string{"a) ", "a)", "a)b"}; !reflect.DeepEqual(exprs, want) {
		t.Fatalf("shrinks of a) b: %q, want %q", exprs, want)
	}
	// Nothing is left to shrink in a single rune, an empty expression or no input.
	if n := len(shrinks(Case{Expression: "m"})) + len(shrinks(Case{})); n != 0 {
		t.Fatalf("%d candidates of cases that cannot shrink", n)
	}
	// A candidate is never larger than the case it came from and never equal to it,
	// and the expression is never shrunk to nothing.
	orig := Case{Expression: `topk(1, label_replace(rate(m[5m]), "a", "$1", "job", "(.*)")) BAD`, Input: []InputRecord{r1, r2, rec("3")}}
	size := func(c Case) int { return len([]rune(c.Expression)) + len(c.Input) }
	for _, c := range shrinks(orig) {
		if size(c) >= size(orig) || c.Expression == "" {
			t.Fatalf("candidate %+v of %+v is not strictly smaller or is empty", c, orig)
		}
	}
	// Candidates share no input memory with the case they came from.
	cands := shrinks(Case{Expression: "a", Input: []InputRecord{r1, r2, rec("3")}})
	cands[0].Input[0] = rec("9")
	if cands[1].Input[0].Timestamp == "9" {
		t.Fatal("two candidates share an input slice")
	}
}

func TestMinimizeTakesTheFirstReproducingCandidateAndStartsOver(t *testing.T) {
	// "At least one record and BAD" has many minimal cases; which one is returned is
	// decided by the documented order: the first reproducing candidate, then again.
	in := []InputRecord{rec("1"), rec("2"), rec("3")}
	reproduces := func(c Case) (bool, error) { return strings.Contains(c.Expression, "BAD") && len(c.Input) >= 1, nil }
	got, err := Minimize(context.Background(), CaseMismatch{Case: Case{Expression: "BAD", Input: in}}, reproduces)
	if err != nil || len(got.Input) != 1 || got.Input[0].Timestamp != "3" || got.Expression != "BAD" {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestMinimizeIsDeterministicAndOneMinimal(t *testing.T) {
	orig := Case{ID: "x", Expression: `topk(1, label_replace(rate(m[5m]), "a", "$1", "job", "(.*)") BAD)`, Input: []InputRecord{rec("1"), {Kind: "float", Timestamp: "2", Bits: StaleBits}, rec("3")}}
	reproduces := func(c Case) bool {
		stale := false
		for _, in := range c.Input {
			stale = stale || in.Bits == StaleBits
		}
		return stale && strings.Contains(c.Expression, "BAD")
	}
	run := func() (Case, []string) {
		var trace []string
		got, err := Minimize(context.Background(), CaseMismatch{Case: orig}, func(c Case) (bool, error) {
			trace = append(trace, c.Expression+"|"+string(rune('0'+len(c.Input))))
			return reproduces(c), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return got, trace
	}
	a, traceA := run()
	b, traceB := run()
	if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(traceA, traceB) {
		t.Fatalf("two runs of the same minimization differ:\n%+v\n%+v", a, b)
	}
	if !reproduces(a) {
		t.Fatalf("the minimized case no longer reproduces: %+v", a)
	}
	if len(a.Input) != 1 || a.Input[0].Bits != StaleBits {
		t.Fatalf("records not minimal: %+v", a.Input)
	}
	for _, c := range shrinks(a) {
		if reproduces(c) {
			t.Fatalf("the result is not 1-minimal: %+v still reproduces", c)
		}
	}
	if len(a.Expression) >= len(orig.Expression) || a.ID != orig.ID {
		t.Fatalf("expression %q (from %q) or identity changed", a.Expression, orig.Expression)
	}
}

func TestMinimizeReturnsTheOriginalWhenNothingSmallerReproduces(t *testing.T) {
	orig := Case{Expression: "topk(1, m) BAD", Input: []InputRecord{rec("1"), rec("2")}}
	calls := 0
	got, err := Minimize(context.Background(), CaseMismatch{Case: orig}, func(c Case) (bool, error) {
		calls++
		return reflect.DeepEqual(c, orig), nil
	})
	if err != nil || !reflect.DeepEqual(got, orig) {
		t.Fatalf("%v %+v", err, got)
	}
	if calls < 1+len(shrinks(orig)) {
		t.Fatalf("%d predicate calls: every candidate must be tried", calls)
	}
}

// The mismatch is a claim about a case that fails. A predicate that agreed to the
// returned case once and then no longer does (a flaky runner) must not yield a
// "minimized mismatch" that does not reproduce.
func TestMinimizeRefusesAResultThatNoLongerReproduces(t *testing.T) {
	orig := Case{Expression: "x", Input: []InputRecord{rec("1"), rec("2")}}
	calls := 0
	flaky := func(Case) (bool, error) {
		calls++
		return calls <= 2, nil // the original, then the first shrink; never again
	}
	got, err := Minimize(context.Background(), CaseMismatch{Case: orig}, flaky)
	if err == nil || !strings.Contains(err.Error(), "no longer reproduces") {
		t.Fatalf("a minimized case that no longer fails was returned: %+v %v", got, err)
	}
}

func TestMinimizeRefusesAMismatchThatNeverReproduced(t *testing.T) {
	_, err := Minimize(context.Background(), CaseMismatch{Case: Case{Expression: "x"}}, func(Case) (bool, error) { return false, nil })
	if err == nil || !strings.Contains(err.Error(), "does not reproduce") {
		t.Fatalf("%v", err)
	}
}

func TestMinimizePropagatesPredicateErrorsAndCancellation(t *testing.T) {
	boom := errors.New("runner down")
	orig := Case{Expression: "a b", Input: []InputRecord{rec("1")}}
	if _, err := Minimize(context.Background(), CaseMismatch{Case: orig}, func(Case) (bool, error) { return false, boom }); !errors.Is(err, boom) {
		t.Fatalf("an error on the original case was swallowed: %v", err)
	}
	calls := 0
	if _, err := Minimize(context.Background(), CaseMismatch{Case: orig}, func(Case) (bool, error) {
		calls++
		if calls == 2 {
			return false, boom
		}
		return true, nil
	}); !errors.Is(err, boom) {
		t.Fatalf("an error on a candidate was swallowed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Minimize(ctx, CaseMismatch{Case: orig}, func(Case) (bool, error) { return true, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled minimization went on: %v", err)
	}
}

func TestProblemShapeIgnoresPositionsButNotTheDisagreement(t *testing.T) {
	if got := problemShape("error at 1:30 owned 29"); got != "error at #:# owned #" {
		t.Fatalf("%q", got)
	}
	cases := []struct {
		name      string
		want, got []string
		same      bool
	}{
		{"same text at another position", []string{"syntax error at 1:30"}, []string{"syntax error at 1:7"}, true},
		{"a different disagreement", []string{"value: reference 1, owned 2"}, []string{"error.unclassified: reference parse-error"}, false},
		{"any one of the wanted problems", []string{"a: x", "b: y"}, []string{"b: y"}, true},
		{"none of the wanted problems", []string{"a: x", "b: y"}, []string{"c: z"}, false},
		{"nothing wanted", nil, []string{"a: x"}, false},
		{"nothing observed", []string{"a: x"}, nil, false},
	}
	for _, c := range cases {
		if got := sameProblem(c.want, c.got); got != c.same {
			t.Errorf("%s: sameProblem(%q, %q) = %v", c.name, c.want, c.got, got)
		}
	}
}
