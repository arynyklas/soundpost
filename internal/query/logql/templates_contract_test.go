// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Every reachable failure of a helper or builtin must be a query-visible
// *TemplateError (the native __error__ path) or a typed *TemplateLimitError. A
// plain error aborts the whole query, which is reserved for cancellation and
// authorization (02.06-W1, review M9).
var templateContractLiterals = map[byte][]string{
	's': {`""`, `"a"`, `"é"`, `"-1"`, `"1e100"`, `"9223372036854775808"`, `"(a"`, `"Mon Jan 2"`, `"UTC"`, `"nowhere"`, `"2024-02-30"`, `"1h"`, `"-1h"`, `"10x"`, `"{"`, `"[1,"`, `"1.5"`, `"0"`, `"abc abc"`, `"a/b"`, `"%zz"`, `"=="`},
	'i': {`0`, `1`, `-1`, `2`, `9223372036854775807`, `-9223372036854775808`, `1000000`, `100000000`},
	'f': {`0.0`, `-1.5`, `1e308`, `1e100`, `1e-300`},
	't': {`now`, `(toDate "2006-01-02" "2024-03-04")`},
	'a': {`0`, `1`, `-1`, `9223372036854775807`, `-9223372036854775808`, `1.5`, `1e100`, `"s"`, `""`, `"12"`, `true`, `nil`, `now`, `.line`, `.missing`, `(list)`},
}

var templateContractBuiltins = map[string]string{
	"index": "aa*", "slice": "aa*", "len": "a", "not": "a", "and": "aa*", "or": "aa*", "eq": "aa*", "ne": "aa", "lt": "aa", "le": "aa", "gt": "aa", "ge": "aa",
	"html": "a*", "js": "a*", "urlquery": "a*", "print": "a*", "printf": "sa*", "println": "a*", "call": "a*",
}

func templateContractOK(err error) bool {
	if err == nil {
		return true
	}
	var language *TemplateError
	var limit *TemplateLimitError
	return errors.As(err, &language) || errors.As(err, &limit)
}

func TestEveryTemplateHelperAndBuiltinFailsOnlyThroughTheQueryVisiblePath(t *testing.T) {
	signatures := map[string]string{}
	for name, sig := range templateSignatures {
		signatures[name] = sig
	}
	for name, sig := range templateContractBuiltins {
		signatures[name] = sig
	}
	var names []string
	for name := range signatures {
		names = append(names, name)
	}
	sort.Strings(names)
	input := TemplateInput{Line: "line", Timestamp: 1700000000123456789, Labels: model.Labels{{Name: "level", Value: "warn"}}}
	runtime := templateTestRuntime()
	rng := rand.New(rand.NewPCG(7, 11))
	pick := func(kind byte) string {
		set := templateContractLiterals[kind]
		return set[rng.IntN(len(set))]
	}
	executed, failed := 0, 0
	for _, name := range names {
		sig := signatures[name]
		variadic := strings.HasSuffix(sig, "*")
		kinds := []byte(strings.TrimSuffix(sig, "*"))
		var sources []string
		build := func(kinds []byte, choose func(i int) string) string {
			parts := []string{name}
			for i := range kinds {
				parts = append(parts, choose(i))
			}
			return "{{" + strings.Join(parts, " ") + "}}"
		}
		shapes := [][]byte{kinds}
		if variadic {
			shapes = append(shapes, append(append([]byte(nil), kinds...), kinds[len(kinds)-1]), append(append([]byte(nil), kinds...), kinds[len(kinds)-1], kinds[len(kinds)-1]))
			shapes = append(shapes, kinds[:len(kinds)-1])
		}
		for _, shape := range shapes {
			// every literal of every position, the others at their first literal
			for pos := range shape {
				for _, literal := range templateContractLiterals[shape[pos]] {
					sources = append(sources, build(shape, func(i int) string {
						if i == pos {
							return literal
						}
						return templateContractLiterals[shape[i]][0]
					}))
				}
			}
			for range 200 {
				sources = append(sources, build(shape, func(i int) string { return pick(shape[i]) }))
			}
			sources = append(sources, build(shape, func(int) string { return `"a"` }))
		}
		for _, source := range sources {
			c, err := CompileTemplate(source, templateTestProfile(), runtime)
			if err != nil {
				continue // a rejected template is a compile-time answer, not an execution failure
			}
			executed++
			_, err = c.Execute(context.Background(), input, value.NewBoundedAccount(64<<20))
			if !templateContractOK(err) {
				failed++
				if failed <= 40 {
					t.Errorf("%s -> plain error %q", source, err)
				}
			}
		}
	}
	t.Logf("%d templates executed, %d helpers and builtins", executed, len(names))
	if executed < 5000 {
		t.Fatalf("matrix shrank: only %d templates executed", executed)
	}
	if failed > 40 {
		t.Errorf("%d templates failed outside the query-visible path (%s)", failed, fmt.Sprint(executed))
	}
}

// Reservations made for one node's scratch work are returned when the node
// retires, so a long loop is bounded by what it keeps (output, live variables),
// not by the sum of its transient reservations (02.06-W1, review M7).
func TestTemplateScratchReservationsAreReturnedWhenWorkRetires(t *testing.T) {
	cases := []struct{ name, source string }{
		{"helper loop", `{{range 10000}}{{ToUpper "a"}}{{end}}`},
		{"variable loop", `{{range 10000}}{{$x := ToLower "ABC"}}{{$x}}{{end}}`},
		{"nested pipeline", `{{range 10000}}{{"abc" | ToUpper | ToLower}}{{end}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			compiled, err := CompileTemplate(c.source, templateTestProfile(), templateTestRuntime())
			if err != nil {
				t.Fatal(err)
			}
			account := value.NewBoundedAccount(1 << 20)
			out, err := compiled.Execute(context.Background(), TemplateInput{}, account)
			if err != nil {
				t.Fatalf("a loop whose live data is 30 KB at most exhausted its account: %v", err)
			}
			if len(out) != 10000 && len(out) != 30000 {
				t.Fatalf("unexpected output length %d", len(out))
			}
			if used := account.Used(); used != 0 {
				t.Fatalf("%d bytes still reserved after Execute returned", used)
			}
		})
	}
}

// Retiring scratch must not turn live data free: variable bindings stay charged
// until their scope ends.
func TestTemplateLiveBindingsStayChargedUntilTheirScopeEnds(t *testing.T) {
	var source strings.Builder
	for i := range 12 {
		fmt.Fprintf(&source, `{{$v%d := repeat 100000 "x"}}`, i)
	}
	compiled, err := CompileTemplate(source.String(), templateTestProfile(), templateTestRuntime())
	if err != nil {
		t.Fatal(err)
	}
	account := value.NewBoundedAccount(1 << 20)
	_, err = compiled.Execute(context.Background(), TemplateInput{}, account)
	var limit *TemplateLimitError
	if !errors.As(err, &limit) || limit.Resource != "memory" {
		t.Fatalf("1.2 MB of live bindings fit a 1 MiB account: %v", err)
	}
	if account.Used() != 0 {
		t.Fatalf("%d bytes left reserved after the failure", account.Used())
	}
}
