// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"testing"
)

func TestReferenceASTTypeAndBytePosition(t *testing.T) {
	for _, c := range []struct{ raw, want string }{{`{"type":"call","func":{"returnType":"vector"}}`, "vector"}, {`{"type":"binaryExpr","lhs":{"type":"numberLiteral"},"rhs":{"type":"vectorSelector"}}`, "vector"}, {`{"type":"subquery"}`, "matrix"}} {
		var v map[string]any
		if e := json.Unmarshal([]byte(c.raw), &v); e != nil {
			t.Fatal(e)
		}
		got, e := referenceType(v)
		if e != nil || got != c.want {
			t.Fatalf("%s %v", got, e)
		}
	}
	p, e := referenceStart("x\nπ +", `invalid parameter "query": 2:4: parse error: unexpected end`)
	if e != nil || p == nil || *p != 5 {
		t.Fatalf("byte start: %v %v", p, e)
	}
}
