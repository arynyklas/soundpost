// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"sort"
	"soundpost/internal/model"
	"soundpost/internal/query/value"
	"strings"
	"testing"
)

// TestParserLabelCollisions pins how json and logfmt stages treat a written name
// that already exists as a stream label, as structured metadata, or as a parsed
// label from an earlier stage. Every vector restates a native observation of the
// reference (lines are shortened variants of corpus rows); the stream label is
// app=api and the metadata label, when present, is sm.
func TestParserLabelCollisions(t *testing.T) {
	type vec struct {
		name, expr, line string
		sm               *string // nil: no structured metadata
		want             string  // sorted name=value pairs
	}
	pre, empty := "pre", ""
	vecs := []vec{
		// Plain stages: stream names rename, metadata is protected, parsed is replaced.
		{"plain logfmt renames a stream name and keeps the last duplicate", `{app="api"}|logfmt`, `app=a app=b`, nil, `app=api app_extracted=b`},
		{"plain logfmt discards a key that names metadata", `{app="api"}|logfmt`, `sm=1 x=2`, &pre, `app=api sm=pre x=2`},
		{"plain logfmt discards a key that names empty metadata", `{app="api"}|logfmt`, `sm=1`, &empty, `app=api sm=`},
		{"plain logfmt sets the name when no metadata holds it", `{app="api"}|logfmt`, `sm=1`, nil, `app=api sm=1`},
		{"plain json discards a key that names metadata", `{app="api"}|json`, `{"sm":1,"x":2}`, &pre, `app=api sm=pre x=2`},
		{"plain json renames a stream name", `{app="api"}|json`, `{"app":"zz"}`, &pre, `app=api app_extracted=zz sm=pre`},

		// Expression stages, requested name is a stream name.
		{"logfmt request colliding with a stream name is silent when the key is absent", `{app="api"}|logfmt app`, `x=1`, nil, `app=api`},
		{"json request colliding with a stream name is silent when the key is absent", `{app="api"}|json app`, `{}`, nil, `app=api`},
		{"absent colliding request does not suppress other absent requests", `{app="api"}|logfmt a, b, app`, `1k=v`, nil, `a= app=api b=`},
		{"logfmt request colliding with a stream name renames when the key is present", `{app="api"}|logfmt app`, `app=zz`, &pre, `app=api app_extracted=zz sm=pre`},
		{"logfmt renamed request keeps the first duplicate", `{app="api"}|logfmt app`, `app=a app=b`, nil, `app=api app_extracted=a`},
		{"logfmt renamed request keeps the first value even when it is empty", `{app="api"}|logfmt app`, `app app=b`, nil, `app=api app_extracted=`},
		{"logfmt renamed duplicate ends the scan before later keys", `{app="api"}|logfmt a, b, app`, "a=v\tapp\tapp=-3\ta=1.5", nil, `a=v app=api app_extracted= b=`},
		{"logfmt renamed duplicate hides a later strict syntax error", `{app="api"}|logfmt --strict a="b", b="a", app="app"`, "app=0x1\tapp=v\ta.b=a=b", nil, `a= app=api app_extracted=0x1 b=`},
		{"logfmt strict error is kept when no duplicate ends the scan", `{app="api"}|logfmt --strict app`, `app==`, nil, `__error__=LogfmtParserErr __error_details__=logfmt_syntax_error_at_pos_5_:_unexpected_'=' app=api`},
		{"logfmt non-renamed duplicate keeps the last value and the scan goes on", `{app="api"}|logfmt x="a", y="b"`, `a=1 a=2 b=3`, nil, `app=api x=2 y=3`},
		{"json renamed request takes the first duplicate key", `{app="api"}|json app`, `{"app":"a","app":"b"}`, nil, `app=api app_extracted=a`},

		// Expression stages, requested name is structured metadata.
		{"logfmt request replaces metadata when the key is present", `{app="api"}|logfmt sm`, `sm=1`, &pre, `app=api sm=1`},
		{"logfmt request empties metadata when the key is absent", `{app="api"}|logfmt sm`, `x=1`, &pre, `app=api sm=`},
		{"json request replaces metadata when the key is present", `{app="api"}|json sm`, `{"sm":1}`, &pre, `app=api sm=1`},
		{"json request leaves metadata alone when the key is absent", `{app="api"}|json sm`, `{}`, &pre, `app=api sm=pre`},
		{"json request leaves empty metadata alone when the key is absent", `{app="api"}|json sm`, `{}`, &empty, `app=api sm=`},
		{"json request sets empty when nothing holds the name", `{app="api"}|json sm`, `{}`, nil, `app=api sm=`},
		{"swapped requests: stream name renames, metadata name is replaced", `{app="api"}|json app="sm", sm="app"`, `{"app":1,"sm":2}`, &pre, `app=api app_extracted=2 sm=1`},

		// Two stages.
		{"parsed rename from a plain stage is not rewritten by logfmt request", `{app="api"}|logfmt|logfmt app`, `app=a app=b`, nil, `app=api app_extracted=b`},
		{"plain stage keeps metadata, request stage sees nothing to rename", `{app="api"}|logfmt|logfmt app`, `sm=1`, &pre, `app=api sm=pre`},
		{"plain stage keeps metadata, request stage still renames its key", `{app="api"}|logfmt|logfmt app`, `sm=1 app=2`, &pre, `app=api app_extracted=2 sm=pre`},
		{"logfmt request empties a name a json stage parsed", `{app="api"}|json|logfmt sm`, `{"sm":1}`, nil, `app=api sm=`},
		{"json request overwrites a rename left by a plain json stage", `{app="api"}|json|json app`, `{"app":"a","app":"b"}`, nil, `app=api app_extracted=a`},

		// Expression stage, line key naming an existing metadata or parsed label.
		{"logfmt path no longer finds a key shadowed by metadata", `{app="api"}|logfmt t="sm"`, `sm=1`, &pre, `app=api sm=pre t=`},
		{"logfmt path finds a key when nothing holds its name", `{app="api"}|logfmt t="sm"`, `sm=1`, nil, `app=api t=1`},
		{"logfmt path finds a key named like a stream label", `{app="api"}|logfmt t="app"`, `app=z`, nil, `app=api t=z`},
		{"logfmt path no longer finds a key shadowed by a parsed label", `{app="api"}|logfmt|logfmt t="sm"`, `sm=1`, nil, `app=api sm=1 t=`},
		{"logfmt request of the shadowing name takes the key over", `{app="api"}|logfmt app="sm", sm="app"`, `sm=1`, &pre, `app=api app_extracted=1 sm=`},
		{"logfmt request colliding with a stream name finds the key by its own name", `{app="api"}|logfmt t="x", app="x"`, `app=z`, nil, `app=api app_extracted=z t=`},
	}
	for _, v := range vecs {
		t.Run(v.name, func(t *testing.T) {
			e := LogEntry{Line: v.line, ID: model.ID{1}, Multiplicity: 1, StreamLabels: model.Labels{{Name: "app", Value: "api"}}}
			if v.sm != nil {
				e.StructuredMetadata = model.Labels{{Name: "sm", Value: *v.sm}}
			}
			account := value.NewBoundedAccount(16 << 20)
			r, err := RunPipeline(context.Background(), testPlan(t, v.expr), e, account)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Retained {
				t.Fatal("entry dropped")
			}
			got := make([]string, 0, len(r.Labels))
			for _, l := range r.Labels {
				got = append(got, strings.ReplaceAll(l.Name+"="+l.Value, " ", "_"))
			}
			sort.Strings(got)
			if joined := strings.Join(got, " "); joined != v.want {
				t.Fatalf("labels=%s want=%s", joined, v.want)
			}
		})
	}
}
