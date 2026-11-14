// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
	"strings"
	"testing"
	"time"
)

// TestMetricPipelineErrorMessageIsStatic: a LogQL metric whose input carries an
// engine pipeline error fails with the closed error kind the engine itself set,
// while a stored record that merely extracts a label named __error__ never gets
// its own text into the diagnostic, whose message is static.
func TestMetricPipelineErrorMessageIsStatic(t *testing.T) {
	f := newFx(t)
	org, ps := f.newOrg("pipeline-error", 1)
	alice := f.user(org, "alice@example.test", ps, auth.Read)
	scope := f.scope(alice, org, ps...)
	st := newStore()
	const secret = "LEAKED-RECORD-TEXT"
	st.add(logRow(t, ps[0], testEpoch, `{"__error__":"`+secret+`"}`, model.Labels{{Name: "app", Value: "x"}}))
	st.add(logRow(t, ps[0], testEpoch, `not json at all`, model.Labels{{Name: "app", Value: "engine"}}))
	e := f.engineWith(st, testLimits(), false)
	metric := func(selector string) Request {
		r := logReq(`rate({app="`+selector+`"} | json [1m])`, 0, 0, ps...)
		r.Evaluation = Evaluation{Instant: true, Time: model.UnixNano(testEpoch + int64(time.Second))}
		return r
	}

	_, err := e.engine.Execute(f.ctx, scope, metric("x"))
	var language *syntax.LanguageError
	if !errors.As(err, &language) {
		t.Fatalf("a metric input with an __error__ label is a typed language failure, got %v", err)
	}
	failure := failureOf(err)
	wire, _ := json.Marshal(failure)
	if strings.Contains(language.SafeMessage, secret) || strings.Contains(err.Error(), secret) || strings.Contains(string(wire), secret) {
		t.Fatalf("record text reached the diagnostic: %q / %s", language.SafeMessage, wire)
	}
	if language.Code != "metric.pipeline-error" {
		t.Fatalf("the failure keeps its code: %+v", language)
	}

	// The engine's own error kind is a closed vocabulary and stays reported.
	_, err = e.engine.Execute(f.ctx, scope, metric("engine"))
	if !errors.As(err, &language) || language.Code != "metric.pipeline-error" || language.SafeMessage != "metric input contains pipeline error: JSONParserErr" {
		t.Fatalf("an engine-set pipeline error keeps its kind in the message: %v", err)
	}
	e.idle(t)
}
