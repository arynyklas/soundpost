// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releaseevidence

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// decodeReport decodes the way the gate does: unknown fields are refused.
func decodeReport(raw string) (Report, error) {
	var r Report
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	err := dec.Decode(&r)
	return r, err
}

func TestFailureClassDecodesStrictly(t *testing.T) {
	row := func(class string) string {
		return `{"schema":"` + Schema + `","kind":"runtime","commit":"` + commit + `","source_sha256":"` + source + `","expected_rows":["a"],"rows":[{"id":"a","status":"failed","failure_class":` + class + `}]}`
	}
	for _, name := range []string{"budget_miss", "harness", "dropped_records", "assertion"} {
		rep, err := decodeReport(row(`"` + name + `"`))
		if err != nil || rep.Rows[0].FailureClass != FailureClass(name) {
			t.Errorf("%s: %+v %v", name, rep, err)
		}
	}
	for name, raw := range map[string]string{
		"unknown name":    `"budget-miss"`,
		"upper case":      `"BUDGET_MISS"`,
		"padded":          `" budget_miss"`,
		"empty":           `""`,
		"null":            `null`,
		"number":          `1`,
		"bool":            `true`,
		"array":           `["budget_miss"]`,
		"object":          `{"class":"budget_miss"}`,
		"prefix of valid": `"budget"`,
	} {
		if _, err := decodeReport(row(raw)); err == nil {
			t.Errorf("%s: %s was accepted as a failure class", name, raw)
		}
	}
}

func TestRowValidateTiesTheFailureClassToTheStatus(t *testing.T) {
	for name, c := range map[string]struct {
		row Row
		ok  bool
	}{
		"passed, no class":          {Row{ID: "a", Status: StatusPassed}, true},
		"passed with a class":       {Row{ID: "a", Status: StatusPassed, FailureClass: FailureBudgetMiss}, false},
		"failed budget_miss":        {Row{ID: "a", Status: StatusFailed, FailureClass: FailureBudgetMiss}, true},
		"failed harness":            {Row{ID: "a", Status: StatusFailed, FailureClass: FailureHarness}, true},
		"failed dropped_records":    {Row{ID: "a", Status: StatusFailed, FailureClass: FailureDroppedRecords}, true},
		"failed assertion":          {Row{ID: "a", Status: StatusFailed, FailureClass: FailureAssertion}, true},
		"failed without a class":    {Row{ID: "a", Status: StatusFailed}, false},
		"failed not_run class":      {Row{ID: "a", Status: StatusFailed, FailureClass: FailureNotRun}, false},
		"not_run":                   {Row{ID: "a", Status: StatusNotRun, FailureClass: FailureNotRun}, true},
		"not_run as budget_miss":    {Row{ID: "a", Status: StatusNotRun, FailureClass: FailureBudgetMiss}, false},
		"not_exercised":             {Row{ID: "a", Status: "not_exercised", FailureClass: FailureNotRun}, true},
		"not_exercised, no class":   {Row{ID: "a", Status: "not_exercised"}, false},
		"unsupported":               {Row{ID: "a", Status: "unsupported", FailureClass: FailureUnsupported}, true},
		"unsupported as harness":    {Row{ID: "a", Status: "unsupported", FailureClass: FailureHarness}, false},
		"denied":                    {Row{ID: "a", Status: "denied", FailureClass: FailureDenied}, true},
		"out of scope":              {Row{ID: "a", Status: StatusOutOfReleaseScope, FailureClass: FailureOutOfScope, Platform: "linux/arm64"}, true},
		"out of scope as budget":    {Row{ID: "a", Status: StatusOutOfReleaseScope, FailureClass: FailureBudgetMiss, Platform: "linux/arm64"}, false},
		"flaky as assertion":        {Row{ID: "a", Status: "flaky", FailureClass: FailureAssertion}, true},
		"flaky as budget_miss":      {Row{ID: "a", Status: "flaky", FailureClass: FailureBudgetMiss}, false},
		"invented class on failed":  {Row{ID: "a", Status: StatusFailed, FailureClass: "budget_miss_ish"}, false},
		"empty id":                  {Row{Status: StatusPassed}, false},
		"empty status":              {Row{ID: "a"}, false},
		"skipped as not_run":        {Row{ID: "a", Status: "skipped", FailureClass: FailureNotRun}, true},
		"expected_failure as drops": {Row{ID: "a", Status: "expected_failure", FailureClass: FailureDroppedRecords}, false},
	} {
		if err := c.row.Validate(); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", name, err, c.ok)
		}
	}
}

func TestAReportWithAnUnclassifiedOrMisclassifiedRowIsNotAnEnvelope(t *testing.T) {
	for name, row := range map[string]Row{
		"failed without a class": {ID: "a", Status: StatusFailed, Detail: "server_cpu_percent observed 20.5 percent > limit 5"},
		"passed with a class":    {ID: "a", Status: StatusPassed, FailureClass: FailureBudgetMiss},
	} {
		if _, err := New(KindRuntime, commit, source, []string{"a"}, []Row{row}); err == nil {
			t.Errorf("%s: an envelope was built", name)
		}
	}
}

func TestFailureClassSurvivesTheEnvelopeEncoding(t *testing.T) {
	rep, err := New(KindRuntime, commit, source, []string{"a", "b"}, []Row{
		{ID: "a", Status: StatusFailed, FailureClass: FailureDroppedRecords, Detail: "x"},
		{ID: "b", Status: StatusPassed},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := rep.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"failure_class": "dropped_records"`)) || bytes.Count(raw, []byte("failure_class")) != 1 {
		t.Fatalf("the class is written for the failed row only:\n%s", raw)
	}
	back, err := decodeReport(string(raw))
	if err != nil || back.Rows[0].FailureClass != FailureDroppedRecords || back.Rows[1].FailureClass != "" {
		t.Fatalf("round trip: %+v %v", back.Rows, err)
	}
}
