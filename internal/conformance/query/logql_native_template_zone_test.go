// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestOwnedMatchesRecordedNativeTemplateZoneObservations replays observations of
// the pinned Loki 3.5.2 native template executor for the timezone rows of
// cases/logql-templates.json (DST gaps and overlaps, half and quarter hour
// offsets, zones whose rules changed after 2020, the pre-1970 and post-rule
// ranges, host-local parsing). The owned executor must reproduce each output
// from its own embedded Go 1.24.5 zone dataset, with no host timezone input
// (02.06-W1).
func TestOwnedMatchesRecordedNativeTemplateZoneObservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/native-logql-template-zone-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var observed struct {
		Rows []struct {
			ID     string          `json:"id"`
			Output string          `json:"output"`
			Error  json.RawMessage `json:"error"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &observed); err != nil {
		t.Fatal(err)
	}
	if len(observed.Rows) < 22 {
		t.Fatalf("recorded zone observations shrank to %d rows", len(observed.Rows))
	}
	rawCases, err := os.ReadFile("../../../conformance/query/cases/logql-templates.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []LogQLCase `json:"cases"`
	}
	if err = json.Unmarshal(rawCases, &file); err != nil {
		t.Fatal(err)
	}
	byID := map[string]LogQLCase{}
	for _, c := range file.Cases {
		byID[c.ID] = c
	}
	p, err := resolveLogQLProfile("../../../profiles/query", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The pinned dataset is addressed relative to the repository root.
	here, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir("../../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(here) })
	for _, row := range observed.Rows {
		c, ok := byID[row.ID]
		if !ok || !strings.Contains(row.ID, "/template/zone-") {
			t.Errorf("%s is not a zone row of logql-templates.json", row.ID)
			continue
		}
		if len(row.Error) > 0 && string(row.Error) != "null" {
			t.Errorf("%s: the recorded native observation is an error; this replay holds outputs only", row.ID)
			continue
		}
		c.Phase = "logql-template"
		got, err := observeOwnedLogQL(context.Background(), c, p)
		if err != nil {
			t.Errorf("%s: %v", row.ID, err)
			continue
		}
		if got.Error != nil || got.Output != row.Output {
			t.Errorf("%s: owned %q (error %+v), native %q", row.ID, got.Output, got.Error, row.Output)
		}
	}
}
