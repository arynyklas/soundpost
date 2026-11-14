// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const journeysCanaryRow = `{"name":"canaries_absent_everywhere","required":true,"satisfied":%SAT%,"reason":"%REASON%"}`

func journeysFile(t *testing.T, satisfied bool, flows, leaks string) string {
	t.Helper()
	row := strings.NewReplacer("%SAT%", map[bool]string{true: "true", false: "false"}[satisfied], "%REASON%", "none").Replace(journeysCanaryRow)
	body := `{"rows":[` + row + `],"observation":{"canary_flows":` + flows + `,"canary_leaks":` + leaks + `}}`
	path := filepath.Join(t.TempDir(), "observed.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func journeysRow(t *testing.T, path string) Row {
	t.Helper()
	t.Setenv(JourneysObservedEnv, path)
	rc := &runCtx{host: HostInfo{OS: "linux", Arch: "amd64", Class: "wsl2"}}
	spec := RowSpec{ID: "privacy.journeys.reference_canaries", Suite: SuitePrivacy, Required: true, Runner: "journeys_smoke_row",
		Subject: &Subject{Family: "soundpost-journeys", Version: "07.04", OS: "any", Arch: "any"}, Params: map[string]string{"row": "canaries_absent_everywhere"}}
	row := runners[spec.Runner](rc, spec)
	row.ID, row.Suite, row.Required, row.Subject = spec.ID, spec.Suite, true, *spec.Subject
	if err := ValidateRow(row); err != nil {
		t.Fatal(err)
	}
	return row
}

const goodFlows = `[{"canary":"A","reached":["database_row"]},{"canary":"B","reached":["dependency_prompt_counter"]}]`

func TestJourneysRowReadsTheSmokeVerdict(t *testing.T) {
	if row := journeysRow(t, journeysFile(t, true, goodFlows, `null`)); row.State != StateExercised || row.Outcome != OutcomePassed {
		t.Fatalf("a satisfied row with travelled canaries and no leaks must pass: %+v", row)
	}
	if row := journeysRow(t, journeysFile(t, false, goodFlows, `null`)); row.Outcome != OutcomeFailed {
		t.Fatalf("an unsatisfied smoke row must fail: %+v", row)
	}
	if row := journeysRow(t, journeysFile(t, true, goodFlows, `[{"canary":"A","where":"x"}]`)); row.Outcome != OutcomeFailed {
		t.Fatalf("a recorded leak must fail even when the row says satisfied: %+v", row)
	}
	if row := journeysRow(t, journeysFile(t, true, `[{"canary":"A","reached":[]}]`, `null`)); row.Outcome != OutcomeFailed {
		t.Fatalf("a canary that never reached any store proves nothing: %+v", row)
	}
	if row := journeysRow(t, journeysFile(t, true, `null`, `null`)); row.Outcome != OutcomeFailed {
		t.Fatalf("no canary flows must fail: %+v", row)
	}
}

func TestJourneysRowIsNotExercisedWithoutAResult(t *testing.T) {
	if row := journeysRow(t, ""); row.State != StateNotExercised {
		t.Fatalf("no observed.json must stay not exercised: %+v", row)
	}
	if row := journeysRow(t, filepath.Join(t.TempDir(), "missing.json")); row.State != StateNotExercised {
		t.Fatalf("an unreadable observed.json must stay not exercised: %+v", row)
	}
	empty := filepath.Join(t.TempDir(), "observed.json")
	if err := os.WriteFile(empty, []byte(`{"rows":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if row := journeysRow(t, empty); row.State != StateNotExercised {
		t.Fatalf("a file without the row must stay not exercised: %+v", row)
	}
}
