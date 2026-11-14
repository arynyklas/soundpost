// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qualify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// JourneysObservedEnv names the observed.json that `go run ./tools/smoke journeys` wrote. The qualification
// run never starts the journeys itself (they need Docker, a release distribution and minutes of wall time);
// a row that reads a journey row is exercised only by a file that exists and says what it measured.
const JourneysObservedEnv = "SOUNDPOST_JOURNEYS_OBSERVED"

// journeysObserved is the part of the smoke's observed.json this runner reads: its rows, and the proof that
// each canary really travelled through the applications (so an absent canary is a measurement).
type journeysObserved struct {
	Rows []struct {
		Name      string `json:"name"`
		Required  bool   `json:"required"`
		Satisfied bool   `json:"satisfied"`
		Reason    string `json:"reason"`
		Detail    string `json:"detail"`
	} `json:"rows"`
	Observation struct {
		Flows []struct {
			Canary  string   `json:"canary"`
			Reached []string `json:"reached"`
		} `json:"canary_flows"`
		Leaks []json.RawMessage `json:"canary_leaks"`
	} `json:"observation"`
}

// runJourneysRow reports one row of the reference-journeys smoke as a qualification row: passed only when the
// smoke itself recorded that row as satisfied, failed when it recorded it unsatisfied (or reported a leak),
// not exercised when no observed.json was supplied or it does not contain the row.
func runJourneysRow(rc *runCtx, spec RowSpec) Row {
	want := spec.Params["row"]
	if want == "" {
		return notExercised("the matrix row names no journeys smoke row")
	}
	path := os.Getenv(JourneysObservedEnv)
	if path == "" {
		return notExercised(fmt.Sprintf("no journeys result supplied: run `go run ./tools/smoke journeys` (Docker, a release distribution) and set %s to its observed.json; the %q row is read from it", JourneysObservedEnv, want))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return notExercised(fmt.Sprintf("%s=%s is unreadable: %v", JourneysObservedEnv, path, err))
	}
	var obs journeysObserved
	if err := json.Unmarshal(raw, &obs); err != nil {
		return notExercised(fmt.Sprintf("%s is not a journeys observed.json: %v", filepath.Base(path), err))
	}
	found := -1
	for i, r := range obs.Rows {
		if r.Name == want {
			found = i
		}
	}
	if found < 0 {
		return notExercised(fmt.Sprintf("%s holds no %q row", filepath.Base(path), want))
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	r := obs.Rows[found]
	row := Row{
		State:   StateExercised,
		Build:   &Build{Family: "soundpost-journeys", Version: "07.04", OS: rc.host.OS, Arch: rc.host.Arch, ID: "sha256:" + digest, SHA256: digest, Host: rc.host.Class},
		Command: &CommandRun{Command: "go run ./tools/smoke journeys (observed.json row " + want + ")"},
		Evidence: []string{
			fmt.Sprintf("journeys row %s: required=%t satisfied=%t reason=%q", r.Name, r.Required, r.Satisfied, r.Reason),
			"observed.json sha256 " + digest,
		},
	}
	row.Outcome = OutcomePassed
	if !r.Satisfied {
		row.Outcome = OutcomeFailed
		row.Failures = append(row.Failures, fmt.Sprintf("the journeys smoke recorded %s as NOT satisfied: %s %s", want, r.Reason, r.Detail))
	}
	if want == "canaries_absent_everywhere" {
		for _, f := range obs.Observation.Flows {
			if len(f.Reached) == 0 {
				row.Outcome = OutcomeFailed
				row.Failures = append(row.Failures, "a canary never reached any place that could store it, so its absence proves nothing")
				break
			}
		}
		if len(obs.Observation.Flows) == 0 {
			row.Outcome = OutcomeFailed
			row.Failures = append(row.Failures, "the observation carries no canary flows")
		}
		if len(obs.Observation.Leaks) > 0 {
			row.Outcome = OutcomeFailed
			row.Failures = append(row.Failures, fmt.Sprintf("the observation lists %d canary leak(s)", len(obs.Observation.Leaks)))
		}
		row.Evidence = append(row.Evidence, fmt.Sprintf("%d canary flows, %d leaks", len(obs.Observation.Flows), len(obs.Observation.Leaks)))
	}
	return row
}
