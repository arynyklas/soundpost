// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package smoke

import (
	"encoding/json"
	"os"
)

// StepResult is one executed smoke step. A step that could not run is reported
// by the caller as not satisfied, never as passed.
type StepResult struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	// NotRun marks a step (or part of one) the harness could not execute or
	// measure. It is never counted as passed.
	NotRun bool   `json:"not_run,omitempty"`
	Detail string `json:"detail,omitempty"`
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// Failed counts failing steps.
func Failed(steps []StepResult) int {
	n := 0
	for _, s := range steps {
		if !s.Passed && !s.NotRun {
			n++
		}
	}
	return n
}

// NotRunCount counts steps the harness could not execute.
func NotRunCount(steps []StepResult) int {
	n := 0
	for _, s := range steps {
		if s.NotRun {
			n++
		}
	}
	return n
}
