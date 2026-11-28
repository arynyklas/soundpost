//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package appcore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A load harness that runs a soundpost_faults build reads what the worker passes did from
// <SOUNDPOST_FAULT_DIR>/workers.jsonl: one line per pass ("w") and one per project served in a pass
// ("p"), with the time of each step in microseconds and the revision-race retries of the writers. Nothing
// is written unless the variable names a directory, and a write that fails is dropped: observing a pass
// never fails or delays it.

type workerLine struct {
	K       string `json:"k"`
	TNS     int64  `json:"t_ns"`
	Loop    string `json:"loop"`
	Project string `json:"project,omitempty"`
	TookUS  int64  `json:"took_us"`

	Projects  int `json:"projects,omitempty"`
	Evaluated int `json:"evaluated,omitempty"`
	Errors    int `json:"errors,omitempty"`

	AuthUS     int64 `json:"auth_us"`
	RulesUS    int64 `json:"rules_us"`
	EvaluateUS int64 `json:"evaluate_us"`
	CommitUS   int64 `json:"commit_us"`
	OutputsUS  int64 `json:"outputs_us"`
	ProduceUS  int64 `json:"produce_us"`
	ConsumeUS  int64 `json:"consume_us"`
	SubmitUS   int64 `json:"submit_us"`
	CutoverUS  int64 `json:"cutover_us"`
	OutboxUS   int64 `json:"outbox_us"`

	StaleRules      uint64 `json:"stale_rules,omitempty"`
	StaleOutbox     uint64 `json:"stale_outbox,omitempty"`
	StaleConditions uint64 `json:"stale_conditions,omitempty"`
	StaleIncidents  uint64 `json:"stale_incidents,omitempty"`
}

var workerMu sync.Mutex

func workerAppend(line workerLine) {
	dir := os.Getenv("SOUNDPOST_FAULT_DIR")
	if dir == "" {
		return
	}
	raw, err := json.Marshal(line)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	workerMu.Lock()
	defer workerMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, "workers.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(raw)
	_ = f.Close()
}

func us(d time.Duration) int64 { return d.Microseconds() }

func fillSteps(l *workerLine, s StepTimes) {
	l.AuthUS, l.RulesUS, l.EvaluateUS, l.CommitUS, l.OutputsUS = us(s.Auth), us(s.Rules), us(s.Evaluate), us(s.Commit), us(s.Outputs)
	l.ProduceUS, l.ConsumeUS, l.SubmitUS, l.CutoverUS, l.OutboxUS = us(s.Produce), us(s.Consume), us(s.Submit), us(s.Cutover), us(s.Outbox)
}

// workerPassObserved records one finished pass of the loop.
func workerPassObserved(loop string, r PassReport) {
	line := workerLine{K: "w", TNS: time.Now().UnixNano(), Loop: loop, TookUS: us(r.Took), Projects: r.Projects, Evaluated: r.Evaluated, Errors: len(r.Errors),
		StaleRules: r.StaleRetries.Rules, StaleOutbox: r.StaleRetries.Outbox, StaleConditions: r.StaleRetries.Conditions, StaleIncidents: r.StaleRetries.Incidents}
	fillSteps(&line, r.Steps)
	workerAppend(line)
}

// workerProjectObserved records the steps of one project's service in a pass.
func workerProjectObserved(loop string, project model.ID, took time.Duration, s StepTimes) {
	line := workerLine{K: "p", TNS: time.Now().UnixNano(), Loop: loop, Project: project.String(), TookUS: us(took)}
	fillSteps(&line, s)
	workerAppend(line)
}
