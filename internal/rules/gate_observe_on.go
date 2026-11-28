//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
)

// A browser or load harness that runs a soundpost_faults build learns what the rule engine
// did from <SOUNDPOST_FAULT_DIR>/rules.jsonl: one line per committed evaluation ("e") and one
// per rule query ("q"). Nothing is written unless the variable names a directory, and a write
// that fails is dropped: observing an evaluation must never fail or delay it.

// gateRuleLine mirrors the harness's RuleLine field for field (the product does not import the
// harness): the JSON names are the contract.
type gateRuleLine struct {
	K       string `json:"k"`
	TNS     int64  `json:"t_ns"`
	AtNS    int64  `json:"at_ns"`
	Project string `json:"project"`
	Rule    string `json:"rule"`
	Mode    string `json:"mode,omitempty"`
	Outcome string `json:"outcome,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Blocked bool   `json:"blocked,omitempty"`
	Members int    `json:"members,omitempty"`
	MS      int64  `json:"ms,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Pages   uint64 `json:"pages,omitempty"`
	Rows    uint64 `json:"rows,omitempty"`
	Bytes   uint64 `json:"bytes,omitempty"`
	PeakMem uint64 `json:"peak_mem,omitempty"`
	OK      bool   `json:"ok,omitempty"`
}

// gateMu serializes the appends of one process. Each line is one O_APPEND write of a whole line
// opened and closed under the lock: a line is on disk when the call returns, so nothing is lost
// to a kill and no buffer needs a timer.
var gateMu sync.Mutex

func gateAppend(line gateRuleLine) {
	dir := os.Getenv("SOUNDPOST_FAULT_DIR")
	if dir == "" {
		return
	}
	raw, err := json.Marshal(line)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	gateMu.Lock()
	defer gateMu.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, "rules.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(raw)
	_ = f.Close()
}

// gateStamp is the wall clock at the start of one commitAt call (zero when nothing is observed).
type gateStamp struct{ at time.Time }

func gateBegin() gateStamp {
	if os.Getenv("SOUNDPOST_FAULT_DIR") == "" {
		return gateStamp{}
	}
	return gateStamp{at: time.Now()}
}

// gateCommitted records one evaluation after its successful Commit; ms is the wall time of the
// Evaluate and Commit calls of the grid point.
func gateCommitted(ev Evaluation, begun gateStamp) {
	now := time.Now()
	var ms int64
	if !begun.at.IsZero() {
		ms = now.Sub(begun.at).Milliseconds()
	}
	gateAppend(gateRuleLine{
		K: "e", TNS: now.UnixNano(), AtNS: int64(ev.At), Project: ev.Project.String(), Rule: ev.Rule.String(),
		Mode: string(ev.Mode), Outcome: string(ev.Outcome), Reason: ev.Reason, Blocked: ev.RecoveryBlocked,
		Members: len(ev.Members), MS: ms, Kind: string(ev.Kind),
	})
}

// gateQueried records the rule's query: the storage work its answer reports, summed over the
// projects it named (a rule names exactly one), and whether it answered without error.
func gateQueried(rule Rule, at model.UnixNano, result query.Result, qerr error) {
	line := gateRuleLine{K: "q", TNS: time.Now().UnixNano(), AtNS: int64(at), Project: rule.Project.String(), Rule: rule.ID.String(), OK: qerr == nil}
	for _, p := range result.Projects {
		line.Pages += uint64(p.Stats.PagesRead)
		line.Rows += uint64(p.Stats.RowsRead)
		line.Bytes += uint64(p.Stats.BytesRead)
		line.PeakMem += uint64(p.Stats.PeakMemoryBytes)
	}
	gateAppend(line)
}
