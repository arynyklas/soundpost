//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package rules_test

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/rules"
)

// gateLine is the subset of a rules.jsonl line the checks read (the harness's RuleLine names).
type gateLine struct {
	K       string `json:"k"`
	TNS     int64  `json:"t_ns"`
	AtNS    int64  `json:"at_ns"`
	Project string `json:"project"`
	Rule    string `json:"rule"`
	Mode    string `json:"mode"`
	Outcome string `json:"outcome"`
	Reason  string `json:"reason"`
	Members int    `json:"members"`
	Kind    string `json:"kind"`
	Pages   uint64 `json:"pages"`
	Rows    uint64 `json:"rows"`
	Bytes   uint64 `json:"bytes"`
	OK      bool   `json:"ok"`
}

func gateRead(t *testing.T, dir string) []gateLine {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "rules.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []gateLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l gateLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("not a rules line: %v: %s", err, sc.Text())
		}
		out = append(out, l)
	}
	return out
}

// A rule evaluated over real storage writes its query line and then its committed-evaluation line;
// an evaluation whose data is unavailable is still written, with an outcome that is not complete
// and a query line that says it failed.
func TestGateObserveRulesWriteEvaluationAndQueryLines(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SOUNDPOST_FAULT_DIR", dir)
	n := newNode(t)
	n.put("queue_depth", lbl("job", "api"), 30*sec, 10)
	n.put("queue_depth", lbl("job", "api"), 90*sec, 10)
	alert := n.rule(rules.KindAlert, `queue_depth > 5`)
	if err := alert.Check(n.registry); err != nil {
		t.Fatal(err)
	}
	clock := &fixedClock{}
	clock.set(65)
	read, admin := n.scope(auth.Read), n.scope(auth.OrgAdmin)
	evaluator, committer, store := n.wiring(clock)
	scheduler := rules.NewScheduler(evaluator, committer, store, rules.WithSchedulerClock(clock))
	lease := n.lease()
	if _, err := scheduler.RunOnce(n.ctx, read, admin, alert, lease); err != nil {
		t.Fatal(err)
	}

	lines := gateRead(t, dir)
	if len(lines) != 2 || lines[0].K != "q" || lines[1].K != "e" {
		t.Fatalf("lines after one evaluation: %+v", lines)
	}
	q, e := lines[0], lines[1]
	if !q.OK || q.Rule != alert.ID.String() || q.Project != n.project.String() || q.AtNS != int64(60*sec) || q.Pages == 0 || q.Rows == 0 || q.Bytes == 0 || q.TNS == 0 {
		t.Fatalf("query line: %+v", q)
	}
	if e.Outcome != string(rules.OutcomeComplete) || e.Mode != string(rules.ModeLive) || e.Rule != alert.ID.String() || e.Project != n.project.String() || e.AtNS != int64(60*sec) || e.Members != 1 || e.Kind != string(rules.KindAlert) || e.TNS == 0 {
		t.Fatalf("evaluation line: %+v", e)
	}

	// The data goes away: the next grid point is committed as not complete and says why.
	n.scanner.down.Store(true)
	clock.set(125)
	if _, err := scheduler.RunOnce(n.ctx, read, admin, alert, lease); err != nil {
		t.Fatal(err)
	}
	lines = gateRead(t, dir)
	if len(lines) != 4 || lines[2].K != "q" || lines[3].K != "e" {
		t.Fatalf("lines after the second evaluation: %+v", lines)
	}
	if lines[2].OK || lines[2].AtNS != int64(120*sec) {
		t.Fatalf("failed query line: %+v", lines[2])
	}
	if lines[3].Outcome == string(rules.OutcomeComplete) || lines[3].Outcome == "" || lines[3].Reason == "" || lines[3].AtNS != int64(120*sec) {
		t.Fatalf("evaluation over unavailable data: %+v", lines[3])
	}
}
