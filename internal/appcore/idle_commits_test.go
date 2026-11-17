// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// commitsByKind returns the control revision and, for every command kind, how many commands the control state has applied.
func (n *workerNode) commitsByKind() (model.Revision, map[string]int) {
	n.t.Helper()
	kinds := map[string]int{}
	var revision model.Revision
	if err := n.app.Control.View(n.ctx, func(st model.ControlState) error {
		revision = st.Revision
		for _, binding := range st.CommandOwners {
			kinds[binding[strings.LastIndex(binding, ":")+1:]]++
		}
		return nil
	}); err != nil {
		n.t.Fatal(err)
	}
	return revision, kinds
}

// idleWorkers is the production wiring over a node that has nothing to do: every producer, routing, a sender, no rules, no evidence.
func (n *workerNode) idleWorkers(projects int) *appcore.Workers {
	n.t.Helper()
	for range projects - 1 {
		n.addProject(model.NewID())
	}
	cfg := n.conditionConfig(n.alertRule(), &countingSender{}, nil, nil)
	cfg.Rules = nil
	cfg.Producers = n.app.Producers()
	cfg.MaxProjects = projects
	cfg.Sender = notify.Sender(&countingSender{})
	w, err := n.app.NewWorkers(cfg)
	if err != nil {
		n.t.Fatal(err)
	}
	return w
}

// TestAnIdleRunnerPassMovesNoControlRevision: a pass that has nothing to do commits nothing. The control revision is the one precondition a client command
// that names no narrower one compares (create_org, create_user, evidence and release registration), so every commit that changes no state is a reason to
// refuse a command on a system that is doing nothing. The first passes may settle real state (mode sync, fences); the later ones are idle.
func TestAnIdleRunnerPassMovesNoControlRevision(t *testing.T) {
	const projects = 6
	n := newWorkerNode(t)
	w := n.idleWorkers(projects)
	for range 2 {
		n.clock.v.Add(int64(time.Second))
		n.tick(w)
	}
	before, kindsBefore := n.commitsByKind()
	const passes = 3
	for range passes {
		n.clock.v.Add(int64(time.Second))
		if rep := n.tick(w); rep.Projects != projects {
			t.Fatalf("the pass served %d projects, want %d", rep.Projects, projects)
		}
	}
	after, kindsAfter := n.commitsByKind()
	var moved []string
	for kind, count := range kindsAfter {
		if d := count - kindsBefore[kind]; d != 0 {
			moved = append(moved, fmt.Sprintf("%s x%d", kind, d))
		}
	}
	slices.Sort(moved)
	fmt.Printf("IDLECOMMITS projects=%d passes=%d revision %d -> %d (%d commits, %.1f per pass): %v\n", projects, passes, before, after, after-before, float64(after-before)/passes, moved)
	if after != before {
		t.Fatalf("%d idle passes over %d projects committed %d times (%v); an idle pass must not move the revision", passes, projects, after-before, moved)
	}
}

// TestAClientCommandAtAFreshRevisionSurvivesAnIdleRunnerPass is the symptom the e2e fixtures had to paper over with a one-minute retry
// (web/e2e/support/real.ts sendAtRevision): an operator reads the control revision, the runner makes a pass over the projects while the request is on
// its way, and create_user (an instance-level command: it has no organization epoch to compare, only the global revision) is refused with a
// conflict although nothing the command depends on changed.
func TestAClientCommandAtAFreshRevisionSurvivesAnIdleRunnerPass(t *testing.T) {
	n := newWorkerNode(t)
	w := n.idleWorkers(4)
	for range 2 {
		n.clock.v.Add(int64(time.Second))
		n.tick(w)
	}
	revision, _ := n.commitsByKind()
	n.clock.v.Add(int64(time.Second))
	n.tick(w) // the pass that runs between the read and the command
	id := model.NewID()
	raw, _ := json.Marshal(auth.AdminPayload{ID: id, Email: "late-user@example.test", Password: "a client command password 2026", Reason: "idle pass"})
	if _, err := n.app.Auth.AdminCommand(n.ctx, n.actor, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: revision, OrgID: n.org, Kind: "create_user", Payload: raw}); err != nil {
		t.Fatalf("create_user at the revision read before an idle runner pass: %v", err)
	}
}
