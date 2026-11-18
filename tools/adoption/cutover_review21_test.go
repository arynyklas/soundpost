// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// Review l5w21 wave 21, task 08.06: resuming an interrupted quiescence long
// after the evidence bound, plan shapes the engine can never accept, an
// unreadable engine at receipt time, and the CLI's error fidelity.

// review21BlindEngine answers the ownership read with an error once told to,
// the way an unreachable control store does; every command still works.
type review21BlindEngine struct {
	CutoverEngine
	blind bool
}

func (b *review21BlindEngine) Cutover(ctx context.Context, scope auth.Scope) (notify.CutoverState, bool, error) {
	if b.blind {
		return notify.CutoverState{}, false, errors.New("the control store is unreachable")
	}
	return b.CutoverEngine.Cutover(ctx, scope)
}

func review21Fields(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestReview21CutoverResumesQuiescenceAfterTheReplayedAcknowledgementAges: the
// quiescence command took effect and the process died before the state was
// saved. The operator resumes far after the evidence-age bound; the legacy
// operator repeats the ORIGINAL acknowledgement (docs/adoption/cutover.md),
// whose observation time has aged out. The run must still converge to one owner
// by observing the route afresh, never stick "incomplete" with no sender.
func TestReview21CutoverResumesQuiescenceAfterTheReplayedAcknowledgementAges(t *testing.T) {
	w := newCutoverWorld(t)
	w.crashAt("legacy.after.QuiesceNormal")
	if _, crashed, _ := w.cutover(); !crashed {
		t.Fatal("the quiescence command must take effect and then lose the process")
	}
	if es, found := w.engineState(); !found || es.Phase != notify.CutoverQuiescingOld {
		t.Fatalf("engine at the crash: found=%v %+v", found, es)
	}
	if w.legacy.enabled || len(w.legacy.callsNamed("QuiesceNormal:")) != 1 {
		t.Fatalf("the lost command must have disabled the old route once: calls %v enabled %v", w.legacy.calls, w.legacy.enabled)
	}
	// The operator notices 40 minutes later: far beyond the grant's 900-second
	// evidence bound, so the replayed acknowledgement is stale on arrival.
	w.advance(40 * time.Minute)
	w.gate = w.makeGate(w.now())
	w.assertConverged(w.mustCutover())
	if n := len(w.legacy.callsNamed("QuiesceNormal:")); n != 2 {
		t.Fatalf("quiescence commands %d, want the one lost command repeated once", n)
	}
	if got := w.state(); !slices.Equal(got.Completed, cutoverSteps) {
		t.Fatalf("state file after the late resume: %+v", got)
	}
	// The fallback proves the route quiesced NOW: someone re-enabled it during the
	// gap, so a stale acknowledgement plus a fresh enabled observation is still a
	// refusal, never an acceptance.
	w2 := newCutoverWorld(t)
	w2.crashAt("legacy.after.QuiesceNormal")
	if _, crashed, _ := w2.cutover(); !crashed {
		t.Fatal("the quiescence command must take effect and then lose the process")
	}
	w2.advance(40 * time.Minute)
	w2.gate = w2.makeGate(w2.now())
	w2.legacy.enabled = true
	rcpt, crashed, err := w2.cutover()
	if crashed || err == nil || rcpt.Phase != CutoverPhaseIncomplete || rcpt.IncompleteCode != CutoverIncompleteQuiescence {
		t.Fatalf("crashed=%v err=%v receipt=%+v", crashed, err, rcpt)
	}
	if slices.Contains(rcpt.Completed, cutoverStepHandover) {
		t.Fatalf("a re-enabled old route must not be walked past: %+v", rcpt)
	}
	w2.tolerateViolations = true // the world is left with both senders by construction
}

// TestReview21CutoverRefusesAFrontierTheEngineCanNeverAccept: every frontier
// shape the plan 06 engine refuses must be refused by the plan validation,
// before the destination test delivery is made and before any state exists.
func TestReview21CutoverRefusesAFrontierTheEngineCanNeverAccept(t *testing.T) {
	cases := map[string]func(w *cutoverWorld){
		"a source named twice": func(w *cutoverWorld) {
			w.plan.Frontier = []notify.FrontierEntry{w.plan.Frontier[0], w.plan.Frontier[0]}
		},
		"a source policy version of zero": func(w *cutoverWorld) {
			f := w.plan.Frontier[0]
			f.Version = 0
			w.plan.Frontier = []notify.FrontierEntry{f}
		},
		"a frontier entry without a source": func(w *cutoverWorld) {
			f := w.plan.Frontier[0]
			f.Source = model.ID{}
			w.plan.Frontier = []notify.FrontierEntry{f}
		},
		"a frontier entry without a cursor group": func(w *cutoverWorld) {
			f := w.plan.Frontier[0]
			f.Cursor.Group = model.ID{}
			w.plan.Frontier = []notify.FrontierEntry{f}
		},
		"more sources than the engine accepts": func(w *cutoverWorld) {
			// 17: one above control's unexported maxCutoverFrontier of 16.
			base := w.plan.Frontier[0]
			list := make([]notify.FrontierEntry, 0, 17)
			for i := range 17 {
				f := base
				f.Source = model.ID{0xaa, byte(i + 1)}
				list = append(list, f)
			}
			w.plan.Frontier = list
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			w := newCutoverWorld(t)
			edit(w)
			w.wantRefusal("invalid ownership plan")
			w.assertUntouched()
		})
	}
}

// TestReview21CutoverReceiptDistinguishesAnUnreadableEngine: the receipt asks the
// engine who is active. "The engine could not be read" and "the engine answers
// nobody is active" both leave the owner list empty; only one of them is a fact
// about the owners, and the public projection must not blur them.
func TestReview21CutoverReceiptDistinguishesAnUnreadableEngine(t *testing.T) {
	w := newCutoverWorld(t)
	blind := &review21BlindEngine{CutoverEngine: w.engine}
	rt := w.runtime()
	rt.Engine = blind
	proofs := 0
	w.observe("deadman.Proof", func() {
		if proofs++; proofs == 5 { // the reconciliation's last read: the run is over
			blind.blind = true
		}
	})
	rcpt, err := Cutover(CutoverWithRuntime(w.ctx, rt), w.gate, w.plan, w.grant)
	if err != nil || rcpt.Phase != CutoverPhaseDone {
		t.Fatalf("err=%v receipt=%+v", err, rcpt)
	}
	if len(rcpt.ActiveOwners) != 0 {
		t.Fatalf("an unreadable engine reported owners %v", rcpt.ActiveOwners)
	}
	unreadable := review21Fields(t, CutoverPublicSummary(rcpt))
	got, ok := unreadable["engine_readable"]
	if !ok {
		t.Fatal("the public projection cannot tell an unreadable engine from one that answers nobody is active")
	}
	if got != false {
		t.Fatalf("an unreadable engine projected as %v", got)
	}
	// The same empty owner list, this time answered by the engine itself: the
	// verified barrier has no active owner.
	w2 := newCutoverWorld(t)
	w2.failAt("engine.before.new_active", context.DeadlineExceeded)
	rcpt2, crashed2, err2 := w2.cutover()
	if crashed2 || err2 == nil || rcpt2.Phase != CutoverPhaseIncomplete || len(rcpt2.ActiveOwners) != 0 {
		t.Fatalf("crashed=%v err=%v receipt=%+v", crashed2, err2, rcpt2)
	}
	if answered := review21Fields(t, CutoverPublicSummary(rcpt2)); answered["engine_readable"] != true {
		t.Fatalf("a readable engine that answers nobody is active projected as %v", answered["engine_readable"])
	}
}

// TestReview21RollbackReceiptDistinguishesAnUnreadableEngine: the same for the
// rollback projection.
func TestReview21RollbackReceiptDistinguishesAnUnreadableEngine(t *testing.T) {
	w := newCutoverWorld(t)
	done := w.mustCutover()
	blind := &review21BlindEngine{CutoverEngine: w.engine}
	rt := w.runtime()
	rt.Engine = blind
	proofs := 0
	w.observe("deadman.Proof", func() {
		if proofs++; proofs == 2 { // the read that closes the restore: only the receipt is blind
			blind.blind = true
		}
	})
	rb, err := Rollback(CutoverWithRuntime(w.ctx, rt), done, Reason{Code: RollbackReasonOperator, Text: "review21 blind read"}, w.grant)
	if err != nil || rb.Phase != CutoverPhaseDone {
		t.Fatalf("err=%v receipt=%+v", err, rb)
	}
	if len(rb.ActiveOwners) != 0 || !rb.OldRouteEnabled {
		t.Fatalf("blind rollback receipt: %+v", rb)
	}
	if fields := review21Fields(t, RollbackPublicSummary(rb)); fields["engine_readable"] != false {
		t.Fatalf("rollback projection cannot tell an unreadable engine: %v", fields)
	}
}

// TestReview21CutoverCLIKeepsTheRunCauseWhenTheReceiptCannotBeWritten: the
// private receipt is named after the state version, so an interrupted run can
// want a name that already exists; the run's own coded reason must survive.
func TestReview21CutoverCLIKeepsTheRunCauseWhenTheReceiptCannotBeWritten(t *testing.T) {
	w := newCutoverWorld(t)
	w.connectCLI()
	w.failAt("legacy.before.QuiesceNormal", context.DeadlineExceeded)
	env := w.cliEnv()
	if err := runCutover(w.ctx, env.args); err == nil {
		t.Fatal("the interrupted run must be an error")
	}
	review21Occupy(t, env.private, "cutover", w.plan.RunID)
	w.failAt("legacy.before.QuiesceNormal", context.DeadlineExceeded)
	err := runCutover(w.ctx, cutoverFlag(env.args, "--public-summary", filepath.Join(env.inputs, "public-2.json")))
	if err == nil {
		t.Fatal("the resumed run must still report the interruption")
	}
	if !strings.Contains(err.Error(), CutoverIncompleteTimeout) {
		t.Fatalf("the run's own cause is lost behind the output failure: %v", err)
	}
	if !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("the output failure must also be named: %v", err)
	}
}

// TestReview21RollbackCLIKeepsTheRunCauseWhenTheReceiptCannotBeWritten: the same
// for the rollback subcommand, interrupted by its own deadline while waiting for
// the new owner to drain.
func TestReview21RollbackCLIKeepsTheRunCauseWhenTheReceiptCannotBeWritten(t *testing.T) {
	w := newCutoverWorld(t)
	w.connectCLI()
	env := w.cliEnv()
	if err := runCutover(w.ctx, env.args); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	receipt := ""
	for _, p := range cutoverGlob(t, env.private, "cutover-"+w.plan.RunID+".receipt-v*.json") {
		var r CutoverReceipt
		if readInput(p, &r) == nil && r.Phase == CutoverPhaseDone {
			receipt = p
		}
	}
	if receipt == "" {
		t.Fatal("no done cutover receipt from the CLI run")
	}
	w.engine.inflate = -1 // live claims never drain
	review21Occupy(t, env.private, "rollback", w.plan.RunID)
	err := runRollback(w.ctx, []string{"--receipt", receipt, "--authorization", env.grant, "--reason-code", RollbackReasonGap,
		"--reason-text", "review21 drain timeout", "--private-directory", env.private, "--public-summary", filepath.Join(env.inputs, "rb.json"), "--timeout", "1s"})
	w.engine.inflate = 0
	if err == nil {
		t.Fatal("a rollback that could not drain must be an error")
	}
	if !strings.Contains(err.Error(), CutoverIncompleteTimeout) {
		t.Fatalf("the run's own cause is lost behind the output failure: %v", err)
	}
	if !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("the output failure must also be named: %v", err)
	}
}

// review21Occupy creates every receipt name the next invocation can ask for,
// whichever state version it reports.
func review21Occupy(t *testing.T, dir, kind, runID string) {
	t.Helper()
	st, err := cutoverLoadState(filepath.Join(dir, "cutover-"+runID+".state.json"))
	if err != nil || st == nil {
		t.Fatalf("cli state: %v %+v", err, st)
	}
	for v := st.Version + 1; v <= st.Version+4; v++ {
		name := filepath.Join(dir, fmt.Sprintf("%s-%s.receipt-v%d.json", kind, runID, v))
		if err = os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestReview21OutputFailureNamesNeitherThePrivateDirectoryNorTheOSError: the
// output failure must stay a closed diagnostic. The operating system's error
// carries the private directory path, and the tool's outputs never do.
func TestReview21OutputFailureNamesNeitherThePrivateDirectoryNorTheOSError(t *testing.T) {
	const private = "/srv/private-adoption-evidence/run-7"
	for _, c := range []struct {
		name  string
		cause error
		want  string
	}{
		{"occupied name", &fs.PathError{Op: "open", Path: private + "/cutover-r.receipt-v3.json", Err: fs.ErrExist}, "already exists"},
		{"other failure", &fs.PathError{Op: "open", Path: private + "/cutover-r.receipt-v3.json", Err: errors.New("disk quota exceeded")}, "could not be written"},
	} {
		for _, run := range []error{nil, errors.New(CutoverIncompleteTimeout)} {
			err := cutoverOutputFailure("private receipt creation failed", c.cause, run)
			if strings.Contains(err.Error(), private) || strings.Contains(err.Error(), "disk quota") || strings.Contains(err.Error(), "open ") {
				t.Errorf("%s: the diagnostic echoes the operating system's error: %v", c.name, err)
			}
			if !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "private receipt creation failed") {
				t.Errorf("%s: the diagnostic lost its classification: %v", c.name, err)
			}
			if run != nil && !errors.Is(err, run) {
				t.Errorf("%s: the run's own error is not preserved: %v", c.name, err)
			}
		}
	}
}
