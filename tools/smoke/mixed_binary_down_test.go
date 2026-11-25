// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
)

// TestMixedBinaryPreviousReleaseLearnerAddedWhileDown is the operator order of docs/operations/deletion.md
// (add-learner, THEN start the node) with a PREVIOUS-release binary, on a fresh installation of the candidate
// (born contracted, D72), REAL binaries:
//
//	1  `membership add-learner` while nothing listens at the learner's peer address is admitted in every group
//	   (the learner layout question admits "not running", fix of the D72 regression);
//	2  the voters commit past their journal cadence, so the learner can only be brought up by a snapshot;
//	3  the learner is started on the previous release: it is listed by `membership status` as
//	   layout_incompatible:<identity> on every voter, `membership replace --promote` is refused (applied nowhere,
//	   it stays a learner) and it receives NO contracted snapshot (no snapshot in its control directory, no
//	   snapshot-install line in its log), while the voters stay ready and agree.
//
// Environment: as TestMixedBinaryPostContractGuard.
func TestMixedBinaryPreviousReleaseLearnerAddedWhileDown(t *testing.T) {
	m := newFreshMixedRun(t, "down-learner")
	m.finishFresh(m.runOldLearnerAddedWhileDown())
}

func (m *mixedRun) runOldLearnerAddedWhileDown() error {
	cleanup, err := m.startFreshCandidateGroup()
	defer cleanup()
	if err != nil {
		return err
	}
	if err = m.requireBornContracted("1 fresh installation of the candidate"); err != nil {
		return err
	}
	if err = m.expandSetup(1); err != nil {
		return err
	}
	if err = m.expandWriteVia(1, "down-learner"); err != nil {
		return err
	}

	// ---- 1. add-learner while the learner is not running ----
	learner, err := m.prepareLearner()
	if err != nil {
		return err
	}
	id := learner.ID
	m.say("1 the learner %s is NOT running (nothing listens on %s); `membership add-learner` against each voter until every group holds it", learner.NodeIdentity, m.c.peer[id])
	add := func(via uint64) (string, error) {
		return m.membershipOut(via, "add-learner", "--id", strconv.FormatUint(id, 10), "--address", learner.Address, "--identity", learner.NodeIdentity, "--failure-domain", learner.FailureDomain)
	}
	deadline := time.Now().Add(240 * time.Second)
	for round := 0; ; round++ {
		via := []uint64{1, 2, 3}[round%3]
		text, aerr := add(via)
		lines := strings.Split(text, "\n")
		m.say("  add-learner (learner down) through voter %d: %s (err=%v)", via, lines[len(lines)-1], aerr)
		if _, _, _, incompatible, ok := stepCounts(text); ok && incompatible != 0 {
			return m.violate("down_learner_refused", fmt.Sprintf("voter %d refused a learner nothing runs for: %s", via, text))
		}
		if aerr == nil && strings.Contains(text, "not_leader=0 ") {
			break
		}
		if time.Now().After(deadline) {
			return m.violate("down_learner_not_added", fmt.Sprintf("last output: %s (err %v)", text, aerr))
		}
		time.Sleep(time.Second)
	}

	// ---- 2. the voters commit past the journal cadence: the learner can only get a snapshot ----
	live := []uint64{1, 2, 3}
	sessions := map[uint64]auth.Session{}
	for _, v := range live {
		s, serr := m.login(v)
		if serr != nil {
			return serr
		}
		sessions[v] = s
	}
	peak, compacted := map[uint64]int64{}, map[uint64]bool{}
	for i := range 2500 {
		via := live[i%3]
		if err = m.adminSave(via, sessions[via], "team", m.bigTeamPayload()); err != nil {
			return m.violate("save_failed", fmt.Sprintf("big team save %d through voter %d: %v", i, via, err))
		}
		m.saveCount++
		if i%10 != 0 {
			continue
		}
		done := true
		for _, v := range live {
			size := m.controlWAL(v)
			peak[v] = max(peak[v], size)
			if peak[v] > 1<<20 && size < peak[v]/2 {
				compacted[v] = true
			}
			done = done && compacted[v]
		}
		if done {
			m.say("2 after %d big saves every voter compacted its control journal (peaks %v)", i+1, peak)
			break
		}
	}
	for _, v := range live {
		if !compacted[v] {
			return m.violate("no_journal_cut", fmt.Sprintf("voter %d never compacted its control journal (peak %d bytes, now %d)", v, peak[v], m.controlWAL(v)))
		}
	}

	// ---- 3. the previous release is started on the learner ----
	// The previous release cannot join: it opens its groups from the state the voters hold and exits at startup, within about a second,
	// with reason=unavailable (its groups fail closed; it serves nothing and never becomes ready). The test therefore does not try to
	// catch it while it listens: it waits for the exit, which is the outcome.
	m.c.setBinary(id, m.oldBin)
	m.release[id] = "old"
	if err = m.c.start(id); err != nil {
		return err
	}
	exit, exited := m.waitExit(id, 90*time.Second)
	logText := m.c.logs[id].String()
	m.say("3 the previous-release learner: exited=%t exit=%v log tail %q", exited, exit, lastLines(logText, 4))
	if !exited {
		return m.violate("old_learner_still_running", "the previous-release learner did not exit within 90 s: "+lastLines(logText, 6))
	}
	if exit == nil || !strings.Contains(logText, "soundpost: startup or service failed (reason=unavailable)") {
		return m.violate("old_learner_exit_unexpected", fmt.Sprintf("exit %v, log %q", exit, lastLines(logText, 6)))
	}
	// it received NO contracted snapshot
	listing := dirListing(filepath.Join(m.c.data[id], "raft", "control"))
	logSnap := grepLines(logText, "snapshot")
	m.say("  learner control directory: %s", listing)
	m.say("  learner log, snapshot lines: %q", logSnap)
	if strings.Contains(strings.ToLower(listing), "snap") {
		return m.violate("old_learner_got_a_snapshot", "snapshot file in the learner's control directory: "+listing)
	}
	if strings.Contains(strings.ToLower(logSnap), "install") {
		return m.violate("old_learner_got_a_snapshot", "snapshot install in the learner log: "+logSnap)
	}
	// it is a member that does not answer the layout question, so every voter names it
	for _, via := range []uint64{1, 2, 3} {
		if err = m.waitReasons(via, []string{"layout_incompatible:" + learner.NodeIdentity}, 120*time.Second); err != nil {
			return err
		}
	}
	// promotion refused
	for _, via := range []uint64{1, 2, 3} {
		text, perr := m.membershipOut(via, "replace", "--remove", "3", "--promote", strconv.FormatUint(id, 10))
		m.say("  replace --remove 3 --promote %d through voter %d: err=%v\n%s", id, via, perr, text)
		_, applied, _, incompatible, ok := stepCounts(text)
		if perr == nil || !ok || applied != 0 || (incompatible == 0 && !strings.Contains(text, "not_leader")) {
			return m.violate("old_learner_promoted", fmt.Sprintf("voter %d: err=%v output %q", via, perr, text))
		}
	}
	for _, via := range []uint64{1, 2} {
		if err = waitNodeReady(m.sites[via], 60*time.Second); err != nil {
			return m.violate("new_voter_not_ready", fmt.Sprintf("voter %d: %v", via, err))
		}
	}
	m.say("3 RESULT: added while down; the previous release exits at startup (reason=unavailable), is named by status on every voter, promotion refused, no snapshot delivered")
	return m.settle("3 final: voters agree")
}

// waitExit waits up to limit for the process of member id to exit and returns its exit error (nil: a clean exit).
func (m *mixedRun) waitExit(id uint64, limit time.Duration) (error, bool) {
	m.c.mu.Lock()
	done := m.c.done[id]
	m.c.mu.Unlock()
	select {
	case err := <-done:
		done <- err
		return err, true
	case <-time.After(limit):
		return nil, false
	}
}
