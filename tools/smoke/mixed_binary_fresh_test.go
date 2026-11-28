// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/replica"
)

// The previous release (5475ef6) and an installation the candidate bootstrapped (D72): the control state of such
// an installation carries the born-contracted mark (ControlState.BornContracted, the key
// artifact_refs_index:contracted in the replicated OIDC map) from its first command, and every ledger and replay
// it writes is in the contracted layout only. Two REAL-binary scenarios, both with the three-voter harness of
// TestMixedBinaryVoters (old = the previous release, new = the candidate, the group bootstrapped by the candidate):
//
//	TestMixedBinaryPreviousReleaseVoterOnAFreshInstallation
//	  1  a candidate group is written through every voter (ledgers, replays, tracked admin saves);
//	  2  voter 3 is put back on the previous release: it replays its own log and journal, which carry the mark.
//	     Either it applies, stays ready and holds exactly the other voters' state (equal digests, valid seal, the mark
//	     still in every stored state, saves through it and through the others succeed), or it does not serve and
//	     the candidate voters say so (layout_incompatible:<identity> in `membership status`). A voter that serves a
//	     different state, or that answers a ledger read it cannot understand with wrong data, is the failure;
//	  3  the same voter is stopped, the others commit past the journal cadence, and it comes back on the previous
//	     release and is brought up by a snapshot install that carries the mark: the same two outcomes.
//
//	TestMixedBinaryPreviousReleaseLearnerOnAFreshInstallation
//	  a previous-release learner started for the first time next to a fresh installation of the candidate
//	  (no `contract-indexes` step was ever run) is refused by `membership add-learner` in every group with
//	  layout_incompatible:<identity>, applied nowhere and listed by no voter.
//
// Environment: as TestMixedBinaryPostContractGuard (SOUNDPOST_MIXED_OLD_BINARY, SOUNDPOST_MIXED_NEW_BINARY,
// SOUNDPOST_MIXED_EVIDENCE).

// newFreshMixedRun is the mixedRun of one of the scenarios above; the test is skipped without the binaries.
func newFreshMixedRun(t *testing.T, name string) *mixedRun {
	t.Helper()
	oldBin, newBin, evidence := os.Getenv("SOUNDPOST_MIXED_OLD_BINARY"), os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if oldBin == "" || newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_OLD_BINARY and SOUNDPOST_MIXED_NEW_BINARY to static soundpost binaries of the previous release and the candidate")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	dir := filepath.Join(evidence, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	trace, err := os.Create(filepath.Join(dir, "trace.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { trace.Close() })
	m := &mixedRun{t: t, trace: trace, evidence: dir, oldBin: oldBin, newBin: newBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
	oldSum, _ := fileSHA256(oldBin)
	newSum, _ := fileSHA256(newBin)
	m.say("previous release %s sha256 %s", oldBin, oldSum)
	m.say("candidate %s sha256 %s", newBin, newSum)
	return m
}

func (m *mixedRun) finishFresh(runErr error) {
	m.t.Helper()
	m.writeLogs()
	if runErr != nil && m.violation == "" {
		m.violation = "harness_error: " + runErr.Error()
	}
	m.say("RESULT violation=%q harness_error=%v", m.violation, runErr)
	if m.violation != "" {
		m.t.Fatalf("scenario violated: %s", m.violation)
	}
}

// startFreshCandidateGroup starts three candidate voters on an installation the CANDIDATE bootstrapped (the
// harness bootstraps with its "old" binary, so that is swapped for the candidate for the bootstrap only).
func (m *mixedRun) startFreshCandidateGroup() (func(), error) {
	previous := m.oldBin
	m.oldBin = m.newBin
	cleanup, err := m.startGroup(func(uint64) string { return "new" })
	m.oldBin = previous
	return cleanup, err
}

func TestMixedBinaryPreviousReleaseVoterOnAFreshInstallation(t *testing.T) {
	m := newFreshMixedRun(t, "fresh-voter")
	m.finishFresh(m.runFreshOldVoter())
}

func TestMixedBinaryPreviousReleaseLearnerOnAFreshInstallation(t *testing.T) {
	m := newFreshMixedRun(t, "fresh-learner")
	m.finishFresh(m.runFreshOldLearner())
}

// requireOldVoterReads asks the previous-release voter back for the artifact of a ledger the candidate wrote.
// Nothing but a loud refusal or the intact bytes is acceptable: a 200 with other bytes is silent corruption.
func (m *mixedRun) requireOldVoterReads(label string, back uint64) error {
	if err := m.exp.analyst.login(m.sites[back]); err != nil {
		m.say("  %s: the previous-release voter %d is ready; the analyst login is refused: %v", label, back, err)
		return nil
	}
	status, intact, detail, rerr := readArtifact(m.sites[back], m.exp.analyst, m.fx, m.exp.writes[0].artifact)
	m.say("  %s: the previous-release voter %d answers the artifact read of a ledger the candidate wrote: status %d intact=%t %s (err %v)", label, back, status, intact, detail, rerr)
	if rerr == nil && status == 200 && !intact {
		return m.violate("old_voter_serves_wrong_bytes", fmt.Sprintf("%s: voter %d answered 200 with bytes that are not the uploaded map: %s", label, back, detail))
	}
	return nil
}

// oldVoterOutcome says what a previous-release voter that was just started on the group's state did: it serves
// (true; the caller then requires the same state as everyone) or it does not, in which case the candidate voters
// must say so and must agree among themselves (false).
func (m *mixedRun) oldVoterOutcome(label string, back uint64) (bool, error) {
	identity := distNodes[back-1].identity
	for _, via := range []uint64{1, 2} {
		if err := m.waitReasons(via, []string{"layout_incompatible:" + identity}, 90*time.Second); err != nil {
			return false, err
		}
		if err := waitNodeReady(m.sites[via], 60*time.Second); err != nil {
			return false, m.violate("new_voter_not_ready", fmt.Sprintf("%s: voter %d beside a previous-release voter: %v", label, via, err))
		}
	}
	if err := waitNodeReady(m.sites[back], 180*time.Second); err != nil {
		a, b := m.observe(1), m.observe(2)
		if !a.Ready || !b.Ready || a.Digest == "" || a.Digest != b.Digest {
			return false, m.violate("refusal_left_the_others_diverged", fmt.Sprintf("%s: voter 1 digest %q ready=%t, voter 2 digest %q ready=%t", label, a.Digest, a.Ready, b.Digest, b.Ready))
		}
		m.say("%s RESULT: the previous-release voter %d does not serve this state (alive=%t: %v; log %q); voters 1 and 2 name it layout_incompatible:%s and agree on digest %s", label, back, m.alive(back), err, lastLines(m.c.logs[back].String(), 4), identity, a.Digest)
		return false, nil
	}
	m.say("%s RESULT: the previous-release voter %d is READY on the state that carries the mark; voters 1 and 2 name it layout_incompatible:%s", label, back, identity)
	return true, nil
}

func (m *mixedRun) runFreshOldVoter() error {
	cleanup, err := m.startFreshCandidateGroup()
	defer cleanup()
	if err != nil {
		return err
	}
	// ---- 1. a fresh installation of the candidate, written through every voter ----
	if err = m.requireBornContracted("1 fresh installation of the candidate"); err != nil {
		return err
	}
	if err = m.expandSetup(1); err != nil {
		return err
	}
	for i, via := range []uint64{1, 2, 3} {
		if err = m.expandWriteVia(via, fmt.Sprintf("fresh-old-voter-%d", i+1)); err != nil {
			return err
		}
	}
	if err = m.saves(1, "1 fresh installation"); err != nil {
		return err
	}
	if err = m.expandRequire("1 fresh installation", true); err != nil {
		return err
	}
	if err = m.requireBornContracted("1 after the writes"); err != nil {
		return err
	}

	// ---- 2. voter 3 is put back on the previous release: it replays a log and a journal that carry the mark ----
	back := uint64(3)
	m.say("2 ROLL voter %d from new to old: SIGTERM, restart on the previous release", back)
	if err = m.c.terminate(back); err != nil {
		return err
	}
	m.c.setBinary(back, m.oldBin)
	m.release[back] = "old"
	if err = m.c.start(back); err != nil {
		return err
	}
	if m.sites[back], err = m.c.site(back); err != nil {
		return err
	}
	serves, err := m.oldVoterOutcome("2 log replay", back)
	if err != nil {
		return err
	}
	if !serves {
		return nil
	}
	if err = m.settle("2 log replay: the previous-release voter holds the group's state"); err != nil {
		return err
	}
	if err = m.requireBornContracted("2 after the replay"); err != nil {
		return err
	}
	if err = m.requireOldVoterReads("2", back); err != nil {
		return err
	}
	for _, via := range []uint64{back, 1} {
		if err = m.saves(via, fmt.Sprintf("2 saves through voter %d (%s)", via, m.release[via])); err != nil {
			return err
		}
	}
	if err = m.requireBornContracted("2 after saves through the previous-release voter"); err != nil {
		return err
	}

	// ---- 3. the same voter is brought up by a snapshot install that carries the mark ----
	if err = m.lagThenSnapshot(back, 0); err != nil {
		// The control group's snapshot guard (control.guardSnapshot) does not send a snapshot of a state that carries
		// the mark to a member that cannot read the layout. Then the previous-release voter must not serve, must hold
		// none of the state it was refused, and the other voters must agree.
		if !strings.HasPrefix(m.violation, "lagging_voter_not_ready") {
			return err
		}
		m.violation, m.sawStop = "", false
		a, b, c := m.observe(1), m.observe(2), m.observe(back)
		if !a.Ready || !b.Ready || a.Digest == "" || a.Digest != b.Digest {
			return m.violate("snapshot_refusal_left_the_others_diverged", fmt.Sprintf("voter 1 digest %q ready=%t, voter 2 digest %q ready=%t", a.Digest, a.Ready, b.Digest, b.Ready))
		}
		if c.Ready || c.Applied >= a.Applied {
			return m.violate("previous_release_voter_serves_without_the_state", fmt.Sprintf("voter %d ready=%t applied=%d, the others applied %d", back, c.Ready, c.Applied, a.Applied))
		}
		m.say("3 RESULT: the snapshot install was refused: the previous-release voter %d does not serve (ready=%t, applied %d of %d, log %q); voters 1 and 2 are ready and agree on digest %s", back, c.Ready, c.Applied, a.Applied, lastLines(m.c.logs[back].String(), 2), a.Digest)
		return nil
	}
	if err = m.requireBornContracted("3 after the snapshot install"); err != nil {
		return err
	}
	if err = m.requireOldVoterReads("3", back); err != nil {
		return err
	}
	if err = m.saves(back, "3 save through the previous-release voter after its snapshot install"); err != nil {
		return err
	}
	if err = m.requireBornContracted("3 after the saves"); err != nil {
		return err
	}
	return m.settle("4 final: three voters, one on the previous release, one state")
}

// refuseOldLearner starts a previous-release learner for the first time on a fresh directory and asks every voter to
// add it with `soundpost membership add-learner`: every group must refuse it with layout_incompatible:<identity>,
// none may apply it, no voter may list it, and it must still be running. add repeats the call for the same learner.
func (m *mixedRun) refuseOldLearner(label string) (replica.Member, func(via uint64) (string, error), error) {
	return m.refuseOldLearnerThen(label, func(l string) error { return m.expandRequire(l, true) })
}

// refuseOldLearnerThen is refuseOldLearner with the layout check that closes it named by the caller (nil: none), for the groups whose indexes
// are not contracted.
func (m *mixedRun) refuseOldLearnerThen(label string, layoutCheck func(label string) error) (replica.Member, func(via uint64) (string, error), error) {
	learner, err := m.prepareLearner()
	if err != nil {
		return learner, nil, err
	}
	id := learner.ID
	m.c.setBinary(id, m.oldBin)
	m.release[id] = "old"
	if err = m.c.start(id); err != nil {
		return learner, nil, err
	}
	if err = m.peerListening(id, 60*time.Second); err != nil {
		return learner, nil, err
	}
	m.say("%s the learner %s runs the previous release (alive=%t) and listens on %s; `membership add-learner` against every voter", label, learner.NodeIdentity, m.alive(id), m.c.peer[id])
	add := func(via uint64) (string, error) {
		return m.membershipOut(via, "add-learner", "--id", strconv.FormatUint(id, 10), "--address", learner.Address, "--identity", learner.NodeIdentity, "--failure-domain", learner.FailureDomain)
	}
	totalIncompatible := 0
	for _, via := range []uint64{1, 2, 3} {
		text, aerr := add(via)
		m.say("  add-learner through voter %d: exit-err=%v\n%s", via, aerr, text)
		groups, applied, _, incompatible, ok := stepCounts(text)
		switch {
		case aerr == nil || !ok:
			return learner, add, m.violate("old_learner_not_refused", fmt.Sprintf("voter %d: err=%v output %q", via, aerr, text))
		case applied != 0:
			return learner, add, m.violate("old_learner_applied", fmt.Sprintf("voter %d applied the previous-release learner in %d of %d groups: %s", via, applied, groups, text))
		case incompatible > 0 && !strings.Contains(text, "layout_incompatible:"+learner.NodeIdentity):
			return learner, add, m.violate("refusal_does_not_name_the_member", fmt.Sprintf("voter %d: %s", via, text))
		}
		totalIncompatible += incompatible
	}
	if totalIncompatible == 0 {
		return learner, add, m.violate("old_learner_not_refused", "no group refused the previous-release learner")
	}
	if !m.alive(id) {
		return learner, add, m.violate("old_learner_not_running", fmt.Sprintf("the previous-release learner stopped before the check ended (log %q)", lastLines(m.c.logs[id].String(), 6)))
	}
	for _, via := range []uint64{1, 2, 3} {
		_, _, status, serr := m.controlReasons(via)
		if serr != nil || strings.Contains(status, "learner:"+learner.NodeIdentity) {
			return learner, add, m.violate("old_learner_listed", fmt.Sprintf("voter %d lists the refused learner (err %v):\n%s", via, serr, status))
		}
	}
	m.say("%s refused in %d groups, applied nowhere, listed by no voter", label, totalIncompatible)
	if layoutCheck == nil {
		return learner, add, nil
	}
	return learner, add, layoutCheck(label + " after the refusals")
}

func (m *mixedRun) runFreshOldLearner() error {
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
	if err = m.expandWriteVia(1, "fresh-old-learner"); err != nil {
		return err
	}
	// No contract-indexes step ever ran: the refusal rests on the mark the bootstrap wrote.
	if _, _, err = m.refuseOldLearner("2"); err != nil {
		return err
	}
	return m.settle("3 final: the refused learner changed nothing")
}
