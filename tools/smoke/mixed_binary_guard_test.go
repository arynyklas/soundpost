// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMixedBinaryPostContractGuard is the post-contract guard (D70, review 3a) on REAL binaries: after
// `soundpost upgrade contract-indexes` the previous release (an old binary cannot be changed) must not enter
// the membership, and the voters that run the candidate must say when one of them was put back.
//
//	1  three candidate voters write ledgers and replays, then the step contracts the indexes;
//	2  (a) a learner that runs the PREVIOUS release (alive on its peer port, answering nothing to the live layout
//	   question) is added with `soundpost membership add-learner` against every voter: every group is refused with
//	   layout_incompatible:<identity>, nothing is applied and no voter lists it; a learner on the candidate is then
//	   added and serves (the guard refuses the previous release, not new members);
//	3  (c) voter 3 is rolled back to the previous release: the other two voters list it as
//	   layout_incompatible:<identity> in `soundpost membership status` (control group only) and stay ready; the
//	   previous-release voter itself is recorded (ready or not, and what it answers for a ledger it cannot read:
//	   corrupt); rolled forward again the reason is gone and every voter reads every ledger and replay.
//
// Environment: as TestMixedBinaryContractRefusal (SOUNDPOST_MIXED_OLD_BINARY, SOUNDPOST_MIXED_NEW_BINARY,
// SOUNDPOST_MIXED_EVIDENCE).
func TestMixedBinaryPostContractGuard(t *testing.T) {
	oldBin, newBin, evidence := os.Getenv("SOUNDPOST_MIXED_OLD_BINARY"), os.Getenv("SOUNDPOST_MIXED_NEW_BINARY"), os.Getenv("SOUNDPOST_MIXED_EVIDENCE")
	if oldBin == "" || newBin == "" {
		t.Skip("set SOUNDPOST_MIXED_OLD_BINARY and SOUNDPOST_MIXED_NEW_BINARY to static soundpost binaries of the previous release and the candidate")
	}
	if evidence == "" {
		evidence = t.TempDir()
	}
	dir := filepath.Join(evidence, "guard")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	trace, err := os.Create(filepath.Join(dir, "trace.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer trace.Close()
	m := &mixedRun{t: t, trace: trace, evidence: dir, oldBin: oldBin, newBin: newBin, release: map[uint64]string{}, expect: "green", patchMax: map[uint64]int{}}
	oldSum, _ := fileSHA256(oldBin)
	newSum, _ := fileSHA256(newBin)
	m.say("previous release %s sha256 %s", oldBin, oldSum)
	m.say("candidate %s sha256 %s", newBin, newSum)
	runErr := m.runGuard()
	m.writeLogs()
	if runErr != nil && m.violation == "" {
		m.violation = "harness_error: " + runErr.Error()
	}
	m.say("RESULT violation=%q harness_error=%v", m.violation, runErr)
	if m.violation != "" {
		t.Fatalf("guard scenario violated: %s", m.violation)
	}
}

// layout_incompatible= is absent from the summary of a binary without the guard (the RED run).
var stepSummary = regexp.MustCompile(`groups=(\d+) applied=(\d+) already=(\d+) not_leader=(\d+) learner_not_caught_up=(\d+)(?: layout_incompatible=(\d+))? unavailable=(\d+) rejected=(\d+)`)

// stepCounts parses the summary line of `soundpost membership add-learner`.
func stepCounts(out string) (groups, applied, notLeader, incompatible int, ok bool) {
	f := stepSummary.FindStringSubmatch(out)
	if f == nil {
		return 0, 0, 0, 0, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	return n(f[1]), n(f[2]), n(f[4]), n(f[6]), true
}

// membershipOut runs `soundpost membership <args>` of the candidate binary against voter via's private socket.
func (m *mixedRun) membershipOut(via uint64, args ...string) (string, error) {
	full := append(append([]string{"membership"}, args[:1]...), append([]string{"--data-dir", m.c.data[via]}, args[1:]...)...)
	out, err := exec.Command(m.newBin, full...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// controlReasons is what voter via's `membership status` says about members that cannot read the contracted
// layout: the reasons of the lines that carry any (only the control group's does) and the number of such lines.
func (m *mixedRun) controlReasons(via uint64) (reasons []string, lines int, status string, err error) {
	status, err = m.membershipOut(via, "status")
	if err != nil {
		return nil, 0, status, err
	}
	for _, line := range strings.Split(status, "\n") {
		if i := strings.Index(line, " reasons="); i >= 0 {
			lines++
			reasons = append(reasons, strings.Split(line[i+len(" reasons="):], ",")...)
		}
	}
	return reasons, lines, status, nil
}

// waitReasons waits until voter via reports exactly want (in order) as the reasons of the control group.
func (m *mixedRun) waitReasons(via uint64, want []string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		reasons, lines, status, err := m.controlReasons(via)
		if err == nil && lines <= 1 && strings.Join(reasons, ",") == strings.Join(want, ",") {
			m.say("  voter %d (%s) membership status reasons=%v on %d line(s)", via, m.release[via], reasons, lines)
			return nil
		}
		if time.Now().After(deadline) {
			return m.violate("reasons_wrong", fmt.Sprintf("voter %d: want reasons %v on at most one line, have %v on %d (err %v):\n%s", via, want, reasons, lines, err, status))
		}
		time.Sleep(time.Second)
	}
}

// peerListening waits until the peer port of member id accepts connections.
func (m *mixedRun) peerListening(id uint64, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", m.c.peer[id], time.Second); err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return m.violate("learner_not_listening", fmt.Sprintf("member %d never listened on %s (log %q)", id, m.c.peer[id], lastLines(m.c.logs[id].String(), 6)))
}

// alive reports whether the process of member id is still running.
func (m *mixedRun) alive(id uint64) bool {
	m.c.mu.Lock()
	done := m.c.done[id]
	m.c.mu.Unlock()
	if done == nil {
		return false
	}
	select {
	case <-done:
		return false
	default:
		return true
	}
}

func (m *mixedRun) runGuard() error {
	cleanup, err := m.startGroup(func(uint64) string { return "new" })
	defer cleanup()
	if err != nil {
		return err
	}

	// ---- 1. the candidate writes, then contracts ----
	if err = m.expandSetup(1); err != nil {
		return err
	}
	for i, via := range []uint64{1, 2, 3} {
		if err = m.expandWriteVia(via, fmt.Sprintf("guard-%d", i+1)); err != nil {
			return err
		}
	}
	if err = m.expandRequire("1 all candidate, expanded", false); err != nil {
		return err
	}
	out, code, err := m.contract(1)
	if err != nil {
		return err
	}
	m.say("contract-indexes against voter 1: exit %d: %s", code, out)
	if code != 0 || !strings.Contains(out, "indexes contracted") {
		return m.violate("contract_failed", fmt.Sprintf("exit %d output %q", code, out))
	}
	if err = m.settle("1 contracted"); err != nil {
		return err
	}
	if err = m.expandRequire("1 contracted", true); err != nil {
		return err
	}
	for _, id := range []uint64{1, 2, 3} {
		if reasons, _, status, rerr := m.controlReasons(id); rerr != nil || len(reasons) != 0 {
			return m.violate("reasons_before_rollback", fmt.Sprintf("voter %d: %v (err %v)\n%s", id, reasons, rerr, status))
		}
	}

	// ---- 2. (a) a previous-release learner is refused; a candidate learner is added ----
	learner, err := m.prepareLearner()
	if err != nil {
		return err
	}
	id := learner.ID
	m.c.setBinary(id, m.oldBin)
	m.release[id] = "old"
	if err = m.c.start(id); err != nil {
		return err
	}
	if err = m.peerListening(id, 60*time.Second); err != nil {
		return err
	}
	m.say("2a the learner %s runs the previous release (alive=%t) and listens on %s; `membership add-learner` against every voter", learner.NodeIdentity, m.alive(id), m.c.peer[id])
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
			return m.violate("old_learner_not_refused", fmt.Sprintf("voter %d: err=%v output %q", via, aerr, text))
		case applied != 0:
			return m.violate("old_learner_applied", fmt.Sprintf("voter %d applied the previous-release learner in %d of %d groups: %s", via, applied, groups, text))
		case incompatible > 0 && !strings.Contains(text, "layout_incompatible:"+learner.NodeIdentity):
			return m.violate("refusal_does_not_name_the_member", fmt.Sprintf("voter %d: %s", via, text))
		}
		totalIncompatible += incompatible
	}
	if totalIncompatible == 0 {
		return m.violate("old_learner_not_refused", "no group refused the previous-release learner")
	}
	if !m.alive(id) {
		return m.violate("old_learner_not_running", fmt.Sprintf("the previous-release learner stopped before the check ended (log %q)", lastLines(m.c.logs[id].String(), 6)))
	}
	for _, via := range []uint64{1, 2, 3} {
		_, _, status, serr := m.controlReasons(via)
		if serr != nil || strings.Contains(status, "learner:"+learner.NodeIdentity) {
			return m.violate("old_learner_listed", fmt.Sprintf("voter %d lists the refused learner (err %v):\n%s", via, serr, status))
		}
	}
	m.say("2a refused in %d groups, applied nowhere, listed by no voter", totalIncompatible)
	if err = m.expandRequire("2a after the refusals", true); err != nil {
		return err
	}

	// The learner on the candidate is admitted (a fresh directory, same identity).
	if err = m.c.kill(id); err != nil {
		return err
	}
	if err = os.RemoveAll(m.c.data[id]); err != nil {
		return err
	}
	m.c.setBinary(id, m.newBin)
	m.release[id] = "new"
	if err = m.c.start(id); err != nil {
		return err
	}
	if err = m.peerListening(id, 60*time.Second); err != nil {
		return err
	}
	m.say("2b a learner on the candidate (alive=%t): `membership add-learner` against each voter until every group holds it", m.alive(id))
	deadline := time.Now().Add(240 * time.Second)
	for round := 0; ; round++ {
		via := []uint64{1, 2, 3}[round%3]
		text, aerr := add(via)
		lines := strings.Split(text, "\n")
		m.say("  add-learner (candidate) through voter %d: %s (err=%v)", via, lines[len(lines)-1], aerr)
		if aerr == nil && strings.Contains(text, "not_leader=0 ") {
			break
		}
		if time.Now().After(deadline) {
			return m.violate("candidate_learner_not_added", fmt.Sprintf("last output: %s (err %v; learner log %q)", text, aerr, lastLines(m.c.logs[id].String(), 6)))
		}
		time.Sleep(time.Second)
	}
	if m.sites[id], err = m.c.site(id); err != nil {
		return err
	}
	if err = waitNodeReady(m.sites[id], 240*time.Second); err != nil {
		return m.violate("candidate_learner_not_ready", fmt.Sprintf("%v (log %q)", err, lastLines(m.c.logs[id].String(), 6)))
	}
	m.say("2b the candidate learner is a member and ready")

	// ---- 3. (c) voter 3 is put back on the previous release ----
	back := uint64(3)
	backIdentity := distNodes[back-1].identity
	m.say("3 ROLL voter %d from new to old (after the contraction): SIGTERM, restart on the previous release", back)
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
	for _, via := range []uint64{1, 2} {
		if err = m.waitReasons(via, []string{"layout_incompatible:" + backIdentity}, 90*time.Second); err != nil {
			return err
		}
		if err = waitNodeReady(m.sites[via], 60*time.Second); err != nil {
			return m.violate("new_voter_not_ready", fmt.Sprintf("voter %d with a previous-release voter: %v", via, err))
		}
	}
	// What the previous release does with the state it cannot read, recorded as evidence (not changeable).
	if rerr := waitNodeReady(m.sites[back], 120*time.Second); rerr != nil {
		m.say("  the previous-release voter %d did not become ready on the contracted state: %v (log %q)", back, rerr, lastLines(m.c.logs[back].String(), 6))
	} else if lerr := m.exp.analyst.login(m.sites[back]); lerr != nil {
		m.say("  the previous-release voter %d is ready; the analyst login is refused: %v", back, lerr)
	} else {
		status, intact, detail, rerr := readArtifact(m.sites[back], m.exp.analyst, m.fx, m.exp.writes[0].artifact)
		m.say("  the previous-release voter %d is READY and answers the artifact read of a ledger it cannot read: status %d intact=%t %s (err %v)", back, status, intact, detail, rerr)
		if rerr == nil && status == 200 && intact {
			return m.violate("old_voter_reads_contracted", "the previous release read a contracted ledger: the guard's premise is wrong")
		}
	}
	// Rolled forward again: the reason is gone and nothing was lost.
	m.say("3 ROLL voter %d from old to new", back)
	if err = m.c.terminate(back); err != nil {
		return err
	}
	m.c.setBinary(back, m.newBin)
	m.release[back] = "new"
	if err = m.c.start(back); err != nil {
		return err
	}
	if m.sites[back], err = m.c.site(back); err != nil {
		return err
	}
	if err = waitNodeReady(m.sites[back], 180*time.Second); err != nil {
		return m.violate("roll_forward_not_ready", fmt.Sprintf("voter %d: %v (log %q)", back, err, lastLines(m.c.logs[back].String(), 6)))
	}
	for _, via := range []uint64{1, 2, 3} {
		if err = m.waitReasons(via, nil, 90*time.Second); err != nil {
			return err
		}
	}
	if err = m.settle("3 rolled forward"); err != nil {
		return err
	}
	if err = m.expandRequire("3 rolled forward", true); err != nil {
		return err
	}
	for _, via := range []uint64{1, 2, 3} {
		if err = m.expandReadVia(via, "new_contracted"); err != nil {
			return err
		}
	}
	return nil
}
