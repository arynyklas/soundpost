// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A write that reaches a member while the group has no quorum (real binaries, voters 1 and 2 on the candidate, voter 3
// on the previous release). Two of the three voters are killed, so the one that survives either leads a group
// that cannot commit or forwards to a leader that is gone. The write is sent through the previous-release voter
// in one window and through a candidate follower in another:
//
//	the client is answered 503 (the previous release answers its own unavailable the same way) and never a 2xx;
//	after the voters restart, the write is committed once or not at all: a retry with the SAME command id answers
//	2xx and moves the control revision by the same single step in both windows, and a second retry moves it by none.
//
// Wire notes (by reading the previous release's forward.go, 5475ef6): a candidate leader that cannot reach its
// freshness fence answers a forwarded proposal with the code `timeout`, which the previous release's forwardedError
// maps to ErrUnavailable (503); the previous release's leader answers unavailable, which the candidate maps to a
// retryable no-leader gap; neither side ever treats a code it does not know as a commit.
//
// Environment: as TestMixedBinaryPostContractGuard.
func TestMixedBinaryForwardedProposalWithoutQuorum(t *testing.T) {
	m := newFreshMixedRun(t, "no-quorum-forward")
	m.finishFresh(m.runNoQuorumForward())
}

// holdNoRetry is one hold placement through voter id that is neither repeated on `stale` nor on any other answer.
func (m *mixedRun) holdNoRetry(id uint64, csrf string, commandID model.ID, view model.Revision) (int, string, error) {
	status, raw, err := m.sites[id].post("/api/v1/admin/holds", map[string]any{"command_id": commandID.String(), "expected_revision": strconv.FormatUint(uint64(view), 10),
		"org_id": m.fx.org.String(), "project_ids": []string{m.fx.project.String()}, "reason": "mixed-binary no quorum"}, csrf, "")
	return status, trunc(string(raw), 200), err
}

func (m *mixedRun) runNoQuorumForward() error {
	cleanup, err := m.startGroup(func(id uint64) string {
		if id == 3 {
			return "old"
		}
		return "new"
	})
	defer cleanup()
	if err != nil {
		return err
	}
	deltas := map[string]uint64{}
	for _, w := range []struct {
		name     string
		survivor func(leader uint64) uint64
		allowed  []int
	}{
		{"previous-release voter", func(uint64) uint64 { return 3 }, []int{503, 504, 409}}, // 409 stale: its documented "nothing committed, repeat" fault
		{"candidate follower", func(leader uint64) uint64 {
			if leader == 1 {
				return 2
			}
			return 1
		}, []int{503}},
	} {
		lead, err := leadership(m.sites, []uint64{1, 2, 3}, 60*time.Second)
		if err != nil {
			return err
		}
		survivor := w.survivor(lead.leader)
		s, err := m.login(survivor)
		if err != nil {
			return err
		}
		base, err := m.settledView("before the " + w.name + " window")
		if err != nil {
			return err
		}
		m.say("window %s: voter %d (%s) survives, leader was %d (forwarded=%t)", w.name, survivor, m.release[survivor], lead.leader, lead.leader != survivor)
		var killed []uint64
		for _, id := range m.others(survivor) {
			if err = m.c.kill(id); err != nil {
				return err
			}
			killed = append(killed, id)
		}
		cmd := model.NewID()
		status, body, err := m.holdNoRetry(survivor, s.CSRF, cmd, base)
		m.say("  hold through voter %d without quorum answered %d %s (err %v)", survivor, status, body, err)
		if err == nil {
			ok := false
			for _, want := range w.allowed {
				ok = ok || status == want
			}
			if !ok {
				return m.violate("no_quorum_answer", fmt.Sprintf("%s: answered %d %s, want one of %v and never a 2xx", w.name, status, body, w.allowed))
			}
		} // a transport timeout is no acknowledgement either
		if err = m.c.start(killed...); err != nil {
			return err
		}
		for _, id := range killed {
			if m.sites[id], err = m.c.site(id); err != nil {
				return err
			}
		}
		for _, id := range []uint64{1, 2, 3} {
			if err = waitNodeReady(m.sites[id], 180*time.Second); err != nil {
				return m.violate("restart_not_ready", fmt.Sprintf("voter %d: %v", id, err))
			}
		}
		if _, err = leadership(m.sites, []uint64{1, 2, 3}, 90*time.Second); err != nil {
			return err
		}
		var first, second struct {
			HoldID model.ID `json:"hold_id"`
		}
		for i, receipt := range []*struct {
			HoldID model.ID `json:"hold_id"`
		}{&first, &second} {
			view, err := m.settledView(fmt.Sprintf("%s window, before retry %d", w.name, i+1))
			if err != nil {
				return err
			}
			var st int
			var raw string
			for range 40 { // an election after the restart may still answer 503
				if st, raw, err = m.holdNoRetry(survivor, s.CSRF, cmd, view); err != nil || st != 503 && st != 400 && st != 409 && st != 504 {
					break
				}
				time.Sleep(500 * time.Millisecond)
			}
			m.say("  retry %d with the same command id answered %d %s (err %v)", i+1, st, raw, err)
			if err != nil {
				return err
			}
			if st < 200 || st > 299 {
				return m.violate("retry_not_acknowledged", fmt.Sprintf("%s: retry %d answered %d %s", w.name, i+1, st, raw))
			}
			if err = json.Unmarshal([]byte(raw), receipt); err != nil {
				return err
			}
			after, err := m.settledView(fmt.Sprintf("%s window, after retry %d", w.name, i+1))
			if err != nil {
				return err
			}
			if i == 0 {
				deltas[w.name] = uint64(after) - uint64(base)
			} else if uint64(after)-uint64(base) != deltas[w.name] {
				return m.violate("retry_committed_again", fmt.Sprintf("%s: revision %d after the first retry, %d after the second (base %d)", w.name, uint64(base)+deltas[w.name], after, base))
			}
		}
		if first.HoldID != second.HoldID {
			return m.violate("two_records", fmt.Sprintf("%s: retries named holds %s and %s", w.name, first.HoldID, second.HoldID))
		}
	}
	if deltas["previous-release voter"] != deltas["candidate follower"] || deltas["candidate follower"] == 0 {
		return m.violate("not_exactly_one_record", fmt.Sprintf("revision steps per write differ between windows: %v", deltas))
	}
	return nil
}
