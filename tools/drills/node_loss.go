// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

func init() { register("node-kill-restart", runNodeKillRestart) }

// dcBinaryFacts records which binary the drill ran (its digest, never its content).
func dcBinaryFacts(c *dcCluster, rep *Report) error {
	raw, err := os.ReadFile(c.binary)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	rep.Fact("binary_sha256", hex.EncodeToString(sum[:]))
	rep.Fact("topology", "three local processes of the produced static binary, mTLS between members, one data directory each; NOT three failure domains")
	return nil
}

// runNodeKillRestart SIGKILLs one member of a real three-process cluster while a write stream is
// running, keeps acknowledging through the two survivors, restarts the member, and reconciles every
// acknowledged id against the exact data every member retains. The initial leader (member 1) is
// killed in the first phase and a member that is not the initial leader (member 3) in the second.
func runNodeKillRestart(env *Env, rep *Report) error {
	c, err := newDCCluster(env)
	if err != nil {
		return err
	}
	defer c.close()
	if err = dcBinaryFacts(c, rep); err != nil {
		return err
	}
	if err = c.bootstrapAndStart(); err != nil {
		return rep.Require("cluster_bootstrapped_and_ready", false, err.Error())
	}
	if err = rep.Require("cluster_bootstrapped_and_ready", true, "single installation bootstrapped, seed exported, three mTLS members ready"); err != nil {
		return err
	}
	if err = dcRecordCursors(c, rep, "baseline"); err != nil {
		return err
	}
	w := newDCWriter(c, rep.Ledger(), 700)
	phases := []struct {
		name   string
		victim uint64
	}{{"kill_initial_leader_member_1", 1}, {"kill_member_3", 3}}
	for _, ph := range phases {
		victim := ph.victim
		spec := dcFaultSpec{
			Phase: ph.name, Kind: "sigkill", Victim: victim,
			Inject: func() error {
				signal, err := c.kill(victim)
				if err != nil {
					return err
				}
				rep.Fact(fmt.Sprintf("%s/exit_signal", ph.name), signal)
				if signal != "killed" {
					return fmt.Errorf("member %d ended by %q, not by SIGKILL", victim, signal)
				}
				return nil
			},
			Restore: func() error { return c.start(victim) },
		}
		if err = dcRunStreamFault(c, w, rep, spec); err != nil {
			return err
		}
	}
	retained, err := dcVerifyMembers(c, w, rep, "final", 120*time.Second)
	if err != nil {
		return err
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	if err = dcRecordCursors(c, rep, "final"); err != nil {
		return err
	}
	events := rep.Timeline().Events()
	terr := VerifyTimeline(events, 2*len(phases))
	detail := fmt.Sprintf("%d events, %d failed attempts kept, final state %s", len(events), FailedAttempts(events), rep.Timeline().State())
	if terr != nil {
		detail = terr.Error()
	}
	if err = rep.Require("outage_timeline_verifies", terr == nil && rep.Timeline().State() == StateRecovered, detail); err != nil {
		return err
	}
	attempts := map[string]int{}
	for _, a := range rep.Ledger().Attempts() {
		attempts[a.Outcome]++
	}
	rep.Fact("failed_attempts_by_outcome", attempts)
	rep.Fact("acknowledged_batches", rep.Ledger().Len())
	return nil
}
