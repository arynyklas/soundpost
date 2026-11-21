// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

func init() { register("membership-replace", runMembershipReplace) }

// membershipCLI runs `soundpost membership ...` of the produced binary against one running member's
// data directory and returns its stdout and whether it exited 0.
func (c *dcCluster) membershipCLI(id uint64, args ...string) (string, bool) {
	cmd := exec.Command(c.binary, append([]string{"membership"}, append(args, "--data-dir", c.data[id])...)...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

// membershipUntilDone runs one step on the given members, in turn and repeatedly, until a member
// reports every group done (exit 0). The command acts on the groups its node leads, so the first
// pass makes each node apply its own groups.
func (c *dcCluster) membershipUntilDone(nodes []uint64, limit time.Duration, args ...string) (string, error) {
	deadline := time.Now().Add(limit)
	last := ""
	for time.Now().Before(deadline) {
		for _, id := range nodes {
			out, ok := c.membershipCLI(id, args...)
			last = out
			if ok {
				return out, nil
			}
		}
		time.Sleep(time.Second)
	}
	return last, &dcFailure{Stage: "membership_step", Code: "not_done_within_limit"}
}

// prepareSpare lays out member 4: its addresses, data directory, log and node file (a learner entry
// in the member list, signed by the cluster CA).
func (c *dcCluster) prepareSpare() (replica.Member, error) {
	id := dcSpare.id
	pub, e1 := dcFreeAddress()
	peer, e2 := dcFreeAddress()
	if e1 != nil || e2 != nil {
		return replica.Member{}, errors.Join(e1, e2)
	}
	c.public[id], c.peer[id], c.dial[id] = pub, peer, peer
	c.data[id] = filepath.Join(c.work, "node-"+dcSpare.name)
	c.logs[id] = newDCLog("member-" + dcSpare.name)
	if err := c.env.Approve([]string{c.data[id]}, []string{pub, peer}); err != nil {
		return replica.Member{}, err
	}
	raw, err := os.ReadFile(filepath.Join(c.work, "node-1.json"))
	if err != nil {
		return replica.Member{}, err
	}
	var node appcore.NodeConfig
	if model.StrictJSON(raw, &node) != nil {
		return replica.Member{}, model.Fail(model.Invalid)
	}
	learner := replica.Member{ID: id, Address: "https://" + peer, NodeIdentity: dcSpare.identity, FailureDomain: "process-directory-" + dcSpare.name, Learner: true}
	node.NodeID, node.PeerListen, node.PeerSourceIP = id, peer, ""
	node.Certificate, node.PrivateKey = c.certs[id], c.keys[id]
	node.Members = replica.Members{Revision: node.Members.Revision + 1, Nodes: append(append([]replica.Member(nil), node.Members.Nodes...), learner)}
	out, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return replica.Member{}, err
	}
	return learner, os.WriteFile(filepath.Join(c.work, fmt.Sprintf("node-%d.json", id)), append(out, '\n'), 0o600)
}

// runMembershipReplace drives the operator's replacement of a voter on a REAL three-process cluster
// of the produced binary: `soundpost membership status`, `add-learner` for a fourth node, start that
// node, `replace` of member 3 (stopped, as a lost voter) by member 4, while a write stream keeps
// being acknowledged; then the new voter must serve reads of every acknowledged batch and carry a
// majority with member 1 while member 2 is stopped. Also: a re-add is idempotent, an add that does
// not fit is refused, and a process of another user cannot use the socket.
func runMembershipReplace(env *Env, rep *Report) error {
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
	if err = rep.Require("cluster_bootstrapped_and_ready", true, "three mTLS members ready"); err != nil {
		return err
	}
	learner, err := c.prepareSpare()
	if err != nil {
		return err
	}
	w := newDCWriter(c, rep.Ledger(), 700)
	w.startStream(1, 1500*time.Millisecond, 650, "membership")
	defer func() {
		select {
		case <-w.stop:
		default:
			w.abortStream()
		}
	}()
	acked := func(name string) error {
		if err := w.streamFailed(); err != nil {
			return err
		}
		return rep.Require(name, w.waitAcks(6, time.Now(), 120*time.Second) == nil, "6 batches acknowledged after this step, while the write stream ran")
	}
	if err = acked("acks_before_membership_change"); err != nil {
		return err
	}

	// status
	out, ok := c.membershipCLI(1, "status")
	lines := strings.Count(out, "\n")
	if err = rep.Require("status_lists_every_group_with_three_voters", ok && lines >= 65 && strings.Contains(out, "1:voter:node-a,2:voter:node-b,3:voter:node-c"), fmt.Sprintf("%d groups listed", lines)); err != nil {
		return err
	}
	rep.Fact("groups", lines)

	// socket permissions
	if info, e := os.Stat(filepath.Join(c.data[1], "membership.sock")); e != nil || info.Mode().Perm()&0o077 != 0 {
		return rep.Require("socket_is_private", false, fmt.Sprintf("%v %v", info, e))
	}
	if info, e := os.Stat(c.data[1]); e != nil || info.Mode().Perm()&0o077 != 0 {
		return rep.Require("data_directory_is_private", false, fmt.Sprintf("%v %v", info, e))
	}
	// A process of another user cannot be started here: the drill host user has no sudo and no
	// newuidmap (a user namespace keeps the kernel uid, so it is still the owner). The refusal is
	// shown by the modes above and, per connection, by TestMembershipSocketDropsAPeerThatIsNotTheOwner.
	rep.NotRun("socket refuses a process of another uid", "no second uid is available on the drill host (no sudo, no newuidmap, an unprivileged user namespace keeps the kernel uid); the directory (0700) and socket (0600) modes are asserted above and the SO_PEERCRED gate is covered by cmd/soundpost TestMembershipSocketDropsAPeerThatIsNotTheOwner")

	// negative: an add that does not fit (member 2 is a voter)
	base := []string{"add-learner", "--id", "2", "--address", "https://127.0.0.1:1", "--identity", "node-b", "--failure-domain", "process-directory-b"}
	out, ok = c.membershipCLI(1, base...)
	if err = rep.Require("add_of_an_existing_voter_is_refused", !ok && !strings.HasSuffix(strings.TrimSpace(out), "rejected=0") && strings.Contains(out, "rejected="), "add-learner for member 2 (a voter) exits non-zero with every group rejected"); err != nil {
		return err
	}

	// add the learner to every group
	add := []string{"add-learner", "--id", "4", "--address", learner.Address, "--identity", learner.NodeIdentity, "--failure-domain", learner.FailureDomain}
	if out, err = c.membershipUntilDone([]uint64{1, 2, 3}, 120*time.Second, add...); err != nil {
		return rep.Require("learner_added_to_every_group", false, err.Error())
	}
	if err = rep.Require("learner_added_to_every_group", true, "add-learner exits 0"); err != nil {
		return err
	}
	if out, ok = c.membershipCLI(1, add...); !ok || !strings.Contains(out, "already=") || strings.Contains(out, "already=0 ") {
		return rep.Require("repeated_add_is_idempotent", false, out)
	}
	rep.Require("repeated_add_is_idempotent", true, "the same add-learner again exits 0 with every group already done")
	if err = acked("acks_with_learner_in_configuration"); err != nil {
		return err
	}

	// start member 4 as a learner; it repairs from the leaders
	if err = c.start(dcSpare.id); err != nil {
		return err
	}
	if err = c.waitReady(dcSpare.id, 240*time.Second); err != nil {
		return rep.Require("learner_started_and_ready", false, err.Error())
	}
	if err = rep.Require("learner_started_and_ready", true, "member 4 started from the cluster seed as a learner"); err != nil {
		return err
	}

	// member 3 is lost; replace it by 4
	if _, err = c.kill(3); err != nil {
		return err
	}
	if err = acked("acks_with_member_3_down"); err != nil {
		return err
	}
	if out, err = c.membershipUntilDone([]uint64{1, 2}, 240*time.Second, "replace", "--remove", "3", "--promote", "4"); err != nil {
		return rep.Require("member_3_replaced_by_member_4", false, err.Error()+": "+out)
	}
	out, ok = c.membershipCLI(1, "status")
	if err = rep.Require("member_3_replaced_by_member_4", ok && strings.Contains(out, "4:voter:node-d") && !strings.Contains(out, "3:voter") && !strings.Contains(out, ":learner:"), "replace exits 0; every group lists voters 1, 2, 4 and no member 3"); err != nil {
		return err
	}
	c.retire(3)
	c.mu.Lock()
	c.spare = true
	c.mu.Unlock()
	if err = acked("acks_after_replacement"); err != nil {
		return err
	}

	// member 4 carries a majority: stop member 2, keep acknowledging through 1 and 4
	if _, err = c.kill(2); err != nil {
		return err
	}
	from := time.Now()
	if err = w.streamFailed(); err != nil {
		return err
	}
	if err = rep.Require("acks_through_members_1_and_4_with_member_2_down", w.waitAcks(6, from, 120*time.Second) == nil, "a majority of {1,2,4} without member 2 acknowledges"); err != nil {
		return err
	}
	if err = c.start(2); err != nil {
		return err
	}
	if err = c.waitReady(2, 240*time.Second); err != nil {
		return err
	}
	if err = w.stopStream(); err != nil {
		return err
	}
	retained, err := dcVerifyMembers(c, w, rep, "final", 180*time.Second)
	if err != nil {
		return err
	}
	if err = rep.Reconcile(retained); err != nil {
		return err
	}
	rep.Fact("acknowledged_batches", rep.Ledger().Len())
	return rep.Require("new_voter_serves_every_acknowledged_batch", len(c.members()) == 3, "members 1, 2 and 4 each retain every acknowledged id (dcVerifyMembers read them all back)")
}
