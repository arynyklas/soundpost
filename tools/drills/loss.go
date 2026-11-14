// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The four node_loss drills that need more than a signal: a link-level partition, a power cut, a
// failing fsync and a vanishing disk. All run the produced static binary as three real processes.
// Nothing here changes the host: the partition is the drill's own loopback proxy (proxy.go), the
// storage faults are an unprivileged seccomp user-notification filter (faultfs_linux_amd64.go).

func init() {
	register("network-partition", runNetworkPartition)
	register("power-loss", runPowerLoss)
	register("fsync-failure", runFsyncFailure)
	register("disk-disappearance", runDiskDisappearance)
}

const (
	dcPartitionScope = "partition = every link of one member to the other two is cut in both directions while all three processes keep running and clients can still reach the isolated member; the cut is the drill's own loopback TCP proxy (drop = packets vanish and connections hang, reset = connections are reset and refused), not iptables/tc/network namespaces, so it models link failure between members but not a switch, routing or asymmetric-path failure"
	dcPowerScope     = "power loss = the member's whole process group is SIGKILLed, then every byte and directory entry the member had not fsynced (as observed through the member's own fsync/rename system calls) is rolled back on disk; with torn the first half of the unsynced file tail survives. It does not model reordered writes inside the disk write cache, torn sectors or a real power cut; the kernel page cache is not dropped, the unsynced loss is applied by the drill"
	dcFsyncScope     = "fsync failure = every fsync/fdatasync of the member on its data directory answers EIO from the unprivileged injector while the member runs; the real kernel and filesystem are untouched"
	dcDiskScope      = "disk disappearance = the member's data directory is moved away under the running process and every fsync and path operation on it answers EIO (a pulled disk); the member's page-cache writes to already open files still succeed, as they do on a vanished block device until writeback fails"
)

// dcStartInjected boots the cluster for one of the four drills and returns the writer.
func dcStartInjected(env *Env, rep *Report, opts dcOptions, scope string) (*dcCluster, *dcWriter, error) {
	c, err := newDCClusterWith(env, opts)
	if err != nil {
		return nil, nil, err
	}
	if err = dcBinaryFacts(c, rep); err != nil {
		c.close()
		return nil, nil, err
	}
	rep.Fact("fault_scope", scope)
	if err = c.bootstrapAndStart(); err != nil {
		c.close()
		return nil, nil, rep.Require("cluster_bootstrapped_and_ready", false, err.Error())
	}
	if err = rep.Require("cluster_bootstrapped_and_ready", true, "single installation bootstrapped, seed exported, three mTLS members ready"); err != nil {
		c.close()
		return nil, nil, err
	}
	if err = dcRecordCursors(c, rep, "baseline"); err != nil {
		c.close()
		return nil, nil, err
	}
	return c, newDCWriter(c, rep.Ledger(), 900), nil
}

// dcFinish is the common end of a drill: every member reconciled once more, cursors converged and
// the outage timeline verified.
func dcFinish(c *dcCluster, w *dcWriter, rep *Report, phases int) error {
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
	terr := VerifyTimeline(events, 2*phases)
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

// stop SIGKILLs the whole process group of one member (a member that already exited on its own is
// fine) and waits for it to be reaped. The member is marked down first.
func (c *dcCluster) stop(id uint64) (string, error) {
	c.mu.Lock()
	p := c.procs[id]
	c.down[id] = true
	c.mu.Unlock()
	if p == nil {
		return "not_running", nil
	}
	_ = p.cmd.Process.Signal(dcSigCont)
	if err := dcKillGroup(p.cmd); err != nil {
		return "", err
	}
	select {
	case <-p.done:
	case <-time.After(30 * time.Second):
		return "", &dcFailure{Stage: "stop", Code: "process_did_not_exit"}
	}
	c.mu.Lock()
	delete(c.procs, id)
	c.mu.Unlock()
	if ws, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
		if ws.Signaled() {
			return ws.Signal().String(), nil
		}
		return fmt.Sprintf("exit_%d", ws.ExitStatus()), nil
	}
	return "unknown", nil
}

// exited reports how a member that is not meant to be dead is doing: "running", or how it ended.
func (c *dcCluster) exited(id uint64) string {
	c.mu.Lock()
	p := c.procs[id]
	c.mu.Unlock()
	if p == nil {
		return "not_started"
	}
	select {
	case <-p.done:
		if ws, ok := p.cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return "died_" + ws.Signal().String()
			}
			return fmt.Sprintf("exited_%d", ws.ExitStatus())
		}
		return "exited"
	default:
		return "running"
	}
}

// powerCut cuts the power of the given members at the same instant: every process group is killed
// before any is waited for, then each disk loses what it had not fsynced.
func (c *dcCluster) powerCut(rep *Report, phase string, ids []uint64, torn bool) error {
	// The cut lands INSIDE an fsync: every fsync of every victim is held, so the bytes each member
	// already wrote but had not yet synced (and so had not acknowledged) stay unsynced.
	held := map[uint64]bool{}
	for _, id := range ids {
		c.disks[id].armHold()
	}
	for _, id := range ids {
		held[id] = c.disks[id].waitHeld(10 * time.Second)
		rep.Fact(fmt.Sprintf("%s/member_%d/cut_inside_an_fsync", phase, id), held[id])
	}
	time.Sleep(50 * time.Millisecond)
	c.mu.Lock()
	var kills []*dcProc
	for _, id := range ids {
		c.down[id] = true
		if p := c.procs[id]; p != nil {
			_ = p.cmd.Process.Signal(dcSigCont)
			_ = dcKillGroup(p.cmd)
			kills = append(kills, p)
		}
	}
	c.mu.Unlock()
	for _, p := range kills {
		select {
		case <-p.done:
		case <-time.After(30 * time.Second):
			return &dcFailure{Stage: "power_cut", Code: "process_did_not_exit"}
		}
	}
	c.mu.Lock()
	for _, id := range ids {
		delete(c.procs, id)
	}
	c.mu.Unlock()
	for _, id := range ids {
		d := c.disks[id]
		d.stop()
		syncs := d.Stats()
		cut, err := d.PowerCut(torn)
		if err != nil {
			return err
		}
		rep.Fact(fmt.Sprintf("%s/member_%d/synced_calls_observed", phase, id), syncs.Syncs)
		rep.Fact(fmt.Sprintf("%s/member_%d/dir_syncs_observed", phase, id), syncs.DirSyncs)
		rep.Fact(fmt.Sprintf("%s/member_%d/renames_observed", phase, id), syncs.Renames)
		rep.Fact(fmt.Sprintf("%s/member_%d/unsynced_loss", phase, id), cut)
		if err = rep.Require(fmt.Sprintf("%s_member_%d_injector_saw_durability_calls", phase, id), syncs.Syncs > 0, fmt.Sprintf("%d fsync/fdatasync calls of the member were observed, so the unsynced-loss ledger is live", syncs.Syncs)); err != nil {
			return err
		}
	}
	return nil
}

// dcProbeVictim sends n fresh batches straight to the victim while its fault is active. With strict
// no acknowledgement is allowed (it cannot reach a quorum); otherwise an acknowledgement is
// recorded in the ledger and must survive the final reconciliation. Every batch that was not
// acknowledged is retried unchanged through the other members until acknowledged; when degraded
// the other members may be unable to acknowledge (see dcFaultSpec.Degraded) and such a batch is
// returned instead, for the caller to retry after the restore.
func dcProbeVictim(c *dcCluster, w *dcWriter, rep *Report, phase string, victim uint64, n int, strict, degraded bool) ([]model.Batch, error) {
	others := func() []uint64 {
		var out []uint64
		for _, m := range c.live() {
			if m != victim {
				out = append(out, m)
			}
		}
		return out
	}
	limit := 120 * time.Second
	if degraded {
		limit = 10 * time.Second
	}
	var pending []model.Batch
	acked, refused := 0, 0
	for range n {
		b, err := w.next()
		if err != nil {
			return nil, err
		}
		verdict, detail, err := w.attempt(victim, b, 5*time.Second, phase+"_victim_probe")
		if err != nil {
			return nil, err
		}
		if verdict == dcAcked {
			acked++
			if strict {
				return nil, fmt.Errorf("the isolated member %d acknowledged batch %s (%s) without a quorum", victim, b.ID, detail)
			}
			continue
		}
		refused++
		if _, err = w.deliver(b, others, limit, phase+"_victim_probe_retry"); err != nil {
			if !degraded {
				return nil, fmt.Errorf("%w; cluster at the failure: %s", err, c.diagnose())
			}
			pending = append(pending, b)
		}
	}
	rep.Fact(phase+"/victim_probe_acknowledged", acked)
	rep.Fact(phase+"/victim_probe_refused", refused)
	rep.Fact(phase+"/victim_probe_retried_after_restore", len(pending))
	return pending, nil
}

// retryPending retries unchanged, until acknowledged, the batches a degraded phase could not get
// acknowledged while its fault lasted.
func retryPending(c *dcCluster, w *dcWriter, phase string, pending []model.Batch) error {
	for _, b := range pending {
		if _, err := w.deliver(b, c.live, 150*time.Second, phase+"_pending_after_restore"); err != nil {
			return fmt.Errorf("%w; cluster at the failure: %s", err, c.diagnose())
		}
	}
	return nil
}

// diagnose summarises what every member says about itself (process state, /readyz), for the
// detail of a failed check.
func (c *dcCluster) diagnose() string {
	var out []string
	for _, n := range dcMembers {
		code, st, err := c.readiness(n.id, 3*time.Second)
		out = append(out, fmt.Sprintf("member %d %s readyz=%d ready=%v reason=%q err=%v", n.id, c.exited(n.id), code, st.Ready, st.Reason, err))
	}
	if hold := os.Getenv("SOUNDPOST_DRILL_HOLD_ON_FAILURE"); hold != "" {
		// Debugging aid for a drill developer: keep the failed cluster up so it can be inspected.
		if d, err := time.ParseDuration(hold); err == nil {
			c.env.Logf("holding the failed cluster for %s: work=%s public=%v peer=%v", d, c.work, c.public, c.peer)
			time.Sleep(d)
		}
	}
	return strings.Join(out, "; ")
}

// ---- network-partition ----

// runNetworkPartition isolates ONE member from the other two with both sides alive: the initial
// leader (member 1) with dropped packets, member 3 with reset links. The isolated member stays
// reachable by clients and must never acknowledge; the majority keeps acknowledging; after the
// heal every acknowledged id is on every member and no member diverged.
func runNetworkPartition(env *Env, rep *Report) error {
	c, w, err := dcStartInjected(env, rep, dcOptions{proxy: true}, dcPartitionScope)
	if err != nil {
		return err
	}
	defer c.close()
	phases := []struct {
		name   string
		victim uint64
		mode   dcCut
	}{{"partition_drop_initial_leader_member_1", 1, dcLinkDrop}, {"partition_reset_member_3", 3, dcLinkReset}}
	for _, ph := range phases {
		victim, mode := ph.victim, ph.mode
		spec := dcFaultSpec{
			Phase: ph.name, Kind: "partition_" + mode.String(), Victim: victim,
			Inject: func() error {
				c.link.isolate(victim, mode)
				for _, id := range []uint64{1, 2, 3} {
					if id != victim && c.link.mode(victim, id) != mode {
						return fmt.Errorf("link %d->%d is not %s", victim, id, mode)
					}
				}
				return nil
			},
			During: func() error {
				// The victim is alive: its process must still be running and reachable by clients.
				if st := c.exited(victim); st != "running" {
					return fmt.Errorf("the isolated member is not running: %s", st)
				}
				if _, err := dcProbeVictim(c, w, rep, ph.name, victim, 4, true, false); err != nil {
					return err
				}
				rep.Fact(ph.name+"/isolated_member_process", c.exited(victim))
				return nil
			},
			Restore: func() error { c.link.heal(); return nil },
		}
		if err = dcRunStreamFault(c, w, rep, spec); err != nil {
			return err
		}
	}
	rep.Fact("link_counters", c.link.Counters())
	if err = rep.Require("partition_was_exercised", c.link.Counters().Dropped+c.link.Counters().Resets+c.link.Counters().Refused > 0, fmt.Sprintf("%+v", c.link.Counters())); err != nil {
		return err
	}
	return dcFinish(c, w, rep, len(phases))
}

// ---- power-loss ----

// runPowerLoss cuts the power of one member (the initial leader, then member 3 with a torn tail)
// while the write stream runs, and finally of ALL members at once. Every acknowledged id must
// survive on every member after the restarts.
func runPowerLoss(env *Env, rep *Report) error {
	c, w, err := dcStartInjected(env, rep, dcOptions{inject: true}, dcPowerScope)
	if err != nil {
		return err
	}
	defer c.close()
	singles := []struct {
		name   string
		victim uint64
		torn   bool
	}{{"power_cut_initial_leader_member_1", 1, false}, {"power_cut_member_3_torn_tail", 3, true}}
	for _, ph := range singles {
		victim, torn := ph.victim, ph.torn
		spec := dcFaultSpec{
			Phase: ph.name, Kind: "power_cut", Victim: victim,
			Inject:  func() error { return c.powerCut(rep, ph.name, []uint64{victim}, torn) },
			Restore: func() error { return c.start(victim) },
		}
		if err = dcRunStreamFault(c, w, rep, spec); err != nil {
			return err
		}
	}
	if err = dcPowerCutAll(c, w, rep); err != nil {
		return err
	}
	return dcFinish(c, w, rep, len(singles)+1)
}

// dcPowerCutAll is the whole-cluster power cut: no member survives to keep acknowledging, so every
// batch acknowledged before the cut has to come back from the rolled-back disks alone, and the
// batches that were in flight are retried unchanged after the restart.
func dcPowerCutAll(c *dcCluster, w *dcWriter, rep *Report) error {
	const p = "power_cut_all_members_torn_tail"
	all := []uint64{1, 2, 3}
	w.startStream(4, 60*time.Millisecond, 120, p)
	stopped := false
	defer func() {
		if !stopped {
			w.abortStream()
		}
	}()
	if err := w.waitAcks(10, time.Time{}, 120*time.Second); err != nil {
		return rep.Require(p+"_stream_acks_before_cut", false, err.Error())
	}
	before := len(w.Times())
	rep.Fact(p+"/acks_before_cut", before)
	rep.Timeline().Fail("cluster", "power cut of all three members while the write stream was running")
	if err := c.powerCut(rep, p, all, true); err != nil {
		return rep.Require(p+"_power_cut", false, err.Error())
	}
	cutAt := time.Now()
	// Nothing can acknowledge while every member is down: a probe to each must not be acknowledged.
	probe, err := w.next()
	if err != nil {
		return err
	}
	for _, id := range all {
		verdict, detail, aerr := w.attempt(id, probe, 2*time.Second, p+"_probe")
		if aerr != nil {
			return aerr
		}
		if err = rep.Require(fmt.Sprintf("%s_member_%d_down_does_not_acknowledge", p, id), verdict != dcAcked, string(verdict)+" "+detail); err != nil {
			return err
		}
	}
	rep.Timeline().Fail("cluster", "probe writes to all three down members were not acknowledged")
	for _, id := range all {
		if err = c.start(id); err != nil {
			return rep.Require(p+"_restart", false, err.Error())
		}
	}
	for _, id := range all {
		if err = c.waitReady(id, 240*time.Second); err != nil {
			return rep.Require(p+"_ready_after_restart", false, fmt.Sprintf("member %d: %v", id, err))
		}
	}
	readyAt := time.Now()
	rep.Fact(p+"/ready_after_cut_ms", readyAt.Sub(cutAt).Milliseconds())
	if _, err = w.deliver(probe, c.live, 120*time.Second, p+"_probe"); err != nil {
		return rep.Require(p+"_refused_probe_retried_unchanged_to_ack", false, err.Error())
	}
	if err = w.waitAcks(6, readyAt, 180*time.Second); err != nil {
		return rep.Require(p+"_acks_after_restart", false, err.Error())
	}
	stopped = true
	if err = w.stopStream(); err != nil {
		return rep.Require(p+"_stream_ended_cleanly", false, err.Error())
	}
	rep.Timeline().Deliver("cluster", "the refused probe batch and the interrupted stream were retried unchanged and acknowledged after the restart")
	if err = rep.Timeline().Recover("cluster"); err != nil {
		return rep.Require(p+"_outage_recovered", false, err.Error())
	}
	if err = dcRecordCursors(c, rep, p); err != nil {
		return err
	}
	if err = dcCheckRetries(w, rep, p, "after every member lost its unsynced data", probe.ID.String()); err != nil {
		return err
	}
	if _, err = dcVerifyMembers(c, w, rep, p, 180*time.Second); err != nil {
		return err
	}
	rerr := dcVerifyRetries(w.Sent(), rep.Ledger().Acks())
	detail := fmt.Sprintf("%d attempts, %d failed attempts, every refused batch was retried with an identical body to an acknowledgement", len(w.Sent()), len(rep.Ledger().Attempts()))
	if rerr != nil {
		detail = rerr.Error()
	}
	return rep.Require(p+"_refused_attempts_retried_unchanged", rerr == nil, detail)
}

// ---- fsync-failure ----

// runFsyncFailure makes every fsync of one member fail with EIO while writes stream (the initial
// leader, then member 3). A member whose disk will not take a sync must not acknowledge on its own
// say: any acknowledgement through it must still be durable on a quorum (the final reconciliation
// reads every id back from every member). The member is then restarted on its disk (its failed
// sync state is never trusted) and has to rejoin.
func runFsyncFailure(env *Env, rep *Report) error {
	c, w, err := dcStartInjected(env, rep, dcOptions{inject: true}, dcFsyncScope)
	if err != nil {
		return err
	}
	defer c.close()
	// The initial leader leads groups; a leader whose fsync fails stays up and keeps leading the groups
	// that have not tried to write yet, so the survivors are not required to acknowledge in that phase
	// (Degraded: see the report's findings). A follower must not stop the majority.
	phases := []struct {
		name     string
		victim   uint64
		degraded bool
	}{{"fsync_fails_initial_leader_member_1", 1, true}, {"fsync_fails_member_3", 3, false}}
	for _, ph := range phases {
		victim := ph.victim
		disk := c.disks[victim]
		failedBefore := disk.Stats().SyncsFailed
		var pending []model.Batch
		spec := dcFaultSpec{
			Phase: ph.name, Kind: "fsync_eio", Victim: victim, Degraded: ph.degraded,
			Inject: func() error { disk.setFailSync(true); return nil },
			During: func() error {
				var err error
				if pending, err = dcProbeVictim(c, w, rep, ph.name, victim, 4, false, ph.degraded); err != nil {
					return err
				}
				failed := disk.Stats().SyncsFailed - failedBefore
				rep.Fact(ph.name+"/fsync_calls_failed_with_eio", failed)
				rep.Fact(ph.name+"/victim_process_after_failed_fsync", c.exited(victim))
				return rep.Require(ph.name+"_failing_fsync_was_exercised", failed > 0, fmt.Sprintf("%d fsync calls of member %d answered EIO", failed, victim))
			},
			Restore: func() error {
				if _, err := c.stop(victim); err != nil {
					return err
				}
				disk.setFailSync(false)
				if err := c.start(victim); err != nil {
					return err
				}
				return retryPending(c, w, ph.name, pending)
			},
		}
		if err = dcRunStreamFault(c, w, rep, spec); err != nil {
			return err
		}
	}
	return dcFinish(c, w, rep, len(phases))
}

// ---- disk-disappearance ----

// runDiskDisappearance makes one member's data directory vanish under the running process (the
// initial leader, then member 3) and finally replaces a member's disk with an empty one. The other
// two members keep their own disks and the acknowledgements. Restoring is putting the same disk back.
func runDiskDisappearance(env *Env, rep *Report) error {
	c, w, err := dcStartInjected(env, rep, dcOptions{inject: true}, dcDiskScope)
	if err != nil {
		return err
	}
	defer c.close()
	phases := []struct {
		name     string
		victim   uint64
		replace  bool
		degraded bool
	}{{"disk_gone_initial_leader_member_1", 1, false, true}, {"disk_gone_member_3", 3, false, false}, {"disk_replaced_by_empty_disk_member_2", 2, true, false}}
	for _, ph := range phases {
		victim := ph.victim
		disk := c.disks[victim]
		away := filepath.Join(c.work, fmt.Sprintf("disk-%d-away", victim))
		before := disk.Stats()
		var pending []model.Batch
		spec := dcFaultSpec{
			Phase: ph.name, Kind: "disk_gone", Victim: victim, Degraded: ph.degraded,
			Inject: func() error { return disk.detach(away) },
			During: func() error {
				var err error
				if pending, err = dcProbeVictim(c, w, rep, ph.name, victim, 4, false, ph.degraded); err != nil {
					return err
				}
				after := disk.Stats()
				denied := after.SyncsOnGone - before.SyncsOnGone + after.PathOpsDenied - before.PathOpsDenied
				rep.Fact(ph.name+"/io_calls_answered_eio", denied)
				rep.Fact(ph.name+"/victim_process_after_disk_loss", c.exited(victim))
				if err := rep.Require(ph.name+"_vanished_disk_was_exercised", denied > 0, fmt.Sprintf("%d fsync/path calls of member %d on the vanished disk answered EIO", denied, victim)); err != nil {
					return err
				}
				if !ph.replace {
					return nil
				}
				// The operator puts a blank disk where the data was: the member must not turn a blank
				// directory into acknowledgements that lose data. Every acknowledgement through it is
				// recorded and verified by the reconciliation of every member.
				if _, err := c.stop(victim); err != nil {
					return err
				}
				if err := disk.reattachBlank(away); err != nil {
					return err
				}
				if err := c.start(victim); err != nil {
					return err
				}
				time.Sleep(10 * time.Second)
				rep.Fact(ph.name+"/member_on_blank_disk", c.exited(victim))
				if c.exited(victim) == "running" {
					if _, err := dcProbeVictim(c, w, rep, ph.name+"_blank", victim, 3, false, false); err != nil {
						return err
					}
				}
				if _, err := c.stop(victim); err != nil {
					return err
				}
				return disk.discardBlank(away)
			},
			Restore: func() error {
				if _, err := c.stop(victim); err != nil {
					return err
				}
				if err := disk.reattachOriginal(away); err != nil {
					return err
				}
				if err := c.start(victim); err != nil {
					return err
				}
				return retryPending(c, w, ph.name, pending)
			},
		}
		if err = dcRunStreamFault(c, w, rep, spec); err != nil {
			return err
		}
	}
	return dcFinish(c, w, rep, len(phases))
}
