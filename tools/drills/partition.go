// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"strings"
	"time"
)

func init() {
	register("minority-pause", runMinorityPause)
	register("majority-pause", runMajorityPause)
}

const dcPauseNotPartition = "SIGSTOP freezes a whole process: its sockets stay open and its peers' connections stall instead of being cut, nothing is lost or reordered on a link, and the member cannot run while isolated (no stale leader acting on its own side, no divergent writes on both sides). It proves behaviour under an unresponsive member, not link-level partition behaviour; that needs CAP_NET_ADMIN (network-partition is declared not_run)."

// dcAckedAfter reports whether the batch id was acknowledged after t (an acknowledgement that
// completed before t cannot be the acknowledgement of a retry made after t).
func dcAckedAfter(times []dcAckTime, id string, t time.Time) bool {
	for _, a := range times {
		if a.ID == id && a.At.After(t) {
			return true
		}
	}
	return false
}

// dcLedgerHas reports whether the ledger holds an acknowledgement for id.
func dcLedgerHas(acks []Ack, id string) bool {
	for _, a := range acks {
		if a.ID == id {
			return true
		}
	}
	return false
}

// runMinorityPause SIGSTOPs ONE member (alive but unresponsive: a minority is unreachable) while a
// write stream is running, keeps acknowledging through the majority, SIGCONTs the member, waits for
// convergence and reconciles every acknowledged id on every member. The initial leader (member 1)
// is paused in the first phase and member 3 in the second.
func runMinorityPause(env *Env, rep *Report) error {
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
	rep.NotRun("link-level partition with both sides live", dcPauseNotPartition)
	if err = dcRecordCursors(c, rep, "baseline"); err != nil {
		return err
	}
	w := newDCWriter(c, rep.Ledger(), 700)
	phases := []struct {
		name   string
		victim uint64
	}{{"pause_initial_leader_member_1", 1}, {"pause_member_3", 3}}
	for _, ph := range phases {
		victim := ph.victim
		spec := dcFaultSpec{
			Phase: ph.name, Kind: "sigstop", Victim: victim,
			Inject:  func() error { return c.pause(victim) },
			Restore: func() error { return c.resume(victim) },
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

// runMajorityPause SIGSTOPs TWO members; the lone survivor has no quorum. It must refuse a write
// with the typed retryable 503 (never 200), the refused batch must not be in the ledger as
// acknowledged, /readyz must be unready with a closed reason and a read must not be served as
// complete. After SIGCONT the IDENTICAL batch is retried, must be acknowledged, and every
// acknowledged id is reconciled on every member. Survivor member 1 (initial leader) and survivor
// member 2 (not the initial leader) are exercised in turn.
func runMajorityPause(env *Env, rep *Report) error {
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
	rep.NotRun("link-level partition with both sides live", dcPauseNotPartition)
	w := newDCWriter(c, rep.Ledger(), 200)
	for i := range 6 {
		b, err := w.next()
		if err != nil {
			return err
		}
		if _, err = w.deliver(b, w.rotate(i), 90*time.Second, "baseline"); err != nil {
			return rep.Require("baseline_writes_acknowledged", false, err.Error())
		}
	}
	if err = rep.Require("baseline_writes_acknowledged", true, "6 batches acknowledged through all three members"); err != nil {
		return err
	}
	if err = dcRecordCursors(c, rep, "baseline"); err != nil {
		return err
	}
	for _, ph := range []struct {
		survivor uint64
		paused   []uint64
	}{{1, []uint64{2, 3}}, {2, []uint64{1, 3}}} {
		if err = dcMajorityPhase(c, w, rep, ph.survivor, ph.paused); err != nil {
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
	terr := VerifyTimeline(events, 2)
	detail := fmt.Sprintf("%d events, %d failed attempts kept, final state %s", len(events), FailedAttempts(events), rep.Timeline().State())
	if terr != nil {
		detail = terr.Error()
	}
	if err = rep.Require("outage_timeline_verifies", terr == nil && rep.Timeline().State() == StateRecovered, detail); err != nil {
		return err
	}
	rep.Fact("acknowledged_batches", rep.Ledger().Len())
	return nil
}

// dcMajorityPhase is one majority-loss phase with `survivor` as the only responsive member.
func dcMajorityPhase(c *dcCluster, w *dcWriter, rep *Report, survivor uint64, paused []uint64) error {
	p := fmt.Sprintf("majority_pause_survivor_%d", survivor)
	subject := fmt.Sprintf("survivor_%d", survivor)
	rep.Fact(p+"/survivor_member", survivor)
	rep.Fact(p+"/paused_members", paused)
	// A reader session opened while the quorum exists, so the read attempt below reaches the
	// member's read path instead of failing at login.
	if _, err := c.login(survivor); err != nil {
		return rep.Require(p+"_reader_session_before_pause", false, err.Error())
	}
	for _, id := range paused {
		if err := c.pause(id); err != nil {
			return rep.Require(p+"_members_paused", false, err.Error())
		}
	}
	rep.Timeline().Fail(subject, fmt.Sprintf("members %v SIGSTOPped: the survivor has no quorum", paused))

	c.env.Logf("%s: members %v SIGSTOPped; sending a write to the survivor", p, paused)
	x, err := w.next()
	if err != nil {
		return err
	}
	acksBefore := rep.Ledger().Len()
	var refusals []string
	for i := 1; i <= 2; i++ {
		t0 := time.Now()
		verdict, detail, aerr := w.attempt(survivor, x, 60*time.Second, p+"_refused")
		if aerr != nil {
			return aerr
		}
		took := time.Since(t0)
		if err = rep.Require(fmt.Sprintf("%s_refusal_%d_is_typed_503", p, i), verdict == dcTypedRefusal, fmt.Sprintf("%s after %dms: %s", string(verdict), took.Milliseconds(), detail)); err != nil {
			return err
		}
		refusals = append(refusals, detail)
		rep.Fact(fmt.Sprintf("%s/refusal_%d_ms", p, i), took.Milliseconds())
		rep.Timeline().Fail(subject, "write refused: "+detail)
	}
	rep.Fact(p+"/refusals", refusals)
	if err = rep.Require(p+"_refused_batch_not_acknowledged", !dcLedgerHas(rep.Ledger().Acks(), x.ID.String()) && rep.Ledger().Len() == acksBefore, "the refused batch is not in the ACK ledger"); err != nil {
		return err
	}

	// The survivor must report itself unready with a closed reason.
	c.env.Logf("%s: two refusals seen (%v); waiting for the survivor to report unready", p, refusals)
	reason, seen := "", "no_answer"
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		code, st, rerr := c.readiness(survivor, 5*time.Second)
		if rerr != nil {
			seen = dcTransportClass(rerr)
			continue
		}
		seen = fmt.Sprintf("%d_%s", code, st.Reason)
		if code == 503 && !st.Ready && st.Reason != "" && st.Reason != "unknown" {
			reason = st.Reason
			break
		}
	}
	if err = rep.Require(p+"_survivor_unready_with_closed_reason", reason != "", "last /readyz seen: "+seen); err != nil {
		return err
	}
	rep.Fact(p+"/survivor_unready_reason", reason)

	// A read must not be served as complete either.
	c.env.Logf("%s: survivor unready (%s); trying a read", p, reason)
	status, raw, qerr := c.queryRaw(survivor, "last_over_time("+dcMetric+"[30m])", 60*time.Second)
	complete, why := dcServedComplete(status, raw, qerr)
	if err = rep.Require(p+"_read_not_served_as_complete", !complete, fmt.Sprintf("read answer: status %d, %s", status, strings.ReplaceAll(why, "\n", " "))); err != nil {
		return err
	}
	// And a write attempted after the member reports unready is still refused, not acknowledged.
	verdict, detail, aerr := w.attempt(survivor, x, 60*time.Second, p+"_refused")
	if aerr != nil {
		return aerr
	}
	if err = rep.Require(p+"_refusal_while_unready_is_typed_503", verdict == dcTypedRefusal, string(verdict)+" "+detail); err != nil {
		return err
	}
	if err = rep.Require(p+"_refused_batch_still_not_acknowledged", !dcLedgerHas(rep.Ledger().Acks(), x.ID.String()), "the refused batch is still not in the ACK ledger"); err != nil {
		return err
	}

	c.env.Logf("%s: read answered status %d, served complete: %v; resuming", p, status, complete)
	resumedAt := time.Now()
	for _, id := range paused {
		if err = c.resume(id); err != nil {
			return rep.Require(p+"_members_resumed", false, err.Error())
		}
	}
	for _, n := range dcMembers {
		if err = c.waitReady(n.id, 180*time.Second); err != nil {
			return rep.Require(p+"_all_members_ready_after_resume", false, err.Error())
		}
	}
	rep.Fact(p+"/all_ready_after_resume_ms", time.Since(resumedAt).Milliseconds())

	// The IDENTICAL batch is retried, survivor first.
	order := []uint64{survivor}
	for _, n := range dcMembers {
		if n.id != survivor {
			order = append(order, n.id)
		}
	}
	c.env.Logf("%s: members resumed and ready; retrying the refused batch unchanged", p)
	retryAt := time.Now()
	by, err := w.deliver(x, func() []uint64 { return order }, 120*time.Second, p+"_retry")
	if err != nil {
		return rep.Require(p+"_identical_retry_acknowledged", false, err.Error())
	}
	if err = rep.Require(p+"_identical_retry_acknowledged", dcAckedAfter(w.Times(), x.ID.String(), retryAt) && dcLedgerHas(rep.Ledger().Acks(), x.ID.String()), fmt.Sprintf("the refused batch was acknowledged by member %d only after the members resumed", by)); err != nil {
		return err
	}
	rep.Timeline().Deliver(subject, fmt.Sprintf("the refused batch was retried unchanged and acknowledged by member %d", by))
	if err = rep.Timeline().Recover(subject); err != nil {
		return rep.Require(p+"_outage_recovered", false, err.Error())
	}

	c.env.Logf("%s: converging, retrying acknowledged batches and verifying every member", p)
	if err = dcRecordCursors(c, rep, p); err != nil {
		return err
	}
	if err = dcCheckRetries(w, rep, p, "including the batch that was refused during the outage", x.ID.String()); err != nil {
		return err
	}
	if _, err = dcVerifyMembers(c, w, rep, p, 120*time.Second); err != nil {
		return err
	}
	rerr := dcVerifyRetries(w.Sent(), rep.Ledger().Acks())
	detail = fmt.Sprintf("%d attempts, %d failed attempts, every refused batch was retried with an identical body to an acknowledgement", len(w.Sent()), len(rep.Ledger().Attempts()))
	if rerr != nil {
		detail = rerr.Error()
	}
	return rep.Require(p+"_refused_attempts_retried_unchanged", rerr == nil, detail)
}
