// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/incidents"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

func init() {
	register("provider-failure-outage", providerFailureOutage)
}

// pipeProviderNote is the standing statement of what the provider is: it goes in every report.
const pipeProviderNote = "recording senders behind notify.Sender: no SMTP, Telegram or webhook third party is contacted"

// The checks that DEFINE each scenario. A scenario fails when one is missing or does not hold, so
// removing an assertion from it cannot make it pass.
var (
	pipeProviderChecks = []string{"one_normal_owner", "healthy_announcement", "no_outage_while_healthy", "outage_opens_on_the_first_failed_attempt", "ack_creates_no_notification",
		"material_impact_ignores_ack_and_failing_provider", "material_impact_attempted_during_outage", "ack_still_shows_the_failure", "outage_is_open_with_failures",
		"backlog_delivered_under_original_ids", "recovery_keeps_the_outage", "late_evidence_announces_nothing", "new_material_impact_notifies_after_recovery",
		"no_retroactive_backlog_as_new_emergency", "no_duplicate_announcement", "retries_keep_delivery_id_and_receipt", "one_notification_per_incident_kind", "ack_survives_recovery",
		"exact_reconciliation", "store_and_ledger_agree_on_every_delivery", "node_restart_moved_the_leadership_term", "failed_attempts_retained_after_restart", "ack_and_incident_survive_restart", "nothing_resent_after_restart"}
	pipeCutoverChecks = []string{"shadow_sends_nothing", "barrier_refuses_same_host_observer", "barrier_refuses_unknown_observer", "barrier_sends_nothing",
		"crash_between_phases_node_restarted", "crash_between_phases_one_owner_no_send", "crash_between_phases_command_replays", "crash_between_phases_sync_resumes_once", "activation_reevaluates_once_never_reannounces",
		"new_owner_is_the_one_owner", "new_owner_announces_each_change_once", "replayed_evidence_sends_nothing", "rollback_crash_node_restarted", "rollback_crash_no_owner", "rollback_crash_decides_nothing_to_send",
		"rollback_crash_sync_resumes_once", "rollback_command_replays", "old_owner_is_the_one_owner", "old_active_sends_nothing", "second_activation_is_a_new_epoch",
		"epoch_two_announces_new_change_once", "stale_lease_cannot_claim", "stale_lease_cannot_send", "stale_lease_cannot_remap_policy_states", "stale_lease_cannot_decide",
		"old_owner_revision_cannot_claim", "claim_that_saw_no_cutover_refused", "stale_owner_revision_cannot_remap_policy_states", "stale_cutover_command_loses",
		"old_command_replays_original_result", "stale_attempts_sent_nothing", "final_rollback_sends_nothing", "exactly_one_active_owner_at_every_step",
		"only_the_new_owner_active_phase_sends", "no_duplicate_delivery", "delivery_identity_and_receipt_stable", "changes_announced_exactly_once", "exact_reconciliation",
		"final_restart_moved_the_leadership_term", "no_delivery_lost_or_unacknowledged", "one_owner_after_the_final_restart"}
)

// pipeAckDeliveries records every ACKed (accepted) delivery in the ledger. The digest is built from
// what the recording sender observed (identity, kind, subject, the receipt and every attempt in
// order) plus the committed body digest read from the store at ACK time.
func pipeAckDeliveries(n *pipeNode, led *Ledger, ids []model.ID) {
	for _, id := range ids {
		rec := n.recordOf(id)
		sem, err := pipeSemanticFromSends(id.String(), n.prov.snapshot(), pipeBodyDigest(rec))
		pipeMust(err, "the semantic content of an ACKed delivery")
		pipeMust(led.Record(Ack{ID: id.String(), Group: "receipt:" + sem.Receipt, Index: uint64(len(sem.Attempts)), Digest: pipeDigest(sem), Label: sem.Kind}), "ledger")
	}
}

// pipeAdvanceToNextDue moves the clock to just after the next retry of any open delivery. It
// reports false when nothing is waiting.
func (n *pipeNode) advanceToNextDue() bool {
	var latest model.UnixNano
	for _, r := range n.records() {
		if r.Open() && r.Next > latest {
			latest = r.Next
		}
	}
	if latest == 0 {
		return false
	}
	n.clock.atLeast(latest + pipeSec)
	return true
}

// pipeEligibleIDs are the ids of the deliverable intents of a decision, optionally of one kind.
func pipeEligibleIDs(sub notify.Submission, kind notify.Kind) []model.ID {
	var ids []model.ID
	for _, in := range sub.Intents {
		if in.Eligible() && (kind == "" || in.Key.Kind == kind) {
			ids = append(ids, in.ID)
		}
	}
	return ids
}

func pipeOneID(ids []model.ID, what string) model.ID {
	if len(ids) != 1 {
		pipeFail("%s: %d deliverable intents, want exactly 1", what, len(ids))
	}
	return ids[0]
}

func pipeIDSet(ids ...model.ID) map[string]bool {
	out := map[string]bool{}
	for _, id := range ids {
		out[id.String()] = true
	}
	return out
}

// pipeFailedOnStore counts the attempts the control store holds that did not end accepted.
func pipeFailedOnStore(recs []control.DeliveryRecord) int {
	failed := 0
	for _, r := range recs {
		for _, a := range r.Attempts {
			if a.Outcome != control.DeliveryOutcomeAccepted && a.Outcome != "" {
				failed++
			}
		}
	}
	return failed
}

// providerFailureOutage: a failing provider (retry and unknown outcomes) opens an outage; a later
// successful delivery recovers it; the outage, every failed attempt, every delivery id and receipt
// survive the recovery and a restart of the node; no retroactive backlog is announced as a new
// emergency; an ACK still shows the failure; and a material change still notifies while the
// provider is failing and after it recovered.
func providerFailureOutage(env *Env, rep *Report) error {
	prov := &pipeProvider{}
	return pipeGuard(func() {
		tl, led := rep.Timeline(), rep.Ledger()
		require := func(name string, ok bool, format string, a ...any) {
			pipeMust(rep.Require(name, ok, fmt.Sprintf(format, a...)), name)
		}
		prov.onCall = func(c pipeSend) {
			subject := fmt.Sprintf("%s#%d", c.ID[:12], c.Attempt)
			if c.Outcome == "accepted" {
				tl.Deliver(subject, c.Kind)
				return
			}
			tl.Fail(subject, c.Kind+" "+c.Outcome+" "+c.Code)
			led.Attempted(Attempt{ID: c.ID, Outcome: c.Outcome, Detail: fmt.Sprintf("attempt %d %s", c.Attempt, c.Code)})
		}
		var outage atomic.Bool
		prov.setPlan(func(_ notify.Delivery, nth int) notify.Outcome {
			if !outage.Load() {
				return notify.Outcome{}
			}
			if nth%2 == 0 {
				return notify.Outcome{Kind: notify.OutcomeRetry, Code: "provider_503"}
			}
			return notify.Outcome{Kind: notify.OutcomeUnknown, Code: "timeout"}
		})

		n := newPipeNode(env, "provider-node", prov)
		defer n.close()
		n.activate()
		step := n.ownerStep()
		require("one_normal_owner", len(step.Owners) == 1 && step.Phase == "new_active", "phase %s, %d active owner(s)", step.Phase, len(step.Owners))
		pass := func() notify.RunReport {
			r := n.run()
			pipeAckDeliveries(n, led, r.Accepted)
			return r
		}

		// 1. Healthy: incident A is announced and ACKed by the provider.
		incA, epA, condA := model.ID{0x56}, model.ID{0xec}, model.ID{0xc4}
		subA := pipeSubjectOf(incA)
		n.addRecipient(subA)
		openedA := n.incidentAction(incidents.Action{CommandID: model.ID{0xd1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incA}, Impact: pipeImpact(condA, epA, incidents.SeverityMajor, incidents.ConditionFiring)})
		dOpenA := pipeOneID(pipeEligibleIDs(n.submit(subA, n.evidenceOf(openedA)), notify.KindOpen), "A opening")
		n.clock.add(pipeSec)
		r := pass()
		require("healthy_announcement", len(r.Accepted) == 1 && prov.kinds()[0] == "open" && prov.count() == 1, "kinds %v", prov.kinds())
		require("no_outage_while_healthy", tl.State() == StateOK && FailedAttempts(tl.Events()) == 0, "state %s", tl.State())

		// 2. The provider fails. Material changes keep entering the outbox and keep being attempted.
		outage.Store(true)
		worseA := n.incidentAction(incidents.Action{CommandID: model.ID{0xd2}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incA}, ExpectedVersion: openedA.Version,
			Impact: pipeImpact(condA, epA, incidents.SeverityCritical, incidents.ConditionFiring)})
		dWorseA := pipeOneID(pipeEligibleIDs(n.submit(subA, n.evidenceOf(worseA)), notify.KindWorseImpact), "A worse impact")
		incB, epB, condB := model.ID{0x57}, model.ID{0xed}, model.ID{0xc5}
		subB := pipeSubjectOf(incB)
		n.addRecipient(subB)
		openedB := n.incidentAction(incidents.Action{CommandID: model.ID{0xd3}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incB}, Impact: pipeImpact(condB, epB, incidents.SeverityMajor, incidents.ConditionFiring)})
		dOpenB := pipeOneID(pipeEligibleIDs(n.submit(subB, n.evidenceOf(openedB)), notify.KindOpen), "B opening")
		n.clock.add(pipeSec)
		r = pass()
		require("outage_opens_on_the_first_failed_attempt", len(r.Retried) == 2 && len(r.Accepted) == 0 && tl.State() == StateOutage, "retried %d accepted %d state %s", len(r.Retried), len(r.Accepted), tl.State())

		// A human ACKs incident B while its notification is failing; then B gets WORSE.
		ackedB := n.incidentAction(incidents.Action{CommandID: model.ID{0xd4}, Type: incidents.TypeAck, Origin: incidents.OriginHuman, Target: incidents.Target{Incident: incB}, ExpectedVersion: openedB.Version})
		ackSub := n.submit(subB, n.humanOf(ackedB, notify.ActionAck, func(a *notify.HumanAction) { a.ImpactRevision = ackedB.Ack.ImpactRevision }))
		require("ack_creates_no_notification", len(pipeEligibleIDs(ackSub, "")) == 0, "an ACK decided %d deliverable intents", len(pipeEligibleIDs(ackSub, "")))
		worseB := n.incidentAction(incidents.Action{CommandID: model.ID{0xd5}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incB}, ExpectedVersion: ackedB.Version,
			Impact: pipeImpact(condB, epB, incidents.SeverityCritical, incidents.ConditionFiring)})
		dWorseB := pipeOneID(pipeEligibleIDs(n.submit(subB, n.evidenceOf(worseB)), notify.KindWorseImpact), "B worse impact under an ACK")
		require("material_impact_ignores_ack_and_failing_provider", prov.countID(dWorseB) == 0 && n.recordOf(dWorseB).Phase == control.DeliveryPending, "the worse impact of ACKed incident B is %s with %d provider attempts before the first pass while the provider fails", n.recordOf(dWorseB).Phase, prov.countID(dWorseB))
		for range 3 {
			if !n.advanceToNextDue() {
				pipeFail("nothing is waiting for a retry during the outage")
			}
			if r = pass(); len(r.Accepted) != 0 {
				pipeFail("the failing provider accepted %v", r.Accepted)
			}
		}
		require("material_impact_attempted_during_outage", prov.countID(dWorseB) >= 2 && prov.countID(dWorseA) >= 3, "A worse impact %d attempts, B worse impact %d attempts", prov.countID(dWorseA), prov.countID(dWorseB))
		duringFailed := FailedAttempts(tl.Events())
		recB := n.recordOf(dOpenB)
		require("ack_still_shows_the_failure", ackedB.Ack != nil && recB.Phase != control.DeliveryAccepted && len(recB.Attempts) >= 3 && recB.Attempts[0].Outcome == control.DeliveryOutcomeRetry,
			"incident B acked=%v, its opening is %s with %d attempts, first outcome %q", ackedB.Ack != nil, recB.Phase, len(recB.Attempts), recB.Attempts[0].Outcome)
		require("outage_is_open_with_failures", tl.State() == StateOutage && duringFailed >= 9, "state %s, %d failed attempts", tl.State(), duringFailed)

		// 3. The provider recovers: the very same deliveries are retried and accepted.
		outage.Store(false)
		for range 6 {
			if !n.advanceToNextDue() {
				break
			}
			pass()
		}
		open := 0
		for _, rec := range n.records() {
			if rec.Open() {
				open++
			}
		}
		require("backlog_delivered_under_original_ids", open == 0 && n.recordOf(dWorseA).Phase == control.DeliveryAccepted && n.recordOf(dOpenB).Phase == control.DeliveryAccepted && n.recordOf(dWorseB).Phase == control.DeliveryAccepted, "%d deliveries still open", open)
		pipeMust(tl.Recover("provider"), "recovery")
		boundary := prov.count()
		outageIDs := pipeIDSet(dOpenA, dWorseA, dOpenB, dWorseB)
		failedAtRecovery := FailedAttempts(tl.Events())
		pipeMust(rep.Require("recovery_keeps_the_outage", tl.State() == StateRecovered && failedAtRecovery == duringFailed && VerifyTimeline(tl.Events(), duringFailed) == nil,
			fmt.Sprintf("state %s, %d failed attempts at recovery, %d during the outage", tl.State(), failedAtRecovery, duringFailed)), "recovery")

		// 4. After the recovery: no retroactive backlog, only genuinely new material changes notify.
		late, lateIDs := n.issueLate()
		lateCases := []string{"late live evidence", "backfill", "explicit operator replay", "current live evidence"}
		gotLate := map[string]bool{}
		for _, c := range lateCases {
			gotLate[c] = late[c]
		}
		late = gotLate
		require("late_evidence_announces_nothing", !late["late live evidence"] && !late["backfill"] && late["explicit operator replay"] && late["current live evidence"],
			"deliverable by case %v: late live evidence and backfill must announce nothing, an explicit operator replay and current evidence do", late)
		incC, epC, condC := model.ID{0x58}, model.ID{0xee}, model.ID{0xc6}
		subC := pipeSubjectOf(incC)
		n.addRecipient(subC)
		openedC := n.incidentAction(incidents.Action{CommandID: model.ID{0xd6}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incC}, Impact: pipeImpact(condC, epC, incidents.SeverityMajor, incidents.ConditionFiring)})
		dOpenC := pipeOneID(pipeEligibleIDs(n.submit(subC, n.evidenceOf(openedC)), notify.KindOpen), "C opening")
		expectedNew := pipeIDSet(dOpenC)
		for _, id := range lateIDs {
			expectedNew[id.String()] = true
		}
		for range 4 {
			n.clock.add(2 * pipeSec)
			pass()
		}
		calls := prov.snapshot()
		require("new_material_impact_notifies_after_recovery", n.recordOf(dOpenC).Phase == control.DeliveryAccepted && prov.countID(dOpenC) == 1, "C opening: %s, %d send(s)", n.recordOf(dOpenC).Phase, prov.countID(dOpenC))
		backlog := pipeFindBacklogEmergencies(calls, boundary, outageIDs, expectedNew)
		require("no_retroactive_backlog_as_new_emergency", len(backlog) == 0, "%v", backlog)
		dups := pipeFindDuplicateAnnouncements(calls)
		require("no_duplicate_announcement", len(dups) == 0, "%v", dups)
		retryErr := pipeVerifyRetryIdentity(calls)
		require("retries_keep_delivery_id_and_receipt", retryErr == nil, "%v", retryErr)
		perKind := map[string]int{}
		for _, c := range calls {
			if c.Outcome == "accepted" && strings.HasPrefix(c.Subject, "incident:") {
				perKind[c.Subject[len("incident:"):len("incident:")+4]+"/"+c.Kind]++
			}
		}
		want := map[string]int{incA.String()[:4] + "/open": 1, incA.String()[:4] + "/worse_impact": 1, incB.String()[:4] + "/open": 1, incB.String()[:4] + "/worse_impact": 1, incC.String()[:4] + "/open": 1}
		require("one_notification_per_incident_kind", fmt.Sprint(perKind) == fmt.Sprint(want), "accepted per incident/kind %v, want %v", perKind, want)
		require("ack_survives_recovery", n.incidentState(incB).Ack != nil && pipeFailedOnStore([]control.DeliveryRecord{n.recordOf(dOpenB)}) >= 3, "the ACK is still on the incident and its failed attempts are still on the delivery")

		// 5. Restart the node: the retained delivery records are exactly what was ACKed.
		termBefore, termAfter := n.crashRestart("close the node")
		require("node_restart_moved_the_leadership_term", termAfter > termBefore, "term %d -> %d", termBefore, termAfter)
		recs := n.records()
		retained := pipeRetained(recs)
		pipeMust(rep.Reconcile(retained), "reconciliation")
		uncovered := pipeStoreVsLedger(recs, led.Acks())
		require("store_and_ledger_agree_on_every_delivery", len(uncovered) == 0, "%v", uncovered)
		phases := map[string]int{}
		for _, rec := range recs {
			phases[rec.Phase]++
		}
		rep.Fact("delivery_phases", phases)
		allFailed := FailedAttempts(tl.Events())
		storeFailed := pipeFailedOnStore(recs)
		require("failed_attempts_retained_after_restart", storeFailed == allFailed && VerifyTimeline(tl.Events(), duringFailed) == nil, "%d failed attempts on the store, %d on the timeline", storeFailed, allFailed)
		require("ack_and_incident_survive_restart", n.incidentState(incB).Ack != nil && n.recordOf(dWorseB).Phase == control.DeliveryAccepted, "incident B ACK present, worse impact %s", n.recordOf(dWorseB).Phase)
		before := prov.count()
		n.clock.add(2 * pipeSec)
		n.run()
		require("nothing_resent_after_restart", prov.count() == before, "%d -> %d provider calls", before, prov.count())

		rep.Fact("provider", pipeProviderNote)
		rep.Fact("failed_attempts", allFailed)
		rep.Fact("deliveries", len(recs))
		rep.Fact("acked_deliveries", led.Len())
		rep.Fact("late_evidence_deliverable", late)
		receipts := map[string]string{}
		for _, a := range led.Acks() {
			receipts[a.ID[:12]] = strings.TrimPrefix(a.Group, "receipt:")
		}
		rep.Fact("receipts_by_delivery", receipts)
		rep.Cursor("control_revision_final", uint64(n.revision()))
		rep.Fences = append(rep.Fences, map[string]any{"term": n.lease().Term, "note": "the node's leadership lease at the end of the drill"})
		pipeMust(pipeRequireChecks(rep.Checks, pipeProviderChecks), "the checks that define the scenario")
	})
}

func init() {
	register("owner-cutover-rollback", ownerCutoverRollback)
}

// ownerCutoverRollback drives the canonical notification owner through shadow, quiescing, barrier,
// activation of the new owner, rollback, the old owner again and a second activation, on a real
// node with the real worker, and kills the node between a committed phase and its application to
// the policy states (twice). It asserts exactly one active owner at every step, that only the new
// owner's active phase ever sends, that nothing is duplicated or lost (every ACKed delivery is
// reconciled against the records read back after a final restart), that a stale lease and a stale
// owner revision cannot claim, send, remap policy states or move the cutover, and that a crash
// between phases resumes safely.
func ownerCutoverRollback(env *Env, rep *Report) error {
	prov := &pipeProvider{}
	return pipeGuard(func() {
		led := rep.Ledger()
		require := func(name string, ok bool, format string, a ...any) {
			pipeMust(rep.Require(name, ok, fmt.Sprintf(format, a...)), name)
		}
		n := newPipeNode(env, "cutover-node", prov)
		defer n.close()
		var steps []pipeOwnerStep
		observe := func(label string) pipeOwnerStep {
			s, ok := n.cutState()
			if !ok {
				pipeFail("no cutover is committed at %s", label)
			}
			step := n.ownerStep()
			steps = append(steps, step)
			rep.PolicyTimeline = append(rep.PolicyTimeline, map[string]any{"step": label, "phase": string(s.Phase), "revision": uint64(s.Revision), "epoch": s.Epoch, "active_owners": len(step.Owners)})
			return step
		}
		pass := func() notify.RunReport {
			r := n.run()
			pipeAckDeliveries(n, led, r.Accepted)
			return r
		}
		fence := func(label string, l notify.FenceToken) {
			rep.Fences = append(rep.Fences, map[string]any{"at": label, "group": l.Group.String(), "term": l.Term, "membership_revision": uint64(l.Revision)})
		}
		sends := func() int { return prov.count() }

		// The old owner is handling an episode the product shadows: a real incident.
		inc1, ep1, cond1 := model.ID{0x53}, model.ID{0xe9}, model.ID{0xc1}
		sub1 := pipeSubjectOf(inc1)
		opened1 := n.incidentAction(incidents.Action{CommandID: model.ID{0xa1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: inc1}, Impact: pipeImpact(cond1, ep1, incidents.SeverityMajor, incidents.ConditionFiring)})
		n.addRecipient(sub1)

		// 1. shadow: the opening the old owner announced is decided and recorded, never sent.
		n.advance(notify.CutoverShadow)
		observe("shadow")
		shadowSub := n.submit(sub1, n.evidenceOf(opened1))
		var shadowOpen []model.ID
		for _, in := range shadowSub.Intents {
			if in.Key.Kind == notify.KindOpen {
				shadowOpen = append(shadowOpen, in.ID)
			}
		}
		pass()
		require("shadow_sends_nothing", sends() == 0 && len(shadowOpen) == 1, "%d provider calls, %d shadow opening intent(s)", sends(), len(shadowOpen))

		// 2. quiescing_old; the barrier refuses a truthful same-host observer and an unknown observer.
		n.advance(notify.CutoverQuiescingOld)
		observe("quiescing_old")
		var barrier *notify.BarrierError
		_, err := n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverBarrierVerified, func(e *notify.BarrierEvidence) { e.Observer.Domain = e.Observer.ProductDomain }))
		require("barrier_refuses_same_host_observer", errors.As(err, &barrier) && slices.Contains(barrier.Checks, "observer_domain"), "%v", err)
		_, err = n.cut.AdvanceCutover(n.ctx, n.scope(), n.command(notify.CutoverBarrierVerified, func(e *notify.BarrierEvidence) { e.Observer = nil }))
		require("barrier_refuses_unknown_observer", errors.As(err, &barrier) && slices.Contains(barrier.Checks, "observer"), "%v", err)
		n.advance(notify.CutoverBarrierVerified)
		observe("barrier_verified")
		pass()
		require("barrier_sends_nothing", sends() == 0, "%d provider calls", sends())

		// 3. CRASH BETWEEN PHASES (a): the activation committed, the process died before the policy
		// states followed. After the restart the committed state is the truth: one owner, no send
		// from states that are still shadow; the resumed sync is idempotent and the replay of the
		// committed command is its original result.
		activate := n.command(notify.CutoverNewActive)
		s1, err := n.cut.AdvanceCutover(n.ctx, n.scope(), activate)
		pipeMust(err, "activate the new owner")
		termBefore, termAfter := n.crashRestart("kill the node between the phase and the policy sync")
		require("crash_between_phases_node_restarted", termAfter > termBefore, "leadership term %d -> %d", termBefore, termAfter)
		step := observe("new_active (after the restart, before the sync)")
		pass()
		require("crash_between_phases_one_owner_no_send", len(step.Owners) == 1 && step.Owners[0] == n.nw.String() && sends() == 0, "owners %v, %d provider calls before the resumed sync", step.Owners, sends())
		replayed, err := n.cut.AdvanceCutover(n.ctx, n.scope(), activate)
		require("crash_between_phases_command_replays", err == nil && replayed.Replayed && replayed.Revision == s1.Revision && replayed.Phase == notify.CutoverNewActive, "replayed=%v revision %d/%d: %v", replayed.Replayed, replayed.Revision, s1.Revision, err)
		cur, _ := n.cutState()
		changed := n.syncModes(cur)
		again := n.syncModes(cur)
		require("crash_between_phases_sync_resumes_once", changed >= 1 && again == 0, "the resumed sync changed %d state(s), a second one %d", changed, again)
		pass()
		k := prov.kinds()
		require("activation_reevaluates_once_never_reannounces", len(k) <= 1 && (len(k) == 0 || k[0] == string(notify.KindCurrent)) && prov.countID(shadowOpen[0]) == 0, "provider kinds after the activation %v", k)
		epoch1 := observe("new_active (epoch 1, synced)")
		require("new_owner_is_the_one_owner", len(epoch1.Owners) == 1 && epoch1.Owners[0] == n.nw.String(), "owners %v", epoch1.Owners)

		// 4. The new owner announces a genuinely new material change exactly once; a replay of the
		// same evidence decides nothing and sends nothing.
		worse1 := n.incidentAction(incidents.Action{CommandID: model.ID{0xa2}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: inc1}, ExpectedVersion: opened1.Version, Impact: pipeImpact(cond1, ep1, incidents.SeverityCritical, incidents.ConditionFiring)})
		worseEv := n.evidenceOf(worse1)
		dWorse1 := pipeOneID(pipeEligibleIDs(n.submit(sub1, worseEv), notify.KindWorseImpact), "worse impact of incident 1")
		inc2, ep2, cond2 := model.ID{0x54}, model.ID{0xea}, model.ID{0xc2}
		sub2 := pipeSubjectOf(inc2)
		n.addRecipient(sub2)
		opened2 := n.incidentAction(incidents.Action{CommandID: model.ID{0xa3}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: inc2}, Impact: pipeImpact(cond2, ep2, incidents.SeverityMajor, incidents.ConditionFiring)})
		openEv2 := n.evidenceOf(opened2)
		dOpen2 := pipeOneID(pipeEligibleIDs(n.submit(sub2, openEv2), notify.KindOpen), "opening of incident 2")
		n.clock.add(pipeSec)
		r := pass()
		require("new_owner_announces_each_change_once", prov.countID(dWorse1) == 1 && prov.countID(dOpen2) == 1 && len(r.Accepted) >= 2, "worse impact sent %d time(s), opening of incident 2 %d time(s)", prov.countID(dWorse1), prov.countID(dOpen2))
		before := sends()
		replaySub := n.submit(sub1, worseEv)
		n.submit(sub2, openEv2)
		n.clock.add(pipeSec)
		pass()
		require("replayed_evidence_sends_nothing", replaySub.Unchanged && sends() == before, "unchanged=%v, %d -> %d provider calls", replaySub.Unchanged, before, sends())
		staleLease := n.lease() // the lease the epoch-1 worker holds
		epoch1Revision := epoch1Rev(n)
		fence("epoch 1 worker (becomes stale)", staleLease)

		// 5. CRASH BETWEEN PHASES (b): rollback committed, the policy states still active. The
		// phase alone stops every send, and what is decided meanwhile is never pending.
		rollback := n.command(notify.CutoverRollbackQuiescing)
		rolled, err := n.cut.AdvanceCutover(n.ctx, n.scope(), rollback)
		pipeMust(err, "begin the rollback")
		termBefore, termAfter = n.crashRestart("kill the node between the rollback and the policy sync")
		require("rollback_crash_node_restarted", termAfter > termBefore, "leadership term %d -> %d", termBefore, termAfter)
		step = observe("rollback_quiescing (after the restart, before the sync)")
		require("rollback_crash_no_owner", len(step.Owners) == 0, "owners %v while the new owner quiesces", step.Owners)
		worse2 := n.incidentAction(incidents.Action{CommandID: model.ID{0xa4}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: inc2}, ExpectedVersion: opened2.Version, Impact: pipeImpact(cond2, ep2, incidents.SeverityCritical, incidents.ConditionFiring)})
		decided := n.submit(sub2, n.evidenceOf(worse2))
		before = sends()
		n.clock.add(pipeSec)
		pass()
		open := 0
		for _, rec := range n.records() {
			if rec.Open() {
				open++
			}
		}
		require("rollback_crash_decides_nothing_to_send", open == 0 && sends() == before, "%d open deliveries, %d -> %d provider calls (the decision produced %d intent(s))", open, before, sends(), len(decided.Intents))
		cur, _ = n.cutState()
		changed = n.syncModes(cur)
		again = n.syncModes(cur)
		require("rollback_crash_sync_resumes_once", changed >= 1 && again == 0, "the resumed sync changed %d state(s), a second one %d", changed, again)
		replayedRollback, err := n.cut.AdvanceCutover(n.ctx, n.scope(), rollback)
		require("rollback_command_replays", err == nil && replayedRollback.Replayed && replayedRollback.Revision == rolled.Revision, "replayed=%v: %v", replayedRollback.Replayed, err)

		// 6. The old owner is active again; the product decides and records, and sends nothing.
		n.clock.add(3 * 60 * pipeSec)
		n.advance(notify.CutoverOldActive)
		step = observe("old_active")
		require("old_owner_is_the_one_owner", len(step.Owners) == 1 && step.Owners[0] == n.old.String(), "owners %v", step.Owners)
		recovered1 := n.incidentAction(incidents.Action{CommandID: model.ID{0xa5}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: inc1}, ExpectedVersion: worse1.Version, Impact: pipeImpact(cond1, ep1, incidents.SeverityCritical, incidents.ConditionRecovered)})
		n.submit(sub1, n.evidenceOf(recovered1))
		before = sends()
		n.clock.add(pipeSec)
		pass()
		require("old_active_sends_nothing", sends() == before, "%d -> %d provider calls", before, sends())

		// 7. Second activation (epoch 2): what changed while the new owner was away is reevaluated
		// as current state, and a new material change is announced once.
		n.advance(notify.CutoverQuiescingOld)
		observe("quiescing_old (epoch 2)")
		n.advance(notify.CutoverBarrierVerified)
		observe("barrier_verified (epoch 2)")
		s2 := n.advance(notify.CutoverNewActive)
		epoch2 := observe("new_active (epoch 2)")
		require("second_activation_is_a_new_epoch", s2.Epoch == 2 && len(epoch2.Owners) == 1 && epoch2.Owners[0] == n.nw.String(), "epoch %d, owners %v", s2.Epoch, epoch2.Owners)
		n.clock.add(pipeSec)
		pass()
		inc3, ep3, cond3 := model.ID{0x59}, model.ID{0xeb}, model.ID{0xc3}
		sub3 := pipeSubjectOf(inc3)
		n.addRecipient(sub3)
		opened3 := n.incidentAction(incidents.Action{CommandID: model.ID{0xa6}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: inc3}, Impact: pipeImpact(cond3, ep3, incidents.SeverityMajor, incidents.ConditionFiring)})
		dOpen3 := pipeOneID(pipeEligibleIDs(n.submit(sub3, n.evidenceOf(opened3)), notify.KindOpen), "opening of incident 3")
		n.clock.add(pipeSec)
		pass()
		require("epoch_two_announces_new_change_once", prov.countID(dOpen3) == 1 && n.recordOf(dOpen3).Phase == control.DeliveryAccepted, "opening of incident 3 sent %d time(s)", prov.countID(dOpen3))

		// 8. A stale owner: whatever carries the fence or the owner revision of before the cutover
		// moved can neither claim, send, remap policy states nor move the cutover.
		fence("epoch 2 worker (current)", n.lease())
		curLease := n.lease()
		stale := func(name string, err error, code, detail string) {
			require(name, pipeIsFault(err, code, detail), "%v", err)
		}
		before = sends()
		_, err = n.ob.Claim(n.ctx, n.scope(), n.clock.Now(), staleLease, 4)
		stale("stale_lease_cannot_claim", err, string(model.Stale), "")
		_, err = n.w.RunOnce(n.ctx, n.scope(), n.clock.Now(), staleLease)
		stale("stale_lease_cannot_send", err, string(model.Stale), "")
		_, err = n.ob.SyncModes(n.ctx, n.scope(), staleLease, notify.CutoverShadow, n.cutStateMust().Cutover, n.cutStateMust().Revision, n.clock.Now())
		stale("stale_lease_cannot_remap_policy_states", err, string(model.Stale), "")
		ev := n.event(notify.EventDestination, "stale-lease-edit")
		ev.Destination = &notify.DestinationChange{Recipient: n.dest, Enabled: false}
		_, err = n.ob.Submit(n.ctx, n.scope(), staleLease, sub3, ev, n.clock.Now())
		stale("stale_lease_cannot_decide", err, string(model.Stale), "")
		_, err = n.rawClaim(epoch1Revision, curLease, n.clock.Now())
		stale("old_owner_revision_cannot_claim", err, string(model.Stale), control.DeliveryOwnerStale)
		_, err = n.rawClaim(0, curLease, n.clock.Now())
		require("claim_that_saw_no_cutover_refused", err != nil, "a claim naming no cutover revision was accepted")
		staleEdit := n.event(notify.EventDestination, "stale-owner-revision-edit")
		staleEdit.Destination = &notify.DestinationChange{Recipient: n.dest, Enabled: false}
		staleEdit.OwnerRevision = n.policyOwnerRevision(sub3) - 1
		_, err = n.ob.Submit(n.ctx, n.scope(), curLease, sub3, staleEdit, n.clock.Now())
		reason, _ := notify.ReasonOf(err)
		require("stale_owner_revision_cannot_remap_policy_states", reason == notify.ReasonOwnerRevision, "refusal %v (reason %q)", err, reason)
		late := n.command(notify.CutoverOldActive)
		late.ExpectedRevision = epoch1Revision
		_, err = n.cut.AdvanceCutover(n.ctx, n.scope(), late)
		_, isConflict := notify.CutoverCurrent(err)
		require("stale_cutover_command_loses", isConflict && n.cutStateMust().Phase == notify.CutoverNewActive, "%v", err)
		old, err := n.cut.AdvanceCutover(n.ctx, n.scope(), activate)
		require("old_command_replays_original_result", err == nil && old.Replayed && old.Phase == notify.CutoverNewActive && old.Epoch == 1 && n.cutStateMust().Epoch == 2, "replayed=%v epoch %d (current %d): %v", old.Replayed, old.Epoch, n.cutStateMust().Epoch, err)
		require("stale_attempts_sent_nothing", sends() == before, "%d -> %d provider calls", before, sends())

		// 9. Roll back again: the old owner ends as the one owner and nothing more is sent.
		n.advance(notify.CutoverRollbackQuiescing)
		observe("rollback_quiescing (epoch 2)")
		n.clock.add(3 * 60 * pipeSec)
		n.advance(notify.CutoverOldActive)
		final := observe("old_active (final)")
		before = sends()
		n.clock.add(pipeSec)
		pass()
		require("final_rollback_sends_nothing", len(final.Owners) == 1 && final.Owners[0] == n.old.String() && sends() == before, "owners %v, %d -> %d provider calls", final.Owners, before, sends())

		// 10. Verdicts on the whole journey, then a final restart and the exact reconciliation.
		ownersErr := pipeVerifyOwnerSteps(steps, n.old.String(), n.nw.String())
		require("exactly_one_active_owner_at_every_step", ownersErr == nil, "%d steps observed: %v", len(steps), ownersErr)
		calls := prov.snapshot()
		outside := pipeFindSendsOutsideOwner(calls, "new_active")
		require("only_the_new_owner_active_phase_sends", len(outside) == 0, "%v", outside)
		dups := pipeFindDuplicateAnnouncements(calls)
		require("no_duplicate_delivery", len(dups) == 0, "%v", dups)
		retryErr := pipeVerifyRetryIdentity(calls)
		require("delivery_identity_and_receipt_stable", retryErr == nil, "%v", retryErr)
		accepted := map[string]int{}
		for _, c := range calls {
			if c.Outcome == "accepted" {
				accepted[c.Kind]++
			}
		}
		require("changes_announced_exactly_once", prov.countID(dWorse1) == 1 && prov.countID(dOpen2) == 1 && prov.countID(dOpen3) == 1 && prov.countID(shadowOpen[0]) == 0,
			"worse impact %d, opening 2 %d, opening 3 %d, shadow opening %d send(s); accepted by kind %v", prov.countID(dWorse1), prov.countID(dOpen2), prov.countID(dOpen3), prov.countID(shadowOpen[0]), accepted)
		termBefore, termAfter = n.crashRestart("close the node")
		require("final_restart_moved_the_leadership_term", termAfter > termBefore, "term %d -> %d", termBefore, termAfter)
		recs := n.records()
		pipeMust(rep.Reconcile(pipeRetained(recs)), "reconciliation")
		uncovered := pipeStoreVsLedger(recs, led.Acks())
		require("no_delivery_lost_or_unacknowledged", len(uncovered) == 0, "%v", uncovered)
		endStep := n.ownerStep()
		require("one_owner_after_the_final_restart", len(endStep.Owners) == 1 && endStep.Owners[0] == n.old.String() && endStep.Phase == "old_active", "phase %s owners %v", endStep.Phase, endStep.Owners)
		phases := map[string]int{}
		for _, rec := range recs {
			phases[rec.Phase]++
		}
		rep.Fact("provider", pipeProviderNote)
		rep.Fact("provider_kinds_in_order", prov.kinds())
		rep.Fact("delivery_phases", phases)
		rep.Fact("acked_deliveries", led.Len())
		rep.Fact("cutover_steps_observed", len(steps))
		rep.Cursor("control_revision_final", uint64(n.revision()))
		fence("final", n.lease())
		pipeMust(pipeRequireChecks(rep.Checks, pipeCutoverChecks), "the checks that define the scenario")
	})
}

// epoch1Rev is the committed cutover revision of the first new_active epoch: the revision a stale
// owner's claim would still name.
func epoch1Rev(n *pipeNode) model.Revision {
	s, _ := n.cutState()
	for _, e := range s.Timeline {
		if e.To == notify.CutoverNewActive && e.Epoch == 1 {
			return e.Revision
		}
	}
	pipeFail("no first new_active step in the cutover timeline")
	return 0
}

func (n *pipeNode) cutStateMust() notify.CutoverState {
	s, ok := n.cutState()
	if !ok {
		pipeFail("no cutover is committed")
	}
	return s
}
