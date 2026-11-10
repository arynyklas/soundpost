// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"soundpost/internal/control"
	"soundpost/internal/incidents"
	"soundpost/internal/model"
	"soundpost/internal/notify"
)

func init() {
	register("external-deadman", externalDeadman)
}

// The observer's schedule is the 06.09 fixture's: it polls every 200 ms and declares a component
// missing 1.5 s after its last healthy heartbeat.
const (
	deadmanInterval = 200 * time.Millisecond
	deadmanMissing  = 1500 * time.Millisecond
	deadmanTimeout  = 400 * time.Millisecond
	// A missing heartbeat must be detected within the schedule plus the polling slack the 06.09
	// fixture demonstrated; never earlier than missing-after (no false alarm).
	deadmanDetectSlack = 3*deadmanInterval + 700*time.Millisecond

	deadmanNotRunDomain = "failure-domain independence: the observer runs on the SAME host as the product (same kernel, disk, power, network namespace and operating-system user as this drill). " +
		"The drill shows that a separate operating-system process with its own state directory, poll credential and delivery credential keeps detecting and delivering while every product component is stopped; " +
		"it does NOT show that the observer survives a host, hypervisor, power, network or storage failure of the product's failure domain. A separately provisioned host, network path, credentials and scheduler are an operator prerequisite (docs/operations/external-deadman.md)."
	deadmanNotRunDestination = "a real alert destination (pager, SMS, chat, mail): not contacted. The observer delivers to a loopback receiver this drill started and authorized with the observer's test-only -test-allow-loopback flag."
)

// externalDeadman runs the 06.09 observer as a separate OS process, lets it see healthy heartbeats,
// then stops EVERY product component (heartbeat endpoints, worker, node) and requires the observer
// to detect the outage and deliver it to the loopback destination while all of them are stopped.
// After the product restarts the outage and its failed delivery attempt must still be in the
// observer's record, recovery must not erase it, no second emergency may appear and the product's
// own backlog must not be announced as new emergencies.
func externalDeadman(env *Env, rep *Report) error {
	prov := &pipeProvider{}
	return pipeGuard(func() {
		led, tl := rep.Ledger(), rep.Timeline()
		require := func(name string, ok bool, format string, a ...any) {
			pipeMust(rep.Require(name, ok, fmt.Sprintf(format, a...)), name)
		}

		// ---- the product (in this process), the destination and the heartbeat port ----
		n := newPipeNode(env, "product-node", prov)
		defer n.close()
		n.activate()
		pollToken := n.issueObserverToken()
		deliveryToken := "drill-delivery-" + model.NewID().String()
		recv := newPipeReceiver(deliveryToken, 1)
		defer recv.close()
		hb := newPipeHeartbeat(n, pollToken)
		pipeMust(env.Approve(nil, []string{recv.addr, hb.addr}), "approve the loopback addresses")
		loop := &pipeWorkerLoop{n: n, hb: hb}
		hb.start()
		loop.start()
		defer func() { loop.stop(); hb.stop() }()

		// A real incident the product announces before anything fails.
		incident, episode, condition := model.ID{0x56}, model.ID{0xec}, model.ID{0xc4}
		subject := pipeSubjectOf(incident)
		n.addRecipient(subject)
		opened := n.incidentAction(incidents.Action{CommandID: model.ID{0xd1}, Type: incidents.TypeOpen, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incident}, Impact: pipeImpact(condition, episode, incidents.SeverityMajor, incidents.ConditionFiring)})
		dOpen := pipeOneID(pipeEligibleIDs(n.submit(subject, n.evidenceOf(opened)), notify.KindOpen), "incident opening")
		pipeMust(pipeWaitFor(10*time.Second, "the product to announce the opening", func() bool { return prov.countID(dOpen) == 1 }), "announcement")

		// ---- the observer: a separate process with its own state directory and credentials ----
		binDir, obsDir := filepath.Join(env.Work, "observer-bin"), filepath.Join(env.Work, "observer-state")
		pipeMust(env.Approve([]string{binDir, obsDir}, nil), "approve the observer directories")
		pipeMust(os.MkdirAll(binDir, 0o700), "create the observer binary directory")
		bin := filepath.Join(binDir, "observer")
		pipeMust(pipeBuildObserver(env.Root, bin), "build the observer")
		require("observer_state_is_separate", obsDir != n.dir && !strings.HasPrefix(obsDir, n.dir+string(os.PathSeparator)) && !strings.HasPrefix(n.dir, obsDir+string(os.PathSeparator)), "observer state %s, product state %s", filepath.Base(obsDir), filepath.Base(n.dir))
		// An unauthorized or non-test destination is refused before the observer ever runs.
		for name, args := range map[string][]string{
			"destination_not_on_the_authorized_list":     {"-destination", recv.URL(), "-test-allow-loopback"},
			"loopback_destination_without_the_allowance": {"-destination", recv.URL(), "-authorized-destination", recv.Host()},
		} {
			probeDir := filepath.Join(env.Work, "observer-refused-"+name)
			pipeMust(env.Approve([]string{probeDir}, nil), "approve the probe directory")
			cmd := exec.Command(bin, append([]string{"-state", probeDir, "-poll", "product=" + hb.url("product")}, args...)...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "OBSERVER_POLL_TOKEN=" + pollToken, "OBSERVER_DELIVERY_TOKEN=" + deliveryToken}
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			wantMsg := map[string]string{"destination_not_on_the_authorized_list": "not authorized", "loopback_destination_without_the_allowance": "test allowance"}[name]
			refused := errors.As(err, &exit) && exit.ExitCode() == 2 && strings.Contains(string(out), wantMsg)
			require("observer_refuses_"+name, refused, "exit error %v, message %q", err, strings.TrimSpace(string(out)))
		}
		args := []string{
			"-id", "deadman-fixture",
			"-poll", "product=" + hb.url("product") + ",ingest=" + hb.url("ingest") + ",notification=" + hb.url("notification"),
			"-interval", deadmanInterval.String(), "-missing-after", deadmanMissing.String(), "-timeout", deadmanTimeout.String(),
			"-destination", recv.URL(), "-authorized-destination", recv.Host(), "-test-allow-loopback",
		}
		obs, err := startPipeObserver(bin, obsDir, pollToken, deliveryToken, args)
		pipeMust(err, "start the observer")
		defer func() { obs.kill() }()
		require("observer_is_a_separate_process", obs.pid() != os.Getpid(), "observer pid differs from the drill's")
		var armedCycle int64
		pipeMust(pipeWaitFor(15*time.Second, "the observer to be armed on all three heartbeats", func() bool {
			st, err := obs.state()
			if err != nil || !st.Armed || len(st.Components) != 3 {
				return false
			}
			for _, c := range st.Components {
				if c.Status != "ok" {
					return false
				}
			}
			armedCycle = st.LastCycle
			return true
		}), "armed")
		// The healthy window is a measured fact of the observer's own record: it completed cycles for
		// at least three poll intervals after it was armed, and in all of them nothing was missing.
		var healthy pipeObsState
		pipeMust(pipeWaitFor(10*time.Second, "the observer to poll healthy heartbeats for three intervals after it was armed", func() bool {
			st, err := obs.state()
			if err != nil {
				return false
			}
			healthy = st
			return time.Duration(st.LastCycle-armedCycle) >= 3*deadmanInterval
		}), "healthy window")
		polled := time.Duration(healthy.LastCycle - armedCycle)
		require("no_alert_while_the_product_is_healthy", len(recv.requests()) == 0 && healthy.Armed && len(healthy.Outages) == 0,
			"%d request(s) reached the destination and %d outage(s) opened over %v of healthy polling after the observer was armed (at least %v measured)", len(recv.requests()), len(healthy.Outages), polled, 3*deadmanInterval)

		// ---- a decision the product takes just before it dies: committed, not yet sent ----
		loop.stop()
		worse := n.incidentAction(incidents.Action{CommandID: model.ID{0xd2}, Type: incidents.TypeImpact, Origin: incidents.OriginSystem, Target: incidents.Target{Incident: incident}, ExpectedVersion: opened.Version,
			Impact: pipeImpact(condition, episode, incidents.SeverityCritical, incidents.ConditionFiring)})
		pending := pipeOneID(pipeEligibleIDs(n.submit(subject, n.evidenceOf(worse)), notify.KindWorseImpact), "worse impact")
		require("pending_delivery_committed_before_the_stop", n.recordOf(pending).Phase == control.DeliveryPending, "phase %s", n.recordOf(pending).Phase)
		sentBefore := prov.count()

		// ---- EVERY product component stops: heartbeat endpoints, notification worker, node ----
		stoppedAt := time.Now()
		hb.stop()
		termBeforeStop := n.lease().Term
		pipeMust(n.close(), "close the node")
		productStopped := func() error {
			if hb.running() || loop.running() || n.cur() != nil {
				return fmt.Errorf("a product component runs: heartbeats %v, worker %v, node open %v", hb.running(), loop.running(), n.cur() != nil)
			}
			conn, err := net.DialTimeout("tcp", hb.addr, 300*time.Millisecond)
			if err == nil {
				conn.Close()
				return errors.New("the heartbeat port still accepts connections")
			}
			return nil
		}
		require("every_product_component_stopped", productStopped() == nil, "%v", productStopped())

		// ---- the observer, alone, detects and delivers ----
		pipeMust(pipeWaitFor(25*time.Second, "the observer to alert on all three missing heartbeats", func() bool {
			st, err := obs.state()
			if err != nil || len(st.Outages) != 3 {
				return false
			}
			for _, o := range st.Outages {
				if !o.Alerted {
					return false
				}
			}
			return true
		}), "alerts")
		require("observer_delivered_while_every_component_was_stopped", productStopped() == nil && prov.count() == sentBefore, "product stopped: %v; product sends during the outage %d", productStopped(), prov.count()-sentBefore)
		during, err := obs.state()
		pipeMust(err, "read the observer record")
		seen := map[string]bool{}
		for _, o := range during.Outages {
			seen[o.Component] = true
			gap := time.Duration(o.DetectedNS - o.LastOKNS)
			okWindow := gap >= deadmanMissing && gap <= deadmanMissing+deadmanDetectSlack
			require("detected_"+o.Component+"_within_the_schedule", okWindow && o.LastOKNS <= stoppedAt.UnixNano() && o.DetectedNS >= stoppedAt.UnixNano() && time.Duration(o.DetectedNS-stoppedAt.UnixNano()) <= deadmanMissing+deadmanDetectSlack,
				"detected %v after the last healthy heartbeat (window [%v, %v]) and %v after the stop", gap, deadmanMissing, deadmanMissing+deadmanDetectSlack, time.Duration(o.DetectedNS-stoppedAt.UnixNano()))
		}
		require("outages_for_product_ingest_notification", seen["product"] && seen["ingest"] && seen["notification"], "outages for %v", seen)
		require("observer_kept_running", during.LastCycle > stoppedAt.UnixNano() && obs.alive(), "last cycle %v after the stop", time.Duration(during.LastCycle-stoppedAt.UnixNano()))
		failedAlerts, acceptedAlerts := pipeCountAlertAttempts(during)
		require("failed_delivery_attempt_in_the_record", failedAlerts == 1 && acceptedAlerts == 3, "%d failed (the destination refused the first request with 503) and %d accepted alert attempts, want 1 and 3", failedAlerts, acceptedAlerts)
		received := map[string]bool{}
		for _, q := range recv.requests() {
			if q.Kind == "alert" && q.Observer == "deadman-fixture" && q.Status == http.StatusOK {
				received[q.Component] = true
			}
		}
		require("destination_accepted_an_alert_per_component", received["product"] && received["ingest"] && received["notification"], "accepted alerts for %v", received)
		obsSeen := map[string]bool{}
		pipeAppendObserverEvents(tl, led, during, obsSeen)
		// The failed attempt and the missing heartbeats are on the timeline now; the outage is open.
		require("outage_open_on_the_timeline", tl.State() == StateOutage && FailedAttempts(tl.Events()) == 4, "state %s, %d failed events (3 missing heartbeats and the refused alert)", tl.State(), FailedAttempts(tl.Events()))
		failedEvents := FailedAttempts(tl.Events())

		// ---- the product comes back: its history is intact, the observer's record is not erased ----
		n.reopen()
		require("product_restarted_in_a_new_term", n.lease().Term > termBeforeStop, "leadership term %d -> %d", termBeforeStop, n.lease().Term)
		n.clock.atLeast(model.UnixNano(time.Now().UnixNano()))
		hb.start()
		loop.start() // the notification worker is part of the product: it restarts with it
		pipeMust(pipeWaitFor(25*time.Second, "the observer to see the product again and send its recovery notices", func() bool {
			st, err := obs.state()
			if err != nil || len(st.Outages) != 3 {
				return false
			}
			for _, o := range st.Outages {
				if o.RecoveredNS == 0 || !o.Recovery {
					return false
				}
			}
			return true
		}), "recovery")
		after, err := obs.state()
		pipeMust(err, "read the observer record after the recovery")
		retained := pipeVerifyOutageRetained(during, after)
		require("recovery_keeps_the_outage_and_the_failed_attempt", retained == nil, "%v", retained)
		failedAfter, acceptedAfter := pipeCountAlertAttempts(after)
		recoveries, alerts := 0, map[string]int{}
		for _, q := range recv.requests() {
			if q.Status != http.StatusOK {
				continue
			}
			switch q.Kind {
			case "recovery":
				recoveries++
			case "alert":
				alerts[q.Component]++
			}
		}
		require("recovery_is_one_notice_per_outage_never_a_second_emergency", failedAfter == 1 && acceptedAfter == 3 && recoveries == 3 && alerts["product"] == 1 && alerts["ingest"] == 1 && alerts["notification"] == 1,
			"%d failed and %d accepted alert attempts, %d recovery notices, accepted alerts per component %v", failedAfter, acceptedAfter, recoveries, alerts)
		pipeAppendObserverEvents(tl, led, after, obsSeen)
		pipeMust(tl.Recover("deadman"), "recovery on the timeline")
		timelineErr := VerifyTimeline(tl.Events(), failedEvents)
		require("timeline_recovery_keeps_every_failure", tl.State() == StateRecovered && FailedAttempts(tl.Events()) == failedEvents && timelineErr == nil, "state %s, %d failed events kept of %d, verify: %v", tl.State(), FailedAttempts(tl.Events()), failedEvents, timelineErr)

		// ---- the observer is its own process: a hard kill and a restart keep its record ----
		obs.kill()
		requestsBefore := len(recv.requests())
		obs, err = startPipeObserver(bin, obsDir, pollToken, deliveryToken, args)
		pipeMust(err, "restart the observer")
		time.Sleep(6 * deadmanInterval)
		restarted, err := obs.state()
		pipeMust(err, "read the observer record after its restart")
		restartErr := pipeVerifyOutageRetained(after, restarted)
		require("observer_restart_keeps_its_record_and_repeats_nothing", restartErr == nil && len(recv.requests()) == requestsBefore, "record: %v; destination requests %d -> %d", restartErr, requestsBefore, len(recv.requests()))

		// ---- the product's side: its own backlog is not announced as new emergencies ----
		pipeMust(pipeWaitFor(15*time.Second, "the pending delivery to be sent after the recovery", func() bool { return prov.countID(pending) == 1 }), "pending delivery")
		loop.stop()
		rec := n.recordOf(pending)
		require("pre_outage_delivery_sent_once_under_its_original_id", rec.Phase == control.DeliveryAccepted && len(rec.Attempts) == 1 && prov.count() == sentBefore+1, "phase %s, %d attempt(s), %d provider calls after the recovery (%v)", rec.Phase, len(rec.Attempts), prov.count()-sentBefore, prov.kinds())
		late, lateIDs := n.issueLate()
		lateCases := map[string]bool{}
		for _, c := range []string{"late live evidence", "backfill", "explicit operator replay", "current live evidence"} {
			lateCases[c] = late[c]
		}
		require("late_evidence_announces_nothing", !lateCases["late live evidence"] && !lateCases["backfill"] && lateCases["explicit operator replay"] && lateCases["current live evidence"], "deliverable by case %v", lateCases)
		n.clock.add(pipeSec)
		n.run()
		calls := prov.snapshot()
		expectedNew := pipeIDSet(lateIDs...)
		backlog := pipeFindBacklogEmergencies(calls, sentBefore, pipeIDSet(dOpen, pending), expectedNew)
		require("no_retroactive_backlog_as_new_emergency", len(backlog) == 0, "%v", backlog)
		dups := pipeFindDuplicateAnnouncements(calls)
		require("no_duplicate_announcement", len(dups) == 0, "%v", dups)
		retryErr := pipeVerifyRetryIdentity(calls)
		require("delivery_identity_and_receipt_stable", retryErr == nil, "%v", retryErr)

		// ---- every ACK (product deliveries and observer notices) against what was retained ----
		pipeAckDeliveries(n, led, append([]model.ID{dOpen, pending}, lateIDs...))
		for _, o := range after.Outages {
			for _, a := range o.Attempts {
				if pipeAccepted(a) {
					pipeMust(led.Record(Ack{ID: o.ID + "-" + a.Kind, Group: "destination:" + after.Observer, Index: uint64(a.N), Digest: pipeNoticeDigest(after.Observer, a.Kind, o.ID, o.Component), Label: a.Kind + "/" + o.Component}), "ledger")
				}
			}
		}
		// The observer stops before the product's final shutdown: a product that goes away again
		// while it still watches would be a second, unrelated outage.
		obs.kill()
		loop.stop()
		hb.stop()
		pipeMust(n.close(), "close the node")
		n.reopen()
		recs := n.records()
		merged := pipeRetained(recs)
		for id, digest := range recv.acceptedNotices() {
			merged[id] = digest
		}
		pipeMust(rep.Reconcile(merged), "reconciliation")
		var productAcks []Ack
		for _, a := range led.Acks() {
			if strings.HasPrefix(a.Group, "receipt:") {
				productAcks = append(productAcks, a)
			}
		}
		uncovered := pipeStoreVsLedger(recs, productAcks)
		require("store_and_ledger_agree_on_every_product_delivery", len(uncovered) == 0, "%v", uncovered)

		// ---- no credential anywhere it must not be ----
		leaked := []string{}
		for _, f := range []string{filepath.Join(obsDir, "state.json"), filepath.Join(obsDir, "attempts.jsonl")} {
			raw, err := os.ReadFile(f)
			if err != nil {
				pipeFail("read %s: %v", filepath.Base(f), err)
			}
			if strings.Contains(string(raw), pollToken) || strings.Contains(string(raw), deliveryToken) {
				leaked = append(leaked, filepath.Base(f))
			}
		}
		if strings.Contains(obs.out.String(), pollToken) || strings.Contains(obs.out.String(), deliveryToken) {
			leaked = append(leaked, "observer output")
		}
		require("no_credential_in_the_observer_record_or_output", len(leaked) == 0, "credential found in %v", leaked)

		rep.NotRun("independent failure domain", deadmanNotRunDomain)
		rep.NotRun("real alert destination", deadmanNotRunDestination)
		rep.Fact("provider", pipeProviderNote)
		rep.Fact("observer", map[string]any{"id": after.Observer, "outages": len(after.Outages), "failed_alert_attempts": failedAfter, "accepted_alert_attempts": acceptedAfter, "recovery_notices": recoveries,
			"schedule": map[string]string{"interval": deadmanInterval.String(), "missing_after": deadmanMissing.String(), "timeout": deadmanTimeout.String()}})
		rep.Fact("product_stopped_components", []string{"heartbeat endpoints", "notification worker", "node"})
		rep.Fact("same_host_not_independent", true)
		rep.Cursor("control_revision_final", uint64(n.revision()))
		pipeMust(pipeRequireChecks(rep.Checks, pipeDeadmanChecks), "the checks that define the scenario")
	})
}

// The checks that DEFINE the scenario (see pipeProviderChecks).
var pipeDeadmanChecks = []string{"observer_state_is_separate", "observer_refuses_destination_not_on_the_authorized_list", "observer_refuses_loopback_destination_without_the_allowance",
	"observer_is_a_separate_process", "no_alert_while_the_product_is_healthy", "pending_delivery_committed_before_the_stop", "every_product_component_stopped",
	"observer_delivered_while_every_component_was_stopped", "detected_ingest_within_the_schedule", "detected_notification_within_the_schedule", "detected_product_within_the_schedule",
	"outages_for_product_ingest_notification", "observer_kept_running", "failed_delivery_attempt_in_the_record", "destination_accepted_an_alert_per_component", "outage_open_on_the_timeline",
	"recovery_keeps_the_outage_and_the_failed_attempt", "recovery_is_one_notice_per_outage_never_a_second_emergency", "timeline_recovery_keeps_every_failure",
	"observer_restart_keeps_its_record_and_repeats_nothing", "pre_outage_delivery_sent_once_under_its_original_id", "late_evidence_announces_nothing", "no_retroactive_backlog_as_new_emergency",
	"no_duplicate_announcement", "delivery_identity_and_receipt_stable", "product_restarted_in_a_new_term", "exact_reconciliation", "store_and_ledger_agree_on_every_product_delivery", "no_credential_in_the_observer_record_or_output"}

// pipeAppendObserverEvents appends the events of the observer's record that the timeline does not
// hold yet (by key, remembered in seen) in time order, and records each failed notice attempt in
// the ledger's failed attempts.
func pipeAppendObserverEvents(tl *Timeline, led *Ledger, st pipeObsState, seen map[string]bool) {
	for _, e := range pipeObserverEvents(st) {
		if seen[e.Key] {
			continue
		}
		seen[e.Key] = true
		if e.Fail {
			tl.Fail(e.Subject, e.Detail)
			if !strings.HasPrefix(e.Subject, "heartbeat/") {
				led.Attempted(Attempt{ID: e.Key, Outcome: "failed", Detail: e.Subject + " " + e.Detail})
			}
		} else {
			tl.Deliver(e.Subject, e.Detail)
		}
	}
}
