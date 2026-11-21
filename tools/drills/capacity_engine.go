//go:build soundpost_faults

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

// Part 4 of `capacity-faults`: failed sync and slow apply driven through the real storage.Engine of
// the real application (internal/appcore: control, replicated storage, auth, ingest over HTTPS)
// with the exported fault seam storage.Engine.SetFaultHook. The hook is called by the engine at
// the replica journal's "wal_sync" (immediately before the real fsync) and at the state machine's
// "before_apply"; the real fsync and the real apply still run whenever the hook returns nil.
//
// What this part proves and what it does not: it proves the engine's behaviour (no false
// acknowledgement, typed refusals, the group latch, the restart, the retry of the same batch)
// under a failing or slow durability step. It does not make the operating system fail; the
// operating-system errors (EIO, ENOSPC) are produced by the real-errno part in
// capacity_errno.go.

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/storage"
)

var errCapEngineSync = errors.New("drill: injected engine journal sync failure")

// capEngineSwitch is the hook handed to storage.Engine.SetFaultHook.
type capEngineSwitch struct {
	failSync   atomic.Bool
	syncDelay  atomic.Int64 // ns
	applyDelay atomic.Int64 // ns
	mu         sync.Mutex
	hits       map[string]int
}

func (s *capEngineSwitch) hook(point string) error {
	var delay time.Duration
	fail := false
	switch point {
	case "wal_sync":
		delay, fail = time.Duration(s.syncDelay.Load()), s.failSync.Load()
	case "before_apply":
		delay = time.Duration(s.applyDelay.Load())
	default:
		return nil
	}
	if delay > 0 || fail {
		s.mu.Lock()
		if s.hits == nil {
			s.hits = map[string]int{}
		}
		s.hits[point]++
		s.mu.Unlock()
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	if fail {
		return errCapEngineSync
	}
	return nil
}

func (s *capEngineSwitch) count(point string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits[point]
}

// capReopen closes the site and opens the application over the same files again; the owner session
// and organization survive in the control state.
func capReopen(env *Env, site *capSite, meter storage.DiskMeter, cfg storage.PressureConfig) (*capSite, error) {
	owner, org, token, dir := site.owner, site.org, site.owner.Token, site.dir
	site.close()
	reopened, err := capStartSite(env, dir, meter, cfg)
	if err != nil {
		return nil, fmt.Errorf("reopen: %w", err)
	}
	reopened.owner, reopened.org = owner, org
	if reopened.actor, err = reopened.app.Auth.Authenticate(env.Ctx, token); err != nil {
		reopened.close()
		return nil, fmt.Errorf("authenticate after reopen: %w", err)
	}
	return reopened, nil
}

// sendWithin posts one batch with a caller deadline; a deadline that ends the call is the
// caller's own timeout, a typed class.
func (s *capSite) sendWithin(p capProject, b capHTTPBatch, limit time.Duration) (capIngestAnswer, error) {
	if limit <= 0 {
		return s.send(p, b)
	}
	local := *s // a copy: concurrent callers must not share the deadline of one
	local.client = &http.Client{Transport: s.client.Transport, Timeout: limit}
	a, err := local.send(p, b)
	if err != nil {
		var timeout interface{ Timeout() bool }
		if errors.As(err, &timeout) && timeout.Timeout() {
			return capIngestAnswer{class: capTimeout}, nil
		}
	}
	return a, err
}

func capEngineFaults(env *Env, rep *Report) (map[string]string, error) {
	ctx := env.Ctx
	dir := filepath.Join(env.Work, "engine-faults")
	p := newCapPart(rep, "engine_faults")
	meter := &capMeter{total: 100 << 30}
	meter.set(50)
	cfg := storage.DefaultPressureConfig()
	cfg.Interval = 0
	site, err := capStartSite(env, dir, meter, cfg)
	if err != nil {
		return nil, err
	}
	defer func() { site.close() }()
	if err = site.bootstrap(ctx); err != nil {
		return nil, err
	}
	proj, err := site.project(ctx, "engine-faults")
	if err != nil {
		return nil, err
	}
	sw := &capEngineSwitch{}
	site.app.Storage.SetFaultHook(sw.hook)
	batches := map[string][]string{}
	clock := int64(1000)
	next := func(name string) (capHTTPBatch, error) {
		clock++
		b, err := site.batch(proj, false, clock, name)
		if err == nil {
			batches[b.id.String()] = []string{b.records[0].ID}
		}
		return b, err
	}
	// try sends once; an acknowledgement goes into the ledger, a refusal into the attempts and the timeline.
	try := func(b capHTTPBatch, label string, limit time.Duration) (capIngestAnswer, error) {
		a, err := site.sendWithin(proj, b, limit)
		if err != nil {
			return a, fmt.Errorf("%s: send %s: %w", p.name, label, err)
		}
		if a.class == capAck {
			return a, p.ack(b.id.String(), a.receipt, label)
		}
		p.refuse(b.id.String(), a.class, fmt.Sprintf("%s: http %d %s", label, a.status, capFaultText(a.reply)))
		return a, nil
	}
	outcome := func(b capHTTPBatch, a capIngestAnswer) capOutcome {
		return capOutcome{ID: b.id.String(), Digest: capDigest(b.records), Acked: a.class == capAck, Class: a.class}
	}
	// retry sends the SAME batch (same id, same bytes) after healing, then repeats it: the first
	// answer is an acknowledgement, the repeat carries the same receipt.
	retry := func(b capHTTPBatch, label string) error {
		a, err := try(b, label, 0)
		if err != nil {
			return err
		}
		if err = p.require(label+"_acknowledged", a.class == capAck, fmt.Sprintf("class %s http %d %s", a.class, a.status, capFaultText(a.reply))); err != nil {
			return err
		}
		rep.Timeline().Deliver(p.name, b.id.String()+" retried")
		again, err := site.send(proj, b)
		if err != nil {
			return err
		}
		same := capSameReceipt(a.receipt, again.receipt)
		detail := "the repeat carries the receipt of the first acknowledgement"
		if same != nil {
			detail = same.Error()
		}
		return p.require("repeat_returns_same_receipt:"+b.id.String(), again.class == capAck && same == nil, detail)
	}

	// Healthy: acknowledge a ledger before any fault.
	for i := range 6 {
		b, err := next("engine_acked_total")
		if err != nil {
			return nil, err
		}
		a, err := try(b, fmt.Sprintf("before_fault_%d", i), 0)
		if err != nil {
			return nil, err
		}
		if err = p.require(fmt.Sprintf("before_fault_ack_%d", i), a.class == capAck, fmt.Sprintf("http %d", a.status)); err != nil {
			return nil, err
		}
	}
	state := capAppState{site.app}
	ready, err := capReady(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("%s: readiness before the fault: %w", p.name, err)
	}
	if err = p.require("ready_before_fault", ready.Ready, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}

	// ---- failed sync: the engine's journal fsync step refuses ----
	sw.failSync.Store(true)
	var refused []capHTTPBatch
	var syncWindow []capOutcome
	for i := range 4 {
		b, err := next("engine_refused_total")
		if err != nil {
			return nil, err
		}
		refused = append(refused, b)
		a, err := try(b, fmt.Sprintf("during_sync_fault_%d", i), 0)
		if err != nil {
			return nil, err
		}
		syncWindow = append(syncWindow, outcome(b, a))
	}
	if err = p.require("no_ack_and_typed_refusal_while_the_engine_sync_fails", capVerifyWindow(syncWindow, false, nil) == nil, fmt.Sprint(capVerifyWindow(syncWindow, false, nil))); err != nil {
		return nil, err
	}
	if err = p.require("engine_hook_fired_at_wal_sync", sw.count("wal_sync") >= 1, fmt.Sprintf("%d injected wal_sync failures through storage.Engine", sw.count("wal_sync"))); err != nil {
		return nil, err
	}
	failed := false
	for _, st := range site.app.ReplicationStatus() {
		failed = failed || st.Failed
	}
	if err = p.require("a_group_of_the_engine_is_failed_after_the_sync_failure", failed, "replica status Failed is true for a group of the engine"); err != nil {
		return nil, err
	}
	// Healing the hook alone does not revive a failed group: the latch stays until a restart.
	sw.failSync.Store(false)
	late, err := next("engine_late_total")
	if err != nil {
		return nil, err
	}
	refused = append(refused, late)
	a, err := try(late, "after_heal_before_restart", 0)
	if err != nil {
		return nil, err
	}
	if err = p.require("healing_the_hook_alone_does_not_revive_the_engine", a.class != capAck && a.class.typedRefusal(), fmt.Sprintf("class %s http %d", a.class, a.status)); err != nil {
		return nil, err
	}
	site.app.Storage.SetFaultHook(nil)

	// Restart over the same files; the refused batches may have reached the journal before the
	// refused fsync, in which case they are committed on replay without ever having been acknowledged.
	if site, err = capReopen(env, site, meter, cfg); err != nil {
		return nil, fmt.Errorf("%s: reopen after the sync failure: %w", p.name, err)
	}
	site.app.Storage.SetFaultHook(sw.hook)
	if ready, err = capReady(ctx, capAppState{site.app}); err != nil {
		return nil, fmt.Errorf("%s: readiness after the sync failure restart: %w", p.name, err)
	}
	if err = p.require("restarted_engine_is_ready", ready.Ready, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	for i, b := range refused {
		if err = retry(b, fmt.Sprintf("sync_retry_%d", i)); err != nil {
			return nil, err
		}
	}

	// ---- slow apply: the engine's state machine is slow ----
	var slow []capHTTPBatch
	for range 12 {
		b, err := next("engine_slow_total")
		if err != nil {
			return nil, err
		}
		slow = append(slow, b)
	}
	sw.applyDelay.Store(int64(250 * time.Millisecond))
	started := time.Now()
	outcomes := make([]capOutcome, len(slow))
	answers := make([]capIngestAnswer, len(slow))
	errs := make([]error, len(slow))
	var wg sync.WaitGroup
	for i, b := range slow {
		limit := 150 * time.Millisecond // an impatient caller
		if i%4 == 0 {
			limit = 0 // a patient one
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i], errs[i] = site.sendWithin(proj, b, limit)
		}()
	}
	wg.Wait()
	sw.applyDelay.Store(0)
	acked, refusedSlow := 0, 0
	for i, b := range slow {
		if errs[i] != nil {
			return nil, errs[i]
		}
		a := answers[i]
		if a.class == capAck {
			if err = p.ack(b.id.String(), a.receipt, fmt.Sprintf("slow_apply_%d", i)); err != nil {
				return nil, err
			}
			acked++
		} else {
			p.refuse(b.id.String(), a.class, fmt.Sprintf("slow_apply_%d: http %d %s", i, a.status, capFaultText(a.reply)))
			refusedSlow++
		}
		outcomes[i] = outcome(b, a)
	}
	rep.Fact("engine_faults.slow_apply", map[string]any{"proposed": len(slow), "acked_in_window": acked, "refused_in_window": refusedSlow, "window_ms": time.Since(started).Milliseconds(), "delayed_applies": sw.count("before_apply")})
	if err = p.require("slow_apply_hook_fired_at_before_apply", sw.count("before_apply") >= 1, fmt.Sprintf("%d delayed before_apply calls through storage.Engine", sw.count("before_apply"))); err != nil {
		return nil, err
	}
	if err = p.require("slow_apply_caller_deadline_refusals_observed", refusedSlow >= 1, fmt.Sprintf("%d refused, %d acknowledged inside the window", refusedSlow, acked)); err != nil {
		return nil, err
	}
	if err = p.require("slow_apply_patient_callers_acknowledged", acked >= 1, fmt.Sprintf("%d acknowledged inside the window (reconciled against retained data after the reopen)", acked)); err != nil {
		return nil, err
	}
	if err = capWait("the engine to apply everything it accepted", 60*time.Second, func() bool {
		for _, st := range site.app.ReplicationStatus() {
			if st.Failed || st.Applied != st.LastIndex {
				return false
			}
		}
		return true
	}); err != nil {
		return nil, err
	}
	if ready, err = capReady(ctx, capAppState{site.app}); err != nil {
		return nil, fmt.Errorf("%s: readiness after slow apply: %w", p.name, err)
	}
	if err = p.require("ready_after_slow_apply_heals", ready.Ready, fmt.Sprintf("ready=%v reason=%q", ready.Ready, ready.Reason)); err != nil {
		return nil, err
	}
	for i, b := range slow {
		if err = retry(b, fmt.Sprintf("slow_retry_%d", i)); err != nil {
			return nil, err
		}
	}
	if err = rep.Timeline().Recover(p.name); err != nil {
		return nil, p.require("recovery_after_delivery", false, err.Error())
	}
	site.app.Storage.SetFaultHook(nil)

	// Close and reopen once more; what a fresh engine reads back is the retained data.
	if site, err = capReopen(env, site, meter, cfg); err != nil {
		return nil, fmt.Errorf("%s: final reopen: %w", p.name, err)
	}
	rows, err := site.readAll(ctx, proj)
	if err != nil {
		return nil, fmt.Errorf("%s: read back after the final reopen: %w", p.name, err)
	}
	retained := capFold(batches, rows)
	if err = p.require("sync_fault_window_verified_against_retained_data", capVerifyWindow(syncWindow, false, retained) == nil, fmt.Sprint(capVerifyWindow(syncWindow, false, retained))); err != nil {
		return nil, err
	}
	if err = p.require("slow_apply_window_acks_durable_refusals_typed", capVerifyWindow(outcomes, true, retained) == nil, fmt.Sprint(capVerifyWindow(outcomes, true, retained))); err != nil {
		return nil, err
	}
	if err = p.require("every_sent_batch_retained_once", len(retained) == len(batches) && len(rows) == len(batches), fmt.Sprintf("%d batches, %d retained batches, %d retained rows", len(batches), len(retained), len(rows))); err != nil {
		return nil, err
	}
	if err = p.reconcile("reconcile_after_reopen", retained); err != nil {
		return nil, err
	}
	return retained, nil
}
