// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/notify"
)

// Rollback hands the one normal-notification owner back to the old owner. The
// order is the point:
//
//	new_owner_quiesced   engine rollback_quiescing (nothing active), the new owner drains,
//	                     unknown provider outcomes are recorded explicitly
//	old_owner_recorded   engine old_active: the old owner is recorded BEFORE it is re-enabled
//	old_route_restored   the legacy operator re-enables ITS NORMAL ROUTE, exactly once
//
// At no instant between the phases are both senders enabled: the new owner has
// stopped before the old one is recorded, and the old one is recorded before it
// is re-enabled. A rollback of a cutover that never reached the new owner
// (incomplete, or blocked before activation) is the engine's abort to shadow and
// the same restore. Nothing here deletes or reconfigures the new product or the
// legacy system beyond the normal route.

// The durable rollback phases, in order.
const (
	rollbackStepNewQuiesced = "new_owner_quiesced"
	rollbackStepOldRecorded = "old_owner_recorded"
	rollbackStepOldRestored = "old_route_restored"
)

var rollbackSteps = []string{rollbackStepNewQuiesced, rollbackStepOldRecorded, rollbackStepOldRestored}

// Closed classes of a rollback reason.
const (
	RollbackReasonOperator    = "operator_requested"
	RollbackReasonGap         = "delivery_gap"
	RollbackReasonDuplicate   = "duplicate_delivery"
	RollbackReasonDestination = "destination_failure"
	RollbackReasonIncomplete  = "incomplete_cutover"
	RollbackReasonOther       = "other"
)

var rollbackReasonCodes = []string{RollbackReasonOperator, RollbackReasonGap, RollbackReasonDuplicate, RollbackReasonDestination, RollbackReasonIncomplete, RollbackReasonOther}

// rollbackState is the rollback progress persisted in the run's state file.
type rollbackState struct {
	Reason          Reason          `json:"reason"`
	Completed       []string        `json:"completed"`
	Phase           string          `json:"phase"`
	IncompleteCode  string          `json:"incomplete_code,omitempty"`
	Unknown         RollbackUnknown `json:"unknown"`
	OldRouteEnabled bool            `json:"old_route_enabled"`
	DeadmanArmed    bool            `json:"deadman_armed"`
}

// errRollbackAlreadyDone is returned, with the original receipt, when a finished
// rollback is requested again.
var errRollbackAlreadyDone = errors.New("rollback already done; refusing to run it again")

func rollbackValidateReason(r Reason) error {
	if !slices.Contains(rollbackReasonCodes, r.Code) {
		return errors.New("invalid rollback reason code")
	}
	if r.Text == "" || len(r.Text) > 512 || !utf8.ValidString(r.Text) {
		return errors.New("invalid rollback reason text")
	}
	for _, c := range r.Text {
		if c < 0x20 || c == 0x7f {
			return errors.New("invalid rollback reason text")
		}
	}
	return nil
}

type rollbackDriver struct {
	*cutoverDriver
	reason Reason
}

func (d *rollbackDriver) guard() error {
	if err := cutoverAuthorize(d.grant, d.plan.Scope, cutoverActionRollback, d.rt.Now()); err != nil {
		return cutoverStopErr(CutoverIncompleteGuard, "authorization", err)
	}
	return nil
}

// waitDrained waits until the engine reports no live claim: the new owner has
// quiesced. It ends with the context.
func (d *rollbackDriver) waitDrained(ctx context.Context) error {
	for {
		facts, err := d.rt.Engine.Facts(ctx, d.rt.Scope)
		if err != nil {
			return cutoverFail(err)
		}
		if facts.Claimed == 0 {
			return nil
		}
		timer := time.NewTimer(d.rt.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return cutoverStopErr(cutoverClassify(ctx.Err()), "the new owner still holds live claims", ctx.Err())
		case <-timer.C:
		}
	}
}

// quiesceNew stops the new owner and records what stays unresolved.
func (d *rollbackDriver) quiesceNew(ctx context.Context) error {
	es, found, err := d.engineState(ctx)
	if err != nil {
		return err
	}
	draining := false
	if found {
		switch es.Phase {
		case notify.CutoverNewActive:
			if _, err = d.advance(ctx, cutoverCmdRbQuiesce, notify.CutoverRollbackQuiescing, nil); err != nil {
				return err
			}
			draining = true
		case notify.CutoverRollbackQuiescing:
			draining = true
		case notify.CutoverOldActive, notify.CutoverShadow:
			// the new owner never sent, or already handed back
		case notify.CutoverQuiescingOld, notify.CutoverBarrierVerified:
			// abort: the new owner was never active
			if _, err = d.advance(ctx, cutoverCmdRbAbort, notify.CutoverShadow, nil); err != nil {
				return err
			}
		default:
			return cutoverStopErr(CutoverIncompleteEngine, "the engine cutover is at "+string(es.Phase), nil)
		}
	}
	if !draining {
		return nil
	}
	if err = d.waitDrained(ctx); err != nil {
		return err
	}
	facts, err := d.rt.Engine.Facts(ctx, d.rt.Scope)
	if err != nil {
		return cutoverFail(err)
	}
	delivered, err := d.rt.Route.Delivered(ctx)
	if err != nil {
		return cutoverFail(err)
	}
	seen := map[string]bool{}
	var ids []string
	for _, item := range delivered {
		if item.Outcome == CutoverOutcomeUnknown && !seen[item.ID] {
			seen[item.ID] = true
			ids = append(ids, item.ID)
		}
	}
	sort.Strings(ids)
	rb := d.st.Rollback
	rb.Unknown = RollbackUnknown{Engine: facts.Unknown, RouteIDs: ids, Reviewed: d.reason.UnknownReviewed}
	if (facts.Unknown > 0 || len(ids) > 0) && !d.reason.UnknownReviewed {
		return cutoverStopErr(CutoverIncompleteUnknown, "unknown provider outcomes are recorded and need review before the old owner is restored", nil)
	}
	return nil
}

// recordOld records the old owner as the active owner in the engine, before the
// legacy route is re-enabled.
func (d *rollbackDriver) recordOld(ctx context.Context) error {
	es, found, err := d.engineState(ctx)
	if err != nil || !found {
		return err
	}
	switch es.Phase {
	case notify.CutoverOldActive, notify.CutoverShadow:
		return nil
	case notify.CutoverRollbackQuiescing:
	default:
		return cutoverStopErr(CutoverIncompleteEngine, "the engine cutover is at "+string(es.Phase), nil)
	}
	next, err := d.advance(ctx, cutoverCmdRbRecord, notify.CutoverOldActive, func(es notify.CutoverState) (*notify.BarrierEvidence, error) {
		if es.Phase != notify.CutoverRollbackQuiescing {
			return nil, cutoverStopErr(CutoverIncompleteEngine, "the engine is at "+string(es.Phase)+", not quiescing the new owner", nil)
		}
		proof, err := d.deadmanProof(ctx)
		if err != nil {
			return nil, err
		}
		facts, err := d.rt.Engine.Facts(ctx, d.rt.Scope)
		if err != nil {
			return nil, cutoverFail(err)
		}
		ev := d.evidence(es, facts, nil, proof)
		ev.Accounting.Reviewed = d.reason.UnknownReviewed
		return ev, nil
	})
	if err != nil {
		return err
	}
	if next.Phase != notify.CutoverOldActive {
		return cutoverStopErr(CutoverIncompleteEngine, "the old owner was not recorded", nil)
	}
	return nil
}

// restoreOld re-enables the legacy normal route, once, and only while the
// engine reports exactly the old owner as the active owner: never while the new
// owner is active or quiescing, and never before the old owner is recorded.
func (d *rollbackDriver) restoreOld(ctx context.Context) error {
	es, found, err := d.engineState(ctx)
	if err != nil {
		return err
	}
	if found && !slices.Equal(notify.ActiveOwners(es.Phase, d.plan.OldOwner, d.plan.NewOwner), []model.ID{d.plan.OldOwner}) {
		return cutoverStopErr(CutoverIncompleteEngine, "the engine does not report exactly the old owner as active (phase "+string(es.Phase)+")", nil)
	}
	obs, err := d.rt.Legacy.Observe(ctx, d.plan.OldOwner)
	if err != nil {
		return cutoverFail(err)
	}
	if !obs.Enabled {
		id := cutoverCommandID(d.plan.RunID, cutoverCmdLegacyR).String()
		res, err := d.rt.Legacy.RestoreNormal(ctx, CutoverLegacyCommand{ID: id, Owner: d.plan.OldOwner})
		if err != nil {
			return cutoverFail(err)
		}
		if res.CommandID != id {
			return cutoverStopErr(CutoverIncompleteLegacyUnexpected, "the restore acknowledgement answers another command", nil)
		}
	}
	final, err := d.rt.Legacy.Observe(ctx, d.plan.OldOwner)
	if err != nil {
		return cutoverFail(err)
	}
	if err = d.legacyState(final, "", time.Time{}); err != nil {
		return err
	}
	if !final.Enabled {
		return cutoverStopErr(CutoverIncompleteLegacyUnexpected, "the old normal route is not enabled after the restore", nil)
	}
	rb := d.st.Rollback
	rb.OldRouteEnabled = true // observed enabled just above, or the restore step stopped
	if _, err = d.deadmanProof(ctx); err != nil {
		rb.DeadmanArmed = false
		return err
	}
	rb.DeadmanArmed = true
	return nil
}

func (d *rollbackDriver) run(ctx context.Context, step string) error {
	switch step {
	case rollbackStepNewQuiesced:
		return d.quiesceNew(ctx)
	case rollbackStepOldRecorded:
		return d.recordOld(ctx)
	default:
		return d.restoreOld(ctx)
	}
}

func (d *rollbackDriver) receipt(ctx context.Context) RollbackReceipt {
	rb := d.st.Rollback
	r := RollbackReceipt{Version: 1, RunID: d.plan.RunID, Scope: d.plan.Scope, PlanDigest: d.st.PlanDigest, StatePath: d.plan.StatePath, StateVersion: d.st.Version,
		Phase: rb.Phase, Completed: append([]string{}, rb.Completed...), IncompleteCode: rb.IncompleteCode, ReasonCode: rb.Reason.Code, ActiveOwners: []model.ID{},
		OldRouteEnabled: rb.OldRouteEnabled, DeadmanArmed: rb.DeadmanArmed, Unknown: rb.Unknown, Blockers: []CutoverBlocker{}}
	r.Unknown.RouteIDs = append([]string(nil), rb.Unknown.RouteIDs...)
	if rb.IncompleteCode == CutoverIncompleteUnknown {
		r.Blockers = append(r.Blockers, CutoverBlocker{Code: CutoverIncompleteUnknown, Count: int(rb.Unknown.Engine) + len(rb.Unknown.RouteIDs)})
	}
	if es, found, err := d.rt.Engine.Cutover(context.WithoutCancel(ctx), d.rt.Scope); err == nil && found {
		r.EnginePhase, r.EngineRevision = string(es.Phase), es.Revision
		r.ActiveOwners = append(r.ActiveOwners, notify.ActiveOwners(es.Phase, d.plan.OldOwner, d.plan.NewOwner)...)
	}
	return r
}

func (d *rollbackDriver) stop(ctx context.Context, step string, cause error) (RollbackReceipt, error) {
	rb := d.st.Rollback
	rb.Phase = CutoverPhaseIncomplete
	rb.IncompleteCode = cutoverStopCodeCtx(ctx, cause)
	if err := cutoverSaveState(d.st); err != nil {
		return d.receipt(ctx), fmt.Errorf("rollback stopped at %s (%w) and the state could not be saved: %v", step, cause, err)
	}
	return d.receipt(ctx), fmt.Errorf("rollback incomplete at %s: %w", step, cause)
}

// Rollback quiesces the new owner FIRST, records the old owner, and only then
// re-enables exactly one old normal route, recording unresolved or unknown
// provider outcomes explicitly. It needs the receipt of the cutover to roll
// back, an explicit reason and an authorization that permits "rollback" for the
// run's scope; it needs no ready gate, so an expired gate never blocks a
// rollback. It resumes after a crash or timeout with the same command IDs; the
// resume must repeat the same reason (the unknown-outcome attestation may be
// raised). The runtime travels in ctx (CutoverWithRuntime).
func Rollback(ctx context.Context, receipt CutoverReceipt, reason Reason, grant Authorization) (RollbackReceipt, error) {
	rt, err := cutoverRuntimeFrom(ctx, false)
	if err != nil {
		return RollbackReceipt{}, err
	}
	refuse := func(err error) (RollbackReceipt, error) {
		return RollbackReceipt{}, fmt.Errorf("rollback refused: %w", err)
	}
	if err = rollbackValidateReason(reason); err != nil {
		return refuse(err)
	}
	if receipt.StatePath == "" || !filepath.IsAbs(receipt.StatePath) {
		return refuse(errors.New("the receipt names no state file"))
	}
	st, err := cutoverLoadState(receipt.StatePath)
	if err != nil {
		return refuse(err)
	}
	if st == nil {
		return refuse(errors.New("no cutover state for this receipt"))
	}
	if receipt.RunID != st.Plan.RunID || receipt.PlanDigest != st.PlanDigest || receipt.Scope != st.Plan.Scope || st.Plan.StatePath != receipt.StatePath {
		return refuse(errors.New("the receipt is not this state file's run"))
	}
	if err = cutoverResumeCheck(st, st.Plan, st.PlanDigest); err != nil {
		return refuse(err)
	}
	if err = cutoverAuthorize(grant, st.Plan.Scope, cutoverActionRollback, rt.Now()); err != nil {
		return refuse(err)
	}
	authBytes, err := json.Marshal(grant)
	if err != nil {
		return refuse(err)
	}
	d := &rollbackDriver{cutoverDriver: &cutoverDriver{rt: rt, plan: st.Plan, grant: grant, st: st, authRef: model.Hash(sha256.Sum256(authBytes)), reason: reason.Text}, reason: reason}
	if st.Rollback == nil {
		// the attestation is the call's, not the run's: it is never persisted
		st.Rollback = &rollbackState{Reason: Reason{Code: reason.Code, Text: reason.Text}, Completed: []string{}, Phase: CutoverPhaseIncomplete}
		if err = cutoverSaveState(st); err != nil {
			return refuse(err)
		}
	} else {
		rb := st.Rollback
		if rb.Reason.Code != reason.Code || rb.Reason.Text != reason.Text {
			return refuse(errors.New("the reason differs from the rollback in progress"))
		}
		if rb.Phase == CutoverPhaseDone {
			return d.receipt(ctx), errRollbackAlreadyDone
		}
	}
	for _, step := range rollbackSteps {
		if slices.Contains(st.Rollback.Completed, step) {
			continue
		}
		if err = d.guard(); err == nil {
			err = d.run(ctx, step)
		}
		if err != nil {
			return d.stop(ctx, step, cutoverFail(err))
		}
		rb := st.Rollback
		rb.Completed = append(rb.Completed, step)
		rb.IncompleteCode = ""
		if step == rollbackStepOldRestored {
			rb.Phase = CutoverPhaseDone
		}
		if err = cutoverSaveState(st); err != nil {
			return d.receipt(ctx), fmt.Errorf("rollback phase %s done but the state could not be saved: %w", step, err)
		}
	}
	return d.receipt(ctx), nil
}

// RollbackPublic is the closed public projection of a rollback: enums and
// counts only.
type RollbackPublic struct {
	SchemaVersion      int            `json:"schema_version"`
	Phase              string         `json:"phase"`
	PhasesRequired     int            `json:"phases_required"`
	PhasesCompleted    int            `json:"phases_completed"`
	IncompleteCode     string         `json:"incomplete_code"`
	ReasonCode         string         `json:"reason_code"`
	ActiveOwners       int            `json:"active_owners"`
	NewOwnerQuiesced   bool           `json:"new_owner_quiesced"`
	OldRouteRestored   bool           `json:"old_route_restored"`
	UnknownOutcomes    int            `json:"unknown_outcomes"`
	UnknownReviewed    bool           `json:"unknown_reviewed"`
	DeadmanArmed       bool           `json:"deadman_armed"`
	BlockerCounts      []CutoverCount `json:"blocker_counts"`
	CustomerAcceptance bool           `json:"customer_acceptance"`
}

// RollbackPublicSummary projects a receipt onto the closed public shape.
func RollbackPublicSummary(r RollbackReceipt) RollbackPublic {
	p := RollbackPublic{SchemaVersion: 1, Phase: r.Phase, PhasesRequired: len(rollbackSteps), PhasesCompleted: len(r.Completed), IncompleteCode: r.IncompleteCode,
		ReasonCode: r.ReasonCode, ActiveOwners: len(r.ActiveOwners), NewOwnerQuiesced: slices.Contains(r.Completed, rollbackStepNewQuiesced),
		OldRouteRestored: slices.Contains(r.Completed, rollbackStepOldRestored), UnknownOutcomes: int(r.Unknown.Engine) + len(r.Unknown.RouteIDs),
		UnknownReviewed: r.Unknown.Reviewed, DeadmanArmed: r.DeadmanArmed, BlockerCounts: []CutoverCount{}}
	for _, b := range r.Blockers {
		if b.Count > 0 {
			p.BlockerCounts = append(p.BlockerCounts, CutoverCount{Code: b.Code, Count: b.Count})
		}
	}
	return p
}

// runRollback is the `rollback` subcommand. The parent dispatches
// `adoption rollback <flags>` by passing the flags (without the subcommand name).
//
//	--receipt FILE                  the CutoverReceipt JSON of the run to roll back (private)
//	--authorization FILE            private grant: not read-only, one scope naming the run's scope, collector "rollback"
//	--reason-code CODE              operator_requested|delivery_gap|duplicate_delivery|destination_failure|incomplete_cutover|other
//	--reason-text TEXT              explicit operator reason, 1 to 512 printable bytes (private)
//	--unknown-reviewed              attest that the recorded unknown provider outcomes were reviewed
//	--private-directory DIRECTORY   the operator-private directory holding the run's state file
//	--public-summary FILE           new file for the closed public projection
//	--private-directory-acl-confirmed  operator verified the NTFS ACL (Windows)
//	--timeout DURATION              overall deadline, positive, at most 1h (default 10m)
//
// Each invocation writes DIRECTORY/rollback-RUNID.receipt-vN.json (N is the
// state version).
func runRollback(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	receiptPath := fs.String("receipt", "", "cutover receipt JSON")
	grantPath := fs.String("authorization", "", "private authorization JSON")
	code := fs.String("reason-code", "", "closed reason class")
	text := fs.String("reason-text", "", "explicit operator reason")
	reviewed := fs.Bool("unknown-reviewed", false, "unknown provider outcomes were reviewed")
	dir := fs.String("private-directory", "", "existing operator-private directory")
	summaryPath := fs.String("public-summary", "", "new public summary file")
	acl := fs.Bool("private-directory-acl-confirmed", false, "operator verified restrictive NTFS ACL")
	timeout := fs.Duration("timeout", 10*time.Minute, "overall deadline (positive, at most 1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !nonempty(*receiptPath, *grantPath, *code, *text, *dir, *summaryPath) {
		return errors.New("usage: adoption rollback --receipt FILE --authorization FILE --reason-code CODE --reason-text TEXT --private-directory DIRECTORY --public-summary FILE")
	}
	if *timeout <= 0 || *timeout > time.Hour {
		return errors.New("timeout must be positive and at most 1h")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	var receipt CutoverReceipt
	var grant Authorization
	if readInput(*receiptPath, &receipt) != nil || readInput(*grantPath, &grant) != nil {
		return errors.New("invalid private operator input")
	}
	resolved, err := privateDirectory(ctx, *dir, nil, *acl)
	if err != nil {
		return err
	}
	stateDir, err := canonical(filepath.Dir(receipt.StatePath))
	if err != nil || !samePath(stateDir, resolved) {
		return errors.New("the receipt's state file is not in the private directory")
	}
	st, err := cutoverLoadState(receipt.StatePath)
	if err != nil || st == nil {
		return errors.New("no readable cutover state for this receipt")
	}
	rt, err := cutoverConnect(ctx, CutoverConnectTarget{Scope: st.Plan.Scope, Environment: st.Plan.Environment, Project: st.Plan.Project})
	if err != nil {
		return err
	}
	if rt.Now == nil {
		rt.Now = func() time.Time { return time.Now().UTC() }
	}
	rb, runErr := Rollback(CutoverWithRuntime(ctx, rt), receipt, Reason{Code: *code, Text: *text, UnknownReviewed: *reviewed}, grant)
	if rb.Version == 0 || errors.Is(runErr, errRollbackAlreadyDone) {
		return runErr
	}
	out := filepath.Join(resolved, fmt.Sprintf("rollback-%s.receipt-v%d.json", rb.RunID, rb.StateVersion))
	if err = writeExclusive(out, rb); err != nil {
		return errors.New("private receipt creation failed")
	}
	if err = writeExclusive(*summaryPath, RollbackPublicSummary(rb)); err != nil {
		return errors.New("summary creation failed; private receipt retained")
	}
	return runErr
}
