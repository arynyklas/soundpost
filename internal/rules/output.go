// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Admitter durably admits one recording batch through C03 (normalization against
// the recording source's current policy, quota reservation, data-group append).
// Re-admitting a batch already admitted returns its original receipt: the
// identity of a batch is stable, so admission is idempotent end to end.
type Admitter interface {
	Admit(ctx context.Context, batch model.Batch) (model.Receipt, error)
}

// ReceiptLookup is C03's authenticated historical receipt lookup: after an
// admission whose outcome is ambiguous (a timeout, a lost response, an
// unavailable group) it answers whether the batch was in fact admitted.
// found=false means no receipt exists for it; absence is not proof the batch can
// never commit, which is why the output stays pending and is re-admitted.
type ReceiptLookup interface {
	LookupReceipt(ctx context.Context, batch model.Batch) (receipt model.Receipt, found bool, err error)
}

// Outbox is the control-backed internal output outbox (*OutboxStore).
type Outbox interface {
	Pending(ctx context.Context, scope auth.Scope, limit int) ([]control.RuleOutput, error)
	Settle(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, update control.RuleOutputApply) (control.Result, error)
}

// OutputWorker releases the recording outputs of committed evaluations: it
// admits each stable batch, records the durable receipt, and finalizes the
// output. It is not a second evaluator or outbox, and condition outputs are left
// untouched for the incident side to consume.
//
// Nothing here is atomic across the data group and control, by design. The order
// is admit (idempotent) -> record the receipt -> finalize, and every crash
// leaves one of three states, each resumable: nothing recorded (re-admit, which
// returns the same receipt), receipt recorded (finalize), finalized (done).
type OutputWorker struct {
	admit  Admitter
	outbox Outbox
	lookup ReceiptLookup
	fencer Fencer
}

// NewOutputWorker builds a worker. Every dependency is required: a worker that
// cannot look a receipt up could not tell an ambiguous admission from a failed
// one, and one that cannot fence could release effects for a deposed leader.
func NewOutputWorker(admit Admitter, outbox Outbox, lookup ReceiptLookup, fencer Fencer) (*OutputWorker, error) {
	if admit == nil || outbox == nil || lookup == nil || fencer == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &OutputWorker{admit: admit, outbox: outbox, lookup: lookup, fencer: fencer}, nil
}

// OutputReport says what one Flush did, by output ID.
type OutputReport struct {
	// Finalized outputs are admitted and complete.
	Finalized []model.ID
	// Retried outputs stay pending: admission failed transiently or ambiguously
	// and no receipt could be found.
	Retried []model.ID
	// Suppressed outputs were obsolete (a deletion or retirement covers their
	// origin) or permanently refused by admission, and were retired unreleased.
	Suppressed []model.ID
	// Admitted are the data-group cursors of the receipts of the outputs finalized
	// by this flush.
	Admitted []model.Cursor
}

// permanentAdmissionFailure reports whether an admission error can never succeed
// on retry for this batch: the source is gone or denied, its policy revision
// moved, or the batch itself is invalid.
func permanentAdmissionFailure(err error) (string, bool) {
	switch faultCode(err) {
	case model.Forbidden, model.NotFound, model.Stale, model.Invalid, model.TooLarge, model.Conflict, model.Unsupported:
		return "admission_" + string(faultCode(err)), true
	}
	return "", false
}

// Flush releases up to limit of the scope's project's pending recording
// outputs, in (scheduled time, ID) order, under lease. The lease is validated
// against a fresh quorum observation before any output is released, and every
// control update carries it.
func (w *OutputWorker) Flush(ctx context.Context, scope auth.Scope, lease replica.FenceToken, limit int) (OutputReport, error) {
	var report OutputReport
	if limit <= 0 || lease.Group == (model.ID{}) || lease.Term == 0 {
		return report, model.Fail(model.Invalid)
	}
	if err := w.fencer.ValidateFence(ctx, lease); err != nil {
		return report, fenceFault(err)
	}
	items, err := w.outbox.Pending(ctx, scope, limit)
	if err != nil {
		return report, err
	}
	for _, item := range items {
		if err = ctx.Err(); err != nil {
			return report, model.Fail(model.Cancelled)
		}
		if err = w.release(ctx, scope, lease, item, &report); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (w *OutputWorker) suppress(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, reason string, report *OutputReport) error {
	if _, err := w.outbox.Settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseSuppress, Reason: reason}); err != nil {
		return err
	}
	report.Suppressed = append(report.Suppressed, item.ID)
	return nil
}

func (w *OutputWorker) finalize(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, receipt model.Cursor, hash model.Hash, report *OutputReport) error {
	if _, err := w.outbox.Settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseFinalized, Receipt: &receipt, Hash: &hash}); err != nil {
		return err
	}
	report.Finalized = append(report.Finalized, item.ID)
	report.Admitted = append(report.Admitted, receipt)
	return nil
}

func (w *OutputWorker) release(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, report *OutputReport) error {
	// An obsolete intent is suppressed before release even when it was admitted
	// partway: a deletion that now covers its origin governs, not the outbox.
	if item.Obsolete && item.Phase == control.RulePhasePending {
		return w.suppress(ctx, scope, lease, item, "obsolete_origin", report)
	}
	if item.Phase == control.RulePhaseAdmitted {
		// The receipt was recorded before a crash: only finalization is left.
		if item.Receipt == nil || item.Hash == nil {
			return model.Fail(model.Corrupt)
		}
		return w.finalize(ctx, scope, lease, item, *item.Receipt, *item.Hash, report)
	}
	var intent RecordingIntent
	if model.StrictJSON(item.Payload, &intent) != nil || intent.ID != item.ID || len(intent.Batch.Records) == 0 {
		return model.Fail(model.Corrupt)
	}
	// Re-fence immediately before the external effect: leadership may have moved
	// while earlier outputs of this flush were being released.
	if err := w.fencer.ValidateFence(ctx, lease); err != nil {
		return fenceFault(err)
	}
	receipt, err := w.admit.Admit(ctx, intent.Batch)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		if reason, permanent := permanentAdmissionFailure(err); permanent {
			return w.suppress(ctx, scope, lease, item, reason, report)
		}
		// Ambiguous or transient: the batch may or may not be durable. Ask C03.
		found, ok, lerr := w.lookup.LookupReceipt(ctx, intent.Batch)
		if lerr != nil || !ok {
			if ctx.Err() != nil {
				return fenceFault(ctx.Err())
			}
			report.Retried = append(report.Retried, item.ID)
			return nil
		}
		receipt = found
	}
	if receipt.BatchID != intent.Batch.ID || receipt.Cursor.Group == (model.ID{}) || receipt.Hash == (model.Hash{}) {
		return model.Fail(model.Corrupt)
	}
	// Record the durable receipt, then finalize. A crash between the two leaves an
	// admitted output, which the next flush only finalizes.
	if _, err = w.outbox.Settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseAdmitted, Receipt: &receipt.Cursor, Hash: &receipt.Hash}); err != nil {
		return err
	}
	item.Phase, item.Receipt, item.Hash = control.RulePhaseAdmitted, &receipt.Cursor, &receipt.Hash
	return w.finalize(ctx, scope, lease, item, receipt.Cursor, receipt.Hash, report)
}
