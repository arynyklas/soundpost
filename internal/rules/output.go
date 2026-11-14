// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package rules

import (
	"context"
	"strconv"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
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
	admit   Admitter
	outbox  Outbox
	lookup  ReceiptLookup
	fencer  Fencer
	refresh ProducerResolver
}

// OutputOption configures an OutputWorker.
type OutputOption func(*OutputWorker)

// WithProducerRefresh lets the worker re-resolve the recording producer when
// admission reports the policy revision it built a batch for is out of date.
func WithProducerRefresh(r ProducerResolver) OutputOption {
	return func(w *OutputWorker) { w.refresh = r }
}

// NewOutputWorker builds a worker. Every dependency is required: a worker that
// cannot look a receipt up could not tell an ambiguous admission from a failed
// one, and one that cannot fence could release effects for a deposed leader.
func NewOutputWorker(admit Admitter, outbox Outbox, lookup ReceiptLookup, fencer Fencer, options ...OutputOption) (*OutputWorker, error) {
	if admit == nil || outbox == nil || lookup == nil || fencer == nil {
		return nil, model.Fail(model.Invalid)
	}
	w := &OutputWorker{admit: admit, outbox: outbox, lookup: lookup, fencer: fencer}
	for _, option := range options {
		option(w)
	}
	return w, nil
}

// ReasonSeriesConflict is the closed reason a derived series was dropped because
// it collides with an already-ingested sample of the same identity and time.
const ReasonSeriesConflict = "series_conflict"

// DroppedRecord reports one derived series that was dropped, never silently.
type DroppedRecord struct {
	Output model.ID
	Record model.ID
	Reason string
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
	// Dropped lists the derived series refused individually (a collision with an
	// already-ingested sample); the rest of their batch was still admitted.
	Dropped []DroppedRecord
}

// permanentAdmissionFailure reports whether an admission error can never succeed
// on retry for this batch: the source is gone or denied, or the batch itself is
// invalid or unsupported. A moved policy revision (Stale) and a collision with an
// ingested sample (Conflict) are not in this set: the first is cured by
// refreshing the producer, the second costs only the colliding series.
func permanentAdmissionFailure(err error) (string, bool) {
	switch faultCode(err) {
	case model.Forbidden, model.NotFound, model.Invalid, model.TooLarge, model.Unsupported:
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

func (w *OutputWorker) finalize(ctx context.Context, scope auth.Scope, lease replica.FenceToken, item control.RuleOutput, receipt model.Cursor, hash model.Hash, reason string, report *OutputReport) error {
	if _, err := w.outbox.Settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseFinalized, Receipt: &receipt, Hash: &hash, Reason: reason}); err != nil {
		return err
	}
	report.Finalized = append(report.Finalized, item.ID)
	report.Admitted = append(report.Admitted, receipt)
	return nil
}

// admission is what trying to admit one output's batch came to: a durable
// receipt, or the decision to try again later, or to give the output up.
type admission struct {
	receipt model.Receipt
	// split marks a receipt that is the last of several single-series admissions,
	// not of the output's own batch.
	split    bool
	dropped  []model.ID
	retry    bool
	suppress string
}

// lookupReceipt asks C03 whether the batch was in fact admitted.
func (w *OutputWorker) lookupReceipt(ctx context.Context, batch model.Batch) (model.Receipt, bool, error) {
	found, ok, err := w.lookup.LookupReceipt(ctx, batch)
	if err != nil || !ok {
		if ctx.Err() != nil {
			return model.Receipt{}, false, fenceFault(ctx.Err())
		}
		return model.Receipt{}, false, nil
	}
	return found, true, nil
}

// admitBatch admits one batch and classifies the failure of an admission that
// did not succeed:
//
//   - Stale: the policy revision the batch was built for moved. The batch may
//     have been admitted before it did (an ambiguous answer), so C03 is asked
//     first; otherwise the producer is re-resolved and the same batch is admitted
//     once at the current revision. Without a refresher the output simply stays
//     pending.
//   - Conflict: the batch collides with an already-ingested sample. Only the
//     colliding series are given up (admitSplit).
//   - Forbidden, NotFound, Invalid, TooLarge, Unsupported: permanent.
//   - anything else is transient or ambiguous: C03's receipt lookup decides.
func (w *OutputWorker) admitBatch(ctx context.Context, batch model.Batch, refreshed bool) (admission, error) {
	receipt, err := w.admit.Admit(ctx, batch)
	if err == nil {
		return admission{receipt: receipt}, nil
	}
	if ctx.Err() != nil {
		return admission{}, err
	}
	switch faultCode(err) {
	case model.Stale:
		found, ok, lerr := w.lookupReceipt(ctx, batch)
		if lerr != nil {
			return admission{}, lerr
		}
		if ok {
			return admission{receipt: found}, nil
		}
		if refreshed || w.refresh == nil {
			return admission{retry: true}, nil
		}
		identity, rerr := w.refresh(ctx)
		if rerr != nil {
			if ctx.Err() != nil {
				return admission{}, fenceFault(ctx.Err())
			}
			return admission{retry: true}, nil
		}
		if identity.Source != batch.Source || identity.Producer != batch.Producer {
			// The batch's slot and identity were derived for another producer.
			return admission{suppress: "admission_producer_changed"}, nil
		}
		if identity.PolicyRevision == batch.PolicyRevision {
			return admission{retry: true}, nil
		}
		batch.PolicyRevision = identity.PolicyRevision
		return w.admitBatch(ctx, batch, true)
	case model.Conflict:
		if len(batch.Records) > 1 {
			return w.admitSplit(ctx, batch)
		}
		return admission{suppress: "admission_conflict", dropped: recordIDs(batch)}, nil
	}
	if reason, permanent := permanentAdmissionFailure(err); permanent {
		return admission{suppress: reason}, nil
	}
	// Ambiguous or transient: the batch may or may not be durable. Ask C03.
	found, ok, lerr := w.lookupReceipt(ctx, batch)
	if lerr != nil {
		return admission{}, lerr
	}
	if !ok {
		return admission{retry: true}, nil
	}
	return admission{receipt: found}, nil
}

func recordIDs(batch model.Batch) []model.ID {
	ids := make([]model.ID, 0, len(batch.Records))
	for _, r := range batch.Records {
		ids = append(ids, r.ID)
	}
	return ids
}

// admitSplit admits a batch that collided, one series at a time, under stable
// derived batch identities (so a retry admits nothing twice). A series whose own
// admission collides is dropped and reported; every other series is admitted.
// The output's receipt is that of the last series admitted. With no series
// admitted the output is suppressed.
func (w *OutputWorker) admitSplit(ctx context.Context, batch model.Batch) (admission, error) {
	out := admission{split: true}
	admitted := 0
	for _, record := range batch.Records {
		single := batch
		single.Records = []model.Record{record}
		single.ID = derive("batch-split", batch.ID[:], record.ID[:])
		part, err := w.admitBatch(ctx, single, false)
		if err != nil {
			return admission{}, err
		}
		switch {
		case part.retry:
			return admission{retry: true}, nil
		case part.suppress == "admission_conflict":
			out.dropped = append(out.dropped, record.ID)
		case part.suppress != "":
			return admission{suppress: part.suppress}, nil
		default:
			out.receipt = part.receipt
			admitted++
		}
	}
	if admitted == 0 {
		return admission{suppress: "admission_conflict", dropped: out.dropped}, nil
	}
	return out, nil
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
		return w.finalize(ctx, scope, lease, item, *item.Receipt, *item.Hash, item.Reason, report)
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
	got, err := w.admitBatch(ctx, intent.Batch, false)
	if err != nil {
		return err
	}
	for _, id := range got.dropped {
		report.Dropped = append(report.Dropped, DroppedRecord{Output: item.ID, Record: id, Reason: ReasonSeriesConflict})
	}
	if got.suppress != "" {
		return w.suppress(ctx, scope, lease, item, got.suppress, report)
	}
	if got.retry {
		report.Retried = append(report.Retried, item.ID)
		return nil
	}
	receipt := got.receipt
	if !got.split && receipt.BatchID != intent.Batch.ID || receipt.Cursor.Group == (model.ID{}) || receipt.Hash == (model.Hash{}) {
		return model.Fail(model.Corrupt)
	}
	reason := ""
	if len(got.dropped) > 0 {
		reason = ReasonSeriesConflict + ":" + strconv.Itoa(len(got.dropped))
	}
	// Record the durable receipt, then finalize. A crash between the two leaves an
	// admitted output, which the next flush only finalizes.
	if _, err = w.outbox.Settle(ctx, scope, lease, item, control.RuleOutputApply{To: control.RulePhaseAdmitted, Receipt: &receipt.Cursor, Hash: &receipt.Hash, Reason: reason}); err != nil {
		return err
	}
	item.Phase, item.Receipt, item.Hash = control.RulePhaseAdmitted, &receipt.Cursor, &receipt.Hash
	return w.finalize(ctx, scope, lease, item, receipt.Cursor, receipt.Hash, reason, report)
}
