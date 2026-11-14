// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package notify

import (
	"context"
	"errors"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// Queue is the outbox surface the worker drives (*Outbox).
type Queue interface {
	Due(ctx context.Context, scope auth.Scope, lease FenceToken, at model.UnixNano, limit int) (int, error)
	Claim(ctx context.Context, scope auth.Scope, now model.UnixNano, lease FenceToken, limit int) ([]Delivery, error)
	Complete(ctx context.Context, scope auth.Scope, deliveryID model.ID, attempt uint32, outcome Outcome) error
	Cancel(ctx context.Context, scope auth.Scope, lease FenceToken, deliveryID model.ID, attempt uint32, reason string) error
	Hold(ctx context.Context, scope auth.Scope, deliveryID model.ID, now model.UnixNano) (string, error)
}

// RunError is one safe per-delivery failure of a run: the delivery, the step and a
// closed code. It never carries an error string, a provider message or a
// destination.
type RunError struct {
	Delivery model.ID
	Stage    string
	Code     string
}

// The stages of a RunError.
const (
	StageRevalidate = "revalidate"
	StageComplete   = "complete"
)

// RunReport says what one RunOnce did, by delivery ID.
type RunReport struct {
	// Fired is how many policy timers produced a decision.
	Fired int
	// Claimed are the deliveries leased by this run.
	Claimed []model.ID
	// Accepted were accepted by the provider, with provider evidence.
	Accepted []model.ID
	// Retried got a definite non-acceptance and will be retried.
	Retried []model.ID
	// Unknown may have been accepted by the provider and will be retried under the
	// same ID: a possible duplicate, never a success.
	Unknown []model.ID
	// Failed ended with a terminal failure or a missing channel.
	Failed []model.ID
	// Cancelled were not sent for a safe reason (deleted, destination disabled).
	Cancelled []model.ID
	// Paused were released unsent because a closing deletion covers their origin.
	Paused []model.ID
	// Errors are the steps that could not be recorded; the attempt stays open and
	// lapses to unknown.
	Errors []RunError
}

// WorkerOption configures a Worker.
type WorkerOption func(*Worker)

// WithSendTimeout bounds one provider send (default 30 seconds). It must be
// shorter than the outbox's lease TTL, or a slow send could outlive its claim.
func WithSendTimeout(d time.Duration) WorkerOption { return func(w *Worker) { w.timeout = d } }

// WithBatch bounds the deliveries claimed per run (default 16, at most MaxClaim).
// A smaller batch bounds how many claims a deposed worker leaves to lapse.
func WithBatch(n int) WorkerOption { return func(w *Worker) { w.batch = n } }

// maxTimers bounds the policy timers fired per run.
const maxTimers = 64

// Worker claims, revalidates, sends and completes deliveries. Provider sends
// happen here, through Sender, after the claim and outside every transaction.
type Worker struct {
	queue   Queue
	sender  Sender
	fencer  Fencer
	timeout time.Duration
	batch   int
}

// NewWorker builds a worker. Every dependency is required: a worker that could not
// fence would send for a deposed leader.
func NewWorker(queue Queue, sender Sender, fencer Fencer, opts ...WorkerOption) (*Worker, error) {
	if queue == nil || sender == nil || fencer == nil {
		return nil, model.Fail(model.Invalid)
	}
	w := &Worker{queue: queue, sender: sender, fencer: fencer, timeout: 30 * time.Second, batch: 16}
	for _, opt := range opts {
		opt(w)
	}
	if w.timeout <= 0 || w.batch < 1 || w.batch > MaxClaim {
		return nil, model.Fail(model.Invalid)
	}
	if q, ok := queue.(interface{ LeaseTTL() time.Duration }); ok && w.timeout >= q.LeaseTTL() {
		return nil, model.Fail(model.Invalid)
	}
	return w, nil
}

// faultCode is the closed code of a control or fence error.
func faultCode(err error) string {
	var f *model.Fault
	if errors.As(err, &f) {
		return string(f.Code)
	}
	if err != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return string(model.Cancelled)
	}
	return string(model.Unavailable)
}

// fatal reports an error that ends the whole run: the scope or the lease is no
// longer valid, or the run's own context ended. Everything else is local to one
// delivery.
func fatal(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	var f *model.Fault
	if errors.As(err, &f) {
		switch f.Code {
		case model.Stale, model.NotFound, model.Forbidden, model.Unauthenticated, model.Cancelled:
			return true
		}
	}
	return false
}

// normalize turns what a sender said into a safe, closed Outcome. Only an
// accepted outcome with observed provider evidence is accepted; a sender error
// and a timeout are unknown (the request may have reached the provider); a
// malformed outcome is unknown; nothing the sender printed is kept, only closed
// codes.
func normalize(o Outcome, err error) Outcome {
	if err != nil {
		code := "sender_error"
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			code = "timeout"
		case errors.Is(err, context.Canceled):
			code = "cancelled"
		}
		return Outcome{Kind: OutcomeUnknown, Code: code}
	}
	code := o.Code
	if !outcomeCode(code) {
		code = "unspecified"
	}
	retryAfter := o.RetryAfter
	if retryAfter < 0 {
		retryAfter = 0
	}
	if retryAfter > control.DeliveryMaxAge {
		retryAfter = control.DeliveryMaxAge
	}
	switch o.Kind {
	case OutcomeAccepted:
		if !providerID(o.ProviderID) {
			return Outcome{Kind: OutcomeUnknown, Code: "accepted_without_evidence"}
		}
		return Outcome{Kind: OutcomeAccepted, ProviderID: o.ProviderID}
	case OutcomeRetry:
		return Outcome{Kind: OutcomeRetry, Code: code, RetryAfter: retryAfter}
	case OutcomeUnknown:
		return Outcome{Kind: OutcomeUnknown, Code: code, RetryAfter: retryAfter}
	case OutcomeTerminal:
		return Outcome{Kind: OutcomeTerminal, Code: code}
	}
	return Outcome{Kind: OutcomeUnknown, Code: "invalid_outcome"}
}

// RunOnce is one pass under lease at the instant at: fire due policy timers, claim
// due deliveries, and for each one revalidate, send and complete.
//
// Before every send the worker (1) re-reads the delivery's committed hold: a
// closing deletion that covers its origin pauses it (the claim is released unsent
// as a definite retry), a deleted origin, a disabled or removed destination
// settles it with a safe reason; and (2) validates its lease against a fresh quorum
// observation again, so leadership lost between the claim and the send stops the
// run. The send itself is bounded by the send timeout. A completion that cannot be
// recorded leaves the attempt open; it lapses to unknown, never to success.
//
// RunOnce returns an error only when the run cannot continue (the lease or the
// scope is no longer valid, or ctx ended); per-delivery failures are in the
// report as safe codes. Claims it did not get to are left to lapse.
func (w *Worker) RunOnce(ctx context.Context, scope auth.Scope, at model.UnixNano, lease FenceToken) (RunReport, error) {
	var report RunReport
	if at <= 0 || validLease(lease) != nil {
		return report, model.Fail(model.Invalid)
	}
	fired, err := w.queue.Due(ctx, scope, lease, at, maxTimers)
	report.Fired = fired
	if err != nil {
		return report, err
	}
	items, err := w.queue.Claim(ctx, scope, at, lease, w.batch)
	if err != nil {
		return report, err
	}
	for _, d := range items {
		report.Claimed = append(report.Claimed, d.ID)
	}
	for _, d := range items {
		if err = ctx.Err(); err != nil {
			return report, model.Fail(model.Cancelled)
		}
		if err = w.deliver(ctx, scope, at, lease, d, &report); err != nil {
			return report, err
		}
	}
	return report, nil
}

func (w *Worker) deliver(ctx context.Context, scope auth.Scope, at model.UnixNano, lease FenceToken, d Delivery, report *RunReport) error {
	hold, err := w.queue.Hold(ctx, scope, d.ID, at)
	if err != nil {
		if fatal(ctx, err) {
			return err
		}
		report.Errors = append(report.Errors, RunError{Delivery: d.ID, Stage: StageRevalidate, Code: faultCode(err)})
		return nil
	}
	switch hold {
	case "":
	case control.DeliveryHoldPaused:
		// A closing deletion pauses derived sends: release the claim as a definite
		// non-send. The delivery keeps its ID and resumes if the deletion fails.
		if err = w.queue.Complete(ctx, scope, d.ID, d.Attempt, Outcome{Kind: OutcomeRetry, Code: control.DeliveryHoldPaused}); err != nil {
			return w.completeFailed(ctx, d, err, report)
		}
		report.Paused = append(report.Paused, d.ID)
		return nil
	default:
		if err = w.queue.Cancel(ctx, scope, lease, d.ID, d.Attempt, hold); err != nil {
			return w.completeFailed(ctx, d, err, report)
		}
		if hold == control.DeliveryReasonNoDestination {
			report.Failed = append(report.Failed, d.ID)
		} else {
			report.Cancelled = append(report.Cancelled, d.ID)
		}
		return nil
	}
	// Leadership may have moved since the claim, or while earlier deliveries of this
	// run were sent: validate the lease again immediately before the external effect.
	if err = w.fencer.ValidateFence(ctx, lease); err != nil {
		return fenceFault(err)
	}
	sendCtx, cancel := context.WithTimeout(ctx, w.timeout)
	sent, sendErr := w.sender.Send(sendCtx, scope, d)
	cancel()
	outcome := normalize(sent, sendErr)
	// The request may have been accepted and cannot be recalled: record the outcome
	// even when the run itself is being cancelled.
	completeCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer done()
	if err = w.queue.Complete(completeCtx, scope, d.ID, d.Attempt, outcome); err != nil {
		return w.completeFailed(ctx, d, err, report)
	}
	switch outcome.Kind {
	case OutcomeAccepted:
		report.Accepted = append(report.Accepted, d.ID)
	case OutcomeRetry:
		report.Retried = append(report.Retried, d.ID)
	case OutcomeUnknown:
		report.Unknown = append(report.Unknown, d.ID)
	default:
		report.Failed = append(report.Failed, d.ID)
	}
	return nil
}

// completeFailed records a step that could not be committed. The attempt stays
// open. A lease or scope that is no longer valid ends the run, anything else is
// local to this delivery.
func (w *Worker) completeFailed(ctx context.Context, d Delivery, err error, report *RunReport) error {
	report.Errors = append(report.Errors, RunError{Delivery: d.ID, Stage: StageComplete, Code: faultCode(err)})
	if fatal(ctx, err) {
		return err
	}
	return nil
}
