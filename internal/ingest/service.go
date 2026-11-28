// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import "bytes"
import (
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
	"io"
	"sync/atomic"
	"time"
)

type Batch = model.Batch
type Record = model.Record
type Kind = model.Kind
type Payload = model.Payload
type Receipt = model.Receipt
type ReceiptRequest = model.ReceiptRequest
type NormalizedBatch = model.NormalizedBatch
type SignalDeadline = model.SignalDeadline
type SourceGrant = policy.SourceGrant
type SourceCredential = auth.SourceCredential
type Appender interface {
	Append(context.Context, auth.Scope, model.NormalizedBatch) (model.Receipt, error)
	LookupReceipt(context.Context, auth.Scope, model.ReceiptRequest) (model.Receipt, error)
}
type Quota interface {
	ReserveAdmission(context.Context, auth.Scope, model.NormalizedBatch) (model.AdmissionReservation, error)
	FinalizeAdmission(context.Context, auth.Scope, model.FinalizeAdmission) error
}

// Preflighter is optionally implemented by an Appender: the refusals Append would
// make before it stores anything, run without storing or charging anything. Admit
// calls it before ReserveAdmission. Append keeps its own check, because the state
// it reads can change between the two.
type Preflighter interface {
	Preflight(context.Context, auth.Scope, model.NormalizedBatch) error
}
type Service struct {
	auth     *auth.Service
	policy   *policy.Service
	quota    Quota
	appender Appender
	replay   ReplayGate
	// inFlight is how many ingest requests the process is working on (Enter).
	inFlight atomic.Int64
}

// ReplayGate is the closed-format check for one replay chunk (the chain and
// checkpoint rules, the recorder version and the masked-node format). It is
// injected, not imported, so the agent and conformance binaries that link
// ingest do not link the replay reader and the storage engine behind it.
type ReplayGate func(model.ReplayChunk) error

func New(a *auth.Service, p *policy.Service, q Quota, w Appender) (*Service, error) {
	if a == nil || p == nil || q == nil || w == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{auth: a, policy: p, quota: q, appender: w}, nil
}

// SetReplayGate installs the replay chunk check. Until one is installed, a batch
// carrying a replay record is refused (Unsupported), never admitted unchecked.
func (s *Service) SetReplayGate(g ReplayGate) { s.replay = g }
func Decode(r io.Reader, encoding string) (Batch, error) {
	wireLimit := int64(4 << 20)
	if encoding == "gzip" {
		wireLimit = 1 << 20
	} else if encoding != "" {
		return Batch{}, model.Fail(model.Unsupported)
	}
	compressed, e := io.ReadAll(io.LimitReader(r, wireLimit+1))
	if e != nil {
		return Batch{}, model.Fail(model.Invalid)
	}
	if int64(len(compressed)) > wireLimit {
		return Batch{}, model.Fail(model.TooLarge)
	}
	expanded := compressed
	switch encoding {
	case "":
	case "gzip":
		z, e := gzip.NewReader(bytes.NewReader(compressed))
		if e != nil {
			return Batch{}, model.Fail(model.Invalid)
		}
		expanded, e = io.ReadAll(io.LimitReader(z, (4<<20)+1))
		ce := z.Close()
		if e != nil || ce != nil {
			return Batch{}, model.Fail(model.Invalid)
		}
		if len(expanded) > 4<<20 {
			return Batch{}, model.Fail(model.TooLarge)
		}
	default:
		return Batch{}, model.Fail(model.Unsupported)
	}
	if model.ValidateJSON(expanded) != nil {
		return Batch{}, model.Fail(model.Invalid)
	}
	// The top level is a closed schema: an unknown (or differently cased) batch field is refused, never silently dropped.
	var top map[string]json.RawMessage
	if json.Unmarshal(expanded, &top) != nil {
		return Batch{}, model.Fail(model.Invalid)
	}
	for key := range top {
		switch key {
		case "version", "project", "source", "producer", "id", "policy_revision", "route_slot", "records":
		default:
			return Batch{}, model.Fail(model.Invalid)
		}
	}
	var raw struct {
		Records []json.RawMessage `json:"records"`
	}
	if json.Unmarshal(expanded, &raw) != nil || len(raw.Records) == 0 || len(raw.Records) > 512 {
		return Batch{}, model.Fail(model.Invalid)
	}
	for _, r := range raw.Records {
		if len(r) > 256<<10 {
			return Batch{}, model.Fail(model.TooLarge)
		}
	}
	var b Batch
	if json.Unmarshal(expanded, &b) != nil || b.Version != 1 {
		return Batch{}, model.Fail(model.Invalid)
	}
	return b, nil
}
func (s *Service) ResolveSource(ctx context.Context, c SourceCredential, b Batch) (SourceGrant, error) {
	from := time.Now()
	g, e := s.policy.ResolveSource(ctx, c, b.Project, b.Source, b.PolicyRevision)
	phaseTimes.resolve.add(from)
	return g, e
}

// maxInFlight bounds the ingest requests a process works on at once, counted from the first byte of a request, before the
// credential is checked and before the body is read: a refused request costs a counter and a 503. A batch is admitted in steps
// that each wait for a round of a group (the reservation, the append of its slot, the finalization), so the time of one is the
// length of the queues of those rounds; work that is let in without a bound makes every queue longer for all of it, and a caller
// that gave up after its own budget and asked again adds its batch to the queues while the first is still in them (14,000
// goroutines and 36 s of p95 at 1750 records a second when the cluster was past what it could commit).
//
// The number: a node takes a third of the batches (6.3 records each), 263 a second at 5,000 records a second, so by Little's
// law a request that is answered in the 0.5 s of the target has 130 in flight, and 512 is 4 times that: it is reached only when
// the answer time of the node has passed 1.9 s, which is where the queues are growing and more work only lengthens them. At
// 1,750 records a second a node has 46 in flight at the target. A sender that is refused waits what the refusal says
// (Retry-After, which the SDKs and the load generator honor, with their exponential backoff and jitter) and tries again, so a
// refusal does not make more work for the process.
const maxInFlight = 512

// Enter counts one ingest request in; ok is false when maxInFlight are in progress already (the request is refused as a
// timeout, 503 with Retry-After, and is not counted). Every request that entered calls Leave.
func (s *Service) Enter() (ok bool) {
	n := s.inFlight.Add(1)
	if n > maxInFlight {
		s.inFlight.Add(-1)
		outcomes.bounded.Add(1)
		return false
	}
	for {
		m := outcomes.inFlightMax.Load()
		if n <= m || outcomes.inFlightMax.CompareAndSwap(m, n) {
			return true
		}
	}
}

// Leave counts a request that entered out.
func (s *Service) Leave() { s.inFlight.Add(-1) }

func (s *Service) Admit(ctx context.Context, g SourceGrant, b Batch) (Receipt, error) {
	r, e := s.admit(ctx, g, b)
	noteOutcome(e)
	return r, e
}

func (s *Service) admit(ctx context.Context, g SourceGrant, b Batch) (Receipt, error) {
	n, e := policy.Normalize(g, b)
	if e != nil {
		return Receipt{}, e
	}
	// Replay chunks are admitted only in the closed format, and before any quota
	// is charged: a refused chunk leaves no reservation and no record.
	for i := range n.Records {
		r := &n.Records[i]
		if r.Kind != model.Replay {
			continue
		}
		if r.Payload.Replay == nil {
			return Receipt{}, model.Fail(model.Invalid)
		}
		if s.replay == nil {
			return Receipt{}, model.Fail(model.Unsupported)
		}
		if e = s.replay(*r.Payload.Replay); e != nil {
			return Receipt{}, e
		}
	}
	scope, e := g.Scope()
	if e != nil {
		return Receipt{}, e
	}
	// An appender that can refuse a batch before storing it (the replay index
	// and stored-chunk checks) does so before the reservation, so a refused
	// forged batch never leaves a charged reservation behind.
	if p, ok := s.appender.(Preflighter); ok {
		from := time.Now()
		e = p.Preflight(ctx, scope, n)
		phaseTimes.preflight.add(from)
		if e != nil {
			return Receipt{}, e
		}
	}
	reserveFrom := time.Now()
	reservation, e := s.quota.ReserveAdmission(ctx, scope, n)
	phaseTimes.reserve.add(reserveFrom)
	if e != nil {
		return Receipt{}, e
	}
	n.Reservation = reservation
	// The checks that follow (the append's) have to see the reservation this request just made: they make their own barrier.
	model.InvalidateReadShare(ctx)
	appendFrom := time.Now()
	r, e := s.appender.Append(ctx, scope, n)
	phaseTimes.appendTime.add(appendFrom)
	if e != nil {
		return Receipt{}, e
	}
	// A committed data receipt is already authoritative. A failed control finalize
	// remains conservatively charged and is recoverable; it never refunds bytes. A retry of a
	// batch whose reservation control already holds as consumed at this receipt's cursor (or whose
	// settled window it answers as consumed) has nothing left to finalize.
	if reservation.State == "consumed" && reservation.Cursor != nil && *reservation.Cursor == r.Cursor {
		if e = g.Revalidate(model.WithoutReadShare(ctx)); e != nil {
			return Receipt{}, e
		}
		return r, nil
	}
	finalizeFrom := time.Now()
	e = s.quota.FinalizeAdmission(ctx, scope, model.FinalizeAdmission{ReservationID: reservation.ID, Cursor: r.Cursor})
	phaseTimes.finalize.add(finalizeFrom)
	if e != nil {
		noteFinalizeFailed(e)
		return Receipt{}, model.Fail(model.Unavailable)
	}
	revalidateFrom := time.Now()
	e = g.Revalidate(model.WithoutReadShare(ctx))
	phaseTimes.revalidate.add(revalidateFrom)
	if e != nil {
		return Receipt{}, e
	}
	return r, nil
}
func (s *Service) LookupReceipt(ctx context.Context, c SourceCredential, q ReceiptRequest) (Receipt, error) {
	src, e := s.auth.SourceAuthority(ctx, c, false)
	if e != nil {
		return Receipt{}, e
	}
	if src.ID != q.Source {
		return Receipt{}, model.Fail(model.Forbidden)
	}
	scope, e := s.auth.SourceScope(ctx, c, true)
	if e != nil {
		return Receipt{}, e
	}
	receipt, e := s.appender.LookupReceipt(ctx, scope, q)
	if e != nil {
		return Receipt{}, e
	}
	if _, e = s.auth.SourceAuthority(ctx, c, false); e != nil {
		return Receipt{}, e
	}
	return receipt, nil
}
