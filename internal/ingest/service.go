// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package ingest

import "bytes"
import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/policy"
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
type Service struct {
	auth     *auth.Service
	policy   *policy.Service
	quota    Quota
	appender Appender
}

func New(a *auth.Service, p *policy.Service, q Quota, w Appender) (*Service, error) {
	if a == nil || p == nil || q == nil || w == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{auth: a, policy: p, quota: q, appender: w}, nil
}
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
	return s.policy.ResolveSource(ctx, c, b.Project, b.Source, b.PolicyRevision)
}
func (s *Service) Admit(ctx context.Context, g SourceGrant, b Batch) (Receipt, error) {
	n, e := policy.Normalize(g, b)
	if e != nil {
		return Receipt{}, e
	}
	scope, e := g.Scope()
	if e != nil {
		return Receipt{}, e
	}
	reservation, e := s.quota.ReserveAdmission(ctx, scope, n)
	if e != nil {
		return Receipt{}, e
	}
	n.Reservation = reservation
	r, e := s.appender.Append(ctx, scope, n)
	if e != nil {
		return Receipt{}, e
	}
	// A committed data receipt is already authoritative. A failed control finalize
	// remains conservatively charged and is recoverable; it never refunds bytes.
	if e = s.quota.FinalizeAdmission(ctx, scope, model.FinalizeAdmission{ReservationID: reservation.ID, Cursor: r.Cursor}); e != nil {
		return Receipt{}, model.Fail(model.Unavailable)
	}
	if e = g.Revalidate(ctx); e != nil {
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
