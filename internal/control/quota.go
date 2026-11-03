// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import "sort"
import "bytes"
import (
	"context"
	"math"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

type ReserveAdmission = model.ReserveAdmission
type FinalizeAdmission = model.FinalizeAdmission
type CancelReservation = model.CancelReservation

func reservationKey(r model.AdmissionReservation) string {
	return r.Org.String() + ":" + r.Project.String() + ":" + r.Source.String() + ":" + r.Producer.String() + ":" + stringSlot(r.Slot) + ":" + r.Batch.String()
}
func stringSlot(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>4], digits[v&15]})
}
func quotaKeys(r model.AdmissionReservation) []string {
	return []string{"org:" + r.Org.String(), "project:" + r.Org.String() + ":" + r.Project.String(), "source:" + r.Org.String() + ":" + r.Project.String() + ":" + r.Source.String()}
}
func (s *Store) ReserveAdmission(ctx context.Context, scope auth.Scope, b model.NormalizedBatch) (model.AdmissionReservation, error) {
	canonical, err := model.CanonicalJSON(b.Batch)
	if err != nil || !bytes.Equal(canonical, b.Canonical) || model.HashCanonical(canonical) != b.Hash {
		return model.AdmissionReservation{}, model.Fail(model.Invalid)
	}
	unique := map[string]bool{}
	for _, record := range b.Records {
		if record.Kind == model.Metric {
			id, e := model.CanonicalSeriesID(b.Project, record)
			if e != nil {
				return model.AdmissionReservation{}, e
			}
			unique[id] = true
		}
	}
	b.Series = make([]string, 0, len(unique))
	for id := range unique {
		b.Series = append(b.Series, id)
	}
	sort.Strings(b.Series)
	r := model.AdmissionReservation{ID: model.NewID(), Org: b.Org, Project: b.Project, Source: b.Source, Producer: b.Producer, Batch: b.ID, Slot: b.RouteSlot, Hash: b.Hash, PolicyEpoch: b.PolicyEpoch, Bytes: uint64(len(b.Canonical)), Series: append([]string(nil), b.Series...), State: "reserved"}
	if r.Slot >= 64 || r.Bytes == 0 {
		return r, model.Fail(model.Invalid)
	}
	e := s.Update(ctx, func(st *State) error {
		if e := scope.ValidateSourceState(*st, r.Project, r.Source, true); e != nil {
			return e
		}
		if scope.OrgID() != r.Org || scope.PolicyEpoch() != r.PolicyEpoch {
			return model.Fail(model.Forbidden)
		}
		if st.Reservations == nil {
			st.Reservations = map[string]model.AdmissionReservation{}
		}
		if st.AdmissionKeys == nil {
			if len(st.Reservations) != 0 {
				return model.Fail(model.Corrupt)
			}
			st.AdmissionKeys = map[string]string{}
		}
		if id, exists := st.AdmissionKeys[reservationKey(r)]; exists {
			old, ok := st.Reservations[id]
			if !ok {
				return model.Fail(model.Corrupt)
			}
			if old.Hash != r.Hash || old.State == "cancelled" {
				return model.Fail(model.Conflict)
			}
			r = old
			return nil
		}
		p := st.Sources[r.Source.String()].Policy
		if p.MaxBytes == 0 || p.MaxSeries == 0 {
			return model.Fail(model.Quota)
		}
		if st.Quotas == nil {
			st.Quotas = map[string]model.QuotaState{}
		}
		for _, key := range quotaKeys(r) {
			q := st.Quotas[key]
			if q.Series == nil {
				q.Series = map[string]uint64{}
			}
			if !q.Configured && (q.MaxBytes == 0 || p.MaxBytes < q.MaxBytes) {
				q.MaxBytes = p.MaxBytes
			}
			if !q.Configured && (q.MaxSeries == 0 || p.MaxSeries < q.MaxSeries) {
				q.MaxSeries = p.MaxSeries
			}
			if r.Bytes > q.MaxBytes || q.Bytes > q.MaxBytes-r.Bytes {
				return model.Fail(model.Quota)
			}
			newSeries := uint64(0)
			for _, id := range r.Series {
				if q.Series[id] == 0 {
					newSeries++
				}
				if q.Series[id] == math.MaxUint64 {
					return model.Fail(model.Quota)
				}
			}
			if newSeries > q.MaxSeries || uint64(len(q.Series)) > q.MaxSeries-newSeries {
				return model.Fail(model.Quota)
			}
			q.Bytes += r.Bytes
			for _, id := range r.Series {
				q.Series[id]++
			}
			st.Quotas[key] = q
		}
		st.Reservations[r.ID.String()] = r
		st.AdmissionKeys[reservationKey(r)] = r.ID.String()
		return nil
	})
	return r, e
}
func (s *Store) FinalizeAdmission(ctx context.Context, scope auth.Scope, r FinalizeAdmission) error {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	if owner == nil {
		return model.Fail(model.Unavailable)
	}
	if e := owner.VerifyFinalization(ctx, r); e != nil {
		return e
	}
	return s.Update(ctx, func(st *State) error {
		old, ok := st.Reservations[r.ReservationID.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if e := scope.ValidateSourceState(*st, old.Project, old.Source, false); e != nil {
			return e
		}
		if old.State == "cancelled" {
			return model.Fail(model.Conflict)
		}
		if old.Cursor != nil {
			if *old.Cursor != r.Cursor {
				return model.Fail(model.Conflict)
			}
			return nil
		}
		old.State = "consumed"
		old.Cursor = &r.Cursor
		st.Reservations[r.ReservationID.String()] = old
		return nil
	})
}

// CancelReservation takes only a committed owner-group proof verified against the
// injected group's durable state. Expiry and router death are not evidence.
type AdmissionProofs interface {
	VerifyCancellation(context.Context, model.CancelReservation) error
	VerifyFinalization(context.Context, model.FinalizeAdmission) error
}

func (s *Store) BindAdmissionOwner(owner AdmissionProofs) error {
	s.registryMu.Lock()
	defer s.registryMu.Unlock()
	if owner == nil || s.ownerProof != nil {
		return model.Fail(model.Conflict)
	}
	s.ownerProof = owner
	return nil
}
func (s *Store) CancelAdmission(ctx context.Context, scope auth.Scope, r CancelReservation) error {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	if owner == nil {
		return model.Fail(model.Forbidden)
	}
	if e := owner.VerifyCancellation(ctx, r); e != nil {
		return e
	}
	return s.Update(ctx, func(st *State) error {
		old, ok := st.Reservations[r.ReservationID.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if e := scope.ValidateSourceState(*st, old.Project, old.Source, false); e != nil {
			return e
		}
		if old.Hash != r.Hash || old.State == "consumed" {
			return model.Fail(model.Conflict)
		}
		if old.State == "cancelled" {
			return nil
		}
		for _, key := range quotaKeys(old) {
			q := st.Quotas[key]
			if q.Bytes < old.Bytes {
				return model.Fail(model.Corrupt)
			}
			q.Bytes -= old.Bytes
			for _, id := range old.Series {
				if q.Series[id] <= 1 {
					delete(q.Series, id)
				} else {
					q.Series[id]--
				}
			}
			st.Quotas[key] = q
		}
		old.State = "cancelled"
		st.Reservations[r.ReservationID.String()] = old
		return nil
	})
}
