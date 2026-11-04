// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"soundpost/internal/model"
)

func (scope Scope) ValidateReservation(ctx context.Context, b model.NormalizedBatch) error {
	if scope.service == nil {
		return model.Fail(model.Forbidden)
	}
	return scope.service.store.View(ctx, func(st model.ControlState) error {
		if e := scope.ValidateSourceState(st, b.Project, b.Source, true); e != nil {
			return e
		}
		r, ok := st.Reservations[b.Reservation.ID.String()]
		if !ok || r.State == "cancelled" || r.Org != scope.org || r.Org != b.Org || r.Project != b.Project || r.Source != b.Source || r.Producer != b.Producer || r.Batch != b.ID || r.Slot != b.RouteSlot || r.Hash != b.Hash || r.PolicyEpoch != b.PolicyEpoch || r.Bytes != model.Uint64(len(b.Canonical)) {
			return model.Fail(model.Forbidden)
		}
		if r.State != "reserved" {
			return model.Fail(model.Conflict)
		}
		authoritative, e := model.CanonicalJSON(r)
		if e != nil {
			return model.Fail(model.Corrupt)
		}
		supplied, e := model.CanonicalJSON(b.Reservation)
		if e != nil || !bytes.Equal(authoritative, supplied) {
			return model.Fail(model.Forbidden)
		}
		src := st.Sources[b.Source.String()]
		if src.Policy.Revision != b.PolicyRevision {
			return model.Fail(model.Stale)
		}
		policyBytes, e := model.CanonicalJSON(src.Policy)
		if e != nil || b.PolicyHash != model.HashCanonical(policyBytes).String() {
			return model.Fail(model.Stale)
		}
		// A serializable NormalizedBatch is not itself authority to bypass privacy.
		raw, e := json.Marshal(b.Batch)
		if e != nil {
			return model.Fail(model.Invalid)
		}
		var copyBatch model.Batch
		if json.Unmarshal(raw, &copyBatch) != nil {
			return model.Fail(model.Invalid)
		}
		for i := range copyBatch.Records {
			if e = model.ValidateRecord(&copyBatch.Records[i], src.Policy); e != nil {
				return e
			}
		}
		canonical, e := model.CanonicalJSON(copyBatch)
		if e != nil || !bytes.Equal(canonical, b.Canonical) {
			return model.Fail(model.Invalid)
		}
		return nil
	})
}
func (scope Scope) Reservation(ctx context.Context, id model.ID) (model.AdmissionReservation, error) {
	if scope.service == nil {
		return model.AdmissionReservation{}, model.Fail(model.Forbidden)
	}
	var out model.AdmissionReservation
	e := scope.service.store.View(ctx, func(st model.ControlState) error {
		r, ok := st.Reservations[id.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		if e := scope.ValidateSourceState(st, r.Project, r.Source, false); e != nil {
			return e
		}
		out = r
		return nil
	})
	return out, e
}
