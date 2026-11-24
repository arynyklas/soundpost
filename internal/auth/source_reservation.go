// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"

	"github.com/arynyklas/soundpost/internal/model"
)

// SameReservation says whether two reservation rows are the same row: every field equal, a missing series
// list told from an empty one as the encoding tells them (null and []). It is what comparing the
// canonical encodings of the two said, without encoding either: the supplied row of a batch is checked
// against the authoritative one on every append.
func SameReservation(a, b model.AdmissionReservation) bool {
	if a.ID != b.ID || a.Org != b.Org || a.Project != b.Project || a.Source != b.Source || a.Producer != b.Producer || a.Batch != b.Batch || a.Slot != b.Slot || a.Hash != b.Hash || a.PolicyEpoch != b.PolicyEpoch || a.Bytes != b.Bytes || a.State != b.State {
		return false
	}
	if (a.Series == nil) != (b.Series == nil) || !slices.Equal(a.Series, b.Series) {
		return false
	}
	if (a.Cursor == nil) != (b.Cursor == nil) {
		return false
	}
	return a.Cursor == nil || *a.Cursor == *b.Cursor
}

func (scope Scope) ValidateReservation(ctx context.Context, b model.NormalizedBatch) error {
	if scope.service == nil {
		return model.Fail(model.Forbidden)
	}
	return scope.service.viewAdmission(ctx, func(st model.ControlState, rows AdmissionReader) error {
		if e := scope.ValidateSourceState(st, b.Project, b.Source, true); e != nil {
			return e
		}
		r, ok, err := rows.Reservation(b.Reservation.ID.String())
		if err != nil {
			return err
		}
		if !ok || r.State == "cancelled" || r.Org != scope.org || r.Org != b.Org || r.Project != b.Project || r.Source != b.Source || r.Producer != b.Producer || r.Batch != b.ID || r.Slot != b.RouteSlot || r.Hash != b.Hash || r.PolicyEpoch != b.PolicyEpoch || r.Bytes != model.Uint64(len(b.Canonical)) {
			return model.Fail(model.Forbidden)
		}
		if r.State != "reserved" {
			return model.Fail(model.Conflict)
		}
		if !SameReservation(r, b.Reservation) {
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
	e := scope.service.viewAdmission(ctx, func(st model.ControlState, rows AdmissionReader) error {
		r, ok, err := rows.Reservation(id.String())
		if err != nil {
			return err
		}
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
