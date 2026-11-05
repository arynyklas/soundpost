// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/storage"
)

func reservation(org, project, source model.ID, bytes uint64, state string, series ...string) model.AdmissionReservation {
	return model.AdmissionReservation{ID: model.NewID(), Org: org, Project: project, Source: source, Producer: model.NewID(), Batch: model.NewID(), Slot: 7, Hash: model.HashCanonical([]byte(state + string(rune(bytes)))), PolicyEpoch: 3, Bytes: model.Uint64(bytes), Series: series, State: state}
}
func evidenceOf(r model.AdmissionReservation, index uint64) storage.ReservationEvidence {
	return storage.ReservationEvidence{ID: r.ID, Org: r.Org, Project: r.Project, Source: r.Source, Hash: r.Hash, Bytes: r.Bytes, Series: r.Series, Cursor: model.Cursor{Group: model.NewID(), Index: model.Uint64(index)}}
}

func TestQuotaReconciliationRebuildsControlStateWithoutDoubleCharging(t *testing.T) {
	org, project, source := model.NewID(), model.NewID(), model.NewID()
	consumedAtC := reservation(org, project, source, 100, "consumed", "s1")
	reservedUsedAfterC := reservation(org, project, source, 40, "reserved", "s2")
	reservedCancelledAfterC := reservation(org, project, source, 25, "reserved", "s3")
	pending := reservation(org, project, source, 10, "reserved", "s4")
	createdAfterC := reservation(org, project, source, 7, "consumed", "s5")
	st := model.ControlState{Installation: model.NewID(), Reservations: map[string]model.AdmissionReservation{}, AdmissionKeys: map[string]string{}, Quotas: map[string]model.QuotaState{}}
	for _, r := range []model.AdmissionReservation{consumedAtC, reservedUsedAfterC, reservedCancelledAfterC, pending} {
		st.Reservations[r.ID.String()] = r
		st.AdmissionKeys[reservationKey(r)] = r.ID.String()
	}
	for _, key := range []string{"org:" + org.String(), "project:" + org.String() + ":" + project.String(), "source:" + org.String() + ":" + project.String() + ":" + source.String()} {
		st.Quotas[key] = model.QuotaState{Bytes: 175, MaxBytes: 1000, MaxSeries: 50, Configured: true, Series: map[string]uint64{"s1": 1, "s2": 1, "s3": 1, "s4": 1}}
	}
	cursorC := model.Cursor{Group: model.NewID(), Index: 9}
	consumedAtC.Cursor = &cursorC
	st.Reservations[consumedAtC.ID.String()] = consumedAtC
	evidence := []storage.ReservationEvidence{evidenceOf(consumedAtC, 9), evidenceOf(reservedUsedAfterC, 11), evidenceOf(createdAfterC, 12)}
	evidence[0].Cursor = cursorC
	cert := storage.QuotaReconciliation{
		Version: 1, Consumed: []model.ID{consumedAtC.ID, reservedUsedAfterC.ID, createdAfterC.ID}, AddedAfterCut: []model.ID{createdAfterC.ID},
		Refunded: []model.ID{reservedCancelledAfterC.ID}, Pending: []model.ID{pending.ID},
		Charges: map[string]storage.QuotaCharge{},
	}
	for _, key := range []string{"org:" + org.String(), "project:" + org.String() + ":" + project.String(), "source:" + org.String() + ":" + project.String() + ":" + source.String()} {
		cert.Charges[key] = storage.QuotaCharge{Bytes: 100 + 40 + 7 + 10, Series: map[string]uint64{"s1": 1, "s2": 1, "s4": 1, "s5": 1}}
	}
	if err := applyQuotaReconciliation(&st, cert, map[model.ID]model.AdmissionReservation{createdAfterC.ID: createdAfterC}, evidence); err != nil {
		t.Fatal(err)
	}
	if r := st.Reservations[reservedUsedAfterC.ID.String()]; r.State != "consumed" || r.Cursor == nil || *r.Cursor != evidence[1].Cursor {
		t.Fatalf("a reservation the data cut consumed must be consumed with its cursor: %+v", r)
	}
	if r := st.Reservations[reservedCancelledAfterC.ID.String()]; r.State != "cancelled" {
		t.Fatalf("a reservation a committed fence cancelled must be cancelled: %+v", r)
	}
	if r := st.Reservations[pending.ID.String()]; r.State != "reserved" || r.Cursor != nil {
		t.Fatalf("a pending intent must stay charged and reserved: %+v", r)
	}
	made, ok := st.Reservations[createdAfterC.ID.String()]
	if !ok || made.State != "consumed" || made.Cursor == nil || *made.Cursor != evidence[2].Cursor || made.Producer != createdAfterC.Producer || made.Batch != createdAfterC.Batch || made.Slot != createdAfterC.Slot {
		t.Fatalf("a reservation created after the control cut was not reconstructed whole: %+v", made)
	}
	if st.AdmissionKeys[reservationKey(createdAfterC)] != createdAfterC.ID.String() {
		t.Fatal("the idempotency key of a reconstructed reservation is missing: a client retry would be charged a second time")
	}
	for key, q := range st.Quotas {
		if q.Bytes != 157 || len(q.Series) != 4 || q.Series["s3"] != 0 || q.Series["s5"] != 1 || q.MaxBytes != 1000 || !q.Configured {
			t.Fatalf("%s: charge %d series %v: not the exact reconciled charge with limits intact", key, q.Bytes, q.Series)
		}
	}
	t.Run("applying twice is a no-op", func(t *testing.T) {
		before := st
		if err := applyQuotaReconciliation(&st, cert, map[model.ID]model.AdmissionReservation{createdAfterC.ID: createdAfterC}, evidence); err != nil {
			t.Fatal(err)
		}
		if st.Reservations[createdAfterC.ID.String()].Cursor == nil || len(st.Reservations) != len(before.Reservations) {
			t.Fatal("a second application changed the reservations")
		}
	})
	t.Run("a post-cut consumption without its full reservation fails closed", func(t *testing.T) {
		fresh := model.ControlState{Installation: st.Installation, Reservations: map[string]model.AdmissionReservation{}, AdmissionKeys: map[string]string{}, Quotas: map[string]model.QuotaState{}}
		if err := applyQuotaReconciliation(&fresh, cert, map[model.ID]model.AdmissionReservation{}, evidence); err == nil {
			t.Fatal("a consumed reservation with no reconstructible record was ignored")
		}
	})
	t.Run("a reconstructed reservation must agree with the evidence", func(t *testing.T) {
		fresh := model.ControlState{Installation: st.Installation, Reservations: map[string]model.AdmissionReservation{}, AdmissionKeys: map[string]string{}, Quotas: map[string]model.QuotaState{}}
		wrong := createdAfterC
		wrong.Bytes++
		if err := applyQuotaReconciliation(&fresh, cert, map[model.ID]model.AdmissionReservation{createdAfterC.ID: wrong}, evidence); err == nil {
			t.Fatal("a reservation record contradicting the sealed evidence was accepted")
		}
	})
}
