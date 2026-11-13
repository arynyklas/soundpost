// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package retention_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/retention"
)

// CD-9 (decision D3): a range deletion erases an opaque incident state exactly
// when its recorded window meets the range, and the receipt reports the states
// it had to erase without any window: Delete and PollDelete answer the same
// typed, counted over_erased.
func TestReceiptReportsOpaqueStatesErasedWithoutAWindow(t *testing.T) {
	f := newFx(t, options{})
	if err := f.store.BindIncidentAction(); err != nil {
		t.Fatal(err)
	}
	incident := func(extra string) model.ID {
		t.Helper()
		id := model.NewID()
		state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1"%s}`, id.String(), f.org.String(), f.project.String(), extra))
		c := control.IncidentCommand{Project: f.project, Incident: id, Action: "open", Origin: "human", Actor: f.user, At: 100, NewVersion: 1, State: state, Digest: model.Hash(sha256.Sum256(state))}
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.Transact(f.ctx, f.adminScope(), control.Command{CommandID: model.NewID(), ExpectedRevision: f.revision(), Kind: string(control.KindIncidentAction), Payload: raw}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	inside := incident(`,"at":"60"`)
	after := incident(`,"at":"1000"`)
	bare := incident(`,"labels":{"host":"a"}`)

	receipt, err := f.del(model.DeleteHistoricalRange, func(r *retention.DeleteRequest) {
		r.ProjectIDs, r.Signals, r.Start, r.End = []model.ID{f.project}, []model.Kind{model.Metric}, 40, 100
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []model.OverErased{{Book: model.OverErasedIncident, Count: 1}}
	if !reflect.DeepEqual(receipt.OverErased, want) {
		t.Fatalf("receipt over_erased = %+v, want %+v (only the state with no window)", receipt.OverErased, want)
	}
	if polled := f.poll(receipt.OperationID); !reflect.DeepEqual(polled.OverErased, want) {
		t.Fatalf("polled over_erased = %+v, want %+v", polled.OverErased, want)
	}
	erased := func(id model.ID) bool {
		records, err := f.store.Incidents(f.ctx, f.adminScope(), f.project)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range records {
			if r.ID == id {
				return r.Erased()
			}
		}
		t.Fatalf("incident %s not found", id)
		return false
	}
	if !erased(inside) || !erased(bare) {
		t.Fatal("a state inside the range, or one with no window, was kept")
	}
	if erased(after) {
		t.Fatal("a state whose evidence is all after the range's end was erased")
	}

	// A retirement is exact: nothing is over-erased.
	retired, err := f.del(model.DeleteRetireProject, func(r *retention.DeleteRequest) { r.ProjectIDs = []model.ID{f.other} })
	if err != nil {
		t.Fatal(err)
	}
	if len(retired.OverErased) != 0 {
		t.Fatalf("a retirement reported over-erasure: %+v", retired.OverErased)
	}
}
