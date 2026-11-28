// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The leader answers a finalization with no reservation (and a reserve that must be asked of the owner first with none either):
// the answer has to encode. A zero reservation does not (its identifiers refuse to be written as zero), so every finalization a
// follower handed to the leader committed there and then failed to be answered: the request was answered as unavailable and its
// sender asked again at another member, 40-50 % of the attempts of a cluster at 1,750 records a second.
func TestTheLeadersAnswerWithNoReservationEncodes(t *testing.T) {
	for name, answer := range map[string]remoteAnswer{"finalize": {}, "needs lookup": {NeedsLookup: true}} {
		raw, err := json.Marshal(answer)
		if err != nil {
			t.Fatalf("%s: the answer does not encode: %v", name, err)
		}
		var back remoteAnswer
		if err = model.StrictJSON(raw, &back); err != nil {
			t.Fatalf("%s: the answer %s does not read back: %v", name, raw, err)
		}
		if back.Reservation != nil || back.NeedsLookup != answer.NeedsLookup {
			t.Fatalf("%s: read back as %+v", name, back)
		}
	}
	id := model.NewID()
	raw, err := json.Marshal(remoteAnswer{Reservation: &model.AdmissionReservation{ID: id, Org: model.NewID(), Project: model.NewID(), Source: model.NewID(), Producer: model.NewID(), Batch: model.NewID()}})
	if err != nil {
		t.Fatal(err)
	}
	var back remoteAnswer
	if err = model.StrictJSON(raw, &back); err != nil || back.Reservation == nil || back.Reservation.ID != id {
		t.Fatalf("a reservation does not round-trip: %v %+v", err, back)
	}
}
