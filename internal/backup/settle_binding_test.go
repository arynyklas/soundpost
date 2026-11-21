// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

func settledSample() *model.Settlement {
	group := model.NewID()
	return &model.Settlement{
		Spans:   map[string]uint64{group.String(): 4},
		Windows: map[string]model.SettledWindow{model.SettledKey(group, 0): {Group: group, N: 0, Span: 4, Count: 4, Charge: model.HashCanonical([]byte("w0"))}},
		Charges: map[string]model.SettledCharge{"org:x": {Bytes: 40, Series: map[string]uint64{"s": 4}}},
	}
}

// What the manifest and the bundle agree on about control's reservations is the old binding exactly
// while nothing is settled (existing manifests keep verifying), and the settlement as well once it
// is: control state and cut that disagree about it, or a manifest that binds only the rows, are refused.
func TestCutBindingCoversTheSettlement(t *testing.T) {
	rows := map[string]model.AdmissionReservation{}
	plain, err := canonicalReservations(rows)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := canonicalCutBinding(rows, nil); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("with no settlement the binding changed: %q, %v", got, err)
	}
	settlement := settledSample()
	bound, err := canonicalCutBinding(rows, settlement)
	if err != nil || bytes.Equal(bound, plain) {
		t.Fatalf("a settlement is not part of the binding: %v", err)
	}

	state := model.ControlState{Installation: model.NewID(), Revision: 7, Reservations: rows, Settlement: settlement}
	policies, _ := model.CanonicalJSON(state.RetentionPolicies)
	manifest := BackupManifest{Control: ControlBinding{Installation: state.Installation, Revision: 7, ReservationsSHA256: model.HashCanonical(bound)}, Retention: RetentionBinding{PolicyDigest: model.HashCanonical(policies)}}
	bundle := storage.BackupBundle{Cut: storage.ControlCut{Revision: 7, Reservations: rows, Settlement: settlement}}
	if err := verifyControl(manifest, bundle, state); err != nil {
		t.Fatalf("a control state and cut that agree on the settlement were refused: %v", err)
	}
	other := *settlement
	other.Charges = map[string]model.SettledCharge{"org:x": {Bytes: 41, Series: map[string]uint64{"s": 4}}}
	forged := bundle
	forged.Cut.Settlement = &other
	if err := verifyControl(manifest, forged, state); err == nil {
		t.Fatal("a cut whose settlement is not the control state's was accepted")
	}
	rowsOnly := manifest
	rowsOnly.Control.ReservationsSHA256 = model.HashCanonical(plain)
	if err := verifyControl(rowsOnly, bundle, state); err == nil {
		t.Fatal("a manifest that binds only the reservation rows was accepted for a settled control state")
	}
}
