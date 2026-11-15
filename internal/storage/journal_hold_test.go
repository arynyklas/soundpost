// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func requireJournalReserve(t *testing.T, err error) {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Unavailable || !f.Retryable || f.SafeDetail != JournalReserveDetail {
		t.Fatalf("want retryable unavailable/%s, got %v", JournalReserveDetail, err)
	}
}

// A held journal accepts error evidence only while its reserve lasts and then
// rejects it (retryable, nothing discarded); everything else is unaffected.
func TestJournalHoldAdmitsEvidenceOnlyWhileTheReserveLasts(t *testing.T) {
	e := &Engine{}
	org, project, other := model.NewID(), model.NewID(), model.NewID()
	errors1 := []model.Record{{Kind: model.ErrorKind}}
	metrics := []model.Record{{Kind: model.Metric}}
	mixed := []model.Record{{Kind: model.Metric}, {Kind: model.ErrorKind}}

	// Not held: nothing is gated, whatever the size.
	if err := e.admitJournal(org, project, errors1, 1<<40); err != nil {
		t.Fatalf("an unheld journal gated a batch: %v", err)
	}

	e.HoldJournal(org, project, 100)
	if err := e.admitJournal(org, project, errors1, 60); err != nil {
		t.Fatalf("within the reserve: %v", err)
	}
	// Renewing the hold (the producer does it every pass) must not refill the reserve.
	e.HoldJournal(org, project, 100)
	if err := e.admitJournal(org, project, errors1, 60); err == nil {
		t.Fatal("a renewed hold refilled its reserve")
	} else {
		requireJournalReserve(t, err)
	}
	// A rejected batch consumed nothing: a smaller one still fits.
	if err := e.admitJournal(org, project, mixed, 40); err != nil {
		t.Fatalf("exactly the rest of the reserve: %v", err)
	}
	requireJournalReserve(t, e.admitJournal(org, project, errors1, 1))

	// Batches without error evidence, and other projects, are never gated.
	if err := e.admitJournal(org, project, metrics, 1<<30); err != nil {
		t.Fatalf("a batch without error evidence was gated: %v", err)
	}
	if err := e.admitJournal(org, other, errors1, 1<<30); err != nil {
		t.Fatalf("another project was gated: %v", err)
	}
	if err := e.admitJournal(model.NewID(), project, errors1, 1<<30); err != nil {
		t.Fatalf("another organization's project of the same ID was gated: %v", err)
	}

	holds := e.JournalHolds()
	if len(holds) != 1 || holds[0].Org != org || holds[0].Project != project || holds[0].Reserve != 100 || holds[0].Used != 100 || holds[0].Denied != 2 {
		t.Fatalf("hold status: %+v", holds)
	}

	// Releasing (the gap committed) admits evidence again, and a second release says so.
	if !e.ReleaseJournal(org, project) || e.ReleaseJournal(org, project) {
		t.Fatal("release did not report the hold exactly once")
	}
	if err := e.admitJournal(org, project, errors1, 1<<40); err != nil {
		t.Fatalf("a released journal still gates: %v", err)
	}
	if len(e.JournalHolds()) != 0 {
		t.Fatalf("holds left: %+v", e.JournalHolds())
	}
}
