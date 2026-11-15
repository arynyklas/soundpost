// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/backup"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// A backup that died between BeginBackup and Seal/Abort leaves a durable pin in every group of the
// real engine. With backup.EnginePins as Config.Pins the startup reaper finds those pins through
// storage.Engine.JournalPins, drops them through DropJournalPin and closes the attempt; without it the
// attempt stays open and the pins stay.
func TestEnginePinsLetTheReaperFreeTheJournalOfADeadBackup(t *testing.T) {
	l := newLive(t)
	l.append(100, "row")
	l.reconcile()
	attempts := backup.DirAttempts(filepath.Join(t.TempDir(), "attempts"))
	plane := backup.EngineDataPlane(l.app.Storage)
	var revision model.Revision
	if err := l.app.Control.View(l.ctx, func(st control.State) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	cut := storage.ControlCut{Revision: revision, Reservations: map[string]model.AdmissionReservation{}}
	for _, c := range plane.Applied() {
		cut.Processed = append(cut.Processed, model.Cursor{Group: c.Group, Index: c.Index})
	}
	// The dead process: its marker is on disk, its pins are held, nobody will Seal or Abort.
	if err := attempts.Begin(l.ctx, backup.Attempt{ID: model.NewID(), StartedAt: model.UnixNano(time.Now().UnixNano()), ControlRevision: revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := plane.Begin(l.ctx, cut); err != nil {
		t.Fatal(err)
	}
	if pins, err := l.app.Storage.JournalPins(); err != nil || len(pins) != 64 {
		t.Fatalf("the dead backup holds %d pins (%v), want one per group", len(pins), err)
	}
	service := func(pins backup.PinReaper) *backup.Service {
		svc, err := backup.New(backup.Config{Control: l.app.Control, Data: plane, Processed: backup.AppliedProcessed(plane), Authority: l.authority, Authorizer: l.app.Auth, Keys: l.keys, DataKEK: "data-kek", SecretKEK: "secret-kek", Attempts: attempts, Pins: pins, Clock: time.Now})
		if err != nil {
			t.Fatal(err)
		}
		return svc
	}
	if report, err := service(nil).Reap(l.ctx); err == nil && report.Attempts != 0 {
		t.Fatalf("an attempt was closed with no way to drop its pins: %+v", report)
	}
	report, err := service(backup.EnginePins(l.app.Storage)).Reap(l.ctx)
	if err != nil || report.Attempts != 1 || report.Dropped != 64 || report.Unowned != 0 {
		t.Fatalf("reap: %+v %v", report, err)
	}
	if pins, err := l.app.Storage.JournalPins(); err != nil || len(pins) != 0 {
		t.Fatalf("pins left after the reap: %d (%v)", len(pins), err)
	}
	if open, _ := attempts.Incomplete(l.ctx); len(open) != 0 {
		t.Fatalf("the reaped attempt is still open: %v", open)
	}
}
