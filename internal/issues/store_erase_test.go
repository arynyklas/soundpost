// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"context"
	"encoding/json"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/issues"
	"soundpost/internal/model"
)

// A historical-range deletion of the error signal erases issue evidence in
// control. The service over the real adapter must keep working: an issue left
// without evidence is not found, a partially erased one loads, can be acted on
// and keeps accepting evidence.
func TestServiceOverControlAfterHistoricalRangeErasure(t *testing.T) {
	f := newRealFx(t)
	ctx := context.Background()
	f.apply(f.ev(1, f.A, 50), f.ev(1, f.A, 55), f.ev(2, f.A, 60), f.ev(2, f.A, 500))
	whole, partial := f.issueByFp(1), f.issueByFp(2)
	if len(whole.Occurrences) != 2 || len(partial.Occurrences) != 2 {
		t.Fatalf("fixture: %d and %d occurrences", len(whole.Occurrences), len(partial.Occurrences))
	}

	admin := f.scopeFor("issues@example.test", "issues fixture password 2026", f.org, nil, auth.OrgAdmin)
	var revision model.Revision
	if err := f.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.ErrorKind}, Start: 40, End: 100,
		Reason: "erase range", At: 100, PhysicalDeadline: 1 << 40, BackupDeadline: 1 << 41})
	id := model.NewID()
	if _, err := f.app.Control.Transact(ctx, admin, control.Command{CommandID: id, ExpectedRevision: revision, Kind: string(control.KindDeleteScope), Payload: raw}); err != nil {
		t.Fatal(err)
	}
	barriers := make([]model.Cursor, model.DeleteSlots)
	for i := range barriers {
		barriers[i] = model.Cursor{Group: model.NewID(), Index: model.Uint64(i + 1)}
	}
	if _, err := f.app.Control.RecordBarriers(ctx, id, barriers); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.Control.CompleteDeletion(ctx, id, 100, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := f.svc.Get(ctx, f.writer, f.project, whole.ID); code(err) != model.NotFound {
		t.Fatalf("a fully erased issue must be not found: %v", err)
	}
	got, err := f.svc.Get(ctx, f.writer, f.project, partial.ID)
	if err != nil {
		t.Fatalf("a partially erased issue must load: %v", err)
	}
	if len(got.Occurrences) != 1 || got.Occurrences[0].EventTime != 500 || got.Revision != partial.Revision+1 {
		t.Fatalf("partially erased issue: %+v", got)
	}
	if _, err = f.svc.Explain(ctx, f.writer, f.project, partial.ID); err != nil {
		t.Fatalf("explain: %v", err)
	}
	// It stays actionable (the loaded revision is the current one) and evidence keeps flowing.
	if _, err = f.svc.Act(ctx, f.writer, issues.IssueAction{CommandID: model.NewID(), ExpectedVersion: got.Revision, IssueID: got.ID, Kind: "ignore", Reason: "noise"}); err != nil {
		t.Fatalf("act on the partially erased issue: %v", err)
	}
	f.apply(f.ev(2, f.A, 900))
	if again := f.issueByFp(2); len(again.Occurrences) != 2 {
		t.Fatalf("evidence after the erasure: %+v", again.Occurrences)
	}
	// Erasure is stable across a restart.
	f.restart()
	if _, err = f.svc.Get(ctx, f.writer, f.project, whole.ID); code(err) != model.NotFound {
		t.Fatalf("after restart: %v", err)
	}
}
