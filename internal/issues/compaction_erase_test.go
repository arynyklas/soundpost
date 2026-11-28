// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
)

// Privacy deletion wins over compaction: a range that reaches a folded aggregate
// drops it whole (the counts shrink, the safe direction), and the service keeps
// working over what is left.
func TestServiceOverControlAfterErasingAFoldedAggregate(t *testing.T) {
	f := newRealFx(t)
	ctx := context.Background()
	var all []issues.Evidence
	for i := range 1500 {
		all = append(all, f.ev(1, f.A, model.UnixNano(10_000+10*i)))
	}
	f.applyBatches(all, 100)
	before := f.issueByFp(1)
	if before.Compacted == nil || before.Compacted.FirstEvent != 10_000 {
		t.Fatalf("fixture: %+v", before.Compacted)
	}
	window := len(before.Occurrences)

	admin := f.scopeFor("issues@example.test", "issues fixture password 2026", f.org, nil, auth.OrgAdmin)
	var revision model.Revision
	if err := f.app.Control.View(ctx, func(st model.ControlState) error { revision = st.Revision; return nil }); err != nil {
		t.Fatal(err)
	}
	// The range covers one folded evidence's instant, inside the aggregate's bounds and
	// before every evidence still in the window.
	raw, _ := json.Marshal(control.DeleteScope{Mode: model.DeleteHistoricalRange, Projects: []model.ID{f.project}, Signals: []model.Kind{model.ErrorKind}, Start: 10_000, End: 10_005,
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

	after := f.issueByFp(1)
	if after.Compacted != nil || len(after.Occurrences) != window || after.Revision != before.Revision+1 {
		t.Fatalf("aggregate %+v, %d in the window (was %d), revision %d (was %d)", after.Compacted, len(after.Occurrences), window, after.Revision, before.Revision)
	}
	if s := issues.Summarize(after); s.Count != window || s.FirstSeen <= 10_005 {
		t.Fatalf("the summary still attributes deleted evidence: %+v", s)
	}
	// The dedup tail went with the aggregate; evidence keeps flowing and the index stays consistent.
	f.apply(f.ev(1, f.A, 90_000))
	if got := issues.Summarize(f.issueByFp(1)); got.Count != window+1 || got.LastSeen != 90_000 {
		t.Fatalf("after the erasure: %+v", got)
	}
	if st := f.load(); len(st.Occurrences) != window+1 {
		t.Fatalf("index holds %d IDs, want %d", len(st.Occurrences), window+1)
	}
	f.restart()
	if got := issues.Summarize(f.issueByFp(1)); got.Count != window+1 {
		t.Fatalf("after a restart: %+v", got)
	}
}
