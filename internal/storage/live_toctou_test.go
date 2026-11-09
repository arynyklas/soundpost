// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"testing"
	"time"

	"soundpost/internal/model"
)

// liveFirstPage subscribes, commits rows, arms the view and returns the first page
// the feed releases.
func liveFirstPage(t *testing.T, env *toctouEnv, kind model.Kind, next ...model.DeletePredicate) ChangePage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	it, err := env.engine.Subscribe(ctx, env.scope, SubscribeRequest{Projects: []model.ID{env.d.Project}, Signal: kind})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	env.commit()
	env.view.arm(pageFetchCalls, next...)
	page, err := it.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !env.view.didFlip() {
		t.Fatal("the deletion view never changed during the read: the test did not exercise the window")
	}
	return page
}

// A range deletion that begins between the feed's predicate fetch and the
// release of the page must not release covered rows.
func TestLiveToctouRangeDeletionCommittingMidPageHidesCoveredRows(t *testing.T) {
	env, ids := metricPage(t, true, 2, 3, 4, 5, 6)
	page := liveFirstPage(t, env, model.Metric, rangeDelete(env.d, []model.Kind{model.Metric}, 3, 5))
	want := []model.ID{ids[0], ids[3], ids[4]}
	if !sameIDs(page.Page.IDs, want) {
		t.Fatalf("live page released %v, want only %v", page.Page.IDs, want)
	}
}

func TestLiveToctouEntityDeletionCommittingMidPageHidesCoveredRows(t *testing.T) {
	env, root, _, kept := replayPage(t, true)
	entity := model.DeletePredicate{Operation: model.NewID(), Org: env.d.Org, Mode: model.DeleteEntity, Projects: []model.ID{env.d.Project}, Signals: []model.Kind{model.Replay}, Entities: []model.ID{root}, Generation: 1}
	page := liveFirstPage(t, env, model.Replay, entity)
	if !sameIDs(page.Page.IDs, kept) {
		t.Fatalf("live page released %v under an entity deletion that began mid-page, want only %v", page.Page.IDs, kept)
	}
}
