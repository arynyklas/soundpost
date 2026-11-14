// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

type sumGenerations struct {
	f *artifactFixture
}

func (g sumGenerations) DeleteGeneration(ctx context.Context, org model.ID, projects []model.ID) (uint64, error) {
	base, err := g.f.app.Auth.SourceLifecycleGenerations().DeleteGeneration(ctx, org, projects)
	if err != nil {
		return 0, err
	}
	own, err := g.f.app.Control.DeleteGeneration(ctx, org)
	return base + own, err
}

// Artifact GC removes readable fragment bytes: the cancellation that authorizes
// it advances the delete generation, so a warm cache entry bound to the old
// generation dies.
func TestDeleteArtifactGCAdvancesGenerationAndKillsWarmEntries(t *testing.T) {
	f := newArtifactFixture(t)
	ctx := context.Background()
	r := f.orphan(t)
	scope := f.scope(t, auth.ArtifactWrite)
	cache, err := auth.NewCache(f.app.Auth, sumGenerations{f}, 8, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cache.Lookup(ctx, scope, "profile", "artifact", "p")
	if err != nil || res.Hit {
		t.Fatal(err)
	}
	if err = cache.Store(ctx, scope, res.Fill, []byte("warm"), false); err != nil {
		t.Fatal(err)
	}
	if res, err = cache.Lookup(ctx, scope, "profile", "artifact", "p"); err != nil || !res.Hit {
		t.Fatalf("entry not warm: %v", err)
	}
	before, _ := f.app.Control.DeleteGeneration(ctx, f.org)
	if _, err = f.app.Control.CancelArtifact(ctx, scope, r.Manifest.ReservationID, model.NewID()); err != nil {
		t.Fatal(err)
	}
	if after, _ := f.app.Control.DeleteGeneration(ctx, f.org); after <= before {
		t.Fatalf("artifact GC did not advance the delete generation: %d -> %d", before, after)
	}
	if res, err = cache.Lookup(ctx, scope, "profile", "artifact", "p"); err != nil || res.Hit {
		t.Fatalf("warm entry survived artifact GC: hit=%v err=%v", res.Hit, err)
	}
}
