// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts_test

import (
	"context"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/model"
)

// A restore from a backup older than a retirement brings back a published, unfenced map whose
// retention is long over. ReconcileRetired retires exactly such maps at activation: while a
// snapshot pin holds them nothing is retired, afterwards the maps whose retention is over are,
// a map a reference still retains is left, and a repeat has nothing to do.
func TestReconcileRetiredRetiresOnlyExpiredMapsAndHonoursPins(t *testing.T) {
	f := newLifeFx(t, 1<<20)
	ctx := context.Background()
	expiredA := f.put(t, "expired-a", false)
	expiredB := f.put(t, "expired-b", true)
	held := f.put(t, "held", false)
	f.ref(t, held, f.origin(artifacts.ReferenceError), f.hours(5))

	state := func(a artifacts.Artifact) string {
		t.Helper()
		var got string
		if err := f.app.Control.View(ctx, func(st model.ControlState) error {
			got = st.ArtifactIntents[a.Manifest.Org.String()+":"+a.Manifest.Project.String()+":"+a.ID.String()].State
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return got
	}
	f.at(2 * time.Hour) // every upload's own deadline (one hour) is over; the reference runs to five

	f.pins.set(true, nil)
	if n, err := f.life.ReconcileRetired(ctx); err != nil || n != 0 {
		t.Fatalf("reconcile under a pin: retired %d err %v, want 0", n, err)
	}
	if got := state(expiredA); got != "published" {
		t.Fatalf("a pinned expired map is %q, want published", got)
	}
	f.pins.set(false, nil)
	if n, err := f.life.ReconcileRetired(ctx); err != nil || n != 2 {
		t.Fatalf("reconcile: retired %d err %v, want the 2 expired maps", n, err)
	}
	for name, a := range map[string]artifacts.Artifact{"expired-a": expiredA, "expired-b": expiredB} {
		if got := state(a); got != "retired" {
			t.Fatalf("%s is %q after reconcile, want retired", name, got)
		}
	}
	if got := state(held); got != "published" {
		t.Fatalf("a map a reference retains is %q, want published", got)
	}
	if n, err := f.life.ReconcileRetired(ctx); err != nil || n != 0 {
		t.Fatalf("repeat reconcile: retired %d err %v, want 0", n, err)
	}
}
