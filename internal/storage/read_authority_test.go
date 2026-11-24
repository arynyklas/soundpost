// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// A deletion leaves one tombstone on every slot of the node (its barrier is recorded on each of them). The
// deletions an authority read returns list it once, as the deletion read of a page does: a reader compares
// the sets of two reads (a scan compares the set its chunk was built under with the one of its release
// barrier), and a set that counts the same deletion on every slot differs from one that counts it once.
func TestAuthorityReadListsADeletionOnceHoweverManyTombstonesItLeft(t *testing.T) {
	x := newCheckpointEnv(t)
	pred := x.rangePredicate(0, 10, model.Metric)
	barrierAll(t, x.e, pred)
	ctx := context.Background()
	projects := []model.ID{x.d.Project}
	viaAuthority, err := x.e.authorizeReadDeletions(ctx, x.read, projects, model.Metric)
	if err != nil {
		t.Fatal(err)
	}
	viaDeletions, err := x.e.readDeletions(ctx, x.d.Org, projects)
	if err != nil {
		t.Fatal(err)
	}
	if len(viaAuthority) != 1 || viaAuthority[0].Operation != pred.Operation {
		t.Fatalf("the authority read lists %d deletions for the one deletion that left a tombstone on every slot, want 1", len(viaAuthority))
	}
	if deletionsChanged(viaAuthority, viaDeletions) {
		t.Fatalf("the authority read (%d deletions) and the deletion read (%d) of the same moment differ", len(viaAuthority), len(viaDeletions))
	}
}

// A scan that meets the deletion above ends: the set of its release barrier is the set its chunk was built
// under, so the chunk is not rebuilt for ever.
func TestScanOverADeletionThatLeftATombstoneOnEverySlotEnds(t *testing.T) {
	x := newCheckpointEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	barrierAll(t, x.e, x.rangePredicate(0, 10, model.Metric))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	it, err := x.e.Scan(ctx, x.read, ScanRequest{Projects: []model.ID{x.d.Project}, Signal: model.Metric, End: 1 << 40})
	if err != nil {
		t.Fatal(err)
	}
	defer it.Close()
	var got []model.ID
	for {
		page, err := it.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the scan did not end (%v after %v): its chunk is rebuilt again and again", err, ctx.Err())
		}
		got = append(got, page.IDs...)
	}
	if want := sortedIDs(hit.keepM); len(got) != 1 || got[0] != want[0] {
		t.Fatalf("rows %v want the one the deletion does not cover %v", got, want)
	}
}
