// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
	"testing"
)

// A guard that allowed a candidate during the scan is consulted again, with Final set, inside the
// erasing transaction. A veto that became true in between (a legal hold placed while the pass
// ran) keeps the bytes and is reported as Held; a guard that keeps allowing erases them.
func TestEraseGuardIsConsultedAgainInsideTheErasingTransaction(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	pred := []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}
	var scans, finals []EraseCandidate
	report, err := x.e.EraseDeleted(context.Background(), pred, func(_ context.Context, c EraseCandidate) (bool, error) {
		if c.Final {
			finals = append(finals, c)
			return false, nil // became true after the scan
		}
		scans = append(scans, c)
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Held != 1 || report.Records != 0 || report.Batches != 0 {
		t.Fatalf("a veto that arrived after the scan did not stop the erasure: %+v", report)
	}
	if len(scans) != 1 || len(finals) != 1 {
		t.Fatalf("%d scan and %d final consultations, want one each", len(scans), len(finals))
	}
	same := scans[0]
	same.Final = true
	if finals[0].Record == nil || finals[0].Record.ID != hit.secret.ID || finals[0].Cursor != same.Cursor || finals[0].Org != same.Org || finals[0].Project != same.Project || finals[0].Kind != same.Kind || finals[0].Slot != same.Slot {
		t.Fatalf("the final consultation names a different candidate: %+v vs %+v", finals[0], same)
	}
	if !hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") || !hasHit(rawHits(t, x.e, eraseCanary), "batches") {
		t.Fatal("bytes were removed although the final consultation vetoed them")
	}
	x.integrity()
	// A guard that does not change its mind erases, and sees the Final consultation too.
	finals = nil
	report, err = x.e.EraseDeleted(context.Background(), pred, func(_ context.Context, c EraseCandidate) (bool, error) {
		if c.Final {
			finals = append(finals, c)
		}
		return true, nil
	})
	if err != nil || report.Records != 1 || report.Held != 0 || len(finals) != 1 {
		t.Fatalf("%+v %v finals %d", report, err, len(finals))
	}
	if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
		t.Fatalf("erased bytes still present in %v", hits)
	}
}

// A guard error at the final consultation aborts that erasure fail-closed: nothing is removed.
func TestEraseGuardErrorAtTheFinalConsultationRemovesNothing(t *testing.T) {
	x := newEraseEnv(t)
	x.appendMixed(eraseCanary, bothDeadlines)
	_, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, func(_ context.Context, c EraseCandidate) (bool, error) {
		if c.Final {
			return true, model.Fail(model.Unavailable)
		}
		return true, nil
	})
	if code := faultCode(err); code != model.Unavailable {
		t.Fatalf("final guard failure: %v", err)
	}
	if !hasHit(rawHits(t, x.e, eraseCanary), "replica_commands") || !hasHit(rawHits(t, x.e, eraseCanary), "batches") {
		t.Fatal("bytes were removed although the final guard failed")
	}
}

// The same for an artifact root: the Final consultation names the root, a veto keeps the root and
// every fragment, and an allowing guard erases it.
func TestEraseGuardFinalConsultationProtectsArtifactRoots(t *testing.T) {
	c, a, scope, m, raw := blobFixture(t)
	ctx := context.Background()
	e, err := openTestEngine(t, t.TempDir(), a, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.WriteBlob(ctx, scope, m, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	stored := func() (roots, fragments int) {
		_ = e.db.View(func(tx *bolt.Tx) error {
			roots, fragments = tx.Bucket([]byte("artifact_roots")).Stats().KeyN, tx.Bucket([]byte("artifact_fragments")).Stats().KeyN
			return nil
		})
		return
	}
	if r, f := stored(); r != 1 || f != 2 {
		t.Fatalf("fixture: %d roots %d fragments", r, f)
	}
	pred := []model.DeletePredicate{{Operation: model.NewID(), Org: m.Org, Mode: model.DeleteRetireProject, Projects: []model.ID{m.Project}, Generation: 1}}
	var final *EraseCandidate
	report, err := e.EraseDeleted(ctx, pred, func(_ context.Context, cand EraseCandidate) (bool, error) {
		if cand.Final {
			final = &cand
			return false, nil
		}
		return true, nil
	})
	if err != nil || report.Held != 1 || report.Blobs != 0 {
		t.Fatalf("%+v %v", report, err)
	}
	if final == nil || final.Blob == nil || final.Record != nil || final.Blob.Root != m.Root {
		t.Fatalf("final consultation %+v", final)
	}
	if r, f := stored(); r != 1 || f != 2 {
		t.Fatalf("a vetoed artifact lost data: %d roots %d fragments", r, f)
	}
	if report, err = e.EraseDeleted(ctx, pred, nil); err != nil || report.Blobs != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	if r, f := stored(); r != 0 || f != 0 {
		t.Fatalf("after erase: %d roots %d fragments", r, f)
	}
}
