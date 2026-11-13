// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	bolt "go.etcd.io/bbolt"
	"os"
	"reflect"
	"soundpost/internal/model"
	"soundpost/internal/policy"
	"sync"
	"testing"
)

// applyFileHits counts the canary (every encoding the command history uses) in the raw bytes of
// apply.db, free pages included. rawHits only sees what a bucket can still reach.
func applyFileHits(t *testing.T, e *Engine, canary string) int {
	t.Helper()
	raw, err := os.ReadFile(e.db.Path())
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range canaryForms(canary) {
		n += bytes.Count(raw, f)
	}
	return n
}

// checkDatabase fails if bbolt's own structural check finds anything wrong.
func checkDatabase(t *testing.T, e *Engine) {
	t.Helper()
	// Check walks the transaction from a goroutine of its own: drain it before the transaction
	// ends, or it keeps reading a transaction (and a mapping) that is gone.
	var found []error
	if err := e.db.View(func(tx *bolt.Tx) error {
		for err := range tx.Check() {
			found = append(found, err)
		}
		return nil
	}); err != nil {
		t.Fatalf("bbolt check: %v", err)
	}
	if len(found) > 0 {
		t.Fatalf("bbolt check: %v", found)
	}
}

// bbolt never zeroes a freed page, so after a bucket-level erase the raw apply.db file still
// holds the deleted bytes. The design promises physical erasure: the pass must not leave them in
// the file either, and must leave every live page and every ACKed receipt intact.
func TestEraseScrubsFreedPagesOfApplyDatabase(t *testing.T) {
	x := newEraseEnv(t)
	hit := x.appendMixed(eraseCanary, bothDeadlines)
	other := x.appendMixed(otherCanary, bothDeadlines)
	x.coldCanary(eraseCanary)
	if applyFileHits(t, x.e, eraseCanary) == 0 {
		t.Fatal("fixture invalid: the canary is not in the raw apply.db before erasure")
	}
	report, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil)
	if err != nil || report.Records < 2 {
		t.Fatalf("report %+v %v", report, err)
	}
	if hits := rawHits(t, x.e, eraseCanary); len(hits) != 0 {
		t.Fatalf("reachable bytes survived: %v", hits)
	}
	for _, c := range []string{eraseCanary, otherCanary} {
		if n := applyFileHits(t, x.e, c); n != 0 {
			t.Fatalf("%d copies of an erased canary remain in free pages of the raw apply.db file", n)
		}
	}
	checkDatabase(t, x.e)
	x.integrity()
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM, other.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("kept rows after scrub %v want %v", got, want)
	}
	retry, err := x.e.Append(context.Background(), hit.scope, hit.batch)
	if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, hit.receipt)) {
		t.Fatalf("an ACKed receipt did not survive the scrub: %v", err)
	}
	x.reopen()
	checkDatabase(t, x.e)
	if got, want := x.ids(model.Metric), sortedIDs(hit.keepM, other.keepM); !reflect.DeepEqual(got, want) {
		t.Fatalf("restart after scrub changed rows %v want %v", got, want)
	}
}

// Expiry is physical too: a record that left retention must not stay in free pages.
func TestExpireScrubsFreedPagesOfApplyDatabase(t *testing.T) {
	x := newEraseEnv(t)
	x.appendMixed(eraseCanary, bothDeadlines)
	if applyFileHits(t, x.e, eraseCanary) == 0 {
		t.Fatal("fixture invalid: no canary in the raw file")
	}
	if report, err := x.e.EraseExpired(context.Background(), metricDeadline, nil); err != nil || report.Records == 0 {
		t.Fatalf("expiry %+v %v", report, err)
	}
	if n := applyFileHits(t, x.e, eraseCanary); n != 0 {
		t.Fatalf("%d expired canary copies remain in the raw apply.db file", n)
	}
	checkDatabase(t, x.e)
}

// A read transaction that started before the erasure can still walk the pages the erasure freed,
// so they may not be zeroed while it is open. The pass must say it is incomplete instead of
// claiming success, and a rerun once the reader is gone must finish the job: the owed scrub is
// durable, not an in-memory flag.
func TestEraseScrubDefersWhileAReaderIsOpenThenCompletes(t *testing.T) {
	x := newEraseEnv(t)
	x.appendMixed(eraseCanary, bothDeadlines)
	x.e.scrub = scrubConfig{attempts: 1}
	var reader *bolt.Tx
	x.e.fault = func(at string) error {
		if at == "erase_scrub" && reader == nil {
			var err error
			reader, err = x.e.db.Begin(false)
			return err
		}
		return nil
	}
	preds := []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}
	first, err := x.e.EraseDeleted(context.Background(), preds, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reader == nil {
		t.Fatal("the hook never opened the reader")
	}
	if applyFileHits(t, x.e, eraseCanary) == 0 {
		t.Fatal("pages a live reader may still read were zeroed")
	}
	if !first.ScrubPending {
		t.Fatalf("an incomplete scrub must be reported as pending: %+v", first)
	}
	if err = reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	second, err := x.e.EraseDeleted(context.Background(), preds, nil)
	if err != nil || second.ScrubPending || second.PagesScrubbed == 0 || second.Batches != 0 {
		t.Fatalf("rerun %+v %v", second, err)
	}
	if n := applyFileHits(t, x.e, eraseCanary); n != 0 {
		t.Fatalf("%d copies remain after the rerun", n)
	}
	checkDatabase(t, x.e)
	third, err := x.e.EraseDeleted(context.Background(), preds, nil)
	if err != nil || third != (EraseReport{}) {
		t.Fatalf("the owed scrub was not cleared: %+v %v", third, err)
	}
}

// A crash between the bucket-level erasure and the scrub, and one in the middle of the scrub,
// must each reopen into a consistent database and be repaired by the next pass even though that
// pass finds nothing left to erase.
func TestEraseScrubCrashPointsAreRepairedByRerun(t *testing.T) {
	for _, hook := range []string{"erase_scrub", "scrub_chunk"} {
		t.Run(hook, func(t *testing.T) {
			x := newEraseEnv(t)
			hit := x.appendMixed(eraseCanary, bothDeadlines)
			x.e.scrub = scrubConfig{chunkPages: 4}
			fired := false
			x.e.fault = func(at string) error {
				if at == hook && !fired {
					fired = true
					return errors.New("crash at " + at)
				}
				return nil
			}
			preds := []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}
			if _, err := x.e.EraseDeleted(context.Background(), preds, nil); err == nil || !fired {
				t.Fatalf("hook %s never fired (%v)", hook, err)
			}
			x.reopen()
			checkDatabase(t, x.e)
			x.integrity()
			if got, want := x.ids(model.Metric), sortedIDs(hit.keepM); !reflect.DeepEqual(got, want) {
				t.Fatalf("rows after the crash %v want %v", got, want)
			}
			if _, err := x.e.Append(context.Background(), hit.scope, hit.batch); err != nil {
				t.Fatalf("an ACKed batch is no longer answerable after the crash: %v", err)
			}
			x.e.scrub = scrubConfig{chunkPages: 4}
			if _, err := x.e.EraseDeleted(context.Background(), preds, nil); err != nil {
				t.Fatal(err)
			}
			if n := applyFileHits(t, x.e, eraseCanary); n != 0 {
				t.Fatalf("%d copies remain after the rerun", n)
			}
			checkDatabase(t, x.e)
			x.integrity()
		})
	}
}

// Intake continues while the scrub zeroes free pages in chunks: every batch ACKed before, during
// or after still answers with its original receipt and the database stays structurally valid.
func TestEraseScrubRacesIntakeWithoutLosingAReceipt(t *testing.T) {
	x := newEraseEnv(t)
	x.appendMixed(eraseCanary, bothDeadlines)
	x.e.scrub = scrubConfig{chunkPages: 2}
	var mu sync.Mutex
	var acked []erased
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i >= 40 {
				return
			}
			// t.Fatal is unsafe off the test goroutine, so the helper's failure paths are kept out
			// of it: append directly and record the outcome.
			a, ok := x.tryAppendMixed("RACE" + model.NewID().String()[:16])
			if ok {
				mu.Lock()
				acked = append(acked, a)
				mu.Unlock()
			}
		}
	}()
	for range 3 {
		if _, err := x.e.EraseDeleted(context.Background(), []model.DeletePredicate{x.rangePredicate(0, 10, model.Metric)}, nil); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	if n := applyFileHits(t, x.e, eraseCanary); n != 0 {
		t.Fatalf("%d copies of the erased canary remain after racing intake", n)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(acked) == 0 {
		t.Fatal("fixture invalid: no batch was acknowledged while the scrub ran")
	}
	for _, a := range acked {
		retry, err := x.e.Append(context.Background(), a.scope, a.batch)
		if err != nil || !bytes.Equal(mustJSON(t, retry), mustJSON(t, a.receipt)) {
			t.Fatalf("receipt %s lost: %v", a.receipt.BatchID, err)
		}
	}
	checkDatabase(t, x.e)
	x.integrity()
}

// tryAppendMixed is appendMixed's cousin for goroutines: it returns instead of failing the test,
// and admits one kept metric (outside every erased range) so it never interferes with the erased
// canary.
func (x *eraseEnv) tryAppendMixed(tag string) (erased, bool) {
	ctx := context.Background()
	src, err := x.a.SourceAuthority(ctx, x.cred, true)
	if err != nil {
		return erased{}, false
	}
	service, err := policy.New(x.a, nil)
	if err != nil {
		return erased{}, false
	}
	grant, err := service.ResolveSource(ctx, x.cred, x.d.Project, x.d.Source, src.Policy.Revision)
	if err != nil {
		return erased{}, false
	}
	record := x.metric(tag, 50)
	b := model.Batch{Version: 1, Project: x.d.Project, Source: x.d.Source, Producer: model.NewID(), ID: model.NewID(), PolicyRevision: src.Policy.Revision, Records: []model.Record{record}}
	if b.RouteSlot, err = model.OwnerSlot(x.d.Org, b.Project, b.Source, b.Producer, record); err != nil {
		return erased{}, false
	}
	n, err := policy.Normalize(grant, b)
	if err != nil {
		return erased{}, false
	}
	n.Deadlines = bothDeadlines
	scope, err := grant.Scope()
	if err != nil {
		return erased{}, false
	}
	if n.Reservation, err = x.store.ReserveAdmission(ctx, scope, n); err != nil {
		return erased{}, false
	}
	receipt, err := x.e.Append(ctx, scope, n)
	if err != nil {
		return erased{}, false
	}
	return erased{batch: n, receipt: receipt, scope: scope}, true
}
