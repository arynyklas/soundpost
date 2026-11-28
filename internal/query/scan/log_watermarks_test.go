// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package scan

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/value"
	"github.com/arynyklas/soundpost/internal/storage"
)

// countingMarks counts the times the cut is asked of the storage's iterator: that is a release barrier, a
// fence over every group of the cut and an authority read, each time.
type countingMarks struct {
	*logFixtureRows
	asked int
}

func (r *countingMarks) Watermarks() []model.Cursor { r.asked++; return r.logFixtureRows.Watermarks() }

type countingMarksScanner struct{ rows *countingMarks }

func (s *countingMarksScanner) Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error) {
	return s.rows, nil
}

func marksIterator(t *testing.T, pages int) (LogIterator, *countingMarks, *value.BoundedAccount) {
	t.Helper()
	project := model.ID{9}
	rows := &countingMarks{logFixtureRows: &logFixtureRows{marks: []model.Cursor{{Group: model.ID{8}, Index: 41}}}}
	for range pages {
		rows.pages = append(rows.pages, logPage(project))
	}
	account := value.NewBoundedAccount(1 << 20)
	it, err := NewLogSource(&countingMarksScanner{rows: rows}, auth.Scope{}, project, storage.ReadFence{}).Select(context.Background(), LogSelection{Start: 0, End: 1000, Account: account})
	if err != nil {
		t.Fatal(err)
	}
	return it, rows, account
}

// The cut of a scan is certified when the iterator reports it, not at every page: asking for it after each of
// forty pages made two release barriers of every page of a log query. The cut reported is still one the
// storage certified, at the end of the rows or when the iterator is closed early.
func TestLogIteratorCertifiesItsCutOnceNotAtEveryPage(t *testing.T) {
	const pages = 40
	it, rows, account := marksIterator(t, pages)
	n := 0
	for {
		_, err := it.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != pages*3 {
		t.Fatalf("%d rows, want %d", n, pages*3)
	}
	if got := it.Watermarks(); len(got) != 1 || got[0].Index != 41 {
		t.Fatalf("cut %v after the end of the rows", got)
	}
	if rows.asked > 1 {
		t.Fatalf("the cut was asked %d times for %d pages, want once (at the end)", rows.asked, pages)
	}
	if account.Used() != 0 || rows.closes != 1 {
		t.Fatalf("leaked: %d bytes, %d closes", account.Used(), rows.closes)
	}

	// Closed early: the cut is the one certified at the close, still asked of the open storage iterator.
	it, rows, _ = marksIterator(t, pages)
	for range 7 {
		if _, err := it.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := it.Close(); err != nil {
		t.Fatal(err)
	}
	if got := it.Watermarks(); len(got) != 1 || got[0].Index != 41 {
		t.Fatalf("cut %v after an early close, want the cut the storage certified", got)
	}
	if rows.asked != 1 {
		t.Fatalf("the cut was asked %d times for an early close, want once", rows.asked)
	}

	// Asked in the middle of the rows, it is certified then.
	it, rows, _ = marksIterator(t, pages)
	for range 4 {
		if _, err := it.Next(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if got := it.Watermarks(); len(got) != 1 || rows.asked != 1 {
		t.Fatalf("cut %v asked %d times in the middle of the rows, want the certified cut, once", got, rows.asked)
	}
	_ = it.Close()

	// A failed iterator does not certify anything on its way out.
	it, rows, _ = marksIterator(t, 3)
	rows.failure = model.Fail(model.Unavailable)
	var err error
	for err == nil {
		_, err = it.Next(context.Background())
	}
	if errors.Is(err, io.EOF) {
		t.Fatal("a failure was reported as the end of the rows")
	}
	if rows.asked != 0 {
		t.Fatalf("the cut was asked %d times by an iterator that failed", rows.asked)
	}
}
