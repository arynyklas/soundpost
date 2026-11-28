// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// A reader that allows partial results must be told so even when the shards that did answer hold no
// matching row: otherwise a lost shard reads as a complete, empty answer (a zero graph).
func TestPartialReadSaysSoEvenWhenTheAnsweringShardsHoldNoRow(t *testing.T) {
	store, a, c, d := fixture(t)
	write, b := normalized(t, store, a, c, d)
	read := scanScope(t, store, a, d)
	e, err := openTestEngine(t, t.TempDir(), a, store)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err = e.Append(context.Background(), write, b); err != nil {
		t.Fatal(err)
	}
	scan := func(allowPartial bool, signal model.Kind) (rows int, partial bool, err error) {
		it, err := e.Scan(context.Background(), read, ScanRequest{Projects: []model.ID{d.Project}, Signal: signal, End: 10, Fence: ReadFence{AllowPartial: allowPartial}})
		if err != nil {
			return 0, false, err
		}
		defer it.Close()
		for {
			page, err := it.Next(context.Background())
			if err == io.EOF {
				return rows, partial, nil
			}
			if err != nil {
				return rows, partial, err
			}
			rows += page.Len()
			partial = partial || page.Partial
		}
	}
	// With every shard up, a read that finds nothing is complete.
	if rows, partial, err := scan(true, model.Log); err != nil || rows != 0 || partial {
		t.Fatalf("healthy empty read: rows %d partial %v err %v, want 0 rows, complete", rows, partial, err)
	}
	// One shard is gone: the read without the opt-in is refused, with it the answer says it is partial.
	if err = e.repl.groups[3].Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = scan(false, model.Log); err == nil {
		t.Fatal("a read that forbids partial results was answered with a shard missing")
	}
	if rows, partial, err := scan(true, model.Log); err != nil || rows != 0 || !partial {
		t.Fatalf("empty read with a shard missing: rows %d partial %v err %v, want 0 rows and partial", rows, partial, err)
	}
	// Rows in the surviving shards keep the flag too, delivered once.
	if rows, partial, err := scan(true, model.Metric); err != nil || !partial || rows > 1 {
		t.Fatalf("metric read with a shard missing: rows %d partial %v err %v", rows, partial, err)
	}
}
