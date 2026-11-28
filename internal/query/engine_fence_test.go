// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
)

// A read that forbids partial results lets the storage refuse a shard behind a minimum cursor; a read that allows them reads every answering
// shard at its own cut and judges freshness itself (stale), so it must not hand the minimum to a fence that would drop the shard as missing.
func TestReadFenceDoesNotLetAPartialReadDropAShardThatOnlyLags(t *testing.T) {
	min := []model.Cursor{{Group: model.ID{4}, Index: 9}}
	strict := readFence(normalized{Request: Request{AllowPartial: false, MinCursors: min}})
	if strict.AllowPartial || len(strict.Min) != 1 || strict.Min[0] != min[0] {
		t.Fatalf("a read that forbids partial results keeps the storage refusal: %+v", strict)
	}
	partial := readFence(normalized{Request: Request{AllowPartial: true, MinCursors: min}})
	if !partial.AllowPartial || len(partial.Min) != 0 {
		t.Fatalf("a read that allows partial results does not give the minimum to the storage fence: %+v", partial)
	}
}
