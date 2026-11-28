// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// inheritReference is InheritMetadata as it was written before the merge of cuts in the form it returns: the
// minimum index of a group in any cut, one cursor per group, ascending by group.
func inheritReference(result *Result, inputs ...Result) {
	hasCursors := len(result.Watermarks) > 0
	for _, input := range inputs {
		result.Partial = result.Partial || input.Partial
		hasCursors = hasCursors || len(input.Watermarks) > 0
	}
	if !hasCursors {
		result.Watermarks = nil
		return
	}
	groups := map[model.ID]uint64{}
	merge := func(cursors []model.Cursor) {
		for _, c := range cursors {
			index, ok := groups[c.Group]
			if !ok || uint64(c.Index) < index {
				groups[c.Group] = uint64(c.Index)
			}
		}
	}
	merge(result.Watermarks)
	for _, input := range inputs {
		merge(input.Watermarks)
	}
	result.Watermarks = make([]model.Cursor, 0, len(groups))
	for group, index := range groups {
		result.Watermarks = append(result.Watermarks, model.Cursor{Group: group, Index: model.Uint64(index)})
	}
	sort.Slice(result.Watermarks, func(i, j int) bool {
		return bytes.Compare(result.Watermarks[i].Group[:], result.Watermarks[j].Group[:]) < 0
	})
}

func cutOf(groups []int, index func(int) uint64) []model.Cursor {
	out := make([]model.Cursor, len(groups))
	for i, g := range groups {
		out[i] = model.Cursor{Group: model.ID{byte(g >> 8), byte(g)}, Index: model.Uint64(index(i))}
	}
	return out
}

// Every operator of every series of an evaluation merges the cut of its inputs into its own: 64 cursors, a
// map and a sort for each, 6 % of the CPU of the Queries gate mix. Cuts that are already one cursor per
// group in ascending order, which is the form every merge returns, are merged in one linear pass; the
// cursors are the ones the map and the sort gave.
func TestInheritMetadataMergesCanonicalCutsWithoutAMapAndASort(t *testing.T) {
	groups := make([]int, 64)
	for i := range groups {
		groups[i] = i * 3
	}
	a := Result{Watermarks: cutOf(groups, func(i int) uint64 { return uint64(100 + i) })}
	b := Result{Watermarks: cutOf(groups, func(i int) uint64 { return uint64(120 - i) }), Partial: true}
	canonical := func() Result {
		r := Result{}
		InheritMetadata(&r, a)
		return r
	}
	base := canonical()
	allocs := testing.AllocsPerRun(200, func() {
		r := Result{Watermarks: base.Watermarks}
		InheritMetadata(&r, b)
	})
	t.Logf("%.1f allocations to merge two cuts of 64 cursors", allocs)
	if allocs > 3 {
		t.Fatalf("%.1f allocations to merge two cuts of 64 cursors, want at most 3 (a map and a sort took about ten)", allocs)
	}
}

// The fast path and the general one give the same cut for every combination of cuts, canonical or not, with
// groups in common or not, empty or not.
func TestInheritMetadataFastPathEqualsTheReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 7))
	randomCut := func(canonical bool) []model.Cursor {
		n := rng.IntN(9)
		seen := map[int]bool{}
		var gs []int
		for len(gs) < n {
			g := rng.IntN(12)
			if !seen[g] {
				seen[g] = true
				gs = append(gs, g)
			}
		}
		if canonical {
			sort.Ints(gs)
		} else if rng.IntN(3) == 0 && len(gs) > 0 {
			gs = append(gs, gs[0]) // a group twice: the minimum of the two
		}
		return cutOf(gs, func(int) uint64 { return uint64(rng.IntN(50)) })
	}
	for i := range 2000 {
		canonical := rng.IntN(4) != 0
		inputs := make([]Result, rng.IntN(4))
		for j := range inputs {
			inputs[j] = Result{Watermarks: randomCut(canonical), Partial: rng.IntN(2) == 0}
		}
		start := randomCut(canonical)
		got := Result{Watermarks: append([]model.Cursor(nil), start...)}
		want := Result{Watermarks: append([]model.Cursor(nil), start...)}
		InheritMetadata(&got, inputs...)
		inheritReference(&want, inputs...)
		if !reflect.DeepEqual(got.Watermarks, want.Watermarks) || got.Partial != want.Partial {
			t.Fatalf("case %d: start %v inputs %v:\n got %v (partial %v)\nwant %v (partial %v)", i, start, inputs, got.Watermarks, got.Partial, want.Watermarks, want.Partial)
		}
	}
}
