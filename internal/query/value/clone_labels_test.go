// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/arynyklas/soundpost/internal/model"
)

// A log row is cloned at every pipeline stage that owns it, and CloneLabels cloned each name and value on its
// own: 1+2n allocations for n labels. The clone is two allocations, whatever n is.
func TestCloneLabelsAllocatesTwiceWhateverTheLabelCount(t *testing.T) {
	ls := model.Labels{{Name: "app", Value: "checkout"}, {Name: "cluster", Value: "eu-west-1"}, {Name: "env", Value: "production"}, {Name: "host", Value: "node-0042"}, {Name: "level", Value: "info"}, {Name: "pod", Value: "checkout-7d9f8c6b5-x2x4z"}}
	var out model.Labels
	n := testing.AllocsPerRun(200, func() { out = CloneLabels(ls) })
	if n > 2 {
		t.Fatalf("CloneLabels of %d labels made %v allocations, want at most 2", len(ls), n)
	}
	if !reflect.DeepEqual(out, ls) {
		t.Fatalf("clone differs: %v", out)
	}
}

func TestCloneLabelsDoesNotAliasTheOriginalAndKeepsEmptyShapes(t *testing.T) {
	ls := model.Labels{{Name: "a", Value: ""}, {Name: "", Value: "v"}, {Name: "caf\u00e9", Value: "\xff"}}
	out := CloneLabels(ls)
	if !reflect.DeepEqual(out, ls) {
		t.Fatalf("clone differs: %v", out)
	}
	for i := range ls {
		if len(ls[i].Name) > 0 && unsafe.StringData(out[i].Name) == unsafe.StringData(ls[i].Name) {
			t.Fatalf("name %d aliases the original", i)
		}
		if len(ls[i].Value) > 0 && unsafe.StringData(out[i].Value) == unsafe.StringData(ls[i].Value) {
			t.Fatalf("value %d aliases the original", i)
		}
	}
	if e := CloneLabels(nil); e == nil || len(e) != 0 {
		t.Fatalf("clone of nil labels is %#v, want an empty non-nil slice", e)
	}
	if e := CloneLabels(model.Labels{{}, {}}); len(e) != 2 || e[0] != (model.Label{}) {
		t.Fatalf("clone of empty labels is %#v", e)
	}
}
