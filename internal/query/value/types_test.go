// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package value

import (
	"context"
	"soundpost/internal/model"
	"testing"
)

func TestBoundedAccountEnforcesPeakAndCancellation(t *testing.T) {
	a := NewBoundedAccount(16)
	if e := a.Reserve(12); e != nil {
		t.Fatal(e)
	}
	if e := a.Reserve(5); e == nil {
		t.Fatal("account exceeded limit")
	}
	a.Release(8)
	if e := a.Reserve(12); e != nil {
		t.Fatal(e)
	}
	if a.Used() != 16 {
		t.Fatalf("used %d", a.Used())
	}
	a.Release(16)
	if a.Used() != 0 {
		t.Fatal("release leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := a.Check(ctx); e != context.Canceled {
		t.Fatalf("cancel %v", e)
	}
}
func TestMetadataUsesMinimumSafeGroupCut(t *testing.T) {
	r := Result{Watermarks: []model.Cursor{{Group: model.ID{2}, Index: 12}}}
	InheritMetadata(&r, Result{Partial: true, Watermarks: []model.Cursor{{Group: model.ID{2}, Index: 7}, {Group: model.ID{1}, Index: 30}}})
	if !r.Partial || len(r.Watermarks) != 2 || r.Watermarks[0].Group != (model.ID{1}) || r.Watermarks[1].Index != 7 {
		t.Fatalf("metadata %+v", r)
	}
	InheritMetadata(&r, Result{})
	if !r.Partial || r.Watermarks[1].Index != 7 {
		t.Fatal("empty result fabricated completeness")
	}
}
func TestNativeHistogramCloneRetainsUint64AndBuckets(t *testing.T) {
	h := model.NativeHistogram{Integer: &model.IntegerHistogram{Count: 18446744073709551615, PositiveBuckets: []model.DeltaBucket{9007199254740993}, PositiveCounts: []model.AbsoluteBucket{18446744073709551615}, CustomBounds: []model.FloatBits{0x8000000000000000}}}
	c := CloneHistogram(h)
	h.Integer.Count = 0
	h.Integer.PositiveBuckets[0] = 0
	h.Integer.PositiveCounts[0] = 0
	h.Integer.CustomBounds[0] = 0
	if c.Integer.Count != 18446744073709551615 || c.Integer.PositiveBuckets[0] != 9007199254740993 || c.Integer.PositiveCounts[0] != 18446744073709551615 || c.Integer.CustomBounds[0] != 0x8000000000000000 {
		t.Fatalf("lossy or borrowed histogram %+v", c.Integer)
	}
}
func TestLabelKeysCannotCollideOnSeparators(t *testing.T) {
	a := model.Labels{{Name: "a", Value: "b\x00c=d"}}
	b := model.Labels{{Name: "a", Value: "b"}, {Name: "c", Value: "d"}}
	if LabelKey(a) == LabelKey(b) {
		t.Fatal("ambiguous label identity")
	}
}
func TestSampleCloneRetainsOptionalStartTimestamp(t *testing.T) {
	start := model.UnixNano(-42)
	cloned := CloneSample(Sample{Time: 0, StartTimestamp: &start})
	start = 99
	if cloned.StartTimestamp == nil || *cloned.StartTimestamp != -42 {
		t.Fatal("borrowed start timestamp escaped")
	}
	zero := model.UnixNano(0)
	cloned = CloneSample(Sample{StartTimestamp: &zero})
	if cloned.StartTimestamp == nil || *cloned.StartTimestamp != 0 {
		t.Fatal("present epoch start became absent")
	}
	if CloneSample(Sample{}).StartTimestamp != nil {
		t.Fatal("absent start timestamp invented")
	}
}
func TestExactSampleEqualityIncludesStartAndFloatBits(t *testing.T) {
	zero := model.UnixNano(0)
	otherZero := model.UnixNano(0)
	one := model.UnixNano(1)
	a := Sample{Time: 2, Float: 0x3ff0000000000000, StartTimestamp: &zero}
	b := a
	b.StartTimestamp = &otherZero
	if !EqualSample(a, b) {
		t.Fatal("equal scalar start values depended on pointer identity")
	}
	b.StartTimestamp = nil
	if EqualSample(a, b) {
		t.Fatal("absent and explicit epoch start collapsed")
	}
	b.StartTimestamp = &one
	if EqualSample(a, b) {
		t.Fatal("different start timestamps collapsed")
	}
	if EqualSample(Sample{Float: 0}, Sample{Float: 0x8000000000000000}) {
		t.Fatal("signed zero bits collapsed")
	}
}
func TestLabelOrderingIsLexicalNotIdentityEncoding(t *testing.T) {
	a := model.Labels{{Name: "__name__", Value: "aa"}}
	z := model.Labels{{Name: "__name__", Value: "z"}}
	if CompareLabels(a, z) >= 0 || CompareLabels(z, a) <= 0 || CompareLabels(a, CloneLabels(a)) != 0 {
		t.Fatal("series ordering used length-prefixed identity order instead of lexical labels")
	}
}
