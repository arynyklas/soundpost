// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate_test

import (
	"context"
	"reflect"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/symbolicate"
	"testing"
)

func budgetFixture(t *testing.T) (*scopedFixture, *symbolicate.Service, *int, model.Frame) {
	t.Helper()
	f := newScopedFixture(t)
	_, frame := f.put(t, []byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA"}`), []byte("generated"), false)
	s, e := symbolicate.New(f.app.Artifacts, symbolicate.Config{})
	if e != nil {
		t.Fatal(e)
	}
	launches := new(int)
	s.SetFakeWorker(func(_ context.Context, _ []byte, line, col uint32) (symbolicate.Reason, *symbolicate.CodeIdentity) {
		*launches++
		return symbolicate.Resolved, &symbolicate.CodeIdentity{Source: "a.ts", Line: line, Column: col}
	})
	return f, s, launches, frame
}
func at(frame model.Frame, fn string, col uint32) model.Frame {
	frame.Function = fn
	frame.Column = &col
	return frame
}
func TestDuplicateFramesCostOneWorkerLaunch(t *testing.T) {
	f, s, launches, frame := budgetFixture(t)
	frames := []model.Frame{at(frame, "a", 3), at(frame, "b", 3), at(frame, "a", 3), at(frame, "c", 4)}
	got, e := s.Resolve(context.Background(), f.scope(t, auth.ArtifactRead), f.build, frames)
	if e != nil || *launches != 2 {
		t.Fatalf("launches=%d err=%v", *launches, e)
	}
	for i, g := range got {
		if g.Reason != symbolicate.Resolved || g.Resolved == nil || g.Resolved.Column != *frames[i].Column || !reflect.DeepEqual(g.Original, frames[i]) {
			t.Fatalf("frame %d: %+v", i, g)
		}
	}
	got[1].Resolved.Line = 99
	if got[0].Resolved.Line == 99 {
		t.Fatal("duplicate results alias one another")
	}
}
func TestFrameCapYieldsFrameLimitForOverflow(t *testing.T) {
	f, s, launches, frame := budgetFixture(t)
	n := symbolicate.MaxResolvedFrames + 5
	frames := make([]model.Frame, n)
	for i := range frames {
		frames[i] = at(frame, "f", uint32(i))
	}
	frames = append(frames, frames[0]) // duplicate of an in-budget frame still resolves
	got, e := s.Resolve(context.Background(), f.scope(t, auth.ArtifactRead), f.build, frames)
	if e != nil || *launches != symbolicate.MaxResolvedFrames {
		t.Fatalf("launches=%d err=%v", *launches, e)
	}
	for i, g := range got {
		want := symbolicate.Resolved
		if i >= symbolicate.MaxResolvedFrames && i < n {
			want = symbolicate.FrameLimit
		}
		if g.Reason != want || !reflect.DeepEqual(g.Original, frames[i]) || (want != symbolicate.Resolved && g.Resolved != nil) {
			t.Fatalf("frame %d: %+v want %s", i, g, want)
		}
	}
}
