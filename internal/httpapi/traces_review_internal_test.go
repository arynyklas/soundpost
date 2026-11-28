// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/link"
	"github.com/arynyklas/soundpost/internal/model"
)

type allAvailable struct{ calls int }

func (a *allAvailable) Resolve(_ context.Context, _ auth.Scope, refs []link.Reference) ([]link.ResolvedReference, error) {
	a.calls++
	out := make([]link.ResolvedReference, len(refs))
	for i, r := range refs {
		owned := r
		out[i] = link.ResolvedReference{Reference: &owned, Available: true}
	}
	return out, nil
}

func reviewSpan(n byte, replay model.ID) model.Span {
	var id model.SpanID
	id[7] = n
	return model.Span{Trace: model.ID{1}, ID: id, Replay: &replay}
}

// Finding 05.06#12 (b): one failed grant check must not be remembered as a denial. Two spans name a replay
// each; the first grant check fails transiently and the second would succeed. The failed check fails the
// request (nothing is resolved) and is never memoized, so the second replay is not judged by it.
func TestResolveTargetsTransientGrantErrorIsNotMemoizedAsDenied(t *testing.T) {
	r1, r2 := model.NewID(), model.NewID()
	set := SpanSet{Spans: []model.Span{reviewSpan(1, r1), reviewSpan(2, r2)}}
	transient := model.Fail(model.Unavailable)
	resolver := &allAvailable{}
	tr := NewTraces(nil).WithLinks(resolver)

	calls := 0
	view := &TraceView{}
	targets, err := tr.resolveTargets(context.Background(), auth.Scope{}, model.ID{9}, set, view, func(kind string) (bool, error) {
		calls++
		if calls == 1 {
			return false, transient
		}
		return true, nil
	})
	if !errors.Is(err, transient) {
		t.Fatalf("a failed grant check: err %v targets %+v, want the failure itself", err, targets)
	}
	if resolver.calls != 0 || len(targets) != 0 {
		t.Fatalf("a failed grant check still resolved %d times, targets %+v", resolver.calls, targets)
	}
	if calls != 1 {
		t.Fatalf("the grant check ran %d times; the failure must end the read", calls)
	}

	// The same request retried when the authorizer answers: every replay is judged by its own answer.
	calls = 0
	view = &TraceView{}
	targets, err = tr.resolveTargets(context.Background(), auth.Scope{}, model.ID{9}, set, view, func(kind string) (bool, error) {
		calls++
		return true, nil
	})
	if err != nil || len(targets) != 2 || !targets[0].Available || !targets[1].Available || calls != 1 {
		t.Fatalf("answered grant: err %v targets %+v calls %d, want both available after one check per kind", err, targets, calls)
	}
}
