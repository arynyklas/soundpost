// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"context"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

type allowScope struct{}

func (allowScope) Revalidate(context.Context, auth.Scope) error { return nil }

type pageScanner struct{ page ProfilePage }

func (s pageScanner) ScanProfile(context.Context, auth.Scope, model.ID, Window) (ProfileIterator, error) {
	return &onePage{page: s.page}, nil
}

type onePage struct {
	page ProfilePage
	done bool
}

func (p *onePage) Next(context.Context) (ProfilePage, error) {
	if p.done {
		return ProfilePage{}, io.EOF
	}
	p.done = true
	return p.page, nil
}
func (p *onePage) Close() error { return nil }

// multiChunkPage is one profile in `chunks` chunks of `per` CPU samples each; sample k of chunk c has At
// 100*c + k, so the order of a complete read is the order of At.
func multiChunkPage(project, profile model.ID, chunks, per int) ProfilePage {
	clock := model.TraceClock{Wall: 1000, Domain: model.ClockDomain{Host: model.ID{4}, Boot: model.ID{5}, Runtime: model.ID{6}}}
	page := ProfilePage{Project: project, Source: model.ID{3}, Complete: true, Capabilities: []CapabilityRecord{{ID: model.ID{9}, Value: model.Capability{Signal: model.Profile, Clock: clock.Domain}}}}
	for c := 1; c <= chunks; c++ {
		chunk := model.ProfileChunk{Profile: profile, Process: model.ID{2}, Capability: model.ID{9}, Method: "runtime_cpu", Units: "samples", Sequence: model.Uint64(c), PolicyRevision: 1, Clock: clock, Frames: []model.ProfileFrame{{Reason: "frame_unresolved"}}, Stacks: []model.ProfileStack{{Frames: []uint32{0}}}}
		for k := range per {
			chunk.Samples = append(chunk.Samples, model.ProfileSample{At: model.MonoNano(100*c + k), Stack: 0, Count: 1, Thread: 1})
		}
		page.Chunks = append(page.Chunks, chunk)
	}
	return page
}

// TestMaxSamplesBoundsTheWholeViewAcrossChunks: 04.07-C21 review Minor 2 claimed a view over N chunks returns up to
// N*MaxSamples records. The bound is on the view and the cursor resumes exactly where the page stopped.
func TestMaxSamplesBoundsTheWholeViewAcrossChunks(t *testing.T) {
	scope := realCursorScope(t)
	profile := model.NewID()
	const chunks, per = 4, 3
	service := NewService(pageScanner{multiChunkPage(scope.ProjectIDs()[0], profile, chunks, per)}, allowScope{}, unavailableLinks{})
	for _, max := range []uint32{1, 2, 4, 5, 12, 100} {
		w := Window{Start: 0, End: 1 << 40, MaxSamples: max}
		var seen []model.MonoNano
		for page := 0; ; page++ {
			if page > chunks*per {
				t.Fatalf("max_samples %d: cursor never ended", max)
			}
			view, err := service.Read(context.Background(), scope, profile, w)
			if err != nil {
				t.Fatalf("max_samples %d page %d: %v", max, page, err)
			}
			got := len(view.Samples) + len(view.Intervals)
			if uint32(got) > max {
				t.Fatalf("max_samples %d page %d returned %d records: the cap is per chunk, not per view", max, page, got)
			}
			want := min(int(max), chunks*per-len(seen))
			if got != want {
				t.Fatalf("max_samples %d page %d returned %d records, want %d (a short page loses or repeats records)", max, page, got, want)
			}
			for _, s := range view.Samples {
				seen = append(seen, s.At)
			}
			if view.NextCursor == "" {
				break
			}
			w.Cursor = view.NextCursor
		}
		if len(seen) != chunks*per {
			t.Fatalf("max_samples %d: %d records over all pages, want %d", max, len(seen), chunks*per)
		}
		for i := 1; i < len(seen); i++ {
			if seen[i] <= seen[i-1] {
				t.Fatalf("max_samples %d: record %d repeated or out of order (%v)", max, i, seen)
			}
		}
	}
}
