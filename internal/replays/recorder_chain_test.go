// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"testing"

	recorderfixtures "github.com/arynyklas/soundpost/fixtures/replays/recorder"
	"github.com/arynyklas/soundpost/internal/model"
)

// The stateful half of the recorder contract: chunks the real browser recorder emitted are admitted
// through the production order (Validate, durable append, index) and the chain reader proves their
// continuity from the stored rows, including the holes the recorder itself reports.
func TestRealRecorderChunksChainThroughTheStoredReader(t *testing.T) {
	load := func(t *testing.T, name string) (recorderfixtures.Scenario, []model.ReplayChunk) {
		t.Helper()
		s, err := recorderfixtures.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		chunks, err := s.Chunks()
		if err != nil {
			t.Fatal(err)
		}
		return s, chunks
	}
	t.Run("a complete session is one continuous replay", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		_, chunks := load(t, "session")
		f.mustAdmit(f.main, chunks...)
		got, evs := f.read(scope, chunks[0].Replay, ReplayWindow{})
		if want := "C1 D2 D3 D4 C5 D6"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
		for _, ev := range evs {
			if ev.Kind != EventDelta {
				continue
			}
			// deltas 2-4 depend on checkpoint 1; delta 6 depends on the recorder's second checkpoint
			want := uint64(1)
			if ev.Sequence == 6 {
				want = 5
			}
			if ev.CheckpointSequence != want {
				t.Fatalf("delta %d names checkpoint %d, want %d", ev.Sequence, ev.CheckpointSequence, want)
			}
		}
	})
	t.Run("a chunk lost in transit is an explicit gap until the recorder's next checkpoint", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		_, chunks := load(t, "session")
		f.mustAdmit(f.main, chunks[0], chunks[1], chunks[3], chunks[4], chunks[5]) // sequence 3 never arrives
		got, _ := f.read(scope, chunks[0].Replay, ReplayWindow{})
		if want := "C1 D2 G3-4 C5 D6"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
	})
	t.Run("a refused chunk is healed by the recorder's gap-marked checkpoint, not hidden", func(t *testing.T) {
		f := newFx(t)
		scope, _ := f.reader(f.main, f.main.project)
		s, chunks := load(t, "recovery")
		for i, c := range chunks {
			if s.Delivered[i] {
				f.mustAdmit(f.main, c)
			}
		}
		got, evs := f.read(scope, chunks[0].Replay, ReplayWindow{})
		if want := "C1 G2-2 G3-3 C3 D4"; got != want {
			t.Fatalf("stream %q, want %q", got, want)
		}
		if evs[1].Reason != ReasonMissingChunk || evs[2].Reason != ReasonRecorderGap || evs[3].Loss != 1 {
			t.Fatalf("reasons %q %q loss %d", evs[1].Reason, evs[2].Reason, evs[3].Loss)
		}
	})
}
