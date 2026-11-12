// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"errors"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/storage"
)

type refDouble struct {
	answer model.UnixNano
	err    error
	calls  int
}

func (d *refDouble) LatestReference(context.Context, storage.EraseCandidate) (model.UnixNano, error) {
	d.calls++
	return d.answer, d.err
}

func blobCandidate() storage.EraseCandidate {
	return storage.EraseCandidate{Blob: &model.BlobManifest{}}
}

func replayCandidate() storage.EraseCandidate {
	return storage.EraseCandidate{Kind: model.Replay, Record: &model.Record{Kind: model.Replay, Payload: model.Payload{Replay: &model.ReplayChunk{}}}}
}

func everything(storage.EraseCandidate) bool { return true }

// Any source that pins a candidate pins it: the answer is the latest deadline,
// whichever order the sources are in.
func TestReferenceSetAnswersTheLatestDeadline(t *testing.T) {
	for _, order := range [][2]model.UnixNano{{5, 9}, {9, 5}, {0, 9}, {9, 0}} {
		a, b := &refDouble{answer: order[0]}, &refDouble{answer: order[1]}
		set, err := composeReferences(gatedReference{everything, a}, gatedReference{everything, b})
		if err != nil {
			t.Fatal(err)
		}
		got, err := set.LatestReference(context.Background(), blobCandidate())
		if err != nil || got != 9 || a.calls != 1 || b.calls != 1 {
			t.Fatalf("%v: answered %d (%v) after %d and %d calls, want 9 and one call each", order, got, err, a.calls, b.calls)
		}
	}
	none, _ := composeReferences(gatedReference{everything, &refDouble{}})
	if got, err := none.LatestReference(context.Background(), blobCandidate()); err != nil || got != 0 {
		t.Fatalf("nothing pins: %d %v", got, err)
	}
}

// The first error of any consulted source is the answer, whichever position the
// failing source has and whatever the others answered: nothing is erased on the
// strength of the sources that did answer.
func TestReferenceSetFailsClosedOnAnySourceError(t *testing.T) {
	boom := model.Fail(model.Unavailable)
	for name, build := range map[string]func() []gatedReference{
		"first fails": func() []gatedReference {
			return []gatedReference{{everything, &refDouble{err: boom}}, {everything, &refDouble{answer: 0}}}
		},
		"second fails": func() []gatedReference {
			return []gatedReference{{everything, &refDouble{answer: 0}}, {everything, &refDouble{err: boom}}}
		},
		"last fails after a pin": func() []gatedReference {
			return []gatedReference{{everything, &refDouble{answer: 9}}, {everything, &refDouble{err: boom}}}
		},
	} {
		set, err := composeReferences(build()...)
		if err != nil {
			t.Fatal(err)
		}
		got, err := set.LatestReference(context.Background(), blobCandidate())
		if !errors.Is(err, boom) || got != 0 {
			t.Fatalf("%s: %d %v", name, got, err)
		}
	}
}

// A source is asked only about candidates it handles: the artifact lifecycle takes
// the GC fence as a side effect of answering for an unreferenced root, so it must
// never see a record, and the replay source never sees a blob.
func TestReferenceSetConsultsEachSourceOnlyForItsOwnKind(t *testing.T) {
	artifact, replay := &refDouble{answer: 3}, &refDouble{answer: 7}
	set, err := composeReferences(gatedReference{isBlobCandidate, artifact}, gatedReference{isReplayCandidate, replay})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if got, _ := set.LatestReference(ctx, blobCandidate()); got != 3 || artifact.calls != 1 || replay.calls != 0 {
		t.Fatalf("blob: %d, artifact %d calls, replay %d calls", got, artifact.calls, replay.calls)
	}
	if got, _ := set.LatestReference(ctx, replayCandidate()); got != 7 || artifact.calls != 1 || replay.calls != 1 {
		t.Fatalf("replay chunk: %d, artifact %d calls, replay %d calls", got, artifact.calls, replay.calls)
	}
	for name, c := range map[string]storage.EraseCandidate{
		"a log record":            {Kind: model.Log, Record: &model.Record{Kind: model.Log}},
		"a replay with no chunk":  {Kind: model.Replay, Record: &model.Record{Kind: model.Replay}},
		"a replay with no record": {Kind: model.Replay},
	} {
		if got, err := set.LatestReference(ctx, c); err != nil || got != 0 || artifact.calls != 1 || replay.calls != 1 {
			t.Fatalf("%s: %d %v, artifact %d calls, replay %d calls", name, got, err, artifact.calls, replay.calls)
		}
	}
}

func TestReferenceSetRefusesMissingParts(t *testing.T) {
	var typedNil *refDouble
	for name, parts := range map[string][]gatedReference{
		"no sources":   nil,
		"nil source":   {{everything, nil}},
		"nil gate":     {{nil, &refDouble{}}},
		"nil among ok": {{everything, &refDouble{}}, {everything, nil}},
	} {
		if _, err := composeReferences(parts...); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	_ = typedNil
}
