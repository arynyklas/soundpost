// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// Pins for the wall-clock bound of one artifact read (100 ms, frames.go readFrameArtifact). The two sides of the order
// are observed: a backend that answers well inside the bound is read in full, and a backend that never answers is given
// up on once the bound has run out - not before it and not long after it. A bound of 101 ms instead of 100 ms is
// indistinguishable from this side of any real clock, which is why only the order (answered in time / not answered in
// time) and the window of the bound are pinned here. The five second bound of a whole symbolication is pinned by
// appcore.TestNativeSymbolicationStopsAskingAStalledBackendAfterFiveSeconds (35-56 stalled reads out of 120 within
// 4.5-5.9 s), which rejects 4 s and 6 s.
func TestReadFrameArtifactBoundIsAHundredMillisecondsAndAnswersInsideItAreKept(t *testing.T) {
	object := elfFixtureBytes(t, "approved_hot_loop")
	scratch := make([]byte, 2048)

	// inside the bound: answered after 30 ms, read in full and parsed
	prompt := artifactTestResolver{func(context.Context) (io.ReadCloser, error) {
		return io.NopCloser(&delayedReader{r: bytes.NewReader(object), delay: 30 * time.Millisecond}), nil
	}}
	got, err := readFrameArtifact(context.Background(), context.Background(), prompt, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != "" || got.bytes != 1024 || got.info.buildID != "ab12" {
		t.Fatalf("an answer after 30 ms: %+v %v", got, err)
	}

	// outside the bound: the backend waits for its own context; it is released by the bound, after at least 100 ms and
	// well before any bound of a second
	var waited time.Duration
	stalled := artifactTestResolver{func(ctx context.Context) (io.ReadCloser, error) {
		start := time.Now()
		<-ctx.Done()
		waited = time.Since(start)
		return nil, ctx.Err()
	}}
	start := time.Now()
	got, err = readFrameArtifact(context.Background(), context.Background(), stalled, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128)
	total := time.Since(start)
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 0 {
		t.Fatalf("a backend that never answers: %+v %v", got, err)
	}
	if waited < 99*time.Millisecond || total < 100*time.Millisecond || total > 600*time.Millisecond {
		t.Fatalf("the stalled read was given up on after %v (backend saw %v), want the 100 ms bound", total, waited)
	}
}

// A backend that answers "forbidden" only after the artifact's own bound has run out did not answer in time: the frame is
// artifact_unavailable, not artifact_denied. A refusal is a denial only when it arrives inside the bound.
func TestReadFrameArtifactRefusalAfterTheBoundIsUnavailableNotDenied(t *testing.T) {
	scratch := make([]byte, 2048)
	late := artifactTestResolver{func(ctx context.Context) (io.ReadCloser, error) {
		<-ctx.Done()
		return nil, model.Fail(model.Forbidden)
	}}
	got, err := readFrameArtifact(context.Background(), context.Background(), late, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != FrameArtifactUnavailable || got.bytes != 0 {
		t.Fatalf("a refusal after the bound: %+v %v, want artifact_unavailable", got, err)
	}
	prompt := artifactTestResolver{func(context.Context) (io.ReadCloser, error) { return nil, model.Fail(model.Forbidden) }}
	got, err = readFrameArtifact(context.Background(), context.Background(), prompt, ArtifactReference{BuildID: "ab12"}, scratch, 1024, 1024, 128)
	if err != nil || got.reason != FrameArtifactDenied {
		t.Fatalf("a refusal inside the bound: %+v %v, want artifact_denied", got, err)
	}
}
