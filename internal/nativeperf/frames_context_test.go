// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"errors"
	"io"
	"soundpost/internal/model"
	"strings"
	"testing"
)

type artifactTestResolver struct {
	open func(context.Context) (io.ReadCloser, error)
}

func (r artifactTestResolver) ScopedRead(ctx context.Context, _ ArtifactReference) (io.ReadCloser, error) {
	return r.open(ctx)
}

type artifactCloseFailure struct{ io.Reader }

func (r artifactCloseFailure) Close() error { return io.ErrClosedPipe }

type artifactReadFailure struct{}

func (artifactReadFailure) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (artifactReadFailure) Close() error             { return nil }
func TestNativeFrameCallerCancellationIsNotMissingOrDenied(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ResolveFrames(ctx, nil, MappingTable{}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal("empty resolution swallowed caller cancellation", e)
	}
	sample := CPUSample{IP: 4096, Method: MethodSoftwareCPUClock, Unit: UnitCPUClockNanoseconds, RequestedHz: 99, Period: 1, Truncated: ReasonMissingCallchain}
	task := TaskKey{BootID: "boot", PIDNamespace: 1, TGID: 7, TID: 7, ProcessStart: 1, Generation: 1}
	if _, e := ResolveCPUObservation(ctx, task, sample, MappingTable{}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal("CPU observation detached caller context", e)
	}
}
func TestNativeArtifactErrorClassification(t *testing.T) {
	cases := []struct {
		name   string
		open   func(context.Context) (io.ReadCloser, error)
		reason FrameReason
	}{
		{"definitive_denial", func(context.Context) (io.ReadCloser, error) { return nil, model.Fail(model.Forbidden) }, FrameArtifactDenied},
		{"indistinguishable_missing", func(context.Context) (io.ReadCloser, error) { return nil, model.Fail(model.NotFound) }, FrameArtifactUnavailable},
		{"io_unavailable", func(context.Context) (io.ReadCloser, error) { return nil, io.ErrClosedPipe }, FrameArtifactUnavailable},
		{"read_failure", func(context.Context) (io.ReadCloser, error) { return artifactReadFailure{}, nil }, FrameArtifactUnavailable},
		{"close_failure", func(context.Context) (io.ReadCloser, error) {
			return artifactCloseFailure{strings.NewReader("not ELF")}, nil
		}, FrameArtifactUnavailable},
		{"invalid_complete_bytes", func(context.Context) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("not ELF")), nil }, FrameInvalidELF},
		{"internal_deadline", func(ctx context.Context) (io.ReadCloser, error) { <-ctx.Done(); return nil, ctx.Err() }, FrameArtifactUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, e := readFrameArtifact(context.Background(), context.Background(), artifactTestResolver{tc.open}, ArtifactReference{}, make([]byte, 1025), 1024, 1024, 128)
			if e != nil || got.reason != tc.reason {
				t.Fatalf("classification %s %v", got.reason, e)
			}
		})
	}
}
func TestNativeArtifactCallerCancelWinsOverBackendDenial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolver := artifactTestResolver{func(context.Context) (io.ReadCloser, error) { cancel(); return nil, model.Fail(model.Forbidden) }}
	_, e := readFrameArtifact(ctx, ctx, resolver, ArtifactReference{}, make([]byte, 1025), 1024, 1024, 128)
	if !errors.Is(e, context.Canceled) {
		t.Fatal("caller cancellation became denial/invalid ELF", e)
	}
}
