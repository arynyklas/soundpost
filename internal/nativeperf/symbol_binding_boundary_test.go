// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// Boundary pins for the debug-object verification and the classification of a backend's refusal (l4w33 mutation
// battery B).

// elfWithSymbols is the fixture object with a symbol table of n entries (none of them a function, so none is kept).
func elfWithSymbols(t *testing.T, n int) []byte {
	t.Helper()
	b := elfFixtureBytes(t, "approved_hot_loop")
	b = append(b, make([]byte, n*24)...)
	binary.LittleEndian.PutUint64(b[704+24:], 1024)
	binary.LittleEndian.PutUint64(b[704+32:], uint64(n)*24)
	return b
}

// VerifyDebugELF reads the build ID of an object of at most 8 MiB with at most 65536 symbols; one byte or one symbol more
// is a resource-budget error, and an object that is merely not an ELF is not.
func TestVerifyDebugELFReadsTheBuildIDWithinTheDocumentedBounds(t *testing.T) {
	id, err := VerifyDebugELF(elfFixtureBytes(t, "approved_hot_loop"))
	if err != nil || id != "ab12" {
		t.Fatalf("the fixture: %q %v", id, err)
	}
	if id, err = VerifyDebugELF(elfWithSymbols(t, 65536)); err != nil || id != "ab12" {
		t.Fatalf("65536 symbols: %q %v", id, err)
	}
	if _, err = VerifyDebugELF(elfWithSymbols(t, 65537)); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("65537 symbols: %v, want ErrResourceBudget", err)
	}
	if _, err = VerifyDebugELF(make([]byte, 8<<20)); err == nil || errors.Is(err, ErrResourceBudget) {
		t.Fatalf("8 MiB of zeros: %v, want an invalid object", err)
	}
	if _, err = VerifyDebugELF(make([]byte, 8<<20+1)); !errors.Is(err, ErrResourceBudget) {
		t.Fatalf("8 MiB and one byte: %v, want ErrResourceBudget", err)
	}
	if _, err = VerifyDebugELF(nil); err == nil {
		t.Fatal("an empty object was verified")
	}
}

// Only a refusal of authorization is artifact_denied - forbidden and unauthenticated - and every other answer is
// artifact_unavailable.
func TestReadFrameArtifactDeniesOnlyARefusalOfAuthorization(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		reason FrameReason
	}{
		{"forbidden", model.Fail(model.Forbidden), FrameArtifactDenied},
		{"unauthenticated", model.Fail(model.Unauthenticated), FrameArtifactDenied},
		{"not found", model.Fail(model.NotFound), FrameArtifactUnavailable},
		{"invalid", model.Fail(model.Invalid), FrameArtifactUnavailable},
		{"a plain error", io.ErrUnexpectedEOF, FrameArtifactUnavailable},
	} {
		resolver := artifactTestResolver{func(context.Context) (io.ReadCloser, error) { return nil, tc.err }}
		got, err := readFrameArtifact(context.Background(), context.Background(), resolver, ArtifactReference{}, make([]byte, 1025), 1024, 1024, 128)
		if err != nil || got.reason != tc.reason || got.bytes != 0 {
			t.Errorf("%s: %+v %v, want %s and no bytes charged", tc.name, got, err, tc.reason)
		}
	}
}
