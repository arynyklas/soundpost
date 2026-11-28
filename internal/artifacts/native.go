// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"io"
	"time"
)

// Native debug objects. The C07 store holds inert objects by exact immutable identity; a source map is one kind, an
// ELF debug object of a native build is the other. A native object is addressed by the GNU build ID of the build it
// describes (Manifest.DebugID, lowercase hex) at the reserved path NativeDebugPath(DebugID), so a source-map artifact
// can never be read as a native object or the reverse, and an object is only ever associated with the build ID it
// carries: the caller's verifier reads that ID out of the bytes before anything is stored. The object is stored
// verbatim, is never executed, and is read back only through the same authorized, fenced reads as every artifact.

// NativeDebugPathPrefix is the manifest path prefix reserved for native debug objects.
const NativeDebugPathPrefix = "native-elf/"

// NativeDebugPath is the manifest path of the native debug object of the build with the given GNU build ID.
func NativeDebugPath(buildID string) string { return NativeDebugPathPrefix + buildID }

// IsNativeDebug reports whether a manifest describes a native debug object.
func IsNativeDebug(m Manifest) bool {
	return validGNUBuildID(m.DebugID) && m.Path == NativeDebugPath(m.DebugID) && !m.SourceContent && m.GeneratedSHA256 == m.MapSHA256
}

func validGNUBuildID(s string) bool {
	if len(s) < 2 || len(s) > 128 || len(s)%2 != 0 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ValidateNativeDebugManifest is ValidateManifest plus the native identity rules: the debug ID is a GNU build ID, the
// path is its reserved path, there is no source content, and the object's own hash stands for both hashes.
func ValidateNativeDebugManifest(m Manifest) error {
	if err := ValidateManifest(m); err != nil {
		return err
	}
	if !IsNativeDebug(m) {
		return model.Fail(model.Invalid)
	}
	return nil
}

// NativeDebugVerifier reads the GNU build ID out of a debug object, refusing an object that is not a valid, bounded
// ELF of one build.
type NativeDebugVerifier func(object []byte) (buildID string, err error)

// PutNativeDebug stores a native debug object under the same authority, byte policy, quota and durable publication as
// Put. The object is buffered once at its declared size, hashed, verified (its GNU build ID must be Manifest.DebugID)
// and only then written.
func (s *Service) PutNativeDebug(ctx context.Context, scope auth.Scope, m Manifest, input io.Reader, verify NativeDebugVerifier) (Artifact, error) {
	if err := s.authorizer.Revalidate(ctx, scope); err != nil {
		return Artifact{}, err
	}
	if scope.OrgID() != m.Org || !scope.AllowsProject(m.Project) || scope.Permission() != auth.ArtifactWrite {
		return Artifact{}, model.Fail(model.NotFound)
	}
	if err := ValidateNativeDebugManifest(m); err != nil {
		return Artifact{}, err
	}
	if input == nil || verify == nil || int64(m.RetainUntil) <= time.Now().UnixNano() {
		return Artifact{}, model.Fail(model.Invalid)
	}
	maxBytes, revision, err := scope.ArtifactPolicy(ctx, m.Project, m.Source, m.Build, false)
	if err != nil {
		return Artifact{}, err
	}
	if uint64(m.Size) > maxBytes {
		return Artifact{}, model.Fail(model.TooLarge)
	}
	release, err := s.uploads.acquire(scope.PrincipalID(), uint64(m.Size)*uploadPeakFactor)
	if err != nil {
		return Artifact{}, err
	}
	defer release()
	buf := bytes.NewBuffer(make([]byte, 0, int(m.Size)+1))
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(buf, h), io.LimitReader(input, int64(m.Size)+1))
	if err != nil || n < int64(m.Size) {
		return Artifact{}, model.Fail(model.Invalid)
	}
	if n > int64(m.Size) {
		return Artifact{}, model.Fail(model.TooLarge)
	}
	var hash model.Hash
	copy(hash[:], h.Sum(nil))
	if hash != m.MapSHA256 {
		return Artifact{}, model.Fail(model.Invalid)
	}
	raw := buf.Bytes()
	if id, err := verify(raw); err != nil || id != m.DebugID {
		return Artifact{}, model.Fail(model.Invalid)
	}
	id := artifactID(m)
	manifest := model.BlobManifest{Org: m.Org, Project: m.Project, Source: m.Source, Root: id, Build: m.Build, DebugID: m.DebugID, Path: m.Path, GeneratedSHA256: m.GeneratedSHA256, MapSHA256: m.MapSHA256, PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyRevision: revision, RetainUntil: m.RetainUntil}
	manifest.Hash = hash
	manifest.Size = model.Uint64(len(raw))
	reservation, err := s.metadata.ReserveArtifact(ctx, scope, manifest)
	if err != nil {
		return Artifact{}, err
	}
	receipt, err := s.blobs.WriteBlob(ctx, scope, reservation.Manifest, bytes.NewReader(raw))
	if err != nil {
		return Artifact{}, err
	}
	return s.metadata.PublishArtifact(ctx, scope, Artifact{ID: id, CommandID: id, Manifest: m, Map: receipt})
}
