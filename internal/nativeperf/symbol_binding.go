// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"context"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// DefaultSymbolArtifactBytes is the largest debug object one symbolication reads: the buffer it is parsed from is the
// size of the assembly working set, and a larger object is reported artifact_unavailable instead of being truncated.
const DefaultSymbolArtifactBytes uint64 = 8 << 20

// SymbolBinding is the consumer-side, authorized association of approved GNU build IDs with debug artifacts held by
// the C07 artifact backend. It is trusted configuration of the process that assembles the profile (never a field of a
// capture request or of a stored profile) and is how ELF symbol names reach exported frames:
//
//   - Artifacts says which C07 artifact holds the debug object of which build. The kernel-reported build ID of the mapped
//     code is the key; the content hash of a file never selects an artifact.
//   - Scope must be an artifacts.read scope of the reader the profile is assembled for. Every read goes through
//     Resolver.ScopedRead, which re-authorizes organization, project, the build association, deletion generation and
//     retention. A denial leaves the frame identity-only as artifact_denied, a missing, expired, deleted or oversized
//     artifact as artifact_unavailable, an object that is not a valid ELF of that build as invalid_elf_artifact.
//   - Working is the reservation that pays for the one buffer an artifact is parsed from (MaxELFBytes plus one byte).
//
// No path, source line or DWARF is read: the parser takes function symbols from the ELF symbol tables and ignores
// everything else in the object, and a symbol name is exported only when it is made of a closed set of characters.
type SymbolBinding struct {
	Scope       auth.Scope
	Project     model.ID
	Artifacts   map[string]model.ID
	Resolver    ArtifactResolver
	Working     WorkingReservation
	MaxELFBytes uint64
}

func (b *SymbolBinding) maxBytes() uint64 {
	if b.MaxELFBytes == 0 {
		return DefaultSymbolArtifactBytes
	}
	return b.MaxELFBytes
}

func (b *SymbolBinding) validate() error {
	if b == nil {
		return nil
	}
	max := b.maxBytes()
	if b.Resolver == nil || b.Project == (model.ID{}) || len(b.Artifacts) > 256 || max > 32<<20 {
		return ErrInvalid
	}
	if b.Scope.OrgID() == (model.ID{}) || !b.Scope.AllowsProject(b.Project) || b.Scope.Permission() != auth.ArtifactRead {
		return ErrInvalid
	}
	for build, id := range b.Artifacts {
		if !validBuild(build) || id == (model.ID{}) {
			return ErrInvalid
		}
	}
	if b.Working == nil || b.Working.Bytes() < max+1 {
		return ErrResourceBudget
	}
	return nil
}

// policy is the symbol policy of a table assembled under this binding.
func (b *SymbolBinding) policy(revision uint64, framePointersAbsent bool) SymbolPolicy {
	p := DefaultSymbolPolicy(revision)
	p.FramePointersAbsent = framePointersAbsent
	if b == nil {
		return p
	}
	p.MaxELFBytes = b.maxBytes()
	p.ArtifactScope, p.ProjectID, p.Artifacts = b.Scope, b.Project, b.Artifacts
	return p
}

func (b *SymbolBinding) resolver() ArtifactResolver {
	if b == nil {
		return nil
	}
	return b.Resolver
}

// VerifyDebugELF reads the GNU build ID out of a native debug object after the same bounded parse symbolication uses:
// an ELF64 little-endian amd64/arm64 object with a GNU build ID note, program headers and section headers within the
// size and symbol bounds. It executes nothing and follows no debug link. The C07 upload of a native debug object calls
// it so that only a parseable object is registered under the build ID it carries.
func VerifyDebugELF(object []byte) (string, error) {
	if uint64(len(object)) > DefaultSymbolArtifactBytes {
		return "", ErrResourceBudget
	}
	info, err := readELFSymbols(context.Background(), newImageReader(object), DefaultSymbolArtifactBytes, 65536)
	if err != nil {
		return "", err
	}
	return info.buildID, nil
}
