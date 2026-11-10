// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"context"
	"io"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"sync/atomic"
)

type ArtifactID = model.ID
type BuildID = model.ID
type Manifest = model.ArtifactManifest
type Artifact = model.ArtifactReferenceIntent
type BlobStore interface {
	WriteBlob(context.Context, auth.Scope, model.BlobManifest, io.Reader) (model.BlobReceipt, error)
	VerifyBlob(context.Context, model.BlobReceipt) error
	ReadBlobFragment(context.Context, auth.Scope, model.BlobReceipt, uint32) ([]byte, error)
}
type MetadataStore interface {
	ReserveArtifact(context.Context, auth.Scope, model.BlobManifest) (model.ArtifactQuotaReservation, error)
	PublishArtifact(context.Context, auth.Scope, model.ArtifactReferenceIntent) (model.ArtifactReferenceIntent, error)
	LookupArtifact(context.Context, auth.Scope, model.ID) (model.ArtifactReferenceIntent, error)
}
type ScopeAuthorizer interface {
	Revalidate(context.Context, auth.Scope) error
}
type Service struct {
	blobs      BlobStore
	metadata   MetadataStore
	authorizer ScopeAuthorizer
	// gate is installed by NewLifecycle; reads then also fence on the org
	// delete generation and the artifact's reference state.
	gate atomic.Pointer[readGate]
}

func New(blobs BlobStore, metadata MetadataStore, authorizer ScopeAuthorizer) (*Service, error) {
	if blobs == nil || metadata == nil || authorizer == nil {
		return nil, model.Fail(model.Invalid)
	}
	return &Service{blobs: blobs, metadata: metadata, authorizer: authorizer}, nil
}
