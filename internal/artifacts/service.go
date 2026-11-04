// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package artifacts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"os"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"time"
)

func (s *Service) Put(ctx context.Context, scope auth.Scope, m Manifest, input io.Reader) (Artifact, error) {
	if err := s.authorizer.Revalidate(ctx, scope); err != nil {
		return Artifact{}, err
	}
	if scope.OrgID() != m.Org || !scope.AllowsProject(m.Project) || scope.Permission() != auth.ArtifactWrite {
		return Artifact{}, model.Fail(model.NotFound)
	}
	if err := ValidateManifest(m); err != nil {
		return Artifact{}, err
	}
	if input == nil || int64(m.RetainUntil) <= time.Now().UnixNano() {
		return Artifact{}, model.Fail(model.Invalid)
	}
	_, revision, err := scope.ArtifactPolicy(ctx, m.Project, m.Source, m.Build, m.SourceContent)
	if err != nil {
		return Artifact{}, err
	}
	// No durable reservation or fragment is created until the bounded original
	// stream has been completely verified and transformed by source policy.
	temp, err := os.CreateTemp("", "soundpost-map-")
	if err != nil {
		return Artifact{}, model.Fail(model.Unavailable)
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(temp, h), io.LimitReader(input, int64(m.Size)+1))
	if err != nil {
		return Artifact{}, model.Fail(model.Invalid)
	}
	if n < int64(m.Size) {
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
	if _, err = temp.Seek(0, 0); err != nil {
		return Artifact{}, err
	}
	raw, err := io.ReadAll(temp)
	if err != nil {
		return Artifact{}, err
	}
	public, private, err := transformMap(raw, m.SourceContent)
	if err != nil {
		return Artifact{}, err
	}
	id := artifactID(m)
	manifest := model.BlobManifest{Org: m.Org, Project: m.Project, Source: m.Source, Root: id, Build: m.Build, DebugID: m.DebugID, Path: m.Path, GeneratedSHA256: m.GeneratedSHA256, MapSHA256: m.MapSHA256, Hash: model.HashCanonical(public), Size: model.Uint64(len(public)), PolicyEpoch: model.Uint64(scope.PolicyEpoch()), PolicyRevision: revision, RetainUntil: m.RetainUntil}
	reservation, err := s.metadata.ReserveArtifact(ctx, scope, manifest)
	if err != nil {
		return Artifact{}, err
	}
	receipt, err := s.blobs.WriteBlob(ctx, scope, reservation.Manifest, bytes.NewReader(public))
	if err != nil {
		return Artifact{}, err
	}
	intent := Artifact{ID: id, CommandID: id, Manifest: m, Map: receipt}
	if m.SourceContent {
		manifest.PrivateSources = true
		manifest.Hash = model.HashCanonical(private)
		manifest.Size = model.Uint64(len(private))
		reservation, err = s.metadata.ReserveArtifact(ctx, scope, manifest)
		if err != nil {
			return Artifact{}, err
		}
		sourceReceipt, err := s.blobs.WriteBlob(ctx, scope, reservation.Manifest, bytes.NewReader(private))
		if err != nil {
			return Artifact{}, err
		}
		intent.Sources = &sourceReceipt
	}
	// This is a separate fenced durable control intent after all byte cursors,
	// not an atomic transaction across control and the root-owner data group.
	return s.metadata.PublishArtifact(ctx, scope, intent)
}
func (s *Service) Get(ctx context.Context, scope auth.Scope, id ArtifactID) (io.ReadCloser, error) {
	return s.open(ctx, scope, id, false)
}
func (s *Service) GetSources(ctx context.Context, scope auth.Scope, id ArtifactID) (io.ReadCloser, error) {
	return s.open(ctx, scope, id, true)
}
func (s *Service) Lookup(ctx context.Context, scope auth.Scope, id ArtifactID) (Artifact, error) {
	if err := s.authorizer.Revalidate(ctx, scope); err != nil {
		return Artifact{}, err
	}
	return s.metadata.LookupArtifact(ctx, scope, id)
}
func (s *Service) open(ctx context.Context, scope auth.Scope, id ArtifactID, private bool) (io.ReadCloser, error) {
	artifact, err := s.Lookup(ctx, scope, id)
	if err != nil {
		return nil, err
	}
	receipt := artifact.Map
	if private {
		if artifact.Sources == nil {
			return nil, model.Fail(model.NotFound)
		}
		receipt = *artifact.Sources
	}
	if err = scope.RevalidateArtifact(ctx, receipt.Manifest, false); err != nil {
		return nil, err
	}
	if err = s.blobs.VerifyBlob(ctx, receipt); err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	return &artifactReader{service: s, ctx: ctx, scope: scope, id: id, receipt: receipt, private: private}, nil
}

type artifactReader struct {
	service *Service
	ctx     context.Context
	scope   auth.Scope
	id      ArtifactID
	receipt model.BlobReceipt
	private bool
	ordinal uint32
	pending []byte
	closed  bool
}

func (r *artifactReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	// Even a byte retained in the current fragment is a new release: check the
	// exact current reference, named source grant, epoch and source state first.
	artifact, err := r.service.Lookup(r.ctx, r.scope, r.id)
	if err != nil {
		return 0, err
	}
	current := artifact.Map
	if r.private {
		if artifact.Sources == nil {
			return 0, model.Fail(model.NotFound)
		}
		current = *artifact.Sources
	}
	a, _ := model.CanonicalJSON(current)
	b, _ := model.CanonicalJSON(r.receipt)
	if !bytes.Equal(a, b) {
		return 0, model.Fail(model.NotFound)
	}
	if err = r.scope.RevalidateArtifact(r.ctx, r.receipt.Manifest, false); err != nil {
		return 0, err
	}
	if len(r.pending) == 0 {
		if int(r.ordinal) >= len(r.receipt.Fragments) {
			return 0, io.EOF
		}
		r.pending, err = r.service.blobs.ReadBlobFragment(r.ctx, r.scope, r.receipt, r.ordinal)
		if err != nil {
			return 0, err
		}
		r.ordinal++
	}
	if err = r.scope.RevalidateArtifact(r.ctx, r.receipt.Manifest, false); err != nil {
		return 0, err
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
func (r *artifactReader) Close() error {
	r.closed = true
	clear(r.pending)
	r.pending = nil
	return nil
}
