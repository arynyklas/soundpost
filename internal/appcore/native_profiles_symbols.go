// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"

	"github.com/arynyklas/soundpost/internal/artifacts"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// Native ELF symbolication adapter (04.06-C14): the C07 side of nativeperf.ArtifactResolver.
//
// The association is explicit and approved: an operator registers the debug object of a build (PutNativeDebugArtifact,
// which stores it under the GNU build ID read out of the object itself) and lists build ID -> artifact in the
// nativeperf.SymbolBinding of the process that assembles profiles. A frame is named only when the kernel-reported build
// ID of the mapped code, the binding entry and the stored manifest (organization, project, GNU build ID, reserved
// native path) all agree; the bytes come through the artifact service's authorized, fenced read, so organization,
// project, deletion generation, retention and artifacts.read are re-checked on every read.

// NativeDebugArtifact is a registered native debug object: the GNU build ID it describes and its C07 identity.
type NativeDebugArtifact struct {
	BuildID    string
	ArtifactID model.ID
}

// PutNativeDebugArtifact registers the debug object of a native build with C07. scope must be an artifacts.write scope of
// the project; source and build are the C07 identities the artifact is stored under (the build the profile's resource
// names). The GNU build ID is not a parameter: it is read out of the object, which must be a bounded, valid ELF.
func (a *App) PutNativeDebugArtifact(ctx context.Context, scope auth.Scope, project, source, build model.ID, object []byte, retainUntil model.UnixNano) (NativeDebugArtifact, error) {
	buildID, err := nativeperf.VerifyDebugELF(object)
	if err != nil {
		return NativeDebugArtifact{}, model.Fail(model.Invalid)
	}
	sum := model.Hash(sha256.Sum256(object))
	m := artifacts.Manifest{Version: 1, Org: scope.OrgID(), Project: project, Source: source, Build: build, DebugID: buildID, GeneratedSHA256: sum, MapSHA256: sum, Path: artifacts.NativeDebugPath(buildID), Size: model.Uint64(len(object)), RetainUntil: retainUntil}
	stored, err := a.Artifacts.PutNativeDebug(ctx, scope, m, bytes.NewReader(object), nativeperf.VerifyDebugELF)
	if err != nil {
		return NativeDebugArtifact{}, err
	}
	return NativeDebugArtifact{BuildID: buildID, ArtifactID: stored.ID}, nil
}

// NewNativeSymbolBinding is the symbolication binding of a process that assembles native profiles. scope must be an
// artifacts.read scope (auth.Service.Authorize with auth.ArtifactRead) of the project; associations maps approved GNU
// build IDs to registered artifacts; working pays for the buffer one object is parsed from.
func (a *App) NewNativeSymbolBinding(scope auth.Scope, project model.ID, associations map[string]model.ID, working nativeperf.WorkingReservation) *nativeperf.SymbolBinding {
	owned := make(map[string]model.ID, len(associations))
	for build, id := range associations {
		owned[build] = id
	}
	return &nativeperf.SymbolBinding{Scope: scope, Project: project, Artifacts: owned, Resolver: NativeDebugResolver{Store: a.Artifacts}, Working: working}
}

// nativeDebugStore is what the resolver needs of the C07 artifact service.
type nativeDebugStore interface {
	Lookup(context.Context, auth.Scope, model.ID) (artifacts.Artifact, error)
	Get(context.Context, auth.Scope, model.ID) (io.ReadCloser, error)
}

// NativeDebugResolver implements nativeperf.ArtifactResolver over C07. It never reads a file, URL or cache of its own.
type NativeDebugResolver struct{ Store nativeDebugStore }

// ScopedRead opens the native debug object of ref.BuildID. A scope that is not an artifacts.read scope of the project
// is Forbidden (the frame becomes artifact_denied); an artifact that is absent, belongs to another organization or
// project, is not the native object of exactly this GNU build ID, or fails any current C07 check is the store's error,
// which the caller reports as artifact_unavailable without telling the cases apart.
func (r NativeDebugResolver) ScopedRead(ctx context.Context, ref nativeperf.ArtifactReference) (io.ReadCloser, error) {
	if r.Store == nil || ref.ArtifactID == (model.ID{}) || ref.ProjectID == (model.ID{}) || ref.Scope.OrgID() == (model.ID{}) || ref.Scope.Permission() != auth.ArtifactRead || !ref.Scope.AllowsProject(ref.ProjectID) {
		return nil, model.Fail(model.Forbidden)
	}
	artifact, err := r.Store.Lookup(ctx, ref.Scope, ref.ArtifactID)
	if err != nil {
		return nil, err
	}
	m := artifact.Manifest
	if artifact.ID != ref.ArtifactID || m.Org != ref.Scope.OrgID() || m.Project != ref.ProjectID || m.DebugID != ref.BuildID || !artifacts.IsNativeDebug(m) || m.Path != artifacts.NativeDebugPath(ref.BuildID) {
		return nil, model.Fail(model.NotFound)
	}
	return r.Store.Get(ctx, ref.Scope, ref.ArtifactID)
}
