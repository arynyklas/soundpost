// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/ingest"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"github.com/arynyklas/soundpost/internal/profiles"
	"github.com/arynyklas/soundpost/internal/storage"
	"io"
	"math"
)

// NewNativeProfiles constructs the real C05/C02 read composition. The caller
// retains this scoped service for authenticated cursors; no process-global cache
// or replacement authorization scope is manufactured here.
func (a *App) NewNativeProfiles() *profiles.Service {
	return profiles.NewService(nativeProfileScanner{a.Storage}, a.Auth, nativeProfileLinks{storage: a.Storage, auth: a.Auth, artifacts: a.Artifacts})
}
func (a *App) NewNativeProfileExporter(c auth.SourceCredential, cfg nativeperf.ExportConfig, reserved nativeperf.WorkingReservation) (*nativeperf.Exporter, error) {
	return nativeperf.NewExporter(a.Ingest, nativeReceiptLookup{a.Ingest, c}, cfg, reserved)
}

type nativeReceiptLookup struct {
	ingest     *ingest.Service
	credential auth.SourceCredential
}

func (l nativeReceiptLookup) LookupReceipt(ctx context.Context, q model.ReceiptRequest) (model.Receipt, error) {
	return l.ingest.LookupReceipt(ctx, l.credential, q)
}

type nativeProfileScanner struct{ storage *storage.Engine }
type nativeProfileIterator struct {
	storage      *storage.Engine
	scope        auth.Scope
	id           model.ID
	window       profiles.Window
	sent, closed bool
	original     []model.ID
	source       model.ID
}

func (s nativeProfileScanner) ScanProfile(ctx context.Context, scope auth.Scope, id model.ID, w profiles.Window) (profiles.ProfileIterator, error) {
	if len(scope.ProjectIDs()) != 1 || id == (model.ID{}) {
		return nil, model.Fail(model.NotFound)
	}
	return &nativeProfileIterator{storage: s.storage, scope: scope, id: id, window: w}, nil
}
func idMatcher(name string, id model.ID) storage.Matcher {
	return storage.Matcher{Target: storage.MatchField, Name: name, Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: id.String()}}
}
func mergeProfileMarks(a, b []model.Cursor) []model.Cursor {
	out := make([]model.Cursor, 0, len(a))
	for _, left := range a {
		for _, right := range b {
			if left.Group == right.Group {
				if right.Index < left.Index {
					left.Index = right.Index
				}
				out = append(out, left)
				break
			}
		}
	}
	return out
}
func (it *nativeProfileIterator) scan(ctx context.Context, kind model.Kind, selectors []storage.Matcher, consume func(storage.Page, int) error) ([]model.Cursor, bool, error) {
	req := storage.ScanRequest{Projects: it.scope.ProjectIDs(), Signal: kind, Start: math.MinInt64, End: math.MaxInt64, Selectors: selectors, Fence: storage.ReadFence{Min: it.window.MinCursors}}
	rows, err := it.storage.Scan(ctx, it.scope, req)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	marks := rows.Watermarks()
	complete := true
	var bytes uint64
	for {
		p, err := rows.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false, err
		}
		if p.Partial {
			complete = false
		}
		bytes += p.Bytes
		if bytes > 8<<20 {
			return nil, false, model.Fail(model.TooLarge)
		}
		for i := range p.IDs {
			if err = consume(p, i); err != nil {
				return nil, false, err
			}
		}
	}
	return marks, complete, nil
}
func ownProfileValue[T any](value T) (T, error) {
	raw, e := json.Marshal(value)
	if e != nil {
		var zero T
		return zero, e
	}
	var out T
	e = model.StrictJSON(raw, &out)
	return out, e
}
func (it *nativeProfileIterator) Next(ctx context.Context) (profiles.ProfilePage, error) {
	if it.closed {
		return profiles.ProfilePage{}, io.ErrClosedPipe
	}
	if it.sent {
		// Reopen the actual root index before releasing EOF to the feature service.
		// A deleted root cannot survive in a retained page/cache between scans.
		found := map[model.ID]bool{}
		_, _, err := it.scan(ctx, model.Profile, []storage.Matcher{idMatcher("profile_id", it.id), idMatcher("source_id", it.source)}, func(p storage.Page, i int) error { found[p.IDs[i]] = true; return nil })
		if err != nil {
			return profiles.ProfilePage{}, err
		}
		for _, id := range it.original {
			if !found[id] {
				return profiles.ProfilePage{}, model.Fail(model.NotFound)
			}
		}
		return profiles.ProfilePage{}, io.EOF
	}
	page := profiles.ProfilePage{Project: it.scope.ProjectIDs()[0], Complete: true}
	caps := map[model.ID]bool{}
	var bytes uint64
	marks, complete, err := it.scan(ctx, model.Profile, []storage.Matcher{idMatcher("profile_id", it.id)}, func(p storage.Page, i int) error {
		if p.Values[i].Profile == nil || p.Projects[i] != page.Project {
			return model.Fail(model.Corrupt)
		}
		if page.Source == (model.ID{}) {
			page.Source = p.Sources[i]
		} else if page.Source != p.Sources[i] {
			return model.Fail(model.Corrupt)
		}
		c, e := ownProfileValue(*p.Values[i].Profile)
		if e != nil {
			return e
		}
		raw, e := json.Marshal(c)
		if e != nil {
			return e
		}
		bytes += uint64(len(raw))
		if bytes > 4<<20 || len(page.Chunks) >= 64 {
			return model.Fail(model.TooLarge)
		}
		page.Chunks = append(page.Chunks, c)
		it.original = append(it.original, p.IDs[i])
		caps[c.Capability] = true
		for _, id := range c.NativeCapabilities {
			caps[id] = true
		}
		for _, f := range c.Frames {
			if f.Artifact != "" {
				id, e := model.ParseID(f.Artifact)
				if e == nil {
					page.Links = append(page.Links, profiles.Reference{Project: page.Project, Build: p.Resources[i].Build, Kind: "artifact", ID: id, Relation: "explicit"})
				}
			}
		}
		return nil
	})
	if err != nil {
		return profiles.ProfilePage{}, err
	}
	if len(page.Chunks) == 0 {
		return profiles.ProfilePage{}, model.Fail(model.NotFound)
	}
	if len(caps) > 3 {
		return profiles.ProfilePage{}, model.Fail(model.Corrupt)
	}
	page.Watermarks = marks
	page.Complete = complete
	for id := range caps {
		marks, complete, err = it.scan(ctx, model.CapabilityKind, []storage.Matcher{idMatcher("id", id), idMatcher("source_id", page.Source)}, func(p storage.Page, i int) error {
			c := p.Values[i].Capability
			if c == nil || c.Signal != model.Profile {
				return model.Fail(model.Corrupt)
			}
			owned, e := ownProfileValue(*c)
			if e != nil {
				return e
			}
			page.Capabilities = append(page.Capabilities, profiles.CapabilityRecord{ID: p.IDs[i], Value: owned})
			return nil
		})
		if err != nil {
			return profiles.ProfilePage{}, err
		}
		page.Watermarks = mergeProfileMarks(page.Watermarks, marks)
		page.Complete = page.Complete && complete
	}
	marks, complete, err = it.scan(ctx, model.Loss, []storage.Matcher{idMatcher("epoch_id", it.id), idMatcher("source_id", page.Source)}, func(p storage.Page, i int) error {
		loss := p.Values[i].Loss
		if loss == nil || loss.Signal != model.Profile {
			return model.Fail(model.Corrupt)
		}
		if len(page.Loss) >= 128 {
			return model.Fail(model.TooLarge)
		}
		owned, e := ownProfileValue(*loss)
		if e != nil {
			return e
		}
		page.Loss = append(page.Loss, owned)
		return nil
	})
	if err != nil {
		return profiles.ProfilePage{}, err
	}
	page.Watermarks = mergeProfileMarks(page.Watermarks, marks)
	page.Complete = page.Complete && complete
	it.source = page.Source
	it.sent = true
	return page, nil
}
func (it *nativeProfileIterator) Close() error { it.closed = true; it.original = nil; return nil }

type nativeArtifactLookup interface {
	Lookup(context.Context, auth.Scope, model.ID) (model.ArtifactReferenceIntent, error)
}
type nativeProfileLinks struct {
	storage   *storage.Engine
	auth      *auth.Service
	artifacts nativeArtifactLookup
}

func (l nativeProfileLinks) Resolve(ctx context.Context, scope auth.Scope, refs []profiles.Reference) ([]profiles.ResolvedReference, error) {
	if len(refs) > 128 {
		return nil, model.Fail(model.TooLarge)
	}
	out := make([]profiles.ResolvedReference, len(refs))
	for i, ref := range refs {
		if err := l.auth.Revalidate(ctx, scope); err != nil {
			return nil, model.Fail(model.NotFound)
		}
		if !scope.AllowsProject(ref.Project) || ref.ID == (model.ID{}) || ref.Relation != "explicit" && ref.Relation != "time_overlap_inference" {
			continue
		}
		// C07's real reference lookup reauthorizes artifacts.read using the SAME
		// original credential. Hash equality and telemetry grants never authorize it.
		// This verifies a link, not native ELF symbolication (backend accepts maps).
		if ref.Kind == "artifact" {
			if l.artifacts == nil || ref.Build == (model.ID{}) {
				continue
			}
			artifactScope, e := scope.ArtifactReadScope(ctx, ref.Project)
			if e != nil {
				continue
			}
			artifact, e := l.artifacts.Lookup(ctx, artifactScope, ref.ID)
			if e != nil || artifact.ID != ref.ID || artifact.Manifest.Org != scope.OrgID() || artifact.Manifest.Project != ref.Project || artifact.Manifest.Build != ref.Build {
				continue
			}
			owned := ref
			out[i] = profiles.ResolvedReference{Reference: &owned, Available: true}
			continue
		}
		var kind model.Kind
		var field string
		switch ref.Kind {
		case "profile":
			kind = model.Profile
			field = "profile_id"
		case "trace":
			kind = model.SpanKind
			field = "trace_id"
		case "replay":
			kind = model.Replay
			field = "replay_id"
		default:
			continue
		}
		rows, err := l.storage.Scan(ctx, scope, storage.ScanRequest{Projects: []model.ID{ref.Project}, Signal: kind, Start: math.MinInt64, End: math.MaxInt64, Selectors: []storage.Matcher{idMatcher(field, ref.ID)}})
		if err != nil {
			continue
		}
		page, err := rows.Next(ctx)
		exists := err == nil && page.Len() > 0
		closeErr := rows.Close()
		if !exists || closeErr != nil {
			continue
		}
		owned := ref
		out[i] = profiles.ResolvedReference{Reference: &owned, Available: true}
	}
	if err := l.auth.Revalidate(ctx, scope); err != nil {
		return nil, model.Fail(model.NotFound)
	}
	return out, nil
}
