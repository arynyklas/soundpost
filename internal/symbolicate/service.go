// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"context"
	"errors"
	"io"
	"slices"
	"soundpost/internal/artifacts"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

type Service struct {
	reader  ArtifactReader
	deletes auth.DeleteGenerations
	config  Config
	cache   *boundedCache
	slots   chan struct{}
	// runner launches one worker for one frame; tests replace it with a fake.
	runner func(context.Context, workerInput) workerOutput
}

// New binds the protected artifact reader and the delete-generation authority
// (the retention service in production). Warm map bytes are keyed by the
// generation they were read under, so any deletion, retirement or erasure that
// advances it makes them unreachable; the deletion predicates themselves are
// re-checked on every request through the reader's revalidation fence.
func New(reader ArtifactReader, deletes auth.DeleteGenerations, config Config) (*Service, error) {
	if reader == nil || deletes == nil || config.CacheBytes < 0 || config.CacheBytes > 64<<20 {
		return nil, model.Fail(model.Invalid)
	}
	n := config.CacheBytes
	if n == 0 {
		n = 64 << 20
	}
	s := &Service{reader: reader, deletes: deletes, config: config, cache: newCache(n), slots: make(chan struct{}, 2)}
	s.runner = s.run
	return s, nil
}
func (s *Service) Resolve(ctx context.Context, scope auth.Scope, build BuildID, frames []model.Frame) ([]SymbolicatedFrame, error) {
	return s.ResolveWithOptions(ctx, scope, build, frames, Options{})
}
func (s *Service) ResolveWithOptions(ctx context.Context, scope auth.Scope, build BuildID, frames []model.Frame, options Options) ([]SymbolicatedFrame, error) {
	if build == (model.ID{}) || len(frames) > MaxFrames {
		return nil, model.Fail(model.Invalid)
	}
	ctx, cancel := context.WithTimeout(ctx, ProcessTimeout)
	defer cancel()
	// Bound artifact buffers too, not merely subprocesses after a caller has
	// already read its full map. Waiting requests retain no artifact bytes.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-ctx.Done():
	}
	out := make([]SymbolicatedFrame, len(frames))
	projects := scope.ProjectIDs()
	seen := map[frameKey]int{}
	for i, f := range frames {
		out[i] = SymbolicatedFrame{Original: f, Build: build, Reason: Unavailable}
		if f.Column != nil {
			c := *f.Column
			out[i].Original.Column = &c
		}
		if ctx.Err() != nil {
			out[i].Reason = Deadline
			continue
		}
		// C07 accepts only the actual canonical ArtifactID. Paths, release labels,
		// URLs and map/content hashes are never lookup aliases or fetch targets.
		id, e := model.ParseID(f.Artifact)
		if e != nil {
			continue
		}
		if len(projects) != 1 {
			continue
		}
		if f.Line == 0 || f.Column == nil {
			out[i].Reason = Unmapped
			continue
		}
		// Identical lookups cost one worker run; distinct ones are capped so a
		// deep stack cannot silently exhaust the shared wall budget as `deadline`.
		fk := frameKey{id, f.Line, *f.Column}
		if first, ok := seen[fk]; ok {
			prior := out[first]
			out[i].Reason, out[i].MapSHA256, out[i].SourceContext = prior.Reason, prior.MapSHA256, prior.SourceContext
			if prior.Resolved != nil {
				r := *prior.Resolved
				out[i].Resolved = &r
			}
			if prior.SourceContext != nil {
				c := *prior.SourceContext
				out[i].SourceContext = &c
			}
			continue
		}
		if len(seen) >= MaxResolvedFrames {
			out[i].Reason = FrameLimit
			continue
		}
		seen[fk] = i
		read, e := scope.ArtifactReadScope(ctx, projects[0])
		if e != nil {
			continue
		}
		// The generation is sampled before the reference is looked up, so a deletion
		// that commits afterwards can only make this entry unreachable, never let its
		// bytes be filed under the newer generation. An unanswerable authority fails
		// closed like an absent artifact.
		generation, e := s.deletes.DeleteGeneration(ctx, read.OrgID(), []model.ID{projects[0]})
		if e != nil {
			continue
		}
		s.cache.dropBefore(read.OrgID(), generation)
		ref, e := s.reader.Lookup(ctx, read, id)
		if e != nil {
			continue
		}
		if !matches(id, build, ref) || ref.Manifest.Org != read.OrgID() || ref.Manifest.Project != projects[0] {
			out[i].Reason = IdentityMismatch
			continue
		}
		m := ref.Manifest
		key := cacheKey{Org: m.Org, Project: m.Project, Source: m.Source, Build: build, Root: id, Visibility: read.VisibilityFingerprint(), Epoch: read.PolicyEpoch(), Generation: generation, Hash: ref.Map.Manifest.Hash}
		// Every request, warm or cold, passes the current retention, deletion and
		// grant fence before any cached byte is used.
		if read.RevalidateArtifact(ctx, ref.Map.Manifest, false) != nil {
			s.cache.remove(key)
			continue
		}
		raw := s.cache.get(key)
		if raw == nil {
			raw, e = s.read(ctx, read, ref, false)
			if e != nil {
				s.cache.remove(key)
				// A NotFound read is an absent or denied artifact (a deletion
				// committing between the fence and the read): one answer, never a
				// corruption report that confirms the root existed.
				if !isNotFound(e) {
					out[i].Reason = CorruptArtifact
				}
				continue
			}
			s.cache.put(key, raw)
		}
		in := workerInput{Version: 1, Map: raw, MapHash: ref.Map.Manifest.Hash, Line: f.Line, Column: *f.Column, IncludeSources: options.IncludeSources}
		if options.IncludeSources {
			if ref.Sources == nil {
				out[i].Reason = SourceDenied
				continue
			}
			in.Sources, e = s.read(ctx, read, ref, true)
			if e != nil {
				out[i].Reason = SourceDenied
				continue
			}
			in.SourcesHash = ref.Sources.Manifest.Hash
		}
		result := s.runner(ctx, in)
		if ctx.Err() != nil {
			out[i].Reason = Deadline
			continue
		}
		// Warm bytes/results confer no grant. Fence current reference, policy,
		// retention, deletion and any separate private-source grants on each release.
		current, e := s.reader.Lookup(ctx, read, id)
		if e != nil || !sameReference(ref, current) || read.RevalidateArtifact(ctx, ref.Map.Manifest, false) != nil {
			s.cache.remove(key)
			continue
		}
		if options.IncludeSources && read.RevalidateArtifact(ctx, ref.Sources.Manifest, false) != nil {
			out[i].Reason = SourceDenied
			continue
		}
		out[i].Reason = result.Reason
		if result.Reason == Resolved {
			out[i].Resolved = result.Position
			out[i].SourceContext = result.SourceContext
			out[i].MapSHA256 = m.MapSHA256
		}
	}
	return out, nil
}

func isNotFound(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.NotFound
}

type frameKey struct {
	artifact     model.ID
	line, column uint32
}

func matches(id model.ID, build BuildID, r artifacts.Artifact) bool {
	m, b := r.Manifest, r.Map.Manifest
	if artifacts.ValidateManifest(m) != nil || id != r.ID || m.Build != build || b.PrivateSources || r.Map.Hash != b.Hash || b.Hash == (model.Hash{}) || b.Size == 0 || uint64(b.Size) > MaxMapBytes {
		return false
	}
	if b.Root != id || b.Org != m.Org || b.Project != m.Project || b.Source != m.Source || b.Build != m.Build || b.DebugID != m.DebugID || b.Path != m.Path || b.GeneratedSHA256 != m.GeneratedSHA256 || b.MapSHA256 != m.MapSHA256 || b.RetainUntil != m.RetainUntil {
		return false
	}
	if r.Sources != nil {
		p := r.Sources.Manifest
		if !m.SourceContent || !p.PrivateSources || p.Root != id || p.Org != m.Org || p.Project != m.Project || p.Source != m.Source || p.Build != m.Build || p.DebugID != m.DebugID || p.Path != m.Path || p.GeneratedSHA256 != m.GeneratedSHA256 || p.MapSHA256 != m.MapSHA256 || p.RetainUntil != m.RetainUntil || r.Sources.Hash != p.Hash {
			return false
		}
	}
	return true
}
func sameReference(a, b artifacts.Artifact) bool {
	if a.ID != b.ID || a.Manifest != b.Manifest || a.CommandID != b.CommandID || a.ControlRevision != b.ControlRevision || a.State != b.State || !sameReceipt(a.Map, b.Map) || (a.Sources == nil) != (b.Sources == nil) {
		return false
	}
	return a.Sources == nil || sameReceipt(*a.Sources, *b.Sources)
}
func sameReceipt(a, b model.BlobReceipt) bool {
	return a.Manifest == b.Manifest && a.Hash == b.Hash && a.Cursor == b.Cursor && slices.Equal(a.Fragments, b.Fragments)
}
func (s *Service) read(ctx context.Context, scope auth.Scope, r artifacts.Artifact, private bool) ([]byte, error) {
	receipt := r.Map
	var stream io.ReadCloser
	var e error
	if private {
		if r.Sources == nil {
			return nil, model.Fail(model.NotFound)
		}
		receipt = *r.Sources
		stream, e = s.reader.GetSources(ctx, scope, r.ID)
	} else {
		stream, e = s.reader.Get(ctx, scope, r.ID)
	}
	if e != nil {
		return nil, e
	}
	defer stream.Close()
	if receipt.Manifest.Size == 0 || receipt.Manifest.Size > MaxMapBytes {
		return nil, model.Fail(model.TooLarge)
	}
	raw, e := io.ReadAll(io.LimitReader(stream, int64(receipt.Manifest.Size)+1))
	if e != nil {
		return nil, e
	}
	if uint64(len(raw)) != uint64(receipt.Manifest.Size) || model.HashCanonical(raw) != receipt.Manifest.Hash {
		return nil, model.Fail(model.Invalid)
	}
	return raw, nil
}
