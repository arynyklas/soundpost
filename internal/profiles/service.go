// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"time"
)

type Service struct {
	scanner    ProfileScanner
	authorizer ScopeAuthorizer
	links      LinkResolver
	key        [32]byte
	ready      bool
}

func NewService(scanner ProfileScanner, authorizer ScopeAuthorizer, links LinkResolver) *Service {
	s := &Service{scanner: scanner, authorizer: authorizer, links: links}
	_, err := rand.Read(s.key[:])
	s.ready = err == nil && scanner != nil && authorizer != nil && links != nil
	return s
}

type profileCursor struct {
	Org, Project, Profile model.ID
	Fingerprint           string
	Epoch                 model.Uint64
	Start, End            model.UnixNano
	Offset                uint32
	Expires               model.Int64
	Marks                 []model.Cursor
}

func (s *Service) decodeCursor(text string, scope auth.Scope, id model.ID, w Window) (profileCursor, error) {
	if len(text) > 16384 {
		return profileCursor{}, model.Fail(model.Invalid)
	}
	b, e := base64.RawURLEncoding.DecodeString(text)
	if e != nil || len(b) < 32 {
		return profileCursor{}, model.Fail(model.Invalid)
	}
	body, signature := b[:len(b)-32], b[len(b)-32:]
	h := hmac.New(sha256.New, s.key[:])
	h.Write(body)
	if !hmac.Equal(signature, h.Sum(nil)) {
		return profileCursor{}, model.Fail(model.NotFound)
	}
	var c profileCursor
	if model.StrictJSON(body, &c) != nil || c.Org != scope.OrgID() || !scope.AllowsProject(c.Project) || c.Profile != id || c.Fingerprint != scope.VisibilityFingerprint() || c.Epoch != model.Uint64(scope.PolicyEpoch()) || c.Start != w.Start || c.End != w.End || int64(c.Expires) <= time.Now().Unix() {
		return profileCursor{}, model.Fail(model.NotFound)
	}
	return c, nil
}
func (s *Service) encodeCursor(c profileCursor) (string, error) {
	b, e := json.Marshal(c)
	if e != nil {
		return "", e
	}
	h := hmac.New(sha256.New, s.key[:])
	h.Write(b)
	return base64.RawURLEncoding.EncodeToString(append(b, h.Sum(nil)...)), nil
}
func unavailable() error { return model.Fail(model.NotFound) }
func (s *Service) Read(ctx context.Context, scope auth.Scope, id model.ID, w Window) (view ProfileView, err error) {
	if s == nil || !s.ready {
		return view, model.Fail(model.Unavailable)
	}
	if e := ctx.Err(); e != nil {
		return view, e
	}
	if s.authorizer.Revalidate(ctx, scope) != nil {
		return view, unavailable()
	}
	projects := scope.ProjectIDs()
	if scope.OrgID() == (model.ID{}) || len(projects) != 1 || scope.Permission() != auth.Read && scope.Permission() != auth.Permission("profiles.read") {
		return view, unavailable()
	}
	if id == (model.ID{}) || w.End <= w.Start || w.MaxSamples == 0 || w.MaxSamples > 8192 || len(w.MinCursors) > 64 {
		return view, model.Fail(model.Invalid)
	}
	var offset uint32
	expires := time.Now().Add(15 * time.Minute).Unix()
	if w.Cursor != "" {
		c, e := s.decodeCursor(w.Cursor, scope, id, w)
		if e != nil {
			return view, e
		}
		offset = c.Offset
		expires = int64(c.Expires)
		w.MinCursors = append(w.MinCursors, c.Marks...)
		if len(w.MinCursors) > 128 {
			return view, model.Fail(model.Invalid)
		}
	}
	it, e := s.scanner.ScanProfile(ctx, scope, id, w)
	if e != nil {
		return view, unavailable()
	}
	defer func() {
		if e := it.Close(); err == nil && e != nil {
			view = ProfileView{}
			err = e
		}
	}()
	var pages []ProfilePage
	var chunks []model.ProfileChunk
	var bytes uint64
	for {
		if s.authorizer.Revalidate(ctx, scope) != nil {
			return ProfileView{}, unavailable()
		}
		p, e := it.Next(ctx)
		if e == io.EOF {
			break
		}
		if e != nil {
			return ProfileView{}, unavailable()
		}
		if p.Project != projects[0] || !scope.AllowsProject(p.Project) {
			return ProfileView{}, unavailable()
		}
		raw, e := json.Marshal(p)
		if e != nil {
			return ProfileView{}, model.Fail(model.Corrupt)
		}
		bytes += uint64(len(raw))
		if bytes > 4<<20 || len(chunks)+len(p.Chunks) > 64 {
			return ProfileView{}, model.Fail(model.TooLarge)
		}
		for _, c := range p.Chunks {
			if c.Profile != id {
				return ProfileView{}, model.Fail(model.Corrupt)
			}
		}
		pages = append(pages, p)
		chunks = append(chunks, p.Chunks...)
	}
	if len(chunks) == 0 {
		return ProfileView{}, unavailable()
	}
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].Sequence < chunks[j].Sequence })
	view.Project = projects[0]
	view.Completeness = "complete"
	var refs []Reference
	expected := uint64(1)
	for _, p := range pages {
		if !p.Complete || !capabilitiesComplete(p) {
			view.Completeness = "partial"
			view.Reasons = append(view.Reasons, "missing_capability_or_page")
		}
		view.Capabilities = append(view.Capabilities, p.Capabilities...)
		view.Loss = append(view.Loss, p.Loss...)
		view.Watermarks = append(view.Watermarks, p.Watermarks...)
		refs = append(refs, p.Links...)
	}
	if len(refs) > 128 {
		return ProfileView{}, model.Fail(model.TooLarge)
	}
	var total uint32
	for _, c := range chunks {
		if c.NativeDomain != nil {
			if uint64(c.Sequence) != expected {
				view.Completeness = "partial"
				view.Reasons = append(view.Reasons, "missing_chunk")
			}
			if uint64(c.Sequence) < expected {
				return ProfileView{}, model.Fail(model.Corrupt)
			}
			expected = uint64(c.Sequence) + 1
		}
		clipped, e := clipChunk(c, w)
		if e != nil {
			return ProfileView{}, e
		}
		count := uint32(len(clipped.Samples) + len(clipped.Intervals))
		skip := uint32(0)
		if offset > total {
			skip = offset - total
			if skip > count {
				skip = count
			}
		}
		if e = appendChunk(&view, clipped, skip, w.MaxSamples); e != nil {
			return ProfileView{}, e
		}
		if count > ^uint32(0)-total {
			return ProfileView{}, model.Fail(model.TooLarge)
		}
		total += count
	}
	last := chunks[len(chunks)-1]
	if last.NativeDomain != nil && !last.Complete || view.Truncated || view.LossCount > 0 || len(view.NativeLoss) > 0 || len(view.Loss) > 0 {
		view.Completeness = "partial"
		view.Reasons = append(view.Reasons, "coverage_incomplete")
	}
	emitted := uint32(len(view.Samples) + len(view.Intervals))
	if offset > total {
		return ProfileView{}, unavailable()
	}
	if offset+emitted < total {
		view.NextCursor, e = s.encodeCursor(profileCursor{Org: scope.OrgID(), Project: projects[0], Profile: id, Fingerprint: scope.VisibilityFingerprint(), Epoch: model.Uint64(scope.PolicyEpoch()), Start: w.Start, End: w.End, Offset: offset + emitted, Expires: model.Int64(expires), Marks: view.Watermarks})
		if e != nil {
			return ProfileView{}, e
		}
	}
	if emitted == 0 {
		view.Completeness = "partial"
		view.Reasons = append(view.Reasons, "no_observations_in_window")
	}
	view.Links, e = s.links.Resolve(ctx, scope, refs)
	if e != nil {
		return ProfileView{}, unavailable()
	}
	if len(view.Links) != len(refs) {
		return ProfileView{}, model.Fail(model.Corrupt)
	}
	// Missing/denied links disclose no target metadata. Inference is never promoted
	// to an explicit causal relationship by either the resolver or this service.
	for i := range view.Links {
		if !view.Links[i].Available {
			view.Links[i].Reference = nil
		} else if view.Links[i].Reference == nil || *view.Links[i].Reference != refs[i] {
			return ProfileView{}, model.Fail(model.Corrupt)
		}
	}
	if s.authorizer.Revalidate(ctx, scope) != nil {
		return ProfileView{}, unavailable()
	}
	encoded, e := json.Marshal(view)
	if e != nil {
		return ProfileView{}, e
	}
	if len(encoded) > 4<<20 {
		return ProfileView{}, model.Fail(model.TooLarge)
	}
	return view, nil
}
