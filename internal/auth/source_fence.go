// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"soundpost/internal/model"
)

type SourceBarrier interface {
	FenceSource(context.Context, model.SourceFence) ([]model.Cursor, error)
}

// DrainSourceFences runs against the injected installed one-voter owner. It must
// be replaced by the actual slot quorum owner on the distributed cutover.
func (s *Service) BindSourceBarrier(owner SourceBarrier) error {
	if owner == nil || s.sourceBarrier != nil {
		return model.Fail(model.Conflict)
	}
	s.sourceBarrier = owner
	return nil
}
func (s *Service) DrainSourceFences(ctx context.Context) error {
	owner := s.sourceBarrier
	if owner == nil {
		return model.Fail(model.Unavailable)
	}
	var pending []model.SourceFence
	if e := s.store.View(ctx, func(st model.ControlState) error {
		for _, f := range st.SourceFences {
			if f.Phase == "fencing" {
				pending = append(pending, f)
			}
		}
		return nil
	}); e != nil {
		return e
	}
	for _, f := range pending {
		cursors, e := owner.FenceSource(ctx, f)
		if e != nil {
			return e
		}
		if len(cursors) != 64 {
			return model.Fail(model.Unavailable)
		}
		groups := map[model.ID]bool{}
		for _, cursor := range cursors {
			if cursor.Group == (model.ID{}) || cursor.Index == 0 || groups[cursor.Group] {
				return model.Fail(model.Corrupt)
			}
			groups[cursor.Group] = true
		}
		e = s.store.Update(ctx, func(st *model.ControlState) error {
			current, ok := st.SourceFences[f.Source.String()]
			if !ok || current.Operation != f.Operation || current.Epoch != f.Epoch {
				return model.Fail(model.Stale)
			}
			if current.Phase == "complete" {
				return nil
			}
			current.Phase = "complete"
			current.Barriers = append([]model.Cursor(nil), cursors...)
			st.SourceFences[f.Source.String()] = current
			if st.SourceOperations == nil {
				st.SourceOperations = map[string]model.SourceFence{}
			}
			st.SourceOperations[current.Operation.String()] = current
			src := st.Sources[f.Source.String()]
			src.Closing = false
			st.Sources[f.Source.String()] = src
			return nil
		})
		if e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) SourceOperation(ctx context.Context, c Credential, id model.ID) (model.SourceFence, error) {
	if c.service != s || c.machine {
		return model.SourceFence{}, model.Fail(model.NotFound)
	}
	var out model.SourceFence
	e := s.store.View(ctx, func(st model.ControlState) error {
		if e := s.validateCredentialState(st, c); e != nil {
			return e
		}
		f, ok := st.SourceOperations[id.String()]
		if !ok || !st.Orgs[f.Org.String()].Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		out = f
		return nil
	})
	return out, e
}
