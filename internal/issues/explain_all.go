// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"context"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// ExplainAll returns the stored regression evaluations of every issue of one
// project that has any, oldest first within each issue. It is Explain for the
// whole project under the same authorization, deletion fence and read: a release
// view lists the evaluations whose occurrence ran in that release, and no route
// lists issues by release.
func (s *Service) ExplainAll(ctx context.Context, scope auth.Scope, project model.ID) (map[model.ID][]Explanation, error) {
	state, e := s.read(ctx, scope, project)
	if e != nil {
		return nil, e
	}
	out := make(map[model.ID][]Explanation, len(state.Issues))
	for id, rec := range state.Issues {
		if len(rec.Explanations) > 0 {
			out[id] = cloneRecord(rec).Explanations
		}
	}
	return out, nil
}
