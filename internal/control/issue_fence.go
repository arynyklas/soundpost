// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"

	"github.com/arynyklas/soundpost/internal/model"
)

// ProjectFenced reports whether a deletion saga that covers the project is in
// its fencing phase. While it is, reads and writes of the project's lifecycle
// state are denied: the fence is pending (never success) and nothing may be
// released or changed under it. A completed, held or failed operation does not
// fence; a retired project is already not found.
func (s *Store) ProjectFenced(ctx context.Context, org, project model.ID) (fenced bool, err error) {
	err = s.View(ctx, func(st State) error {
		for _, op := range st.Deletions {
			if op.Phase == model.DeletePhaseFencing && op.Predicate.CoversProject(org, project) {
				fenced = true
				return nil
			}
		}
		return nil
	})
	return fenced, err
}
