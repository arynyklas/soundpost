// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"

	"github.com/arynyklas/soundpost/internal/model"
)

// ViewMembers is ViewCore for a reader of the named members of the state only (the others come empty, as for
// ViewCore its maps are shared and not the reader's to change). It has ViewCore's read barrier and its
// revision: a read never sees a member older than the committed revision, whatever the cache holds. A commit
// that changed none of the named members costs it nothing, where ViewCore decodes every member the commit
// touched, whether or not the reader looks at it: the authentication of a request reads three members, and
// at the gate the rule scheduler and the retention worker commit all the time. A name that is no member of
// the state is a mistake of the caller and panics, as memberSetOf does.
func (s *Store) ViewMembers(ctx context.Context, names []string, fn func(model.ControlState) error) error {
	return s.viewCoreOf(ctx, memberSetOf(names...), fn)
}
