// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"errors"

	"github.com/arynyklas/soundpost/internal/model"
)

// Decision D19 (permission model of human actions, recommended by lane 3 wave 3):
//
//   - A human action on a project needs the project grant that names it:
//     incidents.write for the incident actions, issues.write for the issue
//     actions, and issues.write AND policy.write for the grouping migration (it
//     rewrites a project policy). rules.write names rule-definition writes; no
//     human route exists for them yet, so it authorizes no action today.
//   - Organization administration implies all of them in its own organization,
//     as before, so an administrator keeps acting without being granted each one.
//   - A grant is project-scoped, needs organization membership (as every project
//     grant does), is revoked at once through the policy epoch, and is the same
//     NotFound as an unknown project when absent: a caller never learns which
//     grant was missing.
//   - A write grant authorizes the write only. The control store accepts
//     incidents.write for the incident action kind alone (ControlAuthorize), and
//     every read a write needs is a separate, named allowance in the reader.
//
// AuthorizeWrite derives the scope of such a write.

// IncidentActionKind is the control command kind a human incident action
// commits as (control.KindIncidentAction; a test pins the two equal). The
// control store admits an incidents.write scope for this kind only.
const IncidentActionKind = "IncidentAction"

// AuthorizeWrite derives the scope of a human write on one project: the scope of
// the named grants when the caller holds every one of them on the project, and
// otherwise the organization administrator scope for the project. A caller with
// neither is the one NotFound. It never widens: an administrator's scope is the
// ordinary one-project org.admin scope.
func (s *Service) AuthorizeWrite(ctx context.Context, c Credential, org, project model.ID, grants ...Permission) (Scope, error) {
	if project == (model.ID{}) || len(grants) == 0 {
		return Scope{}, model.Fail(model.Invalid)
	}
	var first Scope
	held := true
	for i, grant := range grants {
		scope, err := s.Authorize(ctx, c, org, []model.ID{project}, grant)
		if err != nil {
			if !notFound(err) {
				return Scope{}, err
			}
			held = false
			break
		}
		if i == 0 {
			first = scope
		}
	}
	if held {
		return first, nil
	}
	return s.Authorize(ctx, c, org, []model.ID{project}, OrgAdmin)
}

func notFound(err error) bool {
	var f *model.Fault
	return errors.As(err, &f) && f.Code == model.NotFound
}
