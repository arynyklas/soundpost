// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package releases

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// appendAttempts bounds the retries of a registration that only lost the control-revision race.
const appendAttempts = 8

// ReleaseConflict is the closed detail of the 409 an append answers when the release identity or the command is already used by other content.
const ReleaseConflict = "release_conflict"

func conflict() error {
	f := model.Fail(model.Conflict)
	f.SafeDetail = ReleaseConflict
	return f
}

// normalize is the form the control apply stores: parents and debug artifacts sorted, empty lists nil.
func normalize(r Release) Release {
	r.Parents = append([]model.ID(nil), r.Parents...)
	sort.Slice(r.Parents, func(i, j int) bool { return bytes.Compare(r.Parents[i][:], r.Parents[j][:]) < 0 })
	if len(r.Parents) == 0 {
		r.Parents = nil
	}
	r.DebugArtifacts = append([]model.ReleaseDebugArtifact(nil), r.DebugArtifacts...)
	sort.Slice(r.DebugArtifacts, func(i, j int) bool {
		return bytes.Compare(r.DebugArtifacts[i].ArtifactID[:], r.DebugArtifacts[j].ArtifactID[:]) < 0
	})
	if len(r.DebugArtifacts) == 0 {
		r.DebugArtifacts = nil
	}
	return r
}

// sameIdentity compares the immutable identity of two releases: ID, build, parents, build time and debug artifacts.
func sameIdentity(a, b Release) bool {
	a, b = normalize(a), normalize(b)
	return a.ID == b.ID && a.BuildID == b.BuildID && a.BuildTime == b.BuildTime && reflect.DeepEqual(a.Parents, b.Parents) && reflect.DeepEqual(a.DebugArtifacts, b.DebugArtifacts)
}

// original is the first committed receipt of a stored release.
func original(stored Release) Release {
	if len(stored.History) == 0 {
		return stored
	}
	out := stored
	out.Revision = stored.History[0].Revision
	out.DisplayLabel = stored.History[0].DisplayLabel
	out.History = stored.History[:1]
	return out
}

// RegisterAppend is the release registration of a release pipeline: an idempotent append keyed by the release identity (ID, build,
// parents, build time, debug artifacts) and the command ID, for a caller that cannot read the control revision. The server reads
// the revision itself and retries when the registration only lost a revision race. A release that is already registered with the
// identical identity (and a label it ever had) answers its original receipt and commits nothing; a release ID or command ID that
// is already used by other content, or any rename, is a conflict (the label of a registered release changes only through Register
// with the entity revision, by an administrator).
func (s *Service) RegisterAppend(ctx context.Context, scope auth.Scope, release Release, commandID model.ID) (Release, error) {
	if e := s.authorize(ctx, scope); e != nil {
		return Release{}, e
	}
	if release.ID == (model.ID{}) || commandID == (model.ID{}) || release.Revision != 0 && release.Revision != 1 {
		return Release{}, model.Fail(model.Invalid)
	}
	release.Revision = 0
	for range appendAttempts {
		var revision model.Revision
		var prior *Release
		var commandRelease *model.ID
		if e := s.store.View(ctx, func(st model.ControlState) error {
			if e := scopedProject(scope, st, release.Project); e != nil {
				return e
			}
			revision = st.Revision
			if stored, ok := st.Releases[model.ReleaseScopeKey(scope.OrgID(), release.Project, release.ID)]; ok {
				prior = &stored
			}
			if result, ok := st.Commands[commandID.String()]; ok && len(result.AffectedIDs) == 1 {
				commandRelease = &result.AffectedIDs[0]
			}
			return nil
		}); e != nil {
			return Release{}, e
		}
		if commandRelease != nil && *commandRelease != release.ID {
			return Release{}, conflict()
		}
		if prior != nil {
			if !sameIdentity(*prior, release) || !labelEver(*prior, release.DisplayLabel) {
				return Release{}, conflict()
			}
			return original(*prior), nil
		}
		out, e := s.Register(ctx, scope, release, revision, commandID)
		var fault *model.Fault
		if e != nil && errors.As(e, &fault) && fault.Code == model.Conflict {
			continue // a revision-only race (or a semantic one the next read turns into the answer above)
		}
		return out, e
	}
	return Release{}, conflict()
}

// labelEver reports whether the label is the one the release was first registered with (the original receipt's).
func labelEver(stored Release, label string) bool {
	if len(stored.History) == 0 {
		return stored.DisplayLabel == label
	}
	return stored.History[0].DisplayLabel == label
}
