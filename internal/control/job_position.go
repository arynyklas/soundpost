// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the durable resume position of the job producer (plan 11.01-W4):
// per data group, the origin index of the project's job_attempt journal through
// which every row has been applied or refused for good. It is one more kind of
// the existing KindUpdateJob command (JobKindAdvance), written only by the
// runner's system scope, and a position only ever moves forward: an entry below
// the committed one is ignored and a command that moves nothing is "unchanged".
// The position is an optimization of what to read; the job reducer's own
// exactly-once keeps a lost or stale position harmless.

// JobKindAdvance is the kind of the command that advances a project's position.
const JobKindAdvance = "advance_through"

// MaxJobPositionGroups bounds the data groups one position names.
const MaxJobPositionGroups = 1024

// JobPositionApply is the closed arm of JobKindAdvance: the entries to raise.
type JobPositionApply struct {
	Project model.ID       `json:"project"`
	Through []model.Cursor `json:"through"`
	At      model.UnixNano `json:"at_ns"`
}

// JobPositionRecord is the committed position of one project.
type JobPositionRecord struct {
	Org       model.ID       `json:"org"`
	Project   model.ID       `json:"project"`
	Through   []model.Cursor `json:"through"`
	UpdatedNS model.UnixNano `json:"updated_ns"`
}

func jobPositionKey(org, project model.ID) string { return org.String() + ":" + project.String() }

func loadJobPosition(st *State, key string) (JobPositionRecord, bool, error) {
	raw, ok := st.JobPositions[key]
	if !ok {
		return JobPositionRecord{}, false, nil
	}
	var rec JobPositionRecord
	if json.Unmarshal(raw, &rec) != nil || jobPositionKey(rec.Org, rec.Project) != key {
		return JobPositionRecord{}, false, model.Fail(model.Corrupt)
	}
	return rec, true, nil
}

func applyJobPosition(scope auth.Scope, st *State, c JobUpdateCommand) (model.ID, model.Revision, string, error) {
	fail := func(err error) (model.ID, model.Revision, string, error) { return model.ID{}, 0, "", err }
	if !scope.IsSystem() {
		return fail(model.Fail(model.Forbidden))
	}
	p := c.Position
	if p == nil || (len(c.State) != 0 && string(c.State) != "null") || c.Origin != nil || c.Audit != nil || c.Definition != nil || c.InputDigest != (model.Hash{}) || c.ExpectedVersion != 0 || c.NewVersion != 0 ||
		p.Project != c.Project || c.Job != c.Project || p.Project == (model.ID{}) || p.At <= 0 || len(p.Through) == 0 || len(p.Through) > MaxJobPositionGroups {
		return fail(model.Fail(model.Invalid))
	}
	org := scope.OrgID()
	key := jobPositionKey(org, p.Project)
	rec, _, err := loadJobPosition(st, key)
	if err != nil {
		return fail(err)
	}
	merged := make(map[model.ID]model.Uint64, len(rec.Through)+len(p.Through))
	for _, e := range rec.Through {
		merged[e.Group] = e.Index
	}
	changed := false
	seen := make(map[model.ID]struct{}, len(p.Through))
	for _, e := range p.Through {
		if _, dup := seen[e.Group]; dup || e.Group == (model.ID{}) {
			return fail(model.Fail(model.Invalid))
		}
		seen[e.Group] = struct{}{}
		if cur, ok := merged[e.Group]; !ok || e.Index > cur {
			merged[e.Group], changed = e.Index, true
		}
	}
	if len(merged) > MaxJobPositionGroups {
		return fail(model.Fail(model.Quota))
	}
	if !changed {
		return c.Project, 0, "unchanged", nil
	}
	out := JobPositionRecord{Org: org, Project: p.Project, Through: make([]model.Cursor, 0, len(merged)), UpdatedNS: p.At}
	for g, i := range merged {
		out.Through = append(out.Through, model.Cursor{Group: g, Index: i})
	}
	sort.Slice(out.Through, func(i, j int) bool { return out.Through[i].Group.String() < out.Through[j].Group.String() })
	raw, err := json.Marshal(out)
	if err != nil {
		return fail(model.Fail(model.Invalid))
	}
	if st.JobPositions == nil {
		st.JobPositions = map[string]json.RawMessage{}
	}
	st.JobPositions[key] = raw
	return c.Project, 0, "advanced", nil
}

// JobPosition reads the project's committed position (empty before the first
// advance) through a linearizable control read, to a scope that may read the
// project's job facts.
func (s *Store) JobPosition(ctx context.Context, scope auth.Scope, project model.ID) (out []model.Cursor, err error) {
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		rec, _, e := loadJobPosition(&st, jobPositionKey(scope.OrgID(), project))
		out = rec.Through
		return e
	})
	return
}

// eraseJobPositions drops the positions of the projects a deletion retires. It
// is idempotent.
func eraseJobPositions(st *State, p model.DeletePredicate) (dropped int, err error) {
	for key := range st.JobPositions {
		a, b, cut := strings.Cut(key, ":")
		org, e1 := model.ParseID(a)
		project, e2 := model.ParseID(b)
		if !cut || e1 != nil || e2 != nil || !p.RetiresProject(org, project) {
			continue
		}
		delete(st.JobPositions, key)
		dropped++
	}
	return dropped, nil
}
