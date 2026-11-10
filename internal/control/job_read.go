// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"

	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// This file is the read half of the committed job books for the investigation
// UI: a deterministic, bounded listing of one project's jobs and a one-job read
// that also names the provenance of the newest attempt evidence. Both are
// linearizable control reads that never mutate state. The scope is checked
// before any book is looked up (a project the scope does not name, a retired or
// missing project and a revoked grant are the same not-found), and a book is
// returned only if its own header names the scope's organization, the project
// and its key.

// MaxJobPage is the largest page JobBooks answers: one project holds at most
// maxJobsPerProject job books.
const MaxJobPage = maxJobsPerProject

// JobEntry is one committed job as a read answers it.
type JobEntry struct {
	Job      model.ID
	Snapshot JobSnapshot
	Origin   *model.Cursor
	Commands int
}

// JobPage is one bounded, ordered page of a project listing.
type JobPage struct {
	Entries []JobEntry
	More    bool
}

// jobEntryOf decodes one committed book into an entry the caller owns.
func jobEntryOf(st *State, org, project, job model.ID) (JobEntry, bool, error) {
	rec, ok, err := loadJobRecord(st, jobKey(org, project, job))
	if err != nil || !ok {
		return JobEntry{}, false, err
	}
	if rec.Org != org || rec.Project != project || rec.Job != job {
		return JobEntry{}, false, model.Fail(model.Corrupt)
	}
	entry := JobEntry{Job: job, Commands: len(rec.Commands), Snapshot: JobSnapshot{Version: rec.Version, Digest: rec.Digest, Erased: stateIsTombstone(rec.State)}}
	if !entry.Snapshot.Erased {
		entry.Snapshot.State = append(json.RawMessage(nil), rec.State...)
	}
	for i := len(rec.Commands) - 1; i >= 0; i-- {
		if c := rec.Commands[i]; c.Kind == jobKindAttempt && c.Origin != nil {
			origin := *c.Origin
			entry.Origin = &origin
			break
		}
	}
	return entry, true, nil
}

// JobBooks lists the jobs of one project in ascending job ID order, strictly
// after the given job ID (the zero ID starts at the beginning), at most limit
// at a time. More reports that further jobs follow the last entry. limit must
// be within 1..MaxJobPage. The scope must be a reading scope (telemetry.read,
// policy.write or org.admin) that names the project.
func (s *Store) JobBooks(ctx context.Context, scope auth.Scope, project, after model.ID, limit int) (out JobPage, err error) {
	if limit < 1 || limit > MaxJobPage {
		return JobPage{}, model.Fail(model.Invalid)
	}
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		org := scope.OrgID()
		prefix := jobProjectPrefix(org, project)
		var ids []model.ID
		for key := range st.JobBooks {
			if !strings.HasPrefix(key, prefix) {
				continue
			}
			id, e := model.ParseID(key[len(prefix):])
			if e != nil {
				return model.Fail(model.Corrupt)
			}
			if bytes.Compare(id[:], after[:]) > 0 {
				ids = append(ids, id)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
		if len(ids) > limit {
			out.More = true
			ids = ids[:limit]
		}
		for _, id := range ids {
			entry, ok, e := jobEntryOf(&st, org, project, id)
			if e != nil {
				return e
			}
			if !ok {
				return model.Fail(model.Corrupt)
			}
			out.Entries = append(out.Entries, entry)
		}
		return nil
	})
	if err != nil {
		return JobPage{}, err
	}
	return out, nil
}

// JobDetail reads one job like JobBook and additionally names the origin cursor
// of the newest attempt command committed for it. A job that does not exist in
// a readable project is found=false.
func (s *Store) JobDetail(ctx context.Context, scope auth.Scope, project, job model.ID) (out JobEntry, found bool, err error) {
	err = s.View(ctx, func(st State) error {
		if e := jobReadScope(scope, &st, project); e != nil {
			return e
		}
		var e error
		out, found, e = jobEntryOf(&st, scope.OrgID(), project, job)
		return e
	})
	if err != nil {
		return JobEntry{}, false, err
	}
	return out, found, nil
}
