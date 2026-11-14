// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package jobs

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// MaxListPage bounds one project listing.
const MaxListPage = control.MaxJobPage

// Book is one committed job as a read store answers it.
type Book struct {
	Job     model.ID
	Version model.Revision
	Erased  bool
	State   JobState
	Origin  *model.Cursor
}

// BookPage is one ordered page of a project's books.
type BookPage struct {
	Books []Book
	More  bool
}

// Reader is the optional read extension of Store.
type Reader interface {
	Book(ctx context.Context, scope auth.Scope, project, job model.ID) (Book, bool, error)
	Books(ctx context.Context, scope auth.Scope, project, after model.ID, limit int) (BookPage, error)
}

// ReadControl is what the control authority offers the read extension.
type ReadControl interface {
	JobBooks(ctx context.Context, scope auth.Scope, project, after model.ID, limit int) (control.JobPage, error)
	JobDetail(ctx context.Context, scope auth.Scope, project, job model.ID) (control.JobEntry, bool, error)
}

var _ Reader = (*ControlStore)(nil)

// bookOf decodes one committed control entry for exactly this scope's
// organization, project and job. An erased book reads as an empty state at the
// preserved version, like Load.
func bookOf(scope auth.Scope, project model.ID, e control.JobEntry) (Book, error) {
	b := Book{Job: e.Job, Version: e.Snapshot.Version, Erased: e.Snapshot.Erased, Origin: e.Origin}
	if e.Snapshot.Erased {
		b.State = JobState{Version: e.Snapshot.Version, Org: scope.OrgID(), Project: project, Job: e.Job}
		return b, nil
	}
	if err := json.Unmarshal(e.Snapshot.State, &b.State); err != nil {
		return Book{}, model.Fail(model.Corrupt)
	}
	if b.State.Org != scope.OrgID() || b.State.Project != project || b.State.Job != e.Job || b.State.Version != e.Snapshot.Version {
		return Book{}, model.Fail(model.Corrupt)
	}
	return b, nil
}

func (s *ControlStore) readControl() (ReadControl, error) {
	rc, ok := s.c.(ReadControl)
	if !ok {
		return nil, model.Fail(model.Unsupported)
	}
	return rc, nil
}

// Book reads one committed job with the origin cursor of its newest attempt.
func (s *ControlStore) Book(ctx context.Context, scope auth.Scope, project, job model.ID) (Book, bool, error) {
	rc, err := s.readControl()
	if err != nil {
		return Book{}, false, err
	}
	entry, found, err := rc.JobDetail(ctx, scope, project, job)
	if err != nil || !found {
		return Book{}, false, err
	}
	b, err := bookOf(scope, project, entry)
	if err != nil {
		return Book{}, false, err
	}
	return b, true, nil
}

// Books lists one project's committed jobs in job ID order, strictly after the
// given ID, at most limit at a time.
func (s *ControlStore) Books(ctx context.Context, scope auth.Scope, project, after model.ID, limit int) (BookPage, error) {
	rc, err := s.readControl()
	if err != nil {
		return BookPage{}, err
	}
	page, err := rc.JobBooks(ctx, scope, project, after, limit)
	if err != nil {
		return BookPage{}, err
	}
	out := BookPage{More: page.More, Books: make([]Book, 0, len(page.Entries))}
	for _, entry := range page.Entries {
		b, err := bookOf(scope, project, entry)
		if err != nil {
			return BookPage{}, err
		}
		out.Books = append(out.Books, b)
	}
	return out, nil
}

// Summary is one job of a listing: its definition and the verdict the reducer
// derives for it now, never a verdict computed elsewhere.
type Summary struct {
	Job        model.ID
	Version    model.Revision
	Erased     bool
	Definition Definition
	Health     Health
	Runs       int
	Attempts   int
}

// ListPage is one ordered page of a project's jobs. More reports that jobs
// follow the last one listed.
type ListPage struct {
	EvaluatedAt model.UnixNano
	Jobs        []Summary
	More        bool
}

// View is the full read of one job: the same report Health answers, plus the
// origin cursor of the newest committed attempt evidence (nil when the job has
// none) and whether a deletion erased its history.
type View struct {
	Report Report
	Origin *model.Cursor
	Erased bool
}

// gapIntervals turns the project's committed evidence gaps that cover job
// attempts into incomplete intervals, like Health.
func gapIntervals(scope auth.Scope, project model.ID, gaps []model.EvidenceGap) []Interval {
	var extra []Interval
	for _, gap := range gaps {
		if gap.Org != scope.OrgID() || gap.Project != project || !coversJobs(gap.Signals) {
			continue
		}
		start := gap.Start
		if gap.End <= start {
			start = gap.End - 1
		}
		extra = append(extra, Interval{ID: gap.ID, Start: start, End: gap.End, Reason: "evidence_expired"})
	}
	return extra
}

func (s *Service) reader() (Reader, error) {
	r, ok := s.store.(Reader)
	if !ok {
		return nil, model.Fail(model.Unsupported)
	}
	return r, nil
}

// List answers one page of a project's jobs (telemetry.read on the project),
// in ascending job ID order strictly after `after` (the zero ID starts at the
// beginning), 1..MaxListPage at a time. The scope is checked first; a project
// outside the scope is NotFound exactly like a missing one, and a store that
// cannot enumerate is the typed Unsupported fault.
func (s *Service) List(ctx context.Context, scope auth.Scope, project, after model.ID, limit int) (ListPage, error) {
	if err := s.authorize(ctx, scope, auth.Read, project); err != nil {
		return ListPage{}, err
	}
	if limit < 1 || limit > MaxListPage {
		return ListPage{}, model.Fail(model.Invalid)
	}
	reader, err := s.reader()
	if err != nil {
		return ListPage{}, err
	}
	page, err := reader.Books(ctx, scope, project, after, limit)
	if err != nil {
		return ListPage{}, err
	}
	gaps, err := s.store.Gaps(ctx, scope, project)
	if err != nil {
		return ListPage{}, err
	}
	extra := gapIntervals(scope, project, gaps)
	now := s.clock.Now()
	out := ListPage{EvaluatedAt: now, More: page.More, Jobs: make([]Summary, 0, len(page.Books))}
	for _, b := range page.Books {
		st := b.State
		out.Jobs = append(out.Jobs, Summary{Job: b.Job, Version: st.Version, Erased: b.Erased, Definition: st.Definition, Health: Evaluate(st, now, extra...), Runs: len(st.Runs), Attempts: len(st.Attempts)})
	}
	return out, nil
}

// View reads one job (telemetry.read on the project): its health re-derived
// with the service clock, runs and attempts, and the committed source cursor.
// A job with no committed state, a project outside the scope and a foreign
// organization are the same NotFound.
func (s *Service) View(ctx context.Context, scope auth.Scope, project, job model.ID) (View, error) {
	if err := s.authorize(ctx, scope, auth.Read, project); err != nil {
		return View{}, err
	}
	if job == (model.ID{}) {
		return View{}, model.Fail(model.Invalid)
	}
	reader, err := s.reader()
	if err != nil {
		return View{}, err
	}
	book, found, err := reader.Book(ctx, scope, project, job)
	if err != nil {
		return View{}, err
	}
	st := book.State
	if !found || st.Org != scope.OrgID() || st.Project != project || st.Job != job {
		return View{}, model.Fail(model.NotFound)
	}
	gaps, err := s.store.Gaps(ctx, scope, project)
	if err != nil {
		return View{}, err
	}
	extra := gapIntervals(scope, project, gaps)
	now := s.clock.Now()
	intervals := append(append([]Interval(nil), st.IncompleteIntervals...), extra...)
	return View{Report: Report{Version: st.Version, EvaluatedAt: now, Health: Evaluate(st, now, extra...), Intervals: intervals, State: st}, Origin: book.Origin, Erased: book.Erased}, nil
}

// RunAttempts returns one retained run and its attempts in attempt order
// (ordinal, then first observation). Everything returned is a copy.
func (s JobState) RunAttempts(run model.ID) (Run, []Attempt, bool) {
	r, ok := s.Runs[run]
	if !ok {
		return Run{}, nil, false
	}
	r.Attempts = append([]model.ID(nil), r.Attempts...)
	out := make([]Attempt, 0, len(r.Attempts))
	for _, id := range r.Attempts {
		a, ok := s.Attempts[id]
		if !ok {
			continue
		}
		a.Events = append([]AppliedEvent(nil), a.Events...)
		for i := range a.Events {
			a.Events[i].Terminal = cloneTime(a.Events[i].Terminal)
		}
		a.Corrections = append([]AppliedCorrection(nil), a.Corrections...)
		a.Terminal = cloneTerminal(a.Terminal)
		a.CauseTrace, a.CauseError = cloneRef(a.CauseTrace), cloneRef(a.CauseError)
		out = append(out, a)
	}
	return r, out, true
}

func cloneTerminal(t *TerminalResult) *TerminalResult {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneRef(id *model.ID) *model.ID {
	if id == nil {
		return nil
	}
	v := *id
	return &v
}
