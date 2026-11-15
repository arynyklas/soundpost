// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/jobs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/storage"
)

// The job producer folds the job_attempt records the product ingested into the
// job books the job routes read. Its source of truth is the data-plane journal
// (storage scan of one project's job_attempt rows under the runner's read scope);
// its effect is jobs.Service.ApplyAttempt under the runner's policy.write scope.
//
// Idempotency lives in the effect, not in the producer: the job command ID is
// derived from the record's origin (group, index, record ID) and the reducer
// dedups an event by (epoch, sequence), so applying a row any number of times,
// after any crash, commits it at most once and reports jobs.Duplicate afterwards.
// The producer's position is therefore only an optimization of what to read.
//
// The position is a per-group origin cursor, "through": every row of the project's
// job_attempt journal whose origin index in its group is at or below it has been
// applied (or refused for good). A pass reads only above it (storage.ScanRequest.After
// skips the rest at the index, without reading a page) and a row that reaches the
// journal late, however far behind the newest event time its stamp is, has a higher
// origin index than anything covered and is therefore read by the very next pass: there
// is no sweep with a rest and no lookback window.
//
// Reading is organised in epochs. An epoch starts when the journal's watermark of
// some group is above through; it fixes those watermarks, reads the rows above through
// in scan order (observed time) in bounded chunks over as many passes as it takes, and
// when it reaches the end of the journal, through moves to the fixed watermarks. Rows
// that arrive during an epoch have an index above them and belong to the next epoch.
// A call reads at most bound rows in total. A row the reducer rejects for good
// (invalid, contradicting committed evidence, over a quota) is skipped; any other
// failure ends the call with the row not covered.
//
// The position is kept in memory: a restart reads from the start of the journal
// through duplicates and never skips a row.
//
// The producer is also the observer of the jobs an administrator defined in the job
// schedule-definition catalogue (jobs.Catalogue, POST /api/v1/jobs/definitions): after the
// journal is read it feeds jobs.Service.ObserveSchedule for every active entry, carrying
// the definition, under the runner's policy.write scope and a fixed observer identity, at
// most once per quarter of the definition's observer staleness bound. What the observation
// attests is deliberately narrow: Healthy says this pass completed, and CompleteThrough is
// the least, over the sources that delivered the job's events, of the newest event time each has
// delivered (as of a read that reached the journal's end), less the late-arrival allowance
// jobLookback. A source that falls silent stops advancing the attestation of its own jobs, so its
// silence is never read as a missed run; a job whose runs stop while its source keeps delivering
// other events is attested through those events, and its missed occurrences are declared.

const (
	defaultJobProducerBound = 256
	// jobLookback is the allowance for evidence delivered after an event of a later time: what a
	// complete read attests is the newest event time minus this.
	jobLookback = 15 * time.Minute
)

// jobCatalogueObserver is the identity every catalogue observation carries. It is not a
// principal: it names the observer in the job state, apart from any external observer.
var jobCatalogueObserver = model.ID{'s', 'p', '.', 'j', 'o', 'b', 's', '.', 'c', 'a', 't', 'a', 'l', 'o', 'g', '.'}

// rowKey is the scan order of a journal row: observed time, record ID, origin.
type rowKey struct {
	set   bool
	at    model.UnixNano
	id    model.ID
	group model.ID
	index model.Uint64
}

// after reports whether k sorts strictly after o. An unset o precedes every row.
func (k rowKey) after(o rowKey) bool {
	if !o.set {
		return true
	}
	if k.at != o.at {
		return k.at > o.at
	}
	if c := bytes.Compare(k.id[:], o.id[:]); c != 0 {
		return c > 0
	}
	if c := bytes.Compare(k.group[:], o.group[:]); c != 0 {
		return c > 0
	}
	return k.index > o.index
}

func (k rowKey) start() model.UnixNano {
	if !k.set {
		return math.MinInt64
	}
	return k.at
}

// jobPositions is the position of one project: through is the committed
// per-group frontier, epoch the read in progress (nil between epochs).
type jobPositions struct {
	through map[model.ID]model.Uint64
	epoch   *jobEpoch
	// newest is, per source, the newest event time of the rows covered by reads that
	// reached the journal's end, and sources the sources each job's rows came from;
	// observed remembers when each catalogue job was last observed. synced is set once a
	// pass found the journal read to its end (a restart starts unsynced, and observes
	// nothing until it is: an observation made before the journal is re-read would claim less
	// than the one before the restart).
	newest   map[model.ID]model.UnixNano
	sources  map[model.ID]map[model.ID]struct{}
	observed map[model.ID]model.UnixNano
	synced   bool
}

// jobEpoch is one read of the rows above through: marks are the watermarks it
// fixed when it started and from is the scan-order position it has reached.
type jobEpoch struct {
	marks   []model.Cursor
	from    rowKey
	newest  map[model.ID]model.UnixNano
	sources map[model.ID]map[model.ID]struct{}
}

type jobProducer struct {
	app   *App
	bound int

	mu  sync.Mutex
	pos map[[2]model.ID]*jobPositions
}

func newJobProducer(a *App, bound int) *jobProducer {
	return &jobProducer{app: a, bound: bound, pos: map[[2]model.ID]*jobPositions{}}
}

// JobProducer is the runner's job stage: it applies the project's ingested
// job_attempt evidence to the job books (see jobs.Service.ApplyAttempt).
func (a *App) JobProducer() Producer { return newJobProducer(a, defaultJobProducerBound) }

// Produce applies the next bounded chunk of the project's job evidence.
func (p *jobProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	group := p.app.Control.ReplicaGroup()
	if group == nil {
		return 0, model.Fail(model.Unavailable)
	}
	if err := group.ValidateFence(ctx, lease); err != nil {
		return 0, err
	}
	read, err := scopes.Scope(ctx, auth.Read)
	if err != nil {
		return 0, err
	}
	write, err := scopes.Scope(ctx, auth.PolicyWrite)
	if err != nil {
		return 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	key := [2]model.ID{scopes.Org(), scopes.Project()}
	pos := p.pos[key]
	if pos == nil {
		pos = &jobPositions{through: map[model.ID]model.Uint64{}, newest: map[model.ID]model.UnixNano{}, sources: map[model.ID]map[model.ID]struct{}{}, observed: map[model.ID]model.UnixNano{}}
		p.pos[key] = pos
	}
	run := jobRun{p: p, group: group, lease: lease, read: read, write: write, project: scopes.Project(), budget: p.bound, newest: map[model.ID]model.UnixNano{}, sources: map[model.ID]map[model.ID]struct{}{}}
	if err = run.epoch(ctx, pos); err != nil {
		return run.committed, err
	}
	pos.synced = pos.synced || pos.epoch == nil
	if !pos.synced {
		return run.committed, nil
	}
	n, err := p.observe(ctx, scopes, read, write, pos)
	return run.committed + n, err
}

// observe feeds the schedule observations of the catalogue's active jobs (see the file comment).
func (p *jobProducer) observe(ctx context.Context, scopes ProducerScopes, read, write auth.Scope, pos *jobPositions) (int, error) {
	catalogue, err := p.app.JobCatalogue()
	if err != nil {
		return 0, err
	}
	entries, err := catalogue.List(ctx, read, scopes.Project())
	if err != nil {
		return 0, err
	}
	now := scopes.Now()
	committed := 0
	for _, entry := range entries {
		if entry.Retired {
			delete(pos.observed, entry.Job)
			continue
		}
		every := entry.Definition.ObserverStaleAfter
		if every <= 0 {
			every = jobs.Duration(jobs.DefaultObserverStaleAfter)
		}
		if last, ok := pos.observed[entry.Job]; ok && now-last < model.UnixNano(every)/4 && now >= last {
			continue
		}
		definition := entry.Definition
		completeThrough := pos.completeThrough(entry.Job, now)
		_, err = p.app.Jobs.ObserveSchedule(ctx, write, jobs.ScheduleEvidence{CommandID: model.NewID(), Project: scopes.Project(), Job: entry.Job, Observer: jobCatalogueObserver,
			ObservedAt: now, CompleteThrough: completeThrough, Healthy: true, Definition: &definition})
		if err != nil {
			if rejectedForGood(err) {
				pos.observed[entry.Job] = now // a definition the reducer refuses for good is retried on the cadence, not every pass
				continue
			}
			return committed, err
		}
		pos.observed[entry.Job] = now
		committed++
	}
	return committed, nil
}

type jobRun struct {
	p         *jobProducer
	group     LeaderFence
	lease     replica.FenceToken
	read      auth.Scope
	write     auth.Scope
	project   model.ID
	budget    int
	committed int
	newest    map[model.ID]model.UnixNano
	sources   map[model.ID]map[model.ID]struct{}
}

// epoch reads the rows above the project's through frontier, starting an epoch
// when the journal has moved past it and finishing it when its end is reached.
func (r *jobRun) epoch(ctx context.Context, pos *jobPositions) error {
	after := make([]model.Cursor, 0, len(pos.through))
	for g, i := range pos.through {
		after = append(after, model.Cursor{Group: g, Index: i})
	}
	from := rowKey{}
	if pos.epoch != nil {
		from = pos.epoch.from
	}
	it, err := r.p.app.Storage.Scan(ctx, r.read, storage.ScanRequest{Projects: []model.ID{r.project}, Signal: model.JobAttempt, Start: from.start(), End: math.MaxInt64, After: after})
	if err != nil {
		return err
	}
	defer it.Close()
	if pos.epoch == nil {
		marks := it.Watermarks()
		if marks == nil || !movedPast(marks, pos.through) {
			return nil
		}
		pos.epoch = &jobEpoch{marks: marks, newest: map[model.ID]model.UnixNano{}, sources: map[model.ID]map[model.ID]struct{}{}}
	}
	end, err := r.drain(ctx, it, &pos.epoch.from)
	mergeNewest(pos.epoch.newest, r.newest)
	mergeSources(pos.epoch.sources, r.sources)
	if err != nil || !end {
		return err
	}
	mergeNewest(pos.newest, pos.epoch.newest)
	mergeSources(pos.sources, pos.epoch.sources)
	for _, m := range pos.epoch.marks {
		if m.Index > pos.through[m.Group] {
			pos.through[m.Group] = m.Index
		}
	}
	pos.epoch = nil
	return nil
}

// completeThrough is what the product's journal attests for one job: the least, over the
// sources that delivered the job's events, of the newest event time each has delivered,
// less the late-arrival allowance (and never after now). A job no source has delivered
// an event for is attested through nothing; a source that falls silent holds back its own
// jobs only.
func (pos *jobPositions) completeThrough(job model.ID, now model.UnixNano) model.UnixNano {
	sources := pos.sources[job]
	if len(sources) == 0 {
		return 0
	}
	through := now
	for source := range sources {
		through = min(through, pos.newest[source])
	}
	return max(through-model.UnixNano(jobLookback), 0)
}

// note records that a row of job came from source at event time at.
func (r *jobRun) note(job, source model.ID, at model.UnixNano) {
	r.newest[source] = max(r.newest[source], at)
	if r.sources[job] == nil {
		r.sources[job] = map[model.ID]struct{}{}
	}
	r.sources[job][source] = struct{}{}
}

func mergeNewest(into, from map[model.ID]model.UnixNano) {
	for source, at := range from {
		into[source] = max(into[source], at)
	}
}

func mergeSources(into, from map[model.ID]map[model.ID]struct{}) {
	for job, sources := range from {
		if into[job] == nil {
			into[job] = map[model.ID]struct{}{}
		}
		for source := range sources {
			into[job][source] = struct{}{}
		}
	}
}

// movedPast reports whether some group's watermark is above its through frontier.
func movedPast(marks []model.Cursor, through map[model.ID]model.Uint64) bool {
	for _, m := range marks {
		if m.Index > through[m.Group] {
			return true
		}
	}
	return false
}

// drain covers the rows of it after *from in scan order, advancing *from past each
// row it covers, until the journal ends or the call's budget is spent. It reports
// whether it reached the end of the journal.
func (r *jobRun) drain(ctx context.Context, it storage.RowIterator, from *rowKey) (bool, error) {
	for {
		page, err := it.Next(ctx)
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		if err = r.group.ValidateFence(ctx, r.lease); err != nil {
			return false, err
		}
		for i := range page.Len() {
			row := rowKey{set: true, at: page.Times[i], id: page.IDs[i], group: page.Origins[i].Group, index: page.Origins[i].Index}
			if !row.after(*from) {
				continue
			}
			if r.budget == 0 {
				return false, nil
			}
			event := page.Values[i].Job
			if event == nil {
				return false, model.Fail(model.Corrupt)
			}
			_, outcome, err := r.p.app.Jobs.ApplyAttempt(ctx, r.write, jobs.AttemptEvidence{Project: r.project, Cursor: page.Origins[i], Record: page.IDs[i], Event: *event})
			if err != nil && !rejectedForGood(err) {
				return false, err
			}
			if err == nil && outcome == jobs.Applied {
				r.committed++
			}
			*from = row
			r.note(event.Job, page.Sources[i], page.Times[i])
			r.budget--
		}
	}
}

// rejectedForGood reports a reducer verdict that repeating cannot change: the
// event is invalid, contradicts committed evidence, or exceeds a bound of the
// job state. Everything else (unavailable, deposed, forbidden, cancelled,
// corrupt) must stop the call so the row is retried.
func rejectedForGood(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && (fault.Code == model.Invalid || fault.Code == model.Conflict || fault.Code == model.Quota)
}
