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

	"soundpost/internal/auth"
	"soundpost/internal/jobs"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/storage"
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
// The producer's own position is therefore only an optimization of where to
// read next. It is kept in memory: a restart re-reads from the start of the
// journal through duplicates and never skips a row.
//
// Rows are read in the scan's order (observed time, record ID, origin). Two
// positions per project serve different needs:
//
//   - the tail, the last row covered in scan order, is where every pass starts
//     reading, so fresh evidence is applied promptly;
//   - the sweep walks the journal from its start up to the tail, a bounded chunk
//     per pass, so a row that reached the journal behind the tail (a retried old
//     event, a producer with a slow clock) is still found. When it reaches the
//     tail it rests for sweepRest before starting over.
//
// A call reads at most bound rows in total. A row the reducer rejects for good
// (invalid, contradicting committed evidence, over a quota) is skipped; any other
// failure ends the call with the row not covered.

const (
	defaultJobProducerBound = 256
	defaultJobSweepRest     = 5 * time.Minute
)

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

type jobPositions struct {
	tail, sweep rowKey
	restUntil   time.Time
}

type jobProducer struct {
	app   *App
	bound int
	rest  time.Duration
	now   func() time.Time

	mu  sync.Mutex
	pos map[[2]model.ID]*jobPositions
}

func newJobProducer(a *App, bound int) *jobProducer {
	return &jobProducer{app: a, bound: bound, rest: defaultJobSweepRest, now: time.Now, pos: map[[2]model.ID]*jobPositions{}}
}

// JobProducer is the runner's job stage: it applies the project's ingested
// job_attempt evidence to the job books (see jobs.Service.ApplyAttempt). It
// observes no schedule: there is no committed source of schedule definitions
// (docs/user/jobs.md), so schedule health stays with the external observer.
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
		pos = &jobPositions{}
		p.pos[key] = pos
	}
	run := jobRun{p: p, group: group, lease: lease, read: read, write: write, project: scopes.Project(), budget: p.bound}
	end, err := run.drain(ctx, &pos.tail, rowKey{}, false)
	if err != nil {
		return run.committed, err
	}
	if end && run.budget > 0 && pos.tail.set && !p.now().Before(pos.restUntil) {
		swept, err := run.drain(ctx, &pos.sweep, pos.tail, true)
		if err != nil {
			return run.committed, err
		}
		if swept {
			pos.sweep = rowKey{}
			pos.restUntil = p.now().Add(p.rest)
		}
	}
	return run.committed, nil
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
}

// drain covers rows after *from in scan order, advancing *from past each row it
// covers, until the journal (or, when bounded, the row `until`) ends or the
// call's budget is spent. It reports whether it reached that end.
func (r *jobRun) drain(ctx context.Context, from *rowKey, until rowKey, bounded bool) (bool, error) {
	it, err := r.p.app.Storage.Scan(ctx, r.read, storage.ScanRequest{Projects: []model.ID{r.project}, Signal: model.JobAttempt, Start: from.start(), End: math.MaxInt64})
	if err != nil {
		return false, err
	}
	defer it.Close()
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
			if bounded && row.after(until) {
				return true, nil
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
