// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	"github.com/arynyklas/soundpost/internal/storage"
)

// The 90-day lifecycle journal (the retained error occurrences the issue
// lifecycle consumes) must never lose unprocessed evidence silently. This
// producer is the scheduler that makes the loss explicit BEFORE it can happen:
//
//	plan      the storage engine lists the error occurrences whose receipt deadline
//	          falls inside the reach (read only, cached for PlanEvery)
//	trigger   an unprocessed occurrence (above its group's issue checkpoint) expires
//	          within Lead
//	declare   issues.RecordGap commits a durable gap and advances the checkpoint over
//	          exactly the contiguous unprocessed run that is expiring, in one control
//	          transaction; the issue health of the project then reads incomplete
//	hold      if the gap cannot commit, the journal is HELD: the retention worker
//	          keeps what no gap covers, and admissions of error evidence are accepted
//	          only while the reserve lasts (storage.HoldJournal), then rejected with a
//	          retryable journal_reserve fault instead of discarding anything
//
// It is leader-only like every Producer, idempotent (the gap ID derives from the
// interval) and bounded (one gap per data group per pass). A gap covers every
// unprocessed entry expiring within Lead+Lead (the reach), so a stalled pipeline
// costs about one gap per group per Lead, far below the book's gap capacity.

// JournalExpiryConfig tunes the journal-expiry producer; zero values are the
// defaults.
type JournalExpiryConfig struct {
	// Lead is how long before its receipt deadline unprocessed evidence triggers a
	// gap (default 24h).
	Lead time.Duration
	// PlanEvery is the minimum age of the cached expiry plan (default 15m): listing
	// the expiring evidence reads the retained commands.
	PlanEvery time.Duration
	// ReserveBytes is the canonical batch bytes a held journal may still grow by
	// (default 64 MiB).
	ReserveBytes uint64
	// Clock stamps the gap; default the system clock.
	Clock WorkerClock
}

const (
	defaultJournalLead      = 24 * time.Hour
	defaultJournalPlanEvery = 15 * time.Minute
	defaultJournalReserve   = 64 << 20
	gapReasonExpiry         = "unprocessed_expiry"
)

// JournalExpiryProducer is the journal-expiry scheduler with the default
// configuration.
func (a *App) JournalExpiryProducer() Producer {
	return a.JournalExpiryProducerWith(JournalExpiryConfig{})
}

// JournalExpiryProducerWith is JournalExpiryProducer with an explicit
// configuration.
func (a *App) JournalExpiryProducerWith(cfg JournalExpiryConfig) Producer {
	if cfg.Lead <= 0 {
		cfg.Lead = defaultJournalLead
	}
	if cfg.PlanEvery <= 0 {
		cfg.PlanEvery = defaultJournalPlanEvery
	}
	if cfg.ReserveBytes == 0 {
		cfg.ReserveBytes = defaultJournalReserve
	}
	if cfg.Clock == nil {
		cfg.Clock = systemWorkerClock{}
	}
	return &journalExpiryProducer{app: a, cfg: cfg}
}

type journalProject struct{ org, project model.ID }

type journalExpiryProducer struct {
	app *App
	cfg JournalExpiryConfig

	mu      sync.Mutex
	planned time.Time
	plan    map[journalProject][]storage.ExpiringEntry
}

// expiring returns the cached plan, refreshed when older than PlanEvery. The
// plan lists everything expiring within twice the Lead as of the instant it was
// made.
func (p *journalExpiryProducer) expiring(ctx context.Context, now model.UnixNano) (map[journalProject][]storage.ExpiringEntry, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := time.Unix(0, int64(now))
	if p.plan != nil && !at.Before(p.planned) && at.Sub(p.planned) < p.cfg.PlanEvery {
		return p.plan, nil
	}
	entries, err := p.app.Storage.ExpiringErrorEvidence(ctx, now+model.UnixNano(2*p.cfg.Lead))
	if err != nil {
		return nil, err
	}
	plan := map[journalProject][]storage.ExpiringEntry{}
	for _, e := range entries {
		k := journalProject{e.Org, e.Project}
		plan[k] = append(plan[k], e)
	}
	p.plan, p.planned = plan, at
	return plan, nil
}

// gapID is the deterministic identity of the gap over one interval of one data
// group, so a repeated pass proposes the very same gap.
func gapID(org, project, group model.ID, after, through model.Uint64) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.issue.gap.v1"))
	h.Write(org[:])
	h.Write(project[:])
	h.Write(group[:])
	var n [16]byte
	binary.BigEndian.PutUint64(n[:8], uint64(after))
	binary.BigEndian.PutUint64(n[8:], uint64(through))
	h.Write(n[:])
	var id model.ID
	copy(id[:], h.Sum(nil))
	return id
}

type journalEntry struct{ at model.UnixNano }

// unprocessed is the part of the project's expiring plan that no checkpoint or
// gap covers yet, per data group, and whether any of it expires inside the Lead
// (the trigger). It is a pure function of the plan and the issue book, so a
// node that just became leader derives the same answer as the one it replaced.
func (p *journalExpiryProducer) unprocessed(mine []storage.ExpiringEntry, state issues.State, now model.UnixNano) (map[model.ID]map[model.Uint64]journalEntry, bool) {
	expiring := map[model.ID]map[model.Uint64]journalEntry{}
	trigger := false
	for _, e := range mine {
		if e.Cursor.Index <= state.Checkpoints[e.Cursor.Group] {
			continue // processed (or already covered by a gap)
		}
		if expiring[e.Cursor.Group] == nil {
			expiring[e.Cursor.Group] = map[model.Uint64]journalEntry{}
		}
		if prior, ok := expiring[e.Cursor.Group][e.Cursor.Index]; !ok || e.At < prior.at {
			expiring[e.Cursor.Group][e.Cursor.Index] = journalEntry{at: e.At}
		}
		if e.Deadline <= now+model.UnixNano(p.cfg.Lead) {
			trigger = true
		}
	}
	return expiring, trigger
}

// Acquired re-derives the journal holds when this node becomes the leader (or
// the process restarts). The hold is in-memory state of the node's storage
// engine, so a new leader starts without it; the hold is nevertheless a pure
// function of replicated state, namely error evidence expiring inside the Lead
// that no gap or checkpoint covers. Holding it here closes the window until the
// project's first Produce pass (which releases the hold again once its gap
// commits, or finds nothing left to protect).
func (p *journalExpiryProducer) Acquired(ctx context.Context, lease replica.FenceToken) error {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return err
	}
	p.mu.Lock()
	p.plan = nil // a fresh plan: the cache of the previous leadership is not evidence
	p.mu.Unlock()
	now := p.cfg.Clock.Now()
	plan, err := p.expiring(ctx, now)
	if err != nil {
		return err
	}
	var failures []error
	for key, mine := range plan {
		scopes := ProducerScopes{authority: p.app.Auth, org: key.org, project: key.project}
		write, err := scopes.Scope(ctx, auth.IssuesWrite)
		if err == nil {
			var store *issues.ControlStore
			var state issues.State
			if _, store, err = (&issueProducer{app: p.app, clock: p.cfg.Clock}).service(lease); err == nil {
				state, err = store.Load(ctx, write, key.project)
			}
			if err == nil {
				if _, trigger := p.unprocessed(mine, state, now); trigger {
					p.app.Storage.HoldJournal(key.org, key.project, p.cfg.ReserveBytes)
				}
				continue
			}
		}
		if code(err) == string(model.NotFound) || code(err) == string(model.Forbidden) {
			continue // the organization or project ended; nothing to protect
		}
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}

func (p *journalExpiryProducer) Produce(ctx context.Context, scopes ProducerScopes, lease replica.FenceToken) (int, error) {
	if err := p.app.leaseGate(ctx, lease); err != nil {
		return 0, err
	}
	now := p.cfg.Clock.Now()
	plan, err := p.expiring(ctx, now)
	if err != nil {
		return 0, err
	}
	org, project := scopes.Org(), scopes.Project()
	mine := plan[journalProject{org, project}]
	if len(mine) == 0 {
		p.app.Storage.ReleaseJournal(org, project)
		return 0, nil
	}
	write, err := scopes.Scope(ctx, auth.IssuesWrite)
	if err != nil {
		return 0, err
	}
	producer := &issueProducer{app: p.app, clock: p.cfg.Clock}
	svc, store, err := producer.service(lease)
	if err != nil {
		return 0, err
	}
	state, err := store.Load(ctx, write, project)
	if err != nil {
		return 0, err
	}
	expiring, trigger := p.unprocessed(mine, state, now)
	if len(expiring) == 0 {
		p.app.Storage.ReleaseJournal(org, project)
		return 0, nil
	}
	if !trigger {
		return 0, nil
	}
	read, err := scopes.Scope(ctx, auth.Read)
	if err != nil {
		return 0, err
	}
	backlog, err := producer.scan(ctx, read, scopes, state)
	if err != nil {
		return 0, err
	}
	groups := make([]model.ID, 0, len(expiring))
	for g := range expiring {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return bytes.Compare(groups[i][:], groups[j][:]) < 0 })
	var failures []error
	committed := 0
	for _, group := range groups {
		b := backlog[group]
		if b == nil {
			continue
		}
		b.sort()
		after := state.Checkpoints[group]
		var through, count model.Uint64
		var start, end model.UnixNano
		// The contiguous unprocessed run that is all expiring: stop at the first
		// unprocessed cursor that is not (it still has time), and never claim the
		// highest cursor of a trimmed scan (it may be incomplete).
		for i := 0; i < len(b.rows); {
			idx := b.rows[i].index
			j := i
			for j < len(b.rows) && b.rows[j].index == idx {
				j++
			}
			e, ok := expiring[group][idx]
			if !ok || b.trimmed && j == len(b.rows) {
				break
			}
			through, count = idx, count+1
			if start == 0 || e.at < start {
				start = e.at
			}
			end = max(end, e.at)
			i = j
		}
		if through == 0 {
			continue
		}
		if start <= 0 {
			start, end = 1, max(end, 1)
		}
		gap := model.EvidenceGap{ID: gapID(org, project, group, after, through), Org: org, Project: project, Group: group, After: after, Through: through, Count: count,
			Start: start, End: end, Signals: []model.Kind{model.ErrorKind}, Reason: gapReasonExpiry, RecordedAt: now}
		if err := svc.RecordGap(ctx, write, gap); err != nil {
			failures = append(failures, err)
			continue
		}
		committed++
	}
	if len(failures) > 0 {
		// The gap could not commit: the journal keeps the evidence (the retention
		// worker erases nothing a gap does not cover) and its growth is bounded by
		// the reserve.
		p.app.Storage.HoldJournal(org, project, p.cfg.ReserveBytes)
		return committed, errors.Join(failures...)
	}
	p.app.Storage.ReleaseJournal(org, project)
	return committed, nil
}
