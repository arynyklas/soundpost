// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	bolt "go.etcd.io/bbolt"
	"io"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strconv"
)

type committedPage struct {
	ID            model.ID
	Kind, Subject model.Kind
	Restricted    bool
	Source        model.ID
}
type committedEvent struct {
	Org, Project model.ID
	Cursor       model.Cursor
	Pages        []committedPage
	Epoch        uint64
}
type changeIterator struct {
	e                *Engine
	scope            auth.Scope
	req              SubscribeRequest
	matchers         []compiledMatcher
	events           chan committedEvent
	pending          *committedEvent
	offset           int
	marks, delivered []model.Cursor
	gap              *ChangeGap
	page             Page
	closed           bool
	revoked          bool
	terminal         error
	stop             func() bool
	ctx              context.Context
	epoch            uint64
}

func (e *Engine) Subscribe(ctx context.Context, scope auth.Scope, req SubscribeRequest) (ChangeIterator, error) {
	if err := e.authorizeRead(ctx, scope, req.Projects, req.Signal); err != nil {
		return nil, err
	}
	if !req.Signal.Valid() {
		return nil, model.Fail(model.Invalid)
	}
	ms, err := compileMatchers(req.Selectors)
	if err != nil {
		return nil, err
	}
	if _, err = readPrefixes(scope, req.Projects, req.Signal, req.Selectors); err != nil {
		return nil, err
	}
	marks, _, err := e.replicaReadFence(ctx, nil, false)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	if err = e.authorizeRead(ctx, scope, req.Projects, req.Signal); err != nil {
		return nil, err
	}
	if e.storageStats.ActiveIterators >= 32 {
		return nil, model.Fail(model.TooLarge)
	}
	req.Projects = append([]model.ID(nil), req.Projects...)
	req.Selectors = append([]Matcher(nil), req.Selectors...)
	req.After = append([]model.Cursor(nil), req.After...)
	it := &changeIterator{e: e, scope: scope, req: req, matchers: ms, events: make(chan committedEvent, liveCapacity), marks: marks, ctx: ctx}
	it.delivered = append([]model.Cursor(nil), it.marks...)
	if len(req.After) > 0 {
		gap := false
		for _, after := range req.After {
			found := false
			for _, m := range it.marks {
				if m.Group == after.Group {
					if after.Index > m.Index {
						return nil, model.Fail(model.Invalid)
					}
					found = after.Index == m.Index
				}
			}
			if !found {
				gap = true
			}
		}
		if gap {
			it.gap = &ChangeGap{After: append([]model.Cursor(nil), req.After...), Through: append([]model.Cursor(nil), it.marks...), Reason: "catch_up_required"}
		}
	}
	through := append([]model.Cursor(nil), marks...)
	advanced := false
	for i, mark := range through {
		for slot, index := range e.indexes {
			if e.group(uint16(slot)) == mark.Group && index > uint64(mark.Index) {
				through[i].Index = model.Uint64(index)
				advanced = true
			}
		}
	}
	if advanced {
		after := marks
		if it.gap != nil {
			after = it.gap.After
		}
		it.gap = &ChangeGap{After: append([]model.Cursor(nil), after...), Through: through, Reason: "catch_up_required"}
	}
	e.subscribers[it] = struct{}{}
	e.storageStats.ActiveIterators++
	it.stop = context.AfterFunc(ctx, func() { _ = it.Close() })
	return it, nil
}
func (e *Engine) publishCommittedLocked(slot uint16, index uint64, entry walEntry) {
	if len(e.subscribers) == 0 {
		return
	}
	cursor := model.Cursor{Group: e.group(slot), Index: model.Uint64(index)}
	event := committedEvent{Cursor: cursor}
	if entry.Batch != nil {
		event.Org = entry.Batch.Org
		event.Project = entry.Batch.Project
		err := e.db.View(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte("scan_commits"))
			if bucket == nil {
				return model.Fail(model.Corrupt)
			}
			return json.Unmarshal(bucket.Get(commitKey(cursor)), &event.Pages)
		})
		if err != nil {
			e.failed = true
			e.closeSubscribersLocked()
			return
		}
	}
	for it := range e.subscribers {
		advanceWatermark(it.marks, cursor)
		if event.Org != it.scope.OrgID() || !it.scope.AllowsProject(event.Project) {
			continue
		}
		relevant := false
		for _, route := range event.Pages {
			if it.allowsRoute(route) {
				relevant = true
				break
			}
		}
		if !relevant {
			continue
		}
		queued := event
		queued.Epoch = it.epoch
		select {
		case it.events <- queued:
		default:
		drain:
			for {
				select {
				case <-it.events:
				default:
					break drain
				}
			}
			it.pending = nil
			it.offset = 0
			it.epoch++
			// An untaken gap already owes the consumer everything after its After
			// (a stale Subscribe cursor sits behind delivered), so the replacement
			// must not start later; same rule as Subscribe's advanced branch.
			after := it.delivered
			if it.gap != nil {
				after = it.gap.After
			}
			it.gap = &ChangeGap{After: append([]model.Cursor(nil), after...), Through: append([]model.Cursor(nil), it.marks...), Reason: "slow_consumer"}
			// Wake a blocked receiver without polling or replaying a discarded epoch.
			it.events <- committedEvent{Epoch: it.epoch}
		}
	}
}
func commitKey(c model.Cursor) []byte {
	return []byte(c.Group.String() + ":" + strconv.FormatUint(uint64(c.Index), 10))
}
func (it *changeIterator) releaseLocked() {
	if it.page.Len() > 0 {
		it.e.storageStats.BorrowedPages--
	}
	it.page = Page{}
}
func (it *changeIterator) closeLocked() {
	if it.closed {
		return
	}
	it.closed = true
	if it.terminal == nil {
		if it.revoked {
			it.terminal = io.EOF
		} else {
			it.terminal = io.ErrClosedPipe
		}
	}
	if it.stop != nil {
		it.stop()
		it.stop = nil
	}
	it.releaseLocked()
	it.pending = nil
	it.gap = nil
	it.matchers = nil
	it.req.Selectors = nil
	it.req.After = nil
	delete(it.e.subscribers, it)
	it.e.storageStats.ActiveIterators--
drain:
	for {
		select {
		case <-it.events:
		default:
			break drain
		}
	}
	close(it.events)
}
func (it *changeIterator) Close() error {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	it.closeLocked()
	return nil
}
func (it *changeIterator) Watermarks() []model.Cursor {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	if it.certifyLocked(it.ctx, it.marks) != nil {
		return nil
	}
	return append([]model.Cursor(nil), it.marks...)
}
func (it *changeIterator) Next(ctx context.Context) (ChangePage, error) {
	e := it.e
	for {
		e.mu.Lock()
		it.releaseLocked()
		if ctx.Err() != nil || it.ctx.Err() != nil {
			it.terminal = model.Fail(model.Cancelled)
			it.closeLocked()
			e.mu.Unlock()
			return ChangePage{}, it.terminal
		}
		if it.closed {
			err := it.terminal
			e.mu.Unlock()
			return ChangePage{}, err
		}
		if err := e.authorizeRead(ctx, it.scope, it.req.Projects, it.req.Signal); err != nil {
			if !revocationError(err) {
				it.terminal = err
				it.closeLocked()
				e.mu.Unlock()
				return ChangePage{}, err
			}
			page := it.revokeLocked()
			e.mu.Unlock()
			return page, nil
		}
		if e.closed || e.failed {
			it.terminal = model.Fail(model.Unavailable)
			it.closeLocked()
			e.mu.Unlock()
			return ChangePage{}, it.terminal
		}
		if it.gap != nil {
			gap := it.gap
			epoch := it.epoch
			if err := it.certifyLocked(ctx, gap.Through); err != nil {
				page, failure := it.failLocked(err)
				e.mu.Unlock()
				return page, failure
			}
			if it.gap != gap || it.epoch != epoch {
				e.mu.Unlock()
				continue
			}
			page := it.takeGapLocked(gap)
			e.mu.Unlock()
			return page, nil
		}
		if it.pending != nil && it.offset < len(it.pending.Pages) {
			pending, epoch := it.pending, it.epoch
			route := it.pending.Pages[it.offset]
			it.offset++
			if !it.allowsRoute(route) {
				e.mu.Unlock()
				continue
			}
			ref, err := e.loadRefLocked(route.ID)
			if err != nil {
				it.terminal = err
				it.closeLocked()
				e.mu.Unlock()
				return ChangePage{}, err
			}
			if ref.Org != it.scope.OrgID() || !it.scope.AllowsProject(ref.Project) || ref.Kind != route.Kind || ref.Subject != route.Subject || ref.Restricted != route.Restricted || ref.Source != route.Source || !allowsSubject(it.scope, ref.Kind, ref.Subject) {
				it.terminal = model.Fail(model.Corrupt)
				it.closeLocked()
				e.mu.Unlock()
				return ChangePage{}, it.terminal
			}
			p, err := e.readPage(ref)
			if err != nil {
				it.terminal = err
				it.closeLocked()
				e.mu.Unlock()
				return ChangePage{}, err
			}
			delPreds, derr := e.readDeletions(ctx, it.scope.OrgID(), it.req.Projects)
			if derr != nil {
				it.terminal = derr
				it.closeLocked()
				e.mu.Unlock()
				return ChangePage{}, derr
			}
			var selected Page
			for i := range p.IDs {
				if !coveredRow(delPreds, it.scope.OrgID(), it.req.Signal, p, i) && matchesRow(it.matchers, p, i, it.req.Signal) {
					appendPageRow(&selected, p, i)
				}
			}
			if selected.Len() == 0 {
				e.mu.Unlock()
				continue
			}
			if err = it.certifyLocked(ctx, it.marks); err != nil {
				page, failure := it.failLocked(err)
				e.mu.Unlock()
				return page, failure
			}
			if it.pending != pending || it.epoch != epoch {
				e.mu.Unlock()
				continue
			}
			// A deletion that began after the predicates above were fetched (the
			// release fence is many round trips) must also hide rows of this
			// page: refilter the decoded page against the current set. A page
			// emptied this way is skipped like any fully covered page.
			latest, lerr := e.readDeletions(ctx, it.scope.OrgID(), it.req.Projects)
			if lerr != nil {
				page, failure := it.failLocked(&scopeReadError{cause: lerr})
				e.mu.Unlock()
				return page, failure
			}
			if deletionsChanged(delPreds, latest) {
				selected = Page{}
				for i := range p.IDs {
					if !coveredRow(latest, it.scope.OrgID(), it.req.Signal, p, i) && matchesRow(it.matchers, p, i, it.req.Signal) {
						appendPageRow(&selected, p, i)
					}
				}
				if selected.Len() == 0 {
					e.mu.Unlock()
					continue
				}
			}
			selected.Bytes = p.Bytes
			it.page = selected
			e.storageStats.BorrowedPages++
			cursor := pending.Cursor
			if it.offset == len(pending.Pages) {
				advanceWatermark(it.delivered, cursor)
			}
			e.mu.Unlock()
			return ChangePage{Page: selected, Cursors: []model.Cursor{cursor}}, nil
		}
		if it.pending != nil {
			advanceWatermark(it.delivered, it.pending.Cursor)
		}
		it.pending = nil
		it.offset = 0
		events := it.events
		e.mu.Unlock()
		select {
		case event, ok := <-events:
			e.mu.Lock()
			if !ok {
				err := it.terminal
				e.mu.Unlock()
				return ChangePage{}, err
			}
			if !it.closed && event.Epoch == it.epoch {
				it.pending = &event
			}
			e.mu.Unlock()
		case <-ctx.Done():
			_ = it.Close()
			return ChangePage{}, model.Fail(model.Cancelled)
		case <-it.ctx.Done():
			_ = it.Close()
			return ChangePage{}, model.Fail(model.Cancelled)
		}
	}
}
func (it *changeIterator) allowsRoute(route committedPage) bool {
	return route.Kind == it.req.Signal && route.Restricted == (it.scope.Permission() == auth.RawRead) && (!route.Restricted || it.scope.AllowsSource(route.Source)) && allowsSubject(it.scope, route.Kind, route.Subject)
}
func advanceWatermark(marks []model.Cursor, cursor model.Cursor) {
	for i, m := range marks {
		if m.Group == cursor.Group && cursor.Index > m.Index {
			marks[i] = cursor
			return
		}
	}
}
func (e *Engine) closeSubscribersLocked() {
	for it := range e.subscribers {
		it.terminal = model.Fail(model.Unavailable)
		it.closeLocked()
	}
	for it := range e.scans {
		it.terminal = model.Fail(model.Unavailable)
		it.closeLocked()
	}
}
func revocationError(err error) bool {
	var fault *model.Fault
	if !errors.As(err, &fault) {
		return false
	}
	switch fault.Code {
	case model.Unauthenticated, model.Forbidden, model.NotFound, model.Stale:
		return true
	}
	return false
}
func (it *changeIterator) certifyLocked(ctx context.Context, marks []model.Cursor) error {
	check := func() error {
		if ctx.Err() != nil || it.ctx.Err() != nil {
			return model.Fail(model.Cancelled)
		}
		if it.e.closed || it.e.failed {
			return model.Fail(model.Unavailable)
		}
		if it.closed {
			return it.terminal
		}
		if err := it.e.authorizeRead(ctx, it.scope, it.req.Projects, it.req.Signal); err != nil {
			return &scopeReadError{cause: err}
		}
		return nil
	}
	if err := check(); err != nil {
		return err
	}
	snapshot := append([]model.Cursor(nil), marks...)
	if err := it.e.replicaReleaseFenceLocked(ctx, snapshot); err != nil {
		return err
	}
	return check()
}

// takeGapLocked hands the pending gap to the consumer. Delivering a gap makes
// the consumer responsible for its whole window, so the delivered cut moves to
// gap.Through; every page's Cursors is the consumer's resume position after
// handling that page.
func (it *changeIterator) takeGapLocked(gap *ChangeGap) ChangePage {
	it.gap = nil
	it.delivered = append(it.delivered[:0], gap.Through...)
	for _, mark := range gap.Through {
		advanceWatermark(it.marks, mark)
	}
	return ChangePage{Gap: gap, Cursors: append([]model.Cursor(nil), gap.Through...)}
}

// revokeLocked is the single exit for confirmed credential revocation, so every
// revoke path gives the consumer the same two guarantees:
//
//   - A pending gap is never swallowed. It is reported first, as an ordinary
//     gap page, and the stream stays open for exactly one more Next, which
//     returns the revoke page (or continues if the scope became valid again).
//     The gap carries cursors only, never rows.
//   - The revoke page advertises it.delivered and nothing else: the rows and gap
//     windows the consumer was actually handed. it.marks is NOT safe to
//     advertise: it advances on every commit, including events still queued,
//     events dropped by an overrun and commits irrelevant to this scope, and
//     Subscribe treats After == mark as caught up, so resuming from marks would
//     silently skip (delivered, marks]. Resuming from delivered instead makes
//     the engine report catch_up_required for exactly that window.
func (it *changeIterator) revokeLocked() ChangePage {
	if it.gap != nil {
		return it.takeGapLocked(it.gap)
	}
	page := ChangePage{Revoked: true, Cursors: append([]model.Cursor(nil), it.delivered...)}
	it.revoked = true
	it.closeLocked()
	return page
}
func (it *changeIterator) failLocked(err error) (ChangePage, error) {
	var denied *scopeReadError
	if errors.As(err, &denied) && revocationError(denied.cause) {
		return it.revokeLocked(), nil
	}
	it.terminal = err
	it.closeLocked()
	return ChangePage{}, err
}

type scopeReadError struct{ cause error }

func (e *scopeReadError) Error() string { return e.cause.Error() }
func (e *scopeReadError) Unwrap() error { return e.cause }
