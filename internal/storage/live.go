// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"io"
	"runtime"
	"strconv"
	"time"
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
	// queued counts the events put on events, settled the ones the consumer is done with (settledLocked),
	// and moved is closed and replaced each time settled grows (and when the iterator closes), under e.mu.
	queued, settled uint64
	moved           chan struct{}
	// replay is the window an overrun dropped, read back from durable storage when the subscription asked for
	// catch-up (SubscribeRequest.CatchUp); pendingReplay says the pending event came from it and not from the queue;
	// handed is how many routes of the pending event the consumer was handed.
	replay        *replayWindow
	pendingReplay bool
	handed        int
	// handedRows are the rows of the pending event the consumer was handed (catch-up subscriptions only): the
	// identity that survives a rewrite of the commit record, which a route offset does not.
	handedRows map[model.ID]struct{}
}

// replayWindow is what an overrun dropped: the commits after next (the last one handled, per group) up to through.
// resume names the one event the consumer had been handed part of, to be read again without the rows it was handed.
type replayWindow struct {
	next, through []model.Cursor
	resume        *replayResume
}
type replayResume struct {
	cursor model.Cursor
	handed map[model.ID]struct{}
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
	if e.afterSubscribeFence != nil {
		e.afterSubscribeFence()
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
	it := &changeIterator{e: e, scope: scope, req: req, matchers: ms, events: make(chan committedEvent, liveCapacity), moved: make(chan struct{}), marks: marks, ctx: ctx}
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
	if advanced && len(req.After) == 0 {
		// A fresh subscription starts at what is applied now. Commits that landed between the read fence
		// and this registration were not acknowledged before the call (the fence covers everything that
		// was), so they are neither owed to the consumer nor a gap: a stream opened with nothing missing
		// used to open with a catch_up_required gap whenever a background commit (an erasure declaration,
		// a verification, a deletion) fell into that window (hundreds of milliseconds under load).
		it.marks = append([]model.Cursor(nil), through...)
		it.delivered = append([]model.Cursor(nil), through...)
	} else if advanced {
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
			raw, err := tableGet(tx, tblCommits, commitKey(cursor))
			if err != nil {
				return err
			}
			return json.Unmarshal(raw, &event.Pages)
		})
		if err != nil {
			e.failLocked()
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
			it.queued++
		default:
			dropped := uint64(0)
		drain:
			for {
				select {
				case <-it.events:
					dropped++
				default:
					break drain
				}
			}
			if it.pending != nil && !it.pendingReplay {
				dropped++
			}
			it.settledLocked(dropped)
			it.epoch++
			if it.req.CatchUp {
				it.startReplayLocked()
			} else {
				it.pending = nil
				it.offset = 0
				// An untaken gap already owes the consumer everything after its After
				// (a stale Subscribe cursor sits behind delivered), so the replacement
				// must not start later; same rule as Subscribe's advanced branch.
				after := it.delivered
				if it.gap != nil {
					after = it.gap.After
				}
				it.gap = &ChangeGap{After: append([]model.Cursor(nil), after...), Through: append([]model.Cursor(nil), it.marks...), Reason: "slow_consumer"}
			}
			// Wake a blocked receiver without polling or replaying a discarded epoch.
			it.events <- committedEvent{Epoch: it.epoch}
			it.queued++
		}
	}
}

// DefaultCatchUpLag is the lag bound of a catch-up subscription that does not name one: commits per group.
const DefaultCatchUpLag = 4096

// replayScanBatch is how many commits one replay step examines under e.mu before it gives the lock up. A
// variable only so a test can shrink it.
var replayScanBatch = 256

// startReplayLocked answers an overrun for a subscription that asked for catch-up: everything the queue held
// is discarded and the window is read back from the commit records instead. An untaken gap (a window the
// consumer is already told to recover) is not read twice: the replay starts after it. The part of the window
// beyond the lag bound is announced as a gap instead of being read (limitLagLocked). The event the consumer
// was handed part of is read again, minus the rows it was handed (identified by row ID: a position in the
// commit record would shift when an erasure rewrites it).
func (it *changeIterator) startReplayLocked() {
	if it.replay == nil {
		base := it.delivered
		if it.gap != nil {
			base = it.gap.Through
		}
		it.replay = &replayWindow{next: append([]model.Cursor(nil), base...)}
		it.queued++ // the whole window is one unit of work for WaitCaughtUp, settled when it has been handed over
	}
	it.limitLagLocked()
	if p := it.pending; p != nil && it.handed < len(p.Pages) && (it.gap == nil || p.Cursor.Index > cursorIndexOf(it.gap.Through, p.Cursor.Group)) {
		it.replay.resume = &replayResume{cursor: p.Cursor, handed: it.handedRows}
		for i := range it.replay.next {
			if it.replay.next[i].Group == p.Cursor.Group && it.replay.next[i].Index >= p.Cursor.Index {
				it.replay.next[i].Index = p.Cursor.Index - 1
			}
		}
	}
	it.pending, it.offset, it.handed, it.pendingReplay, it.handedRows = nil, 0, 0, false, nil
	it.replay.through = append(it.replay.through[:0], it.marks...)
}

// limitLagLocked enforces the lag bound (D99) on a window that is about to be read: a group whose window is
// longer than the bound has its oldest commits announced as an exact slow_consumer gap, ending at the commit
// before the newest CatchUpLag, and the replay of that group starts after it. The gap extends one the
// consumer has not taken yet (its After is kept, its Through moves up).
func (it *changeIterator) limitLagLocked() {
	bound := it.req.CatchUpLag
	if bound == 0 {
		bound = DefaultCatchUpLag
	}
	r := it.replay
	for _, m := range it.marks {
		for i := range r.next {
			next := r.next[i]
			if next.Group != m.Group || m.Index <= next.Index || uint64(m.Index-next.Index) <= bound {
				continue
			}
			cut := model.Cursor{Group: m.Group, Index: m.Index - model.Uint64(bound)}
			gap := &ChangeGap{After: append([]model.Cursor(nil), it.delivered...), Through: append([]model.Cursor(nil), it.delivered...), Reason: "slow_consumer"}
			if it.gap != nil {
				gap = &ChangeGap{After: it.gap.After, Through: append([]model.Cursor(nil), it.gap.Through...), Reason: it.gap.Reason}
			}
			advanceWatermark(gap.Through, cut)
			it.gap = gap
			r.next[i] = cut
			if r.resume != nil && r.resume.cursor.Group == cut.Group && r.resume.cursor.Index <= cut.Index {
				r.resume = nil
			}
		}
	}
}
func cursorIndexOf(cursors []model.Cursor, group model.ID) model.Uint64 {
	for _, c := range cursors {
		if c.Group == group {
			return c.Index
		}
	}
	return 0
}

// rowHanded reports whether the consumer was already handed this row of the pending event.
func (it *changeIterator) rowHanded(id model.ID) bool {
	_, ok := it.handedRows[id]
	return ok
}

// routeGoneLocked reports whether the commit record no longer names the page: an erasure removed it.
func (e *Engine) routeGoneLocked(cursor model.Cursor, page model.ID) (bool, error) {
	var pages []committedPage
	err := e.db.View(func(tx *bolt.Tx) error {
		raw, err := tableGet(tx, tblCommits, commitKey(cursor))
		if err != nil || raw == nil {
			return err
		}
		return json.Unmarshal(raw, &pages)
	})
	if err != nil {
		return false, err
	}
	for _, p := range pages {
		if p.ID == page {
			return false, nil
		}
	}
	return true, nil
}

const (
	replayDone = iota
	replayHit
	replayYield
)

// replayNextLocked is the next commit of the replay window this scope can be handed, read from the commit
// records, with the rows of it that were handed already (nil unless it is the commit a second overrun
// interrupted). It examines at most replayScanBatch commits: status is replayHit for a commit, replayYield
// when the budget ran out first (the caller releases e.mu and asks again) and replayDone once the window is
// exhausted.
func (it *changeIterator) replayNextLocked() (ev committedEvent, handed map[model.ID]struct{}, status int, err error) {
	e, r := it.e, it.replay
	scanned := 0
	for i := range r.next {
		through := cursorIndexOf(r.through, r.next[i].Group)
		for r.next[i].Index < through {
			if scanned == replayScanBatch {
				return committedEvent{}, nil, replayYield, nil
			}
			scanned++
			r.next[i].Index++
			cursor := r.next[i]
			var pages []committedPage
			err = e.db.View(func(tx *bolt.Tx) error {
				raw, err := tableGet(tx, tblCommits, commitKey(cursor))
				if err != nil || raw == nil {
					return err
				}
				return json.Unmarshal(raw, &pages)
			})
			if err != nil {
				return committedEvent{}, nil, replayDone, err
			}
			if len(pages) == 0 {
				continue
			}
			ref, err := e.loadRefLocked(pages[0].ID)
			if err != nil {
				return committedEvent{}, nil, replayDone, err
			}
			if ref.Org != it.scope.OrgID() || !it.scope.AllowsProject(ref.Project) {
				continue
			}
			if r.resume != nil && r.resume.cursor == cursor {
				handed = r.resume.handed
			}
			return committedEvent{Org: ref.Org, Project: ref.Project, Cursor: cursor, Pages: pages, Epoch: it.epoch}, handed, replayHit, nil
		}
	}
	return committedEvent{}, nil, replayDone, nil
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
	it.notifyLocked()
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

// Lag is how many commits the consumer is behind (D99): those queued for it plus those left in the replay
// window, counted per group over every commit of the group (a commit this scope cannot see counts too, so it
// is an upper bound), and zero for a consumer that holds nothing. The queue part may include one wake-up
// marker.
func (it *changeIterator) Lag() uint64 {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	if it.closed {
		return 0
	}
	lag := uint64(len(it.events))
	if r := it.replay; r != nil {
		for _, next := range r.next {
			if through := cursorIndexOf(r.through, next.Group); through > next.Index {
				lag += uint64(through - next.Index)
			}
		}
	}
	return lag
}

// settledLocked records that n committed events queued for this iterator are done: handed to the
// consumer page by page and the consumer came back for more, or discarded by an overrun.
func (it *changeIterator) settledLocked(n uint64) {
	it.settled += n
	it.notifyLocked()
}

// notifyLocked wakes every WaitCaughtUp: moved is closed and replaced, so a waiter that read it before
// the change sees it closed.
func (it *changeIterator) notifyLocked() {
	close(it.moved)
	it.moved = make(chan struct{})
}

// WaitCaughtUp returns once the consumer has finished with every committed event this iterator holds
// for it at the time of the call, once a read fence has made every commit acknowledged before the call
// visible to it. Finished means the consumer asked for the page after the last page of the event, so
// whatever it did with the page is done (the live stream's buffer holds the records). A commit that
// arrives later is not waited for. A closed iterator is caught up.
func (it *changeIterator) WaitCaughtUp(ctx context.Context) error {
	e := it.e
	if _, _, err := e.replicaReadFence(ctx, nil, false); err != nil {
		return err
	}
	e.mu.Lock()
	target := it.queued
	e.mu.Unlock()
	for {
		e.mu.Lock()
		if it.closed || it.settled >= target {
			e.mu.Unlock()
			return nil
		}
		moved := it.moved
		e.mu.Unlock()
		select {
		case <-moved:
		case <-ctx.Done():
			return model.Fail(model.Timeout)
		case <-it.ctx.Done():
			return model.Fail(model.Cancelled)
		}
	}
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
				// A page that an erasure removed after this commit was read is no longer named by the
				// commit record (the erasure rewrites both in one transaction): it is withheld, not corrupt.
				if gone, gerr := e.routeGoneLocked(pending.Cursor, route.ID); gerr == nil && gone {
					e.mu.Unlock()
					continue
				}
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
				if !coveredRow(delPreds, it.scope.OrgID(), it.req.Signal, p, i) && matchesRow(it.matchers, p, i, it.req.Signal) && !it.rowHanded(p.IDs[i]) {
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
					if !coveredRow(latest, it.scope.OrgID(), it.req.Signal, p, i) && matchesRow(it.matchers, p, i, it.req.Signal) && !it.rowHanded(p.IDs[i]) {
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
			if it.req.CatchUp {
				if it.handedRows == nil {
					it.handedRows = make(map[model.ID]struct{}, len(selected.IDs))
				}
				for _, id := range selected.IDs {
					it.handedRows[id] = struct{}{}
				}
			}
			it.handed = it.offset
			e.mu.Unlock()
			return ChangePage{Page: selected, Cursors: []model.Cursor{cursor}}, nil
		}
		if it.pending != nil {
			advanceWatermark(it.delivered, it.pending.Cursor)
			if !it.pendingReplay {
				it.settledLocked(1)
			}
		}
		it.pending, it.offset, it.handed, it.pendingReplay, it.handedRows = nil, 0, 0, false, nil
		if it.replay != nil {
			ev, handed, status, err := it.replayNextLocked()
			if err != nil {
				it.terminal = err
				it.closeLocked()
				e.mu.Unlock()
				return ChangePage{}, err
			}
			switch status {
			case replayHit:
				it.pending, it.offset, it.handed, it.pendingReplay, it.handedRows = &ev, 0, 0, true, handed
				it.replay.resume = nil
				e.mu.Unlock()
				continue
			case replayYield:
				// The scan of commits this scope cannot see is bounded: give e.mu to the appends and
				// acknowledgements that wait for it, then carry on from where the scan stopped.
				hook := e.replayYield
				e.mu.Unlock()
				if hook != nil {
					hook()
				}
				runtime.Gosched()
				continue
			}
			it.replay = nil
			it.settledLocked(1)
		}
		events := it.events
		e.mu.Unlock()
		fence := time.NewTimer(liveFenceEvery)
		select {
		case <-fence.C:
			// Nothing was committed for a while: a shard that went away in the meantime would
			// otherwise leave this stream looking healthy until its next commit. A group that
			// no longer answers ends the stream with its error, like a commit that cannot be certified.
			if _, _, err := e.replicaReadFence(ctx, nil, false); err != nil {
				e.mu.Lock()
				if it.closed {
					terminal := it.terminal
					e.mu.Unlock()
					return ChangePage{}, terminal
				}
				page, failure := it.failLocked(err)
				e.mu.Unlock()
				return page, failure
			}
		case event, ok := <-events:
			fence.Stop()
			e.mu.Lock()
			if !ok {
				err := it.terminal
				e.mu.Unlock()
				return ChangePage{}, err
			}
			if !it.closed && event.Epoch == it.epoch {
				it.pending, it.offset, it.handed, it.pendingReplay, it.handedRows = &event, 0, 0, false, nil
			} else {
				it.settledLocked(1)
			}
			e.mu.Unlock()
		case <-ctx.Done():
			fence.Stop()
			_ = it.Close()
			return ChangePage{}, model.Fail(model.Cancelled)
		case <-it.ctx.Done():
			fence.Stop()
			_ = it.Close()
			return ChangePage{}, model.Fail(model.Cancelled)
		}
	}
}

// liveFenceEvery is how long a live subscription waits for a commit before it asks every replica
// group whether it still answers. A variable only so a test can shorten it.
var liveFenceEvery = 10 * time.Second

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
