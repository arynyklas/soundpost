// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"container/list"
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"io"
	"reflect"
	"regexp"
	"sync"
	"sync/atomic"
)

type compiledMatcher struct {
	Matcher
	re                 *regexp.Regexp
	idField, spanField bool
	id                 model.ID
	span               model.SpanID
}
type rowIterator struct {
	e         *Engine
	scope     auth.Scope
	req       ScanRequest
	prefixes  [][]byte
	partition int
	last      []byte
	marks     []model.Cursor
	visible   map[model.ID]uint64 // marks by group: the highest origin index the cut covers (marks is kept for the barrier and Watermarks)
	after     map[model.ID]uint64
	matchers  []compiledMatcher
	page      Page
	closed    bool
	terminal  error
	stop      func() bool
	ctx       context.Context
	posting   string
	partial   bool
	// partialShown is set once a page carrying Partial was returned, so the flag of a read whose
	// answering shards held no matching row is still delivered, once, at the end.
	partialShown bool
	// slotHeld is true while the iterator owns one scan slot; closeLocked returns it exactly once.
	slotHeld bool
	// rows is the most rows the next page holds. It starts at pageRows and grows by pageRowsGrowth after every
	// page the iterator releases, up to maxRows (ScanRequest.MaxPageRows): every page costs one release
	// barrier, so a scan that reads on pays it once per many rows, and a reader that stops early has asked
	// for no more than a page or two beyond what it used.
	rows, maxRows int
	// startPreds are the deletion predicates the Scan read last, for the first chunk (haveStartPreds until it
	// takes them); certifiedEnd is set when the barrier at the end of the rows certified the cut.
	startPreds     []model.DeletePredicate
	haveStartPreds bool
	certifiedEnd   bool
}

// visibleThrough is the cut as a lookup: a row is visible when its origin index is within the mark of
// its group, which a scan of every mark per row (64 comparisons of 16-byte identifiers) asked.
func visibleThrough(marks []model.Cursor) map[model.ID]uint64 {
	out := make(map[model.ID]uint64, len(marks))
	for _, m := range marks {
		if through, ok := out[m.Group]; !ok || uint64(m.Index) > through {
			out[m.Group] = uint64(m.Index)
		}
	}
	return out
}

// scanPageCache holds the pages the scans of the engine have verified and decoded, newest used first,
// within a byte bound. The index is ordered by time, so the rows of batches that overlap in time
// alternate between their pages (a backfill puts rows of the whole window into every batch), and a
// walk that kept only the current page read, hashed and decoded a page once per alternation: 786 page
// reads for the 8 pages of a scan of 8 batches over the same times, and at the Queries gate 19,500 reads
// of the pages of one project's 24 h. The same pages are read again by the next scan of the same
// window, which at that gate is ten queries a second over 190 pages a project. A chunk is built from one
// bolt read transaction with the engine lock released (read_build.go); a page the chunk meets for the first time is looked up again in
// that transaction and judged by the same checks as a page that was never seen, and its decode is
// reused only when the stored page is the one that was decoded, in the same place (the content hash of
// its reference, which any rewrite of the page, erasure included, changes, and its location, which a
// flush or a compaction changes) and carries the columns the chunk needs.
// The deletion predicates are applied to every row at selection. A page that erasure deletes is
// dropped from the cache in the same transaction (deleteBatchIndex): no decoded copy of erased bytes
// outlives the erasure. The cache is for readers of this engine only and is never persisted.
type scanPageCache struct {
	mu   sync.Mutex
	seq  uint64 // the last chunk begun
	byID map[model.ID]*list.Element
	// scanSlots and liveSlots are the iterator budgets of the engine (scan_slots.go); they live here
	// because the cache is the engine's zero-value-ready read state.
	scanSlots, liveSlots slotPool
	// refLookups counts the page references the scans looked up in the row store (a test and the diagnostics read it).
	refLookups atomic.Uint64
	lru        list.List // of *cachedPage, front = used last
	bytes      uint64    // encoded bytes of the cached pages
	// dropped is the highest write transaction that dropped a page: a chunk whose snapshot is older
	// (bolt numbers a read transaction by the last commit it sees) may hold the page's old bytes.
	dropped uint64
	// rebound is the highest write transaction that changed the reference of a page (refsChanged, drop).
	rebound uint64
}
type cachedPage struct {
	id        model.ID
	length    uint64     // encoded length, as its reference gives it
	hash      model.Hash // content hash of the stored page, as its reference gives it
	segment   string     // where the stored page lies, as its reference gives it: the segment file ("" for a hot page)...
	offset    int64      // ...and its offset in it
	hot       bool       // the page is held in the row itself
	log       string     // the payload log reference of a page stored there
	seq       uint64     // the chunk that last looked the page up and judged it
	snap      uint64     // the snapshot (bolt transaction id) the reference was last judged in
	resources bool       // the decode carries the resource columns
	payload   bool       // the decode carries the payload columns
	// What a reader's scope is judged against, as the reference gives it (the checks of a first sight).
	org, project, source model.ID
	kind, subject        model.Kind
	restricted           bool
	ns                   []byte // the index namespace of the page (pageNamespace)
	page                 Page
}

// storedAs reports whether the page is stored as the reference says, in the same bytes and in the same
// place: a flush or a compaction that moves it makes the next reader read, and verify, it at its new
// place, as a reader that never saw it does.
func (c *cachedPage) storedAs(ref pageRef) bool {
	return c.hash == ref.Hash && c.length == uint64(ref.Length) && c.segment == ref.Segment && c.offset == ref.Offset && c.hot == (len(ref.Hot) > 0) && c.log == string(ref.Log)
}

// scanPageCacheBytes bounds the encoded bytes of the pages the cache holds; a decoded page takes about
// three times its encoded size in memory.
const scanPageCacheBytes = 256 << 20

// scanPageLoadHook, when set (tests), runs before a scan's chunk reads a page that is not in the cache:
// a test that asserts the decode of a scan never holds the engine lock stalls the read here.
var scanPageLoadHook atomic.Pointer[func()]

// begin numbers the chunk that starts.
func (c *scanPageCache) begin() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	return c.seq
}

// get returns the cached page. fresh reports that its stored reference needs no new look-up in the
// chunk's snapshot: no commit that changed the reference of a page (a flush or a compaction publishing
// the manifest, an erasure dropping the page) lies after the older of the snapshot the entry was last
// judged in and this one, so the reference the entry was decoded from is the one this snapshot holds.
func (c *scanPageCache) get(id model.ID, snapshot uint64) (page cachedPage, ok, fresh bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byID[id]
	if !ok {
		return cachedPage{}, false, false
	}
	c.lru.MoveToFront(el)
	page = *el.Value.(*cachedPage)
	return page, true, c.rebound <= min(page.snap, snapshot)
}

// touch records that chunk seq looked the page up in its snapshot and found it unchanged.
func (c *scanPageCache) touch(id model.ID, seq, snapshot uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byID[id]; ok {
		p := el.Value.(*cachedPage)
		p.seq, p.snap = seq, max(p.snap, snapshot)
	}
}

// put keeps a page a chunk decoded in the read transaction snapshot, unless an erasure dropped pages in a
// transaction the snapshot does not see: the page may be one of them, and a decoded copy of erased bytes
// must not outlive the erasure.
func (c *scanPageCache) put(id model.ID, seq, snapshot uint64, ref pageRef, resources, payload bool, page Page) {
	if page.Bytes > scanPageCacheBytes/4 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if snapshot < c.dropped {
		return
	}
	c.removeLocked(id)
	if c.byID == nil {
		c.byID = make(map[model.ID]*list.Element)
	}
	c.byID[id] = c.lru.PushFront(&cachedPage{id: id, length: uint64(ref.Length), hash: ref.Hash, segment: ref.Segment, offset: ref.Offset, hot: len(ref.Hot) > 0, log: string(ref.Log), seq: seq, snap: snapshot, org: ref.Org, project: ref.Project, source: ref.Source, kind: ref.Kind, subject: ref.Subject, restricted: ref.Restricted, ns: pageNamespace(ref.Org, ref.Project, ref.Kind, ref.Restricted, ref.Source, ref.Subject), resources: resources, payload: payload, page: page})
	c.bytes += page.Bytes
	for c.bytes > scanPageCacheBytes {
		c.removeLocked(c.lru.Back().Value.(*cachedPage).id)
	}
}

// refsChanged records that write transaction tx changes the stored reference of pages that exist (a
// manifest publication moving them between the row, the log and segments): an entry judged in a snapshot
// before it is looked up again.
func (c *scanPageCache) refsChanged(tx uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rebound = max(c.rebound, tx)
}

// drop forgets a page whose stored bytes are gone; tx is the write transaction that removes them.
func (c *scanPageCache) drop(id model.ID, tx uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dropped = max(c.dropped, tx)
	c.rebound = max(c.rebound, tx)
	c.removeLocked(id)
}
func (c *scanPageCache) removeLocked(id model.ID) {
	if el, ok := c.byID[id]; ok {
		c.bytes -= el.Value.(*cachedPage).page.Bytes
		c.lru.Remove(el)
		delete(c.byID, id)
	}
}
func compileMatchers(ms []Matcher) ([]compiledMatcher, error) {
	if len(ms) > 64 {
		return nil, model.Fail(model.TooLarge)
	}
	out := make([]compiledMatcher, 0, len(ms))
	for _, m := range ms {
		if m.Target != MatchLabel && m.Target != MatchField || len(m.Name) == 0 || len(m.Name) > 256 || m.Op < MatchEqual || m.Op > MatchNotRegexp || m.Literal.Kind < LiteralString || m.Literal.Kind > LiteralFloatBits || len(m.Literal.String) > 4096 || m.Target == MatchLabel && m.Literal.Kind != LiteralString {
			return nil, model.Fail(model.Invalid)
		}
		c := compiledMatcher{Matcher: m}
		if m.Op == MatchRegexp || m.Op == MatchNotRegexp {
			if m.Literal.Kind != LiteralString {
				return nil, model.Fail(model.Invalid)
			}
			re, err := regexp.Compile("^(?:" + m.Literal.String + ")$")
			if err != nil {
				return nil, model.Fail(model.Invalid)
			}
			c.re = re
		}
		if m.Target == MatchField && (isIDField(m.Name) || m.Name == "span_id") {
			if m.Literal.Kind != LiteralString {
				return nil, model.Fail(model.Invalid)
			}
			c.idField = isIDField(m.Name)
			c.spanField = m.Name == "span_id"
			if c.re == nil && m.Literal.String != "" {
				if c.idField {
					id, err := model.ParseID(m.Literal.String)
					if err != nil {
						return nil, model.Fail(model.Invalid)
					}
					c.id = id
				}
				if c.spanField {
					span, ok := parseSpanLiteral(m.Literal.String)
					if !ok {
						return nil, model.Fail(model.Invalid)
					}
					c.span = span
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}

const profilesRead auth.Permission = "profiles.read"

func (e *Engine) authorizeRead(ctx context.Context, s auth.Scope, projects []model.ID, signal model.Kind) error {
	_, err := e.authorizeReadDeletions(ctx, s, projects, signal)
	return err
}

// authorizeReadDeletions is authorizeRead that also returns the deletion
// predicates it fetched as its last step, so a caller that needs both (the page
// builder) pays one control read, not two. It is readAuthority and
// finishReadDeletions in one step, for a caller that holds e.mu; the reader of a
// scan takes the two steps apart (Scan, rowIterator.authorizeLocked).
func (e *Engine) authorizeReadDeletions(ctx context.Context, s auth.Scope, projects []model.ID, signal model.Kind) ([]model.DeletePredicate, error) {
	control, err := e.readAuthority(ctx, s, projects, signal)
	if err != nil {
		return nil, err
	}
	return e.finishReadDeletions(s.OrgID(), projects, control)
}

// readAuthority is the part of an authority read that waits on the control state: the scope's
// revalidation and the control view of the active deletions, each a ReadIndex round that waits for a
// quorum, for seconds when the quorum is slow. It reads nothing of the engine's data and must be called
// without e.mu: the lock held across it stalled every append and every other reader of the node.
func (e *Engine) readAuthority(ctx context.Context, s auth.Scope, projects []model.ID, signal model.Kind) ([]model.DeletePredicate, error) {
	if ctx.Err() != nil {
		return nil, model.Fail(model.Cancelled)
	}
	permitted := s.Permission() == auth.Read || s.Permission() == auth.RawRead || s.Permission() == profilesRead && (signal == model.Profile || signal == model.CapabilityKind || signal == model.Loss)
	if !permitted || len(projects) == 0 || len(projects) > 128 {
		return nil, model.Fail(model.Forbidden)
	}
	seen := map[model.ID]bool{}
	for _, p := range projects {
		if !s.AllowsProject(p) {
			return nil, model.Fail(model.NotFound)
		}
		if seen[p] {
			return nil, model.Fail(model.Invalid)
		}
		seen[p] = true
	}
	if err := e.validator.Revalidate(ctx, s); err != nil {
		return nil, err
	}
	if e.tomb.gate.Load() {
		return nil, model.Fail(model.Unavailable)
	}
	return e.controlDeletions(ctx, s.OrgID(), projects)
}

// finishReadDeletions completes readAuthority under e.mu with what the engine itself holds: the
// restore gate, the tombstones applied locally (so an erasure that is applied is never missed between
// the control read and the local read, as the lock made it) and the retired projects. Nothing here
// waits: it is memory and one local read.
func (e *Engine) finishReadDeletions(org model.ID, projects []model.ID, control []model.DeletePredicate) ([]model.DeletePredicate, error) {
	if e.tomb.gate.Load() {
		return nil, model.Fail(model.Unavailable)
	}
	preds := control
	seen := make(map[model.ID]bool, len(control))
	for _, p := range control {
		seen[p.Operation] = true
	}
	err := e.db.View(func(tx *bolt.Tx) error {
		barriers, err := tombstonesWithPrefix(tx, nil)
		if err != nil {
			return err
		}
		for _, b := range barriers { // a deletion's barrier is recorded on every slot: list the deletion once
			if b.Predicate.Org == org && !seen[b.Predicate.Operation] {
				seen[b.Predicate.Operation] = true
				preds = append(preds, b.Predicate)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, p := range preds {
		for _, project := range projects {
			if p.RetiresProject(org, project) {
				return nil, model.Fail(model.NotFound)
			}
		}
	}
	return preds, nil
}
func readPrefixes(s auth.Scope, projects []model.ID, kind model.Kind, selectors []Matcher) ([][]byte, error) {
	var source model.ID
	if s.Permission() == auth.RawRead {
		for _, m := range selectors {
			if m.Target == MatchField && m.Name == "source_id" && m.Op == MatchEqual && m.Literal.Kind == LiteralString {
				id, err := model.ParseID(m.Literal.String)
				if err == nil && s.AllowsSource(id) {
					source = id
				}
			}
		}
		if source == (model.ID{}) {
			return nil, model.Fail(model.Forbidden)
		}
	}
	out := make([][]byte, 0, len(projects))
	for _, p := range projects {
		for _, subject := range scopeSubjects(s, kind) {
			out = append(out, pageNamespace(s.OrgID(), p, kind, s.Permission() == auth.RawRead, source, subject))
		}
	}
	return out, nil
}
func (e *Engine) Scan(ctx context.Context, scope auth.Scope, req ScanRequest) (RowIterator, error) {
	if err := e.authorizeRead(ctx, scope, req.Projects, req.Signal); err != nil {
		return nil, err
	}
	if !req.Signal.Valid() || req.End < req.Start || req.MaxPageRows < 0 || req.MaxPageRows > MaxScanPageRows {
		return nil, model.Fail(model.Invalid)
	}
	for _, f := range req.Projection {
		if f < FieldID || f > FieldObservedTime {
			return nil, model.Fail(model.Invalid)
		}
	}
	ms, err := compileMatchers(req.Selectors)
	if err != nil {
		return nil, err
	}
	prefixes, err := readPrefixes(scope, req.Projects, req.Signal, req.Selectors)
	if err != nil {
		return nil, err
	}
	req.Projects = append([]model.ID(nil), req.Projects...)
	req.Selectors = append([]Matcher(nil), req.Selectors...)
	req.Projection = append([]Field(nil), req.Projection...)
	req.Fence.Min = append([]model.Cursor(nil), req.Fence.Min...)
	var after map[model.ID]uint64
	if len(req.After) > 0 {
		after = make(map[model.ID]uint64, len(req.After))
		for _, c := range req.After {
			after[c.Group] = max(after[c.Group], uint64(c.Index))
		}
	}
	req.After = nil
	marks, partial, err := e.replicaReadFence(ctx, req.Fence.Min, req.Fence.AllowPartial)
	if err != nil {
		return nil, err
	}
	// The authority read after the fence waits on the control state: it is made before e.mu is taken
	// and only its local half runs under the lock.
	control, err := e.readAuthority(ctx, scope, req.Projects, req.Signal)
	if err != nil {
		return nil, err
	}
	// A slot is taken before e.mu: the wait is bounded by ctx only and never holds the engine lock. It is
	// held by the iterator (closeLocked returns it) or returned here on every early exit.
	if err = e.scanPages.scanSlots.acquire(ctx, ScanSlots); err != nil {
		return nil, err
	}
	slot := true
	defer func() {
		if slot {
			e.scanPages.scanSlots.release()
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	if ctx.Err() != nil {
		return nil, model.Fail(model.Cancelled)
	}
	startPreds, err := e.finishReadDeletions(scope.OrgID(), req.Projects, control)
	if err != nil {
		return nil, err
	}
	term := postingTerm(req.Selectors, req.Signal)
	if term != "" {
		for i, prefix := range prefixes {
			prefixes[i] = termPrefix(prefix, term)
		}
	}
	it := &rowIterator{e: e, scope: scope, req: req, prefixes: prefixes, marks: marks, visible: visibleThrough(marks), after: after, matchers: ms, ctx: ctx, posting: term, partial: partial, slotHeld: true, rows: pageRows, maxRows: max(pageRows, req.MaxPageRows), startPreds: startPreds, haveStartPreds: true}
	e.scans[it] = struct{}{}
	e.storageStats.ActiveIterators++
	slot = false // the iterator owns the slot now; closeLocked returns it once
	it.stop = context.AfterFunc(ctx, func() { e.mu.Lock(); defer e.mu.Unlock(); it.terminal = model.Fail(model.Cancelled); it.closeLocked() })
	return it, nil
}
func (e *Engine) watermarksLocked() []model.Cursor {
	out := make([]model.Cursor, 0, 64)
	for slot, index := range e.indexes {
		out = append(out, model.Cursor{Group: e.group(uint16(slot)), Index: model.Uint64(index)})
	}
	return out
}
func (e *Engine) Stats() StorageStats {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.storageStats
	out.SegmentFiles = uint64(len(e.catalog.Manifest.Segments))
	out.ManifestRevision = uint64(e.catalog.Manifest.Revision)
	return out
}
func (it *rowIterator) Watermarks() []model.Cursor {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	if it.closed && it.terminal == io.EOF && it.certifiedEnd {
		// The barrier at the end of the rows certified this cut, and nothing has been read since.
		return append([]model.Cursor(nil), it.marks...)
	}
	if _, err := it.certifyLocked(it.ctx, true); err != nil {
		return nil
	}
	return append([]model.Cursor(nil), it.marks...)
}
func (it *rowIterator) closeLocked() {
	if it.closed {
		return
	}
	it.closed = true
	if it.terminal == nil {
		it.terminal = io.ErrClosedPipe
	}
	if it.stop != nil {
		it.stop()
		it.stop = nil
	}
	it.releaseLocked()
	it.last = nil
	it.prefixes = nil
	it.matchers = nil
	it.req.Selectors = nil
	it.req.Projection = nil
	it.req.Fence.Min = nil
	it.after = nil
	it.visible = nil
	delete(it.e.scans, it)
	it.e.storageStats.ActiveIterators--
	if it.slotHeld {
		it.slotHeld = false
		it.e.scanPages.scanSlots.release()
	}
}
func (it *rowIterator) releaseLocked() {
	if it.page.Len() > 0 {
		it.e.storageStats.BorrowedPages--
	}
	it.page = Page{}
}
func (it *rowIterator) Close() error {
	it.e.mu.Lock()
	defer it.e.mu.Unlock()
	it.closeLocked()
	return nil
}
func (it *rowIterator) Next(ctx context.Context) (Page, error) {
	e := it.e
	e.mu.Lock()
	defer e.mu.Unlock()
	it.releaseLocked()
	if ctx.Err() != nil || it.ctx.Err() != nil {
		it.terminal = model.Fail(model.Cancelled)
		it.closeLocked()
		return Page{}, it.terminal
	}
	if it.closed {
		return Page{}, it.terminal
	}
	if e.closed || e.failed {
		it.terminal = model.Fail(model.Unavailable)
		it.closeLocked()
		return Page{}, it.terminal
	}
	// The barrier at the end of the rows reads the authority itself and judges with the same error, so a
	// Next with no chunk left to build makes no read of its own before it.
	for it.partition < len(it.prefixes) {
		// Predicates are fetched fresh when a chunk starts (the authority read already ends in the
		// deletion read, so there is no second one); the release barrier then fetches them again
		// and the chunk is rebuilt if they differ. The read waits on the control state with e.mu
		// released and is judged again under it (authorizeLocked) before the chunk reads the data.
		var delPreds []model.DeletePredicate
		if it.haveStartPreds {
			// The first chunk filters with the predicates the Scan has just read: the barrier below reads
			// them again and rebuilds the page if they differ, so a deletion that began since is caught.
			delPreds, it.startPreds, it.haveStartPreds = it.startPreds, nil, false
		} else {
			var err error
			if delPreds, err = it.authorizeLocked(ctx, false); err != nil {
				it.terminal = err
				it.closeLocked()
				return Page{}, err
			}
		}
		startPartition, startLast := it.partition, append([]byte(nil), it.last...)
		// The chunk is built from a snapshot with e.mu released (read_build.go): one scan's decode no
		// longer stops another scan or an append. What the lock kept out is judged by the release
		// barrier below and by the checks buildUnlocked makes when it comes back.
		res, err := it.buildUnlocked(&chunkJob{ctx: ctx, itCtx: it.ctx, scope: it.scope, req: it.req, prefix: it.prefixes[it.partition], posting: it.posting, last: startLast, visible: it.visible, after: it.after, matchers: it.matchers, delPreds: delPreds, rows: it.rows})
		if err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
		if res.done {
			it.partition++
			it.last = nil
		} else {
			it.last = append(it.last[:0], res.last...)
		}
		selected, chunkBytes := res.selected, res.chunkBytes
		if selected.Len() > 0 {
			certified, err := it.certifyLocked(ctx, false)
			if err != nil {
				it.terminal = err
				it.closeLocked()
				return Page{}, err
			}
			// The page was filtered with predicates fetched before the decode and
			// the release fence. A deletion that began since may cover rows already
			// accumulated, and its entity form may need payload columns this page
			// did not decode, so the page is discarded and rebuilt from the same
			// cursor under the new predicates instead of being patched.
			latest := certified
			if deletionsChanged(delPreds, latest) {
				it.partition, it.last = startPartition, append(it.last[:0], startLast...)
				continue
			}
			projectPage(&selected, it.req.Projection, it.req.Signal)
			selected.Partial = it.partial
			it.partialShown = it.partial
			selected.Bytes = chunkBytes
			it.page = selected
			it.rows = min(it.rows*pageRowsGrowth, it.maxRows)
			e.storageStats.BorrowedPages++
			return it.page, nil
		}
	}
	if _, err := it.certifyLocked(ctx, false); err != nil {
		it.terminal = err
		it.closeLocked()
		return Page{}, err
	}
	if it.partial && !it.partialShown {
		// Some shards did not answer and the ones that did hold no matching row: without this page
		// the reader would see a complete, empty answer, which is a zero graph for missing data.
		it.partialShown = true
		return Page{Partial: true}, nil
	}
	it.certifiedEnd = true
	it.terminal = io.EOF
	it.closeLocked()
	return Page{}, io.EOF
}
func matchesRow(ms []compiledMatcher, p Page, i int, kind model.Kind) bool {
	for _, m := range ms {
		match := false
		switch {
		case m.idField:
			value, found := nativeIDField(p, i, m.Name)
			if m.re != nil {
				text := ""
				if found {
					text = value.String()
				}
				match = m.re.MatchString(text)
			} else if m.Literal.String == "" {
				match = !found
			} else {
				match = found && value == m.id
			}
		case m.spanField:
			value, found := nativeSpanField(p, i)
			if m.re != nil {
				text := ""
				if found {
					text = spanText(value)
				}
				match = m.re.MatchString(text)
			} else if m.Literal.String == "" {
				match = !found
			} else {
				match = found && value == m.span
			}
		default:
			var value Literal
			found := false
			if m.Target == MatchField {
				value, found = nativeValueField(p, i, m.Name)
			}
			if !found {
				value, found = rowField(p, i, kind, m.Target, m.Name)
			}
			if m.re != nil {
				match = value.Kind == LiteralString && m.re.MatchString(value.String)
			} else {
				match = equalLiteral(value, m.Literal)
			}
			if !found && m.re == nil {
				match = m.Literal.Kind == LiteralString && m.Literal.String == ""
			}
		}
		if m.Op == MatchNotEqual || m.Op == MatchNotRegexp {
			match = !match
		}
		if !match {
			return false
		}
	}
	return true
}
func rowField(p Page, i int, kind model.Kind, target MatchTarget, name string) (Literal, bool) {
	v := &p.Values[i]
	labels := p.Resources[i].Labels
	if v.Metric != nil {
		labels = v.Metric.Labels
	}
	if v.Log != nil {
		labels = v.Log.StreamLabels
	}
	if v.Condition != nil {
		labels = v.Condition.Labels
	}
	if target == MatchLabel {
		for _, l := range labels {
			if l.Name == name {
				return Literal{Kind: LiteralString, String: l.Value}, true
			}
		}
		return Literal{Kind: LiteralString}, false
	}
	if v.Log != nil {
		if x, ok := v.Log.Fields[name]; ok {
			return scalarLiteral(x), true
		}
		if x, ok := v.Log.Metadata[name]; ok {
			return scalarLiteral(x), true
		}
	}
	return Literal{Kind: LiteralString}, false
}
func projectionColumns(fields []Field, kind model.Kind) (resource, payload, observed bool) {
	if len(fields) == 0 {
		return true, true, true
	}
	payloadField := FieldMetric + Field(signalCode(kind)-1)
	for _, f := range fields {
		if f == FieldResource {
			resource = true
		}
		if f == payloadField {
			payload = true
		}
		if f == FieldObservedTime {
			observed = true
		}
	}
	return
}
func projectPage(p *Page, fields []Field, kind model.Kind) {
	resource, payload, observed := projectionColumns(fields, kind)
	if !resource {
		clear(p.Resources)
	}
	if !payload {
		clear(p.Values)
	}
	if !observed {
		clear(p.ObservedTimes)
	}
}
func scanColumns(req ScanRequest) (resources, payload bool) {
	resources, payload, _ = projectionColumns(req.Projection, req.Signal)
	for _, m := range req.Selectors {
		if m.Target == MatchLabel {
			if req.Signal == model.Metric || req.Signal == model.Log || req.Signal == model.Condition {
				payload = true
			} else {
				resources = true
			}
			continue
		}
		switch m.Name {
		case "id", "source_id":
		case "service_id", "environment_id", "build_id":
			resources = true
		default:
			payload = true
		}
	}
	return
}

// certifyLocked is the release barrier of a page, EOF or watermark report: the
// quorum barrier over every group of the cut, then the current authorization,
// which is the last word on whether the scope may still read. Authorization is
// judged once, after the barrier (whatever it concluded before the barrier is
// superseded by it), and the deletion predicates it fetched at that point are
// returned for the caller's rebuild check.
func (it *rowIterator) certifyLocked(ctx context.Context, allowEOF bool) ([]model.DeletePredicate, error) {
	if err := it.stateLocked(ctx, allowEOF); err != nil {
		return nil, err
	}
	if err := it.e.replicaReleaseFenceLocked(ctx, it.marks); err != nil {
		return nil, err
	}
	if err := it.stateLocked(ctx, allowEOF); err != nil {
		return nil, err
	}
	return it.authorizeLocked(ctx, allowEOF)
}

// stateLocked is the in-memory judgement of whether the iterator may still be served: its context
// and the request's, the engine, and the iterator itself (closed by a cancellation, a Close or the
// engine while the lock was released), the terminal error of a closed one being the answer.
func (it *rowIterator) stateLocked(ctx context.Context, allowEOF bool) error {
	if ctx.Err() != nil || it.ctx.Err() != nil {
		return model.Fail(model.Cancelled)
	}
	if it.e.closed || it.e.failed {
		return model.Fail(model.Unavailable)
	}
	if it.closed && !(allowEOF && it.terminal == io.EOF) {
		return it.terminal
	}
	return nil
}

// authorizeLocked reads the authority and the deletion predicates the iterator is judged by with e.mu
// released for the control read (a ReadIndex round that can wait seconds), then takes the lock and
// judges, in memory, whether anything that matters moved while it was open: the iterator closed or
// cancelled, the engine closed or failed, a restore gate raised. The answer is used only after that,
// and the local half of the deletion read (tombstones applied on this node) is made under the lock.
// A deletion or a revocation that lands after the read is caught by the release barrier of the page,
// whose own authority read is the last word, exactly as when the lock was held throughout.
func (it *rowIterator) authorizeLocked(ctx context.Context, allowEOF bool) ([]model.DeletePredicate, error) {
	e := it.e
	scope, projects, signal := it.scope, it.req.Projects, it.req.Signal
	control, err := func() ([]model.DeletePredicate, error) {
		e.mu.Unlock()
		defer e.mu.Lock()
		return e.readAuthority(ctx, scope, projects, signal)
	}()
	if serr := it.stateLocked(ctx, allowEOF); serr != nil {
		return nil, serr
	}
	if err != nil {
		return nil, err
	}
	return e.finishReadDeletions(scope.OrgID(), projects, control)
}

// deletionsChanged reports whether the active deletion set differs, which is
// when a page built under the old set can no longer be released as is.
func deletionsChanged(before, after []model.DeletePredicate) bool {
	if len(before) != len(after) {
		return true
	}
	for _, b := range before {
		found := false
		for _, a := range after {
			if a.Operation == b.Operation && reflect.DeepEqual(a, b) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}
