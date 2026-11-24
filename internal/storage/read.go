// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
	"io"
	"reflect"
	"regexp"
	"sync"
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
// window, which at that gate is ten queries a second over 190 pages a project. A chunk is one read
// transaction under the engine lock; a page the chunk meets for the first time is looked up again in
// that transaction and judged by the same checks as a page that was never seen, and its decode is
// reused only when the stored page is the one that was decoded, in the same place (the content hash of
// its reference, which any rewrite of the page, erasure included, changes, and its location, which a
// flush or a compaction changes) and carries the columns the chunk needs.
// The deletion predicates are applied to every row at selection. A page that erasure deletes is
// dropped from the cache in the same transaction (deleteBatchIndex): no decoded copy of erased bytes
// outlives the erasure. The cache is for readers of this engine only and is never persisted.
type scanPageCache struct {
	mu    sync.Mutex
	seq   uint64 // the last chunk begun
	byID  map[model.ID]*list.Element
	lru   list.List // of *cachedPage, front = used last
	bytes uint64    // encoded bytes of the cached pages
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
	resources bool       // the decode carries the resource columns
	payload   bool       // the decode carries the payload columns
	page      Page
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

// begin numbers the chunk that starts.
func (c *scanPageCache) begin() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	return c.seq
}
func (c *scanPageCache) get(id model.ID) (cachedPage, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byID[id]
	if !ok {
		return cachedPage{}, false
	}
	c.lru.MoveToFront(el)
	return *el.Value.(*cachedPage), true
}

// touch records that chunk seq looked the page up in its transaction and found it unchanged.
func (c *scanPageCache) touch(id model.ID, seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byID[id]; ok {
		el.Value.(*cachedPage).seq = seq
	}
}
func (c *scanPageCache) put(id model.ID, seq uint64, ref pageRef, resources, payload bool, page Page) {
	if page.Bytes > scanPageCacheBytes/4 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(id)
	if c.byID == nil {
		c.byID = make(map[model.ID]*list.Element)
	}
	c.byID[id] = c.lru.PushFront(&cachedPage{id: id, length: uint64(ref.Length), hash: ref.Hash, segment: ref.Segment, offset: ref.Offset, hot: len(ref.Hot) > 0, log: string(ref.Log), seq: seq, resources: resources, payload: payload, page: page})
	c.bytes += page.Bytes
	for c.bytes > scanPageCacheBytes {
		c.removeLocked(c.lru.Back().Value.(*cachedPage).id)
	}
}

// drop forgets a page whose stored bytes are gone.
func (c *scanPageCache) drop(id model.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	holder := e.tomb.view.Load()
	if holder == nil {
		return nil, nil
	}
	preds, err := holder.view.ActiveDeletions(ctx, s.OrgID(), projects)
	if err != nil {
		return nil, err
	}
	var out []model.DeletePredicate
	clear(seen)
	for _, p := range preds {
		if p.Validate() != nil {
			return nil, model.Fail(model.Corrupt)
		}
		if p.Org == s.OrgID() && !seen[p.Operation] {
			seen[p.Operation] = true
			out = append(out, p)
		}
	}
	return out, nil
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
	if !req.Signal.Valid() || req.End < req.Start {
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
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return nil, model.Fail(model.Unavailable)
	}
	if ctx.Err() != nil {
		return nil, model.Fail(model.Cancelled)
	}
	if _, err = e.finishReadDeletions(scope.OrgID(), req.Projects, control); err != nil {
		return nil, err
	}
	if e.storageStats.ActiveIterators >= 32 {
		return nil, model.Fail(model.TooLarge)
	}
	term := postingTerm(req.Selectors, req.Signal)
	if term != "" {
		for i, prefix := range prefixes {
			prefixes[i] = termPrefix(prefix, term)
		}
	}
	it := &rowIterator{e: e, scope: scope, req: req, prefixes: prefixes, marks: marks, visible: visibleThrough(marks), after: after, matchers: ms, ctx: ctx, posting: term, partial: partial}
	e.scans[it] = struct{}{}
	e.storageStats.ActiveIterators++
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
	// A chunk below starts with one authority read that also returns the deletion predicates it
	// filters with, so this one is only the check a Next with no chunk left to build is judged by
	// before its barrier: when a chunk is built it would be replaced at once by the chunk's own
	// read, which fails with the same error and closes the iterator the same way.
	if it.partition >= len(it.prefixes) {
		if _, err := it.authorizeLocked(ctx, false); err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
	}
	for it.partition < len(it.prefixes) {
		// Predicates are fetched fresh when a chunk starts (the authority read already ends in the
		// deletion read, so there is no second one); the release barrier then fetches them again
		// and the chunk is rebuilt if they differ. The read waits on the control state with e.mu
		// released and is judged again under it (authorizeLocked) before the chunk reads the data.
		delPreds, err := it.authorizeLocked(ctx, false)
		if err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
		prefix := it.prefixes[it.partition]
		var selected Page
		var current model.ID
		var decoded Page
		var chunkBytes uint64
		startPartition, startLast := it.partition, append([]byte(nil), it.last...)
		seq := e.scanPages.begin()
		err = e.db.View(func(tx *bolt.Tx) error {
			e.storageStats.IndexLookups++
			name := "scan_time"
			if it.posting != "" {
				name = "scan_postings"
			}
			rows, err := rowsOf(tx)
			if err != nil {
				return err
			}
			c, err := openOrderedCursor(tx, name)
			if err != nil {
				return err
			}
			start := append(append([]byte(nil), prefix...), timeKey(it.req.Start)...)
			var k, v []byte
			if len(it.last) > 0 {
				k, v = c.Seek(it.last)
				if bytes.Equal(k, it.last) {
					k, v = c.Next()
				}
			} else {
				k, v = c.Seek(start)
			}
			for ; samePrefix(k, prefix); k, v = c.Next() {
				if ctx.Err() != nil || it.ctx.Err() != nil {
					return model.Fail(model.Cancelled)
				}
				if len(k) != len(prefix)+50 || !validIndexValue(k, v) {
					return model.Fail(model.Corrupt)
				}
				suffix := k[len(prefix):]
				at := model.UnixNano(binary.BigEndian.Uint64(suffix) ^ 1<<63)
				if at >= it.req.End {
					it.partition++
					it.last = nil
					return nil
				}
				var group model.ID
				copy(group[:], suffix[24:40])
				originIndex := binary.BigEndian.Uint64(suffix[40:48])
				if through, ok := it.after[group]; ok && originIndex <= through {
					it.last = append(it.last[:0], k...)
					continue
				}
				if through, ok := it.visible[group]; !ok || originIndex > through {
					it.last = append(it.last[:0], k...)
					continue
				}
				if selected.Len() >= pageRows {
					// The chunk is full and this row is left for the next one. The bound is on the rows
					// the chunk holds, not on the stored rows of the pages they come from: counting the
					// latter closed a chunk at every alternation between two pages.
					return nil
				}
				var id model.ID
				copy(id[:], v[:16])
				if id != current {
					// A chunk spans batches, because every release costs a quorum
					// barrier. It stays within the page bounds (128 rows, 4 MiB):
					// it is closed before this batch's page when its bytes could
					// not fit, and this row is then left for the next chunk.
					doesNotFit := func(length uint64) bool {
						return selected.Len() > 0 && chunkBytes+length > pageByteLimit
					}
					resources, payload := scanColumns(it.req)
					if entityPredicateActive(delPreds) && (it.req.Signal == model.Replay || it.req.Signal == model.Profile) {
						payload = true
					}
					if it.scope.Permission() == profilesRead && partitionedSubject(it.req.Signal) {
						payload = true
					}
					if seen, ok := e.scanPages.get(id); ok && seen.seq == seq {
						// Verified and decoded earlier in this chunk (the rows of pages that
						// overlap in time alternate in the index): the same checks, the same
						// chunk bounds, without reading, hashing and decoding the page again.
						if doesNotFit(seen.length) {
							return nil
						}
						decoded = seen.page
					} else {
						raw := rows.Get(tblPages, id[:])
						if raw == nil {
							return model.Fail(model.Corrupt)
						}
						ref, err := parsePageRef(raw)
						if err != nil {
							return err
						}
						if ref.Org != it.scope.OrgID() || ref.Kind != it.req.Signal || !it.scope.AllowsProject(ref.Project) || ref.Restricted != (it.scope.Permission() == auth.RawRead) || ref.Restricted && !it.scope.AllowsSource(ref.Source) || !allowsSubject(it.scope, ref.Kind, ref.Subject) {
							return model.Fail(model.Forbidden)
						}
						expected := pageNamespace(ref.Org, ref.Project, ref.Kind, ref.Restricted, ref.Source, ref.Subject)
						if it.posting != "" {
							expected = termPrefix(expected, it.posting)
						}
						if !bytes.Equal(expected, prefix) {
							return model.Fail(model.Corrupt)
						}
						if doesNotFit(uint64(ref.Length)) {
							return nil
						}
						if ok && seen.storedAs(ref) && (seen.resources || !resources) && (seen.payload || !payload) {
							// Decoded by an earlier chunk and stored unchanged since.
							decoded = seen.page
							e.scanPages.touch(id, seq)
						} else {
							decoded, err = e.readPageColumns(ref, resources, payload)
							if err != nil {
								return err
							}
							e.scanPages.put(id, seq, ref, resources, payload, decoded)
						}
					}
					current = id
					chunkBytes += decoded.Bytes
				}
				it.last = append(it.last[:0], k...)
				row := int(binary.BigEndian.Uint16(v[16:18]))
				if row >= decoded.Len() {
					return model.Fail(model.Corrupt)
				}
				origin := decoded.Origins[row]
				if decoded.Times[row] != at || !bytes.Equal(decoded.IDs[row][:], suffix[8:24]) || origin.Group != group || uint64(origin.Index) != originIndex {
					return model.Fail(model.Corrupt)
				}
				if !coveredRow(delPreds, it.scope.OrgID(), it.req.Signal, decoded, row) && matchesRow(it.matchers, decoded, row, it.req.Signal) {
					appendPageRow(&selected, decoded, row)
				}
			}
			it.partition++
			it.last = nil
			return nil
		})
		if err != nil {
			it.terminal = err
			it.closeLocked()
			return Page{}, err
		}
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
