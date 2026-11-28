// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The chunk build of a scan (the index seeks, the page reads and the decode of rowIterator.Next) runs
// under a bolt read transaction and not under the engine lock. A read transaction is a snapshot of the
// file: whatever commits after it began is not seen, so the chunk is judged by one committed state, as the
// lock made it, and what the lock also kept out is made safe by the order of the checks around the build:
//
//   - A deletion that becomes active after the chunk's authority read is caught by the release barrier of
//     the page (certifyLocked), whose own authority read is the last word: a page built under other
//     predicates is built again.
//   - A page that a commit replaced after the snapshot began is named, in the snapshot, by a reference
//     whose file a compaction may have retired or whose payload an erasure may have zeroed since: the
//     read then fails, the reference is looked up again outside the transaction, and a page whose stored
//     reference differs is the one the chunk is built again for, in a new snapshot (the same page-by-page
//     judgement as a first sight of it). A page whose reference is unchanged and unreadable is corrupt.
//   - A decoded page put in the cache by a chunk that began before an erasure dropped it would outlive the
//     erasure: the cache refuses a put whose read snapshot is older than the newest drop (scanPageCache.dropped).
//
// Nothing a chunk build reads is guarded by e.mu: the iterator's request, cut and matchers are copied into
// the job before the lock is released (a Close that runs meanwhile clears the iterator's fields, not the
// copies), the engine's statistics are counted in the result and added under the lock.

// chunkJob is what a chunk build needs of its iterator.
type chunkJob struct {
	ctx, itCtx context.Context
	scope      auth.Scope
	req        ScanRequest
	prefix     []byte
	posting    string
	last       []byte // the index key the previous chunk ended at (nil at the start of a partition)
	visible    map[model.ID]uint64
	after      map[model.ID]uint64
	matchers   []compiledMatcher
	delPreds   []model.DeletePredicate
	// rows is the most rows the chunk holds: pageRows, or more for a scan that asked for larger pages
	// (ScanRequest.MaxPageRows), whose chunk is then bounded in bytes by the distinct pages it reads.
	rows int
}

// chunkResult is what a chunk build found. The statistics are the work of every attempt, failed ones
// included.
type chunkResult struct {
	selected   Page
	chunkBytes uint64
	done       bool   // the partition is read to its end (or past the request's end)
	last       []byte // the index key the chunk ended at, when it did not read the partition to its end
	lookups    uint64
	pagesRead  uint64
	bytesRead  uint64
}

// maxChunkRetries bounds how often a chunk is built again because a page it read was replaced under it.
const maxChunkRetries = 16

// suspectPage is a page whose read failed: it is a replaced page, not a corrupt one, when the row store
// holds another reference for it now.
type suspectPage struct {
	id  model.ID
	raw []byte
}

// buildChunk builds one chunk from a snapshot, again when a page was replaced under it. It must be called
// without e.mu.
func (e *Engine) buildChunk(job *chunkJob) (chunkResult, error) {
	var total chunkResult
	for attempt := 0; ; attempt++ {
		res, suspect, err := e.buildChunkOnce(job)
		total.lookups += res.lookups
		total.pagesRead += res.pagesRead
		total.bytesRead += res.bytesRead
		if err == nil {
			res.lookups, res.pagesRead, res.bytesRead = total.lookups, total.pagesRead, total.bytesRead
			return res, nil
		}
		if suspect == nil || attempt >= maxChunkRetries || !e.pageRefMoved(suspect) {
			return total, err
		}
	}
}

// pageRefMoved reports whether the row store holds another reference for the page now than the one a
// reader failed on. It opens a transaction of its own, so it is never called inside one (a second read
// transaction of a goroutine that holds one waits behind a writer that is remapping the file).
func (e *Engine) pageRefMoved(p *suspectPage) bool {
	moved := false
	_ = e.db.View(func(tx *bolt.Tx) error {
		rows, err := rowsOf(tx)
		if err != nil {
			return err
		}
		moved = !bytes.Equal(rows.Get(tblPages, p.id[:]), p.raw)
		return nil
	})
	return moved
}

func (e *Engine) buildChunkOnce(job *chunkJob) (chunkResult, *suspectPage, error) {
	var res chunkResult
	var suspect *suspectPage
	var selected Page
	var current model.ID
	var decoded Page
	var chunkBytes, distinct uint64
	last := append([]byte(nil), job.last...)
	seq := e.scanPages.begin()
	req := job.req
	local := make(map[model.ID]*chunkPage, 8)
	err := e.db.View(func(tx *bolt.Tx) error {
		res.lookups++
		snapTx := uint64(tx.ID())
		name := "scan_time"
		if job.posting != "" {
			name = "scan_postings"
		}
		rows, err := rowsOf(tx)
		if err != nil {
			return err
		}
		c, err := openScanCursor(tx, name)
		if err != nil {
			return err
		}
		start := append(append([]byte(nil), job.prefix...), timeKey(req.Start)...)
		var k, v []byte
		if len(job.last) > 0 {
			k, v = c.Seek(job.last)
			if bytes.Equal(k, job.last) {
				k, v = c.Next()
			}
		} else {
			k, v = c.Seek(start)
		}
		prefix := job.prefix
		for ; samePrefix(k, prefix); k, v = c.Next() {
			if job.ctx.Err() != nil || job.itCtx.Err() != nil {
				return model.Fail(model.Cancelled)
			}
			if len(k) != len(prefix)+50 || !validIndexValue(k, v) {
				return model.Fail(model.Corrupt)
			}
			suffix := k[len(prefix):]
			at := model.UnixNano(binary.BigEndian.Uint64(suffix) ^ 1<<63)
			if at >= req.End {
				res.done = true
				return nil
			}
			var group model.ID
			copy(group[:], suffix[24:40])
			originIndex := binary.BigEndian.Uint64(suffix[40:48])
			if through, ok := job.after[group]; ok && originIndex <= through {
				last = append(last[:0], k...)
				continue
			}
			if through, ok := job.visible[group]; !ok || originIndex > through {
				last = append(last[:0], k...)
				continue
			}
			if selected.Len() >= job.rows {
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
				// not fit, and this row is then left for the next chunk. A chunk of a scan that
				// asked for larger pages counts each page it draws from once (a page that a
				// chunk alternates with is the same bytes in memory), where the 128-row chunk
				// keeps the count it always had.
				doesNotFit := func(length uint64, known bool) bool {
					if job.rows > pageRows {
						return !known && selected.Len() > 0 && distinct+length > pageByteLimit
					}
					return selected.Len() > 0 && chunkBytes+length > pageByteLimit
				}
				resources, payload := scanColumns(req)
				if entityPredicateActive(job.delPreds) && (req.Signal == model.Replay || req.Signal == model.Profile) {
					payload = true
				}
				if job.scope.Permission() == profilesRead && partitionedSubject(req.Signal) {
					payload = true
				}
				if lp, inChunk := local[id]; inChunk {
					// Verified and decoded earlier in this chunk (the rows of pages that
					// overlap in time alternate in the index): the same checks, the same
					// chunk bounds, without reading, hashing and decoding the page again.
					if doesNotFit(lp.length, true) {
						return nil
					}
					decoded = lp.page
				} else {
					seen, cached, fresh := e.scanPages.get(id, snapTx)
					columns := cached && (seen.resources || !resources) && (seen.payload || !payload)
					if columns && fresh {
						// Decoded by an earlier chunk from a reference that no commit has changed
						// since (scanPageCache.get): the checks of a first sight are made against
						// the identity the entry holds, the row store is not asked.
						if !pageAllowed(job.scope, req.Signal, seen.org, seen.project, seen.source, seen.kind, seen.subject, seen.restricted) {
							return model.Fail(model.Forbidden)
						}
						if !prefixIs(prefix, seen.ns, job.posting) {
							return model.Fail(model.Corrupt)
						}
						if doesNotFit(seen.length, false) {
							return nil
						}
						decoded = seen.page
						e.scanPages.touch(id, seq, snapTx)
						local[id] = &chunkPage{page: decoded, length: seen.length}
						distinct += seen.length
					} else {
						e.scanPages.refLookups.Add(1)
						raw := rows.Get(tblPages, id[:])
						if raw == nil {
							return model.Fail(model.Corrupt)
						}
						ref, err := parsePageRef(raw)
						if err != nil {
							return err
						}
						if !pageAllowed(job.scope, req.Signal, ref.Org, ref.Project, ref.Source, ref.Kind, ref.Subject, ref.Restricted) {
							return model.Fail(model.Forbidden)
						}
						expected := pageNamespace(ref.Org, ref.Project, ref.Kind, ref.Restricted, ref.Source, ref.Subject)
						if job.posting != "" {
							expected = termPrefix(expected, job.posting)
						}
						if !bytes.Equal(expected, prefix) {
							return model.Fail(model.Corrupt)
						}
						if doesNotFit(uint64(ref.Length), false) {
							return nil
						}
						if columns && seen.storedAs(ref) {
							// Decoded by an earlier chunk and stored unchanged since.
							decoded = seen.page
							e.scanPages.touch(id, seq, snapTx)
						} else {
							if hook := scanPageLoadHook.Load(); hook != nil {
								(*hook)()
							}
							decoded, err = e.loadPageColumns(ref, resources, payload)
							if err != nil {
								suspect = &suspectPage{id: id, raw: append([]byte(nil), raw...)}
								return err
							}
							res.pagesRead++
							res.bytesRead += decoded.Bytes
							e.scanPages.put(id, seq, snapTx, ref, resources, payload, decoded)
						}
						local[id] = &chunkPage{page: decoded, length: uint64(ref.Length)}
						distinct += uint64(ref.Length)
					}
				}
				current = id
				chunkBytes += decoded.Bytes
			}
			last = append(last[:0], k...)
			row := int(binary.BigEndian.Uint16(v[16:18]))
			if row >= decoded.Len() {
				return model.Fail(model.Corrupt)
			}
			origin := decoded.Origins[row]
			if decoded.Times[row] != at || !bytes.Equal(decoded.IDs[row][:], suffix[8:24]) || origin.Group != group || uint64(origin.Index) != originIndex {
				return model.Fail(model.Corrupt)
			}
			if !coveredRow(job.delPreds, job.scope.OrgID(), req.Signal, decoded, row) && matchesRow(job.matchers, decoded, row, req.Signal) {
				if selected.IDs == nil {
					// The chunk holds at most job.rows rows: one allocation of that size, where the
					// rows appended one by one from pages of 128 grew the nine columns by doubling.
					selected = allocatePage(job.rows)
				}
				appendPageRow(&selected, decoded, row)
			}
		}
		res.done = true
		return nil
	})
	if err != nil {
		return res, suspect, err
	}
	res.selected, res.chunkBytes = selected, chunkBytes
	if !res.done {
		res.last = last
	}
	return res, nil, nil
}

// buildUnlocked builds a chunk with e.mu released (the caller holds it, and holds it again on return), adds
// the work the build counted to the engine's statistics, and judges under the lock, in memory, whether the
// iterator may still be served: it may have been closed or cancelled, or the engine closed or failed, while
// the lock was released (the answer of the build is then the state's, not the build's).
func (it *rowIterator) buildUnlocked(job *chunkJob) (chunkResult, error) {
	e := it.e
	res, err := func() (chunkResult, error) {
		e.mu.Unlock()
		defer e.mu.Lock()
		return e.buildChunk(job)
	}()
	e.storageStats.IndexLookups += res.lookups
	e.storageStats.PagesRead += res.pagesRead
	e.storageStats.BytesRead += res.bytesRead
	if serr := it.stateLocked(job.ctx, false); serr != nil {
		return chunkResult{}, serr
	}
	return res, err
}

// chunkPage is a page a chunk has judged and decoded, kept for the rows of the chunk that come from it.
type chunkPage struct {
	page   Page
	length uint64 // the encoded length, as its reference gives it
}

// pageAllowed is the scope's judgement of a page by its identity: the organization, the signal, the
// project, the restricted-source form and the subject.
func pageAllowed(scope auth.Scope, signal model.Kind, org, project, source model.ID, kind, subject model.Kind, restricted bool) bool {
	return org == scope.OrgID() && kind == signal && scope.AllowsProject(project) && restricted == (scope.Permission() == auth.RawRead) && (!restricted || scope.AllowsSource(source)) && allowsSubject(scope, kind, subject)
}

// prefixIs reports whether prefix is the index prefix of the page namespace ns, with the posting term when
// the scan reads postings: bytes.Equal(termPrefix(ns, term), prefix) without building the prefix.
func prefixIs(prefix, ns []byte, term string) bool {
	if term == "" {
		return bytes.Equal(prefix, ns)
	}
	if len(prefix) != len(ns)+4+len(term) || !bytes.HasPrefix(prefix, ns) {
		return false
	}
	return binary.BigEndian.Uint32(prefix[len(ns):]) == uint32(len(term)) && string(prefix[len(ns)+4:]) == term
}
