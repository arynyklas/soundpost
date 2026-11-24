// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// EraseReport counts what one erasure pass physically removed. Held counts records and
// artifact roots a guard refused to erase; they stay physically present. PagesScrubbed is the
// number of free bbolt pages zeroed; ScrubPending means a scrub is still owed (a reader that
// may still walk a freed page was open): the erased bytes can remain in free pages of apply.db
// until a later pass finishes it, so the pass is not a physical-erasure success.
type EraseReport struct {
	Batches, Records, Pages, Blobs, Held uint64
	SegmentsRewritten                    uint64
	PagesScrubbed                        uint64
	ScrubPending                         bool
}

// EraseCandidate is one record or artifact root a pass wants to remove. Deadline is the
// receipt deadline of the record's kind (0 for deletion-driven erasure).
type EraseCandidate struct {
	Org, Project model.ID
	Slot         uint16
	Cursor       model.Cursor        // origin cursor of the batch (artifact: the root's last fragment)
	Kind         model.Kind          // empty for artifact roots
	Deadline     model.UnixNano      // the receipt deadline for this kind (0 for deletion-driven erasure)
	Record       *model.Record       // nil for blobs
	Blob         *model.BlobManifest // non-nil for artifact roots
	// Final is set when the guard is consulted a second time, inside the erasing write
	// transaction (under the engine lock), immediately before the candidate's bytes are
	// removed. See EraseGuard.
	Final bool
	// Sync is set on the consultation made once per erasing transaction, outside every lock,
	// right before the transaction starts (see syncGuard). The guard may take as long as a
	// network round trip to answer it; its answer is ignored except for an error.
	Sync bool
}

// EraseGuard is how holds, reference counting and the evidence gate veto physical removal.
// Returning an error aborts the pass fail-closed: nothing the guard has not allowed is erased.
//
// A guard is consulted twice for a candidate it allows: during the candidate scan (outside any
// lock; it may be slow: reference counts, processing checkpoints) and again with Final set,
// inside the write transaction that erases the candidate, under the engine lock. The second
// consultation exists so a veto that became true after the scan (a legal hold placed while a
// pass was running) is honoured at the instant the bytes would be destroyed; a vetoed
// candidate is counted in EraseReport.Held and stays. A Final call must therefore be cheap,
// must answer from current state rather than from what the scan saw, and must not call back
// into the Engine. Between the two, right before each erasing transaction takes the engine lock,
// the guard is consulted once more with Sync set (see syncGuard): that call may block on a
// linearizable read, so that the Final call can stay local and still see every veto that was
// acknowledged before the transaction began.
type EraseGuard func(ctx context.Context, c EraseCandidate) (allow bool, err error)

// syncGuard consults the guard with Sync set, once per erasing transaction, before the engine
// lock is taken. The guard may block here (a linearizable read of the control group): it must,
// so that the cheap Final consultation that follows inside the transaction answers from state
// that includes every veto acknowledged before this call. Only the error counts: a guard that
// cannot establish current state aborts the pass (fail closed) and nothing in the transaction
// is erased; the veto itself is decided by the Final consultation.
func syncGuard(ctx context.Context, guard EraseGuard, c EraseCandidate) error {
	c.Sync = true
	_, err := guard(ctx, c)
	return err
}

type eraseSelector struct {
	operations []model.ID
	record     func(org, project model.ID, r model.Record, receipt model.Receipt) (bool, model.UnixNano)
	blob       func(m model.BlobManifest) (bool, model.UnixNano)
	// skip, when set, rules a stored batch command out from its bytes alone (true: nothing in it can match), which spares its decode.
	// It must never say true for a command record would select: a false answer only costs the decode.
	skip func(raw []byte) bool
}

// eraseScanChunk is how many stored commands one read transaction of the candidate scan covers (see eraseCandidates).
var eraseScanChunk = 512

type eraseBatchJob struct {
	slot  uint16
	index uint64
	sum   model.Hash
	erase map[model.ID]bool
	cands []EraseCandidate // the allowed candidates of erase, consulted again at erase time
}
type eraseBlobJob struct {
	key, raw []byte
	receipt  model.BlobReceipt
	cand     EraseCandidate
}

// EraseDeleted physically removes every record and artifact root covered by any predicate
// unless the guard vetoes it. It does not decide that a deletion is allowed or complete: the
// caller (the retention saga) owns that; this is the byte-level effect.
func (e *Engine) EraseDeleted(ctx context.Context, preds []model.DeletePredicate, guard EraseGuard) (EraseReport, error) {
	ops := make([]model.ID, 0, len(preds))
	for _, p := range preds {
		if err := p.Validate(); err != nil {
			return EraseReport{}, err
		}
		ops = append(ops, p.Operation)
	}
	if err := e.noteEraseStart(preds); err != nil {
		return EraseReport{}, err
	}
	return e.erase(ctx, eraseSelector{
		operations: ops,
		record: func(org, project model.ID, r model.Record, _ model.Receipt) (bool, model.UnixNano) {
			for _, p := range preds {
				if p.CoversRecord(org, project, r) {
					return true, 0
				}
			}
			return false, 0
		},
		blob: func(m model.BlobManifest) (bool, model.UnixNano) {
			for _, p := range preds {
				if p.CoversBlob(m) {
					return true, 0
				}
			}
			return false, 0
		},
	}, guard)
}

// EraseExpired removes records whose receipt deadline for their kind is <= now, and artifact
// roots whose manifest deadline is <= now. Receipts are never read for any other purpose, never
// rewritten, and a deadline is never shortened: a kind with no deadline is never expired.
func (e *Engine) EraseExpired(ctx context.Context, now model.UnixNano, guard EraseGuard) (EraseReport, error) {
	return e.erase(ctx, eraseSelector{
		record: func(_, _ model.ID, r model.Record, receipt model.Receipt) (bool, model.UnixNano) {
			for _, d := range receipt.SignalDeadlines {
				if d.Kind == r.Kind && d.RetainUntil != 0 && d.RetainUntil <= now {
					return true, d.RetainUntil
				}
			}
			return false, 0
		},
		blob: func(m model.BlobManifest) (bool, model.UnixNano) {
			return m.RetainUntil != 0 && m.RetainUntil <= now, m.RetainUntil
		},
	}, guard)
}

var batchCommandPrefix = []byte(`{"type":"batch`) // batch and batch_redacted; never parse artifact commands

func (e *Engine) erase(ctx context.Context, sel eraseSelector, guard EraseGuard) (EraseReport, error) {
	var report EraseReport
	if guard == nil {
		guard = func(context.Context, EraseCandidate) (bool, error) { return true, nil }
	}
	batches, blobs, held, err := e.eraseCandidates(ctx, sel, guard)
	if err != nil {
		return report, err
	}
	report.Held = held
	for _, job := range batches {
		if err = ctx.Err(); err != nil {
			return report, model.Fail(model.Cancelled)
		}
		records, pages, held, err := e.eraseBatch(ctx, guard, job, sel.operations)
		if err != nil {
			return report, err
		}
		report.Held += held
		if records > 0 {
			report.Batches++
			report.Records += records
			report.Pages += pages
		}
	}
	for _, job := range blobs {
		if err = ctx.Err(); err != nil {
			return report, model.Fail(model.Cancelled)
		}
		erased, held, err := e.eraseBlob(ctx, guard, job, sel.operations)
		if err != nil {
			return report, err
		}
		report.Held += held
		if erased {
			report.Blobs++
		}
	}
	// The stored commands are redacted; the replication layer keeps its own copy of every
	// committed command (retry table, journal, pin archives) and is told to forget the same
	// bytes before the segment rewrite, the scrub and the snapshot cuts that follow.
	if err = e.redactReplica(ctx); err != nil {
		return report, err
	}
	if report.Batches > 0 || report.Blobs > 0 || e.hasStaleSegments() {
		if report.SegmentsRewritten, err = e.rewriteStaleSegments(ctx); err != nil {
			return report, err
		}
	}
	// The bucket-level erasure and the segment rewrite leave the erased bytes in bbolt's free
	// pages; whether a scrub is owed is durable (set by the erasing transaction), so a crash
	// here, or a rerun that finds nothing left to erase, still completes it.
	if report.PagesScrubbed, report.ScrubPending, err = e.scrubFreePages(ctx); err != nil {
		return report, err
	}
	return report, nil
}

// scanChunks walks bucket in read transactions of at most eraseScanChunk keys each (and eraseScanBytes of values), every one resuming after
// the last key of the one before. A read transaction blocks the remap of the apply database, and a write that has to grow the mapping
// waits for every open reader and holds each new transaction behind it: one transaction over the whole history stopped every
// acknowledgement for as long as the scan lasted (the journal-expiry plan at the single-host load, L2w20Admission22: 40 s at the 15th
// minute, 80 s at the 30th). The view of the bucket is therefore not one snapshot: a command appended meanwhile is seen or not, and
// one a redaction rewrites is seen before or after it, which the callers accept (the write phase of an erasure re-verifies each command
// by digest; a plan only lists). The chunk is copied and fn runs after its transaction ended: a callback that follows a payload
// reference reads the disk, which no read transaction waits for (command_source.go). fn gets keys and values valid only during the call.
func (e *Engine) scanChunks(ctx context.Context, bucket string, fn func(k, v []byte) error) error {
	return e.scanChunksRange(ctx, bucket, nil, nil, fn)
}

// eraseScanBytes bounds the values one chunk of scanChunksRange copies.
const eraseScanBytes = 4 << 20

// scanChunksRange is scanChunks over the keys from from (the first key when nil) up to, not including, to (the last key when nil).
func (e *Engine) scanChunksRange(ctx context.Context, bucket string, from, to []byte, fn func(k, v []byte) error) error {
	var after []byte
	started := false
	type entry struct{ k0, k1, v1 int }
	for {
		if err := ctx.Err(); err != nil {
			return model.Fail(model.Cancelled)
		}
		more := false
		var buf []byte
		var chunk []entry
		err := e.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(bucket))
			if b == nil {
				return model.Fail(model.Corrupt)
			}
			c := b.Cursor()
			var k, v []byte
			if from != nil {
				k, v = c.Seek(from)
			} else {
				k, v = c.First()
			}
			if started {
				if k, v = c.Seek(after); k != nil && bytes.Equal(k, after) {
					k, v = c.Next()
				}
			}
			for ; k != nil && (to == nil || bytes.Compare(k, to) < 0); k, v = c.Next() {
				if len(chunk) == eraseScanChunk || len(buf) >= eraseScanBytes {
					more = true
					return nil
				}
				k0 := len(buf)
				buf = append(buf, k...)
				k1 := len(buf)
				buf = append(buf, v...)
				chunk = append(chunk, entry{k0, k1, len(buf)})
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, en := range chunk {
			k, v := buf[en.k0:en.k1:en.k1], buf[en.k1:en.v1:en.v1]
			after, started = append(after[:0], k...), true
			if err := fn(k, v); err != nil {
				return err
			}
		}
		if !more {
			return nil
		}
	}
}

// eraseCandidates reads (without e.mu: bolt reads are snapshots) which commands and artifact
// roots match, then asks the guard outside any lock. The write phase re-verifies each command
// by digest, so a change between the two phases can only skip work, never erase the wrong bytes.
func (e *Engine) eraseCandidates(ctx context.Context, sel eraseSelector, guard EraseGuard) ([]eraseBatchJob, []eraseBlobJob, uint64, error) {
	type pending struct {
		job   eraseBatchJob
		cands []EraseCandidate
	}
	var pend []pending
	var blobCands []EraseCandidate
	var blobJobs []eraseBlobJob
	err := e.scanChunks(ctx, "replica_commands", func(k, raw []byte) error {
		if isPayloadRef(raw) {
			if raw = storedFromDBCold(e.db.DB, raw); raw == nil {
				return model.Fail(model.Corrupt) // a candidate that cannot be read is never skipped
			}
		}
		if len(k) != 10 || !bytes.HasPrefix(raw, batchCommandPrefix) {
			return nil
		}
		if sel.skip != nil && sel.skip(raw) {
			return nil
		}
		var entry walEntry
		if err := json.Unmarshal(raw, &entry); err != nil || entry.Batch == nil || entry.Receipt == nil {
			return model.Fail(model.Corrupt)
		}
		slot := binary.BigEndian.Uint16(k[:2])
		var cands []EraseCandidate
		for i := range entry.Batch.Records {
			r := entry.Batch.Records[i]
			if match, deadline := sel.record(entry.Batch.Org, entry.Batch.Project, r, *entry.Receipt); match {
				cands = append(cands, EraseCandidate{Org: entry.Batch.Org, Project: entry.Batch.Project, Slot: slot, Cursor: entry.Receipt.Cursor, Kind: r.Kind, Deadline: deadline, Record: &r})
			}
		}
		if len(cands) > 0 {
			pend = append(pend, pending{job: eraseBatchJob{slot: slot, index: binary.BigEndian.Uint64(k[2:]), sum: model.HashCanonical(raw), erase: map[model.ID]bool{}}, cands: cands})
		}
		return nil
	})
	if err == nil {
		err = e.scanChunks(ctx, "artifact_roots", func(k, raw []byte) error {
			var r model.BlobReceipt
			if err := model.StrictJSON(raw, &r); err != nil {
				return model.Fail(model.Corrupt)
			}
			match, deadline := sel.blob(r.Manifest)
			if !match {
				return nil
			}
			m := r.Manifest
			blobCands = append(blobCands, EraseCandidate{Org: m.Org, Project: m.Project, Slot: model.BlobOwnerSlot(m.Org, m.Project, m.Root), Cursor: r.Cursor, Deadline: deadline, Blob: &m})
			blobJobs = append(blobJobs, eraseBlobJob{key: bytes.Clone(k), raw: bytes.Clone(raw), receipt: r})
			return nil
		})
	}
	if err != nil {
		return nil, nil, 0, err
	}
	var held uint64
	var jobs []eraseBatchJob
	for _, p := range pend {
		for _, c := range p.cands {
			allow, err := guard(ctx, c)
			if err != nil {
				return nil, nil, 0, err
			}
			if !allow {
				held++
				continue
			}
			p.job.erase[c.Record.ID] = true
			p.job.cands = append(p.job.cands, c)
		}
		if len(p.job.erase) > 0 {
			jobs = append(jobs, p.job)
		}
	}
	var blobs []eraseBlobJob
	for i, c := range blobCands {
		allow, err := guard(ctx, c)
		if err != nil {
			return nil, nil, 0, err
		}
		if !allow {
			held++
			continue
		}
		blobJobs[i].cand = c
		blobs = append(blobs, blobJobs[i])
	}
	return jobs, blobs, held, nil
}

func (e *Engine) eraseBatch(ctx context.Context, guard EraseGuard, job eraseBatchJob, ops []model.ID) (records, pages, held uint64, err error) {
	if len(job.cands) > 0 {
		if err = syncGuard(ctx, guard, job.cands[0]); err != nil {
			return 0, 0, 0, err
		}
	}
	e.cutMu.Lock() // a snapshot cut derives its windows from the stored commands without mu: not while one is rewritten
	defer e.cutMu.Unlock()
	defer e.dropWindowCaches() // after the rewrite, still under cutMu: a cache built while it ran is never the current epoch's
	e.dropWindowCaches()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return 0, 0, 0, model.Fail(model.Unavailable)
	}
	err = e.db.Update(func(tx *bolt.Tx) error {
		// The decision to erase is taken again here, under the engine lock and the write
		// transaction, so a hold that committed after the candidate scan still wins.
		for _, c := range job.cands {
			c.Final = true
			allow, err := guard(ctx, c)
			if err != nil {
				return err
			}
			if !allow {
				delete(job.erase, c.Record.ID)
				held++
			}
		}
		if len(job.erase) == 0 {
			return nil
		}
		var err error
		records, pages, err = e.eraseBatchTx(tx, job, ops)
		return err
	})
	if err != nil {
		return 0, 0, 0, err
	}
	if records > 0 {
		e.markRedact(job.slot) // after the commit: the reconcile that clears the mark must see it
	}
	return records, pages, held, nil
}

// eraseBatchTx is one atomic transaction: derived rows, pages and index entries of the batch,
// then the stored command, change together or not at all. A trip hook returning an error rolls
// the whole transaction back, which is what a crash at that point does.
func (e *Engine) eraseBatchTx(tx *bolt.Tx, job eraseBatchJob, ops []model.ID) (records, pages uint64, err error) {
	commands := tx.Bucket([]byte("replica_commands"))
	commandRef := commands.Get(commandKey(job.slot, job.index))
	raw := storedValue(commands, commandRef)
	if raw == nil || model.HashCanonical(raw) != job.sum {
		return 0, 0, nil // already redacted or replaced since the candidate scan
	}
	var entry walEntry
	if err = json.Unmarshal(raw, &entry); err != nil || entry.Batch == nil || entry.Receipt == nil {
		return 0, 0, model.Fail(model.Corrupt)
	}
	b, receipt := *entry.Batch, *entry.Receipt
	key := batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID)
	storedRef, err := tableGet(tx, tblBatches, key)
	if err != nil {
		return 0, 0, err
	}
	stored := storedTx(tx, storedRef)
	var rows []model.Record
	if stored == nil || json.Unmarshal(stored, &rows) != nil {
		return 0, 0, model.Fail(model.Corrupt)
	}
	keptCommand := make([]model.Record, 0, len(b.Records))
	for _, r := range b.Records {
		if job.erase[r.ID] {
			records++
		} else {
			keptCommand = append(keptCommand, r)
		}
	}
	keptRows := make([]model.Record, 0, len(rows))
	for _, r := range rows {
		if !job.erase[r.ID] {
			keptRows = append(keptRows, r)
			continue
		}
		if err = eraseDerived(tx, b, r); err != nil {
			return 0, 0, err
		}
	}
	if pages, err = e.deleteBatchIndex(tx, b, receipt, rows); err != nil {
		return 0, 0, err
	}
	raw2, err := json.Marshal(keptRows)
	if err != nil {
		return 0, 0, err
	}
	rs, err := rowsOf(tx)
	if err != nil {
		return 0, 0, err
	}
	if err = rs.Set(tblBatches, key, raw2); err != nil {
		return 0, 0, err
	}
	if err = owePayloadScrub(tx, storedRef); err != nil { // the records the row named are zeroed in the log
		return 0, 0, err
	}
	e.commitRewrites++ // under e.mu (eraseBatch): a live walk of this commit sees it before it takes another page
	if err = e.indexAppliedRows(tx, b, receipt, keptRows); err != nil {
		return 0, 0, err
	}
	if err = e.trip("erase_batch"); err != nil {
		return 0, 0, err
	}
	redacted, err := redactBatch(raw, entry, keptCommand, records, ops)
	if err != nil {
		return 0, 0, err
	}
	if err = commands.Put(commandKey(job.slot, job.index), redacted); err != nil {
		return 0, 0, err
	}
	if err = owePayloadScrub(tx, commandRef); err != nil {
		return 0, 0, err
	}
	if err = dropWindowTx(tx, job.slot, job.index); err != nil { // the sealed-window record no longer describes this command
		return 0, 0, err
	}
	if err = e.markScrubPendingTx(tx); err != nil {
		return 0, 0, err
	}
	if err = stampRedactFloorTx(tx, job.slot); err != nil {
		return 0, 0, err
	}
	if err = e.trip("erase_redacted"); err != nil {
		return 0, 0, err
	}
	return records, pages, nil
}

// eraseDerived drops the per-record derived state that holds the erased payload: the metric
// dedupe value and the job attempt row. A value is removed only if it is still this record's,
// so a newer kept record that replaced it is never lost.
func eraseDerived(tx *bolt.Tx, b model.NormalizedBatch, r model.Record) error {
	switch r.Kind {
	case model.Metric:
		k := metricKey(b, r)
		v, err := model.CanonicalJSON(r.Payload.Metric)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		rs, err := rowsOf(tx)
		if err != nil {
			return err
		}
		if bytes.Equal(rs.Get(tblMetrics, k), v) {
			_, err = rs.Delete(tblMetrics, k)
			return err
		}
	case model.JobAttempt:
		k := jobKey(b, r.Payload.Job)
		v, err := json.Marshal(r.Payload.Job)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		if bucket := tx.Bucket([]byte("jobs")); bytes.Equal(bucket.Get(k), v) {
			return bucket.Delete(k)
		}
	}
	return nil
}

// batchIndexKeys re-derives, with the exact page grouping and key layout of indexAppliedRows,
// every scan_time key, scan_postings key and page ID the rows of one batch were indexed under.
func batchIndexKeys(b model.NormalizedBatch, receipt model.Receipt, rows []model.Record) (timeKeys, postingKeys [][]byte, pageIDs []model.ID) {
	for _, kind := range signalKinds {
		for _, raw := range []bool{false, true} {
			for _, subject := range storageSubjects(kind) {
				var selected []model.Record
				chunk := 0
				flush := func() {
					if len(selected) == 0 {
						return
					}
					identity := model.HashCanonical([]byte(fmt.Sprintf("%s:%s:%s:%s:%d:%s:%s:%t:%d", b.Org, b.Project, b.ID, receipt.Cursor.Group, receipt.Cursor.Index, kind, subject, raw, chunk)))
					var id model.ID
					copy(id[:], identity[:16])
					prefix := pageNamespace(b.Org, b.Project, kind, raw, b.Source, subject)
					for i, r := range selected {
						key := append(append([]byte(nil), prefix...), timeKey(signalTime(r))...)
						key = append(key, r.ID[:]...)
						key = append(key, receipt.Cursor.Group[:]...)
						var tail [10]byte
						binary.BigEndian.PutUint64(tail[:8], uint64(receipt.Cursor.Index))
						binary.BigEndian.PutUint16(tail[8:], uint16(i))
						key = append(key, tail[:]...)
						timeKeys = append(timeKeys, key)
						for _, term := range recordTerms(r) {
							pk := termPrefix(prefix, term)
							postingKeys = append(postingKeys, append(pk, key[len(prefix):]...))
						}
					}
					pageIDs = append(pageIDs, id)
					selected = selected[:0]
					chunk++
				}
				for _, r := range rows {
					restricted := r.Payload.Log != nil && r.Payload.Log.SourceClass == "restricted_raw"
					if r.Kind != kind || restricted != raw || recordSubject(r) != subject {
						continue
					}
					selected = append(selected, r)
					if len(selected) == pageRows {
						flush()
					}
				}
				flush()
			}
		}
	}
	return
}

// deleteBatchIndex removes the batch's pages and index entries, keeping scan_integrity exact.
func (e *Engine) deleteBatchIndex(tx *bolt.Tx, b model.NormalizedBatch, receipt model.Receipt, rows []model.Record) (uint64, error) {
	timeKeys, postingKeys, pageIDs := batchIndexKeys(b, receipt, rows)
	index, err := newIndexWriter(tx, "scan_time")
	if err != nil {
		return 0, err
	}
	postings, err := newIndexWriter(tx, "scan_postings")
	if err != nil {
		return 0, err
	}
	// indexAppliedRows puts a key once even when a record yields the same term twice, so the
	// entry exists once: delete each distinct key exactly once.
	for _, set := range []struct {
		w    *indexWriter
		keys [][]byte
	}{{index, timeKeys}, {postings, postingKeys}} {
		seen := make(map[string]struct{}, len(set.keys))
		for _, k := range set.keys {
			if _, dup := seen[string(k)]; dup {
				continue
			}
			seen[string(k)] = struct{}{}
			if err = set.w.delete(k); err != nil {
				return 0, err
			}
		}
	}
	if err = index.finish(); err != nil {
		return 0, err
	}
	if err = postings.finish(); err != nil {
		return 0, err
	}
	rs, err := rowsOf(tx)
	if err != nil {
		return 0, err
	}
	for _, id := range pageIDs {
		if old := rs.Get(tblPages, id[:]); old != nil {
			if ref, perr := parsePageRef(old); perr == nil {
				if err = owePayloadScrub(tx, ref.Log); err != nil { // the hot page of the erased records
					return 0, err
				}
			}
		}
		if found, err := rs.Delete(tblPages, id[:]); err != nil {
			return 0, err
		} else if !found {
			return 0, model.Fail(model.Corrupt)
		}
	}
	return uint64(len(pageIDs)), nil
}

// redactBatch builds the stored "batch_redacted" command: the kept records re-encoded as the
// canonical input (the original Hash stays: receipts and replay evidence bind it), the
// original receipt and reservation, and the digest of the bytes that were replaced.
func redactBatch(raw []byte, entry walEntry, kept []model.Record, erased uint64, ops []model.ID) ([]byte, error) {
	nb := *entry.Batch
	nb.Records = kept
	canonical, err := model.CanonicalJSON(nb.Batch)
	if err != nil {
		return nil, err
	}
	nb.Canonical = canonical
	red := redaction{Original: model.HashCanonical(raw)}
	if entry.Redaction != nil {
		red = *entry.Redaction
	}
	red.Erased += uint32(erased)
	red.Operations = unionIDs(red.Operations, ops)
	return json.Marshal(walEntry{Type: "batch_redacted", Batch: &nb, Receipt: entry.Receipt, Redaction: &red})
}
func unionIDs(a, b []model.ID) []model.ID {
	out := append([]model.ID(nil), a...)
	for _, id := range b {
		found := false
		for _, have := range out {
			found = found || have == id
		}
		if !found {
			out = append(out, id)
		}
	}
	return out
}

func (e *Engine) eraseBlob(ctx context.Context, guard EraseGuard, job eraseBlobJob, ops []model.ID) (erased bool, held uint64, err error) {
	if err = syncGuard(ctx, guard, job.cand); err != nil {
		return false, 0, err
	}
	e.cutMu.Lock()
	defer e.cutMu.Unlock()
	defer e.dropWindowCaches()
	e.dropWindowCaches()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return false, 0, model.Fail(model.Unavailable)
	}
	err = e.db.Update(func(tx *bolt.Tx) error {
		// The decision to erase is taken again here, under the engine lock and the write
		// transaction, so a hold that committed after the candidate scan still wins.
		c := job.cand
		c.Final = true
		allow, err := guard(ctx, c)
		if err != nil {
			return err
		}
		if !allow {
			held = 1
			return nil
		}
		erased, err = e.eraseBlobTx(tx, job, ops)
		return err
	})
	if err != nil {
		return false, 0, err
	}
	if erased {
		e.markRedact(model.BlobOwnerSlot(job.receipt.Manifest.Org, job.receipt.Manifest.Project, job.receipt.Manifest.Root))
	}
	return erased, held, nil
}
func (e *Engine) eraseBlobTx(tx *bolt.Tx, job eraseBlobJob, ops []model.ID) (bool, error) {
	roots := tx.Bucket([]byte("artifact_roots"))
	if !bytes.Equal(roots.Get(job.key), job.raw) {
		return false, nil
	}
	m := job.receipt.Manifest
	slot := model.BlobOwnerSlot(m.Org, m.Project, m.Root)
	commands, fragments := tx.Bucket([]byte("replica_commands")), tx.Bucket([]byte("artifact_fragments"))
	for _, f := range job.receipt.Fragments {
		if f.Cursor.Group != e.group(slot) {
			return false, model.Fail(model.Corrupt)
		}
		ck := commandKey(slot, uint64(f.Cursor.Index))
		commandRef := commands.Get(ck)
		raw := storedValue(commands, commandRef)
		var entry walEntry
		if raw == nil || json.Unmarshal(raw, &entry) != nil {
			return false, model.Fail(model.Corrupt)
		}
		switch entry.Type {
		case "artifact_fragment":
			if entry.Artifact == nil || entry.Artifact.Manifest.Root != m.Root || entry.Artifact.Ordinal != f.Ordinal {
				return false, model.Fail(model.Corrupt)
			}
			redacted, err := json.Marshal(walEntry{Type: "artifact_redacted", Redaction: &redaction{Original: model.HashCanonical(raw), Erased: 1, Operations: unionIDs(nil, ops)}})
			if err != nil {
				return false, err
			}
			if err = commands.Put(ck, redacted); err != nil {
				return false, err
			}
			if err = owePayloadScrub(tx, commandRef); err != nil {
				return false, err
			}
			if err = dropWindowTx(tx, slot, uint64(f.Cursor.Index)); err != nil {
				return false, err
			}
		case "artifact_redacted":
		default:
			return false, model.Fail(model.Corrupt)
		}
		if err := fragments.Delete(blobFragmentKey(m, f.Ordinal)); err != nil {
			return false, err
		}
	}
	if err := e.trip("erase_batch"); err != nil {
		return false, err
	}
	if err := roots.Delete(job.key); err != nil {
		return false, err
	}
	if err := adjustBlobCounts(tx, -1, -int64(len(job.receipt.Fragments)), 0); err != nil {
		return false, err
	}
	if err := e.markScrubPendingTx(tx); err != nil {
		return false, err
	}
	if err := stampRedactFloorTx(tx, slot); err != nil {
		return false, err
	}
	if err := e.trip("erase_redacted"); err != nil {
		return false, err
	}
	return true, nil
}

// staleSegmentsLocked counts segments that still list pages no longer indexed: their bytes
// contain rows that were erased from every reader-visible structure.
func (e *Engine) staleSegmentsLocked() (uint64, error) {
	home := map[model.ID]string{} // page -> segment file it is currently read from ("" = hot)
	err := e.db.View(func(tx *bolt.Tx) error {
		return tableForEach(tx, tblPages, func(k, v []byte) error {
			var id model.ID
			if len(k) != len(id) {
				return model.Fail(model.Corrupt)
			}
			ref, err := parsePageRef(v)
			if err != nil {
				return err
			}
			copy(id[:], k)
			home[id] = ref.Segment
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	// A re-indexed kept page keeps its identity but is hot again, so identity alone does not
	// prove the segment's bytes are still live: the page must still be read from that segment.
	var stale uint64
	for _, s := range e.catalog.Manifest.Segments {
		for _, id := range s.Pages {
			if file, ok := home[id]; !ok || file != s.File {
				stale++
				break
			}
		}
	}
	return stale, nil
}
func (e *Engine) hasStaleSegments() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return false
	}
	n, err := e.staleSegmentsLocked()
	return err == nil && n > 0
}

// rewriteStaleSegments runs the segment rewrite (Compact) that makes cold pages holding erased
// rows disappear. Retired files honor snapshot pins: a pinned segment is removed by its last
// release, not here.
func (e *Engine) rewriteStaleSegments(ctx context.Context) (uint64, error) {
	e.mu.Lock()
	if e.closed || e.failed {
		e.mu.Unlock()
		return 0, model.Fail(model.Unavailable)
	}
	stale, err := e.staleSegmentsLocked()
	e.mu.Unlock()
	if err != nil || stale == 0 {
		return 0, err
	}
	if err = e.trip("erase_compact"); err != nil {
		return 0, err
	}
	if err = e.Compact(ctx); err != nil {
		return 0, err
	}
	return stale, nil
}

// unmarshalRedacted decodes the two local-only redacted command types. The batch keeps the
// ORIGINAL hash (receipts bind it) but its canonical bytes are the re-encoded kept records, so
// the hash check of a normal batch does not apply: redaction provenance is the Redaction digest.
func (entry *walEntry) unmarshalRedacted(wire durableEntry) error {
	if wire.Redaction == nil || wire.Cancel != nil || wire.Fence != nil || wire.Artifact != nil || wire.ArtifactGC != nil || wire.Rejection != nil || wire.DeleteBarrier != nil || wire.EraseAck != nil || wire.EraseUnack != nil || wire.EraseNotice != nil || wire.Proposer != nil || wire.CommitSet != nil {
		return model.Fail(model.Corrupt)
	}
	out := walEntry{Type: wire.Type, Receipt: wire.Receipt, Redaction: wire.Redaction}
	if wire.Type == "artifact_redacted" {
		if wire.Batch != nil || wire.Receipt != nil {
			return model.Fail(model.Corrupt)
		}
		*entry = out
		return nil
	}
	b := wire.Batch
	if b == nil || wire.Receipt == nil || len(b.Canonical) > 4<<20 {
		return model.Fail(model.Corrupt)
	}
	var input model.Batch
	if model.StrictJSON(b.Canonical, &input) != nil {
		return model.Fail(model.Corrupt)
	}
	out.Batch = &model.NormalizedBatch{Batch: input, Org: b.Org, Hash: b.Hash, Canonical: b.Canonical, PolicyEpoch: b.PolicyEpoch, PolicyHash: b.PolicyHash, AdmissionAt: b.AdmissionAt, Deadlines: b.Deadlines, Reservation: b.Reservation, Series: b.Reservation.Series}
	*entry = out
	return nil
}

// applyBatchRedactedTx replays a redacted batch: the same effects as a batch for its kept
// records, without the canonical-hash verification (the canonical bytes are the kept records).
// It is how Restore and snapshot install rebuild redacted history.
func (e *Engine) applyBatchRedactedTx(tx *bolt.Tx, slot uint16, index uint64, entry walEntry) error {
	if entry.Batch == nil || entry.Receipt == nil || entry.Redaction == nil {
		return model.Fail(model.Corrupt)
	}
	b, r := *entry.Batch, *entry.Receipt
	if b.RouteSlot != slot || uint64(r.Cursor.Index) != index || r.Cursor.Group != e.group(slot) || r.Hash != b.Hash || r.BatchID != b.ID {
		return model.Fail(model.Corrupt)
	}
	if tx.Bucket([]byte("cancelled")).Get([]byte(b.Reservation.ID.String())) != nil {
		return model.Fail(model.Corrupt)
	}
	key := batchKey(b.Org, b.Project, b.Source, b.Producer, slot, b.ID)
	rows, err := rowsOf(tx)
	if err != nil {
		return err
	}
	if rows.Get(tblReceipts, key) != nil {
		return model.Fail(model.Corrupt)
	}
	records := make([]model.Record, 0, len(b.Records))
	for _, record := range b.Records {
		if record.Kind == model.Metric {
			k := metricKey(b, record)
			if rows.Get(tblMetrics, k) != nil {
				continue
			}
			v, err := model.CanonicalJSON(record.Payload.Metric)
			if err != nil {
				return err
			}
			if err = rows.Insert(tblMetrics, k, v); err != nil {
				return err
			}
		}
		if record.Kind == model.JobAttempt {
			if err := putJob(tx, b, record.Payload.Job); err != nil {
				return err
			}
		}
		records = append(records, record)
	}
	raw, err := json.Marshal(records)
	if err != nil {
		return err
	}
	if err = rows.Insert(tblBatches, key, raw); err != nil {
		return err
	}
	if err = e.indexAppliedRows(tx, b, r, records); err != nil {
		return err
	}
	if raw, err = json.Marshal(r); err != nil {
		return err
	}
	if err = rows.Insert(tblReceipts, key, raw); err != nil {
		return err
	}
	consumed := b.Reservation
	consumed.State = "consumed"
	consumed.Cursor = &r.Cursor
	if raw, err = json.Marshal(consumed); err != nil {
		return err
	}
	return putConsumed(rows, consumed.ID, raw)
}

// redactionOf returns the redaction of a stored command, or nil when it is an ordinary command.
func redactionOf(raw []byte) *redaction {
	if !bytes.HasPrefix(raw, []byte(`{"type":"batch_redacted"`)) && !bytes.HasPrefix(raw, []byte(`{"type":"artifact_redacted"`)) {
		return nil
	}
	var peek struct {
		Redaction *redaction `json:"redaction"`
	}
	if json.Unmarshal(raw, &peek) != nil {
		return nil
	}
	return peek.Redaction
}

// sameCommand reports whether two stored forms are the same replicated command: byte-equal, or
// one is the redaction of the other (its Original is the SHA-256 of the other's exact bytes).
// Everything else stays byte-exact.
func sameCommand(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	ra, rb := redactionOf(a), redactionOf(b)
	switch {
	case ra != nil && rb != nil:
		return ra.Original == rb.Original
	case ra != nil:
		return ra.Original == model.HashCanonical(b)
	case rb != nil:
		return rb.Original == model.HashCanonical(a)
	}
	return false
}
