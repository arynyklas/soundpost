// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// Bounded startup verification (decision D15).
//
// A node used to re-prove its whole history before every start: every command of every slot, every
// entry of the scan indexes and the SHA-256 of every cold segment. That cost grows with history.
// The node now keeps a verified record: a durable, checksummed file that states, per group, the
// last fully verified applied index and, for the node, the verified segment set (id, file,
// checksum, size) and the digests of the two scan indexes, all bound to the digest of the node's
// own manifest. A start that finds a valid record verifies only what was written or changed since
// the verified point: the commands above each group's verified index, the index entries and pages
// those commands produced, and any segment the record does not list. A missing, unreadable,
// corrupt, foreign (another node's identity or group ids, another format) or stale-bound
// (manifest digest differs) record forces the full verification before readiness.
//
// What this gives up, deliberately: bit rot in an older, already verified segment, command or
// index entry is no longer caught before readiness. A background full re-verification starts with
// every engine and repeats every verifyInterval; any mismatch fails the engine closed (the node's
// replica groups stop with it) and removes the record so the next start verifies in full.
const (
	verifiedRecordName = "verified-record.bin"
	verifiedFormat     = 1
)

var verifiedMagic = [8]byte{'S', 'P', 'V', 'R', '0', '0', '0', '1'}

// verifyInterval is the period of the background full re-verification; D15 requires at least daily.
var verifyInterval = 24 * time.Hour

// verifyStartDelay is how long after the end of its start (releaseFirstPass) a node opened with OpenReplicated waits before the first
// full pass: the node serves from a cold page cache then, and the pass reads every record it holds.
var verifyStartDelay = time.Minute

// verifyStartMax bounds the wait of that first pass for the end of the start: the start budget of the product is 20 s (appcore), so a
// pass that has not been released after this long is not waiting for a start but for one that never comes (a node opened with
// OpenReplicated that never enables replication), and begins.
var verifyStartMax = 5 * time.Minute

// verifyGate, when non-nil, holds every background pass until it is closed. Tests only.
var verifyGate chan struct{}

// cancelPollEvery is how many units of work (index entries, commands, window records, pages) a read transaction of a verification pass
// does between two looks at its context. A pass at the size the single-host gate leaves is minutes of units, and Close waited for all
// of them (67 s and more than 3 minutes right after a start, L2w20Admission30): the wait that is left is one stretch of this many units.
// A variable of the tests.
var cancelPollEvery uint32 = 256

// verifyUnitDelay makes every polled unit of a pass take this long. Tests only: a store small enough for a test has no pass that lasts.
var verifyUnitDelay time.Duration

// cancelPoll is how a long read transaction notices that its pass was cancelled: it counts the units of work it has done (tick) and
// looks at the context every cancelPollEvery of them. A nil poll never cancels (the start's own validation, the tests).
type cancelPoll struct {
	ctx context.Context
	n   uint32
}

// tick counts one unit of work and reports model.Cancelled once the context is done, at the next look.
func (p *cancelPoll) tick() error {
	if p == nil {
		return nil
	}
	if verifyUnitDelay > 0 {
		time.Sleep(verifyUnitDelay)
	}
	if p.n++; p.n%cancelPollEvery == 0 && p.ctx.Err() != nil {
		return model.Fail(model.Cancelled)
	}
	return nil
}

// isCancelled reports whether err is the fault of a cancelled pass: that is not damage, and fails nothing.
func isCancelled(err error) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == model.Cancelled
}

type verifiedGroup struct {
	Group   model.ID     `json:"group"`
	Applied model.Uint64 `json:"applied"`
}
type verifiedSegment struct {
	ID       model.ID   `json:"id"`
	File     string     `json:"file"`
	Checksum model.Hash `json:"checksum"`
	Bytes    uint64     `json:"bytes"`
}

// verifiedRecord is the content of the verified-record file.
type verifiedRecord struct {
	Format         uint16            `json:"format"`
	Identity       model.ID          `json:"identity"`
	ManifestDigest model.Hash        `json:"manifest_digest"`
	Groups         []verifiedGroup   `json:"groups"`
	Segments       []verifiedSegment `json:"segments"`
	ScanTime       IndexDigest       `json:"scan_time"`
	ScanPostings   IndexDigest       `json:"scan_postings"`
}

// StartupVerification says what the last Open verified; it is the evidence the startup cost does
// not depend on history.
type StartupVerification struct {
	Full           bool   // no usable record: everything was verified before readiness
	Reason         string // why the record was not used ("" when it was)
	Commands       uint64 // commands whose presence was checked
	SegmentsHashed int    // cold segments hashed
	IndexEntries   uint64 // scan-index entries examined
}

type verifyState struct {
	mu      sync.Mutex
	rec     *verifiedRecord // the record on disk and valid for the current manifest, or nil
	pending *verifiedRecord // the record to write once Open has finished recovering
	startup StartupVerification
	// counters of the startup pass; atomic because the replica groups verify snapshots on
	// their own goroutines while Open's caller may already read StartupVerification.
	commands, entries atomic.Uint64
	hashed            atomic.Int64
	starting          atomic.Bool // true from the end of Open until EnableReplication returns
	err               error       // set once a background pass failed the engine
	cancel            context.CancelFunc
	done              chan struct{}
	kick              chan struct{} // wakes the background loop before its interval ends (kickVerify)
	// first, when non-nil (OpenReplicated), holds the loop's first full pass until releaseFirstPass closes it; fullPasses counts the
	// full passes the loop began (a test reads it).
	first      chan struct{}
	firstOnce  sync.Once
	fullPasses atomic.Int64
	// file serializes the writes and removals of the record file, which fsync (recordVerified): a background pass holds it without e.mu;
	// the manifest publication and the identity install take it under e.mu, in the order e.mu, file, mu.
	file sync.Mutex
	// gen (guarded by mu) counts the changes of what the record is bound to that something other than the pass that read it made:
	// a publication, an install, a start's commit, a failure.
	gen uint64
}

func (r *verifiedRecord) encode() ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	out := make([]byte, 0, 40+len(body))
	out = append(out, verifiedMagic[:]...)
	out = append(out, sum[:]...)
	return append(out, body...), nil
}

func decodeVerifiedRecord(raw []byte) (*verifiedRecord, error) {
	if len(raw) < 40 || !bytes.Equal(raw[:8], verifiedMagic[:]) {
		return nil, model.Fail(model.Corrupt)
	}
	sum := sha256.Sum256(raw[40:])
	if !bytes.Equal(sum[:], raw[8:40]) {
		return nil, model.Fail(model.Corrupt)
	}
	var r verifiedRecord
	if model.StrictJSON(raw[40:], &r) != nil || r.Format != verifiedFormat {
		return nil, model.Fail(model.Corrupt)
	}
	return &r, nil
}

func (e *Engine) verifiedPath() string { return filepath.Join(e.dir, verifiedRecordName) }

func (e *Engine) writeVerifiedRecord(r *verifiedRecord) error {
	defer noteSpan(&verifyStats.records, &verifyStats.recordNS, &verifyStats.maxRecordNS, time.Now())
	if err := e.trip("verify_record_write"); err != nil {
		return err
	}
	data, err := r.encode()
	if err != nil {
		return err
	}
	// The file is written with its own fsync and published by the rename, whose directory fsync also makes the new name durable: a
	// directory fsync before the rename (for the temporary file's name) is a commit of the journal the record does not need.
	tmp := e.verifiedPath() + ".tmp"
	if err = os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if ce := f.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	return durablefs.Rename(tmp, e.verifiedPath())
}

// manifestDigestOf peeks at the manifest digest the apply database points at. initStorage later
// proves that the digest matches the manifest file; the peek only decides whether the record is
// bound to this manifest.
func (e *Engine) manifestDigestOf() (model.Hash, error) {
	var digest model.Hash
	err := e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("meta")).Get([]byte("segment_manifest"))
		if raw == nil {
			return nil
		}
		var state manifestState
		if json.Unmarshal(raw, &state) != nil {
			return model.Fail(model.Corrupt)
		}
		digest = state.Hash
		return nil
	})
	return digest, err
}

// loadVerifiedRecord decides, before any verification step, whether this start may use the
// verified record. Every doubt means a full verification, never a failure: the record only ever
// shortens verification.
func (e *Engine) loadVerifiedRecord() {
	reason := func(why string) { e.ver.startup = StartupVerification{Full: true, Reason: why} }
	raw, err := os.ReadFile(e.verifiedPath())
	if os.IsNotExist(err) {
		reason("missing")
		return
	}
	if err != nil {
		reason("unreadable")
		return
	}
	rec, err := decodeVerifiedRecord(raw)
	if err != nil {
		reason("corrupt")
		return
	}
	if rec.Identity != e.identity || len(rec.Groups) != 64 {
		reason("foreign")
		return
	}
	for slot := range uint16(64) {
		if rec.Groups[slot].Group != e.group(slot) {
			reason("foreign")
			return
		}
	}
	digest, err := e.manifestDigestOf()
	if err != nil {
		reason("manifest unreadable")
		return
	}
	if digest != rec.ManifestDigest {
		reason("manifest digest differs")
		return
	}
	// The record must also describe this apply database: no group may be behind the record
	// (a rolled-back database), and a database exactly at the verified point must carry the
	// recorded index digests.
	consistent := false
	_ = e.db.View(func(tx *bolt.Tx) error {
		same := true
		for slot := range uint16(64) {
			applied := appliedOf(tx, slot)
			if applied < uint64(rec.Groups[slot].Applied) {
				return nil
			}
			same = same && applied == uint64(rec.Groups[slot].Applied)
		}
		if same {
			meta := tx.Bucket([]byte("scan_integrity"))
			if meta == nil {
				return nil
			}
			t, err1 := parseDigest(meta.Get([]byte("scan_time")))
			p, err2 := parseDigest(meta.Get([]byte("scan_postings")))
			if err1 != nil || err2 != nil || t != rec.ScanTime || p != rec.ScanPostings {
				return nil
			}
		}
		consistent = true
		return nil
	})
	if !consistent {
		reason("inconsistent with the apply database")
		return
	}
	e.ver.rec = rec
}

// verifiedRec is the current verified record; the background pass may drop it concurrently.
func (e *Engine) verifiedRec() *verifiedRecord {
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	return e.ver.rec
}

// verifiedFrom returns the first command index of slot that still needs verification.
func (e *Engine) verifiedFrom(slot uint16, applied uint64) uint64 {
	if r := e.verifiedRec(); r != nil && uint64(r.Groups[slot].Applied) <= applied {
		return uint64(r.Groups[slot].Applied) + 1
	}
	return 1
}

// verifiedThrough says whether the verified record covers every command of slot up to index (a start does not verify them again, D15).
func (e *Engine) verifiedThrough(slot uint16, index uint64) bool {
	r := e.verifiedRec()
	return r != nil && uint64(r.Groups[slot].Applied) >= index
}

func (e *Engine) recordHasSegment(s SegmentManifest) bool {
	r := e.verifiedRec()
	if r == nil {
		return false
	}
	for _, v := range r.Segments {
		if v.ID == s.ID && v.File == s.File && v.Checksum == s.Checksum && v.Bytes == s.Bytes {
			return true
		}
	}
	return false
}

func appliedOf(tx *bolt.Tx, slot uint16) uint64 {
	raw := tx.Bucket([]byte("cursors")).Get(slotKey(slot))
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// buildVerifiedRecord states the current state as verified; the caller has just verified it. The
// identity is the caller's, read under e.mu together with cat: this runs on the background pass
// beside InstallReplicationIdentity, so it reads neither e.identity nor e.group, and a record is
// bound to exactly one identity (the identity and its 64 group ids come from one value).
func (e *Engine) buildVerifiedRecord(tx *bolt.Tx, identity model.ID, cat manifestState) (*verifiedRecord, error) {
	rec := &verifiedRecord{Format: verifiedFormat, Identity: identity, ManifestDigest: cat.Hash}
	for slot := range uint16(64) {
		rec.Groups = append(rec.Groups, verifiedGroup{Group: groupOf(identity, slot), Applied: model.Uint64(appliedOf(tx, slot))})
	}
	for _, s := range cat.Manifest.Segments {
		rec.Segments = append(rec.Segments, verifiedSegment{ID: s.ID, File: s.File, Checksum: s.Checksum, Bytes: s.Bytes})
	}
	meta := tx.Bucket([]byte("scan_integrity"))
	var err error
	if meta == nil {
		return nil, model.Fail(model.Corrupt)
	}
	if rec.ScanTime, err = parseDigest(meta.Get([]byte("scan_time"))); err != nil {
		return nil, err
	}
	if rec.ScanPostings, err = parseDigest(meta.Get([]byte("scan_postings"))); err != nil {
		return nil, err
	}
	return rec, nil
}

// tailPage is a page above the verified point whose scan_time entries are still to be found: the first and the last key they can have
// (the namespace of the page and its start and end time) and how many of them the page's reference says there are.
type tailPage struct {
	id    model.ID
	from  []byte
	upper []byte
	count uint32
}

// tailPageBatch is how many pages of the tail are collected before their entries are looked up: the lookups of a batch are made in key
// order (one block of a run serves all the keys it holds), and a batch is what the memory of a pass holds.
const tailPageBatch = 1 << 16

// validateIndexTail verifies, bounded by what was written since the record, the scan-index side
// of every command above each group's verified index: the commit entry, its pages and the
// scan_time entries of every page. The records of the pages are read in the order the log holds them and forgotten after the read (a
// page is hashed once, a minute after it was written; the log's pages are not the page cache's to keep, L2w20Admission35), and the entries
// are looked up in key order: a Seek per page in the order of the commits fetched, from every run of the index, the block that holds the
// key, 128 KiB each, which at the single-host gate was 46,600 pages x the sealed windows x 128 KiB a minute (G7, 18-30 s of one thread).
func (e *Engine) validateIndexTail(tx *bolt.Tx, poll *cancelPoll, entries *atomic.Uint64) error {
	rows, err := rowsOf(tx)
	if err != nil {
		return err
	}
	times, err := openOrderedCursor(tx, "scan_time")
	if err != nil {
		return err
	}
	// The digest itself must parse (it is CRC-protected); a damaged one is corruption.
	for _, name := range []string{"scan_time", "scan_postings"} {
		if _, err := parseDigest(tx.Bucket([]byte("scan_integrity")).Get([]byte(name))); err != nil {
			return err
		}
	}
	var batch []tailPage
	scan := func() error {
		slices.SortFunc(batch, func(a, b tailPage) int { return bytes.Compare(a.from, b.from) })
		for i := range batch {
			if err := scanTailPage(times, poll, &batch[i], entries); err != nil {
				return err
			}
		}
		batch = batch[:0]
		return nil
	}
	for slot := range uint16(64) {
		applied := appliedOf(tx, slot)
		for index := e.verifiedFrom(slot, applied); index <= applied; index++ {
			if err := poll.tick(); err != nil {
				return err
			}
			raw := rows.Get(tblCommits, commitKey(model.Cursor{Group: e.group(slot), Index: model.Uint64(index)}))
			if raw == nil {
				continue // not a batch command
			}
			var ids []committedPage
			if json.Unmarshal(raw, &ids) != nil {
				return model.Fail(model.Corrupt)
			}
			for _, id := range ids {
				page, ok, err := e.checkTailPage(rows, id.ID)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				if batch = append(batch, page); len(batch) == tailPageBatch {
					if err := scan(); err != nil {
						return err
					}
				}
			}
		}
	}
	if err := scan(); err != nil {
		return err
	}
	return rows.Err()
}

// checkTailPage checks a page's reference and its record (hot or in the log) against the hash of the reference, and returns what the
// lookup of its entries needs; ok is false for a page erased with its batch.
func (e *Engine) checkTailPage(rows *rowStore, id model.ID) (page tailPage, ok bool, err error) {
	raw := rows.Get(tblPages, id[:])
	if raw == nil {
		return tailPage{}, false, nil // erased with its batch
	}
	ref, err := parsePageRef(raw)
	if err != nil || ref.ID != id {
		return tailPage{}, false, model.Fail(model.Corrupt)
	}
	if ref.Hot != nil && model.HashCanonical(ref.Hot) != ref.Hash {
		return tailPage{}, false, model.Fail(model.Corrupt)
	}
	if isPayloadRef(ref.Log) {
		hot, err := e.payload.readCold(ref.Log)
		if err != nil || model.HashCanonical(hot) != ref.Hash {
			return tailPage{}, false, model.Fail(model.Corrupt)
		}
	}
	prefix := pageNamespace(ref.Org, ref.Project, ref.Kind, ref.Restricted, ref.Source, ref.Subject)
	from := append(append(make([]byte, 0, len(prefix)+8), prefix...), timeKey(ref.Start)...)
	upper := append(append(make([]byte, 0, len(prefix)+8), prefix...), timeKey(ref.End)...)
	return tailPage{id: id, from: from, upper: upper, count: ref.Count}, true, nil
}

// scanTailPage finds the entries of a page in the index and checks them: as many as the page's reference says, each with the CRC of its value.
func scanTailPage(times orderedCursor, poll *cancelPoll, p *tailPage, entries *atomic.Uint64) error {
	var found uint32
	for k, v := times.Seek(p.from); k != nil && len(k) >= len(p.upper) && bytes.Compare(k[:len(p.upper)], p.upper) <= 0; k, v = times.Next() {
		if err := poll.tick(); err != nil {
			return err
		}
		entries.Add(1)
		if len(v) >= 16 && bytes.Equal(v[:16], p.id[:]) {
			if !validIndexValue(k, v) {
				return model.Fail(model.Corrupt)
			}
			found++
		}
	}
	if found != p.count {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// rebindVerifiedLocked carries the record over a manifest publication: the new manifest's segments
// were hashed (or carried from a verified manifest) by the publication, so the segment set stays
// verified, while the verified applied indexes and index digests stay where they were. e.mu held.
func (e *Engine) rebindVerifiedLocked(old model.Hash, next manifestState) {
	e.ver.file.Lock()
	defer e.ver.file.Unlock()
	e.ver.mu.Lock()
	e.ver.gen++
	r := e.ver.rec
	e.ver.mu.Unlock()
	if r == nil || r.ManifestDigest != old {
		return
	}
	nr := *r
	nr.ManifestDigest = next.Hash
	nr.Segments = nil
	for _, s := range next.Manifest.Segments {
		nr.Segments = append(nr.Segments, verifiedSegment{ID: s.ID, File: s.File, Checksum: s.Checksum, Bytes: s.Bytes})
	}
	written := e.writeVerifiedRecord(&nr) == nil
	e.ver.mu.Lock()
	if written {
		e.ver.rec = &nr
	} else {
		e.ver.rec = nil // the old file is now bound to a retired manifest: the next start verifies in full
	}
	e.ver.mu.Unlock()
}

// recordVerified writes next as the verified record and makes it the current one, unless a manifest publication, an identity
// install or a failed pass changed what the record is bound to since gen was read (the next pass records the point then). The pass
// that calls it holds no engine lock: writing the record is a file fsync, a rename and the directory's fsync, each a commit of the
// file system's journal, which waits for everything the engine has dirtied meanwhile, and the 64 slot groups apply under e.mu: held
// for it, every ack of the node waited out those commits once a minute, seconds at a time at the gate's write rate (L2w20Admission29).
// needCurrent says a record must exist and be bound to next's manifest (an advance has nothing to advance from without one; the
// full pass records one when there is none).
func (e *Engine) recordVerified(next *verifiedRecord, gen uint64, needCurrent bool) error {
	e.ver.file.Lock()
	defer e.ver.file.Unlock()
	e.ver.mu.Lock()
	stale := e.ver.gen != gen || needCurrent && (e.ver.rec == nil || e.ver.rec.ManifestDigest != next.ManifestDigest)
	e.ver.mu.Unlock()
	if stale {
		return nil
	}
	if e.writeVerifiedRecord(next) == nil {
		e.ver.mu.Lock()
		e.ver.rec = next
		e.ver.mu.Unlock()
	}
	return nil
}

// commitVerifiedStart is called once Open has recovered: the state verified by this start becomes
// the new verified point.
func (e *Engine) commitVerifiedStart() {
	e.ver.file.Lock()
	defer e.ver.file.Unlock()
	e.ver.mu.Lock()
	p := e.ver.pending
	e.ver.pending = nil
	e.ver.mu.Unlock()
	if p == nil {
		return
	}
	written := e.writeVerifiedRecord(p) == nil
	e.ver.mu.Lock()
	e.ver.gen++
	if written {
		e.ver.rec = p
	} else {
		e.ver.rec = nil
	}
	e.ver.mu.Unlock()
}

// StartupVerification reports what Open verified.
func (e *Engine) StartupVerification() StartupVerification {
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	out := e.ver.startup
	out.Commands, out.IndexEntries, out.SegmentsHashed = e.ver.commands.Load(), e.ver.entries.Load(), int(e.ver.hashed.Load())
	return out
}

// VerifyFailure is the typed fault of a failed background verification, nil while none failed.
func (e *Engine) VerifyFailure() error {
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	return e.ver.err
}

// VerifyFull re-verifies the whole node (every cold segment, every command, every index entry)
// and, if everything holds, records the verified point. A mismatch fails the engine closed.
//
// The pass runs beside InstallReplicationIdentity, which re-binds an empty engine to the identity
// of the installation it joins. The identity (and with it the group ids a record names) is read
// once, under e.mu with the catalog, and the record is kept only if e.identity still is that
// value when it is committed under e.mu again: a record built across an install is dropped, and
// the install asks the loop for a new pass (kickVerify).
func (e *Engine) VerifyFull(ctx context.Context) error {
	e.mu.Lock()
	if e.closed || e.failed {
		e.mu.Unlock()
		return model.Fail(model.Unavailable)
	}
	cat, identity := e.catalog, e.identity
	e.mu.Unlock()
	poll := &cancelPoll{ctx: ctx}
	if err := e.verifySegments(ctx, cat, nil); err != nil {
		return err
	}
	var rec *verifiedRecord
	err := e.db.View(func(tx *bolt.Tx) error {
		if err := e.trip("verify_full_view"); err != nil {
			return err
		}
		if err := validateReplicaNamespacesTx(tx, poll, nil, nil); err != nil {
			return err
		}
		if err := validateIndexIntegrityPolled(tx, poll); err != nil {
			return err
		}
		if err := validateWindowRecordsTx(tx, poll); err != nil {
			return err
		}
		var err error
		rec, err = e.buildVerifiedRecord(tx, identity, cat)
		return err
	})
	if err != nil {
		if isCancelled(err) {
			return err // the pass was stopped (Close); nothing it saw is damage
		}
		return e.failVerify(err)
	}
	if err = e.trip("verify_built"); err != nil {
		return err
	}
	e.mu.Lock()
	if e.closed || e.failed || e.catalog.Hash != cat.Hash || e.identity != identity {
		e.mu.Unlock()
		return nil // the manifest or the identity moved on: the next pass records the new point
	}
	e.ver.mu.Lock()
	gen := e.ver.gen
	e.ver.mu.Unlock()
	e.mu.Unlock()
	return e.recordVerified(rec, gen, false)
}

// verifySegments hashes the segments of cat that pick selects (every one when pick is nil) and checks their file headers. A segment a
// publication retired while the pass ran is skipped; any other failure fails the engine closed.
func (e *Engine) verifySegments(ctx context.Context, cat manifestState, pick func(SegmentManifest) bool) error {
	for _, s := range cat.Manifest.Segments {
		if err := ctx.Err(); err != nil {
			return model.Fail(model.Cancelled)
		}
		if pick != nil && !pick(s) {
			continue
		}
		path, err := segmentPath(e.dir, s.File)
		if err == nil {
			var h model.Hash
			if h, err = hashFileCtx(ctx, path); err == nil && h != s.Checksum {
				err = model.Fail(model.Corrupt)
			}
			if err == nil {
				err = verifySegmentFileHeader(path, s)
			}
		}
		if isCancelled(err) {
			return err
		}
		if err != nil {
			e.mu.Lock()
			current := false
			for _, c := range e.catalog.Manifest.Segments {
				current = current || c.File == s.File
			}
			e.mu.Unlock()
			if !current {
				continue // retired by a publication while this pass ran
			}
			return e.failVerify(err)
		}
	}
	return nil
}

// verifyAdvanceInterval is how often a running engine moves its verified point up to what it has applied.
var verifyAdvanceInterval = time.Minute

// verifyStats counts the advance passes of the process (a diagnostic build reports them, diag_stats_on.go): the passes, the time of their
// read transaction (and the longest), the index entries they examined, and the writes of the record (count, time and the longest).
var verifyStats struct {
	passes, readNS, maxReadNS, entries atomic.Int64
	records, recordNS, maxRecordNS     atomic.Int64
}

// noteSpan adds one event that began at began to a count, a total and a longest.
func noteSpan(n, total, longest *atomic.Int64, began time.Time) {
	took := time.Since(began).Nanoseconds()
	n.Add(1)
	total.Add(took)
	for old := longest.Load(); took > old && !longest.CompareAndSwap(old, took); old = longest.Load() {
	}
}

// advanceVerified verifies what the engine applied since the verified record exactly as a start does (the commands above each group's verified
// index, the index entries and pages they produced, the segments the record does not list) and records the new point. The record used to be
// written only by a start and by the full pass at that start: a node that ran for an hour under load still held the point of its first second,
// and its first restart verified that whole hour before readiness (L2w20Admission22). A node with no record has nothing to advance from: the full
// pass records one. Damage fails the engine closed, as in the full pass, and the point stays where it was.
func (e *Engine) advanceVerified(ctx context.Context) error {
	if !e.lockCtx(ctx) {
		return model.Fail(model.Cancelled)
	}
	if e.closed || e.failed {
		e.mu.Unlock()
		return model.Fail(model.Unavailable)
	}
	cat, identity := e.catalog, e.identity
	e.mu.Unlock()
	if e.verifiedRec() == nil {
		return nil
	}
	if err := e.verifySegments(ctx, cat, func(s SegmentManifest) bool { return !e.recordHasSegment(s) }); err != nil {
		return err
	}
	var next *verifiedRecord
	poll := &cancelPoll{ctx: ctx}
	var entries atomic.Uint64 // the counters of StartupVerification are the start's, not the advance's
	viewAt := time.Now()
	err := e.db.View(func(tx *bolt.Tx) error {
		if err := e.trip("verify_advance_view"); err != nil {
			return err
		}
		if err := validateReplicaNamespacesTx(tx, poll, e.verifiedFrom, nil, true); err != nil {
			return err
		}
		if err := e.validateIndexTail(tx, poll, &entries); err != nil {
			return err
		}
		var err error
		next, err = e.buildVerifiedRecord(tx, identity, cat)
		return err
	})
	noteSpan(&verifyStats.passes, &verifyStats.readNS, &verifyStats.maxReadNS, viewAt)
	verifyStats.entries.Add(int64(entries.Load()))
	if err != nil {
		if ctx.Err() != nil {
			return model.Fail(model.Cancelled)
		}
		return e.failVerify(err)
	}
	if !e.lockCtx(ctx) {
		return model.Fail(model.Cancelled)
	}
	if e.closed || e.failed || e.catalog.Hash != cat.Hash || e.identity != identity {
		e.mu.Unlock()
		return nil // the manifest or the identity moved on: the next pass starts from the record the publication carried
	}
	e.ver.mu.Lock()
	gen, rec := e.ver.gen, e.ver.rec
	e.ver.mu.Unlock()
	e.mu.Unlock()
	if rec == nil || rec.ManifestDigest != cat.Hash {
		return nil
	}
	if old, err := rec.encode(); err == nil {
		if fresh, err := next.encode(); err == nil && bytes.Equal(old, fresh) {
			return nil // nothing new: no write
		}
	}
	return e.recordVerified(next, gen, true)
}

// closeVerifyBudget bounds the advance that a graceful close makes (verifyAtClose).
var closeVerifyBudget = 10 * time.Second

// verifyAtClose moves the verified point to what the engine applied, once the groups no longer apply: the advance runs once a minute, so
// the point of a node that is stopped is up to a minute behind, and its start verifies that minute (every page's record and index
// entries, one thread) before it answers /readyz: 40 s at the single-host gate after the hour (L2w20Admission34, G7). The pass is the
// advance itself, bounded by closeVerifyBudget; a pass that does not finish leaves the point where it was (the start verifies the tail), and
// damage fails the engine closed, as in the background.
func (e *Engine) verifyAtClose() {
	// A publication holds e.mu for a whole segment rewrite and Close must not wait behind it longer than closeDeadline
	// (TestCloseDeadlineAndPublicationStop): a node that cannot take the engine in that time leaves the verified point
	// where it is, and the start verifies the tail.
	if !e.lockWithin(closeDeadline) {
		return
	}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), closeVerifyBudget)
	defer cancel()
	_ = e.advanceVerified(ctx)
}

// dropVerifiedLocked forgets the verified record and removes its file; e.mu is held. A record
// states group ids and a manifest digest of one identity, so the identity install calls this: the
// record of the old identity must neither stay in memory nor be what the next start finds
// (loadVerifiedRecord would refuse it as foreign, at the price of a full verification).
func (e *Engine) dropVerifiedLocked() {
	e.ver.file.Lock()
	defer e.ver.file.Unlock()
	_ = durablefs.Remove(e.verifiedPath())
	e.ver.mu.Lock()
	e.ver.rec = nil
	e.ver.pending = nil
	e.ver.gen++
	e.ver.mu.Unlock()
}

// kickVerify asks the background loop for a pass now instead of at the end of its interval; it
// never blocks and is a no-op once the loop is gone.
func (e *Engine) kickVerify() {
	e.ver.mu.Lock()
	kick := e.ver.kick
	e.ver.mu.Unlock()
	select {
	case kick <- struct{}{}:
	default:
	}
}

// failVerify fails the engine closed: it serves nothing, the node's groups stop with it, and the
// record is removed so the next start verifies everything before readiness.
func (e *Engine) failVerify(cause error) error {
	err := model.Fail(model.Corrupt)
	e.ver.file.Lock()
	_ = durablefs.Remove(e.verifiedPath())
	e.ver.mu.Lock()
	e.ver.rec = nil
	e.ver.pending = nil
	e.ver.gen++
	if e.ver.err == nil {
		e.ver.err = err
	}
	e.ver.mu.Unlock()
	e.ver.file.Unlock()
	e.mu.Lock()
	e.failLocked()
	e.mu.Unlock()
	return err
}

// startBackgroundVerify runs VerifyFull at start (of a node opened with OpenReplicated: once its start is complete and verifyStartDelay
// has passed, advancing the verified point meanwhile), again whenever kickVerify asks, and otherwise every verifyInterval until Close.
func (e *Engine) startBackgroundVerify() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	kick := make(chan struct{}, 1)
	e.ver.mu.Lock()
	e.ver.cancel, e.ver.done, e.ver.kick = cancel, done, kick
	e.ver.mu.Unlock()
	expiryDone := make(chan struct{})
	go func() {
		defer close(expiryDone)
		e.expiry.keepUp(ctx, e)
	}()
	go func() {
		defer close(done)
		defer func() { <-expiryDone }() // Close cancels ctx, which ends both
		if gate := verifyGate; gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return
			}
		}
		if first := e.ver.first; first != nil {
			advance := time.NewTicker(verifyAdvanceInterval)
			defer advance.Stop()
			var delay *time.Timer
			defer func() {
				if delay != nil {
					delay.Stop()
				}
			}()
			var due <-chan time.Time // the end of the delay, once the start is complete
			limit := time.NewTimer(verifyStartMax)
			defer limit.Stop()
			for started := false; !started; {
				select {
				case <-first:
					first = nil // closed: never selected again
					delay = time.NewTimer(verifyStartDelay)
					due = delay.C
				case <-due:
					started = true
				case <-limit.C: // a node that never completes a replicated start (none enables replication) is still verified
					started = true
				case <-advance.C:
					if err := e.advanceVerified(ctx); err != nil && e.VerifyFailure() != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}
		for {
			e.ver.fullPasses.Add(1)
			if err := e.VerifyFull(ctx); err != nil && e.VerifyFailure() != nil {
				return
			}
			full := time.NewTimer(verifyInterval)
			advance := time.NewTicker(verifyAdvanceInterval)
			due := false
			for !due {
				select {
				case <-full.C:
					due = true
				case <-kick:
					due = true
				case <-advance.C:
					if err := e.advanceVerified(ctx); err != nil && e.VerifyFailure() != nil {
						full.Stop()
						advance.Stop()
						return
					}
				case <-ctx.Done():
					full.Stop()
					advance.Stop()
					return
				}
			}
			full.Stop()
			advance.Stop()
		}
	}()
}

func (e *Engine) stopBackgroundVerify() {
	e.ver.mu.Lock()
	cancel, done := e.ver.cancel, e.ver.done
	e.ver.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// releaseFirstPass lets the first full pass of a node opened with OpenReplicated begin, after verifyStartDelay: its start is over
// (EnableReplication returned, whatever it returned: a node that failed to start is closed by its caller, which ends the loop).
func (e *Engine) releaseFirstPass() {
	e.ver.firstOnce.Do(func() {
		if e.ver.first != nil {
			close(e.ver.first)
		}
	})
}
