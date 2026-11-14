// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
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

// verifyGate, when non-nil, holds every background pass until it is closed. Tests only.
var verifyGate chan struct{}

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
	data, err := r.encode()
	if err != nil {
		return err
	}
	tmp := e.verifiedPath() + ".tmp"
	if err = durablefs.Remove(tmp); err != nil {
		return err
	}
	if err = durablefs.Exclusive(tmp, data); err != nil {
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

// verifiedFrom returns the first command index of slot that still needs verification.
func (e *Engine) verifiedFrom(slot uint16, applied uint64) uint64 {
	if r := e.ver.rec; r != nil && uint64(r.Groups[slot].Applied) <= applied {
		return uint64(r.Groups[slot].Applied) + 1
	}
	return 1
}

func (e *Engine) recordHasSegment(s SegmentManifest) bool {
	r := e.ver.rec
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

// buildVerifiedRecord states the current state as verified; the caller has just verified it.
func (e *Engine) buildVerifiedRecord(tx *bolt.Tx, cat manifestState) (*verifiedRecord, error) {
	rec := &verifiedRecord{Format: verifiedFormat, Identity: e.identity, ManifestDigest: cat.Hash}
	for slot := range uint16(64) {
		rec.Groups = append(rec.Groups, verifiedGroup{Group: e.group(slot), Applied: model.Uint64(appliedOf(tx, slot))})
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

// validateIndexTail verifies, bounded by what was written since the record, the scan-index side
// of every command above each group's verified index: the commit entry, its pages and the
// scan_time entries of every page.
func (e *Engine) validateIndexTail(tx *bolt.Tx) error {
	commits, pages, times := tx.Bucket([]byte("scan_commits")), tx.Bucket([]byte("scan_pages")), tx.Bucket([]byte("scan_time"))
	if commits == nil || pages == nil || times == nil {
		return model.Fail(model.Corrupt)
	}
	// The digest itself must parse (it is CRC-protected); a damaged one is corruption.
	for _, name := range []string{"scan_time", "scan_postings"} {
		if _, err := parseDigest(tx.Bucket([]byte("scan_integrity")).Get([]byte(name))); err != nil {
			return err
		}
	}
	for slot := range uint16(64) {
		applied := appliedOf(tx, slot)
		for index := e.verifiedFrom(slot, applied); index <= applied; index++ {
			raw := commits.Get(commitKey(model.Cursor{Group: e.group(slot), Index: model.Uint64(index)}))
			if raw == nil {
				continue // not a batch command
			}
			var ids []committedPage
			if json.Unmarshal(raw, &ids) != nil {
				return model.Fail(model.Corrupt)
			}
			for _, id := range ids {
				if err := e.validateTailPage(pages, times, id.ID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (e *Engine) validateTailPage(pages, times *bolt.Bucket, id model.ID) error {
	raw := pages.Get(id[:])
	if raw == nil {
		return nil // erased with its batch
	}
	ref, err := parsePageRef(raw)
	if err != nil || ref.ID != id {
		return model.Fail(model.Corrupt)
	}
	if ref.Hot != nil && model.HashCanonical(ref.Hot) != ref.Hash {
		return model.Fail(model.Corrupt)
	}
	prefix := pageNamespace(ref.Org, ref.Project, ref.Kind, ref.Restricted, ref.Source, ref.Subject)
	upper := append(append([]byte(nil), prefix...), timeKey(ref.End)...)
	var found uint32
	c := times.Cursor()
	for k, v := c.Seek(append(append([]byte(nil), prefix...), timeKey(ref.Start)...)); k != nil && len(k) >= len(upper) && bytes.Compare(k[:len(upper)], upper) <= 0; k, v = c.Next() {
		e.ver.entries.Add(1)
		if len(v) >= 16 && bytes.Equal(v[:16], id[:]) {
			if !validIndexValue(k, v) {
				return model.Fail(model.Corrupt)
			}
			found++
		}
	}
	if found != ref.Count {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// rebindVerifiedLocked carries the record over a manifest publication: the new manifest's segments
// were hashed (or carried from a verified manifest) by the publication, so the segment set stays
// verified, while the verified applied indexes and index digests stay where they were. e.mu held.
func (e *Engine) rebindVerifiedLocked(old model.Hash, next manifestState) {
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	r := e.ver.rec
	if r == nil || r.ManifestDigest != old {
		return
	}
	nr := *r
	nr.ManifestDigest = next.Hash
	nr.Segments = nil
	for _, s := range next.Manifest.Segments {
		nr.Segments = append(nr.Segments, verifiedSegment{ID: s.ID, File: s.File, Checksum: s.Checksum, Bytes: s.Bytes})
	}
	if e.writeVerifiedRecord(&nr) != nil {
		e.ver.rec = nil // the old file is now bound to a retired manifest: the next start verifies in full
		return
	}
	e.ver.rec = &nr
}

// commitVerifiedStart is called once Open has recovered: the state verified by this start becomes
// the new verified point.
func (e *Engine) commitVerifiedStart() {
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	p := e.ver.pending
	e.ver.pending = nil
	if p == nil {
		return
	}
	if e.writeVerifiedRecord(p) != nil {
		e.ver.rec = nil
		return
	}
	e.ver.rec = p
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
func (e *Engine) VerifyFull(ctx context.Context) error {
	e.mu.Lock()
	if e.closed || e.failed {
		e.mu.Unlock()
		return model.Fail(model.Unavailable)
	}
	cat := e.catalog
	e.mu.Unlock()
	for _, s := range cat.Manifest.Segments {
		if err := ctx.Err(); err != nil {
			return model.Fail(model.Cancelled)
		}
		path, err := segmentPath(e.dir, s.File)
		if err == nil {
			var h model.Hash
			if h, err = hashFile(path); err == nil && h != s.Checksum {
				err = model.Fail(model.Corrupt)
			}
			if err == nil {
				err = verifySegmentFileHeader(path, s)
			}
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
	var rec *verifiedRecord
	err := e.db.View(func(tx *bolt.Tx) error {
		if err := validateReplicaNamespacesTx(tx, nil, nil); err != nil {
			return err
		}
		if err := validateIndexIntegrity(tx); err != nil {
			return err
		}
		var err error
		rec, err = e.buildVerifiedRecord(tx, cat)
		return err
	})
	if err != nil {
		return e.failVerify(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed || e.catalog.Hash != cat.Hash {
		return nil // the manifest moved on: the next pass records the new point
	}
	e.ver.mu.Lock()
	defer e.ver.mu.Unlock()
	if e.writeVerifiedRecord(rec) == nil {
		e.ver.rec = rec
	}
	return nil
}

// failVerify fails the engine closed: it serves nothing, the node's groups stop with it, and the
// record is removed so the next start verifies everything before readiness.
func (e *Engine) failVerify(cause error) error {
	err := model.Fail(model.Corrupt)
	_ = durablefs.Remove(e.verifiedPath())
	e.ver.mu.Lock()
	e.ver.rec = nil
	e.ver.pending = nil
	if e.ver.err == nil {
		e.ver.err = err
	}
	e.ver.mu.Unlock()
	e.mu.Lock()
	e.failLocked()
	e.mu.Unlock()
	return err
}

// startBackgroundVerify runs VerifyFull at start and then every verifyInterval until Close.
func (e *Engine) startBackgroundVerify() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	e.ver.mu.Lock()
	e.ver.cancel, e.ver.done = cancel, done
	e.ver.mu.Unlock()
	go func() {
		defer close(done)
		if gate := verifyGate; gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return
			}
		}
		for {
			if err := e.VerifyFull(ctx); err != nil && e.VerifyFailure() != nil {
				return
			}
			select {
			case <-time.After(verifyInterval):
			case <-ctx.Done():
				return
			}
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
