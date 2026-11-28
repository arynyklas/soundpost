// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrCorrupt is returned when a snapshot directory or stream does not verify.
	ErrCorrupt = errors.New("replica snapshot corrupt")
	// ErrNoLedger is returned for a snapshot that has no deletion ledger. Such a
	// snapshot could resurrect deleted data and never becomes ready.
	ErrNoLedger = errors.New("replica snapshot has no deletion ledger")
	// ErrNoSnapshot means no verified snapshot is installed.
	ErrNoSnapshot = errors.New("replica has no verified snapshot")
)

const (
	snapshotFormat      = 1
	maxSnapshotFileSize = 1 << 40
	maxSnapshotFiles    = 1 << 16

	fileEnvelope = "envelope.json"
	fileLedger   = "ledger.json"
	fileConf     = "raft.conf"
	fileManifest = "MANIFEST.json"
	filePrefix   = "files/"
)

var safeFileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// LedgerEntry is one retained deletion/tombstone fact, identified by its C05
// application index and a digest of the exact committed bytes.
type LedgerEntry struct {
	Index uint64     `json:"index,string"`
	Kind  string     `json:"kind"`
	Hash  model.Hash `json:"hash"`
}

// Ledger is the deletion ledger carried by every snapshot. An empty Entries list
// is a legitimate ledger; an absent ledger is not.
type Ledger struct {
	Version    uint16        `json:"version"`
	Group      model.ID      `json:"group"`
	Generation uint64        `json:"generation,string"`
	Entries    []LedgerEntry `json:"entries"`
}

// LedgerSummary pins the ledger inside the checksummed manifest.
type LedgerSummary struct {
	Generation uint64     `json:"generation,string"`
	Count      uint64     `json:"count,string"`
	Digest     model.Hash `json:"digest"`
}

// LedgerMachine must be implemented by every Machine that takes snapshots.
type LedgerMachine interface {
	DeletionLedger() (Ledger, error)
}

// PinnedFile is an immutable file the machine promises not to change or remove
// until release is called. A file with Reuse set has no Path: the machine states its
// size and SHA-256 and the snapshot store takes it, without reading it, from the
// selected snapshot when that holds a file of the same name, size and hash (a hard link,
// or a verified copy where links are unavailable). That is how a cut stays incremental.
type PinnedFile struct {
	Name  string
	Path  string
	Reuse bool
	// Own gives the file at Path to the snapshot store: the machine wrote it for this cut, synced it and states its Size and SHA-256, and
	// will not write it again. The store moves it into the snapshot directory instead of copying it (a copy where a move is not possible:
	// another file system), so that a cut writes the bytes once. Nothing is shared with the snapshot afterwards, no inode and no later
	// write: the machine's release finds the name gone.
	Own    bool
	Size   uint64
	SHA256 model.Hash
}

// FileMachine is optionally implemented by machines with authoritative or
// derived files beside their serialized state. PinFiles must be atomic: the
// returned set is internally consistent and survives until release.
type FileMachine interface {
	PinFiles() (files []PinnedFile, release func(), err error)
}

// CompactMachine is optionally implemented by a machine whose locally cut snapshots keep
// most of their state in snapshot files (FileMachine) instead of inside the envelope.
// CompactSnapshot is the state such a cut puts in the envelope: it names the files and cannot
// be installed by a peer, so a snapshot sent to a peer is always cut with Snapshot, which is
// self-contained. Restore must accept both and resolve a compact state from the store
// handed over by SnapshotStoreUser.
type CompactMachine interface {
	CompactSnapshot() ([]byte, error)
}

// CutPinner is optionally implemented by a machine that can answer a snapshot cut for one applied index after the group
// has gone on applying. A cut holds the group's ready stage and lock (lockAll) for as long as it asks the machine for its
// state, its deletion ledger and its pinned files, and a group that holds them runs no cycle and takes no tick or step: a
// machine whose derivation takes a long time (a data group's window table decodes every command of its open window) kept
// a leader silent for the length of every cut. With a CutPinner the cut holds them only for what the applied index fixes
// (the index and term, the members, the retry table and PinCut), and the PinnedCut derives the rest without them.
//
// PinCut is called with both locks held, at the applied index of the cut, and nothing is applied while it runs. It
// captures what only that index fixes and does no derivation, no I/O and no waiting, and calls nothing of the group.
// What it returns holds nothing that outlives the cut except through PinFiles' release.
//
// A machine implements it only when everything the PinnedCut derives is a function of its state at that index that no
// later command changes. The retry table of such a cut is always inline in the envelope, whatever CompactStateMachine
// says: that decision reads the state, which a pinned cut derives after the retry table is taken.
type CutPinner interface {
	PinCut() (PinnedCut, error)
}

// PinnedCut answers LedgerMachine, CompactMachine and FileMachine for the index its CutPinner was called at, whatever the
// machine has applied since. The group calls CompactSnapshot, DeletionLedger and PinFiles, in that order, once each,
// without any lock of its own and while it goes on applying, from the one cut that holds the group's cutMu. A ledger that
// names a command after the index of the cut is refused (ErrNoLedger) as it is for any machine.
type PinnedCut interface {
	LedgerMachine
	CompactMachine
	FileMachine
}

// SnapshotStoreUser is optionally implemented by a machine that resolves a compact state or
// reuses files from the group's snapshot store. It is called once, before the machine's first
// Restore, VerifySnapshot or cut.
type SnapshotStoreUser interface {
	UseSnapshotStore(*SnapshotStore)
}

// SnapshotFile is one checksummed byte stream of a snapshot.
type SnapshotFile struct {
	Name   string     `json:"name"`
	Size   uint64     `json:"size,string"`
	SHA256 model.Hash `json:"sha256"`
}

// SnapshotManifest is the checksummed description of a full-byte snapshot. The
// stream accompanying it is the concatenation of Files in order.
type SnapshotManifest struct {
	Version uint16       `json:"version"`
	Group   model.ID     `json:"group"`
	Index   uint64       `json:"index,string"` // physical Raft cut
	Term    uint64       `json:"term,string"`
	Cursor  model.Cursor `json:"cursor"` // C05 application cursor at the cut
	// Generation is the deletion-ledger generation. A node never installs a
	// snapshot whose generation is older than one it already holds or was told
	// to require, so an old replica or backup cannot resurrect deleted data.
	Generation uint64         `json:"generation,string"`
	Ledger     LedgerSummary  `json:"ledger"`
	Files      []SnapshotFile `json:"files"`
	Checksum   model.Hash     `json:"checksum"`
}

func (m SnapshotManifest) seal() model.Hash {
	m.Checksum = model.Hash{}
	raw, err := json.Marshal(m)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}

// Validate checks structure and the manifest checksum; it reads no file bytes.
func (m SnapshotManifest) Validate() error {
	if m.Version != snapshotFormat || m.Group == (model.ID{}) || m.Index == 0 || m.Term == 0 || m.Cursor.Group != m.Group {
		return ErrCorrupt
	}
	if m.Ledger.Generation != m.Generation || len(m.Files) < 2 || len(m.Files) > maxSnapshotFiles {
		return ErrCorrupt
	}
	names := make([]string, 0, len(m.Files))
	seen := map[string]bool{}
	var ledger, envelope bool
	for _, f := range m.Files {
		switch {
		case f.Name == fileEnvelope:
			envelope = true
		case f.Name == fileLedger:
			ledger = true
			if f.SHA256 != m.Ledger.Digest {
				return ErrCorrupt
			}
		case f.Name == fileConf:
		case strings.HasPrefix(f.Name, filePrefix) && safeFileName.MatchString(strings.TrimPrefix(f.Name, filePrefix)):
		default:
			return ErrCorrupt
		}
		if seen[f.Name] || f.Size > maxSnapshotFileSize {
			return ErrCorrupt
		}
		seen[f.Name] = true
		names = append(names, f.Name)
	}
	if !envelope || !sort.StringsAreSorted(names) {
		return ErrCorrupt
	}
	if !ledger {
		return ErrNoLedger
	}
	if m.seal() != m.Checksum {
		return ErrCorrupt
	}
	return nil
}

// Snapshot is a durable, verified, immutable snapshot directory.
type Snapshot struct {
	Manifest SnapshotManifest
	dir      string
}

// Dir is the installed directory; its files are never mutated.
func (s Snapshot) Dir() string { return s.dir }

// File opens one manifest file for reading.
func (s Snapshot) File(name string) (*os.File, error) {
	for _, f := range s.Manifest.Files {
		if f.Name == name {
			return os.Open(filepath.Join(s.dir, filepath.FromSlash(name)))
		}
	}
	return nil, os.ErrNotExist
}

// WriteTo streams every file in manifest order, hashing as it goes. A reader
// that verifies the same hashes (InstallSnapshot) therefore detects any
// truncation or flip in transit.
func (s Snapshot) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for _, f := range s.Manifest.Files {
		in, err := s.File(f.Name)
		if err != nil {
			return total, err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(w, h), in)
		in.Close()
		total += n
		if err != nil {
			return total, err
		}
		if uint64(n) != f.Size || model.Hash(h.Sum(nil)) != f.SHA256 {
			return total, ErrCorrupt
		}
	}
	return total, nil
}

// MachineState returns the serialized Machine state captured at the cut.
func (s Snapshot) MachineState() ([]byte, error) {
	raw, err := s.envelopeBytes()
	if err != nil {
		return nil, err
	}
	var envelope snapshotEnvelope
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, ErrCorrupt
	}
	return envelope.State, nil
}

// Envelope returns the verified Raft snapshot payload bytes.
func (s Snapshot) envelopeBytes() ([]byte, error) {
	in, err := s.File(fileEnvelope)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	return io.ReadAll(in)
}

// CreateSnapshot cuts a full-byte snapshot at the group's current applied
// index, which must have reached at. Concurrent appends continue afterwards; the
// cut is taken under the group lock so state, ledger and receipts agree. Files
// supplied by the machine are pinned while they are copied, so a concurrent flush
// or compaction cannot remove them mid-copy.
func (g *Group) CreateSnapshot(ctx context.Context, at model.Cursor) (Snapshot, error) {
	g.cutMu.Lock()
	defer g.cutMu.Unlock()
	snapshot, err := g.cut(ctx, at)
	if errors.Is(err, errRetryPartsLost) { // the selected snapshot no longer holds the retry parts the cut meant to take from it: write the table whole
		snapshot, err = g.cut(ctx, at)
	}
	return snapshot, err
}

// errRetryPartsLost is cut's report that it failed only because a retry part it meant to reuse was gone; the group
// has forgotten its parts, so the same cut, repeated, writes the whole table.
var errRetryPartsLost = errors.New("replica retry parts lost")

// cut is CreateSnapshot with cutMu held.
func (g *Group) cut(ctx context.Context, at model.Cursor) (Snapshot, error) {
	if at.Group != g.group {
		return Snapshot{}, ErrInvalid
	}
	if err := g.WaitApplied(ctx, at); err != nil {
		return Snapshot{}, err
	}
	ledgerMachine, ok := g.machine.(LedgerMachine)
	if !ok {
		return Snapshot{}, ErrNoLedger
	}
	if err := g.trip("snapshot_cut"); err != nil {
		return Snapshot{}, err
	}
	lockBegan := time.Now()
	pinner, _ := g.machine.(CutPinner)
	c, err := g.captureCut(at, ledgerMachine, pinner)
	if err != nil {
		return Snapshot{}, err
	}
	sinceMax(&g.phases.cutLockNS, &g.phases.cutLockMax, lockBegan)
	defer func() { c.release() }()
	if c.pinned != nil { // the machine answers for the index it pinned, without the group's locks
		if err = g.deriveCut(&c, c.pinned, c.pinned, c.pinned); err != nil {
			return Snapshot{}, err
		}
	}
	envelopeBegan := time.Now()
	envelope := c.envelope
	envelope.State = c.state
	if c.plan == nil { // the retry table is inline: ordered and marked from the copy the locks guarded
		envelope.markRetry()
		sort.Slice(envelope.Completed, func(i, j int) bool { return envelope.Completed[i].Index < envelope.Completed[j].Index })
	}
	index, term, cursor, conf, plan, completed, ledger, pinned := c.index, c.term, c.cursor, c.conf, c.plan, c.completed, c.ledger, c.files
	if ledger.Version != 1 || ledger.Group != g.group || ledger.Entries == nil {
		return Snapshot{}, ErrNoLedger
	}
	var previous uint64
	for _, e := range ledger.Entries {
		if e.Index <= previous || e.Index > uint64(cursor.Index) {
			return Snapshot{}, ErrNoLedger
		}
		previous = e.Index
	}
	var retrySources []bundleSource
	var retryParts []retryPart
	if plan != nil {
		var written uint64
		if retrySources, retryParts, written, err = plan.encode(); err != nil {
			return Snapshot{}, err
		}
		g.phases.cutRetryBytes.Store(written)
		if len(retryParts) > 0 {
			envelope.Retry, envelope.RetryParts = retryDigestTag, partNames(retryParts)
		}
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return Snapshot{}, err
	}
	ledgerRaw, err := json.Marshal(ledger)
	if err != nil {
		return Snapshot{}, err
	}
	confRaw, err := proto.Marshal(conf)
	if err != nil {
		return Snapshot{}, err
	}
	since(&g.phases.cutEnvelopeNS, envelopeBegan)
	g.phases.cutEnvelopeBytes.Store(uint64(len(raw)))
	g.phases.cutCompleted.Store(uint64(completed))
	// The in-memory Raft snapshot is what a lagging follower receives and what the
	// journal rewrite is anchored on; it is made before the directory is
	// published so truncation can never outrun a verified directory.
	lock2Began := time.Now()
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return Snapshot{}, ErrUnavailable
	}
	if existing, err := g.memory.Snapshot(); err == nil && existing.GetMetadata().GetIndex() < index {
		if _, err = g.memory.CreateSnapshot(index, conf, raw); err != nil && err != raft.ErrSnapOutOfDate {
			g.mu.Unlock()
			return Snapshot{}, err
		}
	}
	g.mu.Unlock()
	sinceMax(&g.phases.cutLock2NS, &g.phases.cutLock2Max, lock2Began)
	sources := []bundleSource{{name: fileEnvelope, data: raw}, {name: fileLedger, data: ledgerRaw}, {name: fileConf, data: confRaw}}
	sources = append(sources, retrySources...)
	for _, f := range pinned {
		if !safeFileName.MatchString(f.Name) {
			return Snapshot{}, ErrInvalid
		}
		sources = append(sources, bundleSource{name: filePrefix + f.Name, path: f.Path, reuse: f.Reuse, own: f.Own, size: f.Size, sum: f.SHA256})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	manifest := SnapshotManifest{Version: snapshotFormat, Group: g.group, Index: index, Term: term, Cursor: cursor, Generation: ledger.Generation}
	storeBegan := time.Now()
	snapshot, err := g.snaps.create(ctx, manifest, ledgerRaw, sources)
	since(&g.phases.cutStoreNS, storeBegan)
	if plan != nil {
		g.mu.Lock()
		switch {
		case errors.Is(err, ErrReuseLost) && len(plan.keep) > 0:
			g.resetRetryPartsLocked()
			err = errRetryPartsLost
		case err == nil && g.retryEpoch == plan.epoch && g.snaps.wroteLast():
			g.retryParts = retryParts
		case err == nil:
			g.resetRetryPartsLocked() // the selected snapshot was already this cut and is not what was planned
		}
		g.mu.Unlock()
	}
	return snapshot, err
}

// cutCapture is what a cut takes of the group at its applied index, under the group's locks. For a machine that does not pin
// (CutPinner) that includes everything the machine derives; for one that does, the pinned cut is derived from afterwards
// (deriveCut), without the locks.
type cutCapture struct {
	index, term uint64
	cursor      model.Cursor
	conf        *pb.ConfState
	envelope    snapshotEnvelope // without the machine's state
	plan        *retryPlan       // nil: the retry table is inline in the envelope
	completed   int              // the entries of the retry table, for the phase counters
	pinned      PinnedCut        // the machine's cut at the index, when it pins
	state       []byte
	ledger      Ledger
	files       []PinnedFile
	release     func() // never nil: releases what files pinned
}

// captureCut takes the group's locks and returns what the applied index fixes: its index and term, the members, the retry
// table (copied, not yet ordered) and the machine's cut. The locks are held for the capture and not a moment longer: a machine
// that pins (CutPinner) is only asked to pin, and everything it derives comes after (deriveCut); any other machine is asked
// for its state, ledger and files here, as it always was, because they are its state at this index and nothing else holds it
// there.
func (g *Group) captureCut(at model.Cursor, ledgers LedgerMachine, pinner CutPinner) (c cutCapture, err error) {
	c.release = func() {}
	g.lockAll()
	defer g.unlockAll()
	if g.failed || g.closed || g.applied == 0 {
		return c, ErrUnavailable
	}
	if g.application < uint64(at.Index) {
		return c, ErrStale
	}
	c.index = g.applied
	if c.term, err = g.memory.Term(c.index); err != nil {
		return c, err
	}
	c.envelope = snapshotEnvelope{Application: g.application, Members: cloneMembers(g.members), Retiring: append([]Member(nil), g.retiring...)}
	if pinner != nil {
		if c.pinned, err = pinner.PinCut(); err != nil {
			return c, err
		}
		if c.pinned == nil {
			return c, ErrInvalid
		}
		c.envelope.Completed = g.completedLocked()
	} else {
		compact, _ := g.machine.(CompactMachine)
		files, _ := g.machine.(FileMachine)
		if err = g.deriveCut(&c, compact, ledgers, files); err != nil {
			return c, err
		}
		if g.compactRetry(c.state) {
			c.plan = g.planRetryLocked()
			c.envelope.Completed, c.envelope.RetryFrom = c.plan.plain, c.plan.from
		} else {
			c.envelope.Completed = g.completedLocked()
		}
	}
	c.completed = len(g.completed)
	c.conf = g.conf
	c.cursor = model.Cursor{Group: g.group, Index: model.Uint64(g.application)}
	return c, nil
}

// completedLocked copies the retry table, in no order. g.mu is held.
func (g *Group) completedLocked() []CommittedEntry {
	if len(g.completed) == 0 {
		return nil
	}
	out := make([]CommittedEntry, 0, len(g.completed))
	for _, c := range g.completed {
		out = append(out, c)
	}
	return out
}

// deriveCut asks the machine (or its pinned cut) for the state, the deletion ledger and the pinned files of the cut. A machine
// that is not a CompactMachine is asked for its whole state; one that is not a FileMachine has no files.
func (g *Group) deriveCut(c *cutCapture, compact CompactMachine, ledgers LedgerMachine, files FileMachine) (err error) {
	if compact != nil {
		c.state, err = compact.CompactSnapshot()
	} else {
		c.state, err = g.machine.Snapshot()
	}
	if err != nil {
		return err
	}
	if c.ledger, err = ledgers.DeletionLedger(); err != nil {
		return err
	}
	if files == nil {
		return nil
	}
	if err = g.trip("snapshot_pin"); err != nil {
		return err
	}
	pinned, release, err := files.PinFiles()
	if err != nil {
		return err
	}
	c.files = pinned
	if release != nil {
		c.release = release
	}
	return nil
}

func (g *Group) trip(at string) error {
	if g.fault != nil {
		return g.fault(at)
	}
	return nil
}

func syncDirTree(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			if err = syncDirTree(filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return durablefs.SyncDir(dir)
}
