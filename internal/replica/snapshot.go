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

	raft "go.etcd.io/raft/v3"
	"google.golang.org/protobuf/proto"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
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
// until release is called.
type PinnedFile struct {
	Name string
	Path string
}

// FileMachine is optionally implemented by machines with authoritative or
// derived files beside their serialized state. PinFiles must be atomic: the
// returned set is internally consistent and survives until release.
type FileMachine interface {
	PinFiles() (files []PinnedFile, release func(), err error)
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
	g.mu.Lock()
	if g.failed || g.closed || g.applied == 0 {
		g.mu.Unlock()
		return Snapshot{}, ErrUnavailable
	}
	if g.application < uint64(at.Index) {
		g.mu.Unlock()
		return Snapshot{}, ErrStale
	}
	index := g.applied
	term, err := g.memory.Term(index)
	if err != nil {
		g.mu.Unlock()
		return Snapshot{}, err
	}
	state, err := g.machine.Snapshot()
	if err != nil {
		g.mu.Unlock()
		return Snapshot{}, err
	}
	ledger, err := ledgerMachine.DeletionLedger()
	if err != nil {
		g.mu.Unlock()
		return Snapshot{}, err
	}
	var pinned []PinnedFile
	release := func() {}
	if files, ok := g.machine.(FileMachine); ok {
		if err = g.trip("snapshot_pin"); err != nil {
			g.mu.Unlock()
			return Snapshot{}, err
		}
		if pinned, release, err = files.PinFiles(); err != nil {
			g.mu.Unlock()
			return Snapshot{}, err
		}
	}
	defer func() { release() }()
	envelope := snapshotEnvelope{Application: g.application, State: state, Members: cloneMembers(g.members), Retiring: append([]Member(nil), g.retiring...)}
	for _, c := range g.completed {
		envelope.Completed = append(envelope.Completed, c)
	}
	sort.Slice(envelope.Completed, func(i, j int) bool { return envelope.Completed[i].Index < envelope.Completed[j].Index })
	conf := g.conf
	cursor := model.Cursor{Group: g.group, Index: model.Uint64(g.application)}
	g.mu.Unlock()
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
	// The in-memory Raft snapshot is what a lagging follower receives and what the
	// journal rewrite is anchored on; it is made before the directory is
	// published so truncation can never outrun a verified directory.
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
	sources := []bundleSource{{name: fileEnvelope, data: raw}, {name: fileLedger, data: ledgerRaw}, {name: fileConf, data: confRaw}}
	for _, f := range pinned {
		if !safeFileName.MatchString(f.Name) {
			return Snapshot{}, ErrInvalid
		}
		sources = append(sources, bundleSource{name: filePrefix + f.Name, path: f.Path})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	manifest := SnapshotManifest{Version: snapshotFormat, Group: g.group, Index: index, Term: term, Cursor: cursor, Generation: ledger.Generation}
	return g.snaps.create(ctx, manifest, ledgerRaw, sources)
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
