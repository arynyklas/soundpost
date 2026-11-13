// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

type replicatedEngine struct{ groups [64]*replica.Group }
type slotMachine struct {
	// validated is the last artifact fragment that Validate decoded: the proposer validates the
	// payload and Apply decodes the same bytes once they commit, and a fragment is hundreds of KiB.
	// Apply reuses it only when its payload is byte-identical, so a payload that differs in any
	// byte is decoded and checked from scratch.
	validated struct {
		mu      sync.Mutex
		payload []byte
		entry   walEntry
	}
	engine    *Engine
	slot      uint16
	authority ReplicatedAuthority
}
type slotSnapshot struct {
	Version     uint16            `json:"version"`
	Identity    model.ID          `json:"identity"`
	Slot        uint16            `json:"slot"`
	Application model.Uint64      `json:"application"`
	Entries     []json.RawMessage `json:"entries"`
}
type ReplicationSeed struct {
	Identity     model.ID         `json:"identity"`
	Slots        [64][]byte       `json:"slots"`
	Applications [64]model.Uint64 `json:"applications"`
	Physical     [64]model.Uint64 `json:"physical"`
	Terms        [64]model.Uint64 `json:"terms"`
}
type ReplicatedAuthority interface {
	ValidateReplicatedBatch(context.Context, model.NormalizedBatch) error
	ValidateReplicatedFragment(context.Context, model.ArtifactFragment) error
	ValidateReplicatedGC(context.Context, model.ArtifactGC) error
	ValidateReplicatedFence(context.Context, model.SourceFence) error
	ValidateReplicatedCancellation(context.Context, model.CancelReservation) error
	ValidateReplicatedDeleteBarrier(context.Context, model.DeleteBarrier) error
}

func storageReplicaFault(err error) error {
	if err == nil {
		return nil
	}
	var fault *model.Fault
	if errors.As(err, &fault) {
		return err
	}
	if errors.Is(err, replica.ErrConflict) {
		return model.Fail(model.Conflict)
	}
	if errors.Is(err, replica.ErrStale) {
		return model.Fail(model.Stale)
	}
	if errors.Is(err, replica.ErrInvalid) {
		return model.Fail(model.Invalid)
	}
	return model.Fail(model.Unavailable)
}
func metaKey(slot uint16, name string) []byte {
	return append(append([]byte(nil), slotKey(slot)...), []byte(name)...)
}
func commandKey(slot uint16, index uint64) []byte {
	var key [10]byte
	binary.BigEndian.PutUint16(key[:2], slot)
	binary.BigEndian.PutUint64(key[2:], index)
	return key[:]
}
func getUint(b *bolt.Bucket, key []byte) uint64 {
	if b == nil {
		return 0
	}
	raw := b.Get(key)
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}
func putUint(b *bolt.Bucket, key []byte, value uint64) error {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return b.Put(key, raw[:])
}

// This marker is written only after a fully recovered legacy prefix has been
// imported. Its loss is corruption, not permission to create a new authority.
func (e *Engine) validateReplicaNamespaces() error {
	return e.db.View(func(tx *bolt.Tx) error {
		marker := tx.Bucket([]byte("meta")).Get([]byte("replica_format"))
		meta, commands := tx.Bucket([]byte("replica_data")), tx.Bucket([]byte("replica_commands"))
		if marker == nil {
			if meta != nil || commands != nil {
				return model.Fail(model.Corrupt)
			}
			return nil
		}
		if !bytes.Equal(marker, []byte{1}) || meta == nil || commands == nil {
			return model.Fail(model.Corrupt)
		}
		var expected uint64
		for slot := range uint16(64) {
			for _, name := range []string{"legacy", "physical", "application", "term"} {
				if len(meta.Get(metaKey(slot, name))) != 8 {
					return model.Fail(model.Corrupt)
				}
			}
			applied := getUint(meta, metaKey(slot, "application"))
			cursor := tx.Bucket([]byte("cursors")).Get(slotKey(slot))
			if applied != 0 && (len(cursor) != 8 || binary.BigEndian.Uint64(cursor) != applied) || applied == 0 && len(cursor) != 0 && getUint(tx.Bucket([]byte("cursors")), slotKey(slot)) != 0 {
				return model.Fail(model.Corrupt)
			}
			if applied < getUint(meta, metaKey(slot, "legacy")) || applied > ^uint64(0)-expected || getUint(meta, metaKey(slot, "physical")) == 0 && applied > getUint(meta, metaKey(slot, "legacy")) {
				return model.Fail(model.Corrupt)
			}
			expected += applied
			for index := uint64(1); index <= applied; index++ {
				if commands.Get(commandKey(slot, index)) == nil {
					return model.Fail(model.Corrupt)
				}
				if index == ^uint64(0) {
					return model.Fail(model.Corrupt)
				}
			}
		}
		if uint64(commands.Stats().KeyN) != expected {
			return model.Fail(model.Corrupt)
		}
		return nil
	})
}
func (e *Engine) replicatedLegacyCut(slot uint16) (bool, uint64, error) {
	var replicated bool
	var legacy uint64
	err := e.db.View(func(tx *bolt.Tx) error {
		replicated = tx.Bucket([]byte("meta")).Get([]byte("replica_format")) != nil
		if replicated {
			legacy = getUint(tx.Bucket([]byte("replica_data")), metaKey(slot, "legacy"))
		}
		return nil
	})
	return replicated, legacy, err
}
func legacyHistory(dir string, slot uint16, expected uint64) ([]json.RawMessage, error) {
	raw, err := os.ReadFile(filepath.Join(dir, walName(slot)))
	if os.IsNotExist(err) && expected == 0 {
		return []json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	reader := bytes.NewReader(raw)
	entries := make([]json.RawMessage, 0)
	for index := uint64(1); reader.Len() > 0; index++ {
		var header [walHeader]byte
		if _, err := io.ReadFull(reader, header[:]); err != nil {
			return nil, model.Fail(model.Corrupt)
		}
		if string(header[:4]) != "SPW1" || binary.BigEndian.Uint16(header[4:6]) != 1 || binary.BigEndian.Uint16(header[6:8]) != slot || binary.BigEndian.Uint64(header[16:24]) != 1 || binary.BigEndian.Uint64(header[24:32]) != index || headerChecksum(header[:]) != binary.BigEndian.Uint32(header[32:36]) || binary.BigEndian.Uint32(header[36:40]) != 0 {
			return nil, model.Fail(model.Corrupt)
		}
		size := binary.BigEndian.Uint32(header[8:12])
		if size == 0 || size > 8<<20 || int(size) > reader.Len() {
			return nil, model.Fail(model.Corrupt)
		}
		payload := make([]byte, size)
		if _, err = io.ReadFull(reader, payload); err != nil || checksum(header[:], payload) != binary.BigEndian.Uint32(header[12:16]) {
			return nil, model.Fail(model.Corrupt)
		}
		var entry walEntry
		if json.Unmarshal(payload, &entry) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		entries = append(entries, json.RawMessage(payload))
	}
	if uint64(len(entries)) != expected {
		return nil, model.Fail(model.Corrupt)
	}
	return entries, nil
}
func (e *Engine) historyLocked(slot uint16) ([]json.RawMessage, error) {
	var entries []json.RawMessage
	initialized := false
	err := e.db.View(func(tx *bolt.Tx) error {
		commands := tx.Bucket([]byte("replica_commands"))
		if commands == nil {
			return nil
		}
		initialized = true
		entries = make([]json.RawMessage, 0)
		for index := uint64(1); index <= e.indexes[slot]; index++ {
			raw := commands.Get(commandKey(slot, index))
			if raw == nil {
				return model.Fail(model.Corrupt)
			}
			entries = append(entries, json.RawMessage(bytes.Clone(raw)))
			if index == ^uint64(0) {
				return model.Fail(model.Corrupt)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !initialized {
		return legacyHistory(e.dir, slot, e.indexes[slot])
	}
	return entries, nil
}
func (e *Engine) initializeReplicaNamespace() error {
	var initialized bool
	if err := e.db.View(func(tx *bolt.Tx) error {
		initialized = tx.Bucket([]byte("meta")).Get([]byte("replica_format")) != nil
		return nil
	}); err != nil {
		return err
	}
	if initialized {
		return e.validateReplicaNamespaces()
	}
	var histories [64][]json.RawMessage
	for slot := range uint16(64) {
		entries, err := legacyHistory(e.dir, slot, e.indexes[slot])
		if err != nil {
			return err
		}
		histories[slot] = entries
	}
	return e.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("replica_data")) != nil || tx.Bucket([]byte("replica_commands")) != nil {
			return model.Fail(model.Corrupt)
		}
		meta, err := tx.CreateBucket([]byte("replica_data"))
		if err != nil {
			return err
		}
		commands, err := tx.CreateBucket([]byte("replica_commands"))
		if err != nil {
			return err
		}
		for slot := range uint16(64) {
			for _, name := range []string{"legacy", "application"} {
				if err = putUint(meta, metaKey(slot, name), e.indexes[slot]); err != nil {
					return err
				}
			}
			for _, name := range []string{"physical", "term"} {
				if err = putUint(meta, metaKey(slot, name), 0); err != nil {
					return err
				}
			}
			for index, raw := range histories[slot] {
				if err = commands.Put(commandKey(slot, uint64(index+1)), raw); err != nil {
					return err
				}
			}
		}
		return tx.Bucket([]byte("meta")).Put([]byte("replica_format"), []byte{1})
	})
}

func (e *Engine) ReplicationSeed() (ReplicationSeed, error) {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	out := ReplicationSeed{Identity: e.identity}
	for slot := range uint16(64) {
		raw, err := (&slotMachine{engine: e, slot: slot}).Snapshot()
		if err != nil {
			return ReplicationSeed{}, err
		}
		out.Slots[slot] = raw
		out.Applications[slot] = model.Uint64(e.indexes[slot])
		if e.repl != nil {
			status := e.repl.groups[slot].Status()
			out.Physical[slot] = model.Uint64(status.Applied)
			out.Terms[slot] = model.Uint64(status.Term)
		}
	}
	return out, nil
}
func (e *Engine) InstallReplicationIdentity(identity model.ID) error {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.repl != nil || identity == (model.ID{}) {
		return model.Fail(model.Conflict)
	}
	if identity == e.identity {
		return nil
	}
	for _, index := range e.indexes {
		if index != 0 {
			return model.Fail(model.Conflict)
		}
	}
	if err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if meta.Get([]byte("segment_manifest")) != nil || meta.Get([]byte("replica_format")) != nil {
			return model.Fail(model.Conflict)
		}
		return meta.Put([]byte("identity"), identity[:])
	}); err != nil {
		return err
	}
	e.identity = identity
	e.catalog.Manifest.Group = identity
	return nil
}
func (e *Engine) EnableReplication(c replica.Config, seed *ReplicationSeed, authority ReplicatedAuthority) ([]*replica.Group, error) {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if e.repl != nil || authority == nil {
		return nil, model.Fail(model.Conflict)
	}
	if seed != nil {
		if seed.Identity != e.identity {
			return nil, model.Fail(model.Conflict)
		}
		for slot := range uint16(64) {
			if seed.Physical[slot] == ^model.Uint64(0) || seed.Terms[slot] == ^model.Uint64(0) {
				return nil, model.Fail(model.Invalid)
			}
		}
	} else if len(c.Members.Nodes) != 1 {
		return nil, model.Fail(model.Invalid)
	}
	if err := e.initializeReplicaNamespace(); err != nil {
		return nil, err
	}
	if err := e.loadRestoreHold(); err != nil {
		return nil, err
	}
	if e.erasure.wake == nil {
		e.erasure.wake = make(chan struct{}, 1)
	}
	r := &replicatedEngine{}
	out := make([]*replica.Group, 0, 64)
	fail := func(err error) ([]*replica.Group, error) {
		for _, group := range out {
			group.Close()
		}
		return nil, err
	}
	for slot := range uint16(64) {
		cfg := c
		cfg.Group = e.group(slot)
		cfg.Directory = filepath.Join(c.Directory, "slot-"+strconv.Itoa(int(slot)))
		machine := &slotMachine{engine: e, slot: slot, authority: authority}
		cfg.Machine = machine
		cfg.Validate = machine.Validate
		cfg.Fault = e.trip
		var err error
		if seed != nil {
			cfg.Seed = seed.Slots[slot]
			cfg.Application = uint64(seed.Applications[slot])
			cfg.SeedIndex = uint64(seed.Physical[slot]) + 1
			cfg.SeedTerm = uint64(seed.Terms[slot]) + 1
		} else {
			cfg.Seed, err = machine.Snapshot()
			cfg.Application = e.indexes[slot]
		}
		if err != nil {
			return fail(err)
		}
		group, err := replica.Open(cfg)
		if err != nil {
			return fail(err)
		}
		r.groups[slot] = group
		out = append(out, group)
	}
	e.repl = r
	// Every slot is reconciled once at open: an erasure whose redaction a crash cut short, and a
	// node whose retry table came from a cut older than the commands it has redacted, converge
	// before any snapshot is cut or proposal accepted.
	for slot := range e.redact.dirty {
		e.redact.dirty[slot].Store(true)
	}
	if err := e.redactReplica(context.Background()); err != nil {
		e.repl = nil
		return fail(err)
	}
	e.startErasureLoop()
	return out, nil
}
func (e *Engine) replicaBeforeWrite(ctx context.Context, slot uint16) error {
	if slot >= 64 {
		return model.Fail(model.Invalid)
	}
	if e.repl == nil || e.snap.hold.Load() || e.tomb.gate.Load() {
		return model.Fail(model.Unavailable)
	}
	_, err := e.repl.groups[slot].ReadIndex(ctx)
	return storageReplicaFault(err)
}

// proposalMu is held before e.mu. The applier takes only e.mu, and control apply
// never invokes an engine callback. Ready WAL is the only new-write WAL.
func (e *Engine) commitReplicated(slot uint16, index uint64, entry walEntry) error {
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	if slot >= 64 || index == 0 || index != e.indexes[slot]+1 {
		return model.Fail(model.Stale)
	}
	raw, err := encodeWAL(entry)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	kind := replica.Data
	var reservation *model.ID
	switch entry.Type {
	case "batch":
		if entry.Batch == nil {
			return model.Fail(model.Invalid)
		}
		id := entry.Batch.Reservation.ID
		reservation = &id
	case "cancel":
		kind = replica.Cancellation
		if entry.Cancel == nil {
			return model.Fail(model.Invalid)
		}
		id := entry.Cancel.ReservationID
		reservation = &id
	case "fence", "delete_barrier", "erase_ack", "erase_unack", "erase_notice":
		kind = replica.Barrier
	case "artifact_fragment":
		kind = replica.Artifact
	case "artifact_gc":
		kind = replica.ArtifactGC
	default:
		return model.Fail(model.Invalid)
	}
	command := replica.Entry{ID: model.NewID(), Kind: kind, Payload: raw, ReservationID: reservation, ApplicationIndex: index}
	group := e.repl.groups[slot]
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = group.Propose(ctx, command)
	cancel()
	e.mu.Lock()
	return storageReplicaFault(err)
}
func (m *slotMachine) Applied() uint64 {
	var applied uint64
	_ = m.engine.db.View(func(tx *bolt.Tx) error {
		applied = getUint(tx.Bucket([]byte("replica_data")), metaKey(m.slot, "physical"))
		return nil
	})
	return applied
}
func (m *slotMachine) decode(payload []byte) (walEntry, error) {
	m.validated.mu.Lock()
	if len(payload) > 0 && bytes.Equal(payload, m.validated.payload) {
		entry := m.validated.entry
		m.validated.mu.Unlock()
		return entry, nil
	}
	m.validated.mu.Unlock()
	return decodeWAL(payload)
}
func (m *slotMachine) adaptedEntry(c replica.CommittedEntry) (walEntry, error) {
	entry, err := m.decode(c.Entry.Payload)
	if err != nil {
		return entry, model.Fail(model.Corrupt)
	}
	if entry.Type == "erase_ack" || entry.Type == "erase_unack" || entry.Type == "erase_notice" {
		// The author of a statement about a voter's own stores is the proposer the replica layer
		// recorded, whatever the payload claimed; a command committed before attribution has none.
		entry.Proposer = c.Entry.Proposer
	}
	if entry.Type == "cancel" {
		if c.Entry.CommitSet == nil || entry.Cancel == nil || c.Entry.CommitSet.Group != c.Group || c.Entry.CommitSet.Reservation != entry.Cancel.ReservationID || c.Entry.CommitSet.PhysicalLast >= c.Index {
			return entry, model.Fail(model.Corrupt)
		}
		entry.CommitSet = c.Entry.CommitSet
	}
	return entry, nil
}
func (m *slotMachine) Apply(c replica.CommittedEntry) error {
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	logical := uint64(c.ApplicationCursor.Index)
	var physical uint64
	var stored []byte
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		physical = getUint(meta, metaKey(m.slot, "physical"))
		if c.Entry.Kind != replica.Noop {
			stored = bytes.Clone(tx.Bucket([]byte("replica_commands")).Get(commandKey(m.slot, logical)))
		}
		return nil
	}); err != nil {
		return err
	}
	entry := walEntry{}
	var err error
	if c.Entry.Kind != replica.Noop {
		entry, err = m.adaptedEntry(c)
		if err != nil {
			return err
		}
	}
	if c.Index <= physical {
		if c.Entry.Kind == replica.Noop {
			return nil
		}
		var original walEntry
		if len(stored) == 0 || json.Unmarshal(stored, &original) != nil {
			return model.Fail(model.Corrupt)
		}
		if original.Type == "rejected" && original.Rejection != nil && *original.Rejection == c.Entry.ID {
			return replica.ErrConflict
		}
		expected, err := encodeWAL(entry)
		if err != nil || !sameCommand(stored, expected) {
			return model.Fail(model.Corrupt)
		}
		return nil
	}
	if c.Index != physical+1 && physical != 0 {
		return model.Fail(model.Corrupt)
	}
	rejected := false
	if c.Entry.Kind != replica.Noop {
		if logical != e.indexes[m.slot]+1 {
			return model.Fail(model.Corrupt)
		}
		if entry.Batch != nil {
			err = e.db.View(func(tx *bolt.Tx) error {
				if tx.Bucket([]byte("cancelled")).Get([]byte(entry.Batch.Reservation.ID.String())) != nil {
					return model.Fail(model.Conflict)
				}
				return validateOrdered(tx, *entry.Batch)
			})
			if err != nil {
				var fault *model.Fault
				if !errors.As(err, &fault) || fault.Code != model.Conflict && fault.Code != model.Stale {
					return err
				}
				rejected = true
				entry = walEntry{Type: "rejected", Rejection: &c.Entry.ID}
			}
		}
		if entry.Artifact != nil && !rejected {
			err = e.db.View(func(tx *bolt.Tx) error {
				return validateTombstoneBlob(tx, entry.Artifact.Manifest, m.slot)
			})
			var deterministic bool
			if deterministic, err = orderedRejection(err); err != nil {
				return err
			}
			if deterministic {
				rejected = true
				entry = walEntry{Type: "rejected", Rejection: &c.Entry.ID}
			}
		}
		if err = e.trip("before_apply"); err != nil {
			e.failed = true
			return err
		}
	}
	var payload []byte
	if c.Entry.Kind != replica.Noop {
		payload, err = encodeWAL(entry)
		if err != nil {
			return err
		}
	}
	err = e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if c.Entry.Kind != replica.Noop {
			if err := e.applyTx(tx, m.slot, logical, entry); err != nil {
				return err
			}
			if err := tx.Bucket([]byte("replica_commands")).Put(commandKey(m.slot, logical), payload); err != nil {
				return err
			}
			if err := putUint(meta, metaKey(m.slot, "logical:"+strconv.FormatUint(logical, 10)), c.Index); err != nil {
				return err
			}
		}
		for name, value := range map[string]uint64{"physical": c.Index, "application": logical, "term": c.Term} {
			if err := putUint(meta, metaKey(m.slot, name), value); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		e.failed = true
		return err
	}
	if c.Entry.Kind != replica.Noop {
		e.indexes[m.slot] = logical
		if !rejected {
			e.publishCommittedLocked(m.slot, logical, entry)
			if entry.Type == "delete_barrier" {
				go e.noteDeletion() // never under e.mu or a group lock: Abort releases journal pins
			}
		}
	}
	if rejected {
		return replica.ErrConflict
	}
	return nil
}
func (m *slotMachine) Snapshot() ([]byte, error) {
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed || e.closed {
		return nil, model.Fail(model.Unavailable)
	}
	entries, err := e.historyLocked(m.slot)
	if err != nil {
		return nil, err
	}
	return json.Marshal(slotSnapshot{Version: 1, Identity: e.identity, Slot: m.slot, Application: model.Uint64(e.indexes[m.slot]), Entries: entries})
}
func (m *slotMachine) VerifySnapshot(raw []byte) error {
	var snapshot slotSnapshot
	if model.StrictJSON(raw, &snapshot) != nil || snapshot.Version != 1 || snapshot.Identity != m.engine.identity || snapshot.Slot != m.slot || uint64(len(snapshot.Entries)) != uint64(snapshot.Application) {
		return model.Fail(model.Corrupt)
	}
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.indexes[m.slot] < uint64(snapshot.Application) {
		return nil
	}
	return e.db.View(func(tx *bolt.Tx) error {
		commands := tx.Bucket([]byte("replica_commands"))
		for index, raw := range snapshot.Entries {
			if !sameCommand(commands.Get(commandKey(m.slot, uint64(index+1))), raw) {
				return model.Fail(model.Corrupt)
			}
		}
		return nil
	})
}
func (m *slotMachine) Restore(raw []byte, physical uint64) error {
	var snapshot slotSnapshot
	if model.StrictJSON(raw, &snapshot) != nil || snapshot.Version != 1 || snapshot.Slot != m.slot || uint64(len(snapshot.Entries)) != uint64(snapshot.Application) {
		return model.Fail(model.Corrupt)
	}
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if snapshot.Identity != e.identity || e.indexes[m.slot] > uint64(snapshot.Application) {
		return model.Fail(model.Conflict)
	}
	// An install that replays data commands can put erased rows back into the live buckets, so
	// the facts "this voter erased the operation" and "this voter acknowledged it" stop being
	// true with the bytes. A command replayed from the snapshot that creates records, or a
	// redacted one that keeps the records of other operations, makes the install such a replay.
	dataBearing, owesWithdrawal := false, false
	err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		commands := tx.Bucket([]byte("replica_commands"))
		for index, raw := range snapshot.Entries {
			logical := uint64(index + 1)
			var entry walEntry
			if json.Unmarshal(raw, &entry) != nil {
				return model.Fail(model.Corrupt)
			}
			if logical <= e.indexes[m.slot] {
				if !sameCommand(commands.Get(commandKey(m.slot, logical)), raw) {
					return model.Fail(model.Corrupt)
				}
			} else {
				if err := e.applyTx(tx, m.slot, logical, entry); err != nil {
					return err
				}
				if err := commands.Put(commandKey(m.slot, logical), raw); err != nil {
					return err
				}
				switch entry.Type {
				case "batch", "batch_redacted", "artifact_fragment":
					dataBearing = true
				}
			}
			if entry.Cancel != nil {
				if err := putUint(meta, metaKey(m.slot, "logical:"+strconv.FormatUint(logical, 10)), physical); err != nil {
					return err
				}
			}
		}
		if dataBearing {
			var err error
			if owesWithdrawal, err = invalidateErasureTx(tx); err != nil {
				return err
			}
		}
		if err := putUint(meta, metaKey(m.slot, "physical"), physical); err != nil {
			return err
		}
		return putUint(meta, metaKey(m.slot, "application"), uint64(snapshot.Application))
	})
	if err == nil {
		if owesWithdrawal {
			e.erasure.wakeLoop()
		}
		previous := e.indexes[m.slot]
		e.indexes[m.slot] = uint64(snapshot.Application)
		if previous < e.indexes[m.slot] {
			e.snapshotGapLocked(m.slot)
		}
		// The installed retry table comes from the sender's cut, which may predate commands this
		// node already redacted: the next reconciliation repeats the redaction.
		e.markRedact(m.slot)
	}
	return err
}

// BeforeSnapshotSend and AdmitSnapshot make the slot machine a replica.SnapshotGate (erase_notice.go).
func (m *slotMachine) BeforeSnapshotSend(ctx context.Context, to uint64) ([]byte, error) {
	return m.engine.beforeSnapshotSend(ctx, to)
}
func (m *slotMachine) AdmitSnapshot(token []byte) (func(), error) {
	return m.engine.admitSnapshot(token)
}
func (m *slotMachine) Validate(ctx context.Context, command replica.Entry) error {
	entry, err := m.decode(command.Payload)
	if err != nil || !m.validRouting(command, entry) {
		return model.Fail(model.Invalid)
	}
	switch command.Kind {
	case replica.Data:
		if entry.Type != "batch" || entry.Batch == nil {
			return model.Fail(model.Invalid)
		}
		if err := m.authority.ValidateReplicatedBatch(ctx, *entry.Batch); err != nil {
			return err
		}
	case replica.Artifact:
		if entry.Type != "artifact_fragment" || entry.Artifact == nil {
			return model.Fail(model.Invalid)
		}
		if err := m.authority.ValidateReplicatedFragment(ctx, *entry.Artifact); err != nil {
			return err
		}
		m.validated.mu.Lock()
		m.validated.payload, m.validated.entry = bytes.Clone(command.Payload), entry
		m.validated.mu.Unlock()
	case replica.ArtifactGC:
		if entry.Type != "artifact_gc" || entry.ArtifactGC == nil {
			return model.Fail(model.Invalid)
		}
		if err := m.authority.ValidateReplicatedGC(ctx, *entry.ArtifactGC); err != nil {
			return err
		}
	case replica.Barrier:
		if entry.Type == "delete_barrier" {
			if entry.DeleteBarrier == nil {
				return model.Fail(model.Invalid)
			}
			if err := m.authority.ValidateReplicatedDeleteBarrier(ctx, *entry.DeleteBarrier); err != nil {
				return err
			}
			break
		}
		if entry.Type == "erase_ack" {
			if entry.EraseAck == nil {
				return model.Fail(model.Invalid)
			}
			break
		}
		if entry.Type == "erase_unack" {
			if entry.EraseUnack == nil {
				return model.Fail(model.Invalid)
			}
			break
		}
		if entry.Type == "erase_notice" {
			if entry.EraseNotice == nil {
				return model.Fail(model.Invalid)
			}
			break
		}
		if entry.Type != "fence" || entry.Fence == nil {
			return model.Fail(model.Invalid)
		}
		if err := m.authority.ValidateReplicatedFence(ctx, *entry.Fence); err != nil {
			return err
		}
	case replica.Cancellation:
		if entry.Type != "cancel" || entry.Cancel == nil {
			return model.Fail(model.Invalid)
		}
		if err := m.authority.ValidateReplicatedCancellation(ctx, *entry.Cancel); err != nil {
			return err
		}
	default:
		return model.Fail(model.Invalid)
	}
	e := m.engine
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	if command.ApplicationIndex != e.indexes[m.slot]+1 {
		return model.Fail(model.Stale)
	}
	return e.db.View(func(tx *bolt.Tx) error {
		if entry.Batch != nil {
			return validateOrdered(tx, *entry.Batch)
		}
		if entry.Artifact != nil {
			return validateBlobFence(tx, entry.Artifact.Manifest, m.slot)
		}
		return nil
	})
}
func (e *Engine) replicaReadFence(ctx context.Context, minimum []model.Cursor, allowPartial bool) ([]model.Cursor, bool, error) {
	if e.repl == nil {
		return nil, false, model.Fail(model.Unavailable)
	}
	marks := make([]model.Cursor, 0, 64)
	partial := false
	for _, group := range e.repl.groups {
		mark, err := group.ReadIndex(ctx)
		if err != nil {
			if !allowPartial {
				return nil, false, storageReplicaFault(err)
			}
			partial = true
			continue
		}
		marks = append(marks, mark)
	}
	for _, min := range minimum {
		found := false
		for _, mark := range marks {
			if mark.Group == min.Group && mark.Index >= min.Index {
				found = true
			}
		}
		if !found {
			if !allowPartial {
				return nil, false, model.Fail(model.Stale)
			}
			partial = true
			for i, mark := range marks {
				if mark.Group == min.Group {
					marks = append(marks[:i], marks[i+1:]...)
					break
				}
			}
		}
	}
	return marks, partial, nil
}
func (e *Engine) replicaReleaseFenceLocked(ctx context.Context, marks []model.Cursor) error {
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	e.mu.Unlock()
	defer e.mu.Lock()
	for _, mark := range marks {
		var owner *replica.Group
		for slot, group := range e.repl.groups {
			if e.group(uint16(slot)) == mark.Group {
				owner = group
				break
			}
		}
		if owner == nil {
			return model.Fail(model.Stale)
		}
		cut, err := owner.ReadIndex(ctx)
		if err != nil {
			return storageReplicaFault(err)
		}
		if cut.Index < mark.Index {
			return model.Fail(model.Stale)
		}
	}
	return nil
}
func (e *Engine) replicaBeforeCursor(ctx context.Context, cursor model.Cursor) error {
	if e.repl == nil {
		return model.Fail(model.Unavailable)
	}
	for slot, group := range e.repl.groups {
		if e.group(uint16(slot)) == cursor.Group {
			cut, err := group.ReadIndex(ctx)
			if err != nil {
				return storageReplicaFault(err)
			}
			if cut.Index < cursor.Index {
				return model.Fail(model.Stale)
			}
			return nil
		}
	}
	return model.Fail(model.Stale)
}
func (e *Engine) AdmissionOutcomes(ctx context.Context) ([]model.FinalizeAdmission, error) {
	if _, _, err := e.replicaReadFence(ctx, nil, false); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed || e.closed {
		return nil, model.Fail(model.Unavailable)
	}
	out := []model.FinalizeAdmission{}
	err := e.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("consumed")).ForEach(func(_, raw []byte) error {
			var reservation model.AdmissionReservation
			if json.Unmarshal(raw, &reservation) != nil || reservation.State != "consumed" || reservation.Cursor == nil {
				return model.Fail(model.Corrupt)
			}
			out = append(out, model.FinalizeAdmission{ReservationID: reservation.ID, Cursor: *reservation.Cursor})
			return nil
		})
	})
	return out, err
}
func (e *Engine) ReplicaGroups() []*replica.Group {
	if e.repl == nil {
		return nil
	}
	return append([]*replica.Group(nil), e.repl.groups[:]...)
}

// publishManifestLocked requires e.mu for the whole call and holds it: it takes
// no group lock and makes no quorum round trip, so a voter publishes its own
// layout whether it leads every group, some groups or none (see
// publishManifestLocalLocked). A publication is allowed only once replication is
// installed; before that no node-local layout is authoritative.
func (e *Engine) publishManifestLocked(ctx context.Context, group model.ID, expected model.Revision, replacement Manifest, updates []pageRef) (model.Revision, error) {
	if e.repl == nil {
		return 0, model.Fail(model.Unavailable)
	}
	revision, err := e.publishManifestLocalLocked(ctx, group, expected, replacement, updates)
	if err != nil {
		return 0, storageReplicaFault(err)
	}
	return revision, nil
}

// Bind the ledger reservation and embedded C05 cursor to this installed slot
// before ordering; malformed peers cannot poison a different group's applier.
func (m *slotMachine) validRouting(command replica.Entry, entry walEntry) bool {
	owner := m.engine.group(m.slot)
	index := model.Uint64(command.ApplicationIndex)
	switch command.Kind {
	case replica.Data:
		batch, receipt := entry.Batch, entry.Receipt
		return batch != nil && receipt != nil && batch.Version == 1 && len(batch.Records) > 0 && len(batch.Records) <= 512 && batch.RouteSlot == m.slot && receipt.Cursor.Group == owner && receipt.Cursor.Index == index && receipt.Hash == batch.Hash && receipt.BatchID == batch.ID && command.ReservationID != nil && *command.ReservationID == batch.Reservation.ID
	case replica.Cancellation:
		return entry.Cancel != nil && entry.Cancel.OwnerGroup == owner && entry.Cancel.Fence.Group == owner && entry.Cancel.Fence.Index == index && command.ReservationID != nil && *command.ReservationID == entry.Cancel.ReservationID
	case replica.Barrier:
		if entry.Type == "delete_barrier" {
			b := entry.DeleteBarrier
			return b != nil && entry.Fence == nil && command.ReservationID == nil && b.Cursor == (model.Cursor{Group: owner, Index: index}) && b.Predicate.Validate() == nil
		}
		if entry.Type == "erase_ack" {
			a := entry.EraseAck
			return m.slot == eraseAckSlot && a.valid() && entry.EraseUnack == nil && entry.Proposer == nil && proposedBy(command.Proposer, a.Node, a.Identity) && entry.Fence == nil && command.ReservationID == nil && a.Cursor == (model.Cursor{Group: owner, Index: index})
		}
		if entry.Type == "erase_unack" {
			u := entry.EraseUnack
			return m.slot == eraseAckSlot && u.valid() && entry.EraseAck == nil && entry.Proposer == nil && proposedBy(command.Proposer, u.Node, u.Identity) && entry.Fence == nil && command.ReservationID == nil && u.Cursor == (model.Cursor{Group: owner, Index: index})
		}
		if entry.Type == "erase_notice" {
			n := entry.EraseNotice
			return m.slot == eraseAckSlot && n.valid() && entry.EraseAck == nil && entry.EraseUnack == nil && entry.Proposer == nil && command.Proposer != nil && entry.Fence == nil && command.ReservationID == nil && n.Cursor == (model.Cursor{Group: owner, Index: index})
		}
		return entry.Fence != nil && command.ReservationID == nil && len(entry.Fence.Barriers) == 1 && entry.Fence.Barriers[0].Group == owner && entry.Fence.Barriers[0].Index == index
	case replica.Artifact:
		return entry.Artifact != nil && command.ReservationID == nil && model.BlobOwnerSlot(entry.Artifact.Manifest.Org, entry.Artifact.Manifest.Project, entry.Artifact.Manifest.Root) == m.slot && entry.Artifact.Cursor.Group == owner && entry.Artifact.Cursor.Index == index
	case replica.ArtifactGC:
		return entry.ArtifactGC != nil && command.ReservationID == nil && entry.ArtifactGC.Cursor != nil && model.BlobOwnerSlot(entry.ArtifactGC.Manifest.Org, entry.ArtifactGC.Manifest.Project, entry.ArtifactGC.Manifest.Root) == m.slot && entry.ArtifactGC.Cursor.Group == owner && entry.ArtifactGC.Cursor.Index == index
	}
	return false
}

// Snapshot installation can skip an incremental delivery interval. Expose a
// certified catch-up gap instead of silently losing a committed live event.
func (e *Engine) snapshotGapLocked(slot uint16) {
	if len(e.subscribers) == 0 {
		return
	}
	cursor := model.Cursor{Group: e.group(slot), Index: model.Uint64(e.indexes[slot])}
	for iterator := range e.subscribers {
		advanceWatermark(iterator.marks, cursor)
	drain:
		for {
			select {
			case <-iterator.events:
			default:
				break drain
			}
		}
		iterator.pending = nil
		iterator.offset = 0
		iterator.epoch++
		iterator.gap = &ChangeGap{After: append([]model.Cursor(nil), iterator.delivered...), Through: append([]model.Cursor(nil), iterator.marks...), Reason: "catch_up_required"}
		iterator.events <- committedEvent{Epoch: iterator.epoch}
	}
}
