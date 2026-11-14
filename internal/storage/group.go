// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Revalidator interface {
	Revalidate(context.Context, auth.Scope) error
}

// Group is the single ordered state-machine seam for both the current one-voter
// proposer and the later Raft proposer. Commit applies only fsynced entries.
type Group interface {
	Append(context.Context, auth.Scope, model.NormalizedBatch) (model.Receipt, error)
}
type Engine struct {
	mu           sync.Mutex
	proposalMu   sync.Mutex
	repl         *replicatedEngine
	db           *bolt.DB
	dir          string
	identity     model.ID
	incarnation  string // hex; the random id of this disk's data directory (ensureIncarnation)
	files        [64]*os.File
	indexes      [64]uint64
	validator    Revalidator
	fault        func(string) error
	failed       bool
	closed       bool
	catalog      manifestState
	scans        map[*rowIterator]struct{}
	subscribers  map[*changeIterator]struct{}
	storageStats StorageStats
	snap         snapshotState
	pressure     pressureState
	tomb         tombstoneState
	scrub        scrubConfig
	redact       redactState
	erasure      erasureState
}
type walEntry struct {
	Type       string                      `json:"type"`
	Batch      *model.NormalizedBatch      `json:"batch,omitempty"`
	Receipt    *model.Receipt              `json:"receipt,omitempty"`
	Cancel     *model.CancelReservation    `json:"cancel,omitempty"`
	Fence      *model.SourceFence          `json:"fence,omitempty"`
	Artifact   *model.ArtifactFragment     `json:"artifact,omitempty"`
	ArtifactGC *model.ArtifactGC           `json:"artifact_gc,omitempty"`
	Rejection  *model.ID                   `json:"rejection,omitempty"`
	CommitSet  *replica.CommitSetWatermark `json:"commit_set,omitempty"`
	// DeleteBarrier is the data-slot tombstone of a C12 deletion saga
	// (Type "delete_barrier", replicated as a replica.Barrier).
	DeleteBarrier *model.DeleteBarrier `json:"delete_barrier,omitempty"`
	// EraseAck is one voter's statement that its own copy of the listed deletion operations'
	// bytes is gone and scrubbed (Type "erase_ack", replicated as a replica.Barrier in slot 0).
	EraseAck *eraseAck `json:"erase_ack,omitempty"`
	// EraseUnack is one voter's withdrawal of every acknowledgement it made before the stated
	// installation epoch (Type "erase_unack", slot 0): its own stores took bytes in that an
	// acknowledgement said were gone.
	EraseUnack *eraseUnack `json:"erase_unack,omitempty"`
	// EraseNotice is a sender's statement, ordered before it sends a snapshot to the member it names
	// (Type "erase_notice", slot 0): that member's earlier acknowledgements no longer stand, whatever
	// the snapshot turns out to carry.
	EraseNotice *eraseNotice `json:"erase_notice,omitempty"`
	// Proposer is the member that proposed an erase_ack, erase_unack or erase_notice, copied from the replicated
	// entry that carried it (replica.Entry.Proposer; the payload never carries it). The statement
	// counts only when it names this member; a command committed before the field existed has
	// none and is not attributed.
	Proposer *replica.Proposer `json:"proposer,omitempty"`
	// Redaction marks a stored command whose erased records were physically
	// removed locally (Type "batch_redacted"/"artifact_redacted"). It is never
	// proposed to Raft: every voter derives it from the replicated tombstone.
	Redaction *redaction `json:"redaction,omitempty"`
}

// redaction describes a locally rewritten command. Original is the SHA-256 of
// the exact bytes the Raft journal committed, so replaying that entry is
// recognised as the same command rather than as corruption.
type redaction struct {
	Original   model.Hash `json:"original"`
	Erased     uint32     `json:"erased"`
	Operations []model.ID `json:"operations,omitempty"` // tombstones/expiry that caused the erasure
}

func Open(dir string, v Revalidator) (*Engine, error) {
	if v == nil {
		return nil, model.Fail(model.Invalid)
	}
	if e := durablefs.MkdirAll(dir); e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "apply.db")
	info, statErr := os.Stat(path)
	fresh := os.IsNotExist(statErr)
	if statErr != nil && !fresh {
		return nil, statErr
	}
	if !fresh && !info.Mode().IsRegular() {
		return nil, model.Fail(model.Corrupt)
	}
	var preparedIdentity model.ID
	if fresh {
		for slot := range uint16(64) {
			if _, err := os.Stat(filepath.Join(dir, walName(slot))); err == nil {
				return nil, model.Fail(model.Corrupt)
			} else if !os.IsNotExist(err) {
				return nil, err
			}
		}
		preparedIdentity = model.NewID()
	}
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	out := &Engine{db: db, dir: dir, validator: v}
	if e = durablefs.SyncFileAndDir(path); e != nil {
		db.Close()
		return nil, e
	}
	buckets := []string{"meta", "receipts", "batches", "metrics", "jobs", "consumed", "cursors", "cancelled", "fences"}
	if fresh {
		out.identity = preparedIdentity
		e = db.Update(func(tx *bolt.Tx) error {
			for _, name := range buckets {
				if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
					return err
				}
			}
			return tx.Bucket([]byte("meta")).Put([]byte("identity"), preparedIdentity[:])
		})
	} else {
		e = db.View(func(tx *bolt.Tx) error {
			for _, name := range buckets {
				if tx.Bucket([]byte(name)) == nil {
					return model.Fail(model.Corrupt)
				}
			}
			raw := tx.Bucket([]byte("meta")).Get([]byte("identity"))
			if len(raw) != 16 {
				return model.Fail(model.Corrupt)
			}
			copy(out.identity[:], raw)
			if out.identity == (model.ID{}) {
				return model.Fail(model.Corrupt)
			}
			return nil
		})
	}
	if e == nil {
		e = out.ensureIncarnation()
	}
	if e == nil {
		e = out.validateReplicaNamespaces()
	}
	if e == nil {
		e = out.initBlobs()
	}
	if e == nil {
		e = out.initStorage()
	}
	if e == nil {
		e = out.recover()
	}
	if e != nil {
		out.Close()
		return nil, e
	}
	return out, nil
}
func (e *Engine) Close() error {
	e.erasure.cancelLoop()
	if e.repl != nil {
		for _, group := range e.repl.groups {
			_ = group.Close()
		}
	}
	e.erasure.waitLoop()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.closeSubscribersLocked()
	var err error
	for _, f := range e.files {
		if f != nil {
			if x := f.Close(); err == nil {
				err = x
			}
		}
	}
	if x := e.db.Close(); err == nil {
		err = x
	}
	return err
}
func (e *Engine) trip(at string) error {
	if e.fault != nil {
		return e.fault(at)
	}
	return nil
}
func (e *Engine) group(slot uint16) model.ID {
	var in [18]byte
	copy(in[:16], e.identity[:])
	binary.BigEndian.PutUint16(in[16:], slot)
	h := sha256.Sum256(in[:])
	var id model.ID
	copy(id[:], h[:16])
	return id
}
func walName(slot uint16) string { return fmt.Sprintf("slot-%02d.wal", slot) }
func batchKey(org, project, source, producer model.ID, slot uint16, batch model.ID) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s:%s:%02d:%s", org, project, source, producer, slot, batch))
}
func slotKey(slot uint16) []byte { var b [2]byte; binary.BigEndian.PutUint16(b[:], slot); return b[:] }
func (e *Engine) Append(ctx context.Context, scope auth.Scope, b model.NormalizedBatch) (model.Receipt, error) {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if err := e.replicaBeforeWrite(ctx, b.RouteSlot); err != nil {
		return model.Receipt{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	if err := ctx.Err(); err != nil {
		return model.Receipt{}, model.Fail(model.Cancelled)
	}
	if b.Version != 1 || len(b.Records) > 512 || len(b.Canonical) > 4<<20 {
		return model.Receipt{}, model.Fail(model.TooLarge)
	}
	if b.RouteSlot >= 64 || b.Org != scope.OrgID() || len(b.Records) == 0 || uint64(b.PolicyEpoch) != scope.PolicyEpoch() {
		return model.Receipt{}, model.Fail(model.Forbidden)
	}
	if err := e.validator.Revalidate(ctx, scope); err != nil {
		return model.Receipt{}, err
	}
	if err := scope.RevalidateSource(ctx, b.Project, b.Source, true); err != nil {
		return model.Receipt{}, err
	}
	key := batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID)
	var old model.Receipt
	found := false
	err := e.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("receipts")).Get(key)
		if raw == nil {
			return nil
		}
		found = true
		if json.Unmarshal(raw, &old) != nil {
			return model.Fail(model.Corrupt)
		}
		if old.Hash != b.Hash {
			return model.Fail(model.Conflict)
		}
		return nil
	})
	if err != nil {
		return model.Receipt{}, err
	}
	if found {
		return old, nil
	}
	if err = e.admitPressure(batchClass(b.Records), uint64(len(b.Canonical))); err != nil {
		return model.Receipt{}, err
	}
	canonical, err := model.CanonicalJSON(b.Batch)
	if err != nil || !bytes.Equal(canonical, b.Canonical) || model.HashCanonical(canonical) != b.Hash {
		return model.Receipt{}, model.Fail(model.Invalid)
	}
	for _, r := range b.Records {
		slot, err := model.OwnerSlot(b.Org, b.Project, b.Source, b.Producer, r)
		if err != nil || slot != b.RouteSlot {
			return model.Receipt{}, model.Fail(model.Invalid)
		}
	}
	if err = scope.ValidateReservation(ctx, b); err != nil {
		return model.Receipt{}, err
	}
	if err = e.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("cancelled")).Get([]byte(b.Reservation.ID.String())) != nil {
			return model.Fail(model.Conflict)
		}
		return validateOrdered(tx, b)
	}); err != nil {
		return model.Receipt{}, err
	}
	if err = e.writeDeletions(ctx, b); err != nil {
		return model.Receipt{}, err
	}
	index := e.indexes[b.RouteSlot] + 1
	r := model.Receipt{Version: 1, BatchID: b.ID, Hash: b.Hash, Cursor: model.Cursor{Group: e.group(b.RouteSlot), Index: model.Uint64(index)}, SignalDeadlines: append([]model.SignalDeadline(nil), b.Deadlines...), DedupUntil: b.AdmissionAt + model.UnixNano(7*24*time.Hour)}
	if len(r.SignalDeadlines) == 0 {
		return model.Receipt{}, model.Fail(model.Invalid)
	}
	r.RetainUntil = r.SignalDeadlines[0].RetainUntil
	for _, d := range r.SignalDeadlines {
		if d.RetainUntil < r.RetainUntil {
			r.RetainUntil = d.RetainUntil
		}
	}
	entry := walEntry{Type: "batch", Batch: &b, Receipt: &r}
	if err = e.commit(b.RouteSlot, index, entry); err != nil {
		return model.Receipt{}, err
	}
	return r, nil
}

// commit is deliberately the sole durable ordered-apply path. There is no
// parallel in-memory implementation and no enqueue acknowledgement.
func (e *Engine) commit(slot uint16, index uint64, entry walEntry) error {
	return e.commitReplicated(slot, index, entry)
}
