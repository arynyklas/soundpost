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
	"sync/atomic"
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
	// repl and identity are written only by EnableReplication (repl) and
	// InstallReplicationIdentity (identity, catalog.Manifest.Group) with proposalMu AND mu held,
	// and by Open before the engine is shared. A reader holds either lock, or runs only after
	// EnableReplication returned (the replica groups; InstallReplicationIdentity refuses once repl
	// is set), or is the background verification, which copies identity under mu (VerifyFull).
	mu engineMu
	// proposalMu is held exclusively by every proposer that needs the engine free of other
	// proposals (fences, barriers, snapshots, blob and erase commands) and shared by Append,
	// which orders itself per slot (slotMu): appends of different slots overlap their round trips
	// and fsyncs, appends of one slot take their application indexes one at a time.
	proposalMu sync.RWMutex
	slotMu     [64]sync.Mutex
	repl       *replicatedEngine
	db         *trackedDB
	dir        string
	// cutMu is held shared by a snapshot cut deriving the windows of its slot without mu (windowTableForCut,
	// DeletionLedger, PinFiles) and exclusively by erasure, the writer that rewrites stored commands. Lock order:
	// cutMu, then mu (the cut takes mu only for a moment, to read the slot's index and the engine's flags).
	cutMu sync.RWMutex
	// cutEpoch is bumped, with cutMu held exclusively, before stored commands are rewritten; windows are the derivations of the open
	// window of each slot (windowCache), valid while the epoch they were built under is the current one.
	cutEpoch atomic.Uint64
	windows  [64]windowCache
	// expiry is the error evidence the journal-expiry plan found in the stored commands, kept so that the next plan reads only the
	// commands appended since (expiry_scan.go); valid while cutEpoch is the one it was built under.
	expiry expiryScan
	// runsLayout is whether the query indexes of the open file are in the runs layout (index_acc.go). A
	// file starts in the single-bucket layout the previous release reads and moves to the runs layout
	// when the installation is contracted (adoptRunsLayout): from then on no previous release is a
	// member. layoutAuthority is where the engine asks.
	runsLayout atomic.Bool
	// payload is the owned payload log (paylog.go), opened with the engine; payloadOn is whether the file has adopted the layout that
	// writes payload references (scanIndexPayload): from then on no previous release can open it.
	payload   *payloadLog
	payloadOn atomic.Bool
	// payloadSweptFrom, payloadDebt, payloadDirty: the sweep of records no reference names (payload_sweep.go). payloadSweptFrom is
	// the position in the log up to which every record is known to be named or dead and zeroed (the mark of the file at open, then
	// the end of the last sweep); payloadDebt is whether the log holds a span past it that a crashed process may have left unnamed
	// records in; payloadDirty is whether this process itself left an append whose commit failed.
	payloadSweepMu   sync.Mutex
	payloadSweptFrom payloadPos
	payloadDebt      atomic.Bool
	payloadDirty     atomic.Bool
	payloadSweepSeen bool     // loadPayloadSwept ran: payloadDebt is known
	externalized     sync.Map // final run buckets whose blocks are all in the log (payload_blocks.go), by bucket name
	layoutAuthority  atomic.Pointer[ReplicatedAuthority]
	settle           settleState  // what the settlement pass remembers between passes (settle.go)
	contractedSeen   atomic.Bool  // the installation was seen contracted (protocolToDeclare)
	contractedAsked  atomic.Int64 // when it was last asked, unix nanoseconds
	indexMerger      indexMerger
	identity         model.ID
	incarnation      string // hex; the random id of this disk's data directory (ensureIncarnation); read through disk()
	incMu            sync.RWMutex
	self             atomic.Pointer[selfRef] // this voter's own member, recorded by EnableReplication
	files            [64]*os.File
	indexes          [64]uint64
	validator        Revalidator
	faultHook        atomic.Pointer[func(string) error]
	injected         atomic.Pointer[func(string) error]
	failed           bool
	closed           bool
	catalog          manifestState
	scans            map[*rowIterator]struct{}
	subscribers      map[*changeIterator]struct{}
	storageStats     StorageStats
	snap             snapshotState
	pressure         pressureState
	journal          journalHolds // held lifecycle evidence journals (journal_hold.go)
	tomb             tombstoneState
	scrub            scrubConfig
	redact           redactState
	erasure          erasureState
	ver              verifyState // bounded startup verification (D15)
	closing          atomic.Bool // set when Close starts: long publications stop at their next check
	// fragmentEnvelope selects the binary wire form for artifact fragment proposals
	// (envelope.go); envelopesProposed counts the proposals that used it.
	fragmentEnvelope  atomic.Bool
	envelopesProposed atomic.Uint64
	// afterSubscribeFence is a test seam: called by Subscribe between its read fence and its registration
	// (nothing is held), so a test can commit exactly there. Nil in production.
	afterSubscribeFence func()
	// duringReleaseFence is a test seam: called while a live subscription's release fence runs (e.mu is not
	// held), so a test can commit exactly while a page is being certified. Nil in production.
	duringReleaseFence func()
	// replayYield is a test seam: called each time a replay's scan of irrelevant commits gives up e.mu (it is
	// not held while the hook runs), so a test can see the scan is bounded. Nil in production.
	replayYield func()
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

// openApplyDB opens apply.db with durablefs.BoltOptions (no freelist in the commits, the array freelist, mapped ahead of its growth). A
// file that carries no freelist (a crash left it so) is opened by a pass over the nodes of its live tree (bolt: PreLoadFreelist), a page
// fault after the other: 14 s for the 107,000 nodes of the file the single-host gate leaves, on a cold disk. The warm-up reads those pages
// 64 at a time first (durablefs.WarmBoltTree), so that bolt's pass finds them in the cache. The crash-restart tests open a file with
// exactly these.
func openApplyDB(path string) (*bolt.DB, error) {
	durablefs.WarmBoltTree(path)
	return bolt.Open(path, 0600, durablefs.BoltOptions())
}

// Open opens the engine at dir. The background verification (verified.go) starts a full pass at once.
func Open(dir string, v Revalidator) (*Engine, error) { return open(dir, v, false) }

// OpenReplicated is Open for a node that enables replication next (EnableReplication): the first full pass of the background
// verification waits until the start is complete and then verifyStartDelay more, instead of reading the whole node (every index entry,
// every record of the payload log) while the start replays the journals from the same cold disk: at the single-host gate that pass was
// 10 of the 39 CPU seconds of the first 13 seconds of a cold start and read as much as the start did itself (L2w20Admission30). A
// start still verifies what the verified record does not vouch for before readiness; only the background re-check is later.
func OpenReplicated(dir string, v Revalidator) (*Engine, error) { return open(dir, v, true) }

func open(dir string, v Revalidator, deferFirstPass bool) (*Engine, error) {
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
	// The freelist is NOT persisted by the commits (D91): a commit that persists it writes every free and pending page id of the file
	// (8 bytes each) next to its own dirty pages, and the file of the single-host gate is mostly free pages (166,000 of 206,000 pages
	// at 100 commits a second: a 1.3 MB overflow node per commit, 64 % of everything the server wrote, L2w20Admission26). A graceful
	// close writes it once (syncFreelist); a start after a crash rebuilds it from the live tree (bolt: PreLoadFreelist), which is a
	// pass over the pages the tree holds, not over the file (the file keeps its blocks as overflow nodes, index_blocks.go).
	// The file is mapped ahead of its growth (durablefs.BoltInitialMmapSize): a commit that grows it past the mapping waits for every
	// read transaction, and every new reader waits for that commit.
	db, e := openApplyDB(path)
	if e != nil {
		return nil, e
	}
	out := &Engine{db: &trackedDB{DB: db}, dir: dir, validator: v}
	pl, e := openPayloadLog(filepath.Join(dir, payloadDirName))
	if e != nil {
		db.Close()
		return nil, e
	}
	out.payload = pl
	payloadLogs.Store(db, pl)
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
		e = out.loadPayloadSwept()
	}
	if e == nil {
		out.loadVerifiedRecord()
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
	out.commitVerifiedStart()
	if deferFirstPass {
		out.ver.first = make(chan struct{})
	}
	out.startBackgroundVerify()
	out.startIndexMerger()
	return out, nil
}

// closeDeadline bounds how long Close waits for a running publication (it holds e.mu for a whole
// segment rewrite). A publication also notices e.closing and stops at its next check, so the wait
// is normally short; past the deadline Close reports model.Timeout and may be called again.
var closeDeadline = 30 * time.Second

// lockWithin takes e.mu, giving up after d.
func (e *Engine) lockWithin(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !e.mu.TryLock() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// lockCtx takes e.mu, giving up when ctx ends.
func (e *Engine) lockCtx(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	for !e.mu.TryLock() {
		if ctx.Err() != nil {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}
func (e *Engine) Close() error {
	e.closing.Store(true)
	e.stopIndexMerger()
	e.stopBackgroundVerify()
	e.erasure.cancelLoop()
	if e.repl != nil {
		for _, group := range e.repl.groups {
			_ = group.Close()
		}
	}
	e.erasure.waitLoop()
	e.verifyAtClose()
	if !e.lockWithin(closeDeadline) {
		return model.Fail(model.Timeout)
	}
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
	payloadLogs.Delete(e.db.DB)
	e.markPayloadClean()
	if !e.failed {
		if x := e.db.syncFreelist(); err == nil {
			err = x
		}
	}
	if e.payload != nil {
		if x := e.payload.close(); err == nil {
			err = x
		}
	}
	if x := e.db.Close(); err == nil {
		err = x
	}
	return err
}

// setFault installs (or, with nil, removes) the in-package fault hook; group goroutines may be
// consulting trip while a test replaces it.
func (e *Engine) setFault(hook func(string) error) {
	if hook == nil {
		e.faultHook.Store(nil)
		return
	}
	e.faultHook.Store(&hook)
}
func (e *Engine) trip(at string) error {
	if h := e.faultHook.Load(); h != nil {
		return (*h)(at)
	}
	if h := e.injected.Load(); h != nil {
		return (*h)(at)
	}
	return nil
}

// groupOf names the replica group of slot under an identity: the first 16 bytes of
// SHA-256(identity || slot). It reads no engine state.
func groupOf(identity model.ID, slot uint16) model.ID {
	var in [18]byte
	copy(in[:16], identity[:])
	binary.BigEndian.PutUint16(in[16:], slot)
	h := sha256.Sum256(in[:])
	var id model.ID
	copy(id[:], h[:16])
	return id
}
func (e *Engine) group(slot uint16) model.ID {
	return groupOf(e.identity, slot)
}
func walName(slot uint16) string { return fmt.Sprintf("slot-%02d.wal", slot) }
func batchKey(org, project, source, producer model.ID, slot uint16, batch model.ID) []byte {
	return []byte(fmt.Sprintf("%s:%s:%s:%s:%02d:%s", org, project, source, producer, slot, batch))
}
func slotKey(slot uint16) []byte { var b [2]byte; binary.BigEndian.PutUint16(b[:], slot); return b[:] }
func (e *Engine) Append(ctx context.Context, scope auth.Scope, b model.NormalizedBatch) (model.Receipt, error) {
	if b.RouteSlot >= 64 {
		return model.Receipt{}, model.Fail(model.Invalid)
	}
	e.proposalMu.RLock()
	defer e.proposalMu.RUnlock()
	if err := e.replicaBeforeWrite(ctx, b.RouteSlot); err != nil {
		return model.Receipt{}, err
	}
	// e.mu is held only to read the engine's state, never across a control read, an fsync or the
	// replication round trip. Every check that asks the control group runs before the slot lock, so
	// the appends of one slot overlap those waits with the round trip of the one in front of them;
	// the slot lock orders only what must be ordered (the receipt and ordering checks that the
	// previous append of the slot can change, the application index, the proposal itself), and the
	// applier, which takes e.mu, never queues behind a request that waits for the control group.
	if e.unusable() {
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
	old, found, err := e.storedReceipt(b)
	if err != nil {
		return model.Receipt{}, err
	}
	if found {
		return old, nil
	}
	if err = e.admitPressure(batchClass(b.Records), uint64(len(b.Canonical))); err != nil {
		return model.Receipt{}, err
	}
	if err = e.admitJournal(b.Org, b.Project, b.Records, uint64(len(b.Canonical))); err != nil {
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
	if err = e.orderedAdmits(b); err != nil {
		return model.Receipt{}, err
	}
	if err = e.writeDeletions(ctx, b); err != nil {
		return model.Receipt{}, err
	}
	e.slotMu[b.RouteSlot].Lock()
	defer e.slotMu[b.RouteSlot].Unlock()
	// The append in front of this one in the slot may have stored this very batch (a retry that
	// raced it) or moved the series the ordering rules look at: ask again, now that nothing can
	// change either until this append has proposed.
	if old, found, err = e.storedReceipt(b); err != nil {
		return model.Receipt{}, err
	} else if found {
		return old, nil
	}
	if err = e.orderedAdmits(b); err != nil {
		return model.Receipt{}, err
	}
	e.mu.Lock()
	if e.closed || e.failed {
		e.mu.Unlock()
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	index := e.indexes[b.RouteSlot] + 1
	e.mu.Unlock()
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
	group, command, err := e.slotCommand(b.RouteSlot, index, entry)
	if err != nil {
		return model.Receipt{}, err
	}
	if err = proposeSlotCommand(group, command); err != nil {
		return model.Receipt{}, err
	}
	return r, nil
}

// unusable reports a closed or failed engine.
func (e *Engine) unusable() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.closed || e.failed
}

// storedReceipt is the receipt a batch already has: found with the original receipt, or a
// conflict when the batch ID is held with another hash.
func (e *Engine) storedReceipt(b model.NormalizedBatch) (model.Receipt, bool, error) {
	key := batchKey(b.Org, b.Project, b.Source, b.Producer, b.RouteSlot, b.ID)
	var old model.Receipt
	found := false
	err := e.db.View(func(tx *bolt.Tx) error {
		raw, err := tableGet(tx, tblReceipts, key)
		if err != nil {
			return err
		}
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
	return old, found, err
}

// orderedAdmits is the cancellation and ordering check of a batch against what the store holds.
func (e *Engine) orderedAdmits(b model.NormalizedBatch) error {
	return e.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("cancelled")).Get([]byte(b.Reservation.ID.String())) != nil {
			return model.Fail(model.Conflict)
		}
		return validateOrdered(tx, b)
	})
}

// commit is deliberately the sole durable ordered-apply path. There is no
// parallel in-memory implementation and no enqueue acknowledgement.
func (e *Engine) commit(slot uint16, index uint64, entry walEntry) error {
	return e.commitReplicated(slot, index, entry)
}
