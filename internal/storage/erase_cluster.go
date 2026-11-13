// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
	"soundpost/internal/replica"
)

// Physical erasure of a deletion is per voter: every voter holds its own apply.db, segments and
// Raft journal, and a voter erases the bytes only from its own copy (the tombstone every voter
// applied, plus the completed operation in the control state, tell its retention worker what
// to erase). The control state's PhysicalAt is one cluster-wide fact recorded by whichever
// voter finished first, so it cannot say that THIS voter, or any other, is clean. Three things
// close that:
//
//   - a durable node-local marker per operation, set after this voter erased, scrubbed and cut
//     its own journal and snapshots (MarkErased / ErasedLocally): a voter whose marker is missing
//     still owes the erasure and its worker runs it even though PhysicalAt is already set;
//   - a replicated acknowledgement (type "erase_ack", slot 0) each voter proposes once its marker
//     is set and its own stores measure clean (AckErasure). ErasureResidual names
//     ResidualApplyDB for an operation until this voter AND every member of the committed
//     configuration has an acknowledgement for it. A stopped or lagging voter has none, so the
//     receipt keeps naming the data store until it catches up, erases and acknowledges;
//   - the acknowledgement is attributed and withdrawable, because the replicated log is the only
//     authority a receipt trusts. Its author is the proposer the replica layer recorded in the
//     entry (replica.Entry.Proposer, never a name inside the payload): an acknowledgement counts
//     only when it names the member that proposed it, so no voter can state another voter's
//     erasure. And it stands only for the bytes it measured: a snapshot install that replays
//     commands into the live buckets (slotMachine.Restore) can bring erased rows back, so it
//     clears this voter's markers and raises its installation epoch, the voter proposes an
//     "erase_unack" naming that epoch, and every acknowledgement it made under an earlier epoch
//     stops counting on every voter until its worker erased again and acknowledged anew.
//
// An acknowledgement written before attribution existed (value of one byte, no proposer in the
// stored command) is never counted: the voter re-acknowledges once.
//
// Three more facts keep an acknowledgement from outliving the bytes it measured (task 11.04):
//
//   - the window between an install and its withdrawal: a snapshot that replays data commands is
//     preceded by a replicated "erase_notice" the SENDER commits (replica.SnapshotGate:
//     BeforeSnapshotSend), naming the receiver. Every acknowledgement the receiver made before the
//     notice stops standing at once, on every voter, because an acknowledgement carries the notice
//     counter its voter had applied when it measured (Basis) and stands only while that is still
//     the voter's latest. The receiver itself does not acknowledge while a notice it has applied has
//     not been settled by the snapshot it announced having been stepped (AdmitSnapshot), or by a
//     grace period after which it refuses that snapshot instead (a token at or below the settled
//     counter is refused, so a late message cannot install under a fresh acknowledgement);
//   - the disk: every data directory carries a random incarnation (ensureIncarnation) and an
//     acknowledgement stands only for the incarnation its voter last declared in the group, so a
//     disk that replaced the old one under the same node id and identity never inherits its acks;
//   - the version: the entries above are new shapes an older binary cannot decode, so nothing is
//     proposed in them until every member of the committed configuration has declared the protocol
//     (a capability statement in the shape an older binary applies harmlessly, see protocolReady).
const (
	// ResidualApplyDB names the data stores (apply.db, its free pages, the segments) of a voter
	// that has not yet erased a completed deletion, or whose free pages still owe a scrub, as
	// seen from the answering node: it is also reported while any member of the group has not
	// acknowledged the operation.
	ResidualApplyDB = "data_apply_db"

	eraseAckSlot   uint16 = 0
	maxEraseAckOps        = 64

	// eraseProtocol is the erase protocol version a binary speaks: 1 is the attributed, epoch
	// acknowledgement; 2 adds notices, incarnations and the basis of an acknowledgement.
	eraseProtocol uint64 = 2
	// noticeGrace is how long a voter that applied a notice naming it waits for the announced
	// snapshot before it stops expecting it (and refuses it if it still arrives).
	noticeGrace = 2 * time.Minute
	// declareInterval is how often the erasure loop retries the declarations that need a leader.
	declareInterval = 3 * time.Second

	withdrawRetryMin = 50 * time.Millisecond
	withdrawRetryMax = 2 * time.Second
)

// eraseAck is the closed DTO of one voter's acknowledgement.
type eraseAck struct {
	Node       model.Uint64 `json:"node"`
	Identity   string       `json:"identity"`
	Operations []model.ID   `json:"operations"`
	// Epoch is the voter's installation epoch when it measured itself clean. The acknowledgement
	// stops counting once a withdrawal of the same voter names a later epoch. It is omitted when
	// zero, so a command written before the field existed encodes to the bytes it was stored as.
	Epoch model.Uint64 `json:"epoch,omitempty"`
	// Basis is the notice counter of this voter in the replicated state the voter had applied when
	// it measured, and Incarnation the random id of its disk. Both are omitted when empty, so an
	// acknowledgement written by a binary that has neither encodes to the bytes it was stored as.
	Basis       model.Uint64 `json:"basis,omitempty"`
	Incarnation string       `json:"incarnation,omitempty"`
	Cursor      model.Cursor `json:"cursor"`
}

func (a *eraseAck) valid() bool {
	return a != nil && a.Node != 0 && a.Identity != "" && len(a.Operations) > 0 && len(a.Operations) <= maxEraseAckOps && (a.Incarnation == "" || validIncarnation(a.Incarnation))
}

// eraseUnack is the closed DTO of one voter's withdrawal: every acknowledgement the voter made
// under an installation epoch below Epoch no longer counts.
type eraseUnack struct {
	Node     model.Uint64 `json:"node"`
	Identity string       `json:"identity"`
	Epoch    model.Uint64 `json:"epoch"`
	// Incarnation, when set, declares the disk the voter now runs on. A declaration of an
	// incarnation the group has not seen for this voter resets its floor to Epoch: nothing a
	// previous disk acknowledged stands for this one.
	Incarnation string       `json:"incarnation,omitempty"`
	Cursor      model.Cursor `json:"cursor"`
}

func (u *eraseUnack) valid() bool {
	return u != nil && u.Node != 0 && u.Identity != "" && (u.Epoch != 0 || validIncarnation(u.Incarnation))
}

// eraseNotice is the closed DTO of a sender's statement that it is about to send the named member a
// snapshot (see replica.SnapshotGate). The proposer is the sender, whoever it is: a notice only
// ever makes an acknowledgement stand less, so it needs no authority over its target.
type eraseNotice struct {
	Node     model.Uint64 `json:"node"`
	Identity string       `json:"identity"`
	Cursor   model.Cursor `json:"cursor"`
}

func (n *eraseNotice) valid() bool { return n != nil && n.Node != 0 && n.Identity != "" }

// validIncarnation is the form ensureIncarnation writes: 32 lowercase hex digits.
func validIncarnation(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// proposedBy reports whether the replicated entry was proposed by the member the statement names.
// An entry with no recorded proposer (one committed before attribution existed) is proposed by
// nobody.
func proposedBy(p *replica.Proposer, node model.Uint64, identity string) bool {
	return p != nil && p.Node == uint64(node) && p.Identity == identity
}

func erasedKey(op model.ID) []byte { return metaKey(eraseAckSlot, "erased:"+op.String()) }
func eraseAckKey(op model.ID, node uint64, identity string) []byte {
	return metaKey(eraseAckSlot, "erase-ack:"+op.String()+":"+strconv.FormatUint(node, 10)+":"+identity)
}

// eraseGenKey is the replicated floor of a voter's acknowledgements: the latest installation epoch
// any of its withdrawals named.
func eraseGenKey(node uint64, identity string) []byte {
	return metaKey(eraseAckSlot, "erase-gen:"+strconv.FormatUint(node, 10)+":"+identity)
}

// installEpochKey is this voter's own installation epoch (node-local, never replicated): it
// rises on every snapshot install that replays data commands into the live buckets.
func installEpochKey() []byte { return metaKey(eraseAckSlot, "install-epoch") }

// unackOwedKey is the installation epoch this voter still has to withdraw its acknowledgements
// for (node-local): set when an install cleared at least one marker, satisfied once the
// replicated floor of this voter reaches it.
func unackOwedKey() []byte { return metaKey(eraseAckSlot, "unack-owed") }

// eraseIncKey is the replicated incarnation a voter last declared (its disk).
func eraseIncKey(node uint64, identity string) []byte {
	return metaKey(eraseAckSlot, "erase-inc:"+strconv.FormatUint(node, 10)+":"+identity)
}

// eraseNoticeKey is the replicated notice counter of a voter: the slot-0 index of the latest
// notice that named it.
func eraseNoticeKey(node uint64, identity string) []byte {
	return metaKey(eraseAckSlot, "erase-notice:"+strconv.FormatUint(node, 10)+":"+identity)
}

// noticeSettledKey is this voter's own (node-local) highest notice counter that is no longer
// expected to be followed by a snapshot: stepped, or given up after the grace period.
func noticeSettledKey() []byte { return metaKey(eraseAckSlot, "notice-settled") }

// capabilityOp is the reserved operation under which a voter declares the erase protocol it speaks:
// an acknowledgement of this operation, in the shape every binary since attribution applies, whose
// epoch field is the protocol version. An older binary stores it and ignores it (at worst it
// withdraws its own acknowledgements once), which is why the declaration needs no gate itself.
var capabilityOp = model.ID{'e', 'r', 'a', 's', 'e', '-', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l', '-', '1'}

// capabilityOf is the protocol version the voter declared (zero: none).
func capabilityOf(meta *bolt.Bucket, node uint64, identity string) uint64 {
	raw := meta.Get(eraseAckKey(capabilityOp, node, identity))
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}

// ackValue is the stored form of an acknowledgement: epoch (8 bytes) as written since attribution,
// or epoch, basis (8 bytes) and incarnation (16 bytes) when it has either of the two.
func ackValue(a *eraseAck) []byte {
	if a.Basis == 0 && a.Incarnation == "" {
		var out [8]byte
		binary.BigEndian.PutUint64(out[:], uint64(a.Epoch))
		return out[:]
	}
	out := make([]byte, 32)
	binary.BigEndian.PutUint64(out[:8], uint64(a.Epoch))
	binary.BigEndian.PutUint64(out[8:16], uint64(a.Basis))
	raw, _ := hex.DecodeString(a.Incarnation)
	copy(out[16:], raw)
	return out
}

// ackFields decodes a stored acknowledgement; ok is false for anything else (the one byte an
// acknowledgement had before attribution).
func ackFields(raw []byte) (epoch, basis uint64, incarnation string, ok bool) {
	switch len(raw) {
	case 8:
		return binary.BigEndian.Uint64(raw), 0, "", true
	case 32:
		return binary.BigEndian.Uint64(raw[:8]), binary.BigEndian.Uint64(raw[8:16]), hex.EncodeToString(raw[16:]), true
	}
	return 0, 0, "", false
}

// ackStands reports whether the member's acknowledgement of the operation counts. It does when it
// carries what a statement about the voter's own stores needs (an epoch; anything else is an
// acknowledgement from before attribution and never counts), no withdrawal of the member names a
// later epoch, no notice has named the member since the acknowledgement measured (its basis is the
// member's latest notice counter) and it was made on the disk the member last declared.
func ackStands(meta *bolt.Bucket, op model.ID, node uint64, identity string) bool {
	epoch, basis, incarnation, ok := ackFields(meta.Get(eraseAckKey(op, node, identity)))
	return ok && epoch >= getUint(meta, eraseGenKey(node, identity)) &&
		basis == getUint(meta, eraseNoticeKey(node, identity)) &&
		incarnation == string(meta.Get(eraseIncKey(node, identity)))
}

// applyEraseAckTx records the acknowledgement. It is deterministic: the same entry on every
// voter writes the same keys. An acknowledgement that does not name the member that proposed it
// (or whose entry carries no proposer, as one written before attribution) writes nothing.
func applyEraseAckTx(tx *bolt.Tx, slot uint16, entry walEntry) error {
	if slot != eraseAckSlot || !entry.EraseAck.valid() || entry.Batch != nil || entry.Receipt != nil || entry.EraseUnack != nil || entry.EraseNotice != nil {
		return model.Fail(model.Corrupt)
	}
	meta := tx.Bucket([]byte("replica_data"))
	if meta == nil {
		return model.Fail(model.Corrupt)
	}
	a := entry.EraseAck
	if !proposedBy(entry.Proposer, a.Node, a.Identity) {
		return nil
	}
	value := ackValue(a)
	for _, op := range a.Operations {
		key := eraseAckKey(op, uint64(a.Node), a.Identity)
		if old := meta.Get(key); len(old) == len(value) {
			oe, ob, oi, _ := ackFields(old)
			if ne, nb, ni, _ := ackFields(value); oi == ni && ob == nb && oe >= ne {
				continue
			}
		}
		if err := meta.Put(key, value); err != nil {
			return err
		}
	}
	return nil
}

// applyEraseUnackTx raises the voter's replicated floor and, when it declares a disk the group has
// not seen for the voter, replaces the declared incarnation and restarts the floor at the declared
// epoch. Like an acknowledgement it counts only when the proposer is the voter it names.
func applyEraseUnackTx(tx *bolt.Tx, slot uint16, entry walEntry) error {
	if slot != eraseAckSlot || !entry.EraseUnack.valid() || entry.Batch != nil || entry.Receipt != nil || entry.EraseAck != nil || entry.EraseNotice != nil {
		return model.Fail(model.Corrupt)
	}
	meta := tx.Bucket([]byte("replica_data"))
	if meta == nil {
		return model.Fail(model.Corrupt)
	}
	u := entry.EraseUnack
	if !proposedBy(entry.Proposer, u.Node, u.Identity) {
		return nil
	}
	key := eraseGenKey(uint64(u.Node), u.Identity)
	if u.Incarnation != "" && string(meta.Get(eraseIncKey(uint64(u.Node), u.Identity))) != u.Incarnation {
		if err := meta.Put(eraseIncKey(uint64(u.Node), u.Identity), []byte(u.Incarnation)); err != nil {
			return err
		}
		return putUint(meta, key, uint64(u.Epoch))
	}
	if getUint(meta, key) >= uint64(u.Epoch) {
		return nil
	}
	return putUint(meta, key, uint64(u.Epoch))
}

// applyEraseNoticeTx records that the proposer is about to send the named member a snapshot: the
// member's notice counter becomes this entry's slot-0 index, so every acknowledgement it measured
// before (a smaller basis) stops standing on every voter that applies the entry.
func applyEraseNoticeTx(tx *bolt.Tx, slot uint16, index uint64, entry walEntry) error {
	if slot != eraseAckSlot || !entry.EraseNotice.valid() || entry.Batch != nil || entry.Receipt != nil || entry.EraseAck != nil || entry.EraseUnack != nil {
		return model.Fail(model.Corrupt)
	}
	meta := tx.Bucket([]byte("replica_data"))
	if meta == nil {
		return model.Fail(model.Corrupt)
	}
	if entry.Proposer == nil {
		return nil // committed by no known member: states nothing
	}
	n := entry.EraseNotice
	key := eraseNoticeKey(uint64(n.Node), n.Identity)
	if getUint(meta, key) >= index {
		return nil
	}
	return putUint(meta, key, index)
}

// invalidateErasureTx is what a snapshot install owes the erasure bookkeeping when it replayed
// data commands into the live buckets: the installation epoch rises and every local erase
// marker goes, so each operation is owed again by this voter's worker. It reports whether a
// marker (and so possibly an acknowledgement) was cleared, i.e. whether a withdrawal is owed.
func invalidateErasureTx(tx *bolt.Tx) (bool, error) {
	meta := tx.Bucket([]byte("replica_data"))
	if meta == nil {
		return false, model.Fail(model.Corrupt)
	}
	epoch := getUint(meta, installEpochKey())
	if epoch == ^uint64(0) {
		return false, model.Fail(model.Corrupt)
	}
	epoch++
	if err := putUint(meta, installEpochKey(), epoch); err != nil {
		return false, err
	}
	prefix := metaKey(eraseAckSlot, "erased:")
	var markers [][]byte
	c := meta.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		markers = append(markers, bytes.Clone(k))
	}
	for _, k := range markers {
		if err := meta.Delete(k); err != nil {
			return false, err
		}
	}
	if len(markers) == 0 {
		return false, nil
	}
	return true, putUint(meta, unackOwedKey(), epoch)
}

// erasureState is the engine's in-memory part of the bookkeeping above.
type erasureState struct {
	// wake tells the withdrawal loop that an install left a withdrawal owed; cancel and done
	// belong to the loop (started by EnableReplication, stopped by Close).
	wake   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
	// erasing is, per operation, the installation epoch the latest EraseDeleted call that named
	// it started under: MarkErased refuses to certify an erasure an install interrupted.
	mu      sync.Mutex
	erasing map[model.ID]*eraseStart
	// settled, refuseBelow, inStep, observed, observedAt and grace belong to the snapshot notices
	// (erase_notice.go); all under mu.
	settled, refuseBelow uint64
	inStep               int
	observed             uint64
	observedAt           time.Time
	grace                time.Duration
	auto                 bool
}

// eraseStart is what an EraseDeleted call knew when it began: the installation epoch and the
// predicate; dirty is set when a command the predicate covers was applied since.
type eraseStart struct {
	epoch uint64
	pred  model.DeletePredicate
	dirty bool
}

func (s *erasureState) cancelLoop() {
	if s.cancel != nil {
		s.cancel()
	}
}
func (s *erasureState) waitLoop() {
	if s.done != nil {
		<-s.done
	}
}

// wakeLoop never blocks: it is called with the group's lock held, from the apply path.
func (s *erasureState) wakeLoop() {
	select {
	case s.wake <- struct{}{}:
	default: // one signal is pending already: the loop reads the live state
	}
}

// installEpoch is this voter's installation epoch.
func (e *Engine) installEpoch() (uint64, error) {
	var epoch uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		epoch = getUint(tx.Bucket([]byte("replica_data")), installEpochKey())
		return nil
	}); err != nil {
		return 0, unavailableDB(err)
	}
	return epoch, nil
}

// noteEraseStart records what an erase of the predicates starts under: the installation epoch, and
// the predicates themselves, so that a covered command APPLIED from here on marks the erase dirty
// (noteApplied). A voter that erases before it applied a slot's barrier can still apply, by catching
// up on the log, commands ordered before that barrier that a predicate covers: they land live after
// the erase read the state, so such an erase is never certified (MarkErased). A covered command
// ordered after the barrier is rejected at apply and never reaches noteApplied.
func (e *Engine) noteEraseStart(preds []model.DeletePredicate) error {
	epoch, err := e.installEpoch()
	if err != nil {
		return err
	}
	e.erasure.mu.Lock()
	defer e.erasure.mu.Unlock()
	if e.erasure.erasing == nil {
		e.erasure.erasing = map[model.ID]*eraseStart{}
	}
	for _, p := range preds {
		e.erasure.erasing[p.Operation] = &eraseStart{epoch: epoch, pred: p}
	}
	return nil
}

// noteApplied is called by the apply of a stored batch or artifact fragment, inside its
// transaction: it marks dirty every erase in progress whose predicate covers the command.
func (e *Engine) noteApplied(org, project model.ID, records []model.Record, blob *model.BlobManifest) {
	s := &e.erasure
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.erasing {
		if st.dirty {
			continue
		}
		if blob != nil && st.pred.CoversBlob(*blob) {
			st.dirty = true
			continue
		}
		for _, r := range records {
			if st.pred.CoversRecord(org, project, r) {
				st.dirty = true
				break
			}
		}
	}
}

// ErasedLocally reports whether this voter finished erasing the operation from its own stores.
func (e *Engine) ErasedLocally(op model.ID) bool {
	found := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		found = tx.Bucket([]byte("replica_data")).Get(erasedKey(op)) != nil
		return nil
	}); err != nil {
		return false
	}
	return found
}

// MarkErased records, durably and only on this voter, that it erased the operations from its
// own stores. The caller does so after the erase, the scrub and the journal cut succeeded. An
// operation whose latest EraseDeleted started before a snapshot install (or was never started in
// this process) is not marked and the call returns a conflict: the install can have put erased
// rows back after the erase read them, so the voter erases again. The same holds for an erase during which
// a command its predicate covers was applied (noteEraseStart).
func (e *Engine) MarkErased(ops []model.ID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	refused := false
	err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		epoch := getUint(meta, installEpochKey())
		e.erasure.mu.Lock()
		defer e.erasure.mu.Unlock()
		for _, op := range ops {
			started, ok := e.erasure.erasing[op]
			delete(e.erasure.erasing, op)
			if !ok || started.epoch != epoch || started.dirty {
				refused = true
				continue
			}
			if err := meta.Put(erasedKey(op), []byte{1}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return unavailableDB(err)
	}
	if refused {
		return model.Fail(model.Conflict)
	}
	return nil
}

// selfMember names this voter in the committed configuration of the group that carries the
// acknowledgements.
func (e *Engine) selfMember() (node uint64, identity string, ok bool) {
	if e.repl == nil {
		return 0, "", false
	}
	st := e.repl.groups[eraseAckSlot].Status()
	for _, m := range st.Members.Nodes {
		if m.ID == st.ID {
			return m.ID, m.NodeIdentity, true
		}
	}
	return 0, "", false
}

// proposeSlotZero commits the entry build returns, bound to the next slot-0 cursor.
func (e *Engine) proposeSlotZero(ctx context.Context, build func(cursor model.Cursor) walEntry) error {
	e.proposalMu.Lock()
	defer e.proposalMu.Unlock()
	if _, err := e.repl.groups[eraseAckSlot].ReadIndex(ctx); err != nil {
		return storageReplicaFault(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	cursor := model.Cursor{Group: e.group(eraseAckSlot), Index: model.Uint64(e.indexes[eraseAckSlot] + 1)}
	return e.commit(eraseAckSlot, uint64(cursor.Index), build(cursor))
}

// withdrawErasure proposes this voter's withdrawal when an install left one owed, and does
// nothing otherwise. It returns the proposal's error (no leader yet, a lost race): the loop and
// the worker retry.
func (e *Engine) withdrawErasure(ctx context.Context) error {
	node, identity, ok := e.selfMember()
	if !ok {
		return nil
	}
	var epoch uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if owed := getUint(meta, unackOwedKey()); owed > getUint(meta, eraseGenKey(node, identity)) {
			epoch = owed
		}
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	if epoch == 0 {
		return nil
	}
	return e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_unack", EraseUnack: &eraseUnack{Node: model.Uint64(node), Identity: identity, Epoch: model.Uint64(epoch), Cursor: cursor}}
	})
}

// startErasureLoop runs the loop that withdraws this voter's acknowledgements after an install,
// at once and retrying until the withdrawal commits, so the receipt does not wait for the next
// worker pass. It also runs once at start for a withdrawal a previous run still owed. The state
// is durable (unackOwedKey against the replicated floor), so a restart loses nothing.
func (e *Engine) startErasureLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	e.erasure.cancel, e.erasure.done = cancel, make(chan struct{})
	e.erasure.auto = autoDeclare
	if err := e.loadNoticeSettled(); err != nil {
		e.erasure.auto = false // an unreadable settled counter keeps its zero: the grace period applies again
	}
	go func(wake <-chan struct{}, done chan<- struct{}) {
		defer close(done)
		tick := time.NewTicker(declareInterval)
		defer tick.Stop()
		if e.erasure.auto {
			_ = e.declareErasure(ctx) // at once, not a tick from now
		}
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				// The declarations need a leader (and every member's protocol declaration needs
				// every member): one attempt per tick, the next tick tries again.
				if e.erasure.auto {
					_ = e.declareErasure(ctx)
				}
				continue
			case <-wake:
			}
			for delay := withdrawRetryMin; ctx.Err() == nil; delay = min(2*delay, withdrawRetryMax) {
				if e.withdrawErasure(ctx) == nil {
					break
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
			}
		}
	}(e.erasure.wake, e.erasure.done)
	e.erasure.wakeLoop()
}

// staleAcknowledgements lists the operations this voter's standing acknowledgement still claims
// but its stores no longer back: the stores are dirty again (an owed scrub, a journal, snapshot or
// retry-table copy from before an erasure) or the marker is gone.
func (e *Engine) staleAcknowledgements(node uint64, identity string, dirty bool) ([]model.ID, error) {
	var stale []model.ID
	suffix := ":" + strconv.FormatUint(node, 10) + ":" + identity
	err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		prefix := metaKey(eraseAckSlot, "erase-ack:")
		c := meta.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			rest := string(k[len(prefix):])
			if !strings.HasSuffix(rest, suffix) {
				continue
			}
			op, err := model.ParseID(strings.TrimSuffix(rest, suffix))
			if err != nil || op == capabilityOp {
				continue // another voter's key whose identity merely ends alike; the protocol declaration
			}
			if ackStands(meta, op, node, identity) && (dirty || meta.Get(erasedKey(op)) == nil) {
				stale = append(stale, op)
			}
		}
		return nil
	})
	if err != nil {
		return nil, unavailableDB(err)
	}
	return stale, nil
}

// oweWithdrawal records that the stale operations' acknowledgements must go: their markers are
// cleared (the worker erases, scrubs and cuts them again) and the installation epoch rises, so
// the withdrawal that follows voids every acknowledgement this voter made before now. A failed
// proposal leaves the debt durable and the next pass proposes it again.
func (e *Engine) oweWithdrawal(stale []model.ID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.failed {
		return model.Fail(model.Unavailable)
	}
	if err := e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		epoch := getUint(meta, installEpochKey())
		if epoch == ^uint64(0) {
			return model.Fail(model.Corrupt)
		}
		epoch++
		if err := putUint(meta, installEpochKey(), epoch); err != nil {
			return err
		}
		if err := putUint(meta, unackOwedKey(), epoch); err != nil {
			return err
		}
		for _, op := range stale {
			if err := meta.Delete(erasedKey(op)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	return nil
}

// AckErasure proposes this voter's acknowledgement of every operation it has marked erased and
// has not yet acknowledged under its current installation epoch, provided its own stores measure
// clean right now (ResidualStores is empty: no owed scrub, no journal, snapshot or retry-table
// copy from before an erasure). An acknowledgement states a fact about the voter's own stores, so
// it follows the fact: a withdrawal an install left owed is proposed first, and a standing
// acknowledgement whose marker is gone or whose stores are dirty again is withdrawn too (its
// marker cleared, the operation owed again), so the new acknowledgement is never ordered before
// the withdrawal that would void it. It is a no-op when there is nothing to acknowledge, and
// returns the proposal's error otherwise (the retention worker retries on its next pass).
func (e *Engine) AckErasure(ctx context.Context) error {
	node, identity, ok := e.selfMember()
	if !ok {
		return nil
	}
	// Once every member speaks the protocol an acknowledgement carries the disk it was made on and
	// the notice counter this voter had applied when it measured; while a notice it applied has not
	// been settled it does not acknowledge at all. The counter is read before anything is measured.
	ready := e.protocolReady()
	var basis uint64
	held := false
	if ready {
		if err := e.declareErasure(ctx); err != nil {
			return err
		}
		var err error
		if basis, held, err = e.noticeHeld(node, identity); err != nil {
			return err
		}
	}
	if err := e.withdrawErasure(ctx); err != nil {
		return err
	}
	dirty := len(e.ResidualStores()) > 0
	stale, err := e.staleAcknowledgements(node, identity, dirty)
	if err != nil {
		return err
	}
	if len(stale) > 0 {
		if err = e.oweWithdrawal(stale); err != nil {
			return err
		}
		if err = e.withdrawErasure(ctx); err != nil {
			return err
		}
	}
	var owed []model.ID
	var epoch uint64
	if err = e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		epoch = getUint(meta, installEpochKey())
		if !ready {
			epoch = max(epoch, getUint(meta, eraseGenKey(node, identity)))
		}
		prefix := metaKey(eraseAckSlot, "erased:")
		c := meta.Cursor()
		for k, _ := c.Seek(prefix); k != nil && strings.HasPrefix(string(k), string(prefix)); k, _ = c.Next() {
			op, err := model.ParseID(string(k[len(prefix):]))
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			if !ackStands(meta, op, node, identity) {
				owed = append(owed, op)
			}
		}
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	if len(owed) == 0 || dirty || held {
		return nil
	}
	sort.Slice(owed, func(i, j int) bool { return owed[i].String() < owed[j].String() })
	if len(owed) > maxEraseAckOps {
		owed = owed[:maxEraseAckOps]
	}
	return e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		ack := &eraseAck{Node: model.Uint64(node), Identity: identity, Operations: owed, Epoch: model.Uint64(epoch), Cursor: cursor}
		if ready {
			ack.Basis, ack.Incarnation = model.Uint64(basis), e.incarnation
		}
		return walEntry{Type: "erase_ack", EraseAck: ack}
	})
}

// ErasureResidual is what a receipt for the operation must add to ResidualStores: ResidualApplyDB
// until this voter erased the operation itself and every member of the group's committed
// configuration has an acknowledgement that stands (attributed to its own proposer and not
// withdrawn). It reads local state only and never blocks on consensus; a configuration that
// cannot be read is reported as owed.
func (e *Engine) ErasureResidual(op model.ID) []string {
	if !e.ErasedLocally(op) {
		return []string{ResidualApplyDB}
	}
	if e.repl == nil {
		return nil
	}
	members := e.repl.groups[eraseAckSlot].Status().Members.Nodes
	if len(members) == 0 {
		return []string{ResidualApplyDB}
	}
	owed := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		for _, m := range members {
			if !ackStands(meta, op, m.ID, m.NodeIdentity) {
				owed = true
			}
		}
		return nil
	}); err != nil || owed {
		return []string{ResidualApplyDB}
	}
	return nil
}
