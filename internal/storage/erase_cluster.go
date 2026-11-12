// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
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
const (
	// ResidualApplyDB names the data stores (apply.db, its free pages, the segments) of a voter
	// that has not yet erased a completed deletion, or whose free pages still owe a scrub, as
	// seen from the answering node: it is also reported while any member of the group has not
	// acknowledged the operation.
	ResidualApplyDB = "data_apply_db"

	eraseAckSlot   uint16 = 0
	maxEraseAckOps        = 64

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
	Epoch  model.Uint64 `json:"epoch,omitempty"`
	Cursor model.Cursor `json:"cursor"`
}

func (a *eraseAck) valid() bool {
	return a != nil && a.Node != 0 && a.Identity != "" && len(a.Operations) > 0 && len(a.Operations) <= maxEraseAckOps
}

// eraseUnack is the closed DTO of one voter's withdrawal: every acknowledgement the voter made
// under an installation epoch below Epoch no longer counts.
type eraseUnack struct {
	Node     model.Uint64 `json:"node"`
	Identity string       `json:"identity"`
	Epoch    model.Uint64 `json:"epoch"`
	Cursor   model.Cursor `json:"cursor"`
}

func (u *eraseUnack) valid() bool {
	return u != nil && u.Node != 0 && u.Identity != "" && u.Epoch != 0
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

// ackStands reports whether the member's acknowledgement of the operation counts: it carries the
// installation epoch it was made under (eight bytes; anything else is an acknowledgement from
// before attribution and never counts) and no withdrawal of the member names a later one.
func ackStands(meta *bolt.Bucket, op model.ID, node uint64, identity string) bool {
	raw := meta.Get(eraseAckKey(op, node, identity))
	return len(raw) == 8 && binary.BigEndian.Uint64(raw) >= getUint(meta, eraseGenKey(node, identity))
}

// applyEraseAckTx records the acknowledgement. It is deterministic: the same entry on every
// voter writes the same keys. An acknowledgement that does not name the member that proposed it
// (or whose entry carries no proposer, as one written before attribution) writes nothing.
func applyEraseAckTx(tx *bolt.Tx, slot uint16, entry walEntry) error {
	if slot != eraseAckSlot || !entry.EraseAck.valid() || entry.Batch != nil || entry.Receipt != nil || entry.EraseUnack != nil {
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
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], uint64(a.Epoch))
	for _, op := range a.Operations {
		key := eraseAckKey(op, uint64(a.Node), a.Identity)
		if old := meta.Get(key); len(old) == 8 && binary.BigEndian.Uint64(old) >= uint64(a.Epoch) {
			continue
		}
		if err := meta.Put(key, epoch[:]); err != nil {
			return err
		}
	}
	return nil
}

// applyEraseUnackTx raises the voter's replicated floor. Like an acknowledgement it counts only
// when the proposer is the voter it names.
func applyEraseUnackTx(tx *bolt.Tx, slot uint16, entry walEntry) error {
	if slot != eraseAckSlot || !entry.EraseUnack.valid() || entry.Batch != nil || entry.Receipt != nil || entry.EraseAck != nil {
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
	if getUint(meta, key) >= uint64(u.Epoch) {
		return nil
	}
	return putUint(meta, key, uint64(u.Epoch))
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
	erasing map[model.ID]uint64
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

// noteEraseStart records the installation epoch an erase of the operations starts under.
func (e *Engine) noteEraseStart(ops []model.ID) error {
	epoch, err := e.installEpoch()
	if err != nil {
		return err
	}
	e.erasure.mu.Lock()
	defer e.erasure.mu.Unlock()
	if e.erasure.erasing == nil {
		e.erasure.erasing = map[model.ID]uint64{}
	}
	for _, op := range ops {
		e.erasure.erasing[op] = epoch
	}
	return nil
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
// rows back after the erase read them, so the voter erases again.
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
			if !ok || started != epoch {
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
	go func(wake <-chan struct{}, done chan<- struct{}) {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
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
			if err != nil {
				continue // another voter's key whose identity merely ends alike
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
		epoch = max(getUint(meta, installEpochKey()), getUint(meta, eraseGenKey(node, identity)))
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
	if len(owed) == 0 || dirty {
		return nil
	}
	sort.Slice(owed, func(i, j int) bool { return owed[i].String() < owed[j].String() })
	if len(owed) > maxEraseAckOps {
		owed = owed[:maxEraseAckOps]
	}
	return e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(node), Identity: identity, Operations: owed, Epoch: model.Uint64(epoch), Cursor: cursor}}
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
