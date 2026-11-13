// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"time"

	bolt "go.etcd.io/bbolt"
	"soundpost/internal/model"
)

// autoDeclare tells the erasure loop to declare this voter's protocol version and disk
// incarnation on its own. Tests that drive the declarations by hand turn it off.
var autoDeclare = true

// ensureIncarnation gives the data directory its random incarnation id the first time it is
// opened (a fresh directory in the same transaction that names it; a directory written by an
// earlier binary at the first open of this one). The id is a fact about this disk: a replacement
// disk, even one restored under the same node id and identity, starts a new one.
func (e *Engine) ensureIncarnation() error {
	return e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("meta"))
		if raw := meta.Get([]byte("incarnation")); raw != nil {
			if !validIncarnation(string(raw)) {
				return model.Fail(model.Corrupt)
			}
			e.incarnation = string(raw)
			return nil
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		e.incarnation = hex.EncodeToString(id[:])
		return meta.Put([]byte("incarnation"), []byte(e.incarnation))
	})
}

// Incarnation is the id of this voter's disk (see ensureIncarnation).
func (e *Engine) Incarnation() string { return e.incarnation }

// protocolReady reports whether every member of the committed configuration of the slot-0 group has
// declared the erase protocol this binary speaks, so the entries an older binary cannot decode may
// be proposed. It reads local replicated state only.
func (e *Engine) protocolReady() bool {
	if e.repl == nil {
		return false
	}
	members := e.repl.groups[eraseAckSlot].Status().Members.Nodes
	if len(members) == 0 {
		return false
	}
	ready := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		ready = true
		for _, m := range members {
			if capabilityOf(meta, m.ID, m.NodeIdentity) < eraseProtocol {
				ready = false
			}
		}
		return nil
	}); err != nil {
		return false
	}
	return ready
}

// declareErasure proposes, in this order and only what is missing, this voter's protocol
// declaration (in the shape every attributed binary applies) and, once every member has declared,
// its disk incarnation. It returns the proposal's error (no leader yet, a lost race) and is
// retried by the erasure loop.
func (e *Engine) declareErasure(ctx context.Context) error {
	node, identity, ok := e.selfMember()
	if !ok {
		return nil
	}
	var declared uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		declared = capabilityOf(tx.Bucket([]byte("replica_data")), node, identity)
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	if declared < eraseProtocol {
		if err := e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
			return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(node), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(eraseProtocol), Cursor: cursor}}
		}); err != nil {
			return err
		}
	}
	if !e.protocolReady() {
		return nil
	}
	var current string
	var epoch uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		current = string(meta.Get(eraseIncKey(node, identity)))
		epoch = getUint(meta, installEpochKey())
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	if current == e.incarnation {
		return nil
	}
	return e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_unack", EraseUnack: &eraseUnack{Node: model.Uint64(node), Identity: identity, Epoch: model.Uint64(epoch), Incarnation: e.incarnation, Cursor: cursor}}
	})
}

// noticeHeld reports whether this voter must not acknowledge now, and the notice counter an
// acknowledgement measured now stands on. It is held while a notice this voter applied (its
// counter above the settled one) has not been followed by the snapshot it announced: while one is
// being stepped, and until the grace period lapses; after that the voter gives the announcement up
// (the snapshot is refused if it still arrives). Deciding not to hold is also what fixes the
// tokens the voter will still admit: nothing at or below the settled counter, because an
// acknowledgement stamped from here on would predate such an install.
func (e *Engine) noticeHeld(node uint64, identity string) (basis uint64, held bool, err error) {
	if err = e.db.View(func(tx *bolt.Tx) error {
		basis = getUint(tx.Bucket([]byte("replica_data")), eraseNoticeKey(node, identity))
		return nil
	}); err != nil {
		return 0, false, unavailableDB(err)
	}
	s := &e.erasure
	s.mu.Lock()
	if s.inStep > 0 {
		s.mu.Unlock()
		return basis, true, nil
	}
	persist := false
	if basis > s.settled {
		grace := s.grace
		if grace <= 0 {
			grace = noticeGrace
		}
		now := time.Now()
		if s.observed != basis {
			s.observed, s.observedAt = basis, now
		}
		if now.Sub(s.observedAt) < grace {
			s.mu.Unlock()
			return basis, true, nil
		}
		s.settled, persist = basis, true
	}
	s.refuseBelow = max(s.refuseBelow, s.settled)
	settled := s.settled
	s.mu.Unlock()
	if persist {
		e.persistSettled(settled)
	}
	return basis, false, nil
}

// persistSettled stores the settled counter so a restart does not wait the grace period again.
// A failure only costs that wait.
func (e *Engine) persistSettled(settled uint64) {
	_ = e.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if getUint(meta, noticeSettledKey()) >= settled {
			return nil
		}
		return putUint(meta, noticeSettledKey(), settled)
	})
}

// loadNoticeSettled reads the settled counter at start: whatever was settled before is also
// refused, so a message delayed across a restart cannot install under an acknowledgement.
func (e *Engine) loadNoticeSettled() error {
	var settled uint64
	if err := e.db.View(func(tx *bolt.Tx) error {
		settled = getUint(tx.Bucket([]byte("replica_data")), noticeSettledKey())
		return nil
	}); err != nil {
		return unavailableDB(err)
	}
	e.erasure.mu.Lock()
	defer e.erasure.mu.Unlock()
	e.erasure.settled = max(e.erasure.settled, settled)
	e.erasure.refuseBelow = max(e.erasure.refuseBelow, settled)
	return nil
}

// BeforeSnapshotSend is replica.SnapshotGate on the sender: before a snapshot of this slot leaves
// for member `to`, commit a notice naming it in slot 0 and return its index as the message's token.
// Until every member declared the protocol it states nothing and returns no token (the receiver
// then relies on the withdrawal an install owes, as before).
func (e *Engine) beforeSnapshotSend(ctx context.Context, to uint64) ([]byte, error) {
	if e.repl == nil {
		return nil, model.Fail(model.Unavailable)
	}
	if !e.protocolReady() {
		return nil, nil
	}
	var target *struct {
		node     uint64
		identity string
	}
	for _, m := range e.repl.groups[eraseAckSlot].Status().Members.Nodes {
		if m.ID == to {
			target = &struct {
				node     uint64
				identity string
			}{m.ID, m.NodeIdentity}
		}
	}
	if target == nil {
		return nil, nil // not a member: it holds no acknowledgement to void
	}
	var index uint64
	if err := e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		index = uint64(cursor.Index)
		return walEntry{Type: "erase_notice", EraseNotice: &eraseNotice{Node: model.Uint64(target.node), Identity: target.identity, Cursor: cursor}}
	}); err != nil {
		return nil, err
	}
	token := make([]byte, 8)
	binary.BigEndian.PutUint64(token, index)
	return token, nil
}

// admitSnapshot is replica.SnapshotGate on the receiver: it refuses a snapshot announced by a
// notice this voter already gave up or acknowledged past, and otherwise marks a step in progress
// until release, after which the notice is settled.
func (e *Engine) admitSnapshot(token []byte) (func(), error) {
	if len(token) == 0 {
		return func() {}, nil
	}
	if len(token) != 8 {
		return nil, model.Fail(model.Invalid)
	}
	n := binary.BigEndian.Uint64(token)
	s := &e.erasure
	s.mu.Lock()
	if n <= s.refuseBelow {
		s.mu.Unlock()
		return nil, model.Fail(model.Stale)
	}
	s.inStep++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.inStep--
		s.settled = max(s.settled, n)
		settled := s.settled
		s.mu.Unlock()
		e.persistSettled(settled)
	}, nil
}
