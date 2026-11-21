// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
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
func (e *Engine) Incarnation() string { return e.disk() }

func (e *Engine) disk() string {
	e.incMu.RLock()
	defer e.incMu.RUnlock()
	return e.incarnation
}

// protocolReady reports whether every member of the committed configuration of the slot-0 group has
// declared the erase protocol this binary speaks, so the entries an older binary cannot decode may
// be proposed. It reads local replicated state only.
func (e *Engine) protocolReady() bool { return e.declaredBy(eraseProtocol) }

// ControlBoundsReady reports whether every member of the committed configuration of the slot-0
// group has declared boundsProtocol, so control may apply the bounded-state rules
// (control.Store.SetBoundedRulesGate). Until then every member applies the previous rules, which
// is what a member of the release before this one does. It is false while replication is not
// enabled yet. It reads local replicated state only and is evaluated at every use, never cached:
// declarations are never withdrawn, but a member added to the configuration closes it again until
// that member declares.
func (e *Engine) ControlBoundsReady() bool { return e.declaredBy(boundsProtocol) }

// ControlAuditDeltaReady reports whether every member of the committed configuration of the slot-0
// group has declared auditDeltaProtocol, so control may propose the audit delta command
// (control.Store.SetAuditDeltaGate). Until then every elevated read audit is committed through the
// whole-state path every release applies. Same reading rules as ControlBoundsReady: local replicated
// state only, evaluated at every use, false without replication.
func (e *Engine) ControlAuditDeltaReady() bool { return e.declaredBy(auditDeltaProtocol) }

// ControlStatePatchReady reports whether every member of the control group's committed
// configuration (control, as the control group reports it) and of the slot-0 group's has declared
// statePatchProtocol, so control may propose a command as a state patch
// (control.Store.SetStatePatchGate). The patch is a wire format of the control group: its members
// are the ones that decode it, and a membership change that reached the control group but not (yet)
// the slot-0 group leaves a voter in the first that the second does not list, so declarations are
// read for the control group's own members, and a member the slot-0 group never listed has none and
// holds the gate closed. The slot-0 members are checked as well (the declarations live in that
// group). An empty control configuration is not ready. Until then every control command is the
// whole-state replacement every release applies, which the replica's entry limit bounds. Same
// reading rules as ControlBoundsReady: local replicated state only, evaluated at every use, false
// without replication.
func (e *Engine) ControlStatePatchReady(control []replica.Member) bool {
	if len(control) == 0 {
		return false
	}
	return e.declaredByAll(statePatchProtocol, control)
}

// declaredBy reports whether every member of the slot-0 group's committed configuration declared
// a protocol of at least version.
func (e *Engine) declaredBy(version uint64) bool { return e.declaredByAll(version, nil) }

// declaredByAll is declaredBy for the slot-0 members and also for the members of extra.
func (e *Engine) declaredByAll(version uint64, extra []replica.Member) bool {
	if e.repl == nil {
		return false
	}
	members := slices.Concat(e.repl.groups[eraseAckSlot].Status().Members.Nodes, extra)
	if len(members) == 0 {
		return false
	}
	ready := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		ready = true
		for _, m := range members {
			if capabilityOf(meta, m.ID, m.NodeIdentity) < version {
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
	if declared < declaredProtocol {
		if err := e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
			return walEntry{Type: "erase_ack", EraseAck: &eraseAck{Node: model.Uint64(node), Identity: identity, Operations: []model.ID{capabilityOp}, Epoch: model.Uint64(declaredProtocol), Cursor: cursor}}
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
	if current == e.disk() {
		return nil
	}
	return e.proposeSlotZero(ctx, func(cursor model.Cursor) walEntry {
		return walEntry{Type: "erase_unack", EraseUnack: &eraseUnack{Node: model.Uint64(node), Identity: identity, Epoch: model.Uint64(epoch), Incarnation: e.disk(), Cursor: cursor}}
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

// selfRef names this voter's own member in the configuration it was enabled with.
type selfRef struct {
	node     uint64
	identity string
}

// diskDeclared reports whether this voter holds acknowledgements that stand on every voter: the
// replicated state lists an incarnation for its own member (its node id and identity from
// EnableReplication), whichever disk that incarnation was. A replaced disk is not the declared one
// until it declares itself, but the acknowledgements its predecessor made still count on every
// voter until then, so it is held to the same rule. A member with nothing recorded (a fresh
// learner, a new member) holds none and is repairable by any snapshot. It reads local state only
// and takes no group lock, because it runs while the group that receives a snapshot holds its own.
func (e *Engine) diskDeclared() bool {
	incarnation := e.disk()
	self := e.self.Load()
	if incarnation == "" && self == nil {
		return false
	}
	declared := false
	if err := e.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_data"))
		if self != nil && len(meta.Get(eraseIncKey(self.node, self.identity))) != 0 {
			declared = true
			return nil
		}
		if incarnation == "" {
			return nil
		}
		prefix := metaKey(eraseAckSlot, "erase-inc:")
		c := meta.Cursor()
		for k, v := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = c.Next() {
			if string(v) == incarnation {
				declared = true
				return nil
			}
		}
		return nil
	}); err != nil {
		return true // cannot tell: refuse, the sender sends again
	}
	return declared
}

// admitSnapshot is replica.SnapshotGate on the receiver: it refuses a snapshot announced by a
// notice this voter already gave up or acknowledged past, and otherwise marks a step in progress
// until release, after which the notice is settled.
//
// A snapshot that carries no token (a gated sender whose own view said the protocol was not
// declared by every member yet, so it committed no notice) is refused by a voter that declared its
// disk: its acknowledgements made under that declaration count on every voter, and nothing was
// committed before this install that could void them (10.35#12). The sender sends again, with a
// token once its view caught up. A voter with nothing recorded for its own member (a fresh or new
// member) holds no acknowledgement a receipt can count and admits it.
func (e *Engine) admitSnapshot(token []byte) (func(), error) {
	if len(token) == 0 {
		if e.diskDeclared() {
			return nil, model.Fail(model.Unavailable)
		}
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
