// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// Compact snapshots of the control group (D86, L2w20Admission15).
//
// A snapshot the group cuts for itself anchors its journal: the record that follows a compaction holds the
// snapshot, and a snapshot of the control state holds the state. That state grows with the admissions that
// are not settled yet (~1.2 KiB a reservation row: 141 MB at 115,000 acknowledged requests, and a data window
// settles only after its 4096 commands), and the record is bounded: at 115,000 rows the first compaction
// failed the bound and stopped the node of the single-host gate. Once the installation is contracted (no
// previous release is a member or can become one) the group therefore cuts a compact snapshot: the state
// stays where it already is, in control.db, and the snapshot names it by the revision it had and the seal of
// the stored state.
//
// What a compact snapshot gives up: a journal alone cannot rebuild control.db. The data groups work the same
// way (a database that is gone while the journal names a compact state is replaced, not repaired). A journal
// on a compact snapshot is therefore opened only over a control.db that backs it: at or past the snapshot's
// revision and, at that revision, with the seal the snapshot names. Anything else is refused with a typed
// corrupt fault that names the two remedies (replace this node, or restore a backup); the node never serves
// an empty or an older state. A snapshot sent to a peer, a seed and a backup are cut whole (Snapshot).
// Before the installation is contracted the previous release can read the journal, so the snapshot is whole
// (CompactSnapshot answers Snapshot) and a journal on it recovers a lost control.db as before.

// compactControl is the state of a compact snapshot.
type compactControl struct {
	Compact  uint64         `json:"compact"` // compactControlVersion
	Revision model.Revision `json:"revision"`
	Seal     string         `json:"seal"`
}

const compactControlVersion = 1

var compactControlPrefix = []byte(`{"compact":`)

func isCompactControl(raw []byte) bool { return bytes.HasPrefix(raw, compactControlPrefix) }

// compactStateRefusal is the fault an open answers when control.db does not back the compact snapshot its
// journal is anchored on.
func compactStateRefusal(why string) error {
	f := model.Fail(model.Corrupt)
	f.SafeDetail = "control_state_not_backed: control.db " + why + " the compact snapshot the control journal names; replace this node (membership replace) or restore a backup"
	return f
}

// storedSeal is the revision control.db holds and the seal of its stored state: the digest of what every
// state write moves together (the state seal and the ledger's accumulator). ok is false for a file that
// keeps neither (nothing to name).
func storedSeal(tx *bolt.Tx) (revision uint64, seal string, ok bool) {
	ctrl, progress := tx.Bucket([]byte("control")), tx.Bucket([]byte("replica_control"))
	if ctrl == nil || progress == nil {
		return 0, "", false
	}
	stateSeal := ctrl.Get(stateSealKey)
	if len(stateSeal) == 0 {
		return 0, "", false
	}
	h := sha256.New()
	h.Write([]byte("compact-control1\x00"))
	h.Write(stateSeal)
	h.Write([]byte{0})
	h.Write(ctrl.Get(ledgerAccKey))
	return readWatermark(progress.Get([]byte("application"))), hex.EncodeToString(h.Sum(nil)), true
}

// CompactSnapshot is replica.CompactMachine: the state of a snapshot the group cuts for itself.
func (m *replicatedControl) CompactSnapshot() ([]byte, error) {
	var out []byte
	err := m.store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("control")).Get([]byte("state"))
		if raw == nil || !bytes.Contains(raw, []byte(`"`+model.IndexesContractedKey+`"`)) {
			return nil // not contracted: whole
		}
		revision, seal, ok := storedSeal(tx)
		if !ok {
			return nil
		}
		var err error
		out, err = json.Marshal(compactControl{Compact: compactControlVersion, Revision: model.Revision(revision), Seal: seal})
		return err
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return m.Snapshot()
	}
	return out, nil
}

var _ replica.CompactMachine = (*replicatedControl)(nil)

// CompactState is replica.CompactStateMachine: a state that is the compact marker is one only this release can read
// (an installation that is contracted has no member and can get none that predates it), and the group may then
// keep the retry table of its snapshots in files beside the envelope as well (replica retry parts, D87).
func (m *replicatedControl) CompactState(raw []byte) bool { return isCompactControl(raw) }

var _ replica.CompactStateMachine = (*replicatedControl)(nil)

// verifyCompact checks a compact snapshot against control.db: it must back it.
func (m *replicatedControl) verifyCompact(raw []byte) error {
	var c compactControl
	if model.StrictJSON(raw, &c) != nil || c.Compact != compactControlVersion || len(c.Seal) != 2*sha256.Size {
		return model.Fail(model.Corrupt)
	}
	return m.store.db.View(func(tx *bolt.Tx) error {
		revision, seal, ok := storedSeal(tx)
		switch {
		case !ok:
			return compactStateRefusal("holds no state for")
		case model.Revision(revision) < c.Revision:
			return compactStateRefusal("is older than")
		case model.Revision(revision) == c.Revision && seal != c.Seal:
			return compactStateRefusal("differs from the state sealed in")
		}
		return nil
	})
}
