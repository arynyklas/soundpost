// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// Layout 2 of a contracted installation (ledgerFormat 2): the revision lives outside the blob.
//
// Every control command steps the revision, and the revision is a member of the state, so the blob under
// control/state (1.76 MB at the single-host gate's estate) was written whole by every command, an
// admission included: ~100 KB per acknowledged request after group commit, 250 commands a second of the
// whole estate through bolt's copy-on-write pages and the SHA-256 of every seal and digest, for a change of
// eight bytes. The blob of a layout 2 file is the encoding of the state without its Revision and its
// revision_clock members; those two (and the installation, which a command is checked against) are keys
// of the control bucket of their own, and the digest of the rest of the blob is kept beside it, so that a
// command that only steps the revision (an admission round) writes a few dozen bytes and reads no blob.
//
// It is a LOCAL layout of a file whose installation is contracted, which has no previous release among its
// members to read the blob (ledger.go). The logical state is unchanged: a snapshot, a patch, a backup and
// every View assemble the same members with the same encoding, and the digest a patch names (Base) is the
// digest of the same logical state (ledgerBase), only computed from the pieces instead of from a pass over
// the blob.
var (
	stateKey       = []byte("state")
	stateRevKey    = []byte("state_rev")    // the encoding of the Revision member's value
	stateClockKey  = []byte("state_clock")  // the encoding of the revision_clock member's value (absent: no member)
	stateInstKey   = []byte("state_inst")   // the encoding of the Installation member's value
	stateDigestKey = []byte("state_digest") // hex digest (hashMembers) of the blob's members
)

const (
	memberRevision     = "Revision"
	memberClock        = "revision_clock"
	memberInstallation = "Installation"
)

// volatileMembers are the root members layout 2 keeps outside the blob, as the encoder wrote them.
type volatileMembers struct {
	installation []byte
	revision     []byte
	clock        []byte // nil: the state has no revision_clock member
}

// splitVolatile takes the Revision and revision_clock members out of the encoding of a state. An
// encoding that is not the compact one the encoder writes is decoded and encoded first.
func splitVolatile(raw []byte) (stripped []byte, v volatileMembers, err error) {
	members, ok := scanObject(raw, 0, len(raw), make([]rawMember, 0, 64))
	if !ok {
		var st State
		if json.Unmarshal(raw, &st) != nil {
			return nil, v, model.Fail(model.Corrupt)
		}
		again, e := json.Marshal(st)
		if e != nil {
			return nil, v, model.Fail(model.Corrupt)
		}
		raw = again
		if members, ok = scanObject(raw, 0, len(raw), make([]rawMember, 0, 64)); !ok {
			return nil, v, model.Fail(model.Corrupt)
		}
	}
	stripped = make([]byte, 0, len(raw))
	stripped = append(stripped, '{')
	first := true
	for _, m := range members {
		name, named := unquoteMemberName(raw, m)
		if !named {
			return nil, v, model.Fail(model.Corrupt)
		}
		switch name {
		case memberRevision:
			v.revision = bytes.Clone(raw[m.vs:m.ve])
			continue
		case memberClock:
			v.clock = bytes.Clone(raw[m.vs:m.ve])
			continue
		case memberInstallation:
			v.installation = bytes.Clone(raw[m.vs:m.ve])
		}
		if !first {
			stripped = append(stripped, ',')
		}
		first = false
		stripped = append(stripped, raw[m.ks:m.ve]...)
	}
	stripped = append(stripped, '}')
	if v.revision == nil || v.installation == nil {
		return nil, v, model.Fail(model.Corrupt)
	}
	return stripped, v, nil
}

// joinVolatile is the encoding of the state whose blob is stripped and whose revision and clock are the
// ones given: the bytes the encoder writes for it.
func joinVolatile(stripped, revision, clock []byte) ([]byte, error) {
	if members, ok := scanObject(stripped, 0, len(stripped), make([]rawMember, 0, 64)); ok {
		ops := []patchOp{{Op: opSet, Path: []string{memberRevision}, Value: revision}}
		if clock != nil {
			ops = append(ops, patchOp{Op: opSet, Path: []string{memberClock}, Value: clock})
		}
		trie, err := newPatchTrie(ops)
		if err == nil {
			p := &rawPatcher{raw: stripped}
			if p.editObject(trie, 0, len(stripped), reflect.TypeFor[State](), members, true) {
				return p.w.bytes(), nil
			}
		}
	}
	var st State
	if json.Unmarshal(stripped, &st) != nil || json.Unmarshal(revision, &st.Revision) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	if clock != nil && json.Unmarshal(clock, &st.RevisionClock) != nil {
		return nil, model.Fail(model.Corrupt)
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return nil, model.Fail(model.Corrupt)
	}
	return raw, nil
}

// hashStripped is the digest of the members of a stripped blob.
func hashStripped(stripped []byte) (string, error) {
	members, err := decodeMembers(stripped)
	if err != nil {
		return "", err
	}
	return hashMembers(members), nil
}

// readState decodes the committed state of the control bucket (the ledger members are not part of it).
func readState(ctrl *bolt.Bucket, st *State) error {
	if ctrl == nil {
		return model.Fail(model.Corrupt)
	}
	if v, ok := trackedDBs.Load(ctrl.Tx().DB()); ok {
		v.(*trackedDB).blobDecodes.Add(1)
	}
	if json.Unmarshal(ctrl.Get(stateKey), st) != nil {
		return model.Fail(model.Corrupt)
	}
	if !ledgerLayout(ctrl) {
		return nil
	}
	return attachVolatile(ctrl, st)
}

// attachVolatile sets the revision and the clock of a layout 2 file in the state decoded from its blob.
func attachVolatile(ctrl *bolt.Bucket, st *State) error {
	if json.Unmarshal(ctrl.Get(stateRevKey), &st.Revision) != nil {
		return model.Fail(model.Corrupt)
	}
	st.RevisionClock = nil
	if raw := ctrl.Get(stateClockKey); raw != nil && json.Unmarshal(raw, &st.RevisionClock) != nil {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// stateRaw is the encoding of the committed state (the ledger members are not part of it). It is the
// bytes of the blob in a file that keeps its revision in it, a copy assembled from the pieces in layout 2;
// the caller must not change it and does not keep it past its transaction.
func stateRaw(ctrl *bolt.Bucket) ([]byte, error) {
	raw := ctrl.Get(stateKey)
	if raw == nil {
		return nil, model.Fail(model.Corrupt)
	}
	if !ledgerLayout(ctrl) {
		return raw, nil
	}
	return joinVolatile(raw, ctrl.Get(stateRevKey), ctrl.Get(stateClockKey))
}

// stateHead is the installation and the revision of the committed state, which a command is checked against.
func stateHead(ctrl *bolt.Bucket) (installation model.ID, revision model.Revision, err error) {
	if ledgerLayout(ctrl) {
		if json.Unmarshal(ctrl.Get(stateInstKey), &installation) != nil || json.Unmarshal(ctrl.Get(stateRevKey), &revision) != nil {
			return model.ID{}, 0, model.Fail(model.Corrupt)
		}
		return installation, revision, nil
	}
	return revisionOf(ctrl.Get(stateKey))
}

// memberJobBooks is the member of the state that holds the job books.
const memberJobBooks = "JobBooks"

// changedMembers names the members of the blob about to replace the committed blob old that are not what old
// holds: added, removed or encoded otherwise. A job update (the worker's ~35 a second at the single-host gate)
// changes the job books and nothing else, a rule commit the rule books and the outbox, and a core reader
// decodes again only what a write changed (coreMembers). Anything the comparison cannot establish is a change of
// every member: all.
func changedMembers(old []byte, members map[string]json.RawMessage) (names []string, all bool) {
	if old == nil {
		return nil, true
	}
	oldMembers, err := decodeMembers(old)
	if err != nil {
		return nil, true
	}
	for name, v := range members {
		if o, ok := oldMembers[name]; !ok || !bytes.Equal(o, v) {
			names = append(names, name)
		}
	}
	for name := range oldMembers {
		if _, ok := members[name]; !ok {
			names = append(names, name)
		}
	}
	return names, false
}

// putStateLayout writes the encoding raw of a whole state into a layout 2 file: the blob without the
// volatile members, the keys that hold them, the digest of the blob and the seals.
func putStateLayout(ctrl *bolt.Bucket, raw []byte) error {
	stripped, v, err := splitVolatile(raw)
	if err != nil {
		return err
	}
	members, err := decodeMembers(stripped)
	if err != nil {
		return err
	}
	digest := hashMembers(members)
	if names, all := changedMembers(ctrl.Get(stateKey), members); all {
		markCoreChanged(ctrl.Tx())
	} else {
		markMembersChanged(ctrl.Tx(), names)
	}
	if err = ctrl.Put(stateKey, stripped); err != nil {
		return err
	}
	if err = ctrl.Put(stateRevKey, v.revision); err != nil {
		return err
	}
	if err = ctrl.Put(stateInstKey, v.installation); err != nil {
		return err
	}
	if err = ctrl.Put(stateDigestKey, []byte(digest)); err != nil {
		return err
	}
	if v.clock != nil {
		err = ctrl.Put(stateClockKey, v.clock)
	} else {
		err = ctrl.Delete(stateClockKey)
	}
	if err != nil {
		return err
	}
	return sealState(ctrl)
}

// putStep moves the revision of a layout 2 file, and its clock when setClock is set (nil clock: the
// member is absent), without touching the blob.
func putStep(ctrl *bolt.Bucket, revision model.Revision, clock []byte, setClock bool) error {
	raw, err := json.Marshal(revision)
	if err != nil {
		return err
	}
	if err = ctrl.Put(stateRevKey, raw); err != nil {
		return err
	}
	if !setClock {
		return nil
	}
	if clock == nil {
		return ctrl.Delete(stateClockKey)
	}
	return ctrl.Put(stateClockKey, clock)
}

// stripBlob moves a file whose blob is the whole encoding of the state (the books already out of it)
// to layout 2: the keys that hold the volatile members and the stripped blob, with its seals.
func stripBlob(ctrl *bolt.Bucket) error {
	raw := ctrl.Get(stateKey)
	if raw == nil {
		return model.Fail(model.Corrupt)
	}
	markCoreChanged(ctrl.Tx())
	return putStateLayout(ctrl, bytes.Clone(raw))
}

// dropLayoutKeys removes the keys of layout 2 (the file goes back to a blob that holds everything).
func dropLayoutKeys(ctrl *bolt.Bucket) error {
	markCoreChanged(ctrl.Tx())
	for _, key := range [][]byte{stateRevKey, stateClockKey, stateInstKey, stateDigestKey} {
		if err := ctrl.Delete(key); err != nil {
			return err
		}
	}
	return nil
}

// ledgerBase is the digest a patch names (Base) for a state of a file that keeps its books in the ledger:
// the digest of the blob's members other than the revision and its clock, those two as they are encoded,
// and the ledger's accumulator. It is a function of the logical state alone (it does not depend on where
// the file keeps the revision), and the parts that change with every command are not part of a pass over
// the blob.
func ledgerBase(blobDigest string, revision, clock []byte, acc [32]byte) string {
	h := sha256.New()
	h.Write([]byte("ledger2\x00"))
	h.Write([]byte(blobDigest))
	h.Write([]byte{0})
	h.Write(revision)
	h.Write([]byte{0})
	h.Write(clock)
	h.Write([]byte{0})
	h.Write(acc[:])
	return hex.EncodeToString(h.Sum(nil))
}

// layoutBase is ledgerBase of the committed state of a layout 2 file, from its keys.
func layoutBase(ctrl *bolt.Bucket, acc [32]byte) string {
	return ledgerBase(string(ctrl.Get(stateDigestKey)), ctrl.Get(stateRevKey), ctrl.Get(stateClockKey), acc)
}

// ledgerBase1 is the digest the first build of the ledger layout named: the digest of the whole blob
// (patchBase) and the accumulator. A command it proposed and the journal still holds is applied by a
// build that names ledgerBase; baseMatches accepts both for the same committed state.
func ledgerBase1(blobBase string, acc [32]byte) string {
	h := sha256.New()
	h.Write([]byte("ledger1\x00"))
	h.Write([]byte(blobBase))
	h.Write([]byte{0})
	h.Write(acc[:])
	return hex.EncodeToString(h.Sum(nil))
}

// stepOfOps is the revision, and the clock when the ops set it (nil clock with setClock: the member is
// absent), that ops (which write nothing but the revision and its clock: onlyStepOps) leave in a layout 2
// file. The values are decoded strictly into their types and encoded again, as the splice of the blob
// does (canonicalLeaf). The revision must be the one after expected.
func stepOfOps(ops []patchOp, expected model.Revision) (revision model.Revision, clock []byte, setClock bool, err error) {
	haveRevision := false
	for _, op := range ops {
		switch op.Path[0] {
		case memberRevision:
			if decodeValue(op.Value, &revision) != nil {
				return 0, nil, false, model.Fail(model.Corrupt)
			}
			haveRevision = true
		case memberClock:
			var stamps []model.RevisionStamp
			if decodeValue(op.Value, &stamps) != nil {
				return 0, nil, false, model.Fail(model.Corrupt)
			}
			setClock = true
			if len(stamps) != 0 {
				if clock, err = json.Marshal(stamps); err != nil {
					return 0, nil, false, model.Fail(model.Corrupt)
				}
			}
		}
	}
	if !haveRevision || revision != expected+1 {
		return 0, nil, false, model.Fail(model.Corrupt)
	}
	return revision, clock, setClock, nil
}

// verifyStepOps checks that a layout 2 file already holds what step ops write (a replay of a command the
// state has applied): the revision and the clock are the ones the ops set.
func verifyStepOps(ctrl *bolt.Bucket, ops []patchOp) error {
	for _, op := range ops {
		var stored []byte
		switch op.Path[0] {
		case memberRevision:
			stored = ctrl.Get(stateRevKey)
		case memberClock:
			stored = ctrl.Get(stateClockKey)
		}
		if stored == nil || !sameJSON(stored, op.Value) {
			return model.Fail(model.Corrupt)
		}
	}
	return nil
}
