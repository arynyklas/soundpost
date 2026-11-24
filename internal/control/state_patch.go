// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

// The state patch is the third shape of a replicated control command. A controlReplacement carries
// the whole next state, so a command is as large as the control state: past 16 MiB (the replica's
// entry limit, replica.Entry) no command could be proposed at all, and well before that every
// command costs a whole-state journal record on every voter, which with the journal cadence
// (DefaultJournalCadence) turns into a snapshot cut per command. The patch carries what the
// transition changed and nothing else, so the size of a command follows the size of its change.
//
// The proposer (Store.replicatedUpdate) runs the same transition function as before, marshals the
// next state, and diffs that JSON against the bytes of the state it read: a member that did not
// change is not mentioned. The diff goes into a record of a map only as far as the shape of the
// state makes a record's address stable: [Field, key] for every map of records, and
// [Orgs, org, Field, key] below an organization (its members, projects and settings are maps of their
// own). Every other value is replaced whole. The two logs that only grow at the end (Audits,
// revision_clock) are arrays, and a change of them is a cut of the oldest rows and an append, so a
// chunk's audit row or a minute's clock stamp is one row, not the log.
//
// A voter applies a patch to the bytes of its committed state, and requires the installation and
// revision the command names: the same compare-and-swap, the same revision step, the same checks of
// the state it ends in as a replacement. It does so without decoding the state when it can
// (patchRaw, state_raw.go: the members the patch does not name are carried over as they are, the
// values it names are decoded strictly into their type and encoded again, and the result is the
// bytes the encoder writes for the state); when the splice cannot prove that it does exactly that, it
// applies the ops to the members (applyPatchRaw), decodes the result strictly as a State and encodes
// it. TestStatePatchEqualsReplacement pins that the state a patch leaves is the state the
// replacement leaves, on random transitions; TestRawPatchEqualsDecodeEncode that the two ways of
// applying it leave the same bytes.
//
// It is a wire format an older binary cannot decode (it stops applying a command it does not
// understand), so it is proposed only once every member of the committed configuration declared
// protocol 5 (storage.statePatchProtocol, SetStatePatchGate); until then, and for a store without a
// gate, a command is a replacement, which is bounded by the entry limit.

// statePatchKey is the only member of a patch payload.
const statePatchKey = "state_patch"

// The three operations of a patch.
const (
	opSet    = "set"   // the value at the path becomes Value (created when absent)
	opDelete = "del"   // the member at the path is removed (nothing, when it is absent)
	opArray  = "array" // the first Cut rows of the array at the path are dropped, Value's rows are appended
)

// patchOp is one change. Path addresses a member from the root of the state; its segments are the
// member names of nested objects.
type patchOp struct {
	Op    string          `json:"op"`
	Path  []string        `json:"p"`
	Value json.RawMessage `json:"v,omitempty"`
	Cut   int             `json:"cut,omitempty"`
}

// statePatch is the body of a state patch command.
//
// Base is the digest (patchBase) of the committed state the proposer computed the ops against. The
// revision alone does not say which bytes a voter holds: a stale command is rejected with the
// revision moved to its application slot and the older bytes kept (Apply), so two voters can hold
// different bytes at one revision, and ops that only name the members they change would commit on
// both and leave the difference for ever, where a replacement rewrote every member. A voter whose
// bytes do not match refuses the patch. Base is empty only in a patch that an erasure pass rewrote
// or that follows a rewritten command in its pass (redactPatch, clearPatchBase): the voter that
// applies the rewritten log is behind and holds records the pass erased, so its maps are not the
// proposer's by design; a proposal is never accepted without one (Validate).
type statePatch struct {
	Installation model.ID          `json:"installation"`
	Expected     model.Revision    `json:"expected"`
	Base         string            `json:"base"`
	Keys         map[string][]byte `json:"keys"`
	Ops          []patchOp         `json:"ops"`
}

type statePatchCommand struct {
	StatePatch statePatch `json:"state_patch"`
}

// patchBase is the digest of a state encoding: every member, in name order, record maps included.
// The retained commands an erasure pass rewrites are the one place where voters legitimately hold
// other record maps at one revision; those commands carry no base (clearPatchBase), so every patch
// that does carry one is applied to the bytes it was computed against, on every voter.
func patchBase(raw []byte) (string, error) {
	members, err := decodeMembers(raw)
	if err != nil {
		return "", err
	}
	return hashMembers(members), nil
}

// hashMembers is patchBase of the members of an encoding.
func hashMembers(members map[string]json.RawMessage) string {
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(members[name])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// validBase is whether s is a digest patchBase writes, or empty (a rewritten patch).
func validBase(s string) bool {
	if s == "" {
		return true
	}
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == s
}

// appendOnlyArrays are the arrays a patch changes row-wise (a cut and an append), by the name of
// the member in the JSON encoding of the state; every other array is replaced whole, so no index of
// a book that an erasure shortens is ever written into a command.
var appendOnlyArrays = map[string]bool{"Audits": true, "revision_clock": true}

// maxPatchOpPath is the deepest path a patch writes.
const maxPatchOpPath = 4

// recursesInto reports whether the diff goes into the object at path (a member of the root and of a
// map of records is a record: recursing past it would address the inside of an opaque book).
func recursesInto(path []string) bool {
	if len(path) < 2 {
		return true
	}
	return path[0] == "Orgs" && len(path) < maxPatchOpPath
}

// validPatchPath is the rule recursesInto draws, as a check of a decoded path. The members of the
// admission ledger (ledger.go) are addressed by their own shapes, which validLedgerOp judges with the op.
func validPatchPath(path []string) bool {
	if len(path) == 0 || path[0] == "" {
		return false
	}
	if ledgerRoot(path[0]) {
		return true
	}
	if path[0] == "Orgs" {
		return len(path) <= maxPatchOpPath
	}
	return len(path) <= 2
}

func isJSONObject(raw []byte) bool { return len(raw) > 0 && raw[0] == '{' }
func isJSONArray(raw []byte) bool  { return len(raw) > 0 && raw[0] == '[' }

// sameJSON reports whether two raw values are the same JSON text once compacted.
func sameJSON(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return false
	}
	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// decodeMembers is the members of the object encoding raw. The values are views of raw (capped, so
// that an append to one cannot write into its neighbour), not copies: the callers read them, and a
// state encoding is tens of megabytes. An encoding that is not compact is decoded the slow way.
func decodeMembers(raw []byte) (map[string]json.RawMessage, error) {
	if members, ok := scanObject(raw, 0, len(raw), nil); ok {
		m := make(map[string]json.RawMessage, len(members))
		named := true
		for _, mem := range members {
			name, ok := unquoteMemberName(raw, mem)
			if !ok {
				named = false
				break
			}
			m[name] = raw[mem.vs:mem.ve:mem.ve]
		}
		if named {
			return m, nil
		}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return m, nil
}

func decodeRows(raw []byte) ([]json.RawMessage, error) {
	var rows []json.RawMessage
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		return nil, model.Fail(model.Corrupt)
	}
	return rows, nil
}

// diffStates is the patch operations that turn the state encoded in oldRaw into newRaw (both the
// encoding of a State). Applying them to oldRaw gives a state equal to newRaw as a JSON value.
func diffStates(oldRaw, newRaw []byte) ([]patchOp, error) {
	if !isJSONObject(oldRaw) || !isJSONObject(newRaw) {
		return nil, model.Fail(model.Corrupt)
	}
	var ops []patchOp
	if err := diffValue(nil, oldRaw, newRaw, &ops); err != nil {
		return nil, err
	}
	return ops, nil
}

func childPath(path []string, name string) []string {
	out := make([]string, len(path)+1)
	copy(out, path)
	out[len(path)] = name
	return out
}

func diffValue(path []string, oldRaw, newRaw json.RawMessage, out *[]patchOp) error {
	if bytes.Equal(oldRaw, newRaw) {
		return nil
	}
	if recursesInto(path) && isJSONObject(oldRaw) && isJSONObject(newRaw) {
		oldM, err := decodeMembers(oldRaw)
		if err != nil {
			return err
		}
		newM, err := decodeMembers(newRaw)
		if err != nil {
			return err
		}
		names := make([]string, 0, len(oldM)+len(newM))
		for name := range oldM {
			names = append(names, name)
		}
		for name := range newM {
			if _, ok := oldM[name]; !ok {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			o, inOld := oldM[name]
			n, inNew := newM[name]
			switch {
			case !inNew:
				*out = append(*out, patchOp{Op: opDelete, Path: childPath(path, name)})
			case !inOld:
				*out = append(*out, patchOp{Op: opSet, Path: childPath(path, name), Value: n})
			default:
				if err := diffValue(childPath(path, name), o, n, out); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if len(path) == 1 && appendOnlyArrays[path[0]] && isJSONArray(oldRaw) && isJSONArray(newRaw) {
		if op, ok, err := diffRows(path, oldRaw, newRaw); err != nil {
			return err
		} else if ok {
			*out = append(*out, op)
			return nil
		}
	}
	*out = append(*out, patchOp{Op: opSet, Path: slices.Clone(path), Value: newRaw})
	return nil
}

// maxCutProbes bounds how many places the search for the first surviving row tries.
const maxCutProbes = 8

// diffRows expresses newRaw as oldRaw without its first cut rows and with rows appended; ok is false
// when it is not of that shape (a row in the middle changed).
func diffRows(path []string, oldRaw, newRaw []byte) (patchOp, bool, error) {
	oldRows, err := decodeRows(oldRaw)
	if err != nil {
		return patchOp{}, false, err
	}
	newRows, err := decodeRows(newRaw)
	if err != nil {
		return patchOp{}, false, err
	}
	survives := func(cut int) bool {
		kept := len(oldRows) - cut
		if kept > len(newRows) {
			return false
		}
		for i := range kept {
			if !bytes.Equal(oldRows[cut+i], newRows[i]) {
				return false
			}
		}
		return true
	}
	cut := -1
	if survives(0) {
		cut = 0
	} else if len(newRows) == 0 {
		cut = len(oldRows)
	} else {
		probes := 0
		for c := 1; c < len(oldRows) && probes < maxCutProbes; c++ {
			if !bytes.Equal(oldRows[c], newRows[0]) {
				continue
			}
			probes++
			if survives(c) {
				cut = c
				break
			}
		}
	}
	if cut < 0 {
		return patchOp{}, false, nil
	}
	appended, err := json.Marshal(newRows[len(oldRows)-cut:])
	if err != nil {
		return patchOp{}, false, model.Fail(model.Invalid)
	}
	return patchOp{Op: opArray, Path: slices.Clone(path), Value: appended, Cut: cut}, true, nil
}

// patchNode is the ops of a patch arranged by path: a node with children is an object that is edited
// member by member, a node with an op is the member the op addresses.
type patchNode struct {
	children map[string]*patchNode
	op       *patchOp
}

// newPatchTrie arranges ops by path. A path that is addressed twice, or that is the prefix of
// another, is not a patch.
func newPatchTrie(ops []patchOp) (*patchNode, error) {
	root := &patchNode{}
	for i := range ops {
		op := &ops[i]
		node := root
		for _, name := range op.Path {
			if node.op != nil {
				return nil, model.Fail(model.Invalid)
			}
			if node.children == nil {
				node.children = map[string]*patchNode{}
			}
			next := node.children[name]
			if next == nil {
				next = &patchNode{}
				node.children[name] = next
			}
			node = next
		}
		if node.op != nil || node.children != nil {
			return nil, model.Fail(model.Invalid)
		}
		node.op = op
	}
	return root, nil
}

// onlyDeletes reports whether every operation under this node deletes.
func (n *patchNode) onlyDeletes() bool {
	if n.op != nil {
		return n.op.Op == opDelete
	}
	for _, child := range n.children {
		if !child.onlyDeletes() {
			return false
		}
	}
	return true
}

func (n *patchNode) names() []string {
	names := make([]string, 0, len(n.children))
	for name := range n.children {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// apply returns the value this node's path holds once the patch is applied to cur (present says
// whether the member existed), and whether it exists after. depth is the node's depth below the root
// of the state. lenient is for a patch an erasure pass rewrote (it carries no base): a record of a map
// of records may be written into a map that is absent or null (depth 1), because the pass emptied the
// whole-map write that created it and an emptied omitted map is not written back, so the voter that
// replays the rewritten log reaches the next record of the book holding no book at all.
func (n *patchNode) apply(cur json.RawMessage, present bool, depth int, lenient bool) (json.RawMessage, bool, error) {
	if n.op != nil {
		switch n.op.Op {
		case opSet:
			return n.op.Value, true, nil
		case opDelete:
			return nil, false, nil
		}
		if !present || !isJSONArray(cur) {
			return nil, false, model.Fail(model.Corrupt)
		}
		rows, err := decodeRows(cur)
		if err != nil || n.op.Cut > len(rows) {
			return nil, false, model.Fail(model.Corrupt)
		}
		more, err := decodeRows(n.op.Value)
		if err != nil {
			return nil, false, err
		}
		out, err := json.Marshal(append(rows[n.op.Cut:len(rows):len(rows)], more...))
		if err != nil {
			return nil, false, model.Fail(model.Corrupt)
		}
		return out, true, nil
	}
	if !present || !isJSONObject(cur) {
		if n.onlyDeletes() {
			return cur, present, nil // nothing to delete from what is not a map
		}
		if lenient && depth == 1 && (!present || string(cur) == "null") {
			cur = json.RawMessage("{}")
		} else {
			return nil, false, model.Fail(model.Corrupt)
		}
	}
	members, err := decodeMembers(cur)
	if err != nil {
		return nil, false, err
	}
	for _, name := range n.names() {
		value, has := members[name]
		next, exists, err := n.children[name].apply(value, has, depth+1, lenient)
		if err != nil {
			return nil, false, err
		}
		if exists {
			members[name] = next
		} else {
			delete(members, name)
		}
	}
	out, err := json.Marshal(members)
	if err != nil {
		return nil, false, model.Fail(model.Corrupt)
	}
	return out, true, nil
}

// verify checks that cur already holds what this node's ops write (a replay of a command the state
// has applied): every set value equal, every deleted member absent, the appended rows at the end of
// every array.
func (n *patchNode) verify(cur json.RawMessage, present bool) error {
	if n.op != nil {
		switch n.op.Op {
		case opSet:
			if !present || !sameJSON(cur, n.op.Value) {
				return model.Fail(model.Corrupt)
			}
		case opDelete:
			if present {
				return model.Fail(model.Corrupt)
			}
		default:
			if !present || !isJSONArray(cur) {
				return model.Fail(model.Corrupt)
			}
			rows, err := decodeRows(cur)
			if err != nil {
				return err
			}
			more, err := decodeRows(n.op.Value)
			if err != nil || len(rows) < len(more) {
				return model.Fail(model.Corrupt)
			}
			tail := rows[len(rows)-len(more):]
			for i := range more {
				if !sameJSON(tail[i], more[i]) {
					return model.Fail(model.Corrupt)
				}
			}
		}
		return nil
	}
	if !present || !isJSONObject(cur) {
		if n.onlyDeletes() {
			return nil // the records it deletes cannot be there: no map holds them
		}
		return model.Fail(model.Corrupt)
	}
	members, err := decodeMembers(cur)
	if err != nil {
		return err
	}
	for _, name := range n.names() {
		value, has := members[name]
		if err := n.children[name].verify(value, has); err != nil {
			return err
		}
	}
	return nil
}

// applyPatchRaw is the state encoded in raw with the patch applied, as one encoding of a State.
// lenient is true for a patch without a base (see patchNode.apply).
func applyPatchRaw(raw []byte, ops []patchOp, lenient bool) ([]byte, error) {
	root, err := newPatchTrie(ops)
	if err != nil {
		return nil, err
	}
	out, _, err := root.apply(raw, true, 0, lenient)
	return out, err
}

// verifyPatchRaw is applyPatchRaw's counterpart for a replay: it checks that the state in raw is one
// the patch has been applied to.
func verifyPatchRaw(raw []byte, ops []patchOp) error {
	root, err := newPatchTrie(ops)
	if err != nil {
		return err
	}
	return root.verify(raw, true)
}

// validatePatch is the structural check of a decoded patch: what a proposer writes and every voter
// accepts, before any state is read.
func validatePatch(p statePatch) error {
	if len(p.Ops) == 0 || p.Expected == ^model.Revision(0) || !validBase(p.Base) {
		return model.Fail(model.Invalid)
	}
	for _, op := range p.Ops {
		if !validPatchPath(op.Path) || ledgerRoot(op.Path[0]) && !validLedgerOp(op) && !wholeMemberOp(op) {
			return model.Fail(model.Invalid)
		}
		switch op.Op {
		case opSet:
			if len(op.Value) == 0 || op.Cut != 0 {
				return model.Fail(model.Invalid)
			}
		case opDelete:
			if len(op.Value) != 0 || op.Cut != 0 {
				return model.Fail(model.Invalid)
			}
		case opArray:
			if len(op.Path) != 1 || !appendOnlyArrays[op.Path[0]] || !isJSONArray(op.Value) || op.Cut < 0 {
				return model.Fail(model.Invalid)
			}
			rows, err := decodeRows(op.Value)
			if err != nil || op.Cut == 0 && len(rows) == 0 {
				return model.Fail(model.Invalid)
			}
		default:
			return model.Fail(model.Invalid)
		}
	}
	_, err := newPatchTrie(p.Ops)
	return err
}

// patchCommand is the payload of a state patch for a transition from oldRaw (the encoding of the
// committed state the proposer read) to next. It names the digest of the blob alone, which is the
// digest of the state while the ledger is empty.
func patchCommand(oldRaw []byte, expected model.Revision, next *State, keys map[string][]byte) ([]byte, error) {
	base, err := patchBase(oldRaw)
	if err != nil {
		return nil, err
	}
	return patchCommandRaw(oldRaw, nil, expected, next, keys, base, nil)
}

// patchCommandRaw is patchCommand for a proposer that already holds the encoding of next (newRaw; nil
// encodes it here), names base as the digest of the state it read and adds ledgerOps (the ops that
// address the admission ledger, which next does not hold). The verification of a per-organization
// commit (settleOrgAuthority) is such a proposer: it has to encode the state to judge the commit, and
// the patch is diffed from the very same bytes.
func patchCommandRaw(oldRaw, newRaw []byte, expected model.Revision, next *State, keys map[string][]byte, base string, ledgerOps []patchOp) ([]byte, error) {
	var err error
	if newRaw == nil {
		if newRaw, err = json.Marshal(next); err != nil {
			return nil, model.Fail(model.Invalid)
		}
	}
	ops, err := diffStates(oldRaw, newRaw)
	if err != nil {
		return nil, err
	}
	ops = append(ops, ledgerOps...)
	payload, err := json.Marshal(statePatchCommand{StatePatch: statePatch{Installation: next.Installation, Expected: expected, Base: base, Keys: keys, Ops: ops}})
	if err != nil {
		return nil, model.Fail(model.Invalid)
	}
	return payload, nil
}

// patchedState is the State that applying ops (the ones that address the blob) to the state encoded in
// raw leaves, checked: decoded strictly, of the same installation, at the revision the patch steps to.
// The base the patch names was checked by the caller. lenient is for a patch without a base (see
// patchNode.apply).
func patchedState(raw []byte, current *State, ops []patchOp, expected model.Revision, lenient bool) (State, error) {
	patched, err := applyPatchRaw(raw, ops, lenient)
	if err != nil {
		return State{}, err
	}
	var next State
	if model.StrictJSON(patched, &next) != nil || next.Installation != current.Installation || next.Revision != expected+1 {
		return State{}, model.Fail(model.Corrupt)
	}
	return next, nil
}

// revisionOf is the installation and revision of a state encoding, without decoding the rest.
func revisionOf(raw []byte) (installation model.ID, revision model.Revision, err error) {
	if root := scanStateRoot(raw); root.ok {
		return root.installation, root.revision, nil
	}
	var head struct {
		Installation model.ID
		Revision     model.Revision
	}
	if json.Unmarshal(raw, &head) != nil {
		return model.ID{}, 0, model.Fail(model.Corrupt)
	}
	return head.Installation, head.Revision, nil
}

// SetStatePatchGate installs the function that says whether every member of the replica group
// declared the state patch protocol (storage.Engine.ControlStatePatchReady). It is read at every
// update, never cached. A Store without a gate proposes no patch: the patch is a wire format an
// older peer cannot decode, so the default is the replacement every release applies; a caller that
// enables replication on several voters has to install the gate to get patches (a single-process
// test installs func() bool { return true }). Passing nil removes the gate, which closes it again.
func (s *Store) SetStatePatchGate(ready func() bool) {
	if ready == nil {
		s.statePatchGate.Store(nil)
		return
	}
	s.statePatchGate.Store(&ready)
}

// StatePatch reports whether a command is proposed as a state patch: what the gate says, false
// without a gate.
func (s *Store) StatePatch() bool {
	gate := s.statePatchGate.Load()
	return gate != nil && (*gate)()
}

// SetLegacyStatePatchGate installs the function that says whether every member of the replica group
// declared the first protocol of the state patch (storage.Engine.ControlLegacyStatePatchReady): the
// previous release is one of them. Such a group proposes a patch only while the admission ledger holds
// no record, where the digest it names is the one every release computes; with books in the ledger a
// command is a whole-state replacement until every member declared the protocol of the ledger layout
// (SetStatePatchGate). Passing nil removes the gate.
func (s *Store) SetLegacyStatePatchGate(ready func() bool) {
	if ready == nil {
		s.legacyStatePatchGate.Store(nil)
		return
	}
	s.legacyStatePatchGate.Store(&ready)
}

func (s *Store) legacyStatePatch() bool {
	gate := s.legacyStatePatchGate.Load()
	return gate != nil && (*gate)()
}

// controlPayload is the payload of the command that takes the committed state encoded in oldRaw
// (read only when the patch is on, otherwise nil) to next; newRaw is the encoding of next when the
// caller already made one (settleOrgAuthority), nil otherwise. A command that does not fit the
// replica's entry limit is refused here with what the replica answers for it (invalid), before
// anything is proposed.
func (s *Store) controlPayload(oldRaw, newRaw []byte, expected model.Revision, next *State, keys map[string][]byte, base string, ledgerOps []patchOp) ([]byte, error) {
	if oldRaw == nil {
		payload, err := json.Marshal(controlReplacement{Expected: expected, State: *next, Keys: keys})
		if err != nil {
			return nil, model.Fail(model.Invalid)
		}
		return payload, nil
	}
	payload, err := patchCommandRaw(oldRaw, newRaw, expected, next, keys, base, ledgerOps)
	if err != nil {
		return nil, err
	}
	s.statePatches.Add(1)
	s.statePatchBytes.Add(uint64(len(payload)))
	return payload, nil
}

// verifyCurrentPatch is verifyCurrentState for a patch the machine already applied (a replay): the
// committed state is for the same installation and not older than the patch's revision; at that very
// revision it holds what the patch wrote.
func (m *replicatedControl) verifyCurrentPatch(p statePatch) error {
	return m.store.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		installation, revision, err := stateHead(ctrl)
		if err != nil {
			return err
		}
		if p.Expected == ^model.Revision(0) || installation != p.Installation || revision < p.Expected+1 {
			return model.Fail(model.Corrupt)
		}
		if revision != p.Expected+1 {
			return nil
		}
		layout := ledgerLayout(ctrl)
		blobOps, ledgerOps := p.Ops, []patchOp(nil)
		if layout {
			blobOps, ledgerOps = splitLedgerOps(p.Ops)
		}
		if len(ledgerOps) != 0 {
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			if err = l.verifyLedgerOps(ledgerOps); err != nil {
				return err
			}
		}
		if layout && onlyStepOps(blobOps) {
			return verifyStepOps(ctrl, blobOps)
		}
		raw, err := stateRaw(ctrl)
		if err != nil {
			return err
		}
		return verifyPatchRaw(raw, blobOps)
	})
}
