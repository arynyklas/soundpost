// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"encoding/json"
	"reflect"
	"slices"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// recordMaps are the members of a State that are maps of records: the books an erasure rewrites
// record by record, and the only members a patch is redacted in.
var recordMaps = func() map[string]bool {
	out := map[string]bool{}
	t := reflect.TypeFor[State]()
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Type.Kind() != reflect.Map {
			continue
		}
		name := f.Name
		if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag != "" {
			name = tag
		}
		out[name] = true
	}
	return out
}()

// Redacting a state patch (RedactControlCommand). A replacement is redacted by running the erasure on
// the state it carries. A patch carries only the records its transition wrote, so the same functions
// run on those records alone: the records of the patch (a "set" of a member of a map of records) are
// put into a State of their own, the erasure of every finished deletion runs on that State, and each
// record it changed or dropped is written back (a dropped record becomes a "del", which leaves the
// record absent, as the erasure left it).
//
// A voter that is behind applies the redacted command in place of the original (the in-memory log
// that is sent to a voter that is behind is redacted), so the state it reaches has to be the state
// of the voters that applied the original and then the erasure. That holds because a record is
// written whole: whatever the redacted command leaves of a record is overwritten by the next
// command that writes the record, and the last command that wrote a record wrote what the
// committed state holds. That last write is left as it is (the committed state holds no payload of a
// finished deletion, so the record it wrote is not one), which also keeps the late-effect rule
// (eraseLateEffect: a state first committed after the deletion from evidence the range did not
// delete is kept) from ever being decided here: it is the committed state, not a rule, that says
// what survives. Every earlier write of the record is redacted with the begin/complete rule
// (stateErased), the wider of the two. The command that established the committed state is
// therefore never changed, and a patch is never refused as the replacement is.
//
// The rule is stateErased for every record, where a replacement that committed after the deletion
// finished is redacted with stateErasedLate (RedactControlCommand): a patch does not carry the
// state it committed in, so it cannot tell. That is a decision, not a gap: the wider rule only ever
// drops more of a record that a later write of the same record overwrites, so a voter that applies
// the rewritten patch passes through an intermediate state that is more erased than the replacement's
// would be, and reaches the committed state at the last write (left as it is, see above). Nothing
// that the narrow rule keeps is retained by the wide one, so it cannot leak what the other drops.

// liveBooks reads the committed state as the members the patch addresses. It encodes the state once,
// when first asked, and decodes a member's records once.
type liveBooks struct {
	state  State
	top    map[string]json.RawMessage
	fields map[string]map[string]json.RawMessage
}

// value is the encoding of the record key of the map field, and whether the committed state holds it.
func (l *liveBooks) value(field, key string) (json.RawMessage, bool, error) {
	if l.top == nil {
		raw, err := json.Marshal(l.state)
		if err != nil {
			return nil, false, model.Fail(model.Invalid)
		}
		if l.top, err = decodeMembers(raw); err != nil {
			return nil, false, err
		}
		l.fields = map[string]map[string]json.RawMessage{}
	}
	records, ok := l.fields[field]
	if !ok {
		if member := l.top[field]; isJSONObject(member) {
			var err error
			if records, err = decodeMembers(member); err != nil {
				return nil, false, err
			}
		}
		l.fields[field] = records
	}
	v, ok := records[key]
	return v, ok, nil
}

// redactPatch is redactControlPayload for a state patch. rules is the committed state with the
// finished deletions, live reads the committed state.
//
// The records of a patch are the "set" of a member of a map of records, and the members of a "set"
// of a whole map (the command that writes the first record of a book writes the book: the state it
// came from held none). A whole map is rewritten member by member and stays an object. When every
// member of it is erased the object is empty, and a state does not write an emptied omitted book
// back: the voter that replays the rewritten log then reaches the book's next record, a key-level
// write that the proposer made when the book existed, holding no book. A patch without a base
// therefore creates the book (patchNode.apply, lenient); TestAVoterReplayingARewrittenLogThatEmptiesAWholeBookReachesThePassHead.
//
// Invariant (the replay window, which carries no base): a rewritten patch only ever (1) drops or
// narrows a record that the committed state does not hold as written, and (2) leaves a record equal
// to the committed state untouched, so after the last retained write of every record a replaying voter
// holds the committed bytes. Deletes may empty an omitted-when-empty map member; the byte-level
// apply (state_raw.go editMember) refuses such a splice so that the voter decodes and the encoder
// omits the member, as every other voter's does.
func redactPatch(rules State, live *liveBooks, p statePatch, payload []byte) (replacement []byte, changed bool, err error) {
	if expanded, err := expandCompact(p.Ops); err != nil {
		return nil, false, err
	} else if len(expanded) != len(p.Ops) {
		p.Ops = expanded // the records of a reservation are read as the plain ops it stands for (compact_admission.go)
	}
	// A rec op (record_delta.go) is history: it adds rows to the record the voter holds. The retained commands of a record are all
	// written as the plain record the committed state holds (a delete when it holds none), so that a voter that replays the
	// rewritten log reaches it at every one of them and no erased row stays in a delta.
	recs, converted, err := expandRecords(p.Ops, func(key string) bool { return keyCoveredByDeletion(rules, key) }, live.value)
	if err != nil {
		return nil, false, err
	}
	p.Ops = recs
	untouched := func() ([]byte, bool, error) {
		if !converted {
			return payload, false, nil
		}
		p.Base = ""
		replacement, err := json.Marshal(statePatchCommand{StatePatch: p})
		if err != nil {
			return nil, false, model.Fail(model.Invalid)
		}
		return replacement, true, nil
	}
	type candidate struct {
		op         int
		field, key string
	}
	var candidates []candidate
	whole := map[int]map[string]json.RawMessage{} // op index -> the members of a set of a whole map
	fragments := map[string]map[string]json.RawMessage{}
	consider := func(i int, field, key string, value json.RawMessage) error {
		if kept, ok, err := live.value(field, key); err != nil {
			return err
		} else if ok && sameJSON(kept, value) {
			return nil // the committed state holds what this command wrote: not covered
		}
		if fragments[field] == nil {
			fragments[field] = map[string]json.RawMessage{}
		}
		fragments[field][key] = value
		candidates = append(candidates, candidate{i, field, key})
		return nil
	}
	for i, op := range p.Ops {
		if len(op.Path) == 0 || !recordMaps[op.Path[0]] {
			continue
		}
		if op.Op != opSet {
			continue
		}
		switch {
		case len(op.Path) == 2:
			if err := consider(i, op.Path[0], op.Path[1], op.Value); err != nil {
				return nil, false, err
			}
		case len(op.Path) == 1 && isJSONObject(op.Value):
			members, err := decodeMembers(op.Value)
			if err != nil {
				return nil, false, err
			}
			whole[i] = members
			for key, value := range members {
				if err := consider(i, op.Path[0], key, value); err != nil {
					return nil, false, err
				}
			}
		}
	}
	if len(candidates) == 0 {
		return untouched()
	}
	raw, err := json.Marshal(fragments)
	if err != nil {
		return nil, false, model.Fail(model.Invalid)
	}
	var sparse State
	if model.StrictJSON(raw, &sparse) != nil {
		return nil, false, model.Fail(model.Corrupt)
	}
	sparse.Installation = rules.Installation // the encoding of a State refuses a zero ID
	ids := make([]string, 0, len(rules.Deletions))
	for id := range rules.Deletions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		op := rules.Deletions[id]
		if op.Phase == model.DeletePhaseHeld {
			continue // a held deletion has not begun: nothing of it is erased
		}
		at := op.CompletedAt
		if at == 0 {
			at = op.RequestedAt
		}
		if _, _, err := eraseBooks(&sparse, op, at, stateErased); err != nil {
			return nil, false, err
		}
	}
	erasedRaw, err := json.Marshal(sparse)
	if err != nil {
		return nil, false, model.Fail(model.Invalid)
	}
	erased, err := decodeMembers(erasedRaw)
	if err != nil {
		return nil, false, err
	}
	records := map[string]map[string]json.RawMessage{}
	ops := slices.Clone(p.Ops)
	rewritten := map[int]bool{}
	for _, c := range candidates {
		after, ok := records[c.field]
		if !ok {
			if isJSONObject(erased[c.field]) {
				if after, err = decodeMembers(erased[c.field]); err != nil {
					return nil, false, err
				}
			}
			records[c.field] = after
		}
		v, present := after[c.key]
		if members, isWhole := whole[c.op]; isWhole {
			switch {
			case !present:
				delete(members, c.key)
				rewritten[c.op] = true
			case !sameJSON(v, members[c.key]):
				members[c.key] = v
				rewritten[c.op] = true
			}
			continue
		}
		switch {
		case !present:
			ops[c.op] = patchOp{Op: opDelete, Path: ops[c.op].Path}
			changed = true
		case !sameJSON(v, ops[c.op].Value):
			ops[c.op].Value = v
			changed = true
		}
	}
	for i := range rewritten {
		value, err := json.Marshal(whole[i])
		if err != nil {
			return nil, false, model.Fail(model.Invalid)
		}
		ops[i].Value = value
		changed = true
	}
	if !changed {
		return untouched()
	}
	// A voter that applies the rewritten command is behind and holds records the pass erased: its
	// bytes are not the ones the proposer read, so the rewritten patch no longer names them.
	p.Ops, p.Base = ops, ""
	replacement, err = json.Marshal(statePatchCommand{StatePatch: p})
	if err != nil {
		return nil, false, model.Fail(model.Invalid)
	}
	return replacement, true, nil
}

// clearPatchBase is the rewrite of a retained patch that follows a rewritten command in an erasure
// pass: the voter that applies the rewritten log reaches that patch holding record maps that the
// pass erased, which the proposer's bytes (the base) still had, so the patch no longer names them.
// A command that is not a patch, or has no base, is returned as it is.
func clearPatchBase(payload []byte) (replacement []byte, changed bool, err error) {
	cmd, derr := decodeControlCommand(payload)
	if derr != nil {
		return nil, false, model.Fail(model.Corrupt)
	}
	if cmd.patch == nil || cmd.patch.Base == "" {
		return payload, false, nil
	}
	p := *cmd.patch
	p.Base = ""
	replacement, err = json.Marshal(statePatchCommand{StatePatch: p})
	if err != nil {
		return nil, false, model.Fail(model.Invalid)
	}
	return replacement, true, nil
}
