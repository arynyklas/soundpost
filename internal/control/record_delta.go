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
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// The record delta op (D108).
//
// A job update rewrites the job's record and an issue commit rewrites the grouping issue's record: a job record carries the
// last 1,024 applied commands (about 40 KB at the 5,000 records/s gate) and a grouping issue carries its whole evidence ledger
// (125 KB and more), so a patch that writes the record whole carries all of it for the one command or the few occurrences that
// were new. Measured on the control leader, the records the sparse items of a round wrote were 3 KB per round in minute 1 and 165 KB
// in minute 20, and a round that carries a settlement command waited behind them (79 ms, then 121 ms).
//
// The op addresses [JobBooks|GroupingIssues, key] and says what changed in the record the voter holds:
//
//	set  the top-level members that are new or changed, whole
//	del  the members that are gone
//	arr  for an array member, the first cut rows dropped and the rows appended (the evidence ledgers only grow at the end, a
//	     job's command log drops its oldest row when it is full)
//	sum  the SHA-256 of the record the op leaves
//
// A voter splices the members into the bytes it holds (the members it does not name are carried over as they are, in their
// order; a new member is appended in name order), requires the digest, and stores the result: every voter, whatever it applied
// before, either leaves the very bytes the proposer's record has or refuses the command (Corrupt), where a plain set could not
// notice that a voter held other bytes. The proposer builds the op only when applying it to the record the round started from
// gives exactly the record the plans left (recordDeltaOp), and writes the record whole otherwise: a record that is small, a member
// that was new in the middle of the object, a change that is not smaller than the record.
//
// It is a wire format a release that does not know it stops applying, so it is proposed only when every member declared the
// compact admission protocol (compact_admission.go, Store.compactAdmission): the previous release interoperates with the
// whole-record sets. An erasure pass rewrites a retained command that carries it as the plain set of the record the control state
// holds (expandRecords), so that no erased row is retained in a delta.

// recordDeltaMin is the size below which a record is written whole: the delta's own framing is not worth it.
const recordDeltaMin = 2048

// recordRows is the change of one array member: its first Cut rows are dropped and Rows are appended.
type recordRows struct {
	Cut  int               `json:"cut,omitempty"`
	Rows []json.RawMessage `json:"rows"`
}

// objDelta says what changed in the members of one JSON object.
type objDelta struct {
	Set map[string]json.RawMessage `json:"set,omitempty"`
	Del []string                   `json:"del,omitempty"`
	Arr map[string]recordRows      `json:"arr,omitempty"`
	// Obj is, for an object member, what changed in its own members (the same delta, one level in).
	Obj map[string]objDelta `json:"obj,omitempty"`
}

// recordDelta is the value of a rec op.
type recordDelta struct {
	Sum string                     `json:"sum"`
	Set map[string]json.RawMessage `json:"set,omitempty"`
	Del []string                   `json:"del,omitempty"`
	Arr map[string]recordRows      `json:"arr,omitempty"`
	Obj map[string]objDelta        `json:"obj,omitempty"`
}

// recordMember is one top-level member of a JSON object, as the bytes it is written in.
type recordMember struct {
	name string
	raw  json.RawMessage
}

// splitRecord is the members of a JSON object in the order they are written; ok is false for anything that is not one object.
func splitRecord(raw []byte) (members []recordMember, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	for dec.More() {
		t, err := dec.Token()
		name, isName := t.(string)
		if err != nil || !isName {
			return nil, false
		}
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, false
		}
		members = append(members, recordMember{name, v})
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err == nil {
		return nil, false // bytes after the object
	}
	return members, true
}

// joinRecord is the compact object of members.
func joinRecord(members []recordMember) []byte {
	n := 2
	for _, m := range members {
		n += len(m.name) + len(m.raw) + 6
	}
	out := make([]byte, 0, n)
	out = append(out, '{')
	for i, m := range members {
		if i != 0 {
			out = append(out, ',')
		}
		name, _ := json.Marshal(m.name)
		out = append(out, name...)
		out = append(out, ':')
		out = append(out, m.raw...)
	}
	return append(out, '}')
}

// splitRows is the rows of a JSON array; ok is false for anything else (null is an array of no rows that is not an empty one).
func splitRows(raw []byte) (rows []json.RawMessage, ok bool) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	if json.Unmarshal(raw, &rows) != nil {
		return nil, false
	}
	return rows, true
}

func joinRows(rows []json.RawMessage) []byte {
	n := 2
	for _, r := range rows {
		n += len(r) + 1
	}
	out := make([]byte, 0, n)
	out = append(out, '[')
	for i, r := range rows {
		if i != 0 {
			out = append(out, ',')
		}
		out = append(out, r...)
	}
	return append(out, ']')
}

func recordSum(record []byte) string {
	sum := sha256.Sum256(record)
	return hex.EncodeToString(sum[:])
}

// compactPiece reports whether raw is one valid JSON value written compactly: what a record's members are.
func compactPiece(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	var out bytes.Buffer
	out.Grow(len(raw))
	return json.Compact(&out, raw) == nil && bytes.Equal(out.Bytes(), raw)
}

// applyRecordDelta is the record that d takes the compact record old to. The members of old that d does not name keep their bytes
// and their place; a refusal (an array that is not one, a cut beyond its rows, a digest that is not the result's) is Corrupt.
func applyRecordDelta(old []byte, d recordDelta) ([]byte, error) {
	out, err := applyObjectDelta(old, objDelta{Set: d.Set, Del: d.Del, Arr: d.Arr, Obj: d.Obj}, false, 0)
	if err != nil {
		return nil, err
	}
	if recordSum(out) != d.Sum {
		return nil, model.Fail(model.Corrupt)
	}
	return out, nil
}

// maxObjectDepth bounds how deep a delta goes into the object members of a record.
const maxObjectDepth = 3

// applyObjectDelta is the compact object that d takes the compact object old to. A member that is new is appended at the end of the
// record (in name order) and into its place in name order in an object inside it (nested: the maps of a record are written with
// their keys in order); the proposer proves the result is the bytes it holds, so an order the rule does not give is not sent.
func applyObjectDelta(old []byte, d objDelta, nested bool, depth int) ([]byte, error) {
	bad := model.Fail(model.Corrupt)
	if depth > maxObjectDepth {
		return nil, bad
	}
	members, ok := splitRecord(old)
	if !ok {
		return nil, bad
	}
	at := make(map[string]int, len(members))
	for i, m := range members {
		at[m.name] = i
	}
	names := make([]string, 0, len(d.Set))
	for name := range d.Set {
		names = append(names, name)
	}
	sort.Strings(names)
	var added []recordMember
	for _, name := range names {
		raw := d.Set[name]
		if !compactPiece(raw) {
			return nil, bad
		}
		if i, held := at[name]; held {
			members[i].raw = raw
		} else {
			added = append(added, recordMember{name, raw})
		}
	}
	names = names[:0]
	for name := range d.Arr {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		i, held := at[name]
		if _, set := d.Set[name]; !held || set {
			return nil, bad
		}
		rows, ok := splitRows(members[i].raw)
		change := d.Arr[name]
		if !ok || change.Cut < 0 || change.Cut > len(rows) {
			return nil, bad
		}
		for _, r := range change.Rows {
			if !compactPiece(r) {
				return nil, bad
			}
		}
		next := make([]json.RawMessage, 0, len(rows)-change.Cut+len(change.Rows))
		next = append(next, rows[change.Cut:]...)
		next = append(next, change.Rows...)
		members[i].raw = joinRows(next)
	}
	names = names[:0]
	for name := range d.Obj {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		i, held := at[name]
		_, set := d.Set[name]
		_, rows := d.Arr[name]
		if !held || set || rows {
			return nil, bad
		}
		next, err := applyObjectDelta(members[i].raw, d.Obj[name], true, depth+1)
		if err != nil {
			return nil, err
		}
		members[i].raw = next
	}
	if len(d.Del) != 0 {
		gone := make(map[int]bool, len(d.Del))
		for _, name := range d.Del {
			i, held := at[name]
			if !held {
				return nil, bad
			}
			gone[i] = true
		}
		kept := members[:0]
		for i, m := range members {
			if !gone[i] {
				kept = append(kept, m)
			}
		}
		members = kept
	}
	if nested {
		for _, m := range added {
			at := len(members)
			for j := range members {
				if members[j].name > m.name {
					at = j
					break
				}
			}
			members = slices.Insert(members, at, m)
		}
		return joinRecord(members), nil
	}
	return joinRecord(append(members, added...)), nil
}

// objectDelta is what takes the members of the object before to those of the object after: what is new or changed whole, what is
// gone, the rows an array member gained, and, for an object member (the maps of a record: occurrences, runs, attempts), the entries
// of it that changed, when that is under half of the member. false when either is not one object.
func objectDelta(before, after []byte, depth int) (objDelta, bool) {
	old, ok1 := splitRecord(before)
	next, ok2 := splitRecord(after)
	if !ok1 || !ok2 {
		return objDelta{}, false
	}
	held := make(map[string]recordMember, len(old))
	for _, m := range old {
		held[m.name] = m
	}
	var d objDelta
	now := make(map[string]bool, len(next))
	for _, m := range next {
		now[m.name] = true
		was, had := held[m.name]
		if had && bytes.Equal(was.raw, m.raw) {
			continue
		}
		if had {
			if rows, ok := rowsDelta(was.raw, m.raw); ok {
				if d.Arr == nil {
					d.Arr = map[string]recordRows{}
				}
				d.Arr[m.name] = rows
				continue
			}
			if depth < maxObjectDepth && len(m.raw) >= recordDeltaMin && m.raw[0] == '{' && was.raw[0] == '{' {
				if sub, ok := objectDelta(was.raw, m.raw, depth+1); ok {
					if v, err := json.Marshal(sub); err == nil && 2*len(v) < len(m.raw) {
						if d.Obj == nil {
							d.Obj = map[string]objDelta{}
						}
						d.Obj[m.name] = sub
						continue
					}
				}
			}
		}
		if d.Set == nil {
			d.Set = map[string]json.RawMessage{}
		}
		d.Set[m.name] = m.raw
	}
	for _, m := range old {
		if !now[m.name] {
			d.Del = append(d.Del, m.name)
		}
	}
	return d, true
}

// rowsDelta is the change that takes the array before to the array after, when after is before without its first rows and with rows
// appended (a pure append is the case of no cut).
func rowsDelta(before, after []byte) (recordRows, bool) {
	be, ok1 := splitRows(before)
	af, ok2 := splitRows(after)
	if !ok1 || !ok2 {
		return recordRows{}, false
	}
	for cut := 0; cut <= len(be); cut++ {
		kept := len(be) - cut
		if kept > len(af) || cut != 0 && kept != 0 && !bytes.Equal(be[cut], af[0]) {
			continue
		}
		if slices.EqualFunc(be[cut:], af[:kept], func(a, b json.RawMessage) bool { return bytes.Equal(a, b) }) {
			return recordRows{Cut: cut, Rows: af[kept:]}, true
		}
	}
	return recordRows{}, false
}

// recordDeltaOp is the rec op that takes the record before to the record after (both compact), at path, or false when the record is
// to be written whole: it is small, it has no members in common with what the delta can say, the delta does not reproduce it
// byte for byte, or it is not at most half of it.
func recordDeltaOp(path []string, before, after []byte) (patchOp, bool) {
	if len(after) < recordDeltaMin || len(before) == 0 {
		return patchOp{}, false
	}
	od, ok := objectDelta(before, after, 0)
	if !ok {
		return patchOp{}, false
	}
	d := recordDelta{Sum: recordSum(after), Set: od.Set, Del: od.Del, Arr: od.Arr, Obj: od.Obj}
	value, err := json.Marshal(d)
	if err != nil || 2*len(value) > len(after) {
		return patchOp{}, false
	}
	// The voters apply what the wire carries: the value as it decodes (json.Marshal escapes what a RawMessage holds beyond what
	// the record's own encoder escaped), not the members as the proposer holds them.
	var wire recordDelta
	if decodeValue(value, &wire) != nil {
		return patchOp{}, false
	}
	if got, err := applyRecordDelta(before, wire); err != nil || !bytes.Equal(got, after) {
		return patchOp{}, false
	}
	return patchOp{Op: opRecord, Path: slices.Clone(path), Value: value}, true
}

// record applies a rec op: the record the voter holds becomes the one the delta takes it to.
func (a *opApplier) record(op patchOp) error {
	var d recordDelta
	if decodeValue(op.Value, &d) != nil {
		return model.Fail(model.Corrupt)
	}
	table := recordTable(op.Path[0])
	old := a.l.t[table].Get([]byte(op.Path[1]))
	if old == nil {
		return model.Fail(model.Corrupt)
	}
	next, err := applyRecordDelta(old, d)
	if err != nil {
		return err
	}
	return a.l.put(table, []byte(op.Path[1]), next)
}

// verifyRecord is verifyOp of a rec op: the ledger holds the record the delta leaves, the digest it names.
func (l *ledgerTx) verifyRecord(op patchOp) error {
	var d recordDelta
	if decodeValue(op.Value, &d) != nil {
		return model.Fail(model.Corrupt)
	}
	got := l.t[recordTable(op.Path[0])].Get([]byte(op.Path[1]))
	if got == nil || recordSum(got) != d.Sum {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// expandRecords is ops with every rec op of a record that covers says is covered written as the plain op for the record that the
// committed state holds under its key (a set, or a delete when the state holds none), and whether it wrote any. An erasure pass
// rewrites the retained commands of the group with it: a delta names rows that the pass may have to erase, and a voter that replays
// the rewritten log reaches the committed record by every one of the ops, where a delta would add its rows to a record that already
// holds them. covers depends only on the key and the deletions, so every retained command of a record is treated alike.
func expandRecords(ops []patchOp, covers func(key string) bool, committed func(member, key string) (json.RawMessage, bool, error)) (out []patchOp, expanded bool, err error) {
	if !slices.ContainsFunc(ops, func(op patchOp) bool { return op.Op == opRecord && covers(op.Path[1]) }) {
		return ops, false, nil
	}
	out = make([]patchOp, len(ops))
	for i, op := range ops {
		out[i] = op
		if op.Op != opRecord || !covers(op.Path[1]) {
			continue
		}
		value, held, err := committed(op.Path[0], op.Path[1])
		if err != nil {
			return nil, false, err
		}
		if held {
			out[i] = patchOp{Op: opSet, Path: op.Path, Value: value}
		} else {
			out[i] = patchOp{Op: opDelete, Path: op.Path}
		}
	}
	return out, true, nil
}

// keyCoveredByDeletion is the covers function of an erasure pass: whether a finished or begun deletion of rules covers the project a
// job or issue key names (org:project:name). A key that does not parse is covered: it is rewritten, which is always correct.
func keyCoveredByDeletion(rules State, key string) bool {
	parts := strings.SplitN(key, ":", 3)
	if len(parts) < 3 {
		return true
	}
	org, e1 := model.ParseID(parts[0])
	project, e2 := model.ParseID(parts[1])
	if e1 != nil || e2 != nil {
		return true
	}
	for _, op := range rules.Deletions {
		if op.Phase != model.DeletePhaseHeld && op.Predicate.CoversProject(org, project) {
			return true
		}
	}
	return false
}
