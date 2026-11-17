// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The state patch (state_patch.go) as pure functions: what the diff of two states is, what applying
// it gives, which payloads are not patches.

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// mutateState changes a state in one of the ways a transition does: a record of some map is added,
// replaced or dropped, a map appears or empties, a scalar moves, the audit log grows or its oldest
// rows go, a row in the middle of it changes.
func mutateState(r *rand.Rand, st *State) {
	key := func(prefix string) string { return fmt.Sprintf("%s-%d", prefix, r.IntN(12)) }
	id := func() (out model.ID) { // drawn from r, so two runs of one seed write the same ids
		for i := range out {
			out[i] = byte(r.IntN(256))
		}
		return out
	}
	raw := func() json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"n":%d,"s":"v%d","l":[%d,%d]}`, r.IntN(1000), r.IntN(1000), r.IntN(9), r.IntN(9)))
	}
	switch r.IntN(20) {
	case 0:
		st.Revision++
	case 1:
		st.AuthorityRevision = st.Revision
	case 2:
		st.DataInitialized = !st.DataInitialized
	case 3:
		if st.Users == nil {
			st.Users = map[string]model.ControlUser{}
		}
		st.Users[key("user")] = model.ControlUser{ID: id(), Email: fmt.Sprintf("u%d@example.test", r.IntN(99)), Recovery: []string{"a", fmt.Sprint(r.IntN(9))}}
	case 4:
		delete(st.Users, key("user"))
	case 5:
		if st.Sessions == nil {
			st.Sessions = map[string]model.ControlSession{}
		}
		st.Sessions[key("session")] = model.ControlSession{User: id(), CSRF: "c", Expires: r.Int64N(1 << 40)}
	case 6:
		delete(st.Sessions, key("session"))
	case 7:
		if st.Orgs == nil {
			st.Orgs = map[string]model.ControlOrg{}
		}
		o := st.Orgs[key("org")]
		o.ID = model.ID{3}
		if o.Members == nil {
			o.Members = map[string]bool{}
		}
		o.Members[key("member")] = r.IntN(2) == 0
		st.Orgs[key("org")] = o
	case 8:
		o, ok := st.Orgs[key("org")]
		if !ok {
			return
		}
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		o.Settings[key("setting")] = raw()
		o.Epoch++
		st.Orgs[key("org")] = o
	case 9:
		o := st.Orgs[key("org")]
		o.ID = model.ID{3}
		o.Settings = nil
		o.Grants = map[string][]string{key("g"): {"a", "b"}}
		if len(st.Orgs) > 0 {
			st.Orgs[key("org")] = o
		}
	case 10:
		if st.IncidentBooks == nil {
			st.IncidentBooks = map[string]json.RawMessage{}
		}
		st.IncidentBooks[key("book")] = raw()
	case 11:
		delete(st.IncidentBooks, key("book"))
		if len(st.IncidentBooks) == 0 {
			st.IncidentBooks = nil
		}
	case 12:
		if st.Commands == nil {
			st.Commands = map[string]model.ControlResult{}
		}
		st.Commands[key("cmd")] = model.ControlResult{Revision: st.Revision, Cursor: model.Cursor{Group: model.ID{1}, Index: 1}}
	case 13:
		st.Audits = append(st.Audits, model.ControlAudit{ID: id(), Principal: model.ID{1}, Action: fmt.Sprintf("a%d", r.IntN(5)), Time: r.Int64N(1 << 40), Outcome: model.AuditAllowed})
	case 14:
		if n := r.IntN(len(st.Audits) + 1); n > 0 {
			st.Audits = append([]model.ControlAudit(nil), st.Audits[n:]...)
		}
	case 15:
		if len(st.Audits) > 0 {
			st.Audits[r.IntN(len(st.Audits))].Reason = fmt.Sprintf("edited %d", r.IntN(99))
		}
	case 16:
		st.RevisionClock = append(st.RevisionClock, model.RevisionStamp{Revision: st.Revision, At: int64(r.IntN(1 << 30))})
	case 17:
		if len(st.RevisionClock) > 2 {
			st.RevisionClock = append([]model.RevisionStamp(nil), st.RevisionClock[len(st.RevisionClock)-2:]...)
		}
	case 18:
		st.Settlement = &model.Settlement{}
	default:
		st.Settlement = nil
		st.BootstrapHash = fmt.Sprintf("h%d", r.IntN(5))
	}
}

// Applying the patch of two states to the first gives the second, whatever the transition: the
// state a voter ends in is the state the proposer meant, byte for byte once encoded.
func TestStatePatchOfTwoStatesAppliesToTheSecond(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 5))
	st := State{Installation: model.ID{5}, Revision: 1}
	for step := range 600 {
		oldRaw := mustMarshal(t, st)
		before := st
		for range 1 + r.IntN(4) {
			mutateState(r, &st)
		}
		st.Revision = before.Revision + 1 // every command steps the revision
		newRaw := mustMarshal(t, st)
		ops, err := diffStates(oldRaw, newRaw)
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		cmd := statePatch{Installation: st.Installation, Expected: before.Revision, Keys: map[string][]byte{}, Ops: ops}
		payload := mustMarshal(t, statePatchCommand{StatePatch: cmd})
		decoded, err := decodeControlCommand(payload)
		if err != nil || decoded.patch == nil {
			t.Fatalf("step %d: the patch of two states does not decode as a patch: %v\n%s", step, err, payload)
		}
		applied, err := applyPatchRaw(oldRaw, decoded.patch.Ops)
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		var got State
		if err := model.StrictJSON(applied, &got); err != nil {
			t.Fatalf("step %d: the patched state does not decode: %v", step, err)
		}
		if !bytes.Equal(mustMarshal(t, got), newRaw) {
			t.Fatalf("step %d: the patched state differs from the state the proposer meant:\nops %s\nwant %s\ngot  %s", step, mustMarshal(t, cmd.Ops), newRaw, mustMarshal(t, got))
		}
		if err := verifyPatchRaw(newRaw, decoded.patch.Ops); err != nil {
			t.Fatalf("step %d: the state the patch leaves does not verify against it: %v", step, err)
		}
	}
}

// A patch is as large as its change: one record out of thousands, one audit row out of the log.
func TestStatePatchIsAsLargeAsTheChange(t *testing.T) {
	st := State{Installation: model.ID{6}, Revision: 7, Orgs: map[string]model.ControlOrg{}, Commands: map[string]model.ControlResult{}, IncidentBooks: map[string]json.RawMessage{}}
	for i := range 40 {
		o := model.ControlOrg{ID: model.ID{3}, Members: map[string]bool{}, Settings: map[string]json.RawMessage{}}
		for j := range 200 {
			o.Members[fmt.Sprintf("m%d", j)] = true
			o.Settings[fmt.Sprintf("s%d", j)] = json.RawMessage(`{"enabled":true,"schedule":"*/5 * * * *","version":3}`)
		}
		st.Orgs[fmt.Sprintf("org-%d", i)] = o
	}
	for i := range 5000 {
		st.Commands[fmt.Sprintf("cmd-%d", i)] = model.ControlResult{Revision: model.Revision(i), Cursor: model.Cursor{Group: model.ID{1}, Index: 1}}
		st.IncidentBooks[fmt.Sprintf("o:p:i%d", i)] = json.RawMessage(fmt.Sprintf(`{"n":%d}`, i))
		st.Audits = append(st.Audits, model.ControlAudit{ID: model.NewID(), Principal: model.ID{1}, Action: "export.chunk", Outcome: model.AuditAllowed})
	}
	oldRaw := mustMarshal(t, st)
	next := st
	next.Revision++
	next.Orgs = map[string]model.ControlOrg{}
	for k, v := range st.Orgs {
		next.Orgs[k] = v
	}
	o := next.Orgs["org-7"]
	o.Settings = map[string]json.RawMessage{}
	for k, v := range st.Orgs["org-7"].Settings {
		o.Settings[k] = v
	}
	o.Settings["s3"] = json.RawMessage(`{"enabled":false}`)
	next.Orgs["org-7"] = o
	next.Audits = append(append([]model.ControlAudit(nil), st.Audits...), model.ControlAudit{ID: model.NewID(), Principal: model.ID{1}, Action: "export.chunk", Outcome: model.AuditAllowed})
	next.IncidentBooks = map[string]json.RawMessage{"o:p:i1": json.RawMessage(`{"n":1}`)}
	for k, v := range st.IncidentBooks {
		next.IncidentBooks[k] = v
	}
	next.IncidentBooks["o:p:new"] = json.RawMessage(`{"n":-1}`)
	delete(next.IncidentBooks, "o:p:i9")
	payload, err := patchCommand(oldRaw, st.Revision, &next, map[string][]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > 1500 || len(oldRaw) < 200_000 {
		t.Fatalf("a patch of five changes to a %d byte state is %d bytes", len(oldRaw), len(payload))
	}
	var c statePatchCommand
	if err := model.StrictJSON(payload, &c); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, op := range c.StatePatch.Ops {
		paths[strings.Join(op.Path, "/")] = op.Op
	}
	for path, op := range map[string]string{"Orgs/org-7/Settings/s3": opSet, "Audits": opArray, "IncidentBooks/o:p:new": opSet, "IncidentBooks/o:p:i9": opDelete, "Revision": opSet} {
		if paths[path] != op {
			t.Errorf("no %s of %s in %v", op, path, paths)
		}
	}
	if len(paths) != 5 {
		t.Errorf("the patch has %d operations, want the 5 changes: %v", len(paths), paths)
	}
}

// The revision clock is a log that grows at its end like the audit log: a minute's stamp is one
// appended row, and the pruning of the oldest stamps is a cut, never the whole array. (The member
// is revision_clock in JSON; the diff and the decoder read the JSON name.)
func TestStatePatchChangesTheRevisionClockRowWise(t *testing.T) {
	st := State{Installation: model.ID{6}, Revision: 7}
	for i := range 1400 {
		st.RevisionClock = append(st.RevisionClock, model.RevisionStamp{Revision: model.Revision(i + 1), At: int64(i) * 60_000_000_000})
	}
	oldRaw := mustMarshal(t, st)
	for name, clock := range map[string][]model.RevisionStamp{
		"a stamp appended":             append(slices.Clone(st.RevisionClock), model.RevisionStamp{Revision: 8, At: 1 << 50}),
		"the oldest cut, one appended": append(slices.Clone(st.RevisionClock[3:]), model.RevisionStamp{Revision: 8, At: 1 << 50}),
	} {
		next := st
		next.Revision++
		next.RevisionClock = clock
		payload, err := patchCommand(oldRaw, st.Revision, &next, map[string][]byte{})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeControlCommand(payload)
		if err != nil || decoded.patch == nil {
			t.Fatalf("%s: %v", name, err)
		}
		var clockOps []patchOp
		for _, op := range decoded.patch.Ops {
			if len(op.Path) == 1 && op.Path[0] == "revision_clock" {
				clockOps = append(clockOps, op)
			}
		}
		if len(clockOps) != 1 || clockOps[0].Op != opArray {
			t.Fatalf("%s: the clock is not changed by one row operation: %+v", name, decoded.patch.Ops)
		}
		if len(payload) > 600 {
			t.Errorf("%s: a patch of one stamp of a %d byte state is %d bytes", name, len(oldRaw), len(payload))
		}
		applied, err := applyPatchRaw(oldRaw, decoded.patch.Ops)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got State
		if err := json.Unmarshal(applied, &got); err != nil || !slices.Equal(got.RevisionClock, clock) {
			t.Fatalf("%s: the patch left a clock of %d stamps (%v), want %d", name, len(got.RevisionClock), err, len(clock))
		}
	}
}

// What is not a patch is refused at decode, before any state is read.
func TestStatePatchDecoderIsStrict(t *testing.T) {
	id := model.ID{9}
	patch := func(ops string) string {
		return fmt.Sprintf(`{"state_patch":{"installation":"%s","expected":"3","keys":{},"ops":%s}}`, id, ops)
	}
	good := patch(`[{"op":"set","p":["Revision"],"v":4},{"op":"del","p":["IncidentBooks","a:b:c"]},{"op":"array","p":["Audits"],"cut":1,"v":[{"ID":"x"}]},{"op":"set","p":["Orgs","o","Settings","k"],"v":{"a":1}}]`)
	if c, err := decodeControlCommand([]byte(good)); err != nil || c.patch == nil || c.replacement != nil || c.delta != nil || len(c.patch.Ops) != 4 {
		t.Fatalf("a patch did not decode as a patch: %v", err)
	}
	for name, payload := range map[string]string{
		"no operation":             patch(`[]`),
		"unknown operation":        patch(`[{"op":"move","p":["Revision"],"v":4}]`),
		"empty path":               patch(`[{"op":"set","p":[],"v":4}]`),
		"empty first segment":      patch(`[{"op":"set","p":[""],"v":4}]`),
		"path too deep":            patch(`[{"op":"set","p":["IncidentBooks","a","b"],"v":4}]`),
		"org path too deep":        patch(`[{"op":"set","p":["Orgs","o","Settings","k","x"],"v":4}]`),
		"set without a value":      patch(`[{"op":"set","p":["Revision"]}]`),
		"set with a cut":           patch(`[{"op":"set","p":["Revision"],"v":4,"cut":1}]`),
		"delete with a value":      patch(`[{"op":"del","p":["Revision"],"v":4}]`),
		"array of another log":     patch(`[{"op":"array","p":["Users"],"cut":0,"v":[1]}]`),
		"array below a member":     patch(`[{"op":"array","p":["Audits","x"],"cut":0,"v":[1]}]`),
		"array value not an array": patch(`[{"op":"array","p":["Audits"],"cut":0,"v":{"a":1}}]`),
		"array that changes none":  patch(`[{"op":"array","p":["Audits"],"cut":0,"v":[]}]`),
		"negative cut":             patch(`[{"op":"array","p":["Audits"],"cut":-1,"v":[1]}]`),
		"path addressed twice":     patch(`[{"op":"set","p":["Revision"],"v":4},{"op":"set","p":["Revision"],"v":5}]`),
		"a path under a path":      patch(`[{"op":"set","p":["Orgs","o"],"v":{}},{"op":"set","p":["Orgs","o","Settings"],"v":{}}]`),
		"a path over a path":       patch(`[{"op":"set","p":["Orgs","o","Settings"],"v":{}},{"op":"del","p":["Orgs","o"]}]`),
		"unknown member of an op":  patch(`[{"op":"set","p":["Revision"],"v":4,"x":1}]`),
		"unknown member":           strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"keys":{}`, `"keys":{},"extra":1`, 1),
		"expected at the maximum":  strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"expected":"3"`, `"expected":"18446744073709551615"`, 1),
		"a replacement member":     strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"keys":{}`, `"keys":{},"state":{}`, 1),
		"trailing data":            patch(`[{"op":"set","p":["Revision"],"v":4}]`) + `{}`,
		"patch not first member":   `{"expected":"3","state_patch":{}}`,
		"base not hex":             strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"keys":{}`, `"keys":{},"base":"zz"`, 1),
		"base too short":           strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"keys":{}`, `"keys":{},"base":"abcd"`, 1),
		"base in capitals":         strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"keys":{}`, `"keys":{},"base":"`+strings.Repeat("AB", 32)+`"`, 1),
		"base not a string":        strings.Replace(patch(`[{"op":"set","p":["Revision"],"v":4}]`), `"keys":{}`, `"keys":{},"base":7`, 1),
	} {
		if c, err := decodeControlCommand([]byte(payload)); err == nil && c.patch != nil {
			t.Errorf("%s: decoded as a patch of %d operations, want a refusal", name, len(c.patch.Ops))
		}
	}
}

// The patch does not apply to a state that is not the one it was made from: an array it cuts beyond
// its length, a record's parent that is gone, an object where a scalar is.
func TestStatePatchRefusesAStateItDoesNotFit(t *testing.T) {
	st := State{Installation: model.ID{7}, Revision: 1, Audits: []model.ControlAudit{{ID: model.ID{2}, Principal: model.ID{1}, Action: "a"}}}
	raw := mustMarshal(t, st)
	for name, ops := range map[string][]patchOp{
		"cut beyond the log":      {{Op: opArray, Path: []string{"Audits"}, Cut: 2, Value: json.RawMessage(`[]`)}},
		"record of a missing org": {{Op: opSet, Path: []string{"Orgs", "gone", "Settings", "k"}, Value: json.RawMessage(`{}`)}},
		"array of a missing log":  {{Op: opArray, Path: []string{"revision_clock"}, Cut: 0, Value: json.RawMessage(`[{"revision":1}]`)}},
	} {
		if _, err := applyPatchRaw(raw, ops); err == nil {
			t.Errorf("%s: applied", name)
		}
	}
	// A delete of what is not there is nothing, not an error (a redacted patch leaves one behind).
	out, err := applyPatchRaw(raw, []patchOp{{Op: opDelete, Path: []string{"IncidentBooks", "gone"}}})
	if err != nil {
		t.Fatalf("a delete of an absent record: %v", err)
	}
	if !bytes.Equal(out, raw) {
		var m map[string]json.RawMessage
		if json.Unmarshal(out, &m) != nil || len(m) == 0 {
			t.Fatalf("a delete of an absent record changed the state: %s", out)
		}
	}
}
