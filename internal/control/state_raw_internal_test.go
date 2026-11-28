// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The byte-level patch (state_raw.go) against the path it replaces: decode the state, apply the
// patch, decode strictly, encode. Every voter must hold the bytes the encoder writes, so the two have
// to agree to the byte on every patch the splice accepts, and the splice has to refuse (ok=false)
// the ones it cannot prove it does exactly.

// decodeEncodePatch is the state encoding a patch leaves by the decode/encode path (what Apply did
// before the splice, patchedState without the revision checks).
func decodeEncodePatch(oldRaw []byte, ops []patchOp) ([]byte, bool) {
	patched, err := applyPatchRaw(oldRaw, ops, false)
	if err != nil {
		return nil, false
	}
	var next State
	if model.StrictJSON(patched, &next) != nil {
		return nil, false
	}
	out, err := json.Marshal(next)
	return out, err == nil
}

// moreMutations are the changes mutateState does not draw: members the encoder omits when empty
// appearing and disappearing at the root, the dedicated book maps, an organization member that is
// deleted down to an empty map.
func moreMutations(r *rand.Rand, st *State) {
	raw := func() json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"v":%d,"h":"<a&b>\u2028é%d"}`, r.IntN(100), r.IntN(9)))
	}
	key := func() string { return fmt.Sprintf("k-%d", r.IntN(6)) }
	switch r.IntN(16) {
	case 0:
		if st.SavedViewBooks == nil {
			st.SavedViewBooks = map[string]json.RawMessage{}
		}
		st.SavedViewBooks[key()] = raw()
	case 1:
		st.SavedViewBooks = nil
	case 2:
		if st.RuleDefinitions == nil {
			st.RuleDefinitions = map[string]json.RawMessage{}
		}
		st.RuleDefinitions[key()] = raw()
	case 3:
		st.RuleDefinitions = nil
		st.JobDefinitions = nil
	case 4:
		if st.JobDefinitions == nil {
			st.JobDefinitions = map[string]json.RawMessage{}
		}
		st.JobDefinitions[key()] = raw()
	case 5:
		st.AuthorityRevision = 0
	case 6:
		st.AuthorityRevision = st.Revision + 1
	case 7:
		for name, o := range st.Orgs {
			for k := range o.Settings {
				delete(o.Settings, k)
			}
			st.Orgs[name] = o
			break
		}
	case 8:
		for name, o := range st.Orgs {
			delete(o.Members, key())
			o.Name = fmt.Sprintf("name-%d", r.IntN(50))
			st.Orgs[name] = o
			break
		}
	case 9:
		if st.RuleBooks == nil {
			st.RuleBooks = map[string]json.RawMessage{}
		}
		st.RuleBooks[fmt.Sprintf("o:p:%d", r.IntN(30))] = raw()
	case 10:
		st.BearerHashKey = fmt.Sprintf("<k&%d>", r.IntN(5)) // characters the encoder escapes
	case 11, 12, 13:
		// Erasing audits are rows that must not be dropped unseen: they are added here and cut by mutateState's
		// trimming of the log, and the effects say how many were added minus dropped.
		st.Audits = append(st.Audits, model.ControlAudit{ID: model.ID{byte(r.IntN(256)), 4}, Principal: model.ID{1}, Action: controlErasedAction, Time: r.Int64N(1 << 30), Outcome: model.AuditAllowed})
	default:
		if r.IntN(8) == 0 {
			st.Audits = nil
		}
	}
}

func TestRawPatchEqualsDecodeEncode(t *testing.T) {
	r := rand.New(rand.NewPCG(11, 13))
	st := State{Installation: model.ID{5}, Revision: 1}
	var spliced, refused int
	for step := range 1500 {
		oldRaw := mustMarshal(t, st)
		for range 1 + r.IntN(4) {
			if r.IntN(3) == 0 {
				moreMutations(r, &st)
			} else {
				mutateState(r, &st)
			}
		}
		st.Revision++
		newRaw := mustMarshal(t, st)
		ops, err := diffStates(oldRaw, newRaw)
		if err != nil {
			t.Fatal(err)
		}
		if len(ops) == 0 {
			continue
		}
		want, ok := decodeEncodePatch(oldRaw, ops)
		if !ok {
			t.Fatalf("step %d: the decode/encode path refuses the proposer's own patch", step)
		}
		if !bytes.Equal(want, newRaw) {
			t.Fatalf("step %d: the decode/encode path does not leave the proposer's state", step)
		}
		root := scanStateRoot(oldRaw)
		if !root.ok {
			t.Fatalf("step %d: the encoding of a State does not scan", step)
		}
		got, eff, ok := patchRaw(oldRaw, root, ops)
		if !ok {
			refused++
			continue
		}
		spliced++
		if !bytes.Equal(got, want) {
			t.Fatalf("step %d: the splice leaves other bytes than the decode/encode path\n got %.300s\nwant %.300s", step, got, want)
		}
		if !eff.revisionSet || eff.revision != st.Revision {
			t.Fatalf("step %d: effects say revision %d (set %v), the state is at %d", step, eff.revision, eff.revisionSet, st.Revision)
		}
		if eff.settled != (st.Settlement != nil) {
			t.Fatalf("step %d: effects say settled=%v, the state's settlement is %v", step, eff.settled, st.Settlement)
		}
		var oldState State
		if err := json.Unmarshal(oldRaw, &oldState); err != nil {
			t.Fatal(err)
		}
		if grew := erasureCount(st.Audits) - erasureCount(oldState.Audits); eff.erasures != grew {
			t.Fatalf("step %d: effects say %d erasing audits added, the states differ by %d", step, eff.erasures, grew)
		}
	}
	t.Logf("%d patches spliced, %d refused", spliced, refused)
	if spliced < 1000 || refused > spliced/10 {
		t.Fatalf("the splice took %d patches and refused %d: the test proves little", spliced, refused)
	}
}

// The splice refuses what it cannot prove it does exactly, and says so rather than leaving other
// bytes: the caller then decodes the state and applies the patch the old way, errors included.
func TestRawPatchRefusesWhatItCannotDoExactly(t *testing.T) {
	st := State{Installation: model.ID{5}, Revision: 7, BootstrapHash: "h", Users: map[string]model.ControlUser{"u1": {ID: model.ID{1}, Email: "a@example.test"}}, Audits: []model.ControlAudit{}}
	st.Orgs = map[string]model.ControlOrg{"o1": {ID: model.ID{3}, Settings: map[string]json.RawMessage{"s": json.RawMessage(`{"a":1}`)}}}
	raw := mustMarshal(t, st)
	root := scanStateRoot(raw)
	if !root.ok {
		t.Fatal("the encoding of a State does not scan")
	}
	set := func(v string, path ...string) patchOp {
		return patchOp{Op: opSet, Path: path, Value: json.RawMessage(v)}
	}
	del := func(path ...string) patchOp { return patchOp{Op: opDelete, Path: path} }
	rev := set(`"8"`, "Revision")
	for _, c := range []struct {
		name string
		ops  []patchOp
		ok   bool
	}{
		{"a record set", []patchOp{rev, set(`{"ID":"`+model.ID{2}.String()+`","Email":"b@example.test"}`, "Users", "u2")}, true},
		{"a member of the State that does not exist", []patchOp{rev, set(`1`, "NoSuchMember")}, false},
		{"a field set to an omitted zero", []patchOp{rev, set(`"0"`, "authority_revision")}, false},
		{"a non-omitted field deleted", []patchOp{rev, del("BootstrapHash")}, false},
		{"a record of the wrong shape", []patchOp{rev, set(`{"Email":5}`, "Users", "u2")}, false},
		{"an unknown member of a record", []patchOp{rev, set(`{"Nope":5}`, "Users", "u2")}, false},
		{"a record that is not what the encoder writes back", []patchOp{rev, set(`{"Email":"b@example.test", "ID":"`+model.ID{2}.String()+`"}`, "Users", "u2")}, true},
		{"a name the encoder would escape", []patchOp{rev, set(`{"ID":"`+model.ID{2}.String()+`"}`, "Users", "u\"2")}, false},
		{"the installation", []patchOp{rev, set(`"`+model.ID{6}.String()+`"`, "Installation")}, false},
		{"an edit below a member that is not there", []patchOp{rev, set(`{"a":1}`, "Orgs", "o9", "Settings", "x")}, false},
		{"a delete of what is not there", []patchOp{rev, del("Users", "nobody")}, true},
		{"an array op on an array that is empty", []patchOp{rev, {Op: opArray, Path: []string{"Audits"}, Value: json.RawMessage(`[]`), Cut: 1}}, false},
	} {
		got, _, ok := patchRaw(raw, root, c.ops)
		if ok != c.ok {
			t.Fatalf("%s: splice ok=%v, want %v", c.name, ok, c.ok)
		}
		if ok {
			want, wantOK := decodeEncodePatch(raw, c.ops)
			if !wantOK || !bytes.Equal(got, want) {
				t.Fatalf("%s: the splice left %.200s, the decode/encode path %.200s (ok %v)", c.name, got, want, wantOK)
			}
		}
	}
	// A state that is not the compact encoding of a State is not spliced at all.
	var spaced bytes.Buffer
	if err := json.Indent(&spaced, raw, "", " "); err != nil {
		t.Fatal(err)
	}
	if scanStateRoot(spaced.Bytes()).ok {
		t.Fatal("an indented state was scanned as the encoding of a State")
	}
	if scanStateRoot([]byte(`{"Installation":"x"}`)).ok || scanStateRoot([]byte(`null`)).ok || scanStateRoot(nil).ok {
		t.Fatal("a document that is not a state was scanned as one")
	}
}

// A map that has a key written with an escape is the encoder's, but its order is not a byte order:
// the splice refuses to place a member next to it.
func TestRawPatchRefusesAnEscapedKeyInAMapItEdits(t *testing.T) {
	st := State{Installation: model.ID{5}, Revision: 7, IncidentBooks: map[string]json.RawMessage{"a\"b": json.RawMessage(`1`), "z": json.RawMessage(`2`)}}
	raw := mustMarshal(t, st)
	if !bytes.Contains(raw, []byte(`a\"b`)) {
		t.Fatal("the fixture's key is not escaped")
	}
	root := scanStateRoot(raw)
	ops := []patchOp{revisionOp(8), {Op: opSet, Path: []string{"IncidentBooks", "m"}, Value: json.RawMessage(`3`)}}
	if _, _, ok := patchRaw(raw, root, ops); ok {
		t.Fatal("the splice placed a member beside an escaped key")
	}
}

// Deleting down to an empty map, inserting into an empty map, and the members at the two ends of a
// map are where a comma goes wrong.
func TestRawPatchCommasAtEveryPosition(t *testing.T) {
	keys := []string{"b", "d", "f"}
	for mask := range 1 << len(keys) {
		for _, op := range []string{"insert-first", "insert-middle", "insert-last", "delete-first", "delete-middle", "delete-last", "replace-all", "delete-all"} {
			st := State{Installation: model.ID{5}, Revision: 7, IncidentBooks: map[string]json.RawMessage{}}
			for i, k := range keys {
				if mask&(1<<i) != 0 {
					st.IncidentBooks[k] = json.RawMessage(fmt.Sprintf(`%d`, i))
				}
			}
			next := State{Installation: st.Installation, Revision: 8, IncidentBooks: map[string]json.RawMessage{}}
			for k, v := range st.IncidentBooks {
				next.IncidentBooks[k] = v
			}
			sorted := slices.Sorted(func(yield func(string) bool) {
				for k := range st.IncidentBooks {
					if !yield(k) {
						return
					}
				}
			})
			switch op {
			case "insert-first":
				next.IncidentBooks["a"] = json.RawMessage(`9`)
			case "insert-middle":
				next.IncidentBooks["c"] = json.RawMessage(`9`)
				next.IncidentBooks["e"] = json.RawMessage(`9`)
			case "insert-last":
				next.IncidentBooks["z"] = json.RawMessage(`9`)
			case "delete-first":
				if len(sorted) > 0 {
					delete(next.IncidentBooks, sorted[0])
				}
			case "delete-middle":
				if len(sorted) > 2 {
					delete(next.IncidentBooks, sorted[1])
				}
			case "delete-last":
				if len(sorted) > 0 {
					delete(next.IncidentBooks, sorted[len(sorted)-1])
				}
			case "replace-all":
				for k := range next.IncidentBooks {
					next.IncidentBooks[k] = json.RawMessage(`7`)
				}
			case "delete-all":
				clear(next.IncidentBooks)
			}
			oldRaw, newRaw := mustMarshal(t, st), mustMarshal(t, next)
			ops, err := diffStates(oldRaw, newRaw)
			if err != nil {
				t.Fatal(err)
			}
			got, _, ok := patchRaw(oldRaw, scanStateRoot(oldRaw), ops)
			if !ok {
				t.Fatalf("mask %b %s: refused", mask, op)
			}
			if !bytes.Equal(got, newRaw) {
				t.Fatalf("mask %b %s:\n got %s\nwant %s", mask, op, got, newRaw)
			}
		}
	}
}

func TestAuditDeltaRawEqualsTheDecodedApply(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 9))
	st := State{Installation: model.ID{5}, Revision: 100}
	var spliced int
	for step := range 400 {
		for range 1 + r.IntN(3) {
			mutateState(r, &st)
		}
		if r.IntN(7) == 0 {
			st.Audits = nil // no log yet: the delta starts it
		}
		raw := mustMarshal(t, st)
		rows := []model.ControlAudit{{ID: model.ID{byte(step), 1}, Principal: model.ID{1}, Action: "export.chunk", Reason: "released", Time: int64(step), Outcome: model.AuditAllowed}}
		if r.IntN(5) == 0 {
			rows = append(rows, model.ControlAudit{ID: model.ID{byte(step), 2}, Principal: model.ID{1}, Action: controlErasedAction, Time: int64(step), Outcome: model.AuditAllowed})
		}
		d := auditDelta{Installation: st.Installation, Expected: st.Revision, At: int64(step) * int64(revisionStampEvery) / 2, Audits: rows}
		var current State
		if err := json.Unmarshal(raw, &current); err != nil {
			t.Fatal(err)
		}
		applyAuditDelta(&current, d)
		want := mustMarshal(t, current)
		got, ok := deltaRaw(raw, scanStateRoot(raw), d)
		if !ok {
			t.Fatalf("step %d: the delta was refused", step)
		}
		spliced++
		if !bytes.Equal(got, want) {
			t.Fatalf("step %d: the splice of a delta leaves other bytes than the decoded apply\n got %.300s\nwant %.300s", step, got, want)
		}
		st = current
	}
	if spliced != 400 {
		t.Fatalf("%d deltas were spliced", spliced)
	}
}

func TestStaleRejectionRawEqualsTheDecodedApply(t *testing.T) {
	r := rand.New(rand.NewPCG(8, 2))
	st := State{Installation: model.ID{5}, Revision: 3}
	for step := range 200 {
		for range 1 + r.IntN(3) {
			mutateState(r, &st)
		}
		raw := mustMarshal(t, st)
		next := model.Revision(r.IntN(1 << 20))
		current := st
		current.Revision = next
		want := mustMarshal(t, current)
		got, _, ok := patchRaw(raw, scanStateRoot(raw), []patchOp{revisionOp(next)})
		if !ok || !bytes.Equal(got, want) {
			t.Fatalf("step %d: ok=%v, the splice of the revision leaves other bytes\n got %.200s\nwant %.200s", step, ok, got, want)
		}
	}
}

// The digest read from the scan is the digest of the members in name order, which is what the
// proposers of every release that wrote patches computed.
func TestPatchBaseOfTheScanIsTheDigestOfTheMembers(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 4))
	st := State{Installation: model.ID{5}, Revision: 1}
	for step := range 200 {
		for range 1 + r.IntN(3) {
			mutateState(r, &st)
		}
		raw := mustMarshal(t, st)
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(members))
		for name := range members {
			names = append(names, name)
		}
		sort.Strings(names)
		h := sha256.New()
		for _, name := range names {
			h.Write([]byte(name + "\x00"))
			h.Write(members[name])
			h.Write([]byte{0})
		}
		want := hex.EncodeToString(h.Sum(nil))
		got, ok := patchBaseRoot(raw, scanStateRoot(raw))
		if !ok || got != want {
			t.Fatalf("step %d: scanned digest %s (ok %v), want %s", step, got, ok, want)
		}
		if viaMembers, err := patchBase(raw); err != nil || viaMembers != want {
			t.Fatalf("step %d: patchBase %s (%v), want %s", step, viaMembers, err, want)
		}
	}
}

func TestSkipValueReadsEveryShapeTheEncoderWrites(t *testing.T) {
	for _, v := range []string{`"a\"b\\"`, `"\\"`, `12`, `-1.5e+3`, `true`, `null`, `{"a":[1,2,{"b":"}]"}],"c":"\\\""}`, `[]`, `{}`, `[[],[{}],"]"]`} {
		raw := []byte(v + ",")
		end, ok := skipValue(raw, 0)
		if !ok || end != len(v) {
			t.Fatalf("%s: end %d ok %v, want %d", v, end, ok, len(v))
		}
	}
	for _, v := range []string{`{"a" :1}`, `[1, 2]`, `{"a":"`, `{"a":[}`, ``, `,`} {
		if end, ok := skipValue([]byte(v), 0); ok && strings.TrimSpace(v) != "" && end == len(v) {
			t.Fatalf("%q: scanned as a compact value", v)
		}
	}
}

func TestLastAuditsAndRevisionOfReadTheHeadWithoutDecodingTheState(t *testing.T) {
	r := rand.New(rand.NewPCG(6, 6))
	st := State{Installation: model.ID{5}, Revision: 1}
	for step := range 300 {
		for range 1 + r.IntN(3) {
			if r.IntN(3) == 0 {
				moreMutations(r, &st)
			} else {
				mutateState(r, &st)
			}
		}
		raw := mustMarshal(t, st)
		root := scanStateRoot(raw)
		installation, revision, err := revisionOf(raw)
		if err != nil || installation != st.Installation || revision != st.Revision {
			t.Fatalf("step %d: revisionOf %v %v %v, want %v %v", step, installation, revision, err, st.Installation, st.Revision)
		}
		for _, n := range []int{1, 2, 5, 64} {
			total, tail, ok := lastAudits(raw, root, n)
			if len(st.Audits) == 0 && raw != nil && bytes.Contains(raw, []byte(`"Audits":null`)) {
				if ok {
					t.Fatalf("step %d: a log that is null was read as an array", step)
				}
				continue
			}
			if !ok || total != len(st.Audits) {
				t.Fatalf("step %d n=%d: total %d ok %v, want %d", step, n, total, ok, len(st.Audits))
			}
			want := st.Audits[max(len(st.Audits)-n, 0):]
			if len(tail) != len(want) {
				t.Fatalf("step %d n=%d: %d rows, want %d", step, n, len(tail), len(want))
			}
			for i := range want {
				if !bytes.Equal(mustMarshal(t, tail[i]), mustMarshal(t, want[i])) {
					t.Fatalf("step %d n=%d: row %d differs", step, n, i)
				}
			}
		}
	}
}

// A patch an erasure pass rewrote carries no base. The pass can have emptied the whole-map write that
// created a book (an emptied omitted map is not written back), so the next record of the book is
// written into a book that is not there; a patch with a base is still refused there, and so is
// anything below the first level of a state.
func TestARewrittenPatchWritesARecordIntoABookThatIsNotThere(t *testing.T) {
	st := State{Installation: model.ID{5}, Revision: 7} // SavedViewBooks is omitted, IncidentBooks is null
	raw := mustMarshal(t, st)
	if !bytes.Contains(raw, []byte(`"IncidentBooks":null`)) || bytes.Contains(raw, []byte("SavedViewBooks")) {
		t.Fatalf("the fixture's books are not an omitted and a null book: %s", raw)
	}
	next := st
	next.Revision = 8
	next.SavedViewBooks = map[string]json.RawMessage{"k": json.RawMessage(`{"v":1}`)}
	next.IncidentBooks = map[string]json.RawMessage{"i": json.RawMessage(`{"v":2}`)}
	want := mustMarshal(t, next)
	ops := []patchOp{revisionOp(8),
		{Op: opSet, Path: []string{"SavedViewBooks", "k"}, Value: json.RawMessage(`{"v":1}`)},
		{Op: opSet, Path: []string{"IncidentBooks", "i"}, Value: json.RawMessage(`{"v":2}`)}}
	if _, err := applyPatchRaw(raw, ops, false); err == nil {
		t.Fatal("a patch with a base was applied to books that are not there")
	}
	if _, _, ok := patchRaw(raw, scanStateRoot(raw), ops); ok {
		t.Fatal("the splice wrote a record into a book that is not there")
	}
	patched, err := applyPatchRaw(raw, ops, true)
	if err != nil {
		t.Fatalf("a rewritten patch: %v", err)
	}
	var got State
	if err := model.StrictJSON(patched, &got); err != nil {
		t.Fatal(err)
	}
	if again := mustMarshal(t, got); !bytes.Equal(again, want) {
		t.Fatalf("the books written into nothing:\n got %s\nwant %s", again, want)
	}
	below := []patchOp{revisionOp(8), {Op: opSet, Path: []string{"Orgs", "o9", "Settings", "x"}, Value: json.RawMessage(`{"a":1}`)}}
	if _, err := applyPatchRaw(raw, below, true); err == nil {
		t.Fatal("a rewritten patch created an organization")
	}
}

// Key-level deletes that empty an omitempty map member must not leave `{}`: the encoder omits the
// member, so the splice has to equal decode/encode (or refuse).
func TestRawPatchOfDeletesThatEmptyAnOmitemptyMapEqualsDecodeEncode(t *testing.T) {
	st := State{Installation: model.ID{5}, Revision: 7,
		SavedViewBooks: map[string]json.RawMessage{"a": json.RawMessage(`1`), "b": json.RawMessage(`2`)}}
	raw := mustMarshal(t, st)
	ops := []patchOp{revisionOp(8),
		{Op: opDelete, Path: []string{"SavedViewBooks", "a"}}, {Op: opDelete, Path: []string{"SavedViewBooks", "b"}}}
	want, ok := decodeEncodePatch(raw, ops)
	if !ok {
		t.Fatal("decode/encode refuses")
	}
	if got, _, ok := patchRaw(raw, scanStateRoot(raw), ops); ok && !bytes.Equal(got, want) {
		t.Fatalf("splice leaves other bytes:\n got %s\nwant %s", got, want)
	}
}

// Key-level deletes of every key of each omitempty map (what a redaction of a patch writes) on random
// states: the splice equals decode/encode or refuses, and is never other bytes.
func TestRawPatchOfEveryKeyDeleteOfEachOmitemptyMapEqualsDecodeEncode(t *testing.T) {
	r := rand.New(rand.NewPCG(21, 4))
	st := State{Installation: model.ID{5}, Revision: 1}
	var checked int
	for step := range 400 {
		for range 1 + r.IntN(4) {
			if r.IntN(2) == 0 {
				moreMutations(r, &st)
			} else {
				mutateState(r, &st)
			}
		}
		raw := mustMarshal(t, st)
		var ops []patchOp
		for field, m := range map[string]map[string]json.RawMessage{"SavedViewBooks": st.SavedViewBooks, "RuleDefinitions": st.RuleDefinitions, "JobDefinitions": st.JobDefinitions, "IncidentBooks": st.IncidentBooks} {
			for k := range m {
				ops = append(ops, patchOp{Op: opDelete, Path: []string{field, k}})
			}
		}
		ops = append(ops, revisionOp(st.Revision+1))
		want, ok := decodeEncodePatch(raw, ops)
		if !ok {
			t.Fatalf("step %d: decode/encode refuses", step)
		}
		checked++
		if got, _, ok := patchRaw(raw, scanStateRoot(raw), ops); ok && !bytes.Equal(got, want) {
			t.Fatalf("step %d: splice leaves other bytes:\n got %.300s\nwant %.300s", step, got, want)
		}
	}
	if checked < 400 {
		t.Fatal("too few cases")
	}
}
