// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The stored form of a command is what encoding/json writes for durableEntry. walEntry.MarshalJSON
// is encodeWAL, so json.Marshal(walEntry) is the code under test and cannot be its own reference:
// every encoder test compares against oracleWAL, which copies the members of a walEntry into a
// durableEntry (no methods) BY NAME with reflection and lets the standard library marshal that. It
// holds no member list of its own, so a member added to walEntry is either copied or a test
// failure, and it shares no code with encodeWAL, encodeFragmentJSON or the envelope.

// plainWalEntry has walEntry's members and tags and none of its methods: json.Marshal of it takes
// the standard library's reflection path. Its Batch is the model's NormalizedBatch, whose JSON form
// is not the stored one, so it is a second reference for every entry without a batch.
type plainWalEntry walEntry

// oracleOmits names the members the stored form does not carry: a batch is stored as its canonical
// input bytes (durableBatch), from which the embedded Batch and Series are derived again.
var oracleOmits = map[string]bool{"NormalizedBatch.Batch": true, "NormalizedBatch.Series": true}

func copyByName(dst, src reflect.Value) error {
	for i := range src.NumField() {
		sf := src.Type().Field(i)
		if !sf.IsExported() {
			continue
		}
		df := dst.FieldByName(sf.Name)
		if !df.IsValid() {
			if oracleOmits[src.Type().Name()+"."+sf.Name] {
				continue
			}
			return fmt.Errorf("%s.%s has no counterpart in %s: the stored form would drop it", src.Type().Name(), sf.Name, dst.Type().Name())
		}
		sv := src.Field(i)
		switch {
		case sv.Type() == df.Type():
			df.Set(sv)
		case sv.Kind() == reflect.Pointer && df.Kind() == reflect.Pointer && sv.Type().Elem().Kind() == reflect.Struct && df.Type().Elem().Kind() == reflect.Struct:
			if sv.IsNil() {
				continue
			}
			df.Set(reflect.New(df.Type().Elem()))
			if err := copyByName(df.Elem(), sv.Elem()); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s.%s is a %s, %s.%s a %s", src.Type().Name(), sf.Name, sv.Type(), dst.Type().Name(), sf.Name, df.Type())
		}
	}
	return nil
}

// oracleWAL is json.Marshal of the stored form of e, by the standard library alone.
func oracleWAL(e walEntry) ([]byte, error) {
	var wire durableEntry
	if err := copyByName(reflect.ValueOf(&wire).Elem(), reflect.ValueOf(e)); err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

func mustOracle(t *testing.T, name string, e walEntry) []byte {
	t.Helper()
	raw, err := oracleWAL(e)
	if err != nil {
		t.Fatalf("%s: oracle: %v", name, err)
	}
	return raw
}

// fillOpts says how fill populates a value. text goes into every string; slices is 0 to leave
// slices and maps nil, 1 for empty non-nil ones, 2 for ones with two members. Integers take the
// extreme of their type (the smallest signed, the largest unsigned) and booleans are true.
type fillOpts struct {
	text   string
	slices int
}

const (
	// nastyValid carries the characters encoding/json escapes (<, >, &, U+2028, U+2029, a NUL, the
	// quote and the backslash) beside non-ASCII text; it survives a decode unchanged.
	nastyValid = "a<b>&c\u2028d\u2029e\u00e9\u4e16\x00\"\\/"
	// nastyInvalid ends in invalid UTF-8, which encoding/json writes as U+FFFD.
	nastyInvalid = nastyValid + "\xff\xfe\xe2\x80"
)

// fill gives every exported member of v a non-zero value of its own type (IDs and hashes are
// byte arrays: every byte is set). A member tagged json:"-" is left alone.
func fill(v reflect.Value, o fillOpts, depth int) {
	if depth > 12 {
		return
	}
	switch v.Kind() {
	case reflect.String:
		v.SetString(o.text)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(-1) << uint(v.Type().Bits()-1))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(^uint64(0) >> uint(64-v.Type().Bits()))
	case reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			for i := range v.Len() {
				v.Index(i).SetUint(uint64(i*7+0xa1) & 0xff)
			}
			return
		}
		for i := range v.Len() {
			fill(v.Index(i), o, depth+1)
		}
	case reflect.Slice:
		switch o.slices {
		case 0:
		case 1:
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		default:
			v.Set(reflect.MakeSlice(v.Type(), 2, 2))
			for i := range v.Len() {
				fill(v.Index(i), o, depth+1)
			}
		}
	case reflect.Map:
		if o.slices > 0 {
			v.Set(reflect.MakeMap(v.Type()))
		}
		if o.slices > 1 {
			key, val := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
			fill(key, o, depth+1)
			fill(val, o, depth+1)
			v.SetMapIndex(key, val)
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(v.Elem(), o, depth+1)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(model.NormalizedBatch{}) {
			// Only the members of the stored form: the embedded Batch is derived from Canonical.
			for _, name := range []string{"Org", "Hash", "Canonical", "PolicyEpoch", "PolicyHash", "AdmissionAt", "Deadlines", "Reservation"} {
				fill(v.FieldByName(name), o, depth+1)
			}
			return
		}
		for i := range v.NumField() {
			f := v.Type().Field(i)
			if f.IsExported() && f.Tag.Get("json") != "-" {
				fill(v.Field(i), o, depth+1)
			}
		}
	}
}

// fillOptions is every way the fixtures are populated: with nasty valid text, with nasty invalid
// text, and with no text at all, each with nil, empty and populated slices.
func fillOptions() []fillOpts {
	var out []fillOpts
	for _, text := range []string{nastyValid, nastyInvalid, ""} {
		for slices := range 3 {
			out = append(out, fillOpts{text: text, slices: slices})
		}
	}
	return out
}

// nastyFragment is an artifact fragment command whose every member is populated by fill, with n
// bytes of fragment before a tail of characters the JSON text escapes.
func nastyFragment(o fillOpts, n int) walEntry {
	f := model.ArtifactFragment{}
	fill(reflect.ValueOf(&f).Elem(), o, 0)
	f.Bytes = append(bytes.Repeat([]byte{'x'}, n), "<&>\u2028\n\"\\\u00e9\xff"...)
	f.Hash = model.HashCanonical(f.Bytes)
	return walEntry{Type: "artifact_fragment", Artifact: &f}
}

// memberJSONKey is the JSON object key of the walEntry member name.
func memberJSONKey(t *testing.T, name string) string {
	t.Helper()
	f, ok := reflect.TypeOf(walEntry{}).FieldByName(name)
	if !ok {
		t.Fatalf("walEntry has no member %s", name)
	}
	return strings.Split(f.Tag.Get("json"), ",")[0]
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// The mirrors the oracle copies through must have exactly the members of the types they mirror.
func TestOracleIsIndependentOfTheCodeUnderTest(t *testing.T) {
	members := func(typ reflect.Type) (out []string) {
		for i := range typ.NumField() {
			if typ.Field(i).IsExported() {
				out = append(out, typ.Field(i).Name)
			}
		}
		return out
	}
	if got, want := members(reflect.TypeOf(durableEntry{})), members(reflect.TypeOf(walEntry{})); !reflect.DeepEqual(sorted(got), sorted(want)) {
		t.Fatalf("durableEntry members %q are not walEntry's %q", got, want)
	}
	var batch []string
	for _, name := range members(reflect.TypeOf(model.NormalizedBatch{})) {
		if !oracleOmits["NormalizedBatch."+name] {
			batch = append(batch, name)
		}
	}
	if got := members(reflect.TypeOf(durableBatch{})); !reflect.DeepEqual(sorted(got), sorted(batch)) {
		t.Fatalf("durableBatch members %q are not the stored members of NormalizedBatch %q", got, batch)
	}
	// The fixtures must reach the characters the escaping rules are about, in the string members that
	// a fragment carries; and the oracle must equal the standard library over a plain mirror.
	e := nastyFragment(fillOpts{text: nastyInvalid, slices: 2}, 3)
	want := mustOracle(t, "nasty", e)
	for _, probe := range []string{`\u003cb\u003e\u0026c\u2028d\u2029e`, `\u0000`, `"debug_id":"a`, `"path":"a`, `"state":"a`} {
		if !bytes.Contains(want, []byte(probe)) {
			t.Fatalf("the nasty fixture does not reach %s", probe)
		}
	}
	for _, o := range fillOptions() {
		e := nastyFragment(o, 5)
		plain, err := json.Marshal(plainWalEntry(e))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plain, mustOracle(t, "plain", e)) {
			t.Fatalf("%+v: the oracle differs from json.Marshal over the methodless mirror", o)
		}
	}
}

// Every encoder of a command's stored form writes the bytes encoding/json writes for it.
func TestWALEncodersMatchTheStandardLibraryOracle(t *testing.T) {
	type fixture struct {
		name string
		e    walEntry
	}
	var fixtures []fixture
	nilBytes, emptyBytes := nastyFragment(fillOpts{text: nastyValid, slices: 2}, 4), nastyFragment(fillOpts{text: nastyValid, slices: 2}, 4)
	nilBytes.Artifact.Bytes, emptyBytes.Artifact.Bytes = nil, []byte{}
	emptyBytes.Artifact.Hash = model.HashCanonical(emptyBytes.Artifact.Bytes)
	fixtures = append(fixtures, fixture{"nil bytes", nilBytes}, fixture{"empty bytes", emptyBytes},
		fixture{"legacy empty", fragmentWAL('a', 0)}, fixture{"legacy small", fragmentWAL('b', 1)}, fixture{"legacy full", fragmentWAL('c', model.ArtifactFragmentLimit-16)})
	for _, o := range fillOptions() {
		for _, n := range []int{0, 1, 4096} {
			fixtures = append(fixtures, fixture{fmt.Sprintf("%q/%d slices/%d bytes", o.text, o.slices, n), nastyFragment(o, n)})
		}
	}
	fixtures = append(fixtures, fixture{"full", nastyFragment(fillOpts{text: nastyInvalid, slices: 2}, model.ArtifactFragmentLimit-16)})
	for _, fx := range fixtures {
		name, e := fx.name, fx.e
		want := mustOracle(t, name, e)
		plain, err := json.Marshal(plainWalEntry(e))
		if err != nil || !bytes.Equal(plain, want) {
			t.Fatalf("%s: the methodless mirror differs from the oracle: %v", name, err)
		}
		got, ok, err := encodeFragmentJSON(e)
		if err != nil || !ok || !bytes.Equal(got, want) {
			t.Fatalf("%s: encodeFragmentJSON differs from encoding/json (len %d vs %d, ok %v, %v)", name, len(got), len(want), ok, err)
		}
		if cap(got) != len(got) {
			t.Fatalf("%s: output buffer is %d for %d bytes of text", name, cap(got), len(got))
		}
		if generic, err := encodeWAL(e); err != nil || !bytes.Equal(generic, want) {
			t.Fatalf("%s: encodeWAL differs from encoding/json: %v", name, err)
		}
		if viaMarshal, err := json.Marshal(e); err != nil || !bytes.Equal(viaMarshal, want) {
			t.Fatalf("%s: json.Marshal(walEntry) differs from encoding/json over the stored form: %v", name, err)
		}
		if e.Artifact.Bytes == nil || uint64(len(e.Artifact.Bytes)) > model.ArtifactFragmentLimit {
			continue
		}
		// What the envelope carries is stored as the same JSON as the command proposed in JSON: the
		// stored form of a decoded command (invalid UTF-8 has become U+FFFD by then, in either form).
		env, ok, err := encodeFragmentEnvelope(e)
		if err != nil || !ok {
			t.Fatalf("%s: the envelope did not take the fragment (ok %v): %v", name, ok, err)
		}
		back, err := decodeWAL(env)
		if err != nil {
			t.Fatalf("%s: envelope: %v", name, err)
		}
		fromJSON, err := decodeWAL(want)
		if err != nil {
			t.Fatalf("%s: the oracle's bytes do not decode: %v", name, err)
		}
		if stored, err := encodeWAL(back); err != nil || !bytes.Equal(stored, mustOracle(t, name, fromJSON)) {
			t.Fatalf("%s: the stored form of an envelope-proposed fragment differs from the JSON-proposed one: %v", name, err)
		}
	}
	// A command that is not a plain fragment takes the generic path, and it too is the standard library's bytes.
	rejection := model.NewID()
	plain := nastyFragment(fillOpts{text: nastyValid, slices: 2}, 8)
	for name, e := range map[string]walEntry{
		"no artifact":   {Type: "artifact_fragment"},
		"wrong type":    {Type: "fence", Artifact: plain.Artifact},
		"rejection":     {Type: "rejected", Rejection: &rejection},
		"two arms":      {Type: "artifact_fragment", Artifact: plain.Artifact, Rejection: &rejection},
		"batch missing": {Type: "batch"},
	} {
		want, wantErr := oracleWAL(e)
		got, err := encodeWAL(e)
		if (wantErr == nil) != (err == nil) || err == nil && !bytes.Equal(got, want) {
			t.Fatalf("%s: encodeWAL differs from encoding/json (%v vs %v)", name, err, wantErr)
		}
	}
}

// carriers say which command a walEntry member rides in: its Type and the other members the
// decoder requires beside it.
var carriers = map[string]struct {
	typ  string
	with []string
}{
	"Batch":         {"batch", []string{"Batch", "Receipt"}},
	"Receipt":       {"batch", []string{"Batch", "Receipt"}},
	"Cancel":        {"cancel", []string{"Cancel"}},
	"CommitSet":     {"cancel", []string{"Cancel", "CommitSet"}},
	"Fence":         {"fence", []string{"Fence"}},
	"Artifact":      {"artifact_fragment", []string{"Artifact"}},
	"ArtifactGC":    {"artifact_gc", []string{"ArtifactGC"}},
	"Rejection":     {"rejected", []string{"Rejection"}},
	"DeleteBarrier": {"delete_barrier", []string{"DeleteBarrier"}},
	"EraseAck":      {"erase_ack", []string{"EraseAck"}},
	"EraseUnack":    {"erase_unack", []string{"EraseUnack"}},
	"EraseNotice":   {"erase_notice", []string{"EraseNotice"}},
	"Proposer":      {"erase_ack", []string{"EraseAck", "Proposer"}},
	"Redaction":     {"artifact_redacted", []string{"Redaction"}},
}

func setMember(e *walEntry, name string, o fillOpts) {
	fill(reflect.ValueOf(e).Elem().FieldByName(name), o, 0)
}

// alignEntry makes the members of e the decoder derives or checks agree with the ones it carries:
// a batch is its canonical bytes and their hash, and a cancel's commit set names the cancel.
func alignEntry(e *walEntry) {
	if b := e.Batch; b != nil {
		aligned := model.NormalizedBatch{Org: b.Org, Canonical: []byte("{}"), PolicyEpoch: b.PolicyEpoch, PolicyHash: b.PolicyHash, AdmissionAt: b.AdmissionAt, Deadlines: b.Deadlines, Reservation: b.Reservation, Series: b.Reservation.Series}
		aligned.Hash = model.HashCanonical(aligned.Canonical)
		e.Batch = &aligned
	}
	if e.Cancel != nil && e.CommitSet != nil {
		e.CommitSet.Reservation, e.CommitSet.Group = e.Cancel.ReservationID, e.Cancel.OwnerGroup
	}
}

// carrierEntry is a command of the type member rides in, with member (and what the decoder needs
// beside it) populated.
func carrierEntry(t *testing.T, member string, o fillOpts) walEntry {
	t.Helper()
	c, ok := carriers[member]
	if !ok {
		t.Fatalf("walEntry.%s is not in carriers: say which command carries it, so the wire tests cover it", member)
	}
	e := walEntry{Type: c.typ}
	for _, name := range c.with {
		setMember(&e, name, o)
	}
	alignEntry(&e)
	return e
}

// Every member of walEntry is on the wire: the stored form of a command that carries it holds the
// member's key, is encoding/json's bytes, and decodes back to the same command. encodeWAL, the
// fast path in front of it and the decoder each list the members by hand; a member left out of any
// of them is dropped from the journal, and nothing but this walk over the type notices.
func TestEveryWalEntryMemberSurvivesTheWire(t *testing.T) {
	typ := reflect.TypeOf(walEntry{})
	for i := range typ.NumField() {
		member := typ.Field(i).Name
		if member == "Type" {
			continue
		}
		key := `"` + memberJSONKey(t, member) + `":`
		for _, o := range fillOptions() {
			label := fmt.Sprintf("%s %q/%d slices", member, o.text, o.slices)
			// Carried by a command of its own type: key, bytes, round trip.
			e := carrierEntry(t, member, o)
			if reflect.ValueOf(e).FieldByName(member).IsZero() {
				t.Fatalf("%s: the fixture left the member zero", label)
			}
			got, err := encodeWAL(e)
			if err != nil {
				t.Fatalf("%s: encodeWAL: %v", label, err)
			}
			if !bytes.Contains(got, []byte(key)) {
				t.Fatalf("%s: encodeWAL dropped the member: %.200s", label, got)
			}
			if want := mustOracle(t, label, e); !bytes.Equal(got, want) {
				t.Fatalf("%s: encodeWAL differs from encoding/json\n got %.300s\nwant %.300s", label, got, want)
			}
			if o.text != nastyInvalid && o.slices != 1 {
				back, err := decodeWAL(got)
				if err != nil {
					t.Fatalf("%s: decodeWAL(encodeWAL(e)): %v", label, err)
				}
				if !reflect.DeepEqual(back, e) {
					t.Fatalf("%s: decodeWAL(encodeWAL(e)) is another command", label)
				}
			}
			if member == "Artifact" || member == "Type" {
				continue
			}
			// And on top of a plain fragment: no member may be dropped because the fragment path ran.
			frag := nastyFragment(o, 16)
			setMember(&frag, member, o)
			got, err = encodeWAL(frag)
			if err != nil {
				t.Fatalf("%s on a fragment: encodeWAL: %v", label, err)
			}
			if !bytes.Contains(got, []byte(key)) || !bytes.Equal(got, mustOracle(t, label, frag)) {
				t.Fatalf("%s on a fragment: encodeWAL dropped or changed the member: %.300s", label, got)
			}
		}
	}
	// Every member at once: nothing is lost to another member being present.
	for _, o := range fillOptions() {
		all := nastyFragment(o, 16)
		for i := range typ.NumField() {
			if name := typ.Field(i).Name; name != "Type" && name != "Artifact" {
				setMember(&all, name, o)
			}
		}
		got, err := encodeWAL(all)
		if err != nil || !bytes.Equal(got, mustOracle(t, "all members", all)) {
			t.Fatalf("every member set (%q/%d slices): encodeWAL differs from encoding/json: %v", o.text, o.slices, err)
		}
		for i := range typ.NumField() {
			if name := typ.Field(i).Name; name != "Type" && !bytes.Contains(got, []byte(`"`+memberJSONKey(t, name)+`":`)) {
				t.Fatalf("every member set: encodeWAL dropped %s", name)
			}
		}
	}
}

// The binary envelope carries a plain fragment and nothing else. Any other member, set on a
// fragment command, sends the proposal to the JSON form, which carries it (a proposer on the
// envelope switch must not silently shed a member of the command it proposes).
func TestEnvelopeDeclinesEveryOtherMember(t *testing.T) {
	e := &Engine{}
	e.EnableFragmentEnvelope(true)
	plain := nastyFragment(fillOpts{text: nastyValid, slices: 2}, 64)
	if _, ok, err := encodeFragmentEnvelope(plain); !ok || err != nil {
		t.Fatalf("a plain fragment is not carried by the envelope (ok %v, %v)", ok, err)
	}
	if raw, err := e.encodeProposal(plain); err != nil || !isEnvelope(raw) {
		t.Fatalf("a plain fragment is not proposed in the envelope: %v", err)
	}
	typ := reflect.TypeOf(walEntry{})
	for i := range typ.NumField() {
		member := typ.Field(i).Name
		if member == "Type" || member == "Artifact" {
			continue
		}
		for _, o := range fillOptions() {
			frag := nastyFragment(o, 64)
			setMember(&frag, member, o)
			if _, ok, err := encodeFragmentEnvelope(frag); ok || err != nil {
				t.Fatalf("walEntry.%s set on a fragment command is carried by the envelope (ok %v, %v): the envelope would drop it", member, ok, err)
			}
			if onlyFragment(frag) {
				t.Fatalf("onlyFragment accepts a fragment command with walEntry.%s set", member)
			}
			before := e.envelopesProposed.Load()
			raw, err := e.encodeProposal(frag)
			if err != nil || isEnvelope(raw) || e.envelopesProposed.Load() != before {
				t.Fatalf("walEntry.%s: the proposal of a fragment command that carries it was not the JSON form (%v)", member, err)
			}
			if want := mustOracle(t, member, frag); !bytes.Equal(raw, want) {
				t.Fatalf("walEntry.%s: the JSON proposal differs from encoding/json", member)
			}
			if _, ok, _ := encodeFragmentJSON(frag); ok {
				t.Fatalf("walEntry.%s: the JSON fast path takes what the envelope declined for the same member", member)
			}
		}
	}
	// A fragment that is not the plain one: the type, and fragment bytes that are absent.
	wrongType := plain
	wrongType.Type = "fence"
	noBytes := nastyFragment(fillOpts{text: nastyValid, slices: 2}, 4)
	noBytes.Artifact.Bytes = nil
	for name, frag := range map[string]walEntry{"wrong type": wrongType, "nil bytes": noBytes, "no artifact": {Type: "artifact_fragment"}} {
		if _, ok, err := encodeFragmentEnvelope(frag); ok || err != nil {
			t.Fatalf("%s: carried by the envelope (ok %v, %v)", name, ok, err)
		}
	}
}
