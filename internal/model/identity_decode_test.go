// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// A Raft snapshot envelope or a journal record holds an ID and a Hash in every record, and decoding
// it calls the member's UnmarshalJSON once per value. When that call went through json.Unmarshal each
// value took a pooled decoder; under -race sync.Pool deliberately drops a quarter of what is put back,
// so every decoded ID allocated a decoder buffer and a snapshot cut's allocation was a multiple of its
// plain-build self (11.05-W1, measured: model.ID.UnmarshalJSON 1.8 MB of one cut under -race, 50 KB
// without). The canonical form is decoded in place and allocates nothing in either build.
func TestDecodingACanonicalIDOrHashAllocatesNothing(t *testing.T) {
	id := mustHexID("00112233445566778899aabbccddeeff")
	idJSON := []byte(`"00112233445566778899aabbccddeeff"`)
	hashJSON := []byte(`"` + strings.Repeat("ab01", 16) + `"`)
	var gotID ID
	var gotHash Hash
	if n := testing.AllocsPerRun(200, func() {
		if err := gotID.UnmarshalJSON(idJSON); err != nil {
			t.Fatal(err)
		}
		if err := gotHash.UnmarshalJSON(hashJSON); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatalf("decoding one ID and one Hash allocated %v times", n)
	}
	if gotID != id || gotHash.String() != strings.Repeat("ab01", 16) {
		t.Fatalf("decoded %s and %s", gotID, gotHash)
	}
}

func mustHexID(s string) ID {
	id, err := ParseID(s)
	if err != nil {
		panic(err)
	}
	return id
}

// The in-place decoder accepts exactly what the general one accepts: every input that is not the
// canonical form is decided by the general path, so the answers agree on the whole table.
func TestTheCanonicalIDAndHashDecodersAgreeWithTheGeneralPath(t *testing.T) {
	zero := `"` + strings.Repeat("0", 32) + `"`
	cases := []string{
		`"00112233445566778899aabbccddeeff"`,
		// upper case: ParseID refuses it; short and long; not hex; escapes
		`"00112233445566778899AABBCCDDEEFF"`,
		`"00112233445566778899aabbccddeef"`,
		`"00112233445566778899aabbccddeeff0"`,
		`"00112233445566778899aabbccddeefg"`,
		`"\u0030\u00112233445566778899aabbccd"`,
		`"0011223344556677889900aabbccddeeff"`,
		zero,
		`null`,
		`""`,
		`12`,
		`"00112233445566778899aabbccddeeff`,
		`00112233445566778899aabbccddeeff"`,
		`"` + strings.Repeat("ab01", 16) + `"`,
		`"` + strings.Repeat("AB01", 16) + `"`,
		`"` + strings.Repeat("ab01", 15) + `"`,
		`"` + strings.Repeat("zb01", 16) + `"`,
	}
	for _, c := range cases {
		var fast, slow ID
		fastErr := fast.UnmarshalJSON([]byte(c))
		var s string
		slowErr := json.Unmarshal([]byte(c), &s)
		if slowErr == nil {
			slowErr = slow.UnmarshalText([]byte(s))
		}
		if (fastErr == nil) != (slowErr == nil) || fast != slow {
			t.Errorf("ID %s: decoder says (%v, %s), general path says (%v, %s)", c, fastErr, fast, slowErr, slow)
		}
		var fastHash, slowHash Hash
		fastErr = fastHash.UnmarshalJSON([]byte(c))
		slowErr = json.Unmarshal([]byte(c), &s)
		if slowErr == nil {
			slowErr = slowHash.fromString(s)
		}
		if (fastErr == nil) != (slowErr == nil) || fastHash != slowHash {
			t.Errorf("Hash %s: decoder says (%v, %s), general path says (%v, %s)", c, fastErr, fastHash, slowErr, slowHash)
		}
	}
}

// A Cursor in its canonical form decodes in place; every other form (spaces, member order,
// escapes, an unknown member, a missing index, a bad group) is decided by the general decoder and
// answers as it always did.
func TestACanonicalCursorDecodesInPlaceAndEveryOtherFormKeepsItsAnswer(t *testing.T) {
	group := "00112233445566778899aabbccddeeff"
	canonical := []byte(`{"group":"` + group + `","index":"42"}`)
	var got Cursor
	if n := testing.AllocsPerRun(200, func() {
		if err := got.UnmarshalJSON(canonical); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatalf("decoding one canonical cursor allocated %v times", n)
	}
	if got.Group != mustHexID(group) || got.Index != 42 {
		t.Fatalf("decoded %+v", got)
	}
	general := func(raw string) (Cursor, error) { // what the decoder was before the canonical form was decoded in place
		var wire struct {
			Group ID      `json:"group"`
			Index *Uint64 `json:"index"`
		}
		if err := json.Unmarshal([]byte(raw), &wire); err != nil {
			return Cursor{}, err
		}
		if wire.Index == nil {
			return Cursor{}, errors.New("cursor index required")
		}
		return Cursor{Group: wire.Group, Index: *wire.Index}, nil
	}
	inputs := []string{
		string(canonical),
		`{"index":"42","group":"` + group + `"}`,
		`{"group":"` + group + `", "index":"42"}`,
		`{"group":"` + group + `","index":"42","extra":"x"}`,
		`{"group":"` + group + `"}`,
		`{"group":"` + group + `","index":"042"}`,
		`{"group":"` + group + `","index":42}`,
		`{"group":"` + group + `","index":"18446744073709551616"}`,
		`{"group":"` + strings.Repeat("0", 32) + `","index":"1"}`,
		`{"group":"` + strings.ToUpper(group) + `","index":"1"}`,
		`{"group":"` + group + `","index":"1"`,
		`{"group":"` + group + `","index":"1"}}`,
		`{"group":"` + group + `","index":""}`,
		`null`,
		`{}`,
	}
	for _, in := range inputs {
		var c Cursor
		err := c.UnmarshalJSON([]byte(in))
		wantC, wantErr := general(in)
		if (err == nil) != (wantErr == nil) || c != wantC && wantErr == nil {
			t.Errorf("%s: decoder says (%v, %+v), general path says (%v, %+v)", in, err, c, wantErr, wantC)
		}
	}
}
