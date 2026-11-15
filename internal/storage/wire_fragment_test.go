// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

func fragmentFields(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		out = append(out, f.Name+" "+f.Type.String()+" `"+string(f.Tag)+"`")
	}
	return out
}

// encodeFragmentJSON assembles a fragment from a head, its bytes and a tail; a fragment that gains
// a member has to gain it there too, or the stored command would silently stop carrying it.
func TestFragmentHeadAndTailCoverArtifactFragment(t *testing.T) {
	want := fragmentFields(reflect.TypeOf(model.ArtifactFragment{}))
	got := append(fragmentFields(reflect.TypeOf(fragmentHead{})), want[3])
	got = append(got, fragmentFields(reflect.TypeOf(fragmentTail{}))...)
	if !reflect.DeepEqual(want, got) || len(want) != 6 || want[3][:5] != "Bytes" {
		t.Fatalf("ArtifactFragment members\n%q\nare not fragmentHead + bytes + fragmentTail\n%q", want, got)
	}
}

// The stored form of a fragment command is json.Marshal(entry): the same bytes, assembled once.
func TestEncodeFragmentJSONMatchesJSONMarshal(t *testing.T) {
	nilBytes, emptyBytes := fragmentWAL('n', 0), fragmentWAL('e', 0)
	nilBytes.Artifact.Bytes, emptyBytes.Artifact.Bytes = nil, []byte{}
	for name, e := range map[string]walEntry{
		"empty":       fragmentWAL('a', 0),
		"small":       fragmentWAL('b', 1),
		"full":        fragmentWAL('c', 256<<10),
		"nil bytes":   nilBytes,
		"empty bytes": emptyBytes,
	} {
		want, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		got, ok, err := encodeFragmentJSON(e)
		if err != nil || !ok || !bytes.Equal(got, want) {
			t.Fatalf("%s: encodeFragmentJSON differs from json.Marshal (len %d vs %d, ok %v, %v)", name, len(got), len(want), ok, err)
		}
		if cap(got) != len(got) {
			t.Fatalf("%s: output buffer is %d for %d bytes of text", name, cap(got), len(got))
		}
		generic, err := encodeWAL(e)
		if err != nil || !bytes.Equal(generic, want) {
			t.Fatalf("%s: encodeWAL differs from json.Marshal: %v", name, err)
		}
	}
}

// Anything but a plain fragment entry takes the generic path, which already is json.Marshal's bytes.
func TestEncodeFragmentJSONLeavesOtherEntriesToTheGenericPath(t *testing.T) {
	plain := fragmentWAL('a', 64)
	withProposer := plain
	withProposer.Proposer = &replica.Proposer{Node: 1, Identity: "n"}
	wrongType := plain
	wrongType.Type = "fence"
	rejection := model.NewID()
	for name, e := range map[string]walEntry{
		"no artifact":   {Type: "artifact_fragment"},
		"proposer":      withProposer,
		"wrong type":    wrongType,
		"rejection":     {Type: "rejected", Rejection: &rejection},
		"two arms":      {Type: "artifact_fragment", Artifact: plain.Artifact, Rejection: &rejection},
		"commit set":    {Type: "artifact_fragment", Artifact: plain.Artifact, CommitSet: &replica.CommitSetWatermark{}},
		"batch missing": {Type: "batch"},
	} {
		if _, ok, err := encodeFragmentJSON(e); ok || err != nil {
			t.Fatalf("%s: encodeFragmentJSON took an entry it does not encode (ok %v, %v)", name, ok, err)
		}
		want, wantErr := json.Marshal(e)
		got, err := encodeWAL(e)
		if (wantErr == nil) != (err == nil) || err == nil && !bytes.Equal(got, want) {
			t.Fatalf("%s: encodeWAL differs from json.Marshal (%v vs %v)", name, err, wantErr)
		}
	}
}

// The fast path names the walEntry members it requires to be absent. A member added to walEntry later
// would pass that list unseen and be dropped from the journal; every member other than Type and
// Artifact, set on an otherwise plain fragment entry, must send it to the generic path.
func TestEveryOtherWalEntryMemberDisablesTheFragmentFastPath(t *testing.T) {
	typ := reflect.TypeOf(walEntry{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		if f.Name == "Type" || f.Name == "Artifact" {
			continue
		}
		e := fragmentWAL('a', 64)
		v := reflect.ValueOf(&e).Elem().Field(i)
		switch v.Kind() {
		case reflect.Pointer:
			v.Set(reflect.New(v.Type().Elem()))
		case reflect.Slice:
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		case reflect.Map:
			v.Set(reflect.MakeMap(v.Type()))
		case reflect.String:
			v.SetString("x")
		case reflect.Bool:
			v.SetBool(true)
		case reflect.Int, reflect.Int64, reflect.Int32, reflect.Uint, reflect.Uint64, reflect.Uint32:
			if v.CanInt() {
				v.SetInt(1)
			} else {
				v.SetUint(1)
			}
		default:
			t.Fatalf("walEntry.%s has kind %s: teach this test how to set it", f.Name, v.Kind())
		}
		if _, ok, err := encodeFragmentJSON(e); ok || err != nil {
			t.Fatalf("walEntry.%s set on a fragment entry still takes the fragment fast path (ok %v, %v): it would be dropped from the journal", f.Name, ok, err)
		}
	}
}
