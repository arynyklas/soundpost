// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"soundpost/internal/model"
)

func entryDecodeCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	id := model.NewID()
	res := model.NewID()
	good := func(e Entry) []byte {
		raw, err := json.Marshal(e) // the encoding the journal and the proposer have always used
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	plain := Entry{ID: id, Kind: Artifact, Payload: []byte(`{"type":"artifact_fragment"}`), ApplicationIndex: 7}
	withRes := Entry{ID: id, Kind: Data, Payload: bytes.Repeat([]byte("<&>\u00e9"), 5000), ReservationID: &res, ApplicationIndex: 1 << 40}
	orig := model.HashCanonical([]byte("x"))
	redacted := Entry{ID: id, Kind: Data, Payload: []byte("r"), Original: &orig, ApplicationIndex: 3}
	idText := id.String()
	return map[string][]byte{
		"plain":            good(plain),
		"reservation":      good(withRes),
		"redacted":         good(redacted),
		"padded":           append([]byte(" \n"), append(good(plain), ' ', '\n')...),
		"unknown field":    []byte(`{"id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":"1","extra":1}`),
		"duplicate key":    []byte(`{"id":"` + idText + `","id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":"1"}`),
		"numeric index":    []byte(`{"id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":1}`),
		"leading zero":     []byte(`{"id":"` + idText + `","kind":"artifact","payload":"eA==","application_index":"01"}`),
		"bad base64":       []byte(`{"id":"` + idText + `","kind":"artifact","payload":"e","application_index":"1"}`),
		"trailing data":    append(good(plain), []byte(` {}`)...),
		"trailing garbage": append(good(plain), 'x'),
		"truncated":        good(plain)[:20],
		"null":             []byte(`null`),
		"array":            []byte(`[]`),
		"empty":            []byte(``),
		"bad utf8":         []byte("{\"id\":\"" + idText + "\",\"kind\":\"ar\xfftifact\",\"payload\":\"eA==\",\"application_index\":\"1\"}"),
		"lone surrogate":   []byte(`{"id":"` + idText + `","kind":"\ud800","payload":"eA==","application_index":"1"}`),
		"deep":             []byte(strings.Repeat(`[`, 70) + strings.Repeat(`]`, 70)),
		"unknown kind":     []byte(`{"id":"` + idText + `","kind":"nope","payload":"eA==","application_index":"1"}`),
		"zero id":          []byte(`{"id":"00000000000000000000000000000000","kind":"artifact","payload":"eA==","application_index":"1"}`),
		"empty payload":    []byte(`{"id":"` + idText + `","kind":"artifact","payload":"","application_index":"1"}`),
	}
}

// decodeEntry must accept and refuse exactly what model.StrictJSON(data, &Entry) does, and return
// the same Entry for what it accepts.
func TestDecodeEntryMatchesNestedStrictJSON(t *testing.T) {
	accepted := 0
	for name, raw := range entryDecodeCorpus(t) {
		var want Entry
		wantErr := model.StrictJSON(raw, &want)
		got, gotErr := decodeEntry(raw)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%s: reference err=%v, decodeEntry err=%v", name, wantErr, gotErr)
		}
		if wantErr != nil {
			continue
		}
		accepted++
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: decodeEntry differs from the reference\n got  %+v\n want %+v", name, got, want)
		}
		g := &Group{}
		cached, cerr := g.decodeEntry(raw)
		if (cerr == nil) != want.valid() || cerr == nil && !reflect.DeepEqual(cached, want) {
			t.Fatalf("%s: Group.decodeEntry err=%v valid=%v", name, cerr, want.valid())
		}
	}
	if accepted < 4 {
		t.Fatalf("the corpus accepted only %d inputs: it no longer proves equality", accepted)
	}
}

// The reuse is keyed by the identity of the Raft data slice. A different slice with the same
// length and different (or corrupt) bytes is decoded and refused on its own.
func TestGroupDecodeEntryReuseIsByIdentityOnly(t *testing.T) {
	good := entryDecodeCorpus(t)["plain"]
	g := &Group{}
	first, err := g.decodeEntry(good)
	if err != nil {
		t.Fatal(err)
	}
	again, err := g.decodeEntry(good)
	if err != nil || !reflect.DeepEqual(first, again) {
		t.Fatalf("same slice: %v", err)
	}
	// Same length, same first byte address class, but a corrupt copy.
	corrupt := bytes.Clone(good)
	corrupt[len(corrupt)/2] ^= 0x01
	if _, err = g.decodeEntry(corrupt); err == nil {
		if bytes.Equal(corrupt, good) {
			t.Fatal("test did not corrupt")
		}
		var ref Entry
		if model.StrictJSON(corrupt, &ref) != nil || !ref.valid() {
			t.Fatal("a corrupt entry was served from the reuse slot")
		}
	}
	// A refusal must not poison the slot: the corrupt bytes are refused every time.
	bad := entryDecodeCorpus(t)["unknown field"]
	for range 2 {
		if _, err = g.decodeEntry(bad); err == nil {
			t.Fatal("an entry with an unknown field was accepted")
		}
	}
	// A different valid entry of the same length is not answered with the first one.
	other := bytes.Clone(good)
	other[bytes.Index(other, []byte(`"application_index":"7"`))+len(`"application_index":"`)] = '8'
	got, err := g.decodeEntry(other)
	if err != nil || got.ApplicationIndex != 8 {
		t.Fatalf("same-length different entry: index %d err %v", got.ApplicationIndex, err)
	}
}
