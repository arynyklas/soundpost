// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func fragmentWAL(fill byte, size int) walEntry {
	b := bytes.Repeat([]byte{fill}, size)
	b = append(b, []byte("<&>\u2028\n\"\\é")...)
	f := model.ArtifactFragment{Ordinal: 3, Bytes: b, Hash: model.HashCanonical(b), Cursor: model.Cursor{Group: model.NewID(), Index: 9}}
	fillIDs(reflect.ValueOf(&f).Elem())
	return walEntry{Type: "artifact_fragment", Artifact: &f}
}

// fillIDs gives every zero model.ID in v a fresh value (the model refuses to encode a zero ID).
func fillIDs(v reflect.Value) {
	switch {
	case v.Type() == reflect.TypeOf(model.ID{}):
		if v.Interface().(model.ID) == (model.ID{}) {
			v.Set(reflect.ValueOf(model.NewID()))
		}
	case v.Kind() == reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				fillIDs(v.Field(i))
			}
		}
	case v.Kind() == reflect.Pointer && !v.IsNil():
		fillIDs(v.Elem())
	}
}

func walCodecCorpus(t *testing.T) map[string][]byte {
	t.Helper()
	rej := model.NewID()
	enc := func(e walEntry) []byte {
		raw, err := oracleWAL(e) // the pre-change encoding: encoding/json over the stored form
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	frag := enc(fragmentWAL('a', 1000))
	return map[string][]byte{
		"fragment":      frag,
		"rejected":      enc(walEntry{Type: "rejected", Rejection: &rej}),
		"padded":        append([]byte("\n "), append(bytes.Clone(frag), '\n')...),
		"type mismatch": []byte(strings.Replace(string(frag), `"artifact_fragment"`, `"fence"`, 1)),
		"unknown field": []byte(strings.Replace(string(frag), `{"type"`, `{"zz":1,"type"`, 1)),
		"duplicate key": []byte(strings.Replace(string(frag), `{"type":"artifact_fragment"`, `{"type":"artifact_fragment","type":"artifact_fragment"`, 1)),
		"no arm":        []byte(`{"type":"artifact_fragment"}`),
		"two arms":      []byte(strings.Replace(string(frag), `{"type"`, `{"rejection":"`+rej.String()+`","type"`, 1)),
		"truncated":     frag[:len(frag)/2],
		"trailing":      append(bytes.Clone(frag), '{', '}'),
		"null":          []byte(`null`),
		"empty":         []byte(``),
		"bad utf8":      []byte("{\"type\":\"a\xffb\"}"),
	}
}

// The slimmed codec must write the same bytes and accept and refuse the same inputs as the
// json.Marshal / json.Unmarshal path it replaced, which is how every journal entry on disk was written.
func TestWALCodecMatchesTheJSONPackagePath(t *testing.T) {
	for _, e := range []walEntry{fragmentWAL('a', 0), fragmentWAL('b', 256<<10), fragmentWAL(0xff, 1), nastyFragment(fillOpts{text: nastyValid, slices: 2}, 100), nastyFragment(fillOpts{text: nastyValid}, 0)} {
		want, err := oracleWAL(e)
		if err != nil {
			t.Fatal(err)
		}
		got, err := encodeWAL(e)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("encodeWAL differs from encoding/json (len %d vs %d, %v)", len(got), len(want), err)
		}
		back, err := decodeWAL(got)
		if err != nil || !reflect.DeepEqual(back, e) {
			t.Fatalf("decodeWAL(encodeWAL(e)) != e: %v", err)
		}
	}
	accepted := 0
	for name, raw := range walCodecCorpus(t) {
		var want walEntry
		wantErr := json.Unmarshal(raw, &want)
		got, gotErr := decodeWAL(raw)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("%s: json.Unmarshal err=%v, decodeWAL err=%v", name, wantErr, gotErr)
		}
		if wantErr == nil {
			accepted++
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("%s: decodeWAL differs from json.Unmarshal", name)
			}
		}
	}
	if accepted < 3 {
		t.Fatalf("only %d corpus entries accepted", accepted)
	}
}

// Validate hands its decoded fragment to Apply only for a byte-identical payload.
func TestSlotMachineDecodeReusesOnlyIdenticalPayload(t *testing.T) {
	m := &slotMachine{}
	e := fragmentWAL('a', 4096)
	payload, err := encodeWAL(e)
	if err != nil {
		t.Fatal(err)
	}
	m.validated.payload, m.validated.entry = bytes.Clone(payload), e
	got, err := m.decode(payload)
	if err != nil || got.Artifact != e.Artifact {
		t.Fatalf("an identical payload was not served from the validated slot: %v", err)
	}
	// One flipped byte inside the base64 of the fragment: decoded afresh, never the cached entry.
	flipped := bytes.Clone(payload)
	i := bytes.Index(flipped, []byte(`"bytes":"`)) + len(`"bytes":"`) + 10
	if flipped[i] == 'A' {
		flipped[i] = 'B'
	} else {
		flipped[i] = 'A'
	}
	got, err = m.decode(flipped)
	if err == nil && (got.Artifact == e.Artifact || bytes.Equal(got.Artifact.Bytes, e.Artifact.Bytes)) {
		t.Fatal("a payload that differs in one byte was answered from the validated slot")
	}
	// A refused payload of the same length is refused, with the slot untouched.
	broken := bytes.Clone(payload)
	broken[len(broken)-1] = 'x'
	if _, err = m.decode(broken); err == nil {
		t.Fatal("a corrupt payload was accepted")
	}
	if again, err := m.decode(payload); err != nil || again.Artifact != e.Artifact {
		t.Fatalf("the slot did not survive a refusal: %v", err)
	}
}

// The journal entries below were written by the binary of commit e805349 (json.Marshal over
// walEntry, in commitReplicated), by a generator test run in a clean `git archive e805349` tree.
// testdata/e805349/wal_sha256.json records the SHA-256 the generator observed for each file. The
// current codec must read them, and write exactly the same bytes back.
func TestGoldenWALEntriesOfE805349ReadBack(t *testing.T) {
	var sums map[string]string
	raw, err := os.ReadFile("testdata/e805349/wal_sha256.json")
	if err != nil || json.Unmarshal(raw, &sums) != nil || len(sums) != 3 {
		t.Fatalf("golden checksums: %v %v", sums, err)
	}
	read := func(name string) (walEntry, []byte) {
		t.Helper()
		raw, err := os.ReadFile("testdata/e805349/wal_" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != sums[name] {
			t.Fatalf("%s is not the bytes e805349 wrote", name)
		}
		got, err := decodeWAL(raw)
		if err != nil {
			t.Fatalf("%s: the current decoder refuses what e805349 wrote: %v", name, err)
		}
		var ref walEntry
		if err = json.Unmarshal(raw, &ref); err != nil || !reflect.DeepEqual(ref, got) {
			t.Fatalf("%s: decodeWAL differs from json.Unmarshal (%v)", name, err)
		}
		again, err := encodeWAL(got)
		if err != nil || !bytes.Equal(again, raw) {
			t.Fatalf("%s: the current encoder does not reproduce the bytes e805349 wrote (len %d vs %d, %v)", name, len(again), len(raw), err)
		}
		return got, raw
	}
	batch, _ := read("batch")
	if batch.Type != "batch" || batch.Batch == nil || len(batch.Batch.Records) != 1 {
		t.Fatalf("batch entry: %+v", batch)
	}
	if c := batch.Batch.Records[0].Payload.Replay; c == nil || c.Sequence != 2 || c.CheckpointSequence != 1 || len(c.Nodes) != 1 || c.Nodes[0].Text != "[masked]" || batch.Batch.PolicyEpoch != 3 {
		t.Fatalf("the replay chunk of the old batch entry read back wrong: %+v", batch.Batch.Records[0].Payload.Replay)
	}
	fragment, _ := read("fragment")
	if fragment.Type != "artifact_fragment" || fragment.Artifact == nil || fragment.Artifact.Ordinal != 3 || len(fragment.Artifact.Bytes) != 300+len("<&>\u2028\n\"\\é") || fragment.Artifact.Hash != model.HashCanonical(fragment.Artifact.Bytes) {
		t.Fatalf("fragment entry: %+v", fragment.Artifact)
	}
	rejected, _ := read("rejected")
	if rejected.Type != "rejected" || rejected.Rejection == nil || *rejected.Rejection != (model.ID{0xa0, 15: 0xee}) {
		t.Fatalf("rejected entry: %+v", rejected)
	}
}
