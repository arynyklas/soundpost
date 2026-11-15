// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	bolt "go.etcd.io/bbolt"
)

func faultOf(t *testing.T, err error) *model.Fault {
	t.Helper()
	var f *model.Fault
	if !errors.As(err, &f) {
		t.Fatalf("not a typed fault: %v", err)
	}
	return f
}

// The envelope round-trips to the same command the JSON form carries, and the JSON the stored
// command is written as is byte for byte the same either way.
func TestFragmentEnvelopeRoundTripsToTheJSONCommand(t *testing.T) {
	for name, e := range map[string]walEntry{
		"empty tail": fragmentWAL('a', 0),
		"small":      fragmentWAL('b', 1),
		"full":       fragmentWAL('c', model.ArtifactFragmentLimit-len("<&>\u2028\n\"\\é")),
	} {
		raw, ok, err := encodeFragmentEnvelope(e)
		if err != nil || !ok || !isEnvelope(raw) {
			t.Fatalf("%s: encode: ok %v err %v", name, ok, err)
		}
		got, err := decodeWAL(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Fatalf("%s: the envelope decodes to another command", name)
		}
		fromEnvelope, err := encodeWAL(got)
		if err != nil {
			t.Fatal(err)
		}
		jsonForm, err := encodeWAL(e)
		if err != nil || !bytes.Equal(fromEnvelope, jsonForm) {
			t.Fatalf("%s: stored JSON differs by wire form: %v", name, err)
		}
		if len(raw) >= len(jsonForm) {
			t.Fatalf("%s: envelope %d bytes is not smaller than JSON %d", name, len(raw), len(jsonForm))
		}
	}
}

// Anything the envelope does not carry stays JSON, and the dual reader still reads every JSON
// command, including the golden fragment e805349 wrote.
func TestDualFormatReaderReadsOldRecords(t *testing.T) {
	nilBytes := fragmentWAL('n', 0)
	nilBytes.Artifact.Bytes = nil
	rejection := model.NewID()
	for name, e := range map[string]walEntry{"nil bytes": nilBytes, "rejected": {Type: "rejected", Rejection: &rejection}} {
		if _, ok, err := encodeFragmentEnvelope(e); ok || err != nil {
			t.Fatalf("%s: envelope took a command it does not carry (%v, %v)", name, ok, err)
		}
	}
	old, err := os.ReadFile("testdata/e805349/wal_fragment.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeWAL(old)
	if err != nil || got.Artifact == nil || got.Artifact.Ordinal != 3 {
		t.Fatalf("a JSON record the previous build wrote no longer reads: %v", err)
	}
	if again, err := encodeWAL(got); err != nil || !bytes.Equal(again, old) {
		t.Fatalf("an old record re-encodes to other bytes: %v", err)
	}
	// And carried in the envelope it is the same command.
	env, ok, err := encodeFragmentEnvelope(got)
	if err != nil || !ok {
		t.Fatalf("old record not envelope-encodable: %v", err)
	}
	if back, err := decodeWAL(env); err != nil || !reflect.DeepEqual(back, got) {
		t.Fatalf("old record through the envelope: %v", err)
	}
}

// A reader that predates the envelope runs decodeWALJSON on every payload. It refuses an
// envelope with the typed Corrupt fault, never misreads it; the new reader names an unknown
// version and refuses torn, altered and padded envelopes.
func TestEnvelopeRefusals(t *testing.T) {
	raw, _, err := encodeFragmentEnvelope(fragmentWAL('r', 1024))
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeWALJSON(raw)
	if f := faultOf(t, err); f.Code != model.Corrupt {
		t.Fatalf("an older reader answered %s, want corrupt", f.Code)
	}
	mutate := func(f func([]byte) []byte) []byte { return f(bytes.Clone(raw)) }
	for name, mutated := range map[string][]byte{
		"flipped fragment byte": mutate(func(b []byte) []byte { b[len(b)-1] ^= 1; return b }),
		"flipped hash byte": mutate(func(b []byte) []byte {
			headLen := int(b[5])<<24 | int(b[6])<<16 | int(b[7])<<8 | int(b[8])
			b[9+headLen] ^= 1
			return b
		}),
		"truncated":        raw[:len(raw)-1],
		"padded":           append(bytes.Clone(raw), 0),
		"only the magic":   raw[:4],
		"header cut short": raw[:12],
	} {
		if _, err := decodeWAL(mutated); faultOf(t, err).Code != model.Corrupt {
			t.Fatalf("%s: %v, want corrupt", name, err)
		}
	}
	future := bytes.Clone(raw)
	future[4] = envelopeVersion + 1
	_, err = decodeWAL(future)
	if f := faultOf(t, err); f.Code != model.Invalid || f.SafeDetail != envelopeUnsupported {
		t.Fatalf("an unknown version answered %s/%s", f.Code, f.SafeDetail)
	}
}

// Mixed proposers: a leader that writes JSON, then envelopes, then JSON again leaves every voter
// with the same verified artifacts and the same stored command bytes, all JSON, whatever form
// carried each fragment (the stored form is always encodeWAL's).
func TestMixedFormatProposersLeaveIdenticalState(t *testing.T) {
	x := newBlobOnVoters(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	leader := x.v.engines[1]
	next := func(on bool) (model.BlobManifest, model.BlobReceipt) {
		t.Helper()
		m := orphanManifest(t, x.store, x.scope, x.manifest)
		x.v.lead(t, func(int) uint64 { return 1 })
		leader.EnableFragmentEnvelope(on)
		r, err := leader.WriteBlob(ctx, x.scope, m, bytes.NewReader(x.raw))
		if err != nil {
			t.Fatal(err)
		}
		return m, r
	}
	before := leader.envelopesProposed.Load()
	_, jsonReceipt := next(false)
	if leader.envelopesProposed.Load() != before {
		t.Fatal("an engine with the envelope off proposed one")
	}
	envManifest, envReceipt := next(true)
	if got := leader.envelopesProposed.Load() - before; got != uint64(len(envReceipt.Fragments)) {
		t.Fatalf("%d envelope proposals for %d fragments", got, len(envReceipt.Fragments))
	}
	_, afterReceipt := next(false)
	leader.EnableFragmentEnvelope(false)
	x.v.converge(t, nil)
	for node := uint64(1); node <= 3; node++ {
		e := x.v.engines[node]
		for name, r := range map[string]model.BlobReceipt{"json": jsonReceipt, "envelope": envReceipt, "json again": afterReceipt} {
			if err := e.VerifyBlob(ctx, r); err != nil {
				t.Fatalf("voter %d cannot verify the %s artifact: %v", node, name, err)
			}
		}
		_ = e.db.View(func(tx *bolt.Tx) error {
			for _, f := range envReceipt.Fragments {
				raw := tx.Bucket([]byte("replica_commands")).Get(commandKey(model.BlobOwnerSlot(envManifest.Org, envManifest.Project, envManifest.Root), uint64(f.Cursor.Index)))
				if len(raw) == 0 || raw[0] != '{' {
					t.Fatalf("voter %d stores an envelope fragment as %.8q, want JSON text", node, raw)
				}
				entry, err := decodeWALJSON(raw)
				if err != nil || entry.Artifact == nil || entry.Artifact.Hash != f.Hash {
					t.Fatalf("voter %d: stored envelope fragment: %v", node, err)
				}
			}
			return nil
		})
	}
	// Every voter holds identical fragment bytes for the artifact the envelope carried.
	for i := range envReceipt.Fragments {
		a, b, c := x.holds(1, envManifest, uint32(i)), x.holds(2, envManifest, uint32(i)), x.holds(3, envManifest, uint32(i))
		if len(a) == 0 || !bytes.Equal(a, b) || !bytes.Equal(a, c) {
			t.Fatalf("fragment %d differs between voters", i)
		}
	}
}
