// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// Tests for the mutants the 01.09 review reported as surviving (see
// l1w18-evidence/backup-survivors-report.md for the id -> test table).

// forgeFirstFormat writes one signed, sealed first-format head record (the whole ledger) after
// letting tweak change the record before it is signed, and encodes it indented when pretty (the
// signature covers the compact form, so only the canonical-encoding check can tell).
func (a *Authority) forgeFirstFormat(ctx context.Context, tb testing.TB, authority model.ID, sequence uint64, prev model.Hash, installation model.ID, tombstones []model.DeletePredicate, tweak func(*headRecord), pretty bool) model.Hash {
	tb.Helper()
	g := generation(installation, sequence, tombstones...)
	plain, err := json.Marshal(headPayload{Ledger: g.Ledger, Tombstones: g.Tombstones})
	if err != nil {
		tb.Fatal(err)
	}
	aead, err := a.keys.seal.aead()
	if err != nil {
		tb.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		tb.Fatal(err)
	}
	rec := headRecord{Version: authorityFormat, Authority: authority, Sequence: sequence, Prev: prev, Generation: g.Generation, Tombstones: uint64(len(tombstones)), Payload: digestOf(plain), At: model.UnixNano(a.now().UnixNano()), KeyID: a.keys.ID, Nonce: nonce}
	rec.Sealed = aead.Seal(nil, nonce, plain, payloadAAD(authority, sequence, prev, g.Generation))
	if tweak != nil {
		tweak(&rec)
	}
	if rec.Signature, err = a.sign(rec); err != nil {
		tb.Fatal(err)
	}
	var raw []byte
	if pretty {
		raw, err = json.MarshalIndent(rec, "", "  ")
	} else {
		raw, err = json.Marshal(rec)
	}
	if err != nil {
		tb.Fatal(err)
	}
	if err = a.dest.Create(ctx, headName(sequence), bytes.NewReader(raw), int64(len(raw))); err != nil {
		tb.Fatal(err)
	}
	return digestOf(raw)
}

// A record of the journal must itself name the key the journal is signed under; the root's own
// key id is a separate statement. A genuine, correctly signed record that names another key is
// not part of this journal (D6/X7/H1).
func TestAuthorityRefusesARecordNamingAnotherKey(t *testing.T) {
	ctx := context.Background()
	for name, keyID := range map[string]string{"the same key": "", "another key": "authority-key-2"} {
		f := newAuthFixture(t)
		f.initialize()
		root, err := f.a.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t1 := tombstone(model.NewID(), model.NewID(), 10, 15)
		f.a.forgeFirstFormat(ctx, t, root.Head.Authority, 1, root.Head.Digest, f.installation, []model.DeletePredicate{t1}, func(r *headRecord) {
			if keyID != "" {
				r.KeyID = keyID
			}
		}, false)
		_, err = f.a.Current(ctx)
		if keyID == "" && err != nil {
			t.Fatalf("%s: the control record was refused: %v", name, err)
		}
		if keyID != "" && faultCode(err) != model.Corrupt {
			t.Fatalf("%s: a record naming another key was read as authority: %v", name, err)
		}
	}
}

// A first-format record holds the whole ledger, so it may only add to what the head before it
// held: a record that forgot a tombstone is a forgotten deletion, even when its own ledger is
// internally valid and signed (X3/H3).
func TestAuthorityRefusesAFirstFormatRecordThatForgotATombstone(t *testing.T) {
	ctx := context.Background()
	t1, t2 := tombstone(model.NewID(), model.NewID(), 10, 15), tombstone(model.NewID(), model.NewID(), 20, 25)
	for name, second := range map[string][]model.DeletePredicate{"keeps it": {t1, t2}, "forgets it": {t2}} {
		f := newAuthFixture(t)
		f.initialize()
		root, err := f.a.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		prev := f.a.forgeFirstFormat(ctx, t, root.Head.Authority, 1, root.Head.Digest, f.installation, []model.DeletePredicate{t1}, nil, false)
		f.a.forgeFirstFormat(ctx, t, root.Head.Authority, 2, prev, f.installation, second, nil, false)
		_, err = f.a.Current(ctx)
		if name == "keeps it" && err != nil {
			t.Fatalf("an honest journal was refused: %v", err)
		}
		if name == "forgets it" && faultCode(err) != model.Corrupt {
			t.Fatalf("a record that forgot a deletion was read as authority: %v", err)
		}
	}
}

// The record states how many tombstones the ledger holds after it; the sealed payload must agree (C15).
func TestAuthorityRefusesAFirstFormatRecordWithAWrongTombstoneCount(t *testing.T) {
	ctx := context.Background()
	for name, total := range map[string]uint64{"honest": 1, "overstated": 2, "understated": 0} {
		f := newAuthFixture(t)
		f.initialize()
		root, err := f.a.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f.a.forgeFirstFormat(ctx, t, root.Head.Authority, 1, root.Head.Digest, f.installation, []model.DeletePredicate{tombstone(model.NewID(), model.NewID(), 10, 15)}, func(r *headRecord) { r.Tombstones = total }, false)
		_, err = f.a.Current(ctx)
		if total == 1 && err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if total != 1 && faultCode(err) != model.Corrupt {
			t.Fatalf("%s: a record whose count disagrees with its payload was read as authority: %v", name, err)
		}
	}
}

// The record carries the digest of the sealed payload it signed; a payload that decrypts under the
// right key and AAD but is not the one the record names is refused (C14).
func TestAuthorityRefusesARecordWhoseSealedPayloadIsNotTheOneItNames(t *testing.T) {
	ctx := context.Background()
	for _, honest := range []bool{true, false} {
		f := newAuthFixture(t)
		f.initialize()
		root, err := f.a.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f.a.forgeFirstFormat(ctx, t, root.Head.Authority, 1, root.Head.Digest, f.installation, []model.DeletePredicate{tombstone(model.NewID(), model.NewID(), 10, 15)}, func(r *headRecord) {
			if !honest {
				r.Payload = digestOf([]byte("some other payload"))
			}
		}, false)
		_, err = f.a.Current(ctx)
		if honest && err != nil {
			t.Fatalf("an honest record was refused: %v", err)
		}
		if !honest && faultCode(err) != model.Corrupt {
			t.Fatalf("a record whose payload digest is not the sealed payload's was read as authority: %v", err)
		}
	}
}

// Only the exact encoding this package writes is a record: the same signed content with other
// whitespace verifies (the signature covers the compact form) but is a different file (H5).
func TestAuthorityRefusesANonCanonicalHeadRecord(t *testing.T) {
	ctx := context.Background()
	for _, pretty := range []bool{false, true} {
		f := newAuthFixture(t)
		f.initialize()
		root, err := f.a.Current(ctx)
		if err != nil {
			t.Fatal(err)
		}
		f.a.forgeFirstFormat(ctx, t, root.Head.Authority, 1, root.Head.Digest, f.installation, []model.DeletePredicate{tombstone(model.NewID(), model.NewID(), 10, 15)}, nil, pretty)
		_, err = f.a.Current(ctx)
		if !pretty && err != nil {
			t.Fatalf("the canonical record was refused: %v", err)
		}
		if pretty && faultCode(err) != model.Corrupt {
			t.Fatalf("a re-spelled head record was read as authority: %v", err)
		}
	}
}

// onceCorruptDest returns altered bytes the first time name is opened and the true bytes every time after.
type onceCorruptDest struct {
	Destination
	name string
	hit  atomic.Bool
}

func (d *onceCorruptDest) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	rc, err := d.Destination.Open(ctx, name)
	if err != nil || name != d.name || !d.hit.CompareAndSwap(false, true) {
		return rc, err
	}
	raw, _ := io.ReadAll(rc)
	rc.Close()
	raw[len(raw)/2] ^= 1
	return io.NopCloser(bytes.NewReader(raw)), nil
}

// CheckpointDeletion returns a receipt only after the stored bytes read back are the bytes it
// wrote. That read-back is its own proof: the verification of the whole chain that follows reads
// the destination again and could pass on a later, healthier read (H2).
func TestCheckpointNeverReturnsAReceiptForBytesThatReadBackDifferently(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	dest := &onceCorruptDest{Destination: f.dest, name: headName(1)}
	a := f.open(dest, f.keys)
	if _, err := a.Initialize(ctx, f.installation); err != nil {
		t.Fatal(err)
	}
	_, err := a.CheckpointDeletion(ctx, generation(f.installation, 1, tombstone(model.NewID(), model.NewID(), 10, 15)))
	if faultCode(err) != model.Unavailable {
		t.Fatalf("a checkpoint whose read-back differed returned a receipt or the wrong error: %v", err)
	}
	if !dest.hit.Load() {
		t.Fatal("fixture: the read-back never happened")
	}
}

// A key without the signing half cannot create the authority root: it is refused before the
// destination is touched, not left to fail later (D12).
func TestRestrictedKeysCannotInitializeAnAuthority(t *testing.T) {
	ctx := context.Background()
	f := newAuthFixture(t)
	counted := &countingWrites{Destination: f.dest}
	restricted := f.open(counted, f.keys.Restricted())
	if _, err := restricted.Initialize(ctx, f.installation); faultCode(err) != model.Forbidden {
		t.Fatalf("a verification-only key initialized an authority: %v", err)
	}
	if counted.creates.Load() != 0 {
		t.Fatalf("a refused initialize wrote %d objects", counted.creates.Load())
	}
	if names, _ := f.dest.List(ctx, ""); len(names) != 0 {
		t.Fatalf("a refused initialize left %v", names)
	}
}

type countingWrites struct {
	Destination
	creates atomic.Int64
}

func (d *countingWrites) Create(ctx context.Context, name string, r io.Reader, size int64) error {
	d.creates.Add(1)
	return d.Destination.Create(ctx, name, r, size)
}

func validManifestForTest() BackupManifest {
	id := model.NewID()
	cursors := func() []model.Cursor {
		out := make([]model.Cursor, 64)
		for i := range out {
			out[i].Group = model.NewID()
		}
		return out
	}
	return BackupManifest{
		Version: ManifestVersion, ID: id, CreatedAt: 1, ExpiresAt: 2,
		Control:  ControlBinding{Installation: model.NewID()},
		Data:     DataBinding{Identity: model.NewID(), Applied: cursors(), Processed: cursors()},
		Deletion: AuthorityBinding{Authority: model.NewID()},
		Encryption: Encryption{Algorithm: AlgorithmAES256GCM, ChunkSize: DefaultChunkSize, Keys: []KeyRef{
			{ID: id.String() + "-data", Purpose: ClassData, KEK: "data-kek", Object: "keys/a"},
			{ID: id.String() + "-keys", Purpose: ClassKeys, KEK: "secret-kek", Object: "keys/b"},
		}},
	}
}

// The manifest's own structure is checked on its own: the algorithm it names is the only one
// there is (D14), and it carries exactly one wrapped key for each of the two purposes (C2).
func TestManifestStructureIsValidatedByItself(t *testing.T) {
	if err := validManifestForTest().validate(); err != nil {
		t.Fatalf("fixture manifest invalid: %v", err)
	}
	cases := map[string]func(m *BackupManifest){
		"another algorithm":    func(m *BackupManifest) { m.Encryption.Algorithm = "aes-128-cbc" },
		"no algorithm":         func(m *BackupManifest) { m.Encryption.Algorithm = "" },
		"only the data key":    func(m *BackupManifest) { m.Encryption.Keys = m.Encryption.Keys[:1] },
		"only the secrets key": func(m *BackupManifest) { m.Encryption.Keys = m.Encryption.Keys[1:] },
		"no keys":              func(m *BackupManifest) { m.Encryption.Keys = nil },
		"a third key": func(m *BackupManifest) {
			m.Encryption.Keys = append(m.Encryption.Keys, KeyRef{ID: "x", Purpose: "other", KEK: "k", Object: "keys/c"})
		},
		"two keys of one purpose":   func(m *BackupManifest) { m.Encryption.Keys[1].Purpose = ClassData },
		"an unknown key purpose":    func(m *BackupManifest) { m.Encryption.Keys[1].Purpose = "other" },
		"the same key id twice":     func(m *BackupManifest) { m.Encryption.Keys[1].ID = m.Encryption.Keys[0].ID },
		"an invalid chunk size":     func(m *BackupManifest) { m.Encryption.ChunkSize = 3 },
		"expiry not after creation": func(m *BackupManifest) { m.ExpiresAt = m.CreatedAt },
	}
	for name, mutate := range cases {
		m := validManifestForTest()
		mutate(&m)
		if err := m.validate(); faultCode(err) != model.Corrupt {
			t.Errorf("%s: validate returned %v", name, err)
		}
		raw, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = ParseManifest(raw); faultCode(err) != model.Corrupt {
			t.Errorf("%s: ParseManifest returned %v", name, err)
		}
	}
}

// A restore arms a fresh recovery bootstrap and never the old one: the old installation's bootstrap
// token file is dropped from the key files the seed is reassembled from (E10).
func TestReassembleSeedDropsTheOldBootstrapTokenAndKeepsTheOtherKeys(t *testing.T) {
	state, err := json.Marshal(model.ControlState{Installation: model.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	stateObject, err := json.Marshal(map[string]json.RawMessage{"state": state, "metadata": json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	keysObject := []byte(`{"envelope.key":"a2V5","bootstrap.token":"b2xk"}`)
	seed, st, err := reassembleSeed(stateObject, keysObject)
	if err != nil || st.Installation == (model.ID{}) {
		t.Fatalf("reassemble: %v", err)
	}
	var parts map[string]json.RawMessage
	var keys map[string]json.RawMessage
	if err = json.Unmarshal(seed, &parts); err != nil || json.Unmarshal(parts["keys"], &keys) != nil {
		t.Fatalf("seed does not parse: %v", err)
	}
	if _, ok := keys["bootstrap.token"]; ok {
		t.Fatal("the old installation's bootstrap token survived into the restored seed")
	}
	if _, ok := keys["envelope.key"]; !ok || len(keys) != 1 {
		t.Fatalf("the other key files were not carried over: %v", keys)
	}
}

// A gap of the sealed certificate is attested only by a committed fact naming exactly it; the
// backup side refuses to attest one control never committed (X5/G5).
func TestAttestationsRequireACommittedFactForEveryUsedGap(t *testing.T) {
	group := model.NewID()
	fact := model.EvidenceGap{ID: model.NewID(), Org: model.NewID(), Project: model.NewID(), Group: group, After: 10, Through: 12, Count: 2, Reason: "unprocessed_expiry", RecordedAt: 99}
	committed := []committedFact{{gap: storage.DeclaredGap{Group: group, After: 10, Through: 12, Reason: "unprocessed_expiry"}, fact: fact}}
	gap := storage.ReplayInterval{Group: group, After: 10, Through: 12, Mode: "gap", Count: 2, Reason: "unprocessed_expiry"}
	replay := storage.ReplayInterval{Group: group, After: 0, Through: 10, Mode: "replay", Count: 10}
	got, err := attestations([]storage.ReplayInterval{replay, gap}, committed, 500)
	if err != nil || len(got) != 1 || got[0].Fact != fact.ID || got[0].Digest != GapDigest(fact) || got[0].ControlRevision != 500 {
		t.Fatalf("an honest gap was not attested: %+v %v", got, err)
	}
	if got, err = attestations([]storage.ReplayInterval{replay}, nil, 500); err != nil || len(got) != 0 {
		t.Fatalf("a certificate with no gap needed an attestation: %+v %v", got, err)
	}
	if _, err = attestations([]storage.ReplayInterval{replay, gap}, nil, 500); faultCode(err) != model.Corrupt {
		t.Fatalf("a gap no committed fact names was attested: %v", err)
	}
	wide := gap
	wide.Through, wide.Count = 15, 5
	if _, err = attestations([]storage.ReplayInterval{wide}, committed, 500); faultCode(err) != model.Corrupt {
		t.Fatalf("a gap wider than the committed fact was attested: %v", err)
	}
}
