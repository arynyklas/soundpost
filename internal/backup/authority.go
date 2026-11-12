// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"soundpost/internal/durablefs"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/retention"
)

// The restore authority (C12) is an independently durable, versioned journal of
// completed deletions kept on a Destination that is NOT the data volume and
// whose credentials the data node does not otherwise need. It is an append-only,
// hash-chained sequence of immutable signed records:
//
//	authority/ROOT                 signed anchor: authority ID, installation, signing key ID
//	authority/head/<seq, 20 digits>  record seq: previous record digest, generation,
//	                                 the whole deletion ledger and its tombstones
//	                                 (AES-256-GCM sealed), Ed25519 signature
//
// HEAD is the highest sequence. Advancing it is the conditional, monotonic
// update: the record for seq+1 is created only if absent (If-None-Match: *), so
// two racing writers cannot both advance from the same head, and every earlier
// generation stays retained and immutable. A checkpoint returns only after the
// record was read back byte for byte and the whole chain re-verified.
//
// The signing and sealing keys belong to the authority, not to any backup. A
// backup key decrypts backup data and nothing else; holding it confers no way
// to write, roll back or even verify this journal. Restore needs the sealing
// key and the trusted public key (AuthorityKeys.Restricted) to read it.
const (
	authorityRoot   = "authority/ROOT"
	authorityHeads  = "authority/head/"
	authorityFormat = 1
	maxChain        = 1 << 20
)

func headName(sequence uint64) string { return fmt.Sprintf("%s%020d", authorityHeads, sequence) }

// AuthorityKeys are the authority's signing identity and sealing key.
type AuthorityKeys struct {
	ID     string
	signer ed25519.PrivateKey
	public ed25519.PublicKey
	seal   Key
}

func GenerateAuthorityKeys(id string) (AuthorityKeys, error) {
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return AuthorityKeys{}, err
	}
	seal, err := GenerateKey(id)
	if err != nil {
		return AuthorityKeys{}, err
	}
	return AuthorityKeys{ID: id, signer: signer, public: public, seal: seal}, nil
}

// Restricted drops the signing key: it can verify and read the journal, never write it.
func (k AuthorityKeys) Restricted() AuthorityKeys {
	k.signer = nil
	return k
}

// CanSign reports whether the keys include the signing key (the full keys a deletion
// checkpoint needs) rather than the restricted read-only subset.
func (k AuthorityKeys) CanSign() bool { return k.signer != nil }

func (k AuthorityKeys) valid() bool {
	return keyID.MatchString(k.ID) && len(k.public) == ed25519.PublicKeySize && k.seal.valid() && k.seal.id == k.ID && (k.signer == nil || len(k.signer) == ed25519.PrivateKeySize)
}

func (k AuthorityKeys) String() string { return "authority-keys:" + k.ID }

func (k AuthorityKeys) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

type authorityKeyFile struct {
	Version     int    `json:"version"`
	ID          string `json:"id"`
	SigningSeed string `json:"signing_seed,omitempty"`
	Public      string `json:"public"`
	Seal        string `json:"seal"`
}

// WriteAuthorityKeys stores the keys with mode 0600 and never overwrites.
func WriteAuthorityKeys(path string, k AuthorityKeys) error {
	if !k.valid() {
		return model.Fail(model.Invalid)
	}
	file := authorityKeyFile{Version: 1, ID: k.ID, Public: base64.StdEncoding.EncodeToString(k.public), Seal: base64.StdEncoding.EncodeToString(k.seal.b[:])}
	if k.signer != nil {
		file.SigningSeed = base64.StdEncoding.EncodeToString(k.signer.Seed())
	}
	raw, err := json.Marshal(file)
	if err != nil {
		return err
	}
	return durablefs.Exclusive(path, raw)
}

func ReadAuthorityKeys(path string) (AuthorityKeys, error) {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return AuthorityKeys{}, model.Fail(model.NotFound)
	}
	if err != nil || !info.Mode().IsRegular() {
		return AuthorityKeys{}, model.Fail(model.Unavailable)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return AuthorityKeys{}, model.Fail(model.Forbidden)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return AuthorityKeys{}, model.Fail(model.Unavailable)
	}
	var file authorityKeyFile
	if model.StrictJSON(raw, &file) != nil || file.Version != 1 {
		return AuthorityKeys{}, model.Fail(model.Corrupt)
	}
	public, err1 := base64.StdEncoding.DecodeString(file.Public)
	seal, err2 := base64.StdEncoding.DecodeString(file.Seal)
	if err1 != nil || err2 != nil {
		return AuthorityKeys{}, model.Fail(model.Corrupt)
	}
	sealKey, err := NewKey(file.ID, seal)
	clear(seal)
	if err != nil {
		return AuthorityKeys{}, model.Fail(model.Corrupt)
	}
	out := AuthorityKeys{ID: file.ID, public: ed25519.PublicKey(public), seal: sealKey}
	if file.SigningSeed != "" {
		seed, err := base64.StdEncoding.DecodeString(file.SigningSeed)
		if err != nil || len(seed) != ed25519.SeedSize {
			return AuthorityKeys{}, model.Fail(model.Corrupt)
		}
		out.signer = ed25519.NewKeyFromSeed(seed)
		clear(seed)
		if !bytes.Equal(out.signer.Public().(ed25519.PublicKey), out.public) {
			return AuthorityKeys{}, model.Fail(model.Corrupt)
		}
	}
	if !out.valid() {
		return AuthorityKeys{}, model.Fail(model.Corrupt)
	}
	return out, nil
}

// AuthorityHead identifies one verified position of the journal.
type AuthorityHead struct {
	Authority  model.ID       `json:"authority"`
	Sequence   uint64         `json:"sequence,string"`
	Generation uint64         `json:"generation,string"`
	Digest     model.Hash     `json:"digest"`
	At         model.UnixNano `json:"at_ns"`
}

// CurrentDeletion is one atomically verified read of the whole journal: the
// head, the digest of every record from sequence 1 (so a backup's recorded
// head can be located in, or found missing from, the chain), and the ledger
// and exact tombstones of the head.
type CurrentDeletion struct {
	Installation model.ID
	Root         model.Hash // digest of the signed root; the chain tip at sequence 0
	Head         AuthorityHead
	Chain        []model.Hash
	Ledger       replica.Ledger
	Tombstones   []model.DeletePredicate
}

// DeletionLedger is the restore-time view of the authority: one verified read.
type DeletionLedger interface {
	Current(ctx context.Context) (CurrentDeletion, error)
}

// AsAuthority pins this read as a read-only retention.Authority, so a restore
// applies exactly the head it verified even if the journal advances meanwhile.
func (c CurrentDeletion) AsAuthority() retention.Authority { return pinned{c} }

type pinned struct{ c CurrentDeletion }

func (p pinned) CheckpointDeletion(context.Context, retention.LedgerGeneration) (retention.AuthorityReceipt, error) {
	return retention.AuthorityReceipt{}, model.Fail(model.Forbidden)
}
func (p pinned) CurrentDeletionLedger(context.Context) (replica.Ledger, error) {
	return p.c.Ledger, nil
}
func (p pinned) CurrentDeletionTombstones(context.Context) ([]model.DeletePredicate, error) {
	return append([]model.DeletePredicate(nil), p.c.Tombstones...), nil
}

type rootRecord struct {
	Version      uint16         `json:"version"`
	Authority    model.ID       `json:"authority"`
	Installation model.ID       `json:"installation"`
	CreatedAt    model.UnixNano `json:"created_at_ns"`
	KeyID        string         `json:"key_id"`
	Signature    []byte         `json:"signature,omitempty"`
}

type headRecord struct {
	Version    uint16         `json:"version"`
	Authority  model.ID       `json:"authority"`
	Sequence   uint64         `json:"sequence,string"`
	Prev       model.Hash     `json:"prev"`
	Generation uint64         `json:"generation,string"`
	Tombstones uint64         `json:"tombstones,string"`
	Payload    model.Hash     `json:"payload_sha256"`
	At         model.UnixNano `json:"at_ns"`
	KeyID      string         `json:"key_id"`
	Nonce      []byte         `json:"nonce"`
	Sealed     []byte         `json:"sealed"`
	Signature  []byte         `json:"signature,omitempty"`
}

type headPayload struct {
	Ledger     replica.Ledger          `json:"ledger"`
	Tombstones []model.DeletePredicate `json:"tombstones"`
}

// Authority implements retention.Authority (and TombstoneSource) over a Destination.
type Authority struct {
	dest Destination
	keys AuthorityKeys
	now  func() time.Time
}

func NewAuthority(dest Destination, keys AuthorityKeys, now func() time.Time) (*Authority, error) {
	if dest == nil || !keys.valid() {
		return nil, model.Fail(model.Invalid)
	}
	if now == nil {
		now = time.Now
	}
	return &Authority{dest: dest, keys: keys, now: now}, nil
}

func (a *Authority) sign(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(a.keys.signer, raw), nil
}

func (a *Authority) verify(unsigned any, signature []byte) bool {
	raw, err := json.Marshal(unsigned)
	return err == nil && len(signature) == ed25519.SignatureSize && ed25519.Verify(a.keys.public, raw, signature)
}

func (a *Authority) read(ctx context.Context, name string) ([]byte, error) {
	r, err := a.dest.Open(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return nil, model.Fail(model.Unavailable)
	}
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	return raw, nil
}

func digestOf(raw []byte) model.Hash { return model.Hash(sha256.Sum256(raw)) }

// canonical reports whether raw is exactly the encoding this package writes for
// v, so no alternative spelling of a signed record (padding bits, spacing,
// field order) is ever accepted as the same record.
func canonical(v any, raw []byte) bool {
	again, err := json.Marshal(v)
	return err == nil && bytes.Equal(again, raw)
}

func (a *Authority) loadRoot(ctx context.Context) (rootRecord, model.Hash, error) {
	raw, err := a.read(ctx, authorityRoot)
	if err != nil {
		return rootRecord{}, model.Hash{}, err
	}
	var root rootRecord
	if model.StrictJSON(raw, &root) != nil || !canonical(root, raw) || root.Version != authorityFormat || root.KeyID != a.keys.ID {
		return rootRecord{}, model.Hash{}, model.Fail(model.Corrupt)
	}
	signature := root.Signature
	root.Signature = nil
	if !a.verify(root, signature) {
		return rootRecord{}, model.Hash{}, model.Fail(model.Corrupt)
	}
	root.Signature = signature
	return root, digestOf(raw), nil
}

func payloadAAD(authority model.ID, sequence uint64, prev model.Hash, generation uint64) []byte {
	return []byte("soundpost/authority/v1\x00" + authority.String() + "\x00" + strconv.FormatUint(sequence, 10) + "\x00" + prev.String() + "\x00" + strconv.FormatUint(generation, 10))
}

func digestSet(tombstones []model.DeletePredicate) map[model.Hash]bool {
	out := make(map[model.Hash]bool, len(tombstones))
	for _, t := range tombstones {
		out[t.Digest()] = true
	}
	return out
}

func subset(a, b map[model.Hash]bool) bool {
	for h := range a {
		if !b[h] {
			return false
		}
	}
	return true
}

// validateLedger checks the shape every checkpoint and every stored record must have.
func validateLedger(installation model.ID, generation uint64, ledger replica.Ledger, tombstones []model.DeletePredicate) error {
	if ledger.Version != 1 || ledger.Group != installation || ledger.Generation != generation || len(ledger.Entries) != len(tombstones) || ledger.Entries == nil {
		return model.Fail(model.Invalid)
	}
	seen := map[model.ID]bool{}
	for i, t := range tombstones {
		if err := t.Validate(); err != nil {
			return err
		}
		if ledger.Entries[i].Index != uint64(i+1) || ledger.Entries[i].Hash != t.Digest() || seen[t.Operation] {
			return model.Fail(model.Invalid)
		}
		seen[t.Operation] = true
	}
	return nil
}

// Current reads and fully verifies the journal: the root signature, every
// record's signature, hash chain, sequence continuity, generation order and
// tombstone monotonicity, and the sealed payload against its recorded digest.
// An uninitialized, incomplete or altered journal is an error, never "no deletions".
func (a *Authority) Current(ctx context.Context) (CurrentDeletion, error) {
	root, rootDigest, err := a.loadRoot(ctx)
	if err != nil {
		return CurrentDeletion{}, err
	}
	names, err := a.dest.List(ctx, authorityHeads)
	if err != nil {
		return CurrentDeletion{}, model.Fail(model.Unavailable)
	}
	if len(names) > maxChain {
		return CurrentDeletion{}, model.Fail(model.Corrupt)
	}
	out := CurrentDeletion{Installation: root.Installation, Root: rootDigest, Head: AuthorityHead{Authority: root.Authority, Digest: rootDigest, At: root.CreatedAt}, Chain: []model.Hash{}, Ledger: replica.Ledger{Version: 1, Group: root.Installation, Entries: []replica.LedgerEntry{}}, Tombstones: []model.DeletePredicate{}}
	prev := rootDigest
	var previousSet map[model.Hash]bool = map[model.Hash]bool{}
	for i, name := range names {
		sequence := uint64(i + 1)
		if name != headName(sequence) {
			return CurrentDeletion{}, model.Fail(model.Corrupt) // a gap, a stray object or a malformed name
		}
		raw, err := a.read(ctx, name)
		if err != nil {
			return CurrentDeletion{}, err
		}
		var rec headRecord
		if model.StrictJSON(raw, &rec) != nil || !canonical(rec, raw) || rec.Version != authorityFormat || rec.Authority != root.Authority || rec.Sequence != sequence || rec.Prev != prev || rec.KeyID != a.keys.ID || rec.Generation < out.Head.Generation {
			return CurrentDeletion{}, model.Fail(model.Corrupt)
		}
		signature := rec.Signature
		rec.Signature = nil
		if !a.verify(rec, signature) {
			return CurrentDeletion{}, model.Fail(model.Corrupt)
		}
		g, err := a.keys.seal.aead()
		if err != nil || len(rec.Nonce) != g.NonceSize() {
			return CurrentDeletion{}, model.Fail(model.Corrupt)
		}
		plain, err := g.Open(nil, rec.Nonce, rec.Sealed, payloadAAD(root.Authority, sequence, prev, rec.Generation))
		if err != nil || digestOf(plain) != rec.Payload {
			return CurrentDeletion{}, model.Fail(model.Corrupt)
		}
		var payload headPayload
		if model.StrictJSON(plain, &payload) != nil || uint64(len(payload.Tombstones)) != rec.Tombstones || validateLedger(root.Installation, rec.Generation, payload.Ledger, payload.Tombstones) != nil {
			return CurrentDeletion{}, model.Fail(model.Corrupt)
		}
		set := digestSet(payload.Tombstones)
		if !subset(previousSet, set) {
			return CurrentDeletion{}, model.Fail(model.Corrupt) // a deletion was ever forgotten
		}
		previousSet = set
		prev = digestOf(raw)
		out.Chain = append(out.Chain, prev)
		out.Head = AuthorityHead{Authority: root.Authority, Sequence: sequence, Generation: rec.Generation, Digest: prev, At: rec.At}
		out.Ledger, out.Tombstones = payload.Ledger, payload.Tombstones
	}
	return out, nil
}

// Initialize creates the authority root for installation, after verifying the
// destination honours create-only semantics. It is idempotent for the same
// installation and refuses a different one.
func (a *Authority) Initialize(ctx context.Context, installation model.ID) (model.ID, error) {
	if installation == (model.ID{}) {
		return model.ID{}, model.Fail(model.Invalid)
	}
	existing := func() (model.ID, error) {
		root, _, err := a.loadRoot(ctx)
		if err != nil {
			return model.ID{}, err
		}
		if root.Installation != installation {
			return model.ID{}, model.Fail(model.Conflict)
		}
		return root.Authority, nil
	}
	if id, err := existing(); err == nil || faultIs(err, model.Conflict) {
		return id, err
	}
	if a.keys.signer == nil {
		return model.ID{}, model.Fail(model.Forbidden)
	}
	if err := VerifyConditionalCreate(ctx, a.dest); err != nil {
		return model.ID{}, model.Fail(model.Unsupported)
	}
	root := rootRecord{Version: authorityFormat, Authority: model.NewID(), Installation: installation, CreatedAt: model.UnixNano(a.now().UnixNano()), KeyID: a.keys.ID}
	signature, err := a.sign(root)
	if err != nil {
		return model.ID{}, err
	}
	root.Signature = signature
	raw, err := json.Marshal(root)
	if err != nil {
		return model.ID{}, err
	}
	if err = a.dest.Create(ctx, authorityRoot, bytes.NewReader(raw), int64(len(raw))); err != nil && !errors.Is(err, ErrExists) {
		return model.ID{}, model.Fail(model.Unavailable)
	}
	return existing()
}

func faultIs(err error, code model.Code) bool {
	var fault *model.Fault
	return errors.As(err, &fault) && fault.Code == code
}

// CheckpointDeletion durably appends g (the whole current ledger with its
// tombstones) as the new head, verifies it, and only then returns. See the
// package comment for the monotonic rules: the new ledger must contain every
// tombstone already in the head; a ledger the head already covers is answered
// with the head's receipt and writes nothing.
func (a *Authority) CheckpointDeletion(ctx context.Context, g retention.LedgerGeneration) (retention.AuthorityReceipt, error) {
	if a.keys.signer == nil {
		return retention.AuthorityReceipt{}, model.Fail(model.Forbidden)
	}
	for attempt := 0; attempt < 4; attempt++ {
		cur, err := a.Current(ctx)
		if err != nil {
			return retention.AuthorityReceipt{}, err
		}
		if g.Generation != g.Ledger.Generation {
			return retention.AuthorityReceipt{}, model.Fail(model.Invalid)
		}
		if err = validateLedger(cur.Installation, g.Generation, g.Ledger, g.Tombstones); err != nil {
			return retention.AuthorityReceipt{}, err
		}
		have, want := digestSet(cur.Tombstones), digestSet(g.Tombstones)
		if subset(want, have) && g.Generation <= cur.Head.Generation {
			return retention.AuthorityReceipt{Generation: cur.Head.Generation, Head: cur.Head.Digest, At: cur.Head.At}, nil
		}
		if !subset(have, want) || g.Generation < cur.Head.Generation {
			return retention.AuthorityReceipt{}, model.Fail(model.Conflict)
		}
		receipt, err := a.advance(ctx, cur, g)
		if errors.Is(err, ErrExists) {
			continue // another writer advanced first: re-read and re-evaluate
		}
		return receipt, err
	}
	return retention.AuthorityReceipt{}, model.Fail(model.Conflict)
}

func (a *Authority) advance(ctx context.Context, cur CurrentDeletion, g retention.LedgerGeneration) (retention.AuthorityReceipt, error) {
	sequence := cur.Head.Sequence + 1
	plain, err := json.Marshal(headPayload{Ledger: g.Ledger, Tombstones: g.Tombstones})
	if err != nil {
		return retention.AuthorityReceipt{}, model.Fail(model.Invalid)
	}
	aead, err := a.keys.seal.aead()
	if err != nil {
		return retention.AuthorityReceipt{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return retention.AuthorityReceipt{}, err
	}
	rec := headRecord{Version: authorityFormat, Authority: cur.Head.Authority, Sequence: sequence, Prev: cur.Head.Digest, Generation: g.Generation, Tombstones: uint64(len(g.Tombstones)), Payload: digestOf(plain), At: model.UnixNano(a.now().UnixNano()), KeyID: a.keys.ID, Nonce: nonce}
	rec.Sealed = aead.Seal(nil, nonce, plain, payloadAAD(cur.Head.Authority, sequence, cur.Head.Digest, g.Generation))
	if rec.Signature, err = a.sign(rec); err != nil {
		return retention.AuthorityReceipt{}, err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return retention.AuthorityReceipt{}, err
	}
	name := headName(sequence)
	if err = a.dest.Create(ctx, name, bytes.NewReader(raw), int64(len(raw))); err != nil {
		if errors.Is(err, ErrExists) {
			return retention.AuthorityReceipt{}, ErrExists
		}
		return retention.AuthorityReceipt{}, model.Fail(model.Unavailable)
	}
	// Verified strong read-after-write: the stored bytes are ours, and the chain
	// that now ends at (or beyond) them verifies and contains them.
	stored, err := a.read(ctx, name)
	if err != nil || !bytes.Equal(stored, raw) {
		return retention.AuthorityReceipt{}, model.Fail(model.Unavailable)
	}
	after, err := a.Current(ctx)
	digest := digestOf(raw)
	if err != nil || uint64(len(after.Chain)) < sequence || after.Chain[sequence-1] != digest {
		return retention.AuthorityReceipt{}, model.Fail(model.Unavailable)
	}
	return retention.AuthorityReceipt{Generation: g.Generation, Head: digest, At: rec.At}, nil
}

func (a *Authority) CurrentDeletionLedger(ctx context.Context) (replica.Ledger, error) {
	cur, err := a.Current(ctx)
	if err != nil {
		return replica.Ledger{}, err
	}
	return cur.Ledger, nil
}

func (a *Authority) CurrentDeletionTombstones(ctx context.Context) ([]model.DeletePredicate, error) {
	cur, err := a.Current(ctx)
	if err != nil {
		return nil, err
	}
	return cur.Tombstones, nil
}

var (
	_ retention.Authority       = (*Authority)(nil)
	_ retention.TombstoneSource = (*Authority)(nil)
	_ DeletionLedger            = (*Authority)(nil)
	_ retention.Authority       = pinned{}
	_ retention.TombstoneSource = pinned{}
)
