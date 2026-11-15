// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package backup

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/arynyklas/soundpost/internal/model"
)

const (
	ManifestVersion = 1
	ClassData       = "data"
	ClassKeys       = "keys"

	BundleObject       = "bundle"
	ControlStateObject = "control-state"
	ControlKeysObject  = "control-keys"
)

func SlotObject(slot int) string                 { return fmt.Sprintf("slot-%02d", slot) }
func ManifestName(id model.ID) string            { return "backups/" + id.String() + "/manifest.json" }
func ObjectName(id model.ID, name string) string { return "backups/" + id.String() + "/obj/" + name }
func KeyName(id model.ID, keyID string) string   { return "backups/" + id.String() + "/key/" + keyID }

// ObjectRef describes one encrypted object: its plaintext and ciphertext size
// and SHA-256, so a restore detects substitution before and after decryption.
type ObjectRef struct {
	Name         string       `json:"name"`
	Class        string       `json:"class"`
	Size         model.Uint64 `json:"size"`
	SHA256       model.Hash   `json:"sha256"`
	CipherSize   model.Uint64 `json:"cipher_size"`
	CipherSHA256 model.Hash   `json:"cipher_sha256"`
}

// KeyRef names a per-bundle data key by ID, the key-encryption key that wraps
// it and the destination object holding the wrapped key. No key material is
// recorded in the manifest.
type KeyRef struct {
	ID           string     `json:"id"`
	Purpose      string     `json:"purpose"`
	KEK          string     `json:"kek"`
	Object       string     `json:"object"`
	ObjectSHA256 model.Hash `json:"object_sha256"`
}
type Encryption struct {
	Algorithm string   `json:"algorithm"`
	ChunkSize uint32   `json:"chunk_size"`
	Keys      []KeyRef `json:"keys"`
}

// ControlBinding ties the backup to the control state taken at C.
type ControlBinding struct {
	Installation       model.ID       `json:"installation"`
	Revision           model.Revision `json:"revision"`
	StateSHA256        model.Hash     `json:"state_sha256"`
	ReservationsSHA256 model.Hash     `json:"reservations_sha256"`
}

// DataBinding carries the cursors of the sealed data cut D and the processed
// highwaters H the control cut named, plus the digests of the C12 certificates.
type DataBinding struct {
	Identity     model.ID       `json:"identity"`
	BundleDigest model.Hash     `json:"bundle_digest"`
	Generation   model.Uint64   `json:"generation"`
	Applied      []model.Cursor `json:"applied"`
	Processed    []model.Cursor `json:"processed"`
	ReplayDigest model.Hash     `json:"replay_digest"`
	QuotaDigest  model.Hash     `json:"quota_digest"`
}
type RetentionBinding struct {
	PolicyDigest model.Hash   `json:"policy_digest"`
	Versions     model.Uint64 `json:"versions"`
}

// AuthorityBinding records the restore-authority head the backup was taken
// under. A restore refuses an authority that is behind it.
type AuthorityBinding struct {
	Authority    model.ID     `json:"authority"`
	Sequence     model.Uint64 `json:"sequence"`
	Generation   model.Uint64 `json:"generation"`
	Head         model.Hash   `json:"head"`
	Tombstones   model.Uint64 `json:"tombstones"`
	LedgerDigest model.Hash   `json:"ledger_digest"`
}

// GapAttestation names the committed control fact (RecordEvidenceGap) that
// explains one gap interval of the replay certificate, at the control revision
// it was verified at. Restore re-verifies it against the control state in the
// backup; a gap with no matching committed fact is never accepted.
type GapAttestation struct {
	Fact            model.ID       `json:"fact"`
	Group           model.ID       `json:"group"`
	After           model.Uint64   `json:"after"`
	Through         model.Uint64   `json:"through"`
	Reason          string         `json:"reason"`
	ControlRevision model.Revision `json:"control_revision"`
	Digest          model.Hash     `json:"digest"`
}

// TopologyMember is one voter of the replication group the backup was taken from.
type TopologyMember struct {
	ID            model.Uint64 `json:"id"`
	Identity      string       `json:"identity"`
	FailureDomain string       `json:"failure_domain"`
}

// Topology records which replicated installation a backup was taken from: the
// voter that was snapshotted (the three voters of a cluster hold the same applied
// state, so the backup is one quorum-verified voter's cut, not three copies), the
// membership every one of its 65 groups (control and 64 data) agreed on at the
// cut, and the node identities that membership names. A restore into a new
// cluster retires these identities (appcore.ClusterSeed.Retired): the restored
// cluster must use fresh ones, so no node of the lost cluster can authenticate to it.
type Topology struct {
	Voters          model.Uint64     `json:"voters"`
	SourceNode      model.Uint64     `json:"source_node"`
	MembersRevision model.Uint64     `json:"members_revision"`
	Members         []TopologyMember `json:"members"`
}

// Retired lists the node identities of the source membership.
func (t *Topology) Retired() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.Members))
	for _, m := range t.Members {
		out = append(out, m.Identity)
	}
	return out
}

// validate is the structural check of a manifest's topology: one voter, or the
// three of the distributed layout, every member named once, the source node a member.
func (t *Topology) validate() error {
	if t == nil {
		return nil
	}
	if t.Voters != 1 && t.Voters != 3 || uint64(len(t.Members)) != uint64(t.Voters) || t.MembersRevision == 0 {
		return model.Fail(model.Corrupt)
	}
	ids, names, source := map[model.Uint64]bool{}, map[string]bool{}, false
	for _, m := range t.Members {
		if m.ID == 0 || m.Identity == "" || m.FailureDomain == "" || ids[m.ID] || names[m.Identity] {
			return model.Fail(model.Corrupt)
		}
		ids[m.ID], names[m.Identity] = true, true
		source = source || m.ID == t.SourceNode
	}
	if !source {
		return model.Fail(model.Corrupt)
	}
	return nil
}

// BackupManifest is the authenticated description of one backup. It is plain
// JSON protected by an HMAC under a key derived from the data KEK; everything it
// names is verified again from the objects themselves.
type BackupManifest struct {
	Version     uint16           `json:"version"`
	ID          model.ID         `json:"id"`
	CreatedAt   model.UnixNano   `json:"created_at_ns"`
	CompletedAt model.UnixNano   `json:"completed_at_ns"`
	ExpiresAt   model.UnixNano   `json:"expires_at_ns"`
	Control     ControlBinding   `json:"control"`
	Data        DataBinding      `json:"data"`
	Retention   RetentionBinding `json:"retention"`
	Deletion    AuthorityBinding `json:"deletion"`
	Gaps        []GapAttestation `json:"gaps"`
	Encryption  Encryption       `json:"encryption"`
	Objects     []ObjectRef      `json:"objects"`
	Topology    *Topology        `json:"topology,omitempty"`
	MAC         model.Hash       `json:"mac"`
}

// GapDigest binds the exact committed control fact a gap attestation names.
func GapDigest(g model.EvidenceGap) model.Hash {
	raw, err := model.CanonicalJSON(g)
	if err != nil {
		return model.Hash{}
	}
	return model.HashCanonical(raw)
}

// Encode is the one canonical serialization (compact JSON, fixed field order).
func (m BackupManifest) Encode() ([]byte, error) { return json.Marshal(m) }

// ParseManifest decodes and structurally validates a manifest. It does not
// authenticate it: call VerifyMAC with the data key-encryption key.
func ParseManifest(raw []byte) (BackupManifest, error) {
	var m BackupManifest
	if len(raw) == 0 || len(raw) > 4<<20 || model.StrictJSON(raw, &m) != nil {
		return BackupManifest{}, model.Fail(model.Corrupt)
	}
	if again, err := m.Encode(); err != nil || !bytes.Equal(again, raw) {
		return BackupManifest{}, model.Fail(model.Corrupt)
	}
	if err := m.validate(); err != nil {
		return BackupManifest{}, err
	}
	return m, nil
}

func (m BackupManifest) validate() error {
	if m.Version != ManifestVersion || m.ID == (model.ID{}) || m.Encryption.Algorithm != AlgorithmAES256GCM || !ValidChunkSize(m.Encryption.ChunkSize) || m.ExpiresAt <= m.CreatedAt || len(m.Data.Applied) != 64 || len(m.Data.Processed) != 64 {
		return model.Fail(model.Corrupt)
	}
	if err := m.Topology.validate(); err != nil {
		return err
	}
	purposes := map[string]bool{}
	ids := map[string]bool{}
	for _, k := range m.Encryption.Keys {
		if !keyID.MatchString(k.ID) || !keyID.MatchString(k.KEK) || ValidName(k.Object) != nil || ids[k.ID] || purposes[k.Purpose] || (k.Purpose != ClassData && k.Purpose != ClassKeys) {
			return model.Fail(model.Corrupt)
		}
		ids[k.ID], purposes[k.Purpose] = true, true
	}
	if len(m.Encryption.Keys) != 2 || !purposes[ClassData] || !purposes[ClassKeys] {
		return model.Fail(model.Corrupt)
	}
	names := map[string]bool{}
	for _, o := range m.Objects {
		if ValidName(o.Name) != nil || names[o.Name] || (o.Class != ClassData && o.Class != ClassKeys) {
			return model.Fail(model.Corrupt)
		}
		names[o.Name] = true
	}
	return nil
}

// kekFor returns the key-encryption key ID that wraps the key for purpose.
func (m BackupManifest) kekFor(purpose string) (string, bool) {
	for _, k := range m.Encryption.Keys {
		if k.Purpose == purpose {
			return k.KEK, true
		}
	}
	return "", false
}

func macKey(kek Key) ([]byte, error) {
	return hkdf.Key(sha256.New, kek.material(), nil, "soundpost/backup/manifest-mac/v1", 32)
}

func (m BackupManifest) mac(kek Key) (model.Hash, error) {
	m.MAC = model.Hash{}
	raw, err := m.Encode()
	if err != nil {
		return model.Hash{}, err
	}
	key, err := macKey(kek)
	if err != nil {
		return model.Hash{}, err
	}
	defer clear(key)
	h := hmac.New(sha256.New, key)
	h.Write(raw)
	var out model.Hash
	copy(out[:], h.Sum(nil))
	return out, nil
}

// Sign authenticates the manifest under kek (the data key-encryption key).
func (m *BackupManifest) Sign(kek Key) error {
	if !kek.valid() {
		return model.Fail(model.Invalid)
	}
	mac, err := m.mac(kek)
	if err != nil {
		return err
	}
	m.MAC = mac
	return nil
}

// VerifyMAC fails unless the manifest is exactly what a holder of kek signed.
func (m BackupManifest) VerifyMAC(kek Key) error {
	if !kek.valid() {
		return model.Fail(model.Invalid)
	}
	want, err := m.mac(kek)
	if err != nil || !hmac.Equal(want[:], m.MAC[:]) {
		return model.Fail(model.Forbidden)
	}
	return nil
}
