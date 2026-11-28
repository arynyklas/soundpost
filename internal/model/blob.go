// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import "encoding/binary"

const ArtifactFragmentLimit = 256 << 10
const ArtifactBundleLimit = 32 << 20

// BlobManifest is private build evidence admission, not a public telemetry kind.
// Root is immutable and owns one slot for map and separately granted source bytes.
type BlobManifest struct {
	Org             ID       `json:"org"`
	Project         ID       `json:"project"`
	Source          ID       `json:"source"`
	Root            ID       `json:"root"`
	Build           ID       `json:"build"`
	DebugID         string   `json:"debug_id"`
	Path            string   `json:"path"`
	GeneratedSHA256 Hash     `json:"generated_sha256"`
	MapSHA256       Hash     `json:"map_sha256"`
	Hash            Hash     `json:"hash"`
	Size            Uint64   `json:"size"`
	PolicyEpoch     Uint64   `json:"policy_epoch"`
	PolicyRevision  Revision `json:"policy_revision"`
	RetainUntil     UnixNano `json:"retain_until_ns"`
	PrivateSources  bool     `json:"private_sources"`
	ReservationID   ID       `json:"reservation_id"`
}
type BlobFragmentReceipt struct {
	Ordinal uint32 `json:"ordinal"`
	Hash    Hash   `json:"hash"`
	Size    uint32 `json:"size"`
	Cursor  Cursor `json:"cursor"`
}
type BlobReceipt struct {
	Manifest  BlobManifest          `json:"manifest"`
	Hash      Hash                  `json:"hash"`
	Fragments []BlobFragmentReceipt `json:"fragments"`
	Cursor    Cursor                `json:"cursor"`
}
type ArtifactFragment struct {
	Manifest    BlobManifest             `json:"manifest"`
	Reservation ArtifactQuotaReservation `json:"reservation"`
	Ordinal     uint32                   `json:"ordinal"`
	Bytes       []byte                   `json:"bytes"`
	Hash        Hash                     `json:"hash"`
	Cursor      Cursor                   `json:"cursor"`
}

func BlobOwnerSlot(org, project, root ID) uint16 {
	var input [48]byte
	copy(input[:16], org[:])
	copy(input[16:32], project[:])
	copy(input[32:], root[:])
	h := HashCanonical(input[:])
	return uint16(binary.BigEndian.Uint64(h[:8]) % 64)
}
func BlobKey(m BlobManifest) string {
	kind := "map"
	if m.PrivateSources {
		kind = "sources"
	}
	return m.Org.String() + ":" + m.Project.String() + ":" + m.Root.String() + ":" + kind
}
func BlobManifestHash(m BlobManifest) Hash {
	// ReservationID is deliberately not in the binding: it is allocated only
	// after admission. Do not marshal a zero model.ID (the model rejects it).
	input := struct {
		Org, Project, Source, Root, Build ID
		DebugID, Path                     string
		GeneratedSHA256, MapSHA256, Hash  Hash
		Size, PolicyEpoch                 uint64
		PolicyRevision                    Revision
		RetainUntil                       UnixNano
		PrivateSources                    bool
	}{m.Org, m.Project, m.Source, m.Root, m.Build, m.DebugID, m.Path, m.GeneratedSHA256, m.MapSHA256, m.Hash, uint64(m.Size), uint64(m.PolicyEpoch), m.PolicyRevision, m.RetainUntil, m.PrivateSources}
	raw, err := CanonicalJSON(input)
	if err != nil {
		return Hash{}
	}
	return HashCanonical(raw)
}
