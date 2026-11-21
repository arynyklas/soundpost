// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

// ArtifactManifest identifies an inert source map by exact immutable build identity.
type ArtifactManifest struct {
	Version         uint16   `json:"version"`
	Org             ID       `json:"org"`
	Project         ID       `json:"project"`
	Source          ID       `json:"source"`
	Build           ID       `json:"build"`
	DebugID         string   `json:"debug_id"`
	GeneratedSHA256 Hash     `json:"generated_sha256"`
	MapSHA256       Hash     `json:"map_sha256"`
	Path            string   `json:"path"`
	SourceContent   bool     `json:"source_content"`
	Size            Uint64   `json:"size"`
	RetainUntil     UnixNano `json:"retain_until_ns"`
}
type ArtifactQuotaReservation struct {
	ID           ID           `json:"id"`
	Manifest     BlobManifest `json:"manifest"`
	ManifestHash Hash         `json:"manifest_hash"`
	Slot         uint16       `json:"slot"`
	State        string       `json:"state"`
	Receipt      *BlobReceipt `json:"receipt,omitempty"`
	GC           *ArtifactGC  `json:"gc,omitempty"`
}

// Intent is durable only after byte receipts have been verified in the owner
// group. Published references are never inferred from orphan fragment existence.
type ArtifactReferenceIntent struct {
	ID              ID               `json:"id"`
	Manifest        ArtifactManifest `json:"manifest"`
	Map             BlobReceipt      `json:"map"`
	Sources         *BlobReceipt     `json:"sources,omitempty"`
	CommandID       ID               `json:"command_id"`
	ControlRevision Revision         `json:"control_revision"`
	State           string           `json:"state"`
}

// ArtifactGC binds the actual durable control revision/command cancellation to
// the subsequent root-owner data-group permanent no-use fence. No quota refund.
type ArtifactGC struct {
	Manifest        BlobManifest `json:"manifest"`
	CommandID       ID           `json:"command_id"`
	ControlRevision Revision     `json:"control_revision"`
	Cursor          *Cursor      `json:"cursor,omitempty"`
}
