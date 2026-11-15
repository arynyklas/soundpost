// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/model"
)

// The binary fragment envelope (10.15-W1) is the wire form of an artifact_fragment command: the
// bytes a proposer hands the replica layer, which the raft log, the ready WAL and a replay
// journal carry. The JSON form base64-encodes the fragment and the replica layer base64-encodes
// that text again; the envelope carries the fragment bytes raw.
//
// It is a wire form only. Apply decodes either form and stores the command through encodeWAL,
// which is always JSON, so replica_commands, snapshots, windows, backups, redaction digests and
// every state digest are identical whichever form a proposer chose (TestMixedFormatProposersLeave
// IdenticalState).
//
//	magic    4  0xF7 'S' 'P' 'F'   0xF7 is never the first byte of JSON text (it is not valid UTF-8)
//	version  1  1
//	head_len 4  big endian
//	head        JSON of fragmentHead (manifest, reservation, ordinal): small, and it follows the
//	            model types without a second schema
//	hash    32  SHA-256 of the fragment bytes (ArtifactFragment.Hash)
//	group   16  cursor group
//	index    8  cursor index, big endian
//	len      4  fragment byte length, big endian
//	bytes       the fragment bytes
//
// Decoding re-verifies the digest of the bytes against the hash field and refuses an envelope
// with any length that does not consume the input exactly, so a torn or altered envelope is
// Corrupt at the first reader instead of a later check.
//
// Mixed versions. A reader that predates the envelope hands every payload to the JSON decoder,
// which refuses the leading 0xF7 as Corrupt (a typed fault, never a misread); on a voter that
// means an apply failure. A cluster therefore proposes envelopes only after every voter runs a
// build that reads both forms: Engine.EnableFragmentEnvelope is off by default
// (docs/operations/upgrade.md, "Fragment envelope"). A reader that knows the envelope but not
// the version byte answers the typed Unsupported detail below.
const (
	envelopeMagic   = "\xf7SPF"
	envelopeVersion = 1
	envelopeHeadMax = 64 << 10
	// envelopeUnsupported is the SafeDetail of an envelope version this build cannot read.
	envelopeUnsupported = "unsupported_fragment_envelope_version"
)

func isEnvelope(raw []byte) bool { return bytes.HasPrefix(raw, []byte(envelopeMagic)) }

// onlyFragment reports whether entry is a plain artifact fragment command the envelope can carry.
func onlyFragment(entry walEntry) bool {
	return entry.Artifact != nil && entry.Artifact.Bytes != nil && entry.Type == "artifact_fragment" && entry.Batch == nil && entry.Receipt == nil && entry.Cancel == nil && entry.Fence == nil && entry.ArtifactGC == nil && entry.Rejection == nil && entry.CommitSet == nil && entry.DeleteBarrier == nil && entry.EraseAck == nil && entry.EraseUnack == nil && entry.EraseNotice == nil && entry.Proposer == nil && entry.Redaction == nil
}

// encodeFragmentEnvelope writes entry as an envelope, assembled once at its exact size. ok is
// false for any entry the envelope does not carry (the caller encodes JSON).
func encodeFragmentEnvelope(entry walEntry) (raw []byte, ok bool, err error) {
	if !onlyFragment(entry) {
		return nil, false, nil
	}
	f := entry.Artifact
	head, err := json.Marshal(fragmentHead{Manifest: f.Manifest, Reservation: f.Reservation, Ordinal: f.Ordinal})
	if err != nil || len(head) > envelopeHeadMax || uint64(len(f.Bytes)) > model.ArtifactFragmentLimit {
		return nil, false, nil
	}
	out := make([]byte, 0, 4+1+4+len(head)+32+16+8+4+len(f.Bytes))
	out = append(out, envelopeMagic...)
	out = append(out, envelopeVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(head)))
	out = append(out, head...)
	out = append(out, f.Hash[:]...)
	out = append(out, f.Cursor.Group[:]...)
	out = binary.BigEndian.AppendUint64(out, uint64(f.Cursor.Index))
	out = binary.BigEndian.AppendUint32(out, uint32(len(f.Bytes)))
	return append(out, f.Bytes...), true, nil
}

// decodeFragmentEnvelope reads an envelope and re-verifies the fragment digest.
func decodeFragmentEnvelope(raw []byte) (walEntry, error) {
	corrupt := model.Fail(model.Corrupt)
	if !isEnvelope(raw) || len(raw) < 5 {
		return walEntry{}, corrupt
	}
	if raw[4] != envelopeVersion {
		fault := model.Fail(model.Invalid)
		fault.SafeDetail = envelopeUnsupported
		return walEntry{}, fault
	}
	rest := raw[5:]
	if len(rest) < 4 {
		return walEntry{}, corrupt
	}
	headLen := binary.BigEndian.Uint32(rest)
	rest = rest[4:]
	if headLen == 0 || headLen > envelopeHeadMax || uint64(len(rest)) < uint64(headLen) {
		return walEntry{}, corrupt
	}
	var head fragmentHead
	if model.StrictJSON(rest[:headLen], &head) != nil {
		return walEntry{}, corrupt
	}
	rest = rest[headLen:]
	if len(rest) < 32+16+8+4 {
		return walEntry{}, corrupt
	}
	f := model.ArtifactFragment{Manifest: head.Manifest, Reservation: head.Reservation, Ordinal: head.Ordinal}
	copy(f.Hash[:], rest[:32])
	copy(f.Cursor.Group[:], rest[32:48])
	f.Cursor.Index = model.Uint64(binary.BigEndian.Uint64(rest[48:56]))
	size := binary.BigEndian.Uint32(rest[56:60])
	rest = rest[60:]
	if uint64(size) > model.ArtifactFragmentLimit || uint64(len(rest)) != uint64(size) {
		return walEntry{}, corrupt
	}
	f.Bytes = bytes.Clone(rest)
	if model.HashCanonical(f.Bytes) != f.Hash {
		return walEntry{}, corrupt
	}
	return walEntry{Type: "artifact_fragment", Artifact: &f}, nil
}

// EnableFragmentEnvelope makes this engine propose artifact fragments in the binary envelope.
// Off by default: call it only once every voter of the group runs a build that reads both
// forms (an older voter refuses the envelope, see the package comment above).
func (e *Engine) EnableFragmentEnvelope(on bool) { e.fragmentEnvelope.Store(on) }

// encodeProposal is the wire form of a command about to be proposed.
func (e *Engine) encodeProposal(entry walEntry) ([]byte, error) {
	if e.fragmentEnvelope.Load() {
		if raw, ok, err := encodeFragmentEnvelope(entry); ok || err != nil {
			if ok {
				e.envelopesProposed.Add(1)
			}
			return raw, err
		}
	}
	return encodeWAL(entry)
}
