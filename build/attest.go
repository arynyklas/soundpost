// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

// Detached release signature and owner approval envelopes. Only VERIFICATION lives in the
// build tool: generating the release key and signing are owner actions, so the tool has no
// signing code and no private key handling. Both envelopes bind to the sha256 of release.json
// (the artifact manifest written by `go run ./build release`) and are checked against a PUBLIC
// key supplied as input.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	signatureSchema = "soundpost-release-signature/1"
	approvalSchema  = "soundpost-release-approval/1"
)

// SignatureEnvelope is the detached signature over a release manifest digest.
type SignatureEnvelope struct {
	Schema         string `json:"schema"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Signature      string `json:"signature"`
}

// ApprovalEnvelope is the owner's explicit approval to proceed with publication. It is signed
// by the same key and names the version, commit and manifest it approves.
type ApprovalEnvelope struct {
	Schema         string `json:"schema"`
	Owner          string `json:"owner"`
	Decision       string `json:"decision"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
	KeyID          string `json:"key_id"`
	Signature      string `json:"signature"`
}

// ManifestDigest is the lowercase hex sha256 of the exact manifest bytes.
func ManifestDigest(manifest []byte) string {
	sum := sha256.Sum256(manifest)
	return hex.EncodeToString(sum[:])
}

// KeyID identifies a public key: the hex sha256 of its raw bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// signatureMessage is what is signed. The purpose prefix keeps a manifest signature from being
// replayed as an approval and vice versa.
func signatureMessage(purpose, payload string) []byte {
	return []byte("soundpost-release/1\n" + purpose + "\n" + payload)
}

func approvalPayload(a ApprovalEnvelope) string {
	return fmt.Sprintf("owner=%s\ndecision=%s\nversion=%s\ncommit=%s\nmanifest_sha256=%s", a.Owner, a.Decision, a.Version, a.Commit, a.ManifestSHA256)
}

// ParsePublicKey decodes a base64 (std) Ed25519 public key.
func ParsePublicKey(text string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
	if err != nil {
		return nil, fmt.Errorf("public key is not base64: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

func decodeStrict(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

func checkSig(pub ed25519.PublicKey, keyID, signature, purpose, payload string) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("no valid public key supplied")
	}
	if keyID != KeyID(pub) {
		return fmt.Errorf("signed by key %q, not the supplied public key %q", keyID, KeyID(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is not a base64 Ed25519 signature")
	}
	if !ed25519.Verify(pub, signatureMessage(purpose, payload), sig) {
		return errors.New("Ed25519 signature does not verify")
	}
	return nil
}

// VerifySignature checks that envelope is a valid signature by pub over the digest of the
// exact manifest bytes. A single changed manifest byte fails.
func VerifySignature(manifest, envelope []byte, pub ed25519.PublicKey) error {
	var e SignatureEnvelope
	if err := decodeStrict(envelope, &e); err != nil {
		return fmt.Errorf("signature envelope: %w", err)
	}
	if e.Schema != signatureSchema || e.Algorithm != "ed25519" {
		return fmt.Errorf("signature envelope schema %q algorithm %q, want %q ed25519", e.Schema, e.Algorithm, signatureSchema)
	}
	if got := ManifestDigest(manifest); e.ManifestSHA256 != got {
		return fmt.Errorf("signature covers manifest sha256 %s but the manifest is %s", e.ManifestSHA256, got)
	}
	return checkSig(pub, e.KeyID, e.Signature, "manifest", e.ManifestSHA256)
}

// VerifyApproval checks an owner approval for exactly this version, commit and manifest.
func VerifyApproval(manifest, envelope []byte, pub ed25519.PublicKey, version, commit string) error {
	var a ApprovalEnvelope
	if err := decodeStrict(envelope, &a); err != nil {
		return fmt.Errorf("approval: %w", err)
	}
	if a.Schema != approvalSchema {
		return fmt.Errorf("approval schema %q, want %q", a.Schema, approvalSchema)
	}
	if a.Decision != "approve" || a.Owner == "" {
		return errors.New("approval is not an explicit owner \"approve\" decision")
	}
	if a.Version != version || a.Commit != commit {
		return fmt.Errorf("approval is for version %q commit %q, not %q %q", a.Version, a.Commit, version, commit)
	}
	if got := ManifestDigest(manifest); a.ManifestSHA256 != got {
		return fmt.Errorf("approval covers manifest sha256 %s but the manifest is %s", a.ManifestSHA256, got)
	}
	return checkSig(pub, a.KeyID, a.Signature, "approval", approvalPayload(a))
}
