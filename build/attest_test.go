// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParsePublicKeyRejectsMalformedKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub) + "\r\n"); err != nil || !got.Equal(pub) {
		t.Fatalf("valid key rejected: %v", err)
	}
	for name, in := range map[string]string{"not base64": "!!!", "short": base64.StdEncoding.EncodeToString(pub[:31]), "empty": ""} {
		if _, err := ParsePublicKey(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestApprovalIsBoundToVersionCommitAndPurpose(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	m := []byte("manifest")
	ok := approveFor(priv, m, "1.0.0", "c1")
	if err := VerifyApproval(m, ok, pub, "1.0.0", "c1"); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ version, commit string }{"version": {"1.0.1", "c1"}, "commit": {"1.0.0", "c2"}} {
		if VerifyApproval(m, ok, pub, c.version, c.commit) == nil {
			t.Errorf("approval accepted for another %s", name)
		}
	}
	if VerifyApproval(m, signFor(priv, m), pub, "1.0.0", "c1") == nil {
		t.Error("a manifest signature was accepted as an owner approval")
	}
	if VerifyApproval([]byte("other"), ok, pub, "1.0.0", "c1") == nil {
		t.Error("approval accepted for another manifest")
	}
}

func TestSignatureAndApprovalDoNotCrossPurposesAndNameTheKeyMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	m := []byte("manifest")
	d := ManifestDigest(m)
	// a signature made for the approval purpose over the bare digest must not verify as a manifest signature
	wrongPurpose, _ := json.Marshal(SignatureEnvelope{Schema: signatureSchema, Algorithm: "ed25519", KeyID: KeyID(pub), ManifestSHA256: d,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signatureMessage("approval", d)))})
	if VerifySignature(m, wrongPurpose, pub) == nil {
		t.Error("an approval-purpose signature verified as a manifest signature")
	}
	// a properly signed envelope whose decision is not "approve" is not an approval
	a := ApprovalEnvelope{Schema: approvalSchema, Owner: "Test Owner", Decision: "reject", Version: "1", Commit: "c", ManifestSHA256: d, KeyID: KeyID(pub)}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signatureMessage("approval", approvalPayload(a))))
	raw, _ := json.Marshal(a)
	if VerifyApproval(m, raw, pub, "1", "c") == nil {
		t.Error("a signed reject was accepted as an approval")
	}
	// verifying with a different key names the mismatch instead of a bare signature failure
	err := VerifySignature(m, signFor(priv, m), otherPub)
	if err == nil || !strings.Contains(err.Error(), "not the supplied public key") {
		t.Errorf("key mismatch not named: %v", err)
	}
}
