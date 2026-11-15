//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestLocalAuthorization(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	target := Target{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"0123456789abcdef"}}
	cfg := DefaultConfig(1)
	grant := StartAuthorization{Installation: "fixture", UID: 42, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{target}, Config: cfg, Mode: ModeCPU}
	grant.Signature = ed25519.Sign(priv, grant.message())
	policy := OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: 42, Revision: 1, Allowlist: []Target{target}}
	request := CaptureRequest{Authorization: grant, Targets: []Target{target}, Config: cfg, Mode: ModeCPU}
	if _, err := authorizeLocal(PeerCredential{UID: 42}, request, policy); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CaptureRequest){func(r *CaptureRequest) { r.Authorization.Signature = nil }, func(r *CaptureRequest) { r.Config.RingBytes *= 2 }, func(r *CaptureRequest) { r.Targets[0].PIDNamespace++ }} {
		r := request
		r.Targets = append([]Target(nil), request.Targets...)
		mutate(&r)
		if _, err := authorizeLocal(PeerCredential{UID: 42}, r, policy); err == nil {
			t.Fatal("accepted unauthorized request")
		}
	}
	if _, err := authorizeLocal(PeerCredential{UID: 43}, request, policy); err == nil {
		t.Fatal("foreign peer")
	}
	expired := request
	expired.Authorization.Expires = time.Now().Add(-time.Minute).Unix()
	expired.Authorization.Signature = ed25519.Sign(priv, expired.Authorization.message())
	if _, err := authorizeLocal(PeerCredential{UID: 42}, expired, policy); err == nil {
		t.Fatal("accepted signed expired grant")
	}
	foreign := policy
	foreign.Allowlist = []Target{{TGID: 1, PIDNamespace: 9, ProcessStart: 3}}
	if _, err := authorizeLocal(PeerCredential{UID: 42}, request, foreign); err == nil {
		t.Fatal("allowlist bypass")
	}
	arbitrary := request
	arbitrary.Mode = "arbitrary_tracepoint"
	arbitrary.Authorization.Mode = arbitrary.Mode
	arbitrary.Authorization.Signature = ed25519.Sign(priv, arbitrary.Authorization.message())
	if _, err := authorizeLocal(PeerCredential{UID: 42}, arbitrary, policy); err == nil {
		t.Fatal("arbitrary event")
	}
}

// A capability is a value the helper derived once from a signed request: nothing the requester (or a later caller of Targets())
// does with the request's or the returned slices changes the targets, build-ID allowlists or mode it grants.
func TestAuthorizedCapabilityIsImmutableAfterAuthorization(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	target := Target{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"0123456789abcdef"}}
	cfg := DefaultConfig(1)
	grant := StartAuthorization{Installation: "fixture", UID: 42, Revision: 1, Expires: time.Now().Add(time.Minute).Unix(), Targets: []Target{target}, Config: cfg, Mode: ModeCPU}
	grant, _ = SignStart(grant, priv)
	policy := OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: 42, Revision: 1, Allowlist: []Target{target}}
	request := CaptureRequest{Authorization: grant, Targets: []Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"0123456789abcdef"}}}, Config: cfg, Mode: ModeCPU}
	capability, e := authorizeLocal(PeerCredential{UID: 42}, request, policy)
	if e != nil {
		t.Fatal(e)
	}
	// The requester keeps its request and rewrites it after authorization: retarget, widen the build-ID allowlist, change the mode.
	request.Targets[0].TGID = 999
	request.Targets[0].AllowedBuildIDs[0] = "ffffffffffffffff"
	request.Targets = append(request.Targets, Target{TGID: 7})
	request.Mode = ModeCPUOffCPU
	got := capability.Targets()
	if len(got) != 1 || got[0].TGID != 1 || got[0].AllowedBuildIDs[0] != "0123456789abcdef" || capability.Mode() != ModeCPU {
		t.Fatalf("capability followed a later change of the request: %+v mode %s", got, capability.Mode())
	}
	// A caller of Targets() cannot change the capability through what it got back either.
	got[0].TGID = 5
	got[0].AllowedBuildIDs[0] = "eeeeeeeeeeeeeeee"
	again := capability.Targets()
	if again[0].TGID != 1 || again[0].AllowedBuildIDs[0] != "0123456789abcdef" {
		t.Fatalf("Targets() exposes the capability's own storage: %+v", again)
	}
}
