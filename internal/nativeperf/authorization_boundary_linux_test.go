//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package nativeperf

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// authFixture is one valid, accepted request; every case below changes exactly one fact (and re-signs the grant when the
// changed fact lives in the grant), so each refusal is attributable to one authorization condition.
type authFixture struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	peer    PeerCredential
	policy  OperatorPolicy
	grant   StartAuthorization
	request CaptureRequest
}

func newAuthFixture() *authFixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	target := Target{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"0123456789abcdef"}}
	cfg := DefaultConfig(1)
	f := &authFixture{pub: pub, priv: priv, peer: PeerCredential{UID: 42}}
	f.policy = OperatorPolicy{Installation: "fixture", PublicKey: pub, UID: 42, Revision: 1, Allowlist: []Target{target}}
	f.grant = StartAuthorization{Installation: "fixture", UID: 42, Revision: 1, Expires: time.Now().Add(time.Hour).Unix(), Targets: []Target{target}, Config: cfg, Mode: ModeCPU}
	f.request = CaptureRequest{Targets: []Target{target}, Config: cfg, Mode: ModeCPU}
	return f
}
func (f *authFixture) sign() *authFixture {
	f.request.Authorization, _ = SignStart(f.grant, f.priv)
	return f
}
func (f *authFixture) authorize() error {
	_, e := authorizeLocal(f.peer, f.request, f.policy)
	return e
}

func TestAuthorizationEachConditionIsEnforced(t *testing.T) {
	if e := newAuthFixture().sign().authorize(); e != nil {
		t.Fatalf("baseline refused: %v", e)
	}
	two := func(f *authFixture) []Target {
		b := Target{TGID: 5, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aabb"}}
		return []Target{f.grant.Targets[0], b}
	}
	cases := []struct {
		name string
		edit func(f *authFixture)
	}{
		{"policy key too short", func(f *authFixture) { f.policy.PublicKey = f.pub[:16] }},
		{"policy key missing", func(f *authFixture) { f.policy.PublicKey = nil }},
		{"policy installation empty and grant empty", func(f *authFixture) { f.policy.Installation = ""; f.grant.Installation = "" }},
		{"grant installation differs", func(f *authFixture) { f.grant.Installation = "other" }},
		{"peer uid differs from policy and grant", func(f *authFixture) { f.peer.UID = 43; f.grant.UID = 43 }},
		{"grant uid differs, peer is the policy uid", func(f *authFixture) { f.grant.UID = 43 }},
		{"peer uid differs, grant is the policy uid", func(f *authFixture) { f.peer.UID = 43 }},
		{"grant revision differs", func(f *authFixture) { f.grant.Revision = 2 }},
		{"request config revision differs", func(f *authFixture) { f.request.Config.PolicyRevision = 2 }},
		{"policy revision differs", func(f *authFixture) { f.policy.Revision = 2 }},
		{"expires now", func(f *authFixture) { f.grant.Expires = time.Now().Unix() }},
		{"expired one second ago", func(f *authFixture) { f.grant.Expires = time.Now().Unix() - 1 }},
		{"expires zero", func(f *authFixture) { f.grant.Expires = 0 }},
		{"expires past the 24h horizon", func(f *authFixture) { f.grant.Expires = time.Now().Add(24*time.Hour + time.Minute).Unix() }},
		{"expires far in the future", func(f *authFixture) { f.grant.Expires = time.Now().Add(30 * 24 * time.Hour).Unix() }},
		{"signed by another key", func(f *authFixture) { _, f.priv, _ = ed25519.GenerateKey(rand.Reader) }},
		{"no targets (grant and request)", func(f *authFixture) { f.grant.Targets = nil; f.request.Targets = nil }},
		{"65 targets", func(f *authFixture) {
			var ts []Target
			for i := range 65 {
				ts = append(ts, Target{TGID: uint32(i + 1), PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aabb"}})
			}
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = ts, ts, ts
		}},
		{"invalid target identity", func(f *authFixture) {
			bad := Target{TGID: 0, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aabb"}}
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = []Target{bad}, []Target{bad}, []Target{bad}
		}},
		{"grant config invalid (revision zero)", func(f *authFixture) { f.grant.Config.PolicyRevision = 0 }},
		{"request config invalid", func(f *authFixture) { f.request.Config.MaxFrames = 0 }},
		{"mode empty", func(f *authFixture) { f.grant.Mode = ""; f.request.Mode = "" }},
		{"mode differs between grant and request", func(f *authFixture) { f.request.Mode = ModeCPUOffCPU }},
		{"request mode wider than grant mode", func(f *authFixture) { f.grant.Mode = ModeCPUOffCPU }},
		{"grant targets differ from request targets", func(f *authFixture) { f.grant.Targets = two(f) }},
		{"request targets differ from grant targets", func(f *authFixture) { f.request.Targets = two(f); f.policy.Allowlist = two(f) }},
		{"request MaxFrames above grant", func(f *authFixture) { f.grant.Config.MaxFrames = 64 }},
		{"request RingBytes above grant", func(f *authFixture) { f.grant.Config.RingBytes = 128 << 10 }},
		{"request MaxMemory above grant", func(f *authFixture) { f.grant.Config.MaxMemory = 32 << 20 }},
		{"target without cgroup", func(f *authFixture) {
			x := f.grant.Targets[0]
			x.CgroupID = 0
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = []Target{x}, []Target{x}, []Target{x}
		}},
		{"target without allowed build IDs", func(f *authFixture) {
			x := f.grant.Targets[0]
			x.AllowedBuildIDs = nil
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = []Target{x}, []Target{x}, []Target{x}
		}},
		{"allowlist empty", func(f *authFixture) { f.policy.Allowlist = nil }},
		{"allowlist has the target with other build IDs", func(f *authFixture) {
			x := f.grant.Targets[0]
			x.AllowedBuildIDs = []string{"ffff"}
			f.policy.Allowlist = []Target{x}
		}},
		{"second target is not allowlisted", func(f *authFixture) {
			ts := two(f)
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = ts, ts, ts[:1]
		}},
		{"first target is not allowlisted", func(f *authFixture) {
			ts := two(f)
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = ts, ts, ts[1:]
		}},
	}
	for _, c := range cases {
		f := newAuthFixture()
		c.edit(f)
		f.sign()
		if e := f.authorize(); e != ErrAuthorization {
			t.Errorf("%s: err = %v, want ErrAuthorization", c.name, e)
		}
	}
}

func TestAuthorizationBoundariesAreInclusive(t *testing.T) {
	// Each of these is at, or strictly inside, a bound and must be accepted: the refusals above are not over-broad.
	accepted := []struct {
		name string
		edit func(f *authFixture)
	}{
		{"expires just inside 24h", func(f *authFixture) { f.grant.Expires = time.Now().Add(24*time.Hour - time.Minute).Unix() }},
		{"expires in two seconds", func(f *authFixture) { f.grant.Expires = time.Now().Add(2 * time.Second).Unix() }},
		{"request MaxFrames below grant", func(f *authFixture) { f.request.Config.MaxFrames = 64 }},
		{"request RingBytes below grant", func(f *authFixture) { f.request.Config.RingBytes = 128 << 10 }},
		{"request MaxMemory below grant", func(f *authFixture) { f.request.Config.MaxMemory = 32 << 20 }},
		{"allowlist holds the target after others", func(f *authFixture) {
			x := Target{TGID: 9, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aabb"}}
			f.policy.Allowlist = []Target{x, f.grant.Targets[0]}
		}},
		{"two targets in reverse allowlist order", func(f *authFixture) {
			b := Target{TGID: 5, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aabb"}}
			ts := []Target{f.grant.Targets[0], b}
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = ts, ts, []Target{b, ts[0]}
		}},
		{"64 targets", func(f *authFixture) {
			var ts []Target
			for i := range 64 {
				ts = append(ts, Target{TGID: uint32(i + 1), PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aabb"}})
			}
			f.grant.Targets, f.request.Targets, f.policy.Allowlist = ts, ts, ts
		}},
		{"cpu_offcpu grant and request", func(f *authFixture) { f.grant.Mode = ModeCPUOffCPU; f.request.Mode = ModeCPUOffCPU }},
	}
	for _, c := range accepted {
		f := newAuthFixture()
		c.edit(f)
		f.sign()
		if e := f.authorize(); e != nil {
			t.Errorf("%s: refused: %v", c.name, e)
		}
	}
	// The signature covers every grant field: flipping any one after signing must be refused even when the rest still pass.
	f := newAuthFixture().sign()
	f.request.Authorization.Expires++
	if e := f.authorize(); e != ErrAuthorization {
		t.Errorf("tampered expiry after signing: %v", e)
	}
	f = newAuthFixture().sign()
	f.request.Authorization.Signature = append([]byte(nil), f.request.Authorization.Signature...)
	f.request.Authorization.Signature[0] ^= 1
	if e := f.authorize(); e != ErrAuthorization {
		t.Errorf("flipped signature bit: %v", e)
	}
}

func TestSignStartRefusesShortKeyAndSignsEveryField(t *testing.T) {
	f := newAuthFixture()
	if _, e := SignStart(f.grant, f.priv[:10]); e != ErrAuthorization {
		t.Fatalf("short key: %v", e)
	}
	signed, e := SignStart(f.grant, f.priv)
	if e != nil || len(signed.Signature) != ed25519.SignatureSize || !ed25519.Verify(f.pub, f.grant.message(), signed.Signature) {
		t.Fatalf("signature does not verify over the grant message: %v", e)
	}
	// message() excludes the signature itself, so a signed grant and the unsigned one share their message.
	if string(signed.message()) != string(f.grant.message()) {
		t.Fatal("message depends on the signature")
	}
}
