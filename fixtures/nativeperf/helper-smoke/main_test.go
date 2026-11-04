//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"soundpost/internal/nativeperf"
	"testing"
	"time"
)

func TestSignedNegativeScenariosReachIntendedBranches(t *testing.T) {
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cfg := nativeperf.DefaultConfig(1)
	target := nativeperf.Target{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"01"}}
	base := nativeperf.CaptureRequest{Targets: []nativeperf.Target{target}, Config: cfg, Mode: nativeperf.ModeCPU}
	policy := nativeperf.OperatorPolicy{Installation: "fixture", UID: uint32(os.Getuid()), Revision: 1, PublicKey: public, Allowlist: base.Targets}
	now := time.Now()
	grant := nativeperf.StartAuthorization{Installation: policy.Installation, UID: policy.UID, Revision: 1, Expires: now.Add(-time.Minute).Unix(), Targets: base.Targets, Config: cfg, Mode: base.Mode}
	signed, e := nativeperf.SignStart(grant, private)
	if e != nil {
		t.Fatal(e)
	}
	expired := base
	expired.Authorization = signed
	if e = validateSignedCase("expired", expired, base, policy, now); e != nil {
		t.Fatal(e)
	}
	tampered := expired
	tampered.Authorization.Expires--
	if validateSignedCase("expired", tampered, base, policy, now) == nil {
		t.Fatal("expiry mutation confused with signed expiry fixture")
	}
	budget := base
	grant.Config = budget.Config
	grant.Expires = now.Add(time.Minute).Unix()
	budget.Authorization, e = nativeperf.SignStart(grant, private)
	if e != nil {
		t.Fatal(e)
	}
	if e = validateSignedCase("fd-cap", budget, base, policy, now); e != nil {
		t.Fatal(e)
	}
	budget.Config.RingBytes = nativeperf.MaxMemoryBytes
	if validateSignedCase("fd-cap", budget, base, policy, now) == nil {
		t.Fatal("config mismatch confused with actual resource admission")
	}
}
func TestFDSnapshotFailureCannotPassSmoke(t *testing.T) {
	if _, e := countFDs(filepath.Join(t.TempDir(), "missing")); e == nil {
		t.Fatal("FD count failure became zero evidence")
	}
}
func TestStrictFixtureRejectsOversizedPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized.json")
	b := make([]byte, 65537)
	for i := range b {
		b[i] = ' '
	}
	copy(b, []byte("{}"))
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if readJSONFixture(path, &value) == nil {
		t.Fatal("oversized fixture accepted")
	}
}
func TestRequestFixtureMustBePrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public-request.json")
	if e := os.WriteFile(path, []byte("{}"), 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if readJSONFixture(path, &value) == nil {
		t.Fatal("non-private request accepted")
	}
}
