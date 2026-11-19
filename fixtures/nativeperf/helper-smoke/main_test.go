//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/nativeperf"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

// The first pollable descriptor of a Go process makes the runtime open its network poller (an epoll descriptor and an
// eventfd). Counting descriptors around the first scenario would charge those two runtime descriptors to the helper
// session ("authorized": fd_before 5, fd_after 7 on the real helper) while every later scenario sees none.
func TestRuntimeDescriptorsAreSettledBeforeTheFirstBaseline(t *testing.T) {
	// A fresh process: other tests of this binary may already have started the poller.
	child := exec.Command(os.Args[0], "-test.run=^TestRuntimeDescriptorsChild$")
	child.Env = append(os.Environ(), "HELPER_SMOKE_FD_CHILD=1")
	if out, e := child.CombinedOutput(); e != nil {
		t.Fatalf("%v\n%s", e, out)
	}
}

func TestRuntimeDescriptorsChild(t *testing.T) {
	if os.Getenv("HELPER_SMOKE_FD_CHILD") != "1" {
		t.Skip("runs only inside TestRuntimeDescriptorsAreSettledBeforeTheFirstBaseline")
	}
	if e := settleRuntimeDescriptors(); e != nil {
		t.Fatal(e)
	}
	before, e := countFDs("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "s"), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	l.Close()
	after, e := countFDs("/proc/self/fd")
	if e != nil {
		t.Fatal(e)
	}
	if before != after {
		t.Fatalf("descriptors %d before and %d after a socket round trip: the poller was not settled", before, after)
	}
}

// Reading a negative fixture must never change the baseline request: scenarios run one after another against one
// helper and every later scenario sends the baseline again.
func TestNegativeFixturesNeverCorruptTheBaselineRequest(t *testing.T) {
	target := nativeperf.Target{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aa"}}
	cfg := nativeperf.DefaultConfig(1)
	pristine := func() nativeperf.CaptureRequest {
		auth := nativeperf.StartAuthorization{Installation: "fixture", UID: uint32(os.Getuid()), Revision: 1, Expires: 100, Targets: []nativeperf.Target{target}, Config: cfg, Mode: nativeperf.ModeCPU, Signature: []byte{1, 2, 3}}
		auth.Targets = []nativeperf.Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aa"}}}
		return nativeperf.CaptureRequest{Authorization: auth, Targets: []nativeperf.Target{{TGID: 1, PIDNamespace: 2, ProcessStart: 3, CgroupID: 4, AllowedBuildIDs: []string{"aa"}}}, Config: cfg, Mode: nativeperf.ModeCPU}
	}
	base := pristine()
	other := pristine()
	other.Authorization.Expires = 1
	other.Authorization.Signature = []byte{9, 9, 9}
	other.Authorization.Targets[0].AllowedBuildIDs = []string{"bb"}
	other.Targets[0].AllowedBuildIDs = []string{"bb"}
	raw, e := json.Marshal(other)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "expired.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	for _, scenario := range []string{"expired", "fd-cap", "denied", "authorized", "capture", "cancel"} {
		r, e := requestFor(scenario, base, path)
		if e != nil {
			t.Fatalf("%s: %v", scenario, e)
		}
		if !reflect.DeepEqual(base, pristine()) {
			t.Fatalf("after scenario %s the baseline request is %+v: a scenario corrupted it", scenario, base)
		}
		switch scenario {
		case "expired", "fd-cap":
			if !reflect.DeepEqual(r, other) {
				t.Fatalf("%s did not return the fixture", scenario)
			}
		case "denied":
			if r.Authorization.Signature != nil || base.Authorization.Signature == nil {
				t.Fatal("denied must drop only its own copy of the signature")
			}
		default:
			if !reflect.DeepEqual(r, base) {
				t.Fatalf("%s must send the baseline", scenario)
			}
		}
	}
}
