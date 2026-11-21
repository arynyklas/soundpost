//go:build linux

// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/nativeperf"
)

func testTarget() nativeperf.Target {
	return nativeperf.Target{CgroupID: 77, PIDNamespace: 4026531836, TGID: 4242, ProcessStart: 123456789, AllowedBuildIDs: []string{"0123456789abcdef0123456789abcdef01234567"}}
}

func TestCommittedTemplateMatchesTheDocumentedFixtureKey(t *testing.T) {
	raw, err := os.ReadFile("operator-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := loadTemplate(raw, fixtureKey(), 0)
	if err != nil {
		t.Fatalf("the committed template is not the fixture's: %v", err)
	}
	if p.Installation != "fixture-e2e" || p.Revision != 1 || len(p.Allowlist) != 0 {
		t.Fatalf("unexpected template content: %+v", p)
	}
	if !bytes.Equal(p.PublicKey, fixtureKey().Public().(ed25519.PublicKey)) {
		t.Fatal("public key differs from the one derived from the documented seed")
	}
}

func TestTemplateIsRefusedWhenItIsNotExactlyTheFixture(t *testing.T) {
	key := fixtureKey()
	good := func() nativeperf.OperatorPolicy {
		return nativeperf.OperatorPolicy{Installation: "fixture-e2e", PublicKey: key.Public().(ed25519.PublicKey), UID: 0, Revision: 1}
	}
	other := make([]byte, ed25519.PublicKeySize)
	cases := map[string]struct {
		mutate func(*nativeperf.OperatorPolicy)
		euid   uint32
	}{
		"foreign public key": {func(p *nativeperf.OperatorPolicy) { p.PublicKey = other }, 0},
		"filled allowlist":   {func(p *nativeperf.OperatorPolicy) { p.Allowlist = []nativeperf.Target{testTarget()} }, 0},
		"wrong uid":          {func(p *nativeperf.OperatorPolicy) {}, 1000},
		"no installation":    {func(p *nativeperf.OperatorPolicy) { p.Installation = "" }, 0},
		"no revision":        {func(p *nativeperf.OperatorPolicy) { p.Revision = 0 }, 0},
	}
	for name, c := range cases {
		p := good()
		c.mutate(&p)
		raw, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = loadTemplate(raw, key, c.euid); err == nil {
			t.Errorf("%s: template accepted", name)
		}
	}
	if _, err := loadTemplate([]byte(`{"Installation":"fixture-e2e","Bogus":1}`), key, 0); err == nil {
		t.Error("unknown field accepted")
	}
	raw, _ := json.Marshal(good())
	if _, err := loadTemplate(append(raw, []byte(` {}`)...), key, 0); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := loadTemplate(raw, key, 0); err != nil {
		t.Errorf("valid template refused: %v", err)
	}
}

func TestRenderedPolicyIsWhatTheHelperDecodesAndAuthorizes(t *testing.T) {
	key := fixtureKey()
	tmpl := nativeperf.OperatorPolicy{Installation: "fixture-e2e", PublicKey: key.Public().(ed25519.PublicKey), UID: 0, Revision: 1}
	target := testTarget()
	out, err := renderPolicy(tmpl, target)
	if err != nil {
		t.Fatal(err)
	}
	// The helper's own reading rules: strict fields, one object, nothing after it.
	var got nativeperf.OperatorPolicy
	d := json.NewDecoder(bytes.NewReader(out))
	d.DisallowUnknownFields()
	if err = d.Decode(&got); err != nil || d.Decode(new(any)) != io.EOF {
		t.Fatalf("helper-side decode failed: %v", err)
	}
	if got.Installation != "fixture-e2e" || got.UID != 0 || got.Revision != 1 || !bytes.Equal(got.PublicKey, tmpl.PublicKey) {
		t.Fatalf("policy fields changed: %+v", got)
	}
	if len(got.Allowlist) != 1 || !reflect.DeepEqual(got.Allowlist[0], target) {
		t.Fatalf("the helper compares targets with DeepEqual; round trip gave %+v, want %+v", got.Allowlist, target)
	}
	if len(tmpl.Allowlist) != 0 {
		t.Fatal("rendering mutated the template")
	}
	bad := target
	bad.CgroupID = 0
	if _, err = renderPolicy(tmpl, bad); err == nil {
		t.Error("a target without a cgroup id was rendered")
	}
	bad = target
	bad.AllowedBuildIDs = nil
	if _, err = renderPolicy(tmpl, bad); err == nil {
		t.Error("a target without a build id was rendered")
	}
	bad = target
	bad.TGID = 0
	if _, err = renderPolicy(tmpl, bad); err == nil {
		t.Error("an invalid target was rendered")
	}
}

const statusFixture = "Name:\tsoundpost-perf-a\nUmask:\t0022\nState:\tS (sleeping)\nVmHWM:\t   23456 kB\nVmRSS:\t   22000 kB\nThreads:\t9\nNoNewPrivs:\t0\nSeccomp:\t2\nSeccomp_filters:\t1\nTHP_enabled:\t0\n"

func TestStatusParsing(t *testing.T) {
	s := []byte(statusFixture)
	for name, want := range map[string]string{"THP_enabled": "0", "Seccomp": "2", "NoNewPrivs": "0", "Threads": "9", "Missing": ""} {
		if got := statusField(s, name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// "Seccomp" must not match "Seccomp_filters" and vice versa.
	if got := statusField(s, "Seccomp_filters"); got != "1" {
		t.Errorf("Seccomp_filters = %q", got)
	}
	if got := statusKB(s, "VmHWM"); got != 23456 {
		t.Errorf("VmHWM = %d", got)
	}
	if got := statusKB(s, "Threads"); got != -1 {
		t.Errorf("a field without a kB unit parsed as %d", got)
	}
	if got := statusKB(s, "Nope"); got != -1 {
		t.Errorf("an absent field parsed as %d", got)
	}
	// A kernel without the field reports no value; it must never read as "0" (opted out).
	if got := statusField([]byte(strings.ReplaceAll(statusFixture, "THP_enabled:\t0\n", "")), "THP_enabled"); got != "" {
		t.Errorf("absent THP_enabled read as %q", got)
	}
}

func TestEvaluateRequiresTheOptOutToBeTheHelpersOwn(t *testing.T) {
	pass := result{DriverTHPEnabled: "1", HelperTHPEnabled: "0", Samples: 10}
	if f := evaluate(pass); len(f) != 0 {
		t.Fatalf("a passing run failed: %v", f)
	}
	cases := map[string]func(*result){
		"helper still THP-enabled":   func(r *result) { r.HelperTHPEnabled = "1" },
		"helper THP absent":          func(r *result) { r.HelperTHPEnabled = "" },
		"driver itself THP-disabled": func(r *result) { r.DriverTHPEnabled = "0" },
		"driver THP absent":          func(r *result) { r.DriverTHPEnabled = "" },
		"no samples":                 func(r *result) { r.Samples = 0 },
		"helper exit 1 on SIGTERM":   func(r *result) { r.HelperExit = 1 },
		"helper killed (no exit)":    func(r *result) { r.HelperExit = -1 },
	}
	for name, mutate := range cases {
		r := pass
		mutate(&r)
		if len(evaluate(r)) == 0 {
			t.Errorf("%s: not reported", name)
		}
	}
}

func TestCgroupV2Path(t *testing.T) {
	if got, err := cgroupV2Path("12:cpu:/x\n0::/user.slice/session-3.scope\n"); err != nil || got != "/user.slice/session-3.scope" {
		t.Fatalf("got %q, %v", got, err)
	}
	for name, in := range map[string]string{"v1 only": "12:cpu:/x\n", "empty": "", "namespace escape": "0::/../../x\n"} {
		if _, err := cgroupV2Path(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestBuildIDFromNote(t *testing.T) {
	desc := []byte("\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67")
	note := make([]byte, 12)
	binary.LittleEndian.PutUint32(note, 4)
	binary.LittleEndian.PutUint32(note[4:], uint32(len(desc)))
	binary.LittleEndian.PutUint32(note[8:], 3)
	note = append(append(note, "GNU\x00"...), desc...)
	if got, err := buildIDFromNote(note); err != nil || got != "0123456789abcdef0123456789abcdef01234567" {
		t.Fatalf("got %q, %v", got, err)
	}
	for name, in := range map[string][]byte{"short": note[:10], "descriptor past the end": note[:len(note)-1], "empty": nil} {
		if _, err := buildIDFromNote(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	zero := append([]byte(nil), note...)
	binary.LittleEndian.PutUint32(zero[4:], 0)
	if _, err := buildIDFromNote(zero); err == nil {
		t.Error("an empty descriptor was accepted")
	}
	huge := append([]byte(nil), note...)
	binary.LittleEndian.PutUint32(huge, 0xffffffff)
	if _, err := buildIDFromNote(huge); err == nil {
		t.Error("an overflowing name size was accepted")
	}
}
