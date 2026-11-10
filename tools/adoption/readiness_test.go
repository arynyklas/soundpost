// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var readinessNow = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func readinessFixture() (AcceptanceLedger, Authorizations) {
	l := AcceptanceLedger{Scope: "synthetic-scope", Now: readinessNow, MaxAgeSeconds: 3600,
		RequireProduction: true, ProductFailureDomain: "product-domain"}
	producer := map[ReadinessKind]string{
		ReadinessJourneyGateway: "adoption-journeys", ReadinessJourneyFrontend: "adoption-journeys",
		ReadinessJourneyBackground: "adoption-journeys", ReadinessSourcePolicy: "adoption-shadow",
		ReadinessQueryProfile: "qualify", ReadinessIsolationMatrix: "drills",
		ReadinessDeliveryPolicy: "adoption-policy-compare", ReadinessDeletionRestore: "drills",
		ReadinessExternalDeadman: "drills", ReadinessLegacyRetention: "adoption-retention",
	}
	for i, k := range readinessKinds {
		e := EvidenceRef{Kind: k, Producer: producer[k],
			Digest:     strings.Repeat(string("0123456789"[i]), 64),
			ObservedAt: readinessNow.Add(-10 * time.Minute), AuthorizationID: "auth-1",
			Scope: l.Scope, Environment: ReadinessEnvProduction, Result: ReadinessResultPass}
		if k == ReadinessExternalDeadman {
			e.FailureDomain = "external-domain"
			e.Disruptive = true
		}
		l.Evidence = append(l.Evidence, e)
	}
	a := Authorizations{Items: []ReadinessAuthorization{{ID: "auth-1", Scope: l.Scope,
		Environment: ReadinessEnvProduction, Kinds: append([]ReadinessKind(nil), readinessKinds...),
		Disruptive: true, NotBefore: readinessNow.Add(-time.Hour), Expires: readinessNow.Add(24 * time.Hour)}}}
	return l, a
}

func readinessEval(t *testing.T, l AcceptanceLedger, a Authorizations) CutoverReadiness {
	t.Helper()
	r, err := ReadyForCutover(context.Background(), l, a)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func readinessWithout(l AcceptanceLedger, k ReadinessKind) AcceptanceLedger {
	var ev []EvidenceRef
	for _, e := range l.Evidence {
		if e.Kind != k {
			ev = append(ev, e)
		}
	}
	l.Evidence = ev
	return l
}

func readinessMutate(l AcceptanceLedger, k ReadinessKind, f func(*EvidenceRef)) AcceptanceLedger {
	ev := append([]EvidenceRef(nil), l.Evidence...)
	for i := range ev {
		if ev[i].Kind == k {
			f(&ev[i])
		}
	}
	l.Evidence = ev
	return l
}

func readinessHas(r CutoverReadiness, code string, k ReadinessKind) bool {
	for _, b := range r.Blockers {
		if b.Code == code && b.Kind == k {
			return true
		}
	}
	return false
}

func TestCutoverReadinessRejectsMissingJourneyOrOutageAuthorization(t *testing.T) {
	l, a := readinessFixture()
	if r := readinessEval(t, l, a); !r.Ready || len(r.Blockers) != 0 || r.Gate == nil || len(r.Satisfied) != len(readinessKinds) {
		t.Fatalf("complete fixture must be ready: %+v", r.Blockers)
	}
	// No partial demonstration approves: dropping any one criterion blocks and names it.
	for _, k := range readinessKinds {
		r := readinessEval(t, readinessWithout(l, k), a)
		if r.Ready || r.Gate != nil || !readinessHas(r, ReadinessBlockMissing, k) {
			t.Fatalf("missing %s must block with its name: %+v", k, r.Blockers)
		}
		found := false
		for _, b := range r.Blockers {
			if strings.Contains(b.Detail, string(k)) {
				found = true
			}
		}
		if !found {
			t.Fatalf("blocker for %s does not name the exact evidence", k)
		}
	}
	// Outage (disruptive) drill without explicit disruptive authorization.
	na := a
	na.Items = []ReadinessAuthorization{a.Items[0]}
	na.Items[0].Disruptive = false
	if r := readinessEval(t, l, na); r.Ready || !readinessHas(r, ReadinessBlockDisruptiveUnauth, ReadinessExternalDeadman) {
		t.Fatalf("disruptive drill without authorization must block: %+v", r.Blockers)
	}
	if r := readinessEval(t, l, Authorizations{}); r.Ready || !readinessHas(r, ReadinessBlockUnauthorized, ReadinessJourneyGateway) {
		t.Fatalf("no authorizations must block every item: %+v", r.Blockers)
	}
	zero := l
	zero.MaxAgeSeconds = 0
	if r := readinessEval(t, zero, a); r.Ready || r.Blockers[0].Code != ReadinessBlockBadLedger {
		t.Fatal("zero freshness window must be refused")
	}
	if r := readinessEval(t, AcceptanceLedger{}, a); r.Ready || r.Blockers[0].Code != ReadinessBlockBadLedger {
		t.Fatalf("empty ledger: %+v", r)
	}
}

func TestCutoverReadinessEvidenceBoundaries(t *testing.T) {
	l, a := readinessFixture()
	k := ReadinessQueryProfile
	cases := []struct {
		name string
		l    AcceptanceLedger
		a    Authorizations
		code string
	}{
		{"not_run", readinessMutate(l, k, func(e *EvidenceRef) { e.Result = ReadinessResultNotRun }), a, ReadinessBlockNotRun},
		{"failed", readinessMutate(l, k, func(e *EvidenceRef) { e.Result = ReadinessResultFail }), a, ReadinessBlockFailed},
		{"unknown result", readinessMutate(l, k, func(e *EvidenceRef) { e.Result = "" }), a, ReadinessBlockBadEvidence},
		{"synthetic", readinessMutate(l, k, func(e *EvidenceRef) { e.Environment = ReadinessEnvSynthetic }), a, ReadinessBlockSynthetic},
		{"staging when production required", readinessMutate(l, k, func(e *EvidenceRef) { e.Environment = ReadinessEnvStaging }), a, ReadinessBlockProductionProof},
		{"unknown environment", readinessMutate(l, k, func(e *EvidenceRef) { e.Environment = "x" }), a, ReadinessBlockBadEvidence},
		{"stale", readinessMutate(l, k, func(e *EvidenceRef) { e.ObservedAt = readinessNow.Add(-2 * time.Hour) }), a, ReadinessBlockStale},
		{"future", readinessMutate(l, k, func(e *EvidenceRef) { e.ObservedAt = readinessNow.Add(time.Second) }), a, ReadinessBlockFuture},
		{"zero time", readinessMutate(l, k, func(e *EvidenceRef) { e.ObservedAt = time.Time{} }), a, ReadinessBlockBadEvidence},
		{"wrong scope", readinessMutate(l, k, func(e *EvidenceRef) { e.Scope = "other" }), a, ReadinessBlockWrongScope},
		{"long digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest += "0" }), a, ReadinessBlockBadDigest},
		{"non-hex digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = strings.Repeat("g", 64) }), a, ReadinessBlockBadDigest},
		{"upper digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = strings.Repeat("A", 64) }), a, ReadinessBlockBadDigest},
		{"colon digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = strings.Repeat(":", 64) }), a, ReadinessBlockBadDigest},
		{"slash digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = strings.Repeat("/", 64) }), a, ReadinessBlockBadDigest},
		{"backtick digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = strings.Repeat("`", 64) }), a, ReadinessBlockBadDigest},
		{"bad digest", readinessMutate(l, k, func(e *EvidenceRef) { e.Digest = "abc" }), a, ReadinessBlockBadDigest},
		{"unknown producer", readinessMutate(l, k, func(e *EvidenceRef) { e.Producer = "hand-written" }), a, ReadinessBlockUnknownProducer},
		{"unknown auth id", readinessMutate(l, k, func(e *EvidenceRef) { e.AuthorizationID = "nope" }), a, ReadinessBlockUnauthorized},
		{"deadman same domain", readinessMutate(l, ReadinessExternalDeadman, func(e *EvidenceRef) { e.FailureDomain = "product-domain" }), a, ReadinessBlockDeadmanNotIndep},
		{"deadman no domain", readinessMutate(l, ReadinessExternalDeadman, func(e *EvidenceRef) { e.FailureDomain = "" }), a, ReadinessBlockDeadmanNotIndep},
	}
	for _, c := range cases {
		kind := k
		if strings.HasPrefix(c.name, "deadman") {
			kind = ReadinessExternalDeadman
		}
		r := readinessEval(t, c.l, c.a)
		if r.Ready || !readinessHas(r, c.code, kind) {
			t.Errorf("%s: want %s on %s, got ready=%v %+v", c.name, c.code, kind, r.Ready, r.Blockers)
		}
	}
	// Product failure domain unknown: independence cannot be shown.
	nl := l
	nl.ProductFailureDomain = ""
	if r := readinessEval(t, nl, a); r.Ready || !readinessHas(r, ReadinessBlockDeadmanNotIndep, ReadinessExternalDeadman) {
		t.Fatal("deadman independence needs a declared product domain")
	}
	// Freshness edges: exactly at max age is fresh; a second older is stale.
	if r := readinessEval(t, readinessMutate(l, k, func(e *EvidenceRef) { e.ObservedAt = readinessNow.Add(-time.Hour) }), a); !r.Ready {
		t.Fatalf("evidence exactly at max age is fresh: %+v", r.Blockers)
	}
	if r := readinessEval(t, readinessMutate(l, k, func(e *EvidenceRef) { e.ObservedAt = readinessNow }), a); !r.Ready {
		t.Fatalf("evidence observed at now is current: %+v", r.Blockers)
	}
	// Authorization boundaries: expiry, not-yet-valid, wrong scope/env/kind.
	for name, f := range map[string]func(*ReadinessAuthorization){
		"expired":     func(x *ReadinessAuthorization) { x.Expires = readinessNow },
		"not yet":     func(x *ReadinessAuthorization) { x.NotBefore = readinessNow.Add(time.Second) },
		"zero window": func(x *ReadinessAuthorization) { x.NotBefore, x.Expires = time.Time{}, time.Time{} },
		"scope":       func(x *ReadinessAuthorization) { x.Scope = "other" },
		"env":         func(x *ReadinessAuthorization) { x.Environment = ReadinessEnvStaging },
		"kind":        func(x *ReadinessAuthorization) { x.Kinds = []ReadinessKind{ReadinessSourcePolicy} },
	} {
		na := Authorizations{Items: []ReadinessAuthorization{a.Items[0]}}
		f(&na.Items[0])
		if r := readinessEval(t, l, na); r.Ready {
			t.Errorf("authorization %s must block", name)
		}
	}
	if r := readinessEval(t, readinessMutate(l, k, func(e *EvidenceRef) { e.Kind = "bogus" }), a); r.Ready {
		t.Fatal("unknown kind must block")
	}
}

func TestCutoverReadinessStagingRecordsProductionOutstanding(t *testing.T) {
	l, a := readinessFixture()
	l.RequireProduction = false
	a.Items[0].Environment = ReadinessEnvStaging
	for i := range l.Evidence {
		l.Evidence[i].Environment = ReadinessEnvStaging
	}
	r := readinessEval(t, l, a)
	if !r.Ready || !r.ProductionProofOutstanding || r.Gate.ProductionProven {
		t.Fatalf("staging gate must record production proof outstanding: %+v", r)
	}
	l.RequireProduction = true
	r = readinessEval(t, l, a)
	if r.Ready || !r.ProductionProofOutstanding {
		t.Fatal("production required must not accept staging")
	}
	// Mixed: one staging item keeps the gate unproven.
	l2, a2 := readinessFixture()
	l2.RequireProduction = false
	a2.Items = append(a2.Items, ReadinessAuthorization{ID: "auth-2", Scope: l2.Scope, Environment: ReadinessEnvStaging,
		Kinds: []ReadinessKind{ReadinessQueryProfile}, NotBefore: readinessNow.Add(-time.Hour), Expires: readinessNow.Add(time.Hour)})
	l2 = readinessMutate(l2, ReadinessQueryProfile, func(e *EvidenceRef) { e.Environment = ReadinessEnvStaging; e.AuthorizationID = "auth-2" })
	if r := readinessEval(t, l2, a2); !r.Ready || r.Gate.ProductionProven || !r.ProductionProofOutstanding {
		t.Fatalf("mixed environments: %+v", r)
	}
}

func TestCutoverReadinessAnyValidReferenceSatisfies(t *testing.T) {
	l, a := readinessFixture()
	bad := l.Evidence[0]
	bad.Result = ReadinessResultNotRun
	l.Evidence = append([]EvidenceRef{bad}, l.Evidence...)
	if r := readinessEval(t, l, a); !r.Ready {
		t.Fatalf("a valid sibling reference satisfies the criterion: %+v", r.Blockers)
	}
}

func readinessKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	k := ed25519.NewKeyFromSeed(seed)
	return k.Public().(ed25519.PublicKey), k
}

func TestCutoverReadinessSignedGate(t *testing.T) {
	l, a := readinessFixture()
	pub, priv := readinessKeys(t)
	r := readinessEval(t, l, a)
	g, err := SignReadyGate(r, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyReadyGate(g, pub, readinessNow); err != nil {
		t.Fatal(err)
	}
	if !g.ExpiresAt.Equal(readinessNow.Add(-10 * time.Minute).Add(time.Hour)) {
		t.Fatalf("expiry must be oldest evidence + window: %v", g.ExpiresAt)
	}
	// Unready results never sign.
	if _, err := SignReadyGate(readinessEval(t, readinessWithout(l, ReadinessExternalDeadman), a), priv); err == nil {
		t.Fatal("unready must not sign")
	}
	if _, err := SignReadyGate(r, priv[:10]); err == nil {
		t.Fatal("bad key must not sign")
	}
	// Survives JSON round trip.
	b, _ := json.Marshal(g)
	var back ReadyGate
	if err := json.Unmarshal(b, &back); err != nil || VerifyReadyGate(back, pub, readinessNow) != nil {
		t.Fatal("round trip must verify")
	}
	clone := func() ReadyGate {
		var c ReadyGate
		_ = json.Unmarshal(b, &c)
		return c
	}
	bad := map[string]func(*ReadyGate){
		"ledger digest": func(g *ReadyGate) { g.LedgerDigest = strings.Repeat("0", 64) },
		"criterion":     func(g *ReadyGate) { g.Criteria[0].Digest = strings.Repeat("f", 64) },
		"authorization": func(g *ReadyGate) { g.Authorizations[0].Disruptive = false },
		"scope":         func(g *ReadyGate) { g.Scope = "other" },
		"expiry":        func(g *ReadyGate) { g.ExpiresAt = g.ExpiresAt.Add(time.Hour) },
		"issued":        func(g *ReadyGate) { g.IssuedAt = g.IssuedAt.Add(-time.Hour) },
		"production":    func(g *ReadyGate) { g.ProductionProven = !g.ProductionProven },
		"unsigned":      func(g *ReadyGate) { g.Signature = "" },
		"garbage sig":   func(g *ReadyGate) { g.Signature = "zz" },
		"truncated sig": func(g *ReadyGate) { g.Signature = g.Signature[:20] },
	}
	for name, f := range bad {
		c := clone()
		f(&c)
		if VerifyReadyGate(c, pub, readinessNow) == nil {
			t.Errorf("tamper %s must be refused", name)
		}
	}
	// Missing criterion, even when re-signed by the right key, is refused.
	c := clone()
	c.Criteria = c.Criteria[1:]
	sb, _ := readinessSigningBytes(c)
	c.Signature = hex.EncodeToString(ed25519.Sign(priv, sb))
	if VerifyReadyGate(c, pub, readinessNow) == nil {
		t.Fatal("missing criterion must be refused")
	}
	c = clone()
	c.Criteria = append(c.Criteria, c.Criteria[0])
	sb, _ = readinessSigningBytes(c)
	c.Signature = hex.EncodeToString(ed25519.Sign(priv, sb))
	if VerifyReadyGate(c, pub, readinessNow) == nil {
		t.Fatal("duplicate criterion must be refused")
	}
	// Wrong key, bad key, future dating, expiry boundary.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if VerifyReadyGate(g, otherPub, readinessNow) == nil || VerifyReadyGate(g, pub[:5], readinessNow) == nil {
		t.Fatal("wrong key refused")
	}
	if VerifyReadyGate(g, pub, readinessNow.Add(-time.Second)) == nil {
		t.Fatal("future-dated gate refused")
	}
	if VerifyReadyGate(g, pub, g.ExpiresAt.Add(-time.Nanosecond)) != nil {
		t.Fatal("gate valid just before expiry")
	}
	if VerifyReadyGate(g, pub, g.ExpiresAt) == nil {
		t.Fatal("gate expired at expiry")
	}
	// Authorization expiry caps gate lifetime.
	a.Items[0].Expires = readinessNow.Add(time.Minute)
	g2, err := SignReadyGate(readinessEval(t, l, a), priv)
	if err != nil || !g2.ExpiresAt.Equal(readinessNow.Add(time.Minute)) {
		t.Fatalf("authorization expiry must cap the gate: %v %v", err, g2.ExpiresAt)
	}
	// Shape validation: even a correctly signed malformed gate is refused.
	for name, f := range map[string]func(*ReadyGate){
		"zero lifetime": func(g *ReadyGate) { g.ExpiresAt = g.IssuedAt },
		"version":       func(g *ReadyGate) { g.Version = 2 },
		"empty scope":   func(g *ReadyGate) { g.Scope = "" },
		"zero issued":   func(g *ReadyGate) { g.IssuedAt = time.Time{} },
		"zero expiry":   func(g *ReadyGate) { g.ExpiresAt = time.Time{} },
		"digest":        func(g *ReadyGate) { g.LedgerDigest = "short" },
	} {
		z := clone()
		f(&z)
		sb, _ = readinessSigningBytes(z)
		z.Signature = hex.EncodeToString(ed25519.Sign(priv, sb))
		if VerifyReadyGate(z, pub, readinessNow) == nil {
			t.Errorf("signed malformed gate (%s) refused", name)
		}
	}
	// Gate lifetime is the minimum over criteria, whatever their order.
	l3, a3 := readinessFixture()
	l3 = readinessMutate(l3, ReadinessLegacyRetention, func(e *EvidenceRef) { e.ObservedAt = readinessNow.Add(-50 * time.Minute) })
	g3, err := SignReadyGate(readinessEval(t, l3, a3), priv)
	if err != nil || !g3.ExpiresAt.Equal(readinessNow.Add(10*time.Minute)) {
		t.Fatalf("lifetime must be the minimum: %v %v", err, g3.ExpiresAt)
	}
}

func TestCutoverReadinessPublicProjectionIsClosed(t *testing.T) {
	l, a := readinessFixture()
	l = readinessWithout(l, ReadinessLegacyRetention)
	l = readinessMutate(l, ReadinessQueryProfile, func(e *EvidenceRef) { e.Result = ReadinessResultNotRun })
	p := ReadinessPublicSummary(readinessEval(t, l, a))
	if p.CustomerAcceptance || p.Ready || p.CriteriaRequired != 10 || p.CriteriaSatisfied != 8 {
		t.Fatalf("%+v", p)
	}
	b, _ := json.Marshal(p)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if len(m) != 6 {
		t.Fatalf("closed shape: %s", b)
	}
	for _, s := range []string{"synthetic-scope", "auth-1", "product-domain", "external-domain", "0000000000", "2026"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("public output leaks %q: %s", s, b)
		}
	}
	ready := readinessEval(t, func() AcceptanceLedger { x, _ := readinessFixture(); return x }(), a)
	if q := ReadinessPublicSummary(ready); !q.Ready || q.CustomerAcceptance || len(q.BlockerCounts) != 0 {
		t.Fatalf("%+v", q)
	}
}

func TestCutoverReadinessCLI(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, v any) string {
		p := filepath.Join(dir, name)
		b, _ := json.Marshal(v)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	l, a := readinessFixture()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := filepath.Join(dir, "key")
	_ = os.WriteFile(key, []byte(hex.EncodeToString(seed)+"\n"), 0o600)
	pub, _ := readinessKeys(t)
	args := func(ledger, tag string) []string {
		return []string{"--ledger", ledger, "--authorizations", write("auth.json", a), "--signing-key", key,
			"--private-output", filepath.Join(dir, tag+".private.json"), "--public-summary", filepath.Join(dir, tag+".public.json")}
	}
	ok := write("ok.json", l)
	if err := runReadiness(context.Background(), args(ok, "ok")); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Gate *ReadyGate `json:"gate"`
	}
	b, _ := os.ReadFile(filepath.Join(dir, "ok.private.json"))
	if json.Unmarshal(b, &out) != nil || out.Gate == nil || VerifyReadyGate(*out.Gate, pub, readinessNow) != nil {
		t.Fatalf("CLI gate must verify: %s", b)
	}
	// Existing outputs are never overwritten.
	if runReadiness(context.Background(), args(ok, "ok")) == nil {
		t.Fatal("must not overwrite")
	}
	bad := write("bad.json", readinessWithout(l, ReadinessExternalDeadman))
	err := runReadiness(context.Background(), args(bad, "bad"))
	if err == nil || !strings.Contains(err.Error(), "missing_evidence:external_deadman") {
		t.Fatalf("incomplete must fail naming blocker: %v", err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "bad.private.json"))
	if strings.Contains(string(b), `"gate"`) && strings.Contains(string(b), `"signature"`) {
		t.Fatal("no signed gate when incomplete")
	}
	pb, _ := os.ReadFile(filepath.Join(dir, "bad.public.json"))
	if !strings.Contains(string(pb), `"customer_acceptance": false`) {
		t.Fatalf("%s", pb)
	}
	// Clock override makes the evidence stale.
	if runReadiness(context.Background(), append(args(ok, "stale"), "--now", "2026-11-11T12:00:00Z")) == nil {
		t.Fatal("stale under later clock")
	}
	if runReadiness(context.Background(), []string{"--ledger", ok}) == nil {
		t.Fatal("missing flags")
	}
}
