// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"strings"
	"testing"
)

// lockedIdentity is the identity the pinned oracle of the row's phase reports: the
// evaluation oracle, or for a configuration-phase row its locked variant.
func lockedIdentity(p SourceProfile, rowType string) *OracleIdentity {
	image, configuration := p.Artifact.SHA256, p.Artifact.ConfigurationSHA256
	if rowType == ConfigurationPhaseType && p.ConfigurationOracle != nil {
		image, configuration = strings.TrimPrefix(p.ConfigurationOracle.ImageID, "sha256:"), p.ConfigurationOracle.ConfigurationFileSHA256
	}
	version := strings.TrimPrefix(strings.TrimPrefix(p.ID, "promql-prometheus-"), "logql-loki-")
	return &OracleIdentity{Profile: p.ID, Revision: p.Commit, Version: version, ImageSHA256: image, ConfigurationSHA256: configuration}
}

// The real locked data must satisfy the gate's stricter checks (the floor of
// scenario names, the strictly decoded policy, manifest and spec, the go test
// evidence stream, the derived interaction coverage). With a runtime absent from
// the unit test environment, the oracle is the only fake: it answers every
// authored and generated row as the locked pinned oracle would and the owned
// side agrees. Everything else is the repository's own data.
func TestTheRealLockedDataPassesTheGateOnceEveryRowRunsAndMatches(t *testing.T) {
	inRepoRoot(t)
	cfg, err := LoadReleaseConfig("conformance/query", "conformance/query/release-policy.json", validSmokeReport(), []uint64{20261110})
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[string]SourceProfile{}
	for _, p := range cfg.Lock.Profiles {
		profiles[p.ID] = p
	}
	observed := PhaseResults{}
	for _, c := range cfg.Cases {
		observed[PhaseKey(c.Profile, c.ID)] = PhaseOutcome{Phase: c.Expected.Type, Identity: lockedIdentity(profiles[c.Profile], c.Expected.Type)}
	}
	cfg.Oracle, cfg.Own = observed.PhaseOracle(), observed.PhaseOwn()
	for i, run := range cfg.Generated {
		cfg.Generated[i] = agreeingRun(cfg, run.Seed, run.Rows)
	}
	rep, err := ReleaseGate(context.Background(), cfg)
	requireReportInvariants(t, rep)
	if err != nil {
		t.Fatalf("the real locked data was rejected: %v\n%q", err, rep.Failures)
	}
	if rep.ObligationCount < 700 || rep.BoundCount != rep.ObligationCount || rep.UnobservedTests != 0 || rep.MatchedCaseCount != rep.RequiredCaseCount || rep.OracleUnverified != 0 || rep.OracleUnavailable != 0 {
		t.Errorf("counts of the real locked data: %+v", rep)
	}
	if rep.InteractionRequired < 100 || rep.InteractionCovered != rep.InteractionRequired || rep.ProvenanceRejected != 0 || rep.ScenarioFailures != 0 {
		t.Errorf("interactions %d of %d, provenance rejected %d, scenario failures %d", rep.InteractionCovered, rep.InteractionRequired, rep.ProvenanceRejected, rep.ScenarioFailures)
	}
	if len(rep.Generated) != 1 || rep.Generated[0].Executed != rep.Generated[0].Generated || rep.Generated[0].Matched != rep.Generated[0].Generated {
		t.Errorf("generated rows: %+v", rep.Generated)
	}
}

// A locked document is read through the lock and then strictly: the approved bytes
// are the only bytes decoded, and a locked document this code can only partly
// understand is refused rather than partly enforced. ReadLockedJSON keeps decoding
// the way its other callers expect.
func TestReadLockedStrictDecodesOnlyTheApprovedBytesAndEverythingInThem(t *testing.T) {
	const body = `{"a":1,"z":2}`
	path := writeTemp(t, "doc.json", body)
	lock := SourceLock{InventoryFiles: map[string]string{"doc.json": digestOf(body), "short.json": "abc"}}
	var target struct {
		A int `json:"a"`
	}
	if err := ReadLockedJSON(lock, "doc.json", path, &target); err != nil || target.A != 1 {
		t.Fatalf("the ordinary locked read refused an unknown field its callers rely on being ignored: %v", err)
	}
	if err := readLockedStrict(lock, "doc.json", path, &target); err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "doc.json") {
		t.Fatalf("the strict locked read ignored an unknown field: %v", err)
	}
	clean := writeTemp(t, "clean.json", `{"a":3}`)
	lock.InventoryFiles["clean.json"] = digestOf(`{"a":3}`)
	if err := readLockedStrict(lock, "clean.json", clean, &target); err != nil || target.A != 3 {
		t.Fatalf("the strict locked read refused a document it fully understands: %v", err)
	}
	for _, c := range []struct {
		name string
		run  func() error
	}{
		{"changed bytes", func() error { return readLockedStrict(lock, "doc.json", clean, &target) }},
		{"no lock", func() error { return readLockedStrict(lock, "other.json", path, &target) }},
		{"a malformed lock", func() error { return readLockedStrict(lock, "short.json", path, &target) }},
		{"no file", func() error { return readLockedStrict(lock, "doc.json", path+".missing", &target) }},
	} {
		if err := c.run(); err == nil {
			t.Errorf("%s: the strict locked read was accepted", c.name)
		}
	}
}
