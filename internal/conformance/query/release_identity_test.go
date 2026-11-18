// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"strings"
	"testing"
)

// An oracle observation counts only if it names the locked image, the locked
// configuration, the profile, a revision of the pinned commit long enough to mean
// it and the pinned version. Each field is its own way to be wrong.
func TestOracleIdentityIsVerifiedFieldByField(t *testing.T) {
	prom := SourceProfile{ID: "promql-prometheus-3.13.5", Commit: "f497435984d1ca1d84cda5ed309387ac2eb1f8f6", Artifact: &Artifact{SHA256: strings.Repeat("a", 64), ConfigurationSHA256: strings.Repeat("b", 64)}}
	loki := SourceProfile{ID: "logql-loki-3.5.2", Commit: "257d2f62bf8a81b44dea6fe88968d1d28c8e01e7", Artifact: &Artifact{SHA256: strings.Repeat("c", 64), ConfigurationSHA256: strings.Repeat("d", 64)}}
	answer := func(p SourceProfile, revision, version string) SemanticResult {
		return SemanticResult{Oracle: &OracleIdentity{Profile: p.ID, Revision: revision, Version: version, ImageSHA256: p.Artifact.SHA256, ConfigurationSHA256: p.Artifact.ConfigurationSHA256}}
	}
	tampered := func(mutate func(o *OracleIdentity)) SemanticResult {
		r := answer(prom, "f497435", "3.13.5")
		mutate(r.Oracle)
		return r
	}
	for _, c := range []struct {
		name   string
		p      SourceProfile
		r      SemanticResult
		accept bool
	}{
		{"a PromQL pin by its short revision", prom, answer(prom, "f497435", "3.13.5"), true},
		{"a PromQL pin by its full commit", prom, answer(prom, prom.Commit, "3.13.5"), true},
		{"a version carrying the v prefix", prom, answer(prom, "f497435", "v3.13.5"), true},
		{"a LogQL pin", loki, answer(loki, "257d2f6", "3.5.2"), true},
		{"a LogQL pin with the v prefix", loki, answer(loki, "257d2f6", "v3.5.2"), true},
		{"a revision one short of seven characters", prom, answer(prom, "f49743", "3.13.5"), false},
		{"no revision", prom, answer(prom, "", "3.13.5"), false},
		{"a revision that is not a prefix of the pin", prom, answer(prom, "e497435", "3.13.5"), false},
		{"a revision longer than the pin", prom, answer(prom, prom.Commit+"0", "3.13.5"), false},
		{"another version", prom, answer(prom, "f497435", "3.1.0"), false},
		{"no version", prom, answer(prom, "f497435", ""), false},
		{"the v prefix twice", prom, answer(prom, "f497435", "vv3.13.5"), false},
		{"another profile", prom, answer(loki, "f497435", "3.13.5"), false},
		{"the profile name alone differs", prom, tampered(func(o *OracleIdentity) { o.Profile = loki.ID }), false},
		{"another image", prom, tampered(func(o *OracleIdentity) { o.ImageSHA256 = strings.Repeat("0", 64) }), false},
		{"another configuration", prom, tampered(func(o *OracleIdentity) { o.ConfigurationSHA256 = strings.Repeat("0", 64) }), false},
		{"the image and configuration swapped", prom, tampered(func(o *OracleIdentity) { o.ImageSHA256, o.ConfigurationSHA256 = o.ConfigurationSHA256, o.ImageSHA256 }), false},
		{"no identity at all", prom, SemanticResult{}, false},
		{"a profile without a locked artifact", SourceProfile{ID: prom.ID, Commit: prom.Commit}, answer(prom, "f497435", "3.13.5"), false},
		{"a LogQL version asked of a PromQL profile", prom, answer(prom, "f497435", "3.5.2"), false},
		{"a PromQL version asked of the LogQL profile", loki, answer(loki, "257d2f6", "3.13.5"), false},
	} {
		if got := oracleIdentityOK(c.p, c.r); got != c.accept {
			t.Errorf("%s: oracleIdentityOK = %v, want %v", c.name, got, c.accept)
		}
	}
}
