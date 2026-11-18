// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// rehash points every observation at the digest of the config's current stream.
func rehash(c *ReleaseConfig) {
	sum := sha256.Sum256(c.TestEvidence)
	for i := range c.Tests {
		c.Tests[i].EvidenceSHA256 = hex.EncodeToString(sum[:])
	}
}

// An observation is evidence only if it is backed by the go test stream it names:
// the stream's digest must be the observation's digest and the stream must hold a
// pass event for the test (and no failed or skipped one). A hand-written entry
// with a well-formed digest observes nothing.
func TestReleaseCountsAnObservationNothingBacksAsUnobserved(t *testing.T) {
	names := func(c *ReleaseConfig) []string {
		var out []string
		for _, o := range c.Tests {
			out = append(out, o.Name)
		}
		return out
	}
	event := func(action, test, pkg string) string {
		return fmt.Sprintf(`{"Time":"2026-11-15T13:36:49Z","Action":%q,"Package":%q,"Test":%q}`+"\n", action, pkg, test)
	}
	faults := []struct {
		name       string
		mutate     func(c *ReleaseConfig)
		unobserved int
		want       string
	}{
		{"no evidence stream", func(c *ReleaseConfig) { c.TestEvidence = nil }, 5, "go test evidence is absent"},
		{"an observation hashed over another stream", func(c *ReleaseConfig) {
			sum := sha256.Sum256([]byte("another stream"))
			c.Tests[0].EvidenceSHA256 = hex.EncodeToString(sum[:])
		}, 1, "does not match the go test stream"},
		{"an upper-case digest of the stream is still the stream's digest", func(c *ReleaseConfig) {
			c.Tests[0].EvidenceSHA256 = strings.ToUpper(c.Tests[0].EvidenceSHA256)
		}, 0, ""},
		{"a stream with no pass event for one test", func(c *ReleaseConfig) {
			all := names(c)
			c.TestEvidence = goTestStream(all[1:]...)
			rehash(c)
		}, 1, "not backed by a pass event"},
		{"a stream that records the test as failed", func(c *ReleaseConfig) {
			c.TestEvidence = append(c.TestEvidence, event("fail", c.Tests[0].Name, "example.test/other")...)
			rehash(c)
		}, 1, "not backed by a pass event"},
		{"a stream that records the test as skipped", func(c *ReleaseConfig) {
			c.TestEvidence = append(c.TestEvidence, event("skip", c.Tests[0].Name, "example.test/other")...)
			rehash(c)
		}, 1, "not backed by a pass event"},
		{"events of other tests and outputs change nothing", func(c *ReleaseConfig) {
			c.TestEvidence = append(c.TestEvidence, event("fail", "TestSomethingElse", "example.test/pkg")...)
			c.TestEvidence = append(c.TestEvidence, event("output", c.Tests[0].Name, "example.test/pkg")...)
			c.TestEvidence = append(c.TestEvidence, event("pass", c.Tests[0].Name+"/sub", "example.test/pkg")...)
			c.TestEvidence = append(c.TestEvidence, `{"Time":"2026-11-15T13:36:49Z","Action":"fail","Package":"example.test/pkg"}`+"\n"...)
			c.TestEvidence = append(c.TestEvidence, "\n"...)
			rehash(c)
		}, 0, ""},
		{"a stream that is not go test json", func(c *ReleaseConfig) {
			c.TestEvidence = []byte("this is not a go test stream\n")
			rehash(c)
		}, 5, "is not a go test event"},
		{"a pass for a subtest does not observe the parent", func(c *ReleaseConfig) {
			var b strings.Builder
			for _, n := range names(c) {
				b.WriteString(event("pass", n+"/case", "example.test/pkg"))
			}
			c.TestEvidence = []byte(b.String())
			rehash(c)
		}, 5, "not backed by a pass event"},
	}
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			cfg := releaseFixture(t)
			f.mutate(&cfg)
			rep, err := runGate(t, cfg)
			if f.unobserved == 0 {
				if err != nil || rep.UnobservedTests != 0 {
					t.Fatalf("a backed observation was refused: %v unobserved %d %q", err, rep.UnobservedTests, rep.Failures)
				}
				return
			}
			requireRejected(t, rep, err, f.want)
			if rep.UnobservedTests != f.unobserved || rep.UnboundCount != 0 {
				t.Fatalf("unobserved %d (want %d) unbound %d", rep.UnobservedTests, f.unobserved, rep.UnboundCount)
			}
		})
	}
	// The shape of an observation is still checked.
	for name, mutate := range map[string]func(o *TestObservation){
		"not passed":    func(o *TestObservation) { o.Passed = false },
		"no command":    func(o *TestObservation) { o.Command = "" },
		"no name":       func(o *TestObservation) { o.Name = "" },
		"digest length": func(o *TestObservation) { o.EvidenceSHA256 = o.EvidenceSHA256[:62] },
		"digest hex":    func(o *TestObservation) { o.EvidenceSHA256 = strings.Repeat("zz", 32) },
	} {
		cfg := releaseFixture(t)
		mutate(&cfg.Tests[0])
		rep, err := runGate(t, cfg)
		requireRejected(t, rep, err, "")
		if rep.UnobservedTests != 1 {
			t.Errorf("%s: unobserved %d", name, rep.UnobservedTests)
		}
	}
}

// The real acceptance.json: every observation is backed by the recorded go test
// stream, and every Go test a production binding cites is one of them.
func TestRealTestObservationsAreBackedByTheRecordedStream(t *testing.T) {
	inRepoRoot(t)
	cfg, err := LoadReleaseConfig("conformance/query", "conformance/query/release-policy.json", nil, []uint64{20261110})
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TestEvidence) == 0 {
		t.Fatal("the go test evidence stream was not loaded with the observations it backs")
	}
	passed, problems := observedTests(cfg.Tests, cfg.TestEvidence)
	if len(problems) != 0 {
		t.Fatalf("the recorded observations are not backed by their stream: %q", problems)
	}
	if len(passed) != len(cfg.Tests) || len(passed) < 100 {
		t.Fatalf("%d of %d observations are backed", len(passed), len(cfg.Tests))
	}
	var unobserved []string
	for _, b := range cfg.Bindings {
		for _, name := range b.GoTests {
			if !passed[name] {
				unobserved = append(unobserved, b.ObligationID+" cites "+name)
			}
		}
	}
	if len(unobserved) != 0 {
		t.Fatalf("%d bindings cite Go tests no evidence observes, e.g. %q", len(unobserved), unobserved[:min(3, len(unobserved))])
	}
}
