// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"errors"
	"testing"
	"time"
)

// The duration and byte-size spellings of the pinned loader, as observed from
// the reference on the authored scenarios (conformance/query/cases/
// release-configuration.json): every accepted spelling and every refused one.
func TestPromConfigDurationAndSizeGrammar(t *testing.T) {
	for text, want := range map[string]time.Duration{
		"0": 0, "0s": 0, "1ms": time.Millisecond, "1s": time.Second, "1m": time.Minute, "5m": 5 * time.Minute, "1h": time.Hour,
		"1h30m": 90 * time.Minute, "1500ms": 1500 * time.Millisecond, "1s500ms": 1500 * time.Millisecond, "1m500ms": time.Minute + 500*time.Millisecond,
		"1d": 24 * time.Hour, "1w": 7 * 24 * time.Hour, "1y": 365 * 24 * time.Hour, "2d3h4m5s6ms": 51*time.Hour + 4*time.Minute + 5*time.Second + 6*time.Millisecond,
	} {
		if got, ok := parsePromDuration(text); !ok || got != want {
			t.Errorf("duration %q: got %v, %t; want %v", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "abc", "-5s", "5", "1.5s", "30s1m", "1m1m", "1 m", "1S", "s", "1ms1m", "99999999999999999999s"} {
		if got, ok := parsePromDuration(text); ok {
			t.Errorf("duration %q accepted as %v", text, got)
		}
	}
	for text, want := range map[string]int64{
		"0": 0, "0B": 0, "1B": 1, "1KB": 1 << 10, "1KiB": 1 << 10, "2MB": 2 << 20, "1MB512KB": 3 << 19, "10GB": 10 << 30, "1TiB": 1 << 40, "3KB": 3 << 10,
	} {
		if got, ok := parsePromBytes(text); !ok || got != want {
			t.Errorf("size %q: got %d, %t; want %d", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "1000", "abc", "1kb", "1 MB", "KB", "1.5MB", "-1MB", "99999999999EiB"} {
		if got, ok := parsePromBytes(text); ok {
			t.Errorf("size %q accepted as %d", text, got)
		}
	}
}

// Keys outside the modelled set are neither interpreted nor refused; the
// effective values of the modelled keys do not depend on them.
func TestPromConfigIgnoresUnmodelledKeys(t *testing.T) {
	plain := "scrape_configs:\n  - job_name: a\n    scrape_interval: 5s\n"
	rich := "rule_files: [\"r.yml\"]\nscrape_configs:\n  - job_name: a\n    scrape_interval: 5s\n    metrics_path: /x\n    relabel_configs: []\n    static_configs:\n      - targets: ['h:1']\n"
	for _, profile := range []PrometheusConfigProfile{PrometheusConfig310, PrometheusConfig3135} {
		a, err := ResolvePrometheusScrapeConfig(profile, nil, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		b, err := ResolvePrometheusScrapeConfig(profile, nil, []byte(rich))
		if err != nil {
			t.Fatal(err)
		}
		if a.Jobs[0].ScrapeInterval != b.Jobs[0].ScrapeInterval || a.Jobs[0].ScrapeTimeout != 5*time.Second || b.Jobs[0].ScrapeTimeout != 5*time.Second {
			t.Errorf("%s: unmodelled keys changed the result: %+v vs %+v", profile, a.Jobs[0], b.Jobs[0])
		}
	}
}

func TestPromConfigRefusalCarriesFamilyAndScope(t *testing.T) {
	_, err := ResolvePrometheusScrapeConfig(PrometheusConfig3135, nil, []byte("scrape_configs:\n  - job_name: web\n    scrape_protocols: []\n"))
	var ce *PrometheusConfigError
	if !errors.As(err, &ce) || ce.Family != PromConfigProtocolsEmpty || ce.Scope != "job:web" {
		t.Fatalf("got %v", err)
	}
	if _, err = ResolvePrometheusScrapeConfig("promql-prometheus-9.9.9", nil, nil); err == nil {
		t.Fatal("an unknown profile resolved")
	}
	if _, err = ResolvePrometheusScrapeConfig(PrometheusConfig310, nil, []byte("global: [")); err == nil {
		t.Fatal("a malformed document resolved")
	}
}
