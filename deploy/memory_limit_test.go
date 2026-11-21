// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package deploy holds the shipped deployment descriptors; this test keeps the memory ceiling
// they carry (docs/artifacts/source-maps.md, "Sizing the memory limit") from being dropped.
package deploy

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// bytesOf parses a Go GOMEMLIMIT value (B, KiB, MiB, GiB) or a systemd/compose/Kubernetes size
// (K, M, G, Ki, Mi, Gi, k, m, g), always as powers of 1024.
func bytesOf(t *testing.T, v string) uint64 {
	t.Helper()
	m := regexp.MustCompile(`^([0-9]+)(B|KiB|MiB|GiB|Ki|Mi|Gi|K|M|G|k|m|g)?$`).FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		t.Fatalf("unparsable size %q", v)
	}
	n, _ := strconv.ParseUint(m[1], 10, 64)
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(m[2], "iB"), "i")) {
	case "k":
		return n << 10
	case "m":
		return n << 20
	case "g":
		return n << 30
	}
	return n
}

func submatch(t *testing.T, re, text, what string) string {
	t.Helper()
	m := regexp.MustCompile(re).FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("%s: no match for %s", what, re)
	}
	return m[1]
}

// The Go heap limit must exist and sit strictly below the hard limit, so the collector works
// harder before the kernel kills the process.
func below(t *testing.T, what, soft, hard string) {
	t.Helper()
	s, h := bytesOf(t, soft), bytesOf(t, hard)
	if s < 512<<20 || s >= h {
		t.Fatalf("%s: GOMEMLIMIT %s must be at least 512MiB and below the hard limit %s", what, soft, hard)
	}
}

func TestSystemdUnitShipsAMemoryCeiling(t *testing.T) {
	unit := read(t, "systemd/soundpost.service")
	soft := submatch(t, `(?m)^Environment=GOMEMLIMIT=(\S+)$`, unit, "soundpost.service GOMEMLIMIT")
	hard := submatch(t, `(?m)^MemoryMax=(\S+)$`, unit, "soundpost.service MemoryMax")
	below(t, "soundpost.service", soft, hard)
}

func TestComposeSingleShipsAMemoryCeiling(t *testing.T) {
	compose := read(t, "compose.single.yaml")
	soft := submatch(t, `(?m)^\s+GOMEMLIMIT: \$\{SOUNDPOST_GOMEMLIMIT:-(\S+)\}$`, compose, "compose GOMEMLIMIT default")
	hard := submatch(t, `(?m)^\s+mem_limit: \$\{SOUNDPOST_MEMORY_LIMIT:-(\S+)\}$`, compose, "compose mem_limit default")
	below(t, "compose.single.yaml", soft, hard)
}

func TestHelmChartShipsAMemoryCeiling(t *testing.T) {
	values := read(t, "helm/soundpost/values.yaml")
	soft := submatch(t, `(?m)^  goMemLimit: (\S+)$`, values, "values goMemLimit")
	hard := submatch(t, `(?m)^  limits: \{memory: (\S+)\}$`, values, "values limits.memory")
	below(t, "helm values", soft, hard)
	sts := read(t, "helm/soundpost/templates/statefulset.yaml")
	if !strings.Contains(sts, `name: GOMEMLIMIT, value: {{ $root.Values.resources.goMemLimit | quote }}`) {
		t.Fatal("the member container does not receive resources.goMemLimit as GOMEMLIMIT")
	}
}
