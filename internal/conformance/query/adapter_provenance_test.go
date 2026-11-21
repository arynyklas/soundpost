// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"path/filepath"
	"strings"
	"testing"
)

// The digests below were fetched from the recorded raw URLs on 2026-11-15; this
// table pins them independently of provenance.json so an edited hash or licence
// in the manifest is caught.
var pinnedAdapterDigests = map[string][3]string{ // id -> {content sha256, SPDX, licence sha256}
	"remote_write_v1:3.1.0:prompb/types.proto":                         {"8a5bbe5e908327875f21108fbda9296678f333392dd12d887f7687ff58e25aea", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"remote_write_v1:3.1.0:prompb/remote.proto":                        {"489d69b2a18db3394dc471ca9d4acf984f202b90b7fc89cdd6df605fb29135cb", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"remote_write_v1:3.13.5:prompb/types.proto":                        {"e89cd64c7b7131c3fc5305272c0716ba203636795a8e4e55bdec64c92106bbfe", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"remote_write_v1:3.13.5:prompb/remote.proto":                       {"489d69b2a18db3394dc471ca9d4acf984f202b90b7fc89cdd6df605fb29135cb", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"remote_write_v2:3.1.0:prompb/io/prometheus/write/v2/types.proto":  {"772846f0991cede7634cbbba1b978ae0412e04ceb9658242d2864b75285c67c8", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"remote_write_v2:3.13.5:prompb/io/prometheus/write/v2/types.proto": {"a34d320a205d86b18000231644d144a899f9b9031ce472cbe62e5dba1bc756d1", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"openmetrics_1_0:specification/OpenMetrics.md":                     {"3115ed69476ddb5e4b64ebf363f1a8f5d0f0a7cc2a6263ea612360d5357f877e", "Apache-2.0", "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4"},
	"loki_push:pkg/push/push.proto":                                    {"47456eccd4f53369c8abf26d490058b48ed0b02c41a76e1fdc1b0ff8bc594aee", "Apache-2.0", "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"},
	"snappy_block:format_description.txt":                              {"1c0b26655d222a24d83707cea12611fa224cc3b128399976bb3fbee2a02fc05a", "BSD-3-Clause", "55172044f7e241207117448a4d9d6ba1d0925c8ad66b5d4c08c70adfa9cc3de6"},
}

func loadAdapterFixture(t *testing.T) ([]AdapterFormat, SourceLock) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "conformance", "query")
	entries, err := LoadAdapterFormats(dir)
	if err != nil {
		t.Fatal(err)
	}
	var lock SourceLock
	if err := ReadJSON(filepath.Join(dir, "source-lock.json"), &lock); err != nil {
		t.Fatal(err)
	}
	return entries, lock
}

func TestAdapterFormatProvenanceIsRecordedAndPinned(t *testing.T) {
	entries, lock := loadAdapterFixture(t)
	if err := ValidateAdapterFormats(entries, lock); err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(pinnedAdapterDigests) {
		t.Fatalf("%d entries, pinned %d", len(entries), len(pinnedAdapterDigests))
	}
	for _, e := range entries {
		want, ok := pinnedAdapterDigests[e.ID]
		if !ok {
			t.Fatalf("unpinned entry %s", e.ID)
		}
		if e.SHA256 != want[0] || e.SPDXLicense != want[1] || e.LicenseSHA256 != want[2] {
			t.Fatalf("%s: recorded digest/licence differ from the pinned values", e.ID)
		}
	}
}

func TestAdapterFormatProvenanceRejectsTampering(t *testing.T) {
	_, lock := loadAdapterFixture(t)
	tests := map[string]struct {
		mutate func([]AdapterFormat) []AdapterFormat
		want   string
	}{
		"entry removed":      {func(e []AdapterFormat) []AdapterFormat { return e[1:] }, "entries"},
		"entry duplicated":   {func(e []AdapterFormat) []AdapterFormat { return append(e[:len(e)-1:len(e)-1], e[0]) }, "duplicate"},
		"licence wrong":      {func(e []AdapterFormat) []AdapterFormat { e[7].SPDXLicense = "AGPL-3.0-only"; return e }, "licence"},
		"licence file wrong": {func(e []AdapterFormat) []AdapterFormat { e[7].LicensePath = "LICENSE"; return e }, "licence file"},
		"hash malformed":     {func(e []AdapterFormat) []AdapterFormat { e[0].SHA256 = "abc"; return e }, "sha256"},
		"commit unpinned":    {func(e []AdapterFormat) []AdapterFormat { e[0].Commit = "v3.1.0"; return e }, "commit"},
		"commit off lock":    {func(e []AdapterFormat) []AdapterFormat { e[7].Commit = strings.Repeat("a", 40); return e }, "source-lock"},
		"url off pin":        {func(e []AdapterFormat) []AdapterFormat { e[8].URL = "https://example.test/x"; return e }, "url"},
		"unknown entry":      {func(e []AdapterFormat) []AdapterFormat { e[0].ID = "other"; return e }, "missing entry"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			entries, _ := loadAdapterFixture(t)
			err := ValidateAdapterFormats(tc.mutate(entries), lock)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("tampered provenance accepted or wrong error: %v", err)
			}
		})
	}
	// A changed recorded hash is caught by the independent pin table.
	entries, _ := loadAdapterFixture(t)
	entries[0].SHA256 = strings.Repeat("0", 64)
	if err := ValidateAdapterFormats(entries, lock); err != nil {
		t.Fatalf("structurally valid hash should validate: %v", err)
	}
	if entries[0].SHA256 == pinnedAdapterDigests[entries[0].ID][0] {
		t.Fatal("pin table does not distinguish a changed hash")
	}
}
