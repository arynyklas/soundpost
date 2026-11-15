// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"fmt"
	"path/filepath"
	"regexp"
)

// AdapterFormat records where an adapter wire-format fact (field numbers,
// grammar, block format) was read: the pinned upstream commit, the SHA-256 of
// the exact bytes fetched, and the SPDX licence taken from the LICENSE file
// present at that commit. No upstream code or schema text is copied.
type AdapterFormat struct {
	ID            string `json:"id"`
	Format        string `json:"format"`
	Upstream      string `json:"upstream"`
	Ref           string `json:"ref"`
	Commit        string `json:"commit"`
	Path          string `json:"path"`
	URL           string `json:"url"`
	SHA256        string `json:"sha256"`
	SPDXLicense   string `json:"spdx_license"`
	LicensePath   string `json:"license_path"`
	LicenseSHA256 string `json:"license_sha256"`
	UsedFor       string `json:"used_for"`
}

// requiredAdapterFormats is the closed set of provenance entries; removing one
// or adding an unknown one fails validation. lockProfile, when set, binds the
// commit to that source-lock profile.
var requiredAdapterFormats = []struct {
	ID, Format, Upstream, Path, SPDX, LicensePath, LockProfile string
}{
	{"remote_write_v1:3.1.0:prompb/types.proto", "remote_write_v1", "prometheus/prometheus", "prompb/types.proto", "Apache-2.0", "LICENSE", "promql-prometheus-3.1.0"},
	{"remote_write_v1:3.1.0:prompb/remote.proto", "remote_write_v1", "prometheus/prometheus", "prompb/remote.proto", "Apache-2.0", "LICENSE", "promql-prometheus-3.1.0"},
	{"remote_write_v1:3.13.5:prompb/types.proto", "remote_write_v1", "prometheus/prometheus", "prompb/types.proto", "Apache-2.0", "LICENSE", "promql-prometheus-3.13.5"},
	{"remote_write_v1:3.13.5:prompb/remote.proto", "remote_write_v1", "prometheus/prometheus", "prompb/remote.proto", "Apache-2.0", "LICENSE", "promql-prometheus-3.13.5"},
	{"remote_write_v2:3.1.0:prompb/io/prometheus/write/v2/types.proto", "remote_write_v2", "prometheus/prometheus", "prompb/io/prometheus/write/v2/types.proto", "Apache-2.0", "LICENSE", "promql-prometheus-3.1.0"},
	{"remote_write_v2:3.13.5:prompb/io/prometheus/write/v2/types.proto", "remote_write_v2", "prometheus/prometheus", "prompb/io/prometheus/write/v2/types.proto", "Apache-2.0", "LICENSE", "promql-prometheus-3.13.5"},
	{"openmetrics_1_0:specification/OpenMetrics.md", "openmetrics_1_0", "prometheus/OpenMetrics", "specification/OpenMetrics.md", "Apache-2.0", "LICENSE", ""},
	{"loki_push:pkg/push/push.proto", "loki_push", "grafana/loki", "pkg/push/push.proto", "Apache-2.0", "pkg/push/LICENSE", "logql-loki-3.5.2"},
	{"snappy_block:format_description.txt", "snappy_block", "google/snappy", "format_description.txt", "BSD-3-Clause", "COPYING", ""},
}

var (
	hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// LoadAdapterFormats reads the adapter_formats section of provenance.json.
func LoadAdapterFormats(queryDir string) ([]AdapterFormat, error) {
	var manifest struct {
		Entries []AdapterFormat `json:"adapter_formats"`
	}
	if err := ReadJSON(filepath.Join(queryDir, "provenance.json"), &manifest); err != nil {
		return nil, err
	}
	return manifest.Entries, nil
}

// ValidateAdapterFormats requires exactly the required entry set, each with a
// pinned commit (bound to the source lock where the lock pins the same repo),
// a derived raw URL, 64-hex content and licence digests, the expected SPDX
// licence and licence file, and a stated use.
func ValidateAdapterFormats(entries []AdapterFormat, lock SourceLock) error {
	commits := map[string]string{}
	for _, p := range lock.Profiles {
		commits[p.ID] = p.Commit
	}
	byID := map[string]AdapterFormat{}
	for _, e := range entries {
		if _, dup := byID[e.ID]; dup {
			return fmt.Errorf("adapter provenance: duplicate entry %s", e.ID)
		}
		byID[e.ID] = e
	}
	if len(byID) != len(requiredAdapterFormats) {
		return fmt.Errorf("adapter provenance: %d entries, want exactly %d", len(byID), len(requiredAdapterFormats))
	}
	for _, r := range requiredAdapterFormats {
		e, ok := byID[r.ID]
		if !ok {
			return fmt.Errorf("adapter provenance: missing entry %s", r.ID)
		}
		bad := func(what string) error { return fmt.Errorf("adapter provenance %s: %s", r.ID, what) }
		switch {
		case e.Format != r.Format || e.Upstream != r.Upstream || e.Path != r.Path:
			return bad("format/upstream/path differ from the required entry")
		case e.SPDXLicense != r.SPDX:
			return bad(fmt.Sprintf("licence %q, want %s", e.SPDXLicense, r.SPDX))
		case e.LicensePath != r.LicensePath:
			return bad(fmt.Sprintf("licence file %q, want %s", e.LicensePath, r.LicensePath))
		case !hex40.MatchString(e.Commit):
			return bad("commit is not a 40-hex pin")
		case r.LockProfile != "" && e.Commit != commits[r.LockProfile]:
			return bad("commit differs from the source-lock pin for " + r.LockProfile)
		case e.URL != "https://raw.githubusercontent.com/"+e.Upstream+"/"+e.Commit+"/"+e.Path:
			return bad("url is not the raw URL of upstream@commit/path")
		case !hex64.MatchString(e.SHA256) || !hex64.MatchString(e.LicenseSHA256):
			return bad("content or licence sha256 is not 64-hex")
		case e.Ref == "" || e.UsedFor == "":
			return bad("ref and used_for are required")
		}
	}
	return nil
}
