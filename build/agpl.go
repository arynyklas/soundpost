// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const checkAGPL = "agpl_derived"

// agplRoots are the first-party trees that ship in or test the product. Provenance records of
// separately acquired, never-vendored upstream artifacts (conformance/query) and docs may name AGPL.
var agplRoots = []string{"cmd", "internal", "packages", "sdk", "tools", "fixtures", "profiles", "web/src", "drills", "tests", "examples", "third_party", "deploy"}

var (
	agplHeader   = regexp.MustCompile(`(?i)SPDX-License-Identifier:[^\n]*AGPL|GNU AFFERO GENERAL PUBLIC LICENSE`)
	agplManifest = regexp.MustCompile(`(?i)["']?(?:license|licence|spdx_license|spdx)["']?\s*[:=]\s*["']?[^"'\n]*AGPL`)
)

// agplFindings lists first-party files carrying an AGPL license header, license text, or a
// provenance/corpus manifest declaring an AGPL license: derived source or a derived corpus
// cannot ship in an Apache-2.0 release. Go test files naming AGPL as a fixture string are skipped.
func agplFindings(root string) []string {
	var out []string
	for _, top := range agplRoots {
		base := filepath.Join(root, filepath.FromSlash(top))
		if _, err := os.Stat(base); err != nil {
			continue // a tree this repository does not have
		}
		_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				out = append(out, filepath.ToSlash(path)+" is unreadable: the AGPL scan cannot vouch for it")
				return nil
			}
			if d.IsDir() {
				if n := d.Name(); n == "node_modules" || n == ".git" || n == "dist" || n == ".tools" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, e := os.ReadFile(path)
			if e != nil {
				out = append(out, filepath.ToSlash(path)+" is unreadable: the AGPL scan cannot vouch for it")
				return nil
			}
			if agplHeader.Match(raw) || ((strings.HasSuffix(path, ".json") || strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".toml")) && agplManifest.Match(raw)) {
				rel, _ := filepath.Rel(root, path)
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

func checkAGPLOf(r Reports) Check {
	c := Check{Name: checkAGPL, Detail: "no AGPL header, license text or AGPL-licensed corpus manifest in first-party trees"}
	for _, f := range agplFindings(r.Root) {
		if strings.Contains(f, " is unreadable") {
			c.Blocking = append(c.Blocking, f)
			continue
		}
		c.Blocking = append(c.Blocking, f+" carries an AGPL license: AGPL-derived source or corpus cannot be released")
	}
	return c
}
