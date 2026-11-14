// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// forbiddenImportPrefixes are packages no production path may reach: the
// conformance harness (which owns every oracle client) and upstream engines.
var forbiddenImportPrefixes = []string{
	"github.com/prometheus/",
	"github.com/grafana/loki",
	"github.com/grafana/dskit",
}

// forbiddenIdentifiers are the oracle entry points of this package.
var forbiddenIdentifiers = []string{"RunOracle", "ServeAdapter", "ServeLogQLAdapter", "OracleRun"}

// forbiddenLiterals in a production string literal name an oracle runtime or image.
var forbiddenLiterals = []string{"soundpost-oracle", "/bin/prometheus", "/usr/bin/loki", "oci-semantic-json-v1"}

type ClosureReport struct {
	Packages  []string `json:"packages"`
	Files     int      `json:"files"`
	Violation []string `json:"violations"`
}

// ProductionClosure proves, from source, that no production path can start or
// contact an oracle: starting from root packages it follows module-internal
// imports of non-test files (build constraints evaluated for linux and
// windows), rejects any import of the conformance harness, an upstream engine
// or the querycheck command, and scans every reached file for oracle entry
// points, oracle image names and exec of an OCI runtime. A finite source check
// complements, and does not replace, the binary symbol check.
func ProductionClosure(moduleRoot, modulePath string, roots []string) (ClosureReport, error) {
	var report ClosureReport
	seen := map[string]bool{}
	queue := append([]string(nil), roots...)
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		rel := strings.TrimPrefix(pkg, modulePath+"/")
		dir := filepath.Join(moduleRoot, filepath.FromSlash(rel))
		var imports []string
		var files []string
		for _, goos := range []string{"linux", "windows"} {
			ctx := build.Default
			ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goos, "amd64", false
			p, err := ctx.ImportDir(dir, 0)
			if err != nil {
				if _, none := err.(*build.NoGoError); none {
					continue
				}
				return report, fmt.Errorf("%s: %w", pkg, err)
			}
			imports = append(imports, p.Imports...)
			for _, f := range p.GoFiles {
				files = append(files, f)
			}
			for _, f := range p.CgoFiles {
				files = append(files, f)
			}
		}
		sort.Strings(files)
		files = dedupe(files)
		report.Packages = append(report.Packages, pkg)
		for _, imp := range dedupe(imports) {
			for _, bad := range forbiddenImportPrefixes {
				if strings.HasPrefix(imp, bad) {
					report.Violation = append(report.Violation, fmt.Sprintf("%s imports upstream engine %s", pkg, imp))
				}
			}
			if strings.HasPrefix(imp, modulePath+"/internal/conformance") || imp == modulePath+"/cmd/soundpost-querycheck" {
				report.Violation = append(report.Violation, fmt.Sprintf("%s imports the conformance harness %s", pkg, imp))
				continue
			}
			if strings.HasPrefix(imp, modulePath+"/") {
				queue = append(queue, imp)
			}
		}
		for _, name := range files {
			report.Files++
			violations, err := scanProductionFile(filepath.Join(dir, name))
			if err != nil {
				return report, err
			}
			for _, v := range violations {
				report.Violation = append(report.Violation, pkg+"/"+name+": "+v)
			}
		}
	}
	sort.Strings(report.Packages)
	sort.Strings(report.Violation)
	return report, nil
}

func dedupe(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

func scanProductionFile(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.Ident:
			for _, bad := range forbiddenIdentifiers {
				if v.Name == bad {
					out = append(out, "references oracle entry point "+bad)
				}
			}
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(v.Value)
			if err != nil {
				return true
			}
			for _, bad := range forbiddenLiterals {
				if strings.Contains(text, bad) {
					out = append(out, "names oracle artifact "+bad)
				}
			}
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") || len(v.Args) == 0 {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "exec" {
				return true
			}
			for _, a := range v.Args {
				lit, ok := a.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				text, _ := strconv.Unquote(lit.Value)
				base := strings.ToLower(filepath.Base(text))
				if strings.Contains(base, "docker") || strings.Contains(base, "podman") || strings.Contains(base, "prometheus") || strings.Contains(base, "loki") {
					out = append(out, "executes "+base)
				}
			}
		}
		return true
	})
	return out, nil
}

// ForbiddenBinarySymbols returns the symbols of `go tool nm` output that belong
// to the conformance harness or an upstream engine. The caller builds the
// production binary and passes the nm output.
func ForbiddenBinarySymbols(nmOutput, modulePath string) []string {
	var bad []string
	needles := append([]string{modulePath + "/internal/conformance", modulePath + "/cmd/soundpost-querycheck"}, forbiddenImportPrefixes...)
	seen := map[string]bool{}
	for _, line := range strings.Split(nmOutput, "\n") {
		for _, n := range needles {
			if strings.Contains(line, n) {
				fields := strings.Fields(line)
				name := line
				if len(fields) >= 3 {
					name = fields[2]
				}
				if !seen[name] {
					seen[name] = true
					bad = append(bad, name)
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// ProductionRoots lists every production package: each cmd/* binary except the
// querycheck tool, and every internal package outside the conformance harness.
func ProductionRoots(moduleRoot, modulePath string) ([]string, error) {
	var roots []string
	add := func(dir string) {
		rel, _ := filepath.Rel(moduleRoot, dir)
		roots = append(roots, modulePath+"/"+filepath.ToSlash(rel))
	}
	entries, err := os.ReadDir(filepath.Join(moduleRoot, "cmd"))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != "soundpost-querycheck" {
			add(filepath.Join(moduleRoot, "cmd", e.Name()))
		}
	}
	err = filepath.WalkDir(filepath.Join(moduleRoot, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if rel, _ := filepath.Rel(moduleRoot, path); filepath.ToSlash(rel) == "internal/conformance" {
			return filepath.SkipDir
		}
		if name := d.Name(); name == "testdata" {
			return filepath.SkipDir
		}
		matches, _ := filepath.Glob(filepath.Join(path, "*.go"))
		for _, m := range matches {
			if !strings.HasSuffix(m, "_test.go") {
				add(path)
				break
			}
		}
		return nil
	})
	sort.Strings(roots)
	return roots, err
}
