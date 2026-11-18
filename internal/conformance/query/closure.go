// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
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

// forbiddenExecutables are, by base name, the programs a production path may not
// execute: an OCI runtime or an upstream engine.
var forbiddenExecutables = []string{"docker", "podman", "prometheus", "loki"}

type ClosureReport struct {
	Packages  []string `json:"packages"`
	Files     int      `json:"files"`
	Violation []string `json:"violations"`
}

// closureTarget is one build configuration the production scan evaluates.
type closureTarget struct {
	goos, goarch string
	cgo          bool
}

// closureTargets are the build configurations a production binary can be built
// for. A file selected by any of them is production code, so every one is
// scanned: a file only built for another platform or architecture, or only with
// cgo enabled, must not escape the scan.
var closureTargets = []closureTarget{
	{"linux", "amd64", false},
	{"linux", "amd64", true},
	{"linux", "arm64", false},
	{"windows", "amd64", false},
	{"darwin", "arm64", false},
	{"freebsd", "amd64", false},
}

// ProductionClosure proves, from source, that no production path can start or
// contact an oracle: starting from root packages it follows module-internal
// imports of non-test files (build constraints evaluated for every target of
// closureTargets), rejects any import of the conformance harness, an upstream
// engine or the querycheck command, and scans every reached file for oracle entry
// points, oracle image names and exec of an OCI runtime (exec.Command however
// os/exec is imported, os.StartProcess, syscall.Exec and syscall.ForkExec). A
// program named through a non-literal argument is not resolved. A finite source
// check complements, and does not replace, the binary symbol check.
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
		for _, t := range closureTargets {
			ctx := build.Default
			ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = t.goos, t.goarch, t.cgo
			p, err := ctx.ImportDir(dir, 0)
			if err != nil {
				var none *build.NoGoError
				if errors.As(err, &none) {
					continue
				}
				return report, fmt.Errorf("%s: %w", pkg, err)
			}
			imports = append(imports, p.Imports...)
			files = append(files, p.GoFiles...)
			files = append(files, p.CgoFiles...)
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

// importNames returns the names under which f refers to the package importPath
// (the declared alias, or the package's own name for a plain import) and whether
// it dot-imports it.
func importNames(f *ast.File, importPath string) (names []string, dot bool) {
	for _, imp := range f.Imports {
		if p, err := strconv.Unquote(imp.Path.Value); err != nil || p != importPath {
			continue
		}
		switch {
		case imp.Name == nil:
			names = append(names, path.Base(importPath))
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			names = append(names, imp.Name.Name)
		}
	}
	return names, dot
}

// forbiddenExecutable reports the program a string literal argument names when it
// is one of forbiddenExecutables, by base name.
func forbiddenExecutable(arg ast.Expr) (string, bool) {
	lit, ok := arg.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	text, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	base := strings.ToLower(filepath.Base(text))
	for _, bad := range forbiddenExecutables {
		if strings.Contains(base, bad) {
			return base, true
		}
	}
	return "", false
}

func scanProductionFile(file string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	// The packages whose calls start a process, under every name the file gives
	// them. The package's own name always counts, even without an import.
	execNames, dotExec := importNames(f, "os/exec")
	execNames = append(execNames, "exec")
	osNames, _ := importNames(f, "os")
	osNames = append(osNames, "os")
	syscallNames, _ := importNames(f, "syscall")
	syscallNames = append(syscallNames, "syscall")
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
			var qualifier, fn string
			switch fun := v.Fun.(type) {
			case *ast.SelectorExpr:
				if x, ok := fun.X.(*ast.Ident); ok {
					qualifier, fn = x.Name, fun.Sel.Name
				}
			case *ast.Ident:
				if dotExec {
					qualifier, fn = "exec", fun.Name // os/exec dot-imported: Command(...)
				}
			}
			var args []ast.Expr
			switch {
			case slices.Contains(execNames, qualifier) && (fn == "Command" || fn == "CommandContext"):
				args = v.Args // any argument may name the program (a wrapper's argument too)
			case slices.Contains(osNames, qualifier) && fn == "StartProcess", slices.Contains(syscallNames, qualifier) && (fn == "Exec" || fn == "ForkExec"):
				if len(v.Args) > 0 {
					args = v.Args[:1] // the program path
				}
			}
			for _, a := range args {
				if base, bad := forbiddenExecutable(a); bad {
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
