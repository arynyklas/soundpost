// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type SourceFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type SourceSymbol struct {
	Path         string `json:"path"`
	Line         int    `json:"line"`
	Kind         string `json:"kind"`
	Name         string `json:"name"`
	SourceSHA256 string `json:"source_sha256"`
}
type SourceAudit struct {
	Files               []SourceFile   `json:"files"`
	Symbols             []SourceSymbol `json:"symbols"`
	UnresolvedFlagCalls []SourceSymbol `json:"unresolved_flag_calls"`
}

var productionSymbol = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z_0-9]*)[ \t]*:`)

// AuditSource emits only declaration names and location/content hashes. It does
// not emit or translate upstream grammar productions, evaluators or test bodies.
// Static discovery is not semantic acceptance; dynamic calls remain explicit.
func AuditSource(ctx context.Context, p SourceProfile, input io.Reader) (SourceAudit, error) {
	var result SourceAudit
	hash := sha256.New()
	compressed := io.TeeReader(input, hash)
	z, e := gzip.NewReader(compressed)
	if e != nil {
		return result, e
	}
	defer z.Close()
	archive := tar.NewReader(z)
	for {
		if e = ctx.Err(); e != nil {
			return result, e
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, err
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		_, file, found := strings.Cut(header.Name, "/")
		if !found || strings.HasPrefix(file, "vendor/") || strings.Contains(file, "/testdata/") || strings.HasSuffix(file, "_test.go") {
			continue
		}
		if !(strings.HasSuffix(file, ".go") || strings.HasSuffix(file, ".y")) || strings.HasSuffix(file, ".y.go") {
			continue
		}
		if header.Size < 0 || header.Size > 32<<20 {
			return result, fmt.Errorf("source file exceeds audit bound: %s", file)
		}
		raw, err := io.ReadAll(archive)
		if err != nil {
			return result, err
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		result.Files = append(result.Files, SourceFile{file, digest})
		add := func(kind, name string, line int) {
			result.Symbols = append(result.Symbols, SourceSymbol{file, line, kind, name, digest})
		}
		if strings.HasSuffix(file, ".y") {
			for _, m := range productionSymbol.FindAllSubmatchIndex(raw, -1) {
				name := string(raw[m[2]:m[3]])
				line := 1 + strings.Count(string(raw[:m[0]]), "\n")
				add("production-symbol", name, line)
			}
			continue
		}
		positions := token.NewFileSet()
		parsed, err := parser.ParseFile(positions, file, raw, parser.SkipObjectResolution)
		if err != nil {
			return result, fmt.Errorf("source syntax audit %s: %w", file, err)
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.FuncDecl:
				add("function-symbol", n.Name.Name, positions.Position(n.Pos()).Line)
			case *ast.TypeSpec:
				add("type-symbol", n.Name.Name, positions.Position(n.Pos()).Line)
			case *ast.ValueSpec:
				for _, name := range n.Names {
					add("value-symbol", name.Name, positions.Position(name.Pos()).Line)
				}
			case *ast.CallExpr:
				selector, ok := n.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				method := selector.Sel.Name
				if !(method == "Flag" || strings.HasSuffix(method, "Var") || method == "String" || method == "Bool" || method == "Int" || method == "Duration") {
					return true
				}
				line := positions.Position(n.Pos()).Line
				index := 0
				if strings.HasSuffix(method, "Var") {
					index = 1
				}
				if len(n.Args) <= index {
					return true
				}
				literal, ok := n.Args[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					result.UnresolvedFlagCalls = append(result.UnresolvedFlagCalls, SourceSymbol{file, line, "possible-dynamic-flag", method, digest})
					return true
				}
				name, err := strconv.Unquote(literal.Value)
				if err == nil {
					add("possible-flag-symbol", name, line)
				}
			}
			return true
		})
	}
	// Consume the compressed trailer and any trailing bytes before checking the
	// actual archive digest. A partial tar traversal cannot attest a source lock.
	if _, e = io.Copy(io.Discard, z); e != nil {
		return result, e
	}
	if _, e = io.Copy(io.Discard, compressed); e != nil {
		return result, e
	}
	if hex.EncodeToString(hash.Sum(nil)) != p.SourceSHA256 {
		return result, fmt.Errorf("source archive digest mismatch for %s", p.ID)
	}
	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	sort.Slice(result.Symbols, func(i, j int) bool {
		a, b := result.Symbols[i], result.Symbols[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Name < b.Name
	})
	return result, nil
}
