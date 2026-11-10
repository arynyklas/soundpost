// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func stringSet(values []string) map[string]bool {
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

// AuditGoSource statically audits one Go source of the acquisition path against
// the policy: forbidden identifiers/imports/strings, a closed raw-syscall surface
// (numbers, constants, ioctl requests, syscall-package symbols) and no printing
// of values. printOK admits reviewed print calls (nil admits none). Findings are
// "file:line: rule detail"; an empty result is a pass.
func AuditGoSource(p Policy, filename, src string, printOK func(*ast.CallExpr) bool) []string {
	fset := token.NewFileSet()
	file, e := parser.ParseFile(fset, filename, src, 0)
	if e != nil {
		return []string{"parse: " + e.Error()}
	}
	var out []string
	add := func(pos token.Pos, rule, detail string) {
		out = append(out, fmt.Sprintf("%s:%d: %s %s", filepath.Base(filename), fset.Position(pos).Line, rule, detail))
	}
	sp := p.Syscalls
	forbiddenID, allowedConst := stringSet(sp.SourceForbiddenID), stringSet(sp.SourceConstants)
	allowedNumber, allowedIoctl := map[int64]bool{}, map[int64]bool{}
	for _, n := range sp.SourceNumbers.Numbers {
		allowedNumber[int64(n)] = true
	}
	for _, n := range sp.SourceIoctl {
		allowedIoctl[int64(n)] = true
	}
	symbol := regexp.MustCompile(sp.SourceSymbolRegex)
	var text []*regexp.Regexp
	for _, expr := range sp.SourceForbiddenText {
		text = append(text, regexp.MustCompile(expr))
	}
	forbiddenImport := stringSet(sp.SourceForbiddenImp)
	for _, imp := range file.Imports {
		if path, _ := strconv.Unquote(imp.Path.Value); forbiddenImport[path] || strings.HasPrefix(path, "soundpost/fixtures") {
			add(imp.Pos(), "forbidden_import", path)
		}
	}
	rawCalls := map[string]bool{"Syscall": true, "Syscall6": true, "RawSyscall": true, "RawSyscall6": true}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.Ident:
			if forbiddenID[x.Name] {
				add(x.Pos(), "forbidden_identifier", x.Name)
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				s, _ := strconv.Unquote(x.Value)
				for _, re := range text {
					if re.MatchString(s) {
						add(x.Pos(), "forbidden_string", re.String())
					}
				}
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "syscall" && !symbol.MatchString(x.Sel.Name) {
				add(x.Pos(), "syscall_symbol_not_allowlisted", x.Sel.Name)
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				pkg, _ := sel.X.(*ast.Ident)
				if pkg != nil && pkg.Name == "syscall" && rawCalls[sel.Sel.Name] && len(x.Args) > 0 {
					switch first := x.Args[0].(type) {
					case *ast.SelectorExpr:
						if !allowedConst[first.Sel.Name] {
							add(x.Pos(), "raw_syscall_constant", first.Sel.Name)
						}
						if first.Sel.Name == "SYS_IOCTL" {
							request := int64(-1)
							if len(x.Args) > 2 {
								if lit, ok := x.Args[2].(*ast.BasicLit); ok {
									if v, err := strconv.ParseInt(lit.Value, 0, 64); err == nil {
										request = v
									}
								}
							}
							if !allowedIoctl[request] {
								add(x.Pos(), "ioctl_request_not_allowlisted", strconv.FormatInt(request, 10))
							}
						}
					case *ast.BasicLit:
						if v, err := strconv.ParseInt(first.Value, 0, 64); err != nil || !allowedNumber[v] {
							add(x.Pos(), "raw_numeric_syscall", first.Value)
						}
					default:
						add(x.Pos(), "non_constant_syscall_number", "")
					}
				}
				prints := pkg != nil && (pkg.Name == "log" || pkg.Name == "fmt" && (strings.HasPrefix(sel.Sel.Name, "Print") || strings.HasPrefix(sel.Sel.Name, "Fprint")))
				if prints && (printOK == nil || !printOK(x)) {
					add(x.Pos(), "prints_values", pkg.Name+"."+sel.Sel.Name)
				}
			}
			if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "print" || id.Name == "println") {
				add(x.Pos(), "prints_values", id.Name)
			}
		}
		return true
	})
	return out
}

// HelperMainPrintOK admits only the helper main's single reviewed line, which
// prints a closed error value to stderr.
func HelperMainPrintOK(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Fprintln" || len(call.Args) != 3 {
		return false
	}
	dest, ok := call.Args[0].(*ast.SelectorExpr)
	prefix, ok2 := call.Args[1].(*ast.BasicLit)
	value, ok3 := call.Args[2].(*ast.Ident)
	return ok && dest.Sel.Name == "Stderr" && ok2 && prefix.Value == `"native helper:"` && ok3 && value.Name == "e"
}
