// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	u15 "soundpost/third_party/regex/go124/unicode"
	"strings"
	"text/template/parse"
)

// Host text/template supplies syntax trees only. Its lexer must not broaden the
// pinned Go1.24 Unicode15 identifier language when the host adopts newer tables.
// Text/string payloads remain unrestricted; this validates identifiers, not data.
func templateIdentifier(name string) bool {
	name = strings.TrimPrefix(name, "$")
	for _, r := range name {
		if r != '_' && !u15.IsLetter(r) && !u15.IsDigit(r) {
			return false
		}
	}
	return true
}
func templateValidate(node parse.Node, remaining *int, depth int) error {
	if node == nil {
		return nil
	}
	if depth > templateMaxDepth {
		return &TemplateLimitError{Resource: "depth"}
	}
	*remaining--
	if *remaining < 0 {
		return &TemplateLimitError{Resource: "source nodes"}
	}
	child := func(n parse.Node) error { return templateValidate(n, remaining, depth+1) }
	fields := func(names []string) error {
		for _, name := range names {
			if !templateIdentifier(name) {
				return &TemplateError{Phase: "parse"}
			}
		}
		return nil
	}
	branch := func(b *parse.BranchNode) error {
		if e := child(b.Pipe); e != nil {
			return e
		}
		if e := child(b.List); e != nil {
			return e
		}
		if b.ElseList != nil {
			return child(b.ElseList)
		}
		return nil
	}
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return nil
		}
		for _, v := range n.Nodes {
			if e := child(v); e != nil {
				return e
			}
		}
	case *parse.ActionNode:
		return child(n.Pipe)
	case *parse.PipeNode:
		if n == nil {
			return nil
		}
		for _, d := range n.Decl {
			if e := fields(d.Ident); e != nil {
				return e
			}
		}
		for _, v := range n.Cmds {
			if e := child(v); e != nil {
				return e
			}
		}
	case *parse.CommandNode:
		for _, v := range n.Args {
			if e := child(v); e != nil {
				return e
			}
		}
	case *parse.ChainNode:
		if e := fields(n.Field); e != nil {
			return e
		}
		return child(n.Node)
	case *parse.FieldNode:
		return fields(n.Ident)
	case *parse.VariableNode:
		return fields(n.Ident)
	case *parse.IdentifierNode:
		if !templateIdentifier(n.Ident) {
			return &TemplateError{Phase: "parse"}
		}
	case *parse.IfNode:
		return branch(&n.BranchNode)
	case *parse.WithNode:
		return branch(&n.BranchNode)
	case *parse.RangeNode:
		return branch(&n.BranchNode)
	case *parse.TemplateNode:
		if n.Pipe != nil {
			return child(n.Pipe)
		}
	case *parse.TextNode, *parse.DotNode, *parse.NilNode, *parse.StringNode, *parse.NumberNode, *parse.BoolNode, *parse.BreakNode, *parse.ContinueNode:
	default:
		return &TemplateError{Phase: "parse"}
	}
	return nil
}
