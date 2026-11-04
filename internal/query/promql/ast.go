// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package promql

import "soundpost/internal/query/syntax"

type ValueType string

const (
	Scalar ValueType = "scalar"
	String ValueType = "string"
	Vector ValueType = "vector"
	Matrix ValueType = "matrix"
)

// Expr is sealed. Walk visits all children in source order; returning false prunes a subtree.
type Expr interface {
	SourceRange() syntax.SourceRange
	expression()
}
type Node struct {
	Range, OperatorRange                   syntax.SourceRange
	Kind                                   string
	Text                                   string
	FloatBits                              uint64
	Children                               []Expr
	Labels                                 []string
	Matchers                               []Matcher
	Matching                               *VectorMatching
	Bool                                   bool
	GroupWithout                           bool
	RangeText, Step, Offset, At, Extension string
	RangeExpr, StepExpr, OffsetExpr        Expr
	FillLeft, FillRight                    *uint64
}

func (*Node) expression()                       {}
func (n *Node) SourceRange() syntax.SourceRange { return n.Range }

type Matcher struct {
	Name, Op, Value string
	Range           syntax.SourceRange
}
type VectorMatching struct {
	On          bool
	Labels      []string
	Cardinality string
	Include     []string
	Range       syntax.SourceRange
}
type TypedExpr struct {
	Expr                                                 Expr
	Type                                                 ValueType
	FloatBits                                            uint64
	OverloadID, ProfileID, ProfileIdentity, FeatureSetID string
	Children                                             []TypedExpr
}

func Walk(e Expr, visit func(Expr) bool) {
	if e == nil || !visit(e) {
		return
	}
	n := e.(*Node)
	for _, c := range n.Children {
		Walk(c, visit)
	}
	Walk(n.RangeExpr, visit)
	Walk(n.StepExpr, visit)
	Walk(n.OffsetExpr, visit)
}
