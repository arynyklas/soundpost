// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/syntax"
)

// Expr is an owned syntax tree; metric execution is supplied by task 02.07.
type Expr interface {
	Span() syntax.SourceRange
	logExpr()
}
type Node struct{ Range syntax.SourceRange }

func (n Node) Span() syntax.SourceRange { return n.Range }
func (Node) logExpr()                   {}

type LiteralExpr struct {
	Node
	Value float64
}
type StringExpr struct {
	Node
	Value string
}
type LogExpr struct {
	Node
	Matchers []Matcher
	Stages   []Stage
}
type RangeExpr struct {
	Node
	Log              *LogExpr
	Interval, Offset int64
}
type UnaryExpr struct {
	Node
	Op   string
	Expr Expr
}
type BinaryExpr struct {
	Node
	Op          string
	Left, Right Expr
	Matching    VectorMatching
	Bool        bool
}
type CallExpr struct {
	Node
	Name     string
	Args     []Expr
	Grouping []string
	Without  bool
}
type VariantsExpr struct {
	Node
	Variants []Expr
	Range    *RangeExpr
}
type VectorMatching struct {
	On          bool
	Labels      []string
	Cardinality string
	Include     []string
}
type Matcher struct{ Name, Op, Value string }
type LineFilter struct {
	Op, Value string
	IP        bool
}
type Extraction struct{ Name, Path string }
type Assignment struct {
	Name, Value string
	Rename      bool
}
type LabelPredicate struct {
	Op, Name, Text, Type string
	Number               float64
	Left, Right          *LabelPredicate
}
type Stage struct {
	Node
	// Head is the first token of the stage a grammar must accept: the line-filter
	// operator, or the token after the leading pipe.
	Head                    syntax.SourceRange
	Kind                    string
	Lines                   []LineFilter
	Extractions             []Extraction
	Pattern                 string
	Strict, KeepEmpty       bool
	Filter                  *LabelPredicate
	Assignments             []Assignment
	Labels                  []Matcher
	UnwrapLabel, Conversion string
}
type Type string

const (
	TypeLogs   Type = "streams"
	TypeRange  Type = "range"
	TypeVector Type = "vector"
	TypeScalar Type = "scalar"
	TypeString Type = "string"
)

type TypedExpr struct {
	Expr Expr
	Type Type
}
type TypedField struct {
	Name  string
	Value model.Scalar
}

// LogEntry starts from the immutable admitted line. Mutations affect only this
// query-owned entry, never a stored template, source page or another query.
type LogEntry struct {
	Timestamp          model.UnixNano
	ID                 model.ID
	Source             model.ID
	Multiplicity       model.Uint64
	Line               string
	StreamLabels       model.Labels
	StructuredMetadata model.Labels
	ParsedLabels       model.Labels
	Fields             []TypedField
	// Reserved language state is projected to result/template maps, not ordinary
	// label lookup. String error predicates have their own __error__ accessor.
	languageError, languageErrorDetails string
	baseStream                          model.Labels // transient immutable namespace during this pipeline
}

// Bytes is the retained account charge. Consumers release it after consuming or
// transferring the returned entry; filtered/error results retain no charge.
type PipelineResult struct {
	Entry                                            LogEntry
	Labels                                           model.Labels
	OriginalStreamLabels, OriginalStructuredMetadata model.Labels
	Retained                                         bool
	Unwrapped                                        *float64
	Bytes                                            int64
}
