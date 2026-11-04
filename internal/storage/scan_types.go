// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"soundpost/internal/auth"
	"soundpost/internal/model"
)

// Kind is the leaf model kind; ingest.Kind aliases the same closed type.
type ReadFence struct {
	Min          []model.Cursor
	AllowPartial bool
}
type ScanRequest struct {
	Projects   []model.ID
	Signal     model.Kind
	Start, End model.UnixNano
	Selectors  []Matcher
	Projection []Field
	Fence      ReadFence
}
type MatchOp uint8

const (
	MatchEqual MatchOp = iota + 1
	MatchNotEqual
	MatchRegexp
	MatchNotRegexp
)

type LiteralKind uint8

const (
	LiteralString LiteralKind = iota + 1
	LiteralInteger
	LiteralBoolean
	LiteralNull
	LiteralUnsigned
	LiteralFloatBits
)

type Literal struct {
	Kind     LiteralKind
	String   string
	Integer  int64
	Boolean  bool
	Unsigned uint64
	Bits     model.FloatBits
}
type MatchTarget uint8

const (
	MatchLabel MatchTarget = iota + 1
	MatchField
)

type Matcher struct {
	Target  MatchTarget
	Name    string
	Op      MatchOp
	Literal Literal
}
type Field uint16

const (
	FieldID Field = iota + 1
	FieldTime
	FieldResource
	FieldMetric
	FieldLog
	FieldSpan
	FieldError
	FieldJob
	FieldReplay
	FieldProfile
	FieldCapability
	FieldLoss
	FieldCondition
	FieldOrigin
	FieldObservedTime
)

// Page columns have identical lengths. All data is borrowed until Next or Close.
// Payloads remain closed C04 native values, never JSON query blobs.
type Page struct {
	IDs           []model.ID
	Times         []model.UnixNano
	ObservedTimes []model.UnixNano
	Resources     []model.Resource
	Values        []model.Payload
	Origins       []model.Cursor
	Projects      []model.ID
	Sources       []model.ID
	Loss          []uint64
	Partial       bool
	Bytes         uint64
}

func (p Page) Len() int { return len(p.IDs) }

type RowIterator interface {
	Next(context.Context) (Page, error)
	Watermarks() []model.Cursor
	Close() error
}
type SubscribeRequest struct {
	Projects  []model.ID
	Signal    model.Kind
	Selectors []Matcher
	After     []model.Cursor
}
type ChangeGap struct {
	After   []model.Cursor
	Through []model.Cursor
	Reason  string
}
type ChangePage struct {
	Page    Page
	Cursors []model.Cursor
	Gap     *ChangeGap
	Revoked bool
}
type ChangeIterator interface {
	Next(context.Context) (ChangePage, error)
	Watermarks() []model.Cursor
	Close() error
}

// Compile-time public producer shape, consumed without storage/auth cycles.
var _ interface {
	Scan(context.Context, auth.Scope, ScanRequest) (RowIterator, error)
	Subscribe(context.Context, auth.Scope, SubscribeRequest) (ChangeIterator, error)
} = (*Engine)(nil)

const pageRows = 128
const pageByteLimit = 4 << 20
const liveCapacity = 64

// StorageStats contains actual IO/resource counters, not estimated dataset sizes.
type StorageStats struct{ IndexLookups, PagesRead, BytesRead, ActiveIterators, BorrowedPages, SegmentFiles, ManifestRevision uint64 }
