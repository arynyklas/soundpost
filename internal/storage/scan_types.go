// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
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
	// After is the resume position of a consumer that applies rows idempotently by
	// origin: a row whose origin index in its group is at or below the entry of that
	// group is skipped before its page is read or decoded. A group with no entry is
	// read whole. It is a read optimization, never a visibility rule: rows the
	// caller still needs are the ones above its own checkpoint.
	After []model.Cursor
	// MaxPageRows lets a scan that reads on until the end release larger pages: the first page holds up to
	// 128 rows and each next page pageRowsGrowth times more, up to MaxPageRows (at most MaxScanPageRows).
	// Every page costs one quorum barrier, one index seek and one transaction, so a reader of a day of
	// rows paid them every 128 rows; a larger page is the same barrier before the same rows are released.
	// Zero keeps pages of 128 rows.
	MaxPageRows int
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
	// CatchUp makes the subscription answer an overrun of its queue by reading the commits it dropped from
	// durable storage and handing them over in order, instead of announcing them as a slow_consumer gap:
	// no committed row is lost and none is repeated. A window opened by After or by a group change is still
	// announced as a gap.
	CatchUp bool
	// CatchUpLag bounds how far behind a catch-up subscription may fall (D99): the number of commits, per
	// replica group, between what the consumer has been handed and the newest commit. While the window is
	// within it the dropped commits are read back and handed over exactly once, in order. Beyond it the part
	// that is older than the bound is announced as one exact slow_consumer gap (After is the consumer's
	// position, Through the last commit skipped) and the stream resumes at the newest CatchUpLag commits.
	// Zero means DefaultCatchUpLag. It has no effect without CatchUp.
	CatchUpLag uint64
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

// MaxScanPageRows is the most a ScanRequest.MaxPageRows may ask for: eight chunks of pageRows, and with the
// distinct pages of a chunk held to pageByteLimit, the memory of one released page stays what a 128-row
// page of the same data costs a few times over, not a day of rows.
const MaxScanPageRows = 1024

// pageRowsGrowth is how many times more rows each page of a scan with MaxPageRows holds than the one before.
const pageRowsGrowth = 4
const pageByteLimit = 4 << 20
const liveCapacity = 64

// StorageStats contains actual IO/resource counters, not estimated dataset sizes.
type StorageStats struct{ IndexLookups, PagesRead, BytesRead, ActiveIterators, BorrowedPages, SegmentFiles, ManifestRevision uint64 }
