// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package replays validates the owned masked replay chunk format, keeps the
// immutable per-replay checkpoint index and group retention state, and
// reconstructs a replay for an authorized reader without ever fabricating
// continuity. It does not certify the SDK pre-buffer masking; it is
// defense-in-depth (docs/protocol/replay-v1.md).
package replays

import (
	"context"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/storage"
)

const (
	// MaxChunkBytes is the closed-format ceiling of one canonical chunk.
	MaxChunkBytes = 128 << 10
	// MaxSequence bounds the chunk count of one replay: the read plan holds one
	// small record per sequence and never a chunk body.
	MaxSequence = 1 << 16
	// MaxCheckpoints bounds the immutable checkpoint index of one replay.
	MaxCheckpoints = 1024
	// ReadBatch is how many chunk bodies a stream buffers at once.
	ReadBatch = 8

	maxNodeID     = 1 << 31
	maxCoordinate = 1 << 24
)

// Recorder versions this server can reconstruct.
var supportedRecorders = map[string]bool{"1": true}

// Closed vocabularies of the masked protocol.
var (
	nodeTags   = map[string]bool{"div": true, "span": true, "p": true, "button": true, "input": true, "section": true, "canvas": true, "masked": true}
	eventKinds = map[string]bool{"pointer": true, "scroll": true, "resize": true, "mutation": true, "checkpoint": true, "gap": true}
)

// ReplayWindow selects inclusive chunk sequences. Zero From starts at the first
// chunk; zero To runs to the last known chunk. A window that begins at a delta
// is preceded by the checkpoint it depends on.
type ReplayWindow struct{ From, To uint64 }

// EventKind is the closed set of stream events.
type EventKind string

const (
	EventCheckpoint  EventKind = "checkpoint"
	EventDelta       EventKind = "delta"
	EventGap         EventKind = "gap"
	EventUnsupported EventKind = "unsupported"
	EventRevoke      EventKind = "revoke"
	EventError       EventKind = "error"
)

// Closed reason codes. None carries page content or caller input.
const (
	ReasonMissingChunk       = "missing_chunk"
	ReasonHashMismatch       = "hash_mismatch"
	ReasonDependencyMismatch = "dependency_mismatch"
	ReasonRecorderGap        = "recorder_gap"
	ReasonConflictingChunk   = "conflicting_chunk"
	ReasonInvalidChunk       = "invalid_chunk"
	ReasonIndexMismatch      = "index_mismatch"
	ReasonNoCheckpoint       = "no_checkpoint"
	ReasonRecorderVersion    = "recorder_version"
	ReasonAuthorityRevoked   = "authority_revoked"
	ReasonDeleted            = "deleted"
)

// Event is one released stream item. Chunk is set only for checkpoint and delta.
// A Gap spans Sequence..Through inclusive; a Revoke or Error ends the stream.
type Event struct {
	Kind               EventKind
	Sequence, Through  uint64
	Hash, Previous     model.Hash
	CheckpointSequence uint64
	Checkpoint         model.Hash
	Policy             model.Revision
	Clock              model.TraceClock
	Loss               uint64
	Reason             string
	Code               model.Code
	Chunk              *model.ReplayChunk
}

// ReplayStream releases events in sequence order. Next returns io.EOF after the
// last event; after a Revoke or Error event every later Next returns io.EOF.
type ReplayStream interface {
	Next(context.Context) (Event, error)
	Close() error
}

// ReplayScanner is the record reader (*storage.Engine).
type ReplayScanner interface {
	Scan(context.Context, auth.Scope, storage.ScanRequest) (storage.RowIterator, error)
}

// ScopeAuthorizer re-checks a scope against current grants (*auth.Service).
type ScopeAuthorizer interface {
	Revalidate(context.Context, auth.Scope) error
}

// ReferenceStore is the replicated control state holding the immutable
// checkpoint indexes, retention groups and delete generations (*control.Store).
type ReferenceStore interface {
	View(context.Context, func(model.ControlState) error) error
	Update(context.Context, func(*model.ControlState) error) error
}
