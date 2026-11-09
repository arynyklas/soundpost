// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package retention owns C11 deletion (Delete/PollDelete), the C12 barrier saga
// driver, legal holds, retention policy resolution, reference-aware expiry,
// evidence-gap gating, disk-pressure sampling and the snapshot/journal
// maintenance worker. It supplies the real auth.DeleteGenerations.
package retention

import (
	"context"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"soundpost/internal/replica"
	"soundpost/internal/storage"
	"time"
)

// DeleteRequest is the C11 request. CommandID is the idempotency key and the
// operation ID; ExpectedRevision is the control revision the caller read.
type DeleteRequest struct {
	CommandID        model.ID       `json:"command_id"`
	ExpectedRevision model.Revision `json:"expected_revision"`
	Mode             string         `json:"mode"`
	OrgID            model.ID       `json:"org_id"`
	ProjectIDs       []model.ID     `json:"project_ids,omitempty"`
	Signals          []model.Kind   `json:"signals,omitempty"`
	Start            model.UnixNano `json:"start_ns,omitempty"`
	End              model.UnixNano `json:"end_ns,omitempty"`
	EntityIDs        []model.ID     `json:"entity_ids,omitempty"`
	Reason           string         `json:"reason"`
}

// Physical cleanup states of a receipt.
const (
	PhysicalPending = "pending" // logical deletion not complete or erasure not yet run
	PhysicalHeld    = "held"    // a legal hold makes physical-erasure success impossible
	PhysicalDone    = "done"
)

// DeleteReceipt is what Delete and PollDelete return. Phase fencing means reads
// are denied but the all-group fence is not complete: it is not success.
//
// Physical "done" means every erasure step this installation can perform has run: records,
// artifact roots, derived rows, segment files, the free pages of apply.db, the replication
// layer's retry table, journal and pin archives (redacted), and the snapshots and journal
// rebuilt from them. Residual names the local stores the engine MEASURES as still able to hold a
// copy of the deleted bytes (a snapshot or journal head cut before the erasure that has not yet
// been replaced, or a redaction still owed); after a completed cleanup it is empty and omitted
// (see docs/privacy/retention.md for what it does not cover). It is reported only once Physical
// is "done"; before that the bytes are simply still present everywhere.
type DeleteReceipt struct {
	OperationID      model.ID       `json:"operation_id"`
	Mode             string         `json:"mode"`
	Phase            string         `json:"phase"`
	Generation       uint64         `json:"generation"`
	Revision         model.Revision `json:"revision"`
	Progress         string         `json:"progress"` // "<recorded>/64" data-slot barriers
	Physical         string         `json:"physical"`
	PhysicalDeadline model.UnixNano `json:"physical_deadline_ns"`
	BackupDeadline   model.UnixNano `json:"backup_deadline_ns"`
	Holds            []model.ID     `json:"holds,omitempty"`
	SafeReason       string         `json:"safe_reason,omitempty"`
	Residual         []string       `json:"residual_stores,omitempty"`
}

// LedgerGeneration is what an independent restore authority durably stores
// after every completed deletion (C12): the digest ledger plus the exact
// tombstones (predicates carry no telemetry values), so a disaster restore can
// re-apply suppression with no other state.
type LedgerGeneration struct {
	Generation uint64                  `json:"generation"`
	Ledger     replica.Ledger          `json:"ledger"`
	Tombstones []model.DeletePredicate `json:"tombstones"`
}

// AuthorityReceipt proves the generation was durably checkpointed and verified.
type AuthorityReceipt struct {
	Generation uint64         `json:"generation"`
	Head       model.Hash     `json:"head"`
	At         model.UnixNano `json:"at_ns"`
}

// Authority is the injected independent restore-authority journal (task 01.09
// implements it in internal/backup). It is REQUIRED whenever off-host backup is
// enabled; a failing authority leaves deletion fencing, never complete.
//
// CheckpointDeletion must durably store (and read back and verify) the whole
// LedgerGeneration, retain every immutable generation, and advance a monotonic
// HEAD; it returns only after that. CurrentDeletionLedger returns the digest
// ledger of the newest verified generation; implementations should also
// implement TombstoneSource so a restore can obtain the exact tombstones.
type Authority interface {
	CheckpointDeletion(ctx context.Context, generation LedgerGeneration) (AuthorityReceipt, error)
	CurrentDeletionLedger(ctx context.Context) (replica.Ledger, error)
}

// TombstoneSource is the optional second read of an Authority: the tombstones of
// its newest verified generation, whose digests must equal the ledger entries.
type TombstoneSource interface {
	CurrentDeletionTombstones(ctx context.Context) ([]model.DeletePredicate, error)
}

// DataPlane is what the retention worker needs from the data groups. The real
// implementation is *storage.Engine.
type DataPlane interface {
	RecordDeleteBarrier(ctx context.Context, slot uint16, p model.DeletePredicate) (model.Cursor, error)
	EraseDeleted(ctx context.Context, preds []model.DeletePredicate, guard storage.EraseGuard) (storage.EraseReport, error)
	EraseExpired(ctx context.Context, now model.UnixNano, guard storage.EraseGuard) (storage.EraseReport, error)
	ApplyDeletionLedger(ctx context.Context, ledger replica.Ledger, tombstones []model.DeletePredicate) error
	CreateSnapshots(ctx context.Context) (storage.EngineSnapshot, error)
	DropSupersededSnapshots(ctx context.Context) (uint64, error)
	CheckpointErasure(ctx context.Context, p model.DeletePredicate) error
	CompactJournals(ctx context.Context) error
	ResidualStores() []string
}

// Pressure is the optional disk-pressure sampler (the engine implements it).
type Pressure interface {
	ObservePressure(ctx context.Context) (storage.PressureStatus, error)
}

// Processed reports, per data group, the highest application index whose
// lifecycle evidence a projection has fully processed (the checkpoint written in
// the transaction that applied its effects). Unknown groups are unprocessed.
type Processed interface {
	Processed(ctx context.Context, group model.ID) (uint64, error)
}

// References answers the reference-aware expiry questions: the latest
// RetainUntil of any still retained record that depends on the candidate (a
// replay chunk that names it as its checkpoint; an error or profile record of
// the same build for a source-map/symbol artifact). Zero means unreferenced.
type References interface {
	LatestReference(ctx context.Context, c storage.EraseCandidate) (model.UnixNano, error)
}

// Config wires a Service. Clock is the single time source.
type Config struct {
	Control    *control.Store
	Data       DataPlane
	Base       auth.DeleteGenerations // source-lifecycle generations (revoked/retired sources)
	Authority  Authority              // nil: off-host backup disabled (deletion needs no checkpoint)
	Pressure   Pressure
	Processed  Processed
	References References
	Clock      func() time.Time
	Worker     WorkerConfig
}

// WorkerConfig holds the conservative maintenance defaults.
type WorkerConfig struct {
	Interval         time.Duration // pass cadence (default 1 minute)
	SnapshotInterval time.Duration // CreateSnapshots+CompactJournals cadence (default 1 hour)
	ExpiryInterval   time.Duration // expiry pass cadence (default 1 hour)
	PhysicalWithin   time.Duration // deletion physical cleanup target (default 24 hours)
	BackupWithin     time.Duration // backup expiry (default 30 days)
}

// SnapshotGenerations are the monotonic ledger generations exposed for
// RequireGeneration at restore.
func (w WorkerConfig) withDefaults() WorkerConfig {
	if w.Interval <= 0 {
		w.Interval = time.Minute
	}
	if w.SnapshotInterval <= 0 {
		w.SnapshotInterval = time.Hour
	}
	if w.ExpiryInterval <= 0 {
		w.ExpiryInterval = time.Hour
	}
	if w.PhysicalWithin <= 0 {
		w.PhysicalWithin = 24 * time.Hour
	}
	if w.BackupWithin <= 0 {
		w.BackupWithin = 30 * 24 * time.Hour
	}
	return w
}
