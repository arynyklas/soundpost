// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package staleretry counts the commands the background workers had to submit again because the
// control revision moved under them (a lost race for the revision, not a semantic conflict). The
// four writers that retry on it (rule commits, the delivery outbox, conditions, incidents) call Note
// at the retry; the worker pass reports the difference of two Snapshots. A process-wide counter is
// enough: it is read as a rate, never as an identity.
package staleretry

import "sync/atomic"

// Kind names a writer that retries a command after losing a race for the control revision.
type Kind int

const (
	Rules Kind = iota
	Outbox
	Conditions
	Incidents
	kinds
)

var counts [kinds]atomic.Uint64

// Note records one retry of kind.
func Note(k Kind) { counts[k].Add(1) }

// Counts are the retries since the process started, by writer.
type Counts struct {
	Rules, Outbox, Conditions, Incidents uint64
}

// Snapshot reads the counters.
func Snapshot() Counts {
	return Counts{Rules: counts[Rules].Load(), Outbox: counts[Outbox].Load(), Conditions: counts[Conditions].Load(), Incidents: counts[Incidents].Load()}
}

// Total is the retries of every writer.
func (c Counts) Total() uint64 { return c.Rules + c.Outbox + c.Conditions + c.Incidents }

// Since is the retries made after before was taken.
func (c Counts) Since(before Counts) Counts {
	return Counts{Rules: c.Rules - before.Rules, Outbox: c.Outbox - before.Outbox, Conditions: c.Conditions - before.Conditions, Incidents: c.Incidents - before.Incidents}
}
