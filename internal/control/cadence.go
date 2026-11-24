// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import "github.com/arynyklas/soundpost/internal/replica"

// DefaultJournalCadence is decision D4: the control Raft journal is cut onto a snapshot and
// compacted every 4096 commands or 8 MiB of applied entry data, whether or not anything was
// deleted. D4 fixed 64 MiB; that bound let a journal grow until reopening it ran past the fixed
// startup budget (measured, TestControlStartupMeasure: replaying the journal costs about 28 to
// 35 ms per MB of ready.wal without the race detector and 0.55 to 0.75 s per MB with it, so the
// 90 MB journal of a 64 MiB bound is about 3 s and, extrapolated, about a minute under -race).
// Every control command carries the whole next state, so a byte bound is what bounds the replay;
// the command bound alone is reached only after 4096 states. The journal file holds the entry data
// base64-encoded inside JSON records, so a journal at 8 MiB of entries is about 11.5 MB on disk and
// reopens in 0.35 to 0.41 s (6.3 to 8.2 s under the race detector). A state larger than the bound
// cuts on every command, which is the cost of a snapshot, not of a journal.
//
// The retry table beside it keeps an entry for replica.DefaultRetryWindow (24 h) or
// replica.DefaultRetryMax (100 000) entries, whichever bounds first; a retry older than that is
// proposed as a fresh command, which every control command's expected revision rejects.
//
// The cut writes the whole state, and the state grows with the admission reservations not yet settled
// (170 MB at 100,000 batches): the cadence amortizes, its bounds growing to half the size of the last
// snapshot (replica.Cadence.Amortize), so a large state is cut when it has journaled an eighth to a
// half of its size, not every 8 MiB (24 % of the server's CPU at the single-host load, L2w20Admission7).
var DefaultJournalCadence = replica.Cadence{Commands: 4096, Bytes: 8 << 20, Amortize: true}
