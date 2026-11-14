// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import "github.com/arynyklas/soundpost/internal/replica"

// DefaultJournalCadence is decision D4: the control Raft journal is cut onto a snapshot and
// compacted every 4096 commands or 64 MiB of journal, whether or not anything was deleted. The
// retry table beside it keeps an entry for replica.DefaultRetryWindow (24 h) or
// replica.DefaultRetryMax (100 000) entries, whichever bounds first; a retry older than that is
// proposed as a fresh command, which every control command's expected revision rejects.
var DefaultJournalCadence = replica.Cadence{Commands: 4096, Bytes: 64 << 20}
