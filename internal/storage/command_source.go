// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"github.com/arynyklas/soundpost/internal/model"

	bolt "go.etcd.io/bbolt"
)

// A reader of the stored commands never waits for the disk inside a read transaction. A command of 256 bytes or more is stored in the
// payload log and the apply database holds its reference: a reader that follows the reference inside its transaction holds the
// transaction open for as long as the read takes, and bolt reuses no page that was freed after the oldest open read transaction began, so
// at the single-host gate (80 MB/s of pages written) every reader that waited for the disk made the file grow and the writes fresh pages
// (L2w20Admission36: apply.db 0.33 -> 2.66 GB in 20 s, G8 acknowledgements failing from the 40th minute). The readers that follow a
// reference are the settlement of the open window, the derivation of a window for a cut, the window files of a snapshot and the scans
// of the journal-expiry plan and of an erasure; each takes the stored values in short read transactions (the references, a few bytes each)
// and reads the log after the transaction ended.

// commandSource yields count stored commands of one slot from index first, in order. raw is valid during the call of fn only.
type commandSource func(first, count uint64, fn func(index uint64, raw []byte) error) error

// treeCommands reads the commands from a bucket of the caller's transaction, the payload log inside it: the readers that are the
// whole pass of the background verification, which holds one transaction for the length of the pass on purpose.
func treeCommands(commands *bolt.Bucket, slot uint16) commandSource {
	return func(first, count uint64, fn func(uint64, []byte) error) error {
		for i := range count {
			raw := commandAtCold(commands, commandKey(slot, first+i))
			if raw == nil {
				return model.Fail(model.Corrupt)
			}
			if err := fn(first+i, raw); err != nil {
				return err
			}
		}
		return nil
	}
}

// commandFetchCount and commandFetchBytes bound the commands one read transaction of fetchedCommands takes: references are a few bytes
// each, an inline command (below payloadMinBytes, or one an older release stored whole) is copied.
const (
	commandFetchCount = 256
	commandFetchBytes = 4 << 20
)

// fetchedCommands reads the commands in read transactions of at most commandFetchCount of them (and commandFetchBytes of inline
// values), and the records of the payload log after each transaction ended. The caller holds no read transaction. The commands below the
// index the slot applied change only by erasure, which takes cutMu exclusively: the callers hold it shared, so the transactions of a
// call see the same commands.
func (e *Engine) fetchedCommands(slot uint16) commandSource {
	return func(first, count uint64, fn func(uint64, []byte) error) error {
		type span struct{ off, end int }
		for done := uint64(0); done < count; {
			var buf []byte
			var spans []span
			err := e.db.View(func(tx *bolt.Tx) error {
				commands := tx.Bucket([]byte("replica_commands"))
				if commands == nil {
					return model.Fail(model.Corrupt)
				}
				for i := done; i < count && len(spans) < commandFetchCount && len(buf) < commandFetchBytes; i++ {
					v := commands.Get(commandKey(slot, first+i))
					if v == nil {
						return model.Fail(model.Corrupt)
					}
					spans = append(spans, span{len(buf), len(buf) + len(v)})
					buf = append(buf, v...)
				}
				return nil
			})
			if err != nil {
				return err
			}
			for j, s := range spans {
				raw := buf[s.off:s.end:s.end]
				if isPayloadRef(raw) {
					if raw = storedFromDBCold(e.db.DB, raw); raw == nil {
						return model.Fail(model.Corrupt)
					}
				}
				if err := fn(first+done+uint64(j), raw); err != nil {
					return err
				}
			}
			done += uint64(len(spans))
		}
		return nil
	}
}
