// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// The journal-expiry plan lists the error evidence that expires soon. It used to read every stored command each time it was made (every
// 15 minutes): the whole payload log, 17,000 records a second for minutes at the single-host gate, and left 70 % of the log in the page
// cache of the scope, where it pushed out apply.db (L2w20Admission36: 174,773 reads in a 12 s perf window at 1,300 s, all from this scan).
// A stored command never changes but by an erasure (which bumps Engine.cutEpoch before and after it rewrites commands), and a command
// is appended above the last one of its slot: the evidence found in a command is kept, and a plan reads only the commands appended since
// the previous one, cold (the log's pages are not the page cache's to keep).

// expiryCacheMax bounds the error records kept; past it the next plan reads every command again, as the plan always did.
const expiryCacheMax = 1 << 21

type expiryRecord struct {
	org, project model.ID
	cursor       model.Cursor
	at           model.UnixNano
	retain       []model.UnixNano // the RetainUntil of the record's error deadlines, in the receipt's order
}

type expiryScan struct {
	mu      sync.Mutex
	valid   bool
	epoch   uint64
	through [64]uint64 // the index of the last command of each slot that was read
	recs    []expiryRecord
	scanned uint64 // the commands read over the life of the engine (tests: a command is read once)
}

func (s *expiryScan) reset(epoch uint64) {
	s.valid, s.epoch, s.through, s.recs = true, epoch, [64]uint64{}, nil
}

// expiryRefresh is how often the background loop reads the commands appended since the last read (keepUp).
var expiryRefresh = time.Minute

// keepUp reads the new commands every expiryRefresh, until ctx ends: a plan is made every 15 minutes, and the commands it would read
// then are 15 minutes old, past the keep window of the payload log (payloadKeep) and read from the disk, one random read each (two
// million of them, at the single-host gate, in the 15th minute). Read a minute after their append they come from the page cache.
func (s *expiryScan) keepUp(ctx context.Context, e *Engine) {
	t := time.NewTicker(expiryRefresh)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.mu.Lock()
		// Only a cache that stands is extended: one an erasure invalidated, or one that is too big to keep, is rebuilt by the plan (a
		// rebuild reads every command, which a minute loop would repeat for every erasure).
		if s.valid && s.epoch == e.cutEpoch.Load() {
			_ = s.advance(ctx, e) // a failure is the plan's to report: it reads the same commands
		}
		s.mu.Unlock()
	}
}

// entries reads the commands appended since the last read and lists the error records whose deadline is at or before horizon.
func (s *expiryScan) entries(ctx context.Context, e *Engine, horizon model.UnixNano) ([]ExpiringEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.advance(ctx, e); err != nil {
		return nil, err
	}
	var out []ExpiringEntry
	for _, r := range s.recs {
		for _, until := range r.retain {
			if until <= horizon {
				out = append(out, ExpiringEntry{Org: r.org, Project: r.project, Cursor: r.cursor, Deadline: until, At: r.at})
				break
			}
		}
	}
	return out, nil
}

// advance reads the commands appended since the last read; s.mu is held.
func (s *expiryScan) advance(ctx context.Context, e *Engine) error {
	epoch := e.cutEpoch.Load()
	if !s.valid || s.epoch != epoch {
		s.reset(epoch)
	}
	for slot := range uint16(64) {
		err := e.scanChunksRange(ctx, "replica_commands", commandKey(slot, s.through[slot]+1), commandKey(slot+1, 0), func(k, raw []byte) error {
			s.scanned++
			if isPayloadRef(raw) {
				if raw = storedFromDBCold(e.db.DB, raw); raw == nil {
					return model.Fail(model.Corrupt) // a candidate that cannot be read is never skipped
				}
			}
			if len(k) == 10 && bytes.HasPrefix(raw, batchCommandPrefix) && bytes.Contains(raw, errorKindJSON) {
				var entry walEntry
				if err := json.Unmarshal(raw, &entry); err != nil || entry.Batch == nil || entry.Receipt == nil {
					return model.Fail(model.Corrupt)
				}
				var retain []model.UnixNano
				for _, d := range entry.Receipt.SignalDeadlines {
					if d.Kind == model.ErrorKind && d.RetainUntil != 0 {
						retain = append(retain, d.RetainUntil)
					}
				}
				if len(retain) > 0 {
					for i := range entry.Batch.Records {
						if r := entry.Batch.Records[i]; r.Kind == model.ErrorKind {
							s.recs = append(s.recs, expiryRecord{org: entry.Batch.Org, project: entry.Batch.Project, cursor: entry.Receipt.Cursor, at: model.SignalTime(r), retain: retain})
						}
					}
				}
			}
			if len(k) == 10 {
				s.through[slot] = binary.BigEndian.Uint64(k[2:])
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if e.cutEpoch.Load() != epoch || len(s.recs) > expiryCacheMax {
		s.valid = false // an erasure rewrote commands while the scan read them, or the cache is too big to keep
	}
	return nil
}
