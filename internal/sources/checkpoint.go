// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
)

// Position names the next unread byte (file/syslog) or the last consumed entry
// (journal). It is an acquisition position, not an admission claim: the
// committed Position of a Checkpoint only ever moves in Acknowledge.
type Position struct {
	// Started is set once the first start decision (end or beginning) was taken.
	Started bool `json:"started,omitempty"`
	// File is an opaque identity token of the file (device and inode, or the
	// Windows file index): never a path.
	File   string `json:"file,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	// Tail is the hex SHA-256 of up to the last 64 bytes before Offset. A file
	// whose identity matches but whose tail differs was replaced in place; a
	// copy of a file (copytruncate) is found by its tail.
	Tail string `json:"tail,omitempty"`
	// Final says File was a rotated predecessor and was read to its end: the
	// successor is read from byte zero even if the predecessor is gone.
	Final bool `json:"final,omitempty"`
	// Skip says the reader is inside an over-long line (already counted as
	// dropped) and discards bytes up to the next newline.
	Skip bool `json:"skip,omitempty"`
	// Cursor is the journal cursor of the last consumed entry; Since is the
	// epoch second a journal with no cursor started from.
	Cursor string `json:"cursor,omitempty"`
	Since  int64  `json:"since,omitempty"`
}

// Gap is an interval in which source records may have been lost before they
// were read (rotation or truncation removed unread bytes). Count is a lower
// bound: the exact number is unknown and never presented as zero.
type Gap struct {
	Reason string         `json:"reason"`
	Count  uint64         `json:"count"`
	Start  model.UnixNano `json:"start_ns"`
	End    model.UnixNano `json:"end_ns"`
}

// Pending is the durable intent for exactly one contiguous range: the range
// that a retry after a lost acknowledgement or restart must rebuild
// byte-identically. It holds no source content, only positions, counts, reason
// counters and identifiers.
type Pending struct {
	Group model.ID `json:"group"`
	// Supersedes names the pending range this one replaces when the source no
	// longer reproduces the earlier range (the only way an intent is replaced).
	Supersedes *model.ID         `json:"supersedes,omitempty"`
	At         model.UnixNano    `json:"at_ns"`
	To         Position          `json:"to"`
	Scanned    uint32            `json:"scanned"`
	Records    uint32            `json:"records"`
	Dropped    map[string]uint64 `json:"dropped,omitempty"`
	Gaps       []Gap             `json:"gaps,omitempty"`
}

// Health is the last observed capability of the source.
type Health struct {
	Status Status         `json:"status"`
	Reason Reason         `json:"reason,omitempty"`
	Since  model.UnixNano `json:"since_ns"`
}

// Checkpoint is the durable state of one source.
type Checkpoint struct {
	Version  uint16            `json:"version"`
	Source   string            `json:"source"`
	Position Position          `json:"position"`
	Pending  *Pending          `json:"pending,omitempty"`
	Counters map[string]uint64 `json:"counters,omitempty"`
	Admitted uint64            `json:"admitted"`
	LastRead model.UnixNano    `json:"last_read_ns,omitempty"`
	Health   Health            `json:"health"`
}

// Batch parts of one pending range.
const (
	PartLogs = "logs"
	PartLoss = "loss"
)

// BatchID is the deterministic identifier of one batch of a pending range, so a
// retry after a lost acknowledgement presents the same batch ID (and, since the
// records are rebuilt identically, the same bytes) and the server's receipt
// ledger deduplicates it.
func BatchID(group model.ID, part string) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.sources.batch.v1\x00"))
	h.Write(group[:])
	h.Write([]byte(part))
	var id model.ID
	copy(id[:], h.Sum(nil))
	if id == (model.ID{}) {
		id[0] = 1
	}
	return id
}

// RecordID is the deterministic identifier of record i of a pending range.
func RecordID(group model.ID, part string, i int) model.ID {
	h := sha256.New()
	h.Write([]byte("soundpost.sources.record.v1\x00"))
	h.Write(group[:])
	h.Write([]byte(part))
	h.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
	var id model.ID
	copy(id[:], h.Sum(nil))
	if id == (model.ID{}) {
		id[0] = 1
	}
	return id
}

// expected lists the batch IDs whose receipts are required before Pending may
// be committed. A range with no admissible record and no gap needs none.
func (p Pending) expected() []model.ID {
	var ids []model.ID
	if p.Records > 0 {
		ids = append(ids, BatchID(p.Group, PartLogs))
	}
	if len(p.Gaps) > 0 {
		ids = append(ids, BatchID(p.Group, PartLoss))
	}
	return ids
}

// Acknowledge returns the checkpoint with the pending range committed. It is
// the ONLY way a Position advances, and it refuses unless the receipts cover
// exactly the batches of the pending range.
func (c Checkpoint) Acknowledge(receipts ...model.Receipt) (Checkpoint, error) {
	if c.Pending == nil {
		return c, newError(c.Source, StatusUnknown, ReasonCheckpointState)
	}
	want := c.Pending.expected()
	if len(receipts) != len(want) {
		return c, newError(c.Source, StatusUnknown, ReasonReceiptMismatch)
	}
	seen := map[model.ID]bool{}
	for _, r := range receipts {
		if r.Version == 0 || r.Cursor.Group == (model.ID{}) || r.Cursor.Index == 0 || seen[r.BatchID] {
			return c, newError(c.Source, StatusUnknown, ReasonReceiptMismatch)
		}
		seen[r.BatchID] = true
	}
	for _, id := range want {
		if !seen[id] {
			return c, newError(c.Source, StatusUnknown, ReasonReceiptMismatch)
		}
	}
	next := c
	next.Position = c.Pending.To
	next.Admitted += uint64(c.Pending.Records)
	next.Counters = make(map[string]uint64, len(c.Counters)+len(c.Pending.Dropped))
	for k, v := range c.Counters {
		next.Counters[k] = v
	}
	for k, v := range c.Pending.Dropped {
		next.Counters[k] += v
	}
	next.Pending = nil
	return next, nil
}

// Store persists checkpoints atomically in one directory. A single agent
// process owns a state directory.
type Store struct {
	mu  sync.Mutex
	dir string
}

// OpenStore creates (if needed) and opens the checkpoint directory.
func OpenStore(dir string) (*Store, error) {
	if dir == "" || !isAbs(dir) {
		return nil, newError("store", StatusUnknown, ReasonInvalidPolicy)
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return nil, newError("store", StatusUnknown, ReasonReadFailed)
	}
	return &Store{dir: filepath.Clean(dir)}, nil
}

func (s *Store) path(source string) (string, error) {
	if !nameRE.MatchString(source) {
		return "", newError(source, StatusUnknown, ReasonInvalidPolicy)
	}
	return filepath.Join(s.dir, source+".checkpoint.json"), nil
}

type checkpointFile struct {
	Checkpoint json.RawMessage `json:"checkpoint"`
	SHA256     string          `json:"sha256"`
}

// Load returns the stored checkpoint, or a zero checkpoint for a source never
// seen. A corrupt file is an error: it is never silently reset to "start at the
// end", which would skip records.
func (s *Store) Load(source string) (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(source)
}

func (s *Store) load(source string) (Checkpoint, error) {
	p, err := s.path(source)
	if err != nil {
		return Checkpoint{}, err
	}
	f, err := os.Open(p)
	if errors.Is(err, os.ErrNotExist) {
		return Checkpoint{Version: 1, Source: source}, nil
	}
	if err != nil {
		return Checkpoint{}, newError(source, StatusUnknown, ReasonReadFailed)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return Checkpoint{}, newError(source, StatusUnknown, ReasonReadFailed)
	}
	var file checkpointFile
	if json.Unmarshal(raw, &file) != nil {
		return Checkpoint{}, newError(source, StatusUnknown, ReasonCheckpointCorrup)
	}
	sum := sha256.Sum256(file.Checkpoint)
	if file.SHA256 != hex.EncodeToString(sum[:]) {
		return Checkpoint{}, newError(source, StatusUnknown, ReasonCheckpointCorrup)
	}
	var cp Checkpoint
	d := json.NewDecoder(bytes.NewReader(file.Checkpoint))
	d.DisallowUnknownFields()
	if d.Decode(&cp) != nil || cp.Version != 1 || cp.Source != source {
		return Checkpoint{}, newError(source, StatusUnknown, ReasonCheckpointCorrup)
	}
	return cp, nil
}

func (s *Store) save(cp Checkpoint) error {
	p, err := s.path(cp.Source)
	if err != nil {
		return err
	}
	cp.Version = 1
	body, err := json.Marshal(cp)
	if err != nil {
		return newError(cp.Source, StatusUnknown, ReasonReadFailed)
	}
	sum := sha256.Sum256(body)
	raw, err := json.Marshal(checkpointFile{Checkpoint: body, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return newError(cp.Source, StatusUnknown, ReasonReadFailed)
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return newError(cp.Source, StatusUnknown, ReasonReadFailed)
	}
	_, werr := f.Write(raw)
	if werr == nil {
		werr = f.Sync()
	}
	cerr := f.Close()
	if werr != nil || cerr != nil {
		os.Remove(tmp)
		return newError(cp.Source, StatusUnknown, ReasonReadFailed)
	}
	if err := durablefs.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return newError(cp.Source, StatusUnknown, ReasonReadFailed)
	}
	return nil
}

// Prepare durably records the pending intent of next BEFORE anything is
// submitted. It cannot advance the committed position, counters or admitted
// total: those only change in Commit.
func (s *Store) Prepare(next Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load(next.Source)
	if err != nil {
		return err
	}
	if next.Pending == nil || next.Position != cur.Position || next.Admitted != cur.Admitted || !sameCounters(next.Counters, cur.Counters) {
		return newError(next.Source, StatusUnknown, ReasonCheckpointState)
	}
	if cur.Pending != nil && cur.Pending.Group != next.Pending.Group && (next.Pending.Supersedes == nil || *next.Pending.Supersedes != cur.Pending.Group) {
		return newError(next.Source, StatusUnknown, ReasonCheckpointState)
	}
	cur.Pending = next.Pending
	return s.save(cur)
}

// Commit advances the committed position to the end of the pending range, and
// only if receipts cover exactly the batches of that range.
func (s *Store) Commit(source string, receipts ...model.Receipt) (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load(source)
	if err != nil {
		return Checkpoint{}, err
	}
	next, err := cur.Acknowledge(receipts...)
	if err != nil {
		return cur, err
	}
	next.LastRead = cur.Pending.At
	if cur.Health.Status != StatusSupported {
		next.Health = Health{Status: StatusSupported, Since: cur.Pending.At}
	}
	if err := s.save(next); err != nil {
		return cur, err
	}
	return next, nil
}

// RecordHealth stores the observed capability of the source. It never moves a
// position.
func (s *Store) RecordHealth(source string, status Status, reason Reason, at model.UnixNano) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.load(source)
	if err != nil {
		return err
	}
	if cur.Health.Status == status && cur.Health.Reason == reason {
		return nil
	}
	cur.Health = Health{Status: status, Reason: reason, Since: at}
	return s.save(cur)
}

func sameCounters(a, b map[string]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if bv, ok := b[k]; !ok || bv != a[k] {
			return false
		}
	}
	return true
}
