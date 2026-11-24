// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// Retry parts (D87, L2w20Admission17).
//
// The retry table of a digest machine (up to DefaultRetryMax entries, ~425 B each: 42 MB at the cap) used to be
// serialized into the envelope of every snapshot a group cut. The control group cut every few seconds under load,
// so every cut wrote, read back, verified and later compacted a 20 to 40 MB file again (and the journal rewrite that
// follows carried the same envelope in its head record): the cost of a cut grew with the table until it was
// capped, and the files created and unlinked every few seconds were the largest in the data directory.
//
// A group whose machine cuts compact snapshots (CompactStateMachine) and whose compact state is what it just
// cut keeps the table in immutable files of the snapshot instead: runs of retryPartEntries entries in apply order,
// named by the first and last index they hold. The envelope names the files (RetryParts) and the index of the
// oldest entry the table still holds (RetryFrom). A cut writes only what is new: the sealed parts of the previous
// cut that still hold retained entries are taken from the selected snapshot (a hard link, the way a machine's
// FileMachine files are), the entries after them are written as new parts, the last of which may be partial and is
// rewritten by the next cut. The serialization of a cut is bounded by the entries applied since the previous cut
// and one part, not by the table.
//
// Retry entries of a digest-kept kind are immutable once applied (no payload to redact, the receipt never
// changes) and are evicted oldest first, so the table at a cut is always the suffix, from RetryFrom on, of the
// concatenation of the parts. A part is dropped once every entry in it is older than RetryFrom.
//
// A snapshot that carries parts can be read only by a build that knows them: the envelope names the table format
// (Retry) and the field is not known to a strict reader of an older build, which refuses it. The group therefore
// cuts parts only for a machine that says its state is already compact, which a machine does only when no
// previous release can read the journal (the control machine after contraction). A snapshot sent to a peer, the
// journal head written by Snapshot and every snapshot of any other group carry the whole table inline as before.
//
// The journal head after a compaction holds the envelope, and the parts it names live in the snapshot directory
// cut at the head's index; a group opened on such a journal resolves them there (restoreSnapshot), which is why a
// cut compacts the journal before it drops the superseded snapshot directory.

// retryPartEntries is how many entries a sealed part holds. A cut rewrites at most one partial part
// (fewer than this) beside the entries applied since the previous cut. It is a variable only so that tests can
// make a part hold a few entries; nothing else assigns it.
var retryPartEntries = 2048

var retryPartName = regexp.MustCompile(`^retry-[0-9]{20}-[0-9]{20}\.json$`)

// CompactStateMachine is optionally implemented by a machine that cuts compact snapshots (CompactMachine):
// CompactState reports whether state, as returned by CompactSnapshot, is the compact form, which only a build that
// knows it can read. Only then may the group keep the retry table of the snapshot in parts (retry_parts.go).
type CompactStateMachine interface {
	CompactState(state []byte) bool
}

// retryPart describes one retry-part file of the selected snapshot.
type retryPart struct {
	Name        string // the name in the envelope; the file is filePrefix+Name in the manifest
	First, Last uint64 // the lowest and highest log index of the entries it holds
	Count       int
	Size        uint64
	Sum         model.Hash
}

// retryPlan is what a cut keeps and writes of the retry table, decided under the group lock.
type retryPlan struct {
	epoch uint64
	keep  []retryPart        // sealed parts of the previous cut that still hold retained entries
	chunk [][]CommittedEntry // the entries after them, split in parts; the last may be partial
	plain []CommittedEntry   // retry entries of kinds that are not kept by digest, inline in the envelope
	from  uint64             // the log index of the oldest entry the table holds (0: none)
}

// compactRetry reports whether the cut of state may keep the retry table in parts.
func (g *Group) compactRetry(state []byte) bool {
	if g.retryDigest == nil {
		return false
	}
	m, ok := g.machine.(CompactStateMachine)
	return ok && m.CompactState(state)
}

// planRetryLocked decides what the cut at the applied index writes. g.mu is held. It copies only the entries applied since
// the previous cut, the partial last part and any entry of a kind that is not kept by digest.
func (g *Group) planRetryLocked() *retryPlan {
	p := &retryPlan{epoch: g.retryEpoch}
	if len(g.completed) != len(g.retryOrder) { // an entry that no eviction order names: kept inline
		for _, c := range g.completed {
			if !g.digestKind(c.Entry.Kind) {
				p.plain = append(p.plain, c)
			}
		}
	}
	oldest := -1 // the first retryOrder position whose entry is still in the table
	for i, id := range g.retryOrder {
		if c, ok := g.completed[id]; ok {
			p.from, oldest = c.Index, i
			break
		}
	}
	if oldest < 0 {
		return p
	}
	// The sealed parts of the previous cut that still hold retained entries.
	parts := g.retryParts
	for len(parts) > 0 && parts[0].Last < p.from {
		parts = parts[1:]
	}
	if n := len(parts); n > 0 && parts[n-1].Count < retryPartEntries {
		parts = parts[:n-1] // the partial tail is rewritten with what follows it
	}
	p.keep = append([]retryPart(nil), parts...)
	var sealed uint64
	if len(p.keep) > 0 {
		sealed = p.keep[len(p.keep)-1].Last
	}
	// The entries after them, newest first until the sealed part (or the oldest retained entry) is reached.
	var rest []CommittedEntry
	for i := len(g.retryOrder) - 1; i >= oldest; i-- {
		c, ok := g.completed[g.retryOrder[i]]
		if !ok {
			continue
		}
		if c.Index <= sealed {
			break
		}
		rest = append(rest, c)
	}
	for i, j := 0, len(rest)-1; i < j; i, j = i+1, j-1 {
		rest[i], rest[j] = rest[j], rest[i]
	}
	for len(rest) > 0 {
		n := min(len(rest), retryPartEntries)
		p.chunk = append(p.chunk, rest[:n:n])
		rest = rest[n:]
	}
	return p
}

// partName is the name of the part holding entries first..last.
func partName(first, last uint64) string {
	return fmt.Sprintf("retry-%020d-%020d.json", first, last)
}

// encode serializes the new parts. It returns the bundle sources of the whole table (kept parts by reference),
// the part list the snapshot will have, and how many bytes were serialized.
func (p *retryPlan) encode() (sources []bundleSource, parts []retryPart, written uint64, err error) {
	for _, k := range p.keep {
		parts = append(parts, k)
		sources = append(sources, bundleSource{name: filePrefix + k.Name, reuse: true, size: k.Size, sum: k.Sum})
	}
	for _, chunk := range p.chunk {
		raw, err := json.Marshal(chunk)
		if err != nil {
			return nil, nil, 0, err
		}
		part := retryPart{Name: partName(chunk[0].Index, chunk[len(chunk)-1].Index), First: chunk[0].Index, Last: chunk[len(chunk)-1].Index, Count: len(chunk), Size: uint64(len(raw)), Sum: model.Hash(sha256.Sum256(raw))}
		parts = append(parts, part)
		sources = append(sources, bundleSource{name: filePrefix + part.Name, data: raw})
		written += uint64(len(raw))
	}
	return sources, parts, written, nil
}

func partNames(parts []retryPart) []string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = p.Name
	}
	return out
}

// resetRetryPartsLocked forgets the parts the group believes the selected snapshot holds: the next cut writes the
// whole table. g.mu is held.
func (g *Group) resetRetryPartsLocked() {
	g.retryParts = nil
	g.retryEpoch++
}

// validRetryParts is the structural check of the names an envelope carries.
func validRetryParts(e snapshotEnvelope) bool {
	if len(e.RetryParts) == 0 {
		return e.RetryFrom == 0
	}
	if e.Retry != retryDigestTag {
		return false
	}
	var last string
	for _, n := range e.RetryParts {
		if !retryPartName.MatchString(n) || n <= last {
			return false
		}
		last = n
	}
	return true
}

// loadRetryParts puts the entries of the parts an envelope names, from RetryFrom on, into the retry table. The
// parts are read from the snapshot directory cut at index and checked against the manifest's hashes.
func (g *Group) loadRetryParts(e snapshotEnvelope, index uint64) ([]retryPart, error) {
	snap, err := g.snaps.at(index)
	if err != nil {
		return nil, ErrCorrupt
	}
	files := map[string]SnapshotFile{}
	for _, f := range snap.Manifest.Files {
		files[f.Name] = f
	}
	var loaded []retryPart
	for _, name := range e.RetryParts {
		f, ok := files[filePrefix+name]
		if !ok {
			return nil, ErrCorrupt
		}
		in, err := snap.File(filePrefix + name)
		if err != nil {
			return nil, ErrCorrupt
		}
		h := sha256.New()
		raw, err := io.ReadAll(io.TeeReader(io.LimitReader(in, int64(f.Size)+1), h))
		in.Close()
		if err != nil || uint64(len(raw)) != f.Size || model.Hash(h.Sum(nil)) != f.SHA256 {
			return nil, ErrCorrupt
		}
		var entries []CommittedEntry
		if model.StrictJSON(raw, &entries) != nil || len(entries) == 0 {
			return nil, ErrCorrupt
		}
		first, last := entries[0].Index, entries[len(entries)-1].Index
		if partName(first, last) != name {
			return nil, ErrCorrupt
		}
		var previous uint64
		for _, c := range entries {
			if c.Group != g.group || c.Index <= previous || c.Index > index || !digestKept(c.Entry) {
				return nil, ErrInvalid
			}
			previous = c.Index
			if c.Index >= e.RetryFrom {
				g.completed[c.Entry.ID] = g.retained(c)
			}
		}
		loaded = append(loaded, retryPart{Name: name, First: first, Last: last, Count: len(entries), Size: f.Size, Sum: f.SHA256})
	}
	return loaded, nil
}

// at returns the snapshot directory cut at index, selected or not, after its structural check.
func (s *SnapshotStore) at(index uint64) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirs, err := s.snapDirs()
	if err != nil {
		return Snapshot{}, err
	}
	for _, d := range dirs {
		fields := strings.SplitN(d, "-", 3) // snap-<20 digit index>-<checksum prefix>
		if len(fields) != 3 {
			continue
		}
		if cut, err := strconv.ParseUint(fields[1], 10, 64); err != nil || cut != index {
			continue
		}
		if snap, err := s.loadDir(filepath.Join(s.root, d), false); err == nil {
			return snap, nil
		}
	}
	return Snapshot{}, ErrNoSnapshot
}

// wroteLast reports whether the newest create wrote files itself (it did not when the selected snapshot was
// already the cut).
func (s *SnapshotStore) wroteLast() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.fresh) > 0
}

// freshBytes is the size of the files the newest create wrote itself, of the snapshot m it published.
func (s *SnapshotStore) freshBytes(m SnapshotManifest) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	fresh := map[string]bool{}
	for _, n := range s.fresh {
		fresh[n] = true
	}
	var total int64
	for _, f := range m.Files {
		if fresh[f.Name] {
			total += int64(f.Size)
		}
	}
	return total
}
