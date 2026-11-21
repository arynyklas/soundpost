// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// Redaction crash hooks (see install.go for the semantics of a hook error).
const (
	HookRedactBegin   = "redact_begin"
	HookRedactPins    = "redact_pins"
	HookRedactWrite   = "redact_write"
	HookRedactSync    = "redact_sync"
	HookRedactSwitch  = "redact_switch"
	HookRedactRenamed = "redact_renamed"
	HookRedactMemory  = "redact_memory"
)

// Residue store names reported by Group.Residue.
const (
	ResidueJournal   = "raft_journal"
	ResidueSnapshots = "raft_snapshots"
)

const (
	journalRedactTemp = "ready.wal.redact"
	maxEntryPayload   = 16 << 20
	// redactUnlockedAttempts is how many times RedactCompleted stages its rewrite without the group
	// lock before it stages it under the lock (a group that commits during every attempt still
	// gets its redaction).
	redactUnlockedAttempts = 3
)

// Redaction names one applied command whose payload this group must stop holding, and the
// payload the machine accepts in its place.
type Redaction struct {
	// ApplicationIndex is the C05 application index of the command (the machine's own
	// position for it), the key both the machine and this group know it by.
	ApplicationIndex uint64
	// Replacement is replayed by the machine instead of the original payload: it must be a
	// payload the machine applies to the same state the redacted stored command has, and it
	// must not carry what is being forgotten. It is retained as the command's payload from now
	// on, in the retry table, the journal and every later snapshot.
	Replacement []byte
}

// RedactResult counts what one call changed. A call that finds everything already redacted
// changes and rewrites nothing.
type RedactResult struct {
	Redacted int // commands whose retained payload in the retry table was replaced
	Absent   int // requested application indexes this group holds no applied command for
	Journal  int // journal entries rewritten on disk
	Pins     int // pin archive entries rewritten on disk
	// PinsSkipped counts the pin archives this call never opened: a pin archives only commands
	// with an application index above its After, so a pin whose After is not below the highest
	// application index of every copy of the commands to redact cannot hold one.
	PinsSkipped int
}

type redactTarget struct {
	replacement []byte
	// application is the highest application index of any copy of the command that the retry table,
	// the log index and the retained log know; 0: not known (the command was located in the
	// retained log or a pin archive), which bounds nothing (pinBound).
	application uint64
}

// RedactCompleted replaces the retained payload of the named applied commands by the machine's
// replacement, in every place this group keeps one that it can rewrite:
//
//   - the retry table (completed commands) that every later snapshot serializes;
//   - every entry of the retained Raft journal, on disk (temp file, fsync, atomic rename) and in
//     the in-memory log that is sent to a voter that is behind, so such a voter receives the
//     redacted entry and never stores the original;
//   - the entries of every backup pin archive.
//
// The command keeps its ID, kind, term, physical and application index, reservation and
// outcome, so a retry answers with the original receipt; only the payload changes, and the digest
// of the payload it was proposed with is kept (Entry.Original), so a retry carrying the original
// payload is still recognized and a different payload under the same ID is still a conflict.
//
// What cannot be rewritten in place is a snapshot directory, and the snapshot record the journal
// begins with: they are sealed at an older cut, checksummed and immutable. They carry the old
// payloads until a snapshot cut at a later index replaces them and the journal is compacted onto
// it (CreateSnapshot after the applied index advanced, SnapshotStore.DropSuperseded,
// CompactJournal). Residue reports whether such copies still exist.
//
// The operation is idempotent and re-derivable: every request names a command by application
// index and carries the replacement, so a caller that knows (durably) which commands are
// redacted can repeat the call after any crash, restart or snapshot installation and the group
// converges. The retry table is rebuilt from the selected snapshot on open, so a redaction that
// only reached the table is repeated by the caller after a restart; the journal rewrite is
// atomic (the old or the new journal is in force, never a mix).
//
// An error returned before the journal was replaced (a hook, a read, a temp file or a pin archive
// that could not be written) did not start writing: the group is untouched and still serves, and
// the caller retries the same call. An error after the journal rename, or in the in-memory swap,
// can leave the open journal handle, the retained log and the retry table disagreeing: the group
// fails until a restart rebuilds it from the journal and the caller repeats the redaction.
//
// The group lock is not held while the journal and the pin archives are rewritten: a rewrite over
// a long journal would stop Propose and ReadIndex for the whole group. The call plans under the
// lock, stages the rewritten files (temporary files, fsync) without it, and installs them under
// the lock only when the group is exactly what the plan read (redactCompletedOnce); otherwise it
// discards them and starts over, and the fourth attempt holds the lock throughout.
//
// A pin archive that cannot hold a command to redact is not opened (RedactResult.PinsSkipped): a
// pin archives only the commands above its After, so one whose After is at or above the highest
// application index of every copy of every command to redact holds none (pinBound). A command
// located by application index because the retry table forgot it has no known bound, and then
// every pin is read. The one copy this cannot see is a second committed copy of an ID that the
// retry table still holds, with an application index above the pin's After and nowhere but in
// that pin's archive; Propose refuses such a copy (the table answers the retry).
//
// A request that cannot be honoured is refused whole with ErrInvalid before anything is
// rewritten: an empty or oversized replacement, application index 0, a duplicate application
// index, or a command that is not telemetry payload (barriers, cancellations, control and
// artifact-GC commands are never redacted). An application index the group holds no command for
// is counted in Absent and is not an error.
func (g *Group) RedactCompleted(ctx context.Context, requests []Redaction) (RedactResult, error) {
	if err := ctx.Err(); err != nil {
		return RedactResult{}, err
	}
	wanted := make(map[uint64][]byte, len(requests))
	for _, r := range requests {
		if r.ApplicationIndex == 0 || len(r.Replacement) == 0 || len(r.Replacement) > maxEntryPayload {
			return RedactResult{}, ErrInvalid
		}
		if _, dup := wanted[r.ApplicationIndex]; dup {
			return RedactResult{}, ErrInvalid
		}
		wanted[r.ApplicationIndex] = r.Replacement
	}
	if len(wanted) == 0 {
		return RedactResult{}, nil
	}
	g.redactMu.Lock() // the journal's temporary file is shared with RedactMachineCommands, which builds it before it takes g.mu
	defer g.redactMu.Unlock()
	for attempt := 0; ; attempt++ {
		res, err := g.redactCompletedOnce(wanted, attempt >= redactUnlockedAttempts)
		if !errors.Is(err, errRedactRaced) {
			return res, err
		}
	}
}

// redactCompletedOnce is one attempt of RedactCompleted: it plans under g.mu (the commands to
// redact in the retry table and the retained log, the journal handle and length, the pin
// archives and their lengths), stages the rewritten journal and pin archives without it (they
// are temporary files: nothing of the group changes), and takes g.mu again to install them, but
// only when the group is exactly what the plan read (same applied index, same retained log, the
// same journal file at the same length, the same pins with the same archive files at the same
// lengths): a cut, a compaction, a commit or a pin that came in between would be undone or missed
// by installing the staged copy, so the attempt discards it and reports errRedactRaced. With
// locked, the lock is held throughout and nothing can change: the last attempt, so a group that
// never stops committing still gets its redaction.
func (g *Group) redactCompletedOnce(wanted map[uint64][]byte, locked bool) (RedactResult, error) {
	g.mu.Lock()
	held := true
	defer func() {
		if held {
			g.mu.Unlock()
		}
	}()
	if g.failed || g.closed {
		return RedactResult{}, ErrUnavailable
	}
	var res RedactResult
	targets := map[model.ID]*redactTarget{}
	found := map[uint64]bool{}
	for id, c := range g.completed {
		replacement, ok := wanted[c.Entry.ApplicationIndex]
		if !ok {
			continue
		}
		if c.Entry.Kind != Data && c.Entry.Kind != Artifact {
			return RedactResult{}, ErrInvalid
		}
		if found[c.Entry.ApplicationIndex] {
			return RedactResult{}, ErrConflict // two retained commands claim one application index
		}
		found[c.Entry.ApplicationIndex] = true
		targets[id] = &redactTarget{replacement: bytes.Clone(replacement), application: g.copyBoundLocked(id, c)}
	}
	loc := &locator{wanted: wanted, found: found, targets: targets, located: map[uint64]bool{}}
	if loc.pending() > 0 {
		// The retry table is bounded (DigestRetryMachine): a command it has evicted can still have
		// a copy in the retained log, the journal file (which mirrors it) or a pin archive. Those
		// copies are located by their application index, so the redaction does not depend on the
		// table having kept the command.
		if err := g.locateRetainedLocked(loc); err != nil {
			return RedactResult{}, err
		}
	}
	pins, err := g.planPinsLocked()
	if err != nil {
		return RedactResult{}, err
	}
	if len(targets) == 0 && (loc.pending() == 0 || len(pins) == 0) {
		res.Absent = loc.pending()
		return res, nil
	}
	tableWork := false
	for id, t := range targets {
		if p := g.completed[id].Entry.Payload; len(p) > 0 && !bytes.Equal(p, t.replacement) { // no payload: kept by digest
			tableWork = true
		}
	}
	in, err := g.journalInputsLocked()
	if err != nil {
		return RedactResult{}, err
	}
	defer in.close()
	if !locked {
		g.mu.Unlock()
		held = false
	}

	// Everything from here to relock touches no group state: it reads the plan and writes temporary
	// files. An error before the journal is replaced (a hook, a read, a temp file, a pin archive:
	// each replaced whole, atomically, and re-derivable) never started writing: the group is
	// intact, the caller retries, and the pass is idempotent. Only a failure after the journal
	// rename, or in the in-memory swap, can leave the group torn.
	var stagedPins []*stagedPin
	var stagedWAL *stagedJournal
	discard := func() {
		for _, p := range stagedPins {
			p.discard()
		}
		if stagedWAL != nil {
			stagedWAL.discard()
		}
	}
	fail := func(err error) (RedactResult, error) {
		discard()
		return RedactResult{}, err
	}
	// relock takes the group lock back before anything is installed and reports errRedactRaced
	// when the group is no longer what the plan read; the staged copies are discarded then.
	relock := func() error {
		if locked {
			return nil
		}
		g.mu.Lock()
		held = true
		var err error
		if g.failed || g.closed {
			err = ErrUnavailable
		} else if current, cerr := in.currentLocked(g); cerr != nil {
			err = cerr
		} else if !current {
			err = errRedactRaced
		} else if current, cerr = pinsCurrentLocked(g, pins); cerr != nil {
			err = cerr
		} else if !current {
			err = errRedactRaced
		}
		if err != nil {
			discard()
		}
		return err
	}

	opened := map[model.ID]bool{} // the pins this attempt read
	if err = loc.scanPins(pins, opened); err != nil {
		return fail(err)
	}
	if len(targets) == 0 {
		if err = relock(); err != nil {
			return RedactResult{}, err
		}
		res.Absent, res.PinsSkipped = loc.pending(), len(pins)-len(opened)
		return res, nil
	}
	raiseCopyBounds(in.log, targets)
	memory, err := redactedLog(in.log, targets)
	if err != nil {
		return fail(err)
	}
	if !tableWork && len(memory) == 0 && len(pins) == 0 {
		if err = relock(); err != nil {
			return RedactResult{}, err
		}
		res.Absent = loc.pending()
		return res, nil
	}
	if err = g.trip(HookRedactBegin); err != nil {
		return fail(err)
	}
	bound := pinBound(targets)
	var toStage []redactPin
	for _, p := range pins {
		if p.after < bound { // a pin archives only commands above its After: at or above every copy's index it holds none
			toStage = append(toStage, p)
		}
	}
	if len(toStage) > 0 {
		if err = g.trip(HookRedactPins); err != nil {
			return fail(err)
		}
	}
	for _, p := range toStage {
		opened[p.id] = true
		staged, serr := stagePinArchive(p.path, p.size, targets)
		if serr != nil {
			return fail(serr)
		}
		if staged != nil {
			stagedPins = append(stagedPins, staged)
		}
	}
	if len(memory) > 0 {
		if stagedWAL, err = g.stageRedactedJournal(in.journal(), targets); err != nil {
			return fail(err)
		}
	}
	if err = relock(); err != nil {
		return RedactResult{}, err
	}

	// The group is what the plan read, and g.mu is held: install.
	for i, staged := range stagedPins {
		if err = staged.install(); err != nil {
			for _, rest := range stagedPins[i+1:] {
				rest.discard()
			}
			if stagedWAL != nil {
				stagedWAL.discard()
			}
			return RedactResult{}, err
		}
		res.Pins += staged.rewritten
	}
	if stagedWAL != nil {
		if res.Journal, err = g.installRedactedJournal(stagedWAL); err != nil {
			var torn *tornError
			if errors.As(err, &torn) {
				g.failStop(FailMaintenance)
				return RedactResult{}, torn.error
			}
			return RedactResult{}, err
		}
		if err = g.trip(HookRedactMemory); err != nil {
			g.failStop(FailMaintenance)
			return RedactResult{}, err
		}
		if err = g.swapLogLocked(memory); err != nil {
			g.failStop(FailMaintenance)
			return RedactResult{}, err
		}
	}
	for id, t := range targets {
		c, ok := g.completed[id]
		if !ok || len(c.Entry.Payload) == 0 || bytes.Equal(c.Entry.Payload, t.replacement) { // no payload: kept by digest
			continue
		}
		c.Entry = redactedCommand(c.Entry, t.replacement)
		g.completed[id] = c
		if l, ok := g.logCommands[id]; ok {
			l.Entry = redactedCommand(l.Entry, t.replacement)
			g.logCommands[id] = l
		}
		res.Redacted++
	}
	g.sendSnap = nil // built from the retry table
	res.Absent, res.PinsSkipped = loc.pending(), len(pins)-len(opened)
	return res, nil
}

// copyBoundLocked is the highest application index any copy of the command c holds that the retry
// table or the log index knows. g.mu is held.
func (g *Group) copyBoundLocked(id model.ID, c CommittedEntry) uint64 {
	bound := c.Entry.ApplicationIndex
	if l, ok := g.logCommands[id]; ok && l.Entry.ApplicationIndex > bound {
		bound = l.Entry.ApplicationIndex
	}
	return bound
}

// raiseCopyBounds raises the bound of every target the retry table holds to the highest
// application index of a copy of it in the retained log.
func raiseCopyBounds(log []*pb.Entry, targets map[model.ID]*redactTarget) {
	for _, ent := range log {
		e, ok := parseEntry(ent)
		if !ok {
			continue
		}
		if t := targets[e.ID]; t != nil && t.application != 0 && e.ApplicationIndex > t.application {
			t.application = e.ApplicationIndex
		}
	}
}

// pinBound is the application index at or above which a pin cannot hold a copy of any target: a
// pin archives only the commands whose application index is above its After (archiveRangeLocked),
// so a pin with After at or above the highest application index of every copy of every target
// holds none. A target whose copies are not all known (application 0: it was located in the
// retained log or in a pin archive, because the retry table had forgotten it, and a copy of an ID
// that was applied again after its eviction carries another application index) bounds nothing: no
// pin is skipped then.
func pinBound(targets map[model.ID]*redactTarget) uint64 {
	var bound uint64
	for _, t := range targets {
		if t.application == 0 {
			return ^uint64(0)
		}
		bound = max(bound, t.application)
	}
	return bound
}

// locator finds the commands of the requested application indexes that the retry table did not
// hold (found lists those it did), among the entries of the retained log and of the pin archives,
// and adds them to targets.
type locator struct {
	wanted  map[uint64][]byte
	found   map[uint64]bool
	targets map[model.ID]*redactTarget
	located map[uint64]bool
}

// pending is how many requested application indexes neither the table nor a search found.
func (l *locator) pending() int { return len(l.wanted) - len(l.found) - len(l.located) }

func (l *locator) visit(ent *pb.Entry) error {
	e, ok := parseEntry(ent)
	if !ok {
		return nil
	}
	replacement, ok := l.wanted[e.ApplicationIndex]
	if !ok || l.found[e.ApplicationIndex] {
		return nil
	}
	if e.Kind != Data && e.Kind != Artifact {
		return ErrInvalid
	}
	if l.targets[e.ID] == nil {
		l.targets[e.ID] = &redactTarget{replacement: bytes.Clone(replacement)}
	}
	l.located[e.ApplicationIndex] = true
	return nil
}

// scanPins searches the pin archives for the indexes still pending, each archive as far as it was
// when the plan was made. A pin whose After is at or above every pending index holds none of them
// and is not opened. It records the pins it read in opened.
func (l *locator) scanPins(pins []redactPin, opened map[model.ID]bool) error {
	var highest uint64
	for index := range l.wanted {
		if !l.found[index] && !l.located[index] && index > highest {
			highest = index
		}
	}
	if highest == 0 {
		return nil
	}
	for _, p := range pins {
		if p.after >= highest {
			continue
		}
		opened[p.id] = true
		if err := scanPinArchivePrefix(p.path, p.size, l.visit); err != nil {
			return err
		}
	}
	return nil
}

// locateRetainedLocked searches the retained log for the requested indexes the retry table did not
// hold (the pin archives are read without the lock, locator.scanPins). The retained log mirrors the
// journal file, so a command located there is rewritten in the file too. The log is read only when
// the application indexes it spans include a requested one the table lacks, so a group whose old
// redactions lie below its retained log pays nothing for them. g.mu is held.
func (g *Group) locateRetainedLocked(l *locator) error {
	var low uint64
	errLow := errors.New("replica: first application index found")
	if err := g.eachMemoryEntryLocked(func(ent *pb.Entry) error {
		if e, ok := parseEntry(ent); ok {
			low = e.ApplicationIndex
			return errLow
		}
		return nil
	}); err != nil && !errors.Is(err, errLow) {
		return err
	}
	inLog := false
	for index := range l.wanted {
		if !l.found[index] && low != 0 && index >= low && index <= g.logApplication {
			inLog = true
			break
		}
	}
	if !inLog {
		return nil
	}
	return g.eachMemoryEntryLocked(func(ent *pb.Entry) error {
		if ent.GetIndex() > g.applied {
			return nil
		}
		return l.visit(ent)
	})
}

// redactPin is one pin archive as a plan read it: the pin, its archive file and the length it had.
type redactPin struct {
	id    model.ID
	pin   *JournalPin
	path  string
	after uint64
	size  int64
	info  os.FileInfo
}

// planPinsLocked lists the pins by ID with the file and length of each archive. g.mu is held.
func (g *Group) planPinsLocked() ([]redactPin, error) {
	if len(g.pins) == 0 {
		return nil, nil
	}
	out := make([]redactPin, 0, len(g.pins))
	for id, p := range g.pins {
		info, err := os.Stat(p.path)
		if err != nil {
			return nil, err
		}
		out = append(out, redactPin{id: id, pin: p, path: p.path, after: p.after, size: info.Size(), info: info})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].id[:], out[j].id[:]) < 0 })
	return out, nil
}

// pinsCurrentLocked reports whether the group still holds exactly the pins the plan read: the same
// pins, each with the same archive file at the same length (an archived range lengthens it, a
// rewrite replaces the file). g.mu is held.
func pinsCurrentLocked(g *Group, pins []redactPin) (bool, error) {
	if len(g.pins) != len(pins) {
		return false, nil
	}
	for _, p := range pins {
		if g.pins[p.id] != p.pin {
			return false, nil
		}
		now, err := os.Stat(p.path)
		if err != nil {
			return false, err
		}
		if !os.SameFile(now, p.info) || now.Size() != p.size {
			return false, nil
		}
	}
	return true, nil
}

// redactedCommand is e with its payload replaced; Original keeps the digest of the payload the
// command was first proposed with, across any number of redactions.
func redactedCommand(e Entry, replacement []byte) Entry {
	original := e.proposed()
	e.Payload = bytes.Clone(replacement)
	e.Original = &original
	return e
}

// redactedEntry returns the Raft entry that replaces ent, or nil when ent is not one of the
// commands to redact or already carries its replacement.
func redactedEntry(ent *pb.Entry, targets map[model.ID]*redactTarget) (*pb.Entry, error) {
	e, ok := parseEntry(ent)
	if !ok {
		return nil, nil
	}
	t := targets[e.ID]
	if t == nil || bytes.Equal(e.Payload, t.replacement) {
		return nil, nil
	}
	data, err := json.Marshal(redactedCommand(e, t.replacement))
	if err != nil {
		return nil, err
	}
	replaced := proto.Clone(ent).(*pb.Entry)
	replaced.Data = data
	return replaced, nil
}

// redactedLog lists the entries (by physical index) that the redaction replaces.
func redactedLog(entries []*pb.Entry, targets map[model.ID]*redactTarget) (map[uint64]*pb.Entry, error) {
	out := map[uint64]*pb.Entry{}
	for _, ent := range entries {
		replaced, err := redactedEntry(ent, targets)
		if err != nil {
			return nil, err
		}
		if replaced != nil {
			out[ent.GetIndex()] = replaced
		}
	}
	return out, nil
}

// swapLogLocked replaces entries of the in-memory log. The Raft state machine reads entries from
// the storage on demand and never caches them, and the entries keep their term and index, so
// the swap changes no Raft state; a voter that is behind is now sent the redacted entries.
func (g *Group) swapLogLocked(replaced map[uint64]*pb.Entry) error {
	last, _ := g.memory.LastIndex()
	lo := ^uint64(0)
	for index := range replaced {
		lo = min(lo, index)
	}
	entries, err := g.memory.Entries(lo, last+1, ^uint64(0))
	if err != nil {
		return err
	}
	suffix := make([]*pb.Entry, len(entries))
	for i, ent := range entries {
		suffix[i] = ent
		if r, ok := replaced[ent.GetIndex()]; ok {
			suffix[i] = r
		}
	}
	return g.memory.Append(suffix)
}

// stagedJournal is a redacted copy of the journal, complete and synced in its temporary file, not
// yet in place.
type stagedJournal struct {
	temp      string
	rewritten int
}

// discard removes the staged copy; the journal is untouched. A copy it cannot remove is overwritten
// by the next redaction and removed by the next Open.
func (s *stagedJournal) discard() { _ = os.Remove(s.temp) }

// stageRedactedJournal writes the journal records read from in to the temporary file, the redacted
// entries substituted, and syncs it. It touches no group state, so it needs no lock: in is the
// journal (or a prefix of it, read through a handle opened while g.mu was held) as its caller
// captured it, and the caller decides, under g.mu, whether that is still the journal.
func (g *Group) stageRedactedJournal(in io.Reader, targets map[model.ID]*redactTarget) (*stagedJournal, error) {
	temp := filepath.Join(g.dir, journalRedactTemp)
	if err := os.Remove(temp); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	out, err := os.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*stagedJournal, error) { out.Close(); return nil, err }
	if err = g.trip(HookRedactWrite); err != nil {
		return fail(err)
	}
	rewritten := 0
	for {
		var header [16]byte
		if _, err = io.ReadFull(in, header[:]); err == io.EOF {
			break
		} else if err != nil {
			return fail(err)
		}
		if string(header[:4]) != "SPR1" || binary.BigEndian.Uint32(header[12:]) != crc32.Checksum(header[:12], readyCRC) {
			return fail(ErrInvalid)
		}
		length := binary.BigEndian.Uint32(header[4:8])
		if length == 0 || length > maxReadyBytes {
			return fail(ErrInvalid)
		}
		raw := make([]byte, length)
		if _, err = io.ReadFull(in, raw); err != nil {
			return fail(err)
		}
		if crc32.Checksum(raw, readyCRC) != binary.BigEndian.Uint32(header[8:12]) {
			return fail(ErrInvalid)
		}
		var record readyRecord
		if model.StrictJSON(raw, &record) != nil {
			return fail(ErrInvalid)
		}
		changed := false
		for i, rawEntry := range record.Entries {
			ent := &pb.Entry{}
			if proto.Unmarshal(rawEntry, ent) != nil {
				return fail(ErrInvalid)
			}
			replaced, rerr := redactedEntry(ent, targets)
			if rerr != nil {
				return fail(rerr)
			}
			if replaced == nil {
				continue
			}
			if record.Entries[i], rerr = proto.Marshal(replaced); rerr != nil {
				return fail(rerr)
			}
			changed = true
			rewritten++
		}
		if !changed {
			if err = writeFull(out, header[:]); err == nil {
				err = writeFull(out, raw)
			}
		} else {
			var encoded []byte
			if encoded, err = encodeReady(record); err == nil {
				err = writeFull(out, encoded)
			}
		}
		if err != nil {
			return fail(err)
		}
	}
	if err = g.trip(HookRedactSync); err != nil {
		return fail(err)
	}
	if err = out.Sync(); err != nil {
		return fail(err)
	}
	if err = out.Close(); err != nil {
		return nil, err
	}
	return &stagedJournal{temp: temp, rewritten: rewritten}, nil
}

// installRedactedJournal renames the staged copy over the journal and reopens the journal handle.
// g.mu is held, and the staged copy is of the journal as it is now.
func (g *Group) installRedactedJournal(staged *stagedJournal) (int, error) {
	w := g.disk
	path := filepath.Join(g.dir, "ready.wal")
	if err := g.trip(HookRedactSwitch); err != nil {
		return 0, err
	}
	if err := os.Rename(staged.temp, path); err != nil {
		return 0, err
	}
	// From here the file on disk is the new journal while the open handle (and the retained
	// in-memory log) still describe the old one: a failure leaves the group torn.
	if err := g.trip(HookRedactRenamed); err != nil {
		return 0, &tornError{err}
	}
	if err := durablefs.SyncDir(g.dir); err != nil {
		return 0, &tornError{err}
	}
	if err := w.file.Close(); err != nil {
		return 0, &tornError{err}
	}
	reopened, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return 0, &tornError{err}
	}
	if _, err = reopened.Seek(0, io.SeekEnd); err != nil {
		reopened.Close()
		return 0, &tornError{err}
	}
	w.file = reopened
	return staged.rewritten, nil
}

// tornError marks a failure after the journal was replaced: the group's durable log, its open
// handle and its in-memory log may disagree, so the group must stop serving until a restart
// rebuilds it. A failure before that point never started writing the journal.
type tornError struct{ error }

func (e *tornError) Unwrap() error { return e.error }

// redactPinsLocked rewrites every pin archive that holds a command to redact. An archive is
// replaced by temp file, fsync and atomic rename; one that holds nothing to redact is not
// touched.
func (g *Group) redactPinsLocked(targets map[model.ID]*redactTarget) (int, error) {
	if len(g.pins) == 0 {
		return 0, nil
	}
	if err := g.trip(HookRedactPins); err != nil {
		return 0, err
	}
	ids := make([]model.ID, 0, len(g.pins))
	for id := range g.pins {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	total := 0
	for _, id := range ids {
		n, err := redactPinArchive(g.pins[id].path, targets)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// redactPinArchive rewrites one pin archive at once: stagePinArchive, then install.
func redactPinArchive(path string, targets map[model.ID]*redactTarget) (int, error) {
	staged, err := stagePinArchive(path, -1, targets)
	if err != nil || staged == nil {
		return 0, err
	}
	return staged.rewritten, staged.install()
}

// stagedPin is a redacted copy of one pin archive, complete and synced in its temporary file, not
// yet in place.
type stagedPin struct {
	path, temp string
	rewritten  int
}

// install renames the staged copy over the archive.
func (s *stagedPin) install() error {
	if err := durablefs.Rename(s.temp, s.path); err != nil {
		os.Remove(s.temp)
		return err
	}
	return durablefs.SyncDir(filepath.Dir(s.path))
}

// discard removes the staged copy; the archive is untouched. A copy it cannot remove is overwritten
// by the next redaction and removed by the next Open.
func (s *stagedPin) discard() { _ = os.Remove(s.temp) }

// stagePinArchive streams the first limit bytes of the archive (a negative limit: all of it)
// record by record into a temp file, so memory is one record, not the archive twice. It touches
// no group state and renames nothing. An archive that holds nothing to redact has its temp file
// removed and yields no staged copy and no error; otherwise the temp file is fsynced.
func stagePinArchive(path string, limit int64, targets map[model.ID]*redactTarget) (*stagedPin, error) {
	src, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer src.Close()
	if limit < 0 {
		info, err := src.Stat()
		if err != nil {
			return nil, err
		}
		limit = info.Size()
	}
	temp := path + ".tmp"
	dst, err := os.OpenFile(temp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			dst.Close()
			os.Remove(temp)
		}
	}()
	in, out := bufio.NewReaderSize(io.LimitReader(src, limit), 1<<20), bufio.NewWriterSize(dst, 1<<20)
	remaining := uint64(limit)
	rewritten := 0
	var h [8]byte
	var buf []byte
	for remaining >= 8 {
		if _, err = io.ReadFull(in, h[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(h[:4])
		if uint64(n) > remaining-8 {
			break // torn tail of an interrupted append: the journal still holds those entries
		}
		if cap(buf) < int(n) {
			buf = make([]byte, n)
		}
		record := buf[:n]
		if _, err = io.ReadFull(in, record); err != nil {
			return nil, err
		}
		remaining -= 8 + uint64(n)
		if crc32.Checksum(record, readyCRC) != binary.BigEndian.Uint32(h[4:]) {
			break // torn tail of an interrupted append: the journal still holds those entries
		}
		var r pinRecord
		if model.StrictJSON(record, &r) != nil {
			return nil, ErrCorrupt
		}
		if r.Entry != nil {
			ent := &pb.Entry{}
			if proto.Unmarshal(r.Entry, ent) != nil {
				return nil, ErrCorrupt
			}
			replaced, rerr := redactedEntry(ent, targets)
			if rerr != nil {
				return nil, rerr
			}
			if replaced != nil {
				if r.Entry, rerr = proto.Marshal(replaced); rerr != nil {
					return nil, rerr
				}
				if record, rerr = json.Marshal(r); rerr != nil {
					return nil, rerr
				}
				rewritten++
			}
		}
		binary.BigEndian.PutUint32(h[:4], uint32(len(record)))
		binary.BigEndian.PutUint32(h[4:], crc32.Checksum(record, readyCRC))
		if _, err = out.Write(h[:]); err != nil {
			return nil, err
		}
		if _, err = out.Write(record); err != nil {
			return nil, err
		}
	}
	if rewritten == 0 {
		return nil, nil
	}
	err = out.Flush()
	if err == nil {
		err = dst.Sync()
	}
	if ce := dst.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return nil, err
	}
	committed = true
	return &stagedPin{path: path, temp: temp, rewritten: rewritten}, nil
}

// readPinPrefix reads the first limit bytes of a pin archive (a negative limit: all of it).
func readPinPrefix(path string, limit int64) ([]byte, error) {
	if limit < 0 {
		return os.ReadFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// Residue reports where copies of a payload redacted at or before floor (a physical index at
// which the machine had applied the original) can still be: "raft_journal" while the journal
// still begins at, or retains entries at or before, floor; "raft_snapshots" while any snapshot
// directory, selected or not, was cut at or before floor. Both are sealed at their cut and are
// replaced only by a snapshot cut at a later index followed by SnapshotStore.DropSuperseded and
// CompactJournal. It reads state only.
func (g *Group) Residue(floor uint64) ([]string, error) {
	if floor == 0 {
		return nil, nil
	}
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return nil, ErrUnavailable
	}
	first, _ := g.memory.FirstIndex()
	snapshot, err := g.memory.Snapshot()
	g.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var out []string
	headAt := snapshot.GetMetadata().GetIndex()
	if first <= floor || headAt != 0 && headAt <= floor {
		out = append(out, ResidueJournal)
	}
	cuts, err := g.snaps.cutIndexes()
	if err != nil {
		return nil, err
	}
	for _, cut := range cuts {
		if cut <= floor {
			out = append(out, ResidueSnapshots)
			break
		}
	}
	return out, nil
}

// cutIndexes returns the physical cut of every snapshot directory, selected or not.
func (s *SnapshotStore) cutIndexes() ([]uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirs, err := s.snapDirs()
	if err != nil {
		return nil, err
	}
	out := make([]uint64, 0, len(dirs))
	for _, d := range dirs {
		// snap-<20 digit index>-<checksum prefix>
		parts := strings.SplitN(d, "-", 3)
		if len(parts) != 3 {
			return nil, ErrCorrupt
		}
		index, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return nil, ErrCorrupt
		}
		out = append(out, index)
	}
	return out, nil
}

// DropSuperseded removes every snapshot directory that sorts before the selected one and reports
// how many it removed. The store keeps the selected snapshot and the newest previous one as a
// fallback if the selected one is damaged; after a redaction or an erasure the previous one is a
// copy of the state from before it. Directories that sort after the selection (a cut still being
// published) are never touched. The trade-off is explicit: until the next cut there is no
// previous snapshot to fall back on. Without a selected snapshot nothing is dropped.
func (s *SnapshotStore) DropSuperseded() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.loadCurrent(false)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	keep := dirName(current.Manifest)
	dirs, err := s.snapDirs()
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, d := range dirs {
		if d >= keep {
			continue
		}
		if err = os.RemoveAll(filepath.Join(s.root, d)); err != nil {
			return removed, err
		}
		removed++
	}
	if removed > 0 {
		err = durablefs.SyncDir(s.root)
	}
	return removed, err
}
