// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
)

var readyCRC = crc32.MakeTable(crc32.Castagnoli)

const maxReadyBytes = 256 << 20

type readyRecord struct {
	Group    model.ID `json:"group"`
	Node     uint64   `json:"node,string"`
	Members  Members  `json:"members"`
	Hard     []byte   `json:"hard,omitempty"`
	Snapshot []byte   `json:"snapshot,omitempty"`
	Entries  [][]byte `json:"entries,omitempty"`
}
type readyWAL struct {
	file       *os.File
	group      model.ID
	node       uint64
	members    Members
	beforeSync func() error
	fault      func(string) error
}

func openReadyWAL(dir string, group model.ID, node uint64, members Members, seed []byte, application, seedIndex, seedTerm uint64, fault func(string) error, installed *installedSeed) (*readyWAL, *raft.MemoryStorage, error) {
	if err := durablefs.MkdirAll(dir); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, "ready.wal")
	_, statErr := os.Stat(path)
	fresh := os.IsNotExist(statErr)
	if statErr != nil && !fresh {
		return nil, nil, statErr
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, nil, err
	}
	fail := func(e error) (*readyWAL, *raft.MemoryStorage, error) { f.Close(); return nil, nil, e }
	if fresh {
		if err = durablefs.SyncFileAndDir(path); err != nil {
			return fail(err)
		}
	}
	w := &readyWAL{file: f, group: group, node: node, members: cloneMembers(members), fault: fault}
	memory := raft.NewMemoryStorage()
	offset := int64(0)
	records := 0
	for {
		var header [16]byte
		n, e := io.ReadFull(f, header[:])
		if e == io.EOF && n == 0 {
			break
		}
		if e == io.ErrUnexpectedEOF {
			if e = w.truncate(offset); e != nil {
				return fail(e)
			}
			break
		}
		if e != nil {
			return fail(e)
		}
		if string(header[:4]) != "SPR1" || binary.BigEndian.Uint32(header[12:]) != crc32.Checksum(header[:12], readyCRC) {
			return fail(ErrInvalid)
		}
		length := binary.BigEndian.Uint32(header[4:8])
		if length == 0 || length > maxReadyBytes {
			return fail(ErrInvalid)
		}
		raw := make([]byte, length)
		if _, e = io.ReadFull(f, raw); e == io.EOF || e == io.ErrUnexpectedEOF {
			if e = w.truncate(offset); e != nil {
				return fail(e)
			}
			break
		} else if e != nil {
			return fail(e)
		}
		if crc32.Checksum(raw, readyCRC) != binary.BigEndian.Uint32(header[8:12]) {
			return fail(ErrInvalid)
		}
		var r readyRecord
		if model.StrictJSON(raw, &r) != nil || r.Group != group || r.Node != node || ValidateMembers(r.Members) != nil {
			return fail(ErrInvalid)
		}
		w.members = cloneMembers(r.Members)
		if e = installRecord(memory, r); e != nil {
			return fail(e)
		}
		records++
		offset += int64(16 + length)
	}
	if !fresh && records == 0 {
		return fail(ErrInvalid)
	}
	if fresh {
		conf := &pb.ConfState{}
		for _, m := range members.Nodes {
			if m.Learner {
				conf.Learners = append(conf.Learners, m.ID)
			} else {
				conf.Voters = append(conf.Voters, m.ID)
			}
		}
		snap := &pb.Snapshot{Metadata: &pb.SnapshotMetadata{ConfState: conf}}
		rd := raft.Ready{Snapshot: snap}
		if installed != nil {
			if installed.conf != nil {
				snap.Metadata.ConfState = installed.conf
			}
			snap.Data = installed.data
			snap.Metadata.Index = new(installed.index)
			snap.Metadata.Term = new(installed.term)
			rd.HardState = &pb.HardState{Term: new(installed.term), Commit: new(installed.index)}
		} else if seed != nil {
			if seedIndex == 0 {
				seedIndex = 1
			}
			if seedTerm == 0 {
				seedTerm = 1
			}
			data, e := json.Marshal(snapshotEnvelope{Application: application, State: seed, Members: cloneMembers(members)})
			if e != nil {
				return fail(e)
			}
			snap.Data = data
			snap.Metadata.Index = new(seedIndex)
			snap.Metadata.Term = new(seedTerm)
			rd.HardState = &pb.HardState{Term: new(seedTerm), Commit: new(seedIndex)}
		}
		if err = w.persist(rd); err != nil {
			return fail(err)
		}
		if err = memory.ApplySnapshot(snap); err != nil {
			return fail(err)
		}
		if rd.HardState != nil {
			if err = memory.SetHardState(rd.HardState); err != nil {
				return fail(err)
			}
		}
	}
	if _, err = f.Seek(0, io.SeekEnd); err != nil {
		return fail(err)
	}
	return w, memory, nil
}
func (w *readyWAL) truncate(offset int64) error {
	if err := w.file.Truncate(offset); err != nil {
		return err
	}
	return w.file.Sync()
}
func (w *readyWAL) Close() error { return w.file.Close() }
func (w *readyWAL) persist(rd raft.Ready) error {
	r := readyRecord{Group: w.group, Node: w.node, Members: cloneMembers(w.members)}
	var err error
	if rd.HardState != nil {
		r.Hard, err = proto.Marshal(rd.HardState)
		if err != nil {
			return err
		}
	}
	if rd.Snapshot != nil {
		r.Snapshot, err = proto.Marshal(rd.Snapshot)
		if err != nil {
			return err
		}
	}
	for _, ent := range rd.Entries {
		raw, e := proto.Marshal(ent)
		if e != nil {
			return e
		}
		r.Entries = append(r.Entries, raw)
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > maxReadyBytes {
		return ErrInvalid
	}
	var header [16]byte
	copy(header[:4], "SPR1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(raw)))
	binary.BigEndian.PutUint32(header[8:12], crc32.Checksum(raw, readyCRC))
	binary.BigEndian.PutUint32(header[12:], crc32.Checksum(header[:12], readyCRC))
	if w.fault != nil {
		if err = w.fault("wal_write"); err != nil {
			return err
		}
	}
	if err = writeFull(w.file, header[:]); err != nil {
		return err
	}
	if w.fault != nil {
		if err = w.fault("wal_payload_write"); err != nil {
			return err
		}
	}
	if err = writeFull(w.file, raw); err != nil {
		return err
	}
	if w.beforeSync != nil {
		if err = w.beforeSync(); err != nil {
			return err
		}
	}
	if w.fault != nil {
		if err = w.fault("wal_sync"); err != nil {
			return err
		}
	}
	return w.file.Sync()
}
func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func installRecord(memory *raft.MemoryStorage, r readyRecord) error {
	if len(r.Snapshot) > 0 {
		snap := &pb.Snapshot{}
		if proto.Unmarshal(r.Snapshot, snap) != nil {
			return ErrInvalid
		}
		if err := memory.ApplySnapshot(snap); err != nil && err != raft.ErrSnapOutOfDate {
			return err
		}
	}
	entries := make([]*pb.Entry, 0, len(r.Entries))
	for _, raw := range r.Entries {
		ent := &pb.Entry{}
		if proto.Unmarshal(raw, ent) != nil {
			return ErrInvalid
		}
		entries = append(entries, ent)
	}
	if len(entries) > 0 {
		last, _ := memory.LastIndex()
		if entries[0].GetIndex() > last+1 {
			return ErrInvalid
		}
		if err := memory.Append(entries); err != nil {
			return err
		}
	}
	if len(r.Hard) > 0 {
		hard := &pb.HardState{}
		if proto.Unmarshal(r.Hard, hard) != nil {
			return ErrInvalid
		}
		last, _ := memory.LastIndex()
		if hard.GetCommit() > last {
			return ErrInvalid
		}
		if err := memory.SetHardState(hard); err != nil {
			return err
		}
	}
	return nil
}

// processReady is the only RawNode.Ready consumer. All changed persistent state,
// including commit-only HardState and snapshots, is fsynced before messages or
// Advance. A message-only Ready relies on that already-durable prefix.
func (g *Group) processReady() error {
	for g.raw.HasReady() {
		rd := g.raw.Ready()
		priorLast, _ := g.memory.LastIndex()
		if len(rd.Entries) > 0 || rd.HardState != nil || rd.Snapshot != nil {
			if err := g.disk.persist(rd); err != nil {
				g.fail()
				return ErrUnavailable
			}
		}
		snapshotChanged := !raft.IsEmptySnap(rd.Snapshot)
		if snapshotChanged {
			if err := g.memory.ApplySnapshot(rd.Snapshot); err != nil {
				g.fail()
				return err
			}
			if err := g.restoreSnapshot(rd.Snapshot); err != nil {
				g.fail()
				return err
			}
		}
		if err := g.memory.Append(rd.Entries); err != nil {
			g.fail()
			return err
		}
		if !raft.IsEmptyHardState(rd.HardState) {
			if err := g.memory.SetHardState(rd.HardState); err != nil {
				g.fail()
				return err
			}
		}
		if snapshotChanged || len(rd.Entries) > 0 && rd.Entries[0].GetIndex() <= priorLast {
			if err := g.rebuildKnown(); err != nil {
				g.fail()
				return err
			}
		} else {
			for _, entry := range rd.Entries {
				if err := g.remember(entry, 0); err != nil {
					g.fail()
					return err
				}
			}
		}
		for _, m := range rd.Messages {
			if err := g.transport.Send(g.group, cloneMessage(m)); err != nil {
				g.raw.ReportUnreachable(m.GetTo())
				if m.GetType() == pb.MsgSnap {
					g.raw.ReportSnapshot(m.GetTo(), raft.SnapshotFailure)
				}
			}
		}
		for _, ent := range rd.CommittedEntries {
			if err := g.applyCommitted(ent); err != nil {
				g.fail()
				return err
			}
		}
		for _, r := range rd.ReadStates {
			if req := g.reads[string(r.RequestCtx)]; req != nil {
				req.index = r.Index
			}
		}
		g.completeReads()
		g.raw.Advance(rd)
		g.notify()
	}
	return nil
}
func (g *Group) rebuildKnown() error {
	g.known = map[model.ID]map[uint64]struct{}{}
	g.logCommands = map[model.ID]CommittedEntry{}
	g.logApplication = g.application
	for id, c := range g.completed {
		if !g.digestKind(c.Entry.Kind) { // kept by digest: nothing to index, the retry table answers
			g.logCommands[id] = c
		}
		if c.Entry.ReservationID != nil && c.Entry.Kind != Cancellation && c.Outcome != "conflict" {
			reservation := *c.Entry.ReservationID
			if g.known[reservation] == nil {
				g.known[reservation] = map[uint64]struct{}{}
			}
			g.known[reservation][c.Index] = struct{}{}
		}
	}
	first, _ := g.memory.FirstIndex()
	last, _ := g.memory.LastIndex()
	if last < first {
		return nil
	}
	entries, err := g.memory.Entries(first, last+1, ^uint64(0))
	if err != nil {
		return err
	}
	for _, ent := range entries {
		if err = g.remember(ent, 0); err != nil {
			return err
		}
	}
	return nil
}
func (g *Group) applyCommitted(ent *pb.Entry) error {
	if ent.GetIndex() <= g.applied {
		return nil
	}
	c := CommittedEntry{Group: g.group, Term: ent.GetTerm(), Index: ent.GetIndex(), ApplicationCursor: model.Cursor{Group: g.group, Index: model.Uint64(g.application)}, Entry: Entry{Kind: Noop}}
	switch ent.GetType() {
	case pb.EntryNormal:
		if len(ent.GetData()) > 0 {
			entry, err := g.decodeEntry(ent.GetData())
			if err != nil {
				return err
			}
			c.Entry = entry
			c.ApplicationCursor.Index = model.Uint64(c.Entry.ApplicationIndex)
		}
	case pb.EntryConfChange:
		change := &pb.ConfChange{}
		if proto.Unmarshal(ent.GetData(), change) != nil {
			return ErrInvalid
		}
		g.conf = g.raw.ApplyConfChange(change)
	case pb.EntryConfChangeV2:
		change := &pb.ConfChangeV2{}
		if proto.Unmarshal(ent.GetData(), change) != nil {
			return ErrInvalid
		}
		g.conf = g.raw.ApplyConfChange(change)
		if len(change.GetContext()) > 0 {
			var next Members
			if model.StrictJSON(change.GetContext(), &next) != nil || ValidateMembers(next) != nil {
				return ErrInvalid
			}
			g.retiring = append([]Member(nil), g.members.Nodes...)
			g.members = next
			g.disk.members = cloneMembers(next)
		}
		if len(g.conf.GetVotersOutgoing()) == 0 {
			g.retiring = nil
		}
	default:
		return ErrInvalid
	}
	result := g.machine.Apply(c)
	if result != nil && result != ErrConflict {
		return result
	}
	if result == ErrConflict && c.Entry.ReservationID != nil {
		delete(g.known[*c.Entry.ReservationID], c.Index)
		if len(g.known[*c.Entry.ReservationID]) == 0 {
			delete(g.known, *c.Entry.ReservationID)
		}
	}
	if result == ErrConflict {
		c.Outcome = "conflict"
		if c.Entry.Kind == Control {
			g.machineRules = 0 // a stale command still carries the state it was built from
			g.proofWithdrawn()
		}
	}
	g.applied = ent.GetIndex()
	g.application = uint64(c.ApplicationCursor.Index)
	if c.Entry.Kind != Noop {
		if old, ok := g.completed[c.Entry.ID]; ok {
			c = old
		} else {
			g.completed[c.Entry.ID] = g.retained(c)
		}
		for _, ch := range g.pending[c.Entry.ID] {
			ch <- proposalResult{entry: c, err: result}
		}
		delete(g.pending, c.Entry.ID)
		if g.digestKind(c.Entry.Kind) {
			// Applied: the retry table answers every later retry, and the log index only
			// matters for a command that is in the log and not yet applied.
			delete(g.logCommands, c.Entry.ID)
		}
	}
	return nil
}

// digestKind reports whether the machine asked for the retry table to keep commands of kind k by
// digest (DigestRetryMachine).
func (g *Group) digestKind(k Kind) bool {
	return g.retryDigest != nil && k != Noop && g.retryDigest(k)
}

// retained is c as the retry table keeps it: for a kind kept by digest the payload is dropped and
// Entry.Original carries the digest of the payload the command was proposed with, so a retry is
// still recognized by sameProposal and a different payload under the ID is still a conflict. The
// receipt (group, term, index, application cursor, outcome) is untouched.
func (g *Group) retained(c CommittedEntry) CommittedEntry {
	if !g.digestKind(c.Entry.Kind) {
		return c
	}
	original := c.Entry.proposed()
	c.Entry.Payload = nil
	c.Entry.Original = &original
	return c
}
func (g *Group) completeReads() {
	status := g.raw.BasicStatus()
	for id, r := range g.reads {
		if status.HardState.GetTerm() != r.term {
			r.done <- proposalResult{err: ErrStale}
			delete(g.reads, id)
		} else if r.index > 0 && g.applied >= r.index {
			r.done <- proposalResult{entry: CommittedEntry{Group: g.group, Term: r.term, Index: g.applied, ApplicationCursor: model.Cursor{Group: g.group, Index: model.Uint64(g.application)}}}
			delete(g.reads, id)
		}
	}
}

type snapshotEnvelope struct {
	Application uint64           `json:"application,string"`
	State       []byte           `json:"state"`
	Completed   []CommittedEntry `json:"completed"`
	Members     Members          `json:"members"`
	Retiring    []Member         `json:"retiring,omitempty"`
}

func (g *Group) restoreSnapshot(snap *pb.Snapshot) error {
	var envelope snapshotEnvelope
	if model.StrictJSON(snap.GetData(), &envelope) != nil || ValidateMembers(envelope.Members) != nil {
		return ErrInvalid
	}
	g.machineRules = 0 // the leader's retry table as it was cut: not covered by any local pass
	index := snap.GetMetadata().GetIndex()
	if verifier, ok := g.machine.(interface{ VerifySnapshot([]byte) error }); ok {
		if err := verifier.VerifySnapshot(envelope.State); err != nil {
			return err
		}
	}
	if g.machine.Applied() < index {
		if err := g.machine.Restore(envelope.State, index); err != nil {
			return err
		}
	}
	g.applied = index
	g.application = envelope.Application
	g.members = cloneMembers(envelope.Members)
	g.retiring = append([]Member(nil), envelope.Retiring...)
	g.conf = snap.GetMetadata().GetConfState()
	for _, c := range envelope.Completed {
		if c.Group != g.group || c.Index > index {
			return ErrInvalid
		}
		g.completed[c.Entry.ID] = g.retained(c)
	}
	g.proofWithdrawn()
	return nil
}

// Snapshot never truncates the durable journal. It transfers every authoritative
// byte supplied by Machine, together with receipts, membership and cursor cuts.
func (g *Group) Snapshot() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed || g.applied == 0 {
		return ErrUnavailable
	}
	state, err := g.machine.Snapshot()
	if err != nil {
		return err
	}
	e := snapshotEnvelope{Application: g.application, State: state, Members: cloneMembers(g.members), Retiring: append([]Member(nil), g.retiring...)}
	for _, c := range g.completed {
		e.Completed = append(e.Completed, c)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	snap, err := g.memory.CreateSnapshot(g.applied, g.conf, raw)
	if err != nil {
		return err
	}
	if err = g.disk.persist(raft.Ready{Snapshot: snap}); err != nil {
		g.fail()
		return err
	}
	return nil
}
