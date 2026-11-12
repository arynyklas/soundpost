// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
	"soundpost/internal/model"
)

var (
	ErrUnavailable = errors.New("replica unavailable")
	ErrConflict    = errors.New("replica conflict")
	ErrInvalid     = errors.New("invalid replica command")
	ErrStale       = errors.New("replica freshness fence not reached")
)

type Kind string

const (
	Noop         Kind = "noop"
	Data         Kind = "data"
	Control      Kind = "control"
	Cancellation Kind = "cancellation"
	Barrier      Kind = "barrier"
	Artifact     Kind = "artifact"
	ArtifactGC   Kind = "artifact_gc"
)

type Entry struct {
	ID               model.ID            `json:"id"`
	Kind             Kind                `json:"kind"`
	Payload          []byte              `json:"payload"`
	ReservationID    *model.ID           `json:"reservation_id,omitempty"`
	ApplicationIndex uint64              `json:"application_index,string"`
	CommitSet        *CommitSetWatermark `json:"commit_set,omitempty"`
	// Original is set only on a command whose payload was redacted after it was applied
	// (RedactCompleted): the SHA-256 of the payload the command was proposed with. Payload then
	// holds the machine's replacement, and a retry of the original command is recognized by this
	// digest instead of by the bytes that no longer exist in this group.
	Original *model.Hash `json:"original,omitempty"`
}

// proposed is the digest of the payload this command was proposed with.
func (e Entry) proposed() model.Hash {
	if e.Original != nil {
		return *e.Original
	}
	return model.HashCanonical(e.Payload)
}

// sameProposal reports whether e is a retry of old: the same kind and the same proposed
// payload, whether or not either side has since been redacted.
func sameProposal(old, e Entry) bool {
	if old.Kind != e.Kind {
		return false
	}
	if old.Original == nil && e.Original == nil {
		return equalPayload(old.Payload, e.Payload)
	}
	return old.proposed() == e.proposed()
}

// ID is an application command identity retained across leader relocation.
type CommittedEntry struct {
	Group             model.ID     `json:"group"`
	Term              uint64       `json:"term,string"`
	Index             uint64       `json:"index,string"`
	ApplicationCursor model.Cursor `json:"application_cursor"`
	Entry             Entry        `json:"entry"`
	Outcome           string       `json:"outcome,omitempty"`
}

func (e Entry) valid() bool {
	if e.ID == (model.ID{}) || len(e.Payload) == 0 || len(e.Payload) > 16<<20 {
		return false
	}
	switch e.Kind {
	case Data, Control, Cancellation, Barrier, Artifact, ArtifactGC:
		return true
	}
	return false
}

type Machine interface {
	Applied() uint64
	Apply(CommittedEntry) error
	Snapshot() ([]byte, error)
	Restore([]byte, uint64) error
}

// DigestRetryMachine is optionally implemented by a Machine whose commands of some kinds each
// carry the machine's whole state (the control machine: a command is the next state plus the
// revision it expects). For a kind it names, the retry table keeps, for every applied command,
// the receipt (term, index, application cursor, outcome) and the SHA-256 of the payload the
// command was proposed with (Entry.Original, the representation a redacted command has), and no
// payload bytes: a retry of a committed command is still answered with its original receipt, a
// different payload under the same ID is still a conflict, and the retry table, the log index and
// every snapshot envelope that serializes it stop growing with the payload bytes of every command
// ever committed. What the retry table keeps per command is a fixed-size record; how long a
// client may retry (and so how many records are kept) is not decided here: records are never
// dropped.
type DigestRetryMachine interface {
	RetryByDigest(Kind) bool
}
type Transport interface {
	Send(model.ID, *pb.Message) error
}
type Config struct {
	ID           uint64
	Group        model.ID
	Directory    string
	Members      Members
	Machine      Machine
	Transport    Transport
	TickInterval time.Duration
	Seed         []byte
	Application  uint64
	SeedIndex    uint64
	SeedTerm     uint64
	Validate     func(context.Context, Entry) error
	Fault        func(string) error
	// PinTTL is the lease of a journal pin (default DefaultPinTTL); Now is the clock it is judged
	// by (default time.Now).
	PinTTL time.Duration
	Now    func() time.Time
}
type proposalResult struct {
	entry CommittedEntry
	err   error
}
type readRequest struct {
	index uint64
	term  uint64
	done  chan proposalResult
}
type Status struct {
	Group                                        model.ID
	ID, Leader, Term, Commit, Applied, LastIndex uint64
	ApplicationCursor                            model.Cursor
	Revision                                     model.Revision
	Failed                                       bool
	Members                                      Members
}
type Group struct {
	mu             sync.Mutex
	id             uint64
	group          model.ID
	raw            *raft.RawNode
	memory         *raft.MemoryStorage
	disk           *readyWAL
	machine        Machine
	transport      Transport
	members        Members
	retiring       []Member
	validate       func(context.Context, Entry) error
	conf           *pb.ConfState
	applied        uint64
	application    uint64
	logApplication uint64
	logCommands    map[model.ID]CommittedEntry
	completed      map[model.ID]CommittedEntry
	known          map[model.ID]map[uint64]struct{}
	pending        map[model.ID][]chan proposalResult
	reads          map[string]*readRequest
	changed        chan struct{}
	failed         bool
	closed         bool
	stop           chan struct{}
	closeOnce      sync.Once
	dir            string
	fault          func(string) error
	snaps          *SnapshotStore
	pins           map[model.ID]*JournalPin
	sendSnap       *pb.Snapshot // snapshot for members added after the stored one; never persisted
	// machineRules and machineFloor are the proof RedactMachineCommands leaves (memory only):
	// the rule set the last completed pass covered (0: no proof) and the physical index it
	// finished at. A snapshot install and a stale committed command withdraw it.
	machineRules uint64
	machineFloor uint64
	owner        model.ID // this instance of the group: stamps the pins it creates
	pinTTL       time.Duration
	now          func() time.Time
	// retryDigest is Machine.RetryByDigest when the machine implements DigestRetryMachine.
	retryDigest func(Kind) bool
}

func Open(c Config) (*Group, error) {
	if c.ID == 0 || c.Group == (model.ID{}) || c.Machine == nil || c.Transport == nil || c.Directory == "" {
		return nil, ErrInvalid
	}
	if err := ValidateMembers(c.Members); err != nil {
		return nil, err
	}
	found := false
	for _, m := range c.Members.Nodes {
		if m.ID == c.ID {
			found = true
		}
	}
	if !found {
		return nil, ErrInvalid
	}
	if c.Machine.Applied() != 0 {
		info, err := os.Stat(filepath.Join(c.Directory, "ready.wal"))
		if err != nil || !info.Mode().IsRegular() {
			return nil, ErrInvalid
		}
	}
	if err := os.Remove(filepath.Join(c.Directory, journalCompactTemp)); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.Remove(filepath.Join(c.Directory, journalRedactTemp)); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	snaps, err := OpenSnapshotStore(c.Directory, c.Group, c.Fault)
	if err != nil {
		return nil, err
	}
	var installed *installedSeed
	if _, statErr := os.Stat(filepath.Join(c.Directory, "ready.wal")); os.IsNotExist(statErr) {
		// A fresh journal starts from an installed, fully verified snapshot when
		// one was selected; a directory that does not verify refuses to open.
		if installed, err = loadInstalledSeed(snaps); err != nil {
			return nil, err
		}
	}
	disk, memory, err := openReadyWAL(c.Directory, c.Group, c.ID, c.Members, c.Seed, c.Application, c.SeedIndex, c.SeedTerm, c.Fault, installed)
	if err != nil {
		return nil, err
	}
	g := &Group{dir: c.Directory, fault: c.Fault, snaps: snaps, id: c.ID, group: c.Group, disk: disk, memory: memory, machine: c.Machine, transport: c.Transport, members: disk.members, completed: map[model.ID]CommittedEntry{}, known: map[model.ID]map[uint64]struct{}{}, pending: map[model.ID][]chan proposalResult{}, reads: map[string]*readRequest{}, changed: make(chan struct{}), stop: make(chan struct{}), owner: model.NewID(), pinTTL: c.PinTTL, now: c.Now}
	if g.pinTTL <= 0 {
		g.pinTTL = DefaultPinTTL
	}
	if g.now == nil {
		g.now = time.Now
	}
	if err = g.loadPins(); err != nil {
		disk.Close()
		return nil, err
	}
	g.validate = c.Validate
	if m, ok := c.Machine.(DigestRetryMachine); ok {
		g.retryDigest = m.RetryByDigest
	}
	g.logCommands = map[model.ID]CommittedEntry{}
	hard, conf, err := memory.InitialState()
	if err != nil {
		disk.Close()
		return nil, err
	}
	g.conf = conf
	snap, err := memory.Snapshot()
	if err != nil {
		disk.Close()
		return nil, err
	}
	if !raft.IsEmptySnap(snap) {
		if err = g.restoreSnapshot(snap); err != nil {
			disk.Close()
			return nil, err
		}
	}
	if c.Machine.Applied() > hard.GetCommit() {
		disk.Close()
		return nil, ErrInvalid
	}
	// Rebuild command identity and known reservations from the entire durable log,
	// including committed-but-unapplied and uncommitted entries before intake.
	if err = g.rebuildKnown(); err != nil {
		disk.Close()
		return nil, err
	}
	g.raw, err = raft.NewRawNode(&raft.Config{ID: c.ID, ElectionTick: 10, HeartbeatTick: 1, Storage: snapshotSource{MemoryStorage: memory, g: g}, Applied: g.applied, MaxSizePerMsg: 20 << 20, MaxCommittedSizePerReady: 32 << 20, MaxUncommittedEntriesSize: 64 << 20, MaxInflightMsgs: 32, CheckQuorum: true, PreVote: true, ReadOnlyOption: raft.ReadOnlySafe, DisableProposalForwarding: true})
	if err != nil {
		disk.Close()
		return nil, err
	}
	if err = g.processReady(); err != nil {
		disk.Close()
		return nil, err
	}
	if c.TickInterval > 0 {
		go g.run(c.TickInterval)
	}
	return g, nil
}
func (g *Group) run(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			g.Tick()
		case <-g.stop:
			return
		}
	}
}
func (g *Group) Close() error {
	g.closeOnce.Do(func() { close(g.stop) })
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	g.fail()
	return g.disk.Close()
}
func (g *Group) fail() {
	g.failed = true
	for id, waiters := range g.pending {
		for _, ch := range waiters {
			ch <- proposalResult{err: ErrUnavailable}
		}
		delete(g.pending, id)
	}
	for id, r := range g.reads {
		r.done <- proposalResult{err: ErrUnavailable}
		delete(g.reads, id)
	}
	g.notify()
}
func (g *Group) notify() { close(g.changed); g.changed = make(chan struct{}) }
func (g *Group) Tick() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return
	}
	g.raw.Tick()
	if g.processReady() != nil {
		g.fail()
	}
}
func (g *Group) Campaign() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return ErrUnavailable
	}
	if err := g.raw.Campaign(); err != nil {
		return err
	}
	return g.processReady()
}
func (g *Group) Step(ctx context.Context, m *pb.Message) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failed || g.closed {
		return ErrUnavailable
	}
	if m == nil || m.GetTo() != g.id {
		return ErrInvalid
	}
	if err := g.raw.Step(m); err != nil {
		return err
	}
	return g.processReady()
}
func (g *Group) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.raw.BasicStatus()
	last, _ := g.memory.LastIndex()
	return Status{Group: g.group, ID: g.id, Leader: s.Lead, Term: s.HardState.GetTerm(), Commit: s.HardState.GetCommit(), Applied: g.applied, LastIndex: last, ApplicationCursor: model.Cursor{Group: g.group, Index: model.Uint64(g.application)}, Revision: g.members.Revision, Failed: g.failed || g.closed, Members: cloneMembers(g.members)}
}
func (g *Group) Propose(ctx context.Context, e Entry) (CommittedEntry, error) {
	return g.propose(ctx, e, true)
}

// Received internal requests are leader-only: a term race never adds a hop.
func (g *Group) propose(ctx context.Context, e Entry, allowForward bool) (CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !e.valid() {
		return CommittedEntry{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return CommittedEntry{}, ctx.Err()
	}
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
	leader := g.raw.BasicStatus().Lead
	g.mu.Unlock()
	if leader != g.id {
		if forward, ok := g.transport.(interface {
			ForwardPropose(context.Context, model.ID, Entry) (CommittedEntry, error)
		}); ok && allowForward {
			committed, err := forward.ForwardPropose(ctx, g.group, e)
			if err != nil {
				return committed, err
			}
			if err = g.waitPhysical(ctx, committed.Index); err != nil {
				return CommittedEntry{}, err
			}
			return committed, nil
		}
		return CommittedEntry{}, ErrUnavailable
	}
	if _, err := g.ReadIndex(ctx); err != nil {
		return CommittedEntry{}, err
	}
	if g.validate != nil {
		if err := g.validate(ctx, e); err != nil {
			return CommittedEntry{}, err
		}
	}
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
	s := g.raw.BasicStatus()
	if s.Lead != g.id || s.RaftState != raft.StateLeader {
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
	if old, ok := g.completed[e.ID]; ok {
		if !sameProposal(old.Entry, e) {
			g.mu.Unlock()
			return CommittedEntry{}, ErrConflict
		}
		g.mu.Unlock()
		if old.Outcome == "conflict" {
			return old, ErrConflict
		}
		return old, nil
	}
	if old, ok := g.logCommands[e.ID]; ok && old.Index > g.applied {
		if !sameProposal(old.Entry, e) {
			g.mu.Unlock()
			return CommittedEntry{}, ErrConflict
		}
		done := make(chan proposalResult, 1)
		g.pending[e.ID] = append(g.pending[e.ID], done)
		g.mu.Unlock()
		return g.awaitProposal(ctx, e.ID, done)
	}
	if e.Kind == Cancellation && e.ReservationID != nil && len(g.known[*e.ReservationID]) != 0 {
		g.mu.Unlock()
		return CommittedEntry{}, ErrConflict
	}
	last, err := g.memory.LastIndex()
	if err != nil || last == ^uint64(0) {
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
	application := g.logApplication
	if application == ^uint64(0) {
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
	if e.ApplicationIndex != 0 && e.ApplicationIndex != application+1 {
		g.mu.Unlock()
		return CommittedEntry{}, ErrStale
	}
	e.ApplicationIndex = application + 1
	if e.Kind == Cancellation {
		if e.ReservationID == nil {
			g.mu.Unlock()
			return CommittedEntry{}, ErrInvalid
		}
		e.CommitSet = &CommitSetWatermark{Group: g.group, Term: s.HardState.GetTerm(), PhysicalCommit: s.HardState.GetCommit(), PhysicalLast: last, ApplicationApplied: g.application, Reservation: *e.ReservationID}
	}
	raw, err := json.Marshal(e)
	if err != nil {
		g.mu.Unlock()
		return CommittedEntry{}, err
	}
	done := make(chan proposalResult, 1)
	g.pending[e.ID] = append(g.pending[e.ID], done)
	if err = g.raw.Propose(raw); err != nil {
		g.removeWaiter(e.ID, done)
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
	err = g.processReady()
	g.mu.Unlock()
	if err != nil {
		return CommittedEntry{}, err
	}
	return g.awaitProposal(ctx, e.ID, done)
}
func equalPayload(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func (g *Group) ReadIndex(ctx context.Context) (model.Cursor, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		if ctx.Err() != nil {
			return model.Cursor{}, ErrStale
		}
		g.mu.Lock()
		if g.failed || g.closed {
			g.mu.Unlock()
			return model.Cursor{}, ErrUnavailable
		}
		if g.raw.BasicStatus().Lead == 0 {
			changed := g.changed
			g.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return model.Cursor{}, ErrStale
			}
		}
		id := model.NewID().String()
		request := &readRequest{term: g.raw.BasicStatus().HardState.GetTerm(), done: make(chan proposalResult, 1)}
		g.reads[id] = request
		g.raw.ReadIndex([]byte(id))
		err := g.processReady()
		if err != nil {
			g.fail()
		}
		g.mu.Unlock()
		if err != nil {
			return model.Cursor{}, err
		}
		select {
		case result := <-request.done:
			if result.err == ErrStale {
				continue
			}
			if result.err != nil {
				return model.Cursor{}, result.err
			}
			return result.entry.ApplicationCursor, nil
		case <-ctx.Done():
			g.mu.Lock()
			delete(g.reads, id)
			g.mu.Unlock()
			return model.Cursor{}, ErrStale
		}
	}
}
func (g *Group) WaitApplied(ctx context.Context, c model.Cursor) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if c.Group != g.group {
		return ErrInvalid
	}
	for {
		g.mu.Lock()
		if g.failed || g.closed {
			g.mu.Unlock()
			return ErrUnavailable
		}
		if g.application >= uint64(c.Index) {
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ErrStale
		}
	}
}
func (g *Group) remember(ent *pb.Entry, _ uint64) error {
	if ent.GetType() != pb.EntryNormal || len(ent.GetData()) == 0 {
		return nil
	}
	var e Entry
	if model.StrictJSON(ent.GetData(), &e) != nil || !e.valid() {
		return ErrInvalid
	}
	if e.ApplicationIndex > g.logApplication {
		g.logApplication = e.ApplicationIndex
	}
	// An entry that is already applied and kept by digest is answered by the retry table; its
	// payload is not copied into the log index (rebuildKnown replays every retained log entry).
	if _, ok := g.logCommands[e.ID]; !ok && !(ent.GetIndex() <= g.applied && g.digestKind(e.Kind)) {
		g.logCommands[e.ID] = CommittedEntry{Group: g.group, Term: ent.GetTerm(), Index: ent.GetIndex(), ApplicationCursor: model.Cursor{Group: g.group, Index: model.Uint64(e.ApplicationIndex)}, Entry: e}
	}
	if old, ok := g.completed[e.ID]; ok && old.Outcome == "conflict" {
		return nil
	}
	if e.ReservationID != nil && e.Kind != Cancellation {
		if g.known[*e.ReservationID] == nil {
			g.known[*e.ReservationID] = map[uint64]struct{}{}
		}
		g.known[*e.ReservationID][ent.GetIndex()] = struct{}{}
	}
	return nil
}
func cloneMessage(m *pb.Message) *pb.Message { return proto.Clone(m).(*pb.Message) }
func (g *Group) removeWaiter(id model.ID, done chan proposalResult) {
	waiters := g.pending[id]
	for i, ch := range waiters {
		if ch == done {
			waiters = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(waiters) == 0 {
		delete(g.pending, id)
	} else {
		g.pending[id] = waiters
	}
}
func (g *Group) awaitProposal(ctx context.Context, id model.ID, done chan proposalResult) (CommittedEntry, error) {
	select {
	case result := <-done:
		return result.entry, result.err
	case <-ctx.Done():
		g.mu.Lock()
		g.removeWaiter(id, done)
		g.mu.Unlock()
		return CommittedEntry{}, ErrUnavailable
	}
}
func (g *Group) waitPhysical(ctx context.Context, index uint64) error {
	for {
		g.mu.Lock()
		if g.failed || g.closed {
			g.mu.Unlock()
			return ErrUnavailable
		}
		if g.applied >= index {
			g.mu.Unlock()
			return nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ErrStale
		}
	}
}
