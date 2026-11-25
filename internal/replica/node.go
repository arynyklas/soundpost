// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replica

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	raft "go.etcd.io/raft/v3"
	pb "go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

var (
	ErrUnavailable = errors.New("replica unavailable")
	ErrConflict    = errors.New("replica conflict")
	ErrInvalid     = errors.New("invalid replica command")
	ErrStale       = errors.New("replica freshness fence not reached")
	// ErrJournalBehind: the journal holds less than this node acknowledged (its persisted commit
	// or applied index is beyond the end of the journal, or a leader committed beyond it). The
	// member must be removed and re-added; it never rejoins as a voter under this identity.
	ErrJournalBehind = errors.New("replica journal is behind what this node acknowledged")
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
	// Proposer is the member that proposed the command, recorded by the group that ordered it and
	// never taken from the caller: a command proposed on the leader names the leader, a command a
	// follower forwarded names the member whose transport credential authenticated the hop, and
	// whatever either claimed in the entry itself is discarded. A state machine that attributes a
	// command to a node (a statement a voter makes about its own store) checks it against this
	// field. A command committed before the field existed has none.
	Proposer *Proposer `json:"proposer,omitempty"`
	// At is the time (Unix nanoseconds) the leader stamped into a command kept by digest
	// (DigestRetryMachine) when it ordered it; it is the clock of the retry window and never
	// taken from the caller. Zero on other commands and on commands committed before the field.
	At int64 `json:"at,omitempty,string"`
}

// Proposer names the member that proposed an Entry: its node ID and its node identity, both as the
// committed configuration lists them.
type Proposer struct {
	Node     uint64 `json:"node,string"`
	Identity string `json:"node_identity"`
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
//
// The identity is the exact payload bytes (or their SHA-256), so it depends on the wire form a
// caller chose for a command that has more than one (the storage artifact fragment: JSON text or
// binary envelope). A caller that retries a command under the same ID resends the payload it
// first proposed, verbatim; re-encoding it in the other form is an ErrConflict. The storage
// engine mints a fresh ID per proposal and never re-proposes, so its switch between forms
// (Engine.EnableFragmentEnvelope) cannot produce one (docs/operations/upgrade.md, "Fragment envelope").
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
	if p := e.Proposer; p != nil && (p.Node == 0 || p.Identity == "") {
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

// SnapshotGate is optionally implemented by a Machine whose installed state can invalidate a
// statement every other member relies on (the storage engine's erasure acknowledgements: a snapshot
// that replays pre-erasure commands puts erased rows back). It orders that fact before the install:
//
//   - BeforeSnapshotSend runs on the sender, outside every group lock, before a snapshot message
//     for member `to` leaves. What it commits through the replicated log is therefore ordered
//     before the receiver can possibly apply the snapshot. Its token travels in the message's
//     Context. An error withholds the message: the delivery is reported as failed and Raft sends
//     the snapshot again.
//   - AdmitSnapshot runs on the receiver, under the group lock, before the message is stepped. An
//     error refuses the message (the sender sees a failed delivery). release is called once Step
//     returned, whatever its outcome.
//
// A message whose Context does not start with the gate's advertisement (its sender does not
// implement the gate) is refused by a receiver that does; a gated sender always advertises, with an
// empty token when its gate declined to state anything yet (snapshot_gate.go).
type SnapshotGate interface {
	BeforeSnapshotSend(ctx context.Context, to uint64) ([]byte, error)
	AdmitSnapshot(token []byte) (release func(), err error)
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
	// SeedFunc supplies Seed when, and only when, a fresh journal is created from the machine's own
	// state: opening an existing journal must not pay for a snapshot of the whole history it ignores.
	SeedFunc    func() ([]byte, error)
	Application uint64
	SeedIndex   uint64
	SeedTerm    uint64
	Validate    func(context.Context, Entry) error
	Fault       func(string) error
	// PinTTL is the lease of a journal pin (default DefaultPinTTL); Now is the clock it is judged
	// by (default time.Now).
	PinTTL time.Duration
	Now    func() time.Time
	// RetryWindow and RetryMax bound the retry table of a DigestRetryMachine (defaults
	// DefaultRetryWindow, DefaultRetryMax); Cadence cuts and compacts on its own (default: never).
	RetryWindow time.Duration
	RetryMax    int
	Cadence     Cadence
	// Domain is the node's FailDomain, shared by every group of the node: a storage failure of
	// any of them fails them all closed. Nil: the group fails alone.
	Domain *FailDomain
	// RebaseInstalled makes a fresh journal that starts from an installed snapshot take its Raft
	// configuration and membership from Members instead of the snapshot's: a disaster restore
	// installs snapshots cut in another cluster (other voters, other identities). Never set for
	// a repair or a join, which keep the leader's configuration.
	RebaseInstalled bool
	// SnapshotGuard runs on the SENDER of a snapshot message, outside every group lock, before the
	// message for member `to` leaves; an error withholds it (the delivery is reported as failed and
	// Raft sends the snapshot again). It is the machine-independent half of SnapshotGate: nothing is
	// ordered through the log and nothing is added to the message, so a receiver that predates it is
	// unaffected. The control machine uses it to withhold a snapshot of a state whose layout `to`
	// cannot read (D70). A node the group does not list is never sent a snapshot.
	SnapshotGuard func(ctx context.Context, to Member) error
	// LeaderSpread makes the leader of the group hand leadership to the group's preferred member (balance.go) when that
	// member is healthy; LeaderSeed picks it among the voters (the storage engine passes the slot, so the 64 groups are
	// shared out evenly). Off: leadership stays wherever elections put it.
	LeaderSpread bool
	LeaderSeed   uint64
}
type proposalResult struct {
	entry CommittedEntry
	err   error
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
	// ioMu is the ready stage (proposals.go): a cycle of persist, send, apply and Advance holds it, and so does every
	// piece of work that must not run beside one. Taken before mu, never while holding it.
	ioMu sync.Mutex
	// The queue of proposals, filled by the proposers and emptied by the cycle that proposes them. propMu is taken last.
	propMu     sync.Mutex
	propQ      []*proposal
	propClosed bool
	// wake and stageDone belong to the stage goroutine of a group that ticks by itself (Config.TickInterval > 0); a group
	// its owner ticks has neither and is driven by its callers.
	wake      chan struct{}
	stageDone chan struct{}
	// busy is true while a cycle runs (Tick uses it: heartbeatNowLocked).
	busy atomic.Bool

	mu      sync.Mutex
	decoded struct {
		data  []byte
		entry Entry
	}
	// replay holds, for every entry of the log that is not applied yet, the command that was decoded when the entry was
	// remembered (persisted), so the apply of each does not validate and decode the same bytes again.
	replay map[uint64]replayedEntry
	// fresh holds the commands this member proposed in the cycle in flight, by the first byte of their encoding (the
	// slice Raft holds as the entry's data), so remembering them does not decode what was just encoded. Owned by the cycle.
	fresh          map[*byte]Entry
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
	reads          map[string]*readRequest // the ReadIndex round in flight (reads.go): at most one
	readNext       *readRequest            // the round callers join; put to the leader when the one in flight is answered
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
	snapWanted     bool         // the next cycle is to cut sendSnap (membershipSnapshotLocked found a cycle applying)
	cutMu          sync.Mutex   // one CreateSnapshot at a time: the incremental cut reuses the selected snapshot's files
	redactMu       sync.Mutex   // one journal redaction at a time (RedactMachineCommands builds its rewrite before it takes g.mu); taken before g.mu, never while holding it
	// machineRules and machineFloor are the proof RedactMachineCommands leaves: the rule set
	// the last completed pass covered (0: no proof) and the physical index it finished at.
	// Durable (machine_proof.go); a snapshot install and a stale committed command withdraw it.
	machineRules uint64
	machineFloor uint64
	owner        model.ID // this instance of the group: stamps the pins it creates
	pinTTL       time.Duration
	// leaderWait bounds how long a follower that does not know the leader waits for it (propose).
	leaderWait time.Duration
	now        func() time.Time
	// retryDigest is Machine.RetryByDigest when the machine implements DigestRetryMachine.
	retryDigest func(Kind) bool
	// gate is Machine.SnapshotGate when the machine implements it; gateCtx bounds the sender-side
	// goroutines gateWG tracks.
	gate       SnapshotGate
	gateCtx    context.Context
	gateCancel context.CancelFunc
	gateWG     sync.WaitGroup
	// guard is Config.SnapshotGuard; it shares gateCtx and gateWG with the gate.
	guard       func(context.Context, Member) error
	cadenceWG   sync.WaitGroup // the cadence loop; Close waits so no cut writes after the group closed
	retryWindow time.Duration
	retryMax    int
	retryOrder  []model.ID
	// retryParts are the retry-part files the selected snapshot holds (retry_parts.go), and retryEpoch counts
	// the events that made that belief void; both under mu.
	retryParts []retryPart
	retryEpoch uint64
	// cadence state: applied commands and entry bytes since the last cut.
	cadence       Cadence
	sinceCommands uint64
	sinceBytes    int64
	cutBytes      int64  // bytes the last cadence cut wrote itself (cutDue scales the bounds by it)
	appliedData   uint64 // entry data bytes countApplied has seen (AppliedDataBytes)
	cadenceWake   chan struct{}
	cadenceCuts   atomic.Uint64 // cuts the cadence loop completed
	cadenceLong   atomic.Int64  // nanoseconds the longest of them took
	// tail is the run of entries below the in-memory log that a cadence cut retained for a member that is behind
	// (tail.go); raft reads it through snapshotSource, everything else in the group sees the log as compacted.
	tail logTail
	// spread and seed place the group's leader on its preferred member (balance.go); bal is the group's own record of it.
	spread bool
	seed   uint64
	bal    balanceState
	// phases are the cumulative times the group spent in the stages of its pipeline (phases.go).
	phases phaseCounters
	domain *FailDomain
	// soloRead is the cursor a read of this group answers while the group is a single voter that
	// leads: such a leader has nobody to confirm its leadership with, and every command it
	// acknowledged is applied, so a read needs neither g.mu nor a Raft round. nil in every other
	// case; refreshSoloRead keeps it current at the end of every cycle.
	soloRead atomic.Pointer[model.Cursor]
	// afterAck is a test seam: called by applyEntry (g.mu held) once it has answered the waiters of
	// a command, so a test can hold the group exactly there and read from another goroutine. Nil in
	// production.
	afterAck func()
	// membersView is the committed configuration, published whenever g.members changes, for the readers
	// that must not wait for g.mu (CommittedMembers).
	membersView atomic.Pointer[Members]
	// transportView is the membership the transport addresses (members and those being retired), published with membersView,
	// so that a batch of heartbeats can prove its sender without the group lock.
	transportView atomic.Pointer[Members]
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
	if user, ok := c.Machine.(SnapshotStoreUser); ok {
		user.UseSnapshotStore(snaps) // before any restoreSnapshot: a compact state is resolved from this store
	}
	var installed *installedSeed
	if _, statErr := os.Stat(filepath.Join(c.Directory, "ready.wal")); os.IsNotExist(statErr) {
		// A fresh journal starts from an installed, fully verified snapshot when
		// one was selected; a directory that does not verify refuses to open.
		if installed, err = loadInstalledSeed(snaps); err != nil {
			return nil, err
		}
		if installed != nil && c.RebaseInstalled {
			if err = installed.rebase(c.Members); err != nil {
				return nil, err
			}
		}
	}
	seed := c.Seed
	if seed == nil && installed == nil && c.SeedFunc != nil {
		if _, statErr := os.Stat(filepath.Join(c.Directory, "ready.wal")); os.IsNotExist(statErr) {
			if seed, err = c.SeedFunc(); err != nil {
				return nil, err
			}
		}
	}
	disk, memory, err := openReadyWAL(c.Directory, c.Group, c.ID, c.Members, seed, c.Application, c.SeedIndex, c.SeedTerm, c.Fault, installed)
	if err != nil {
		return nil, err
	}
	g := &Group{dir: c.Directory, fault: c.Fault, snaps: snaps, id: c.ID, group: c.Group, disk: disk, memory: memory, machine: c.Machine, transport: c.Transport, members: disk.members, completed: map[model.ID]CommittedEntry{}, known: map[model.ID]map[uint64]struct{}{}, pending: map[model.ID][]chan proposalResult{}, reads: map[string]*readRequest{}, changed: make(chan struct{}), stop: make(chan struct{}), owner: model.NewID(), pinTTL: c.PinTTL, now: c.Now, leaderWait: leaderWaitFor(c.TickInterval)}
	if g.pinTTL <= 0 {
		g.pinTTL = DefaultPinTTL
	}
	g.publishMembers()
	if c.TickInterval > 0 {
		g.wake, g.stageDone = make(chan struct{}, 1), make(chan struct{})
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
	if gate, ok := c.Machine.(SnapshotGate); ok {
		g.gate = gate
		g.gateCtx, g.gateCancel = context.WithCancel(context.Background())
	}
	if c.SnapshotGuard != nil {
		g.guard = c.SnapshotGuard
		if g.gateCancel == nil {
			g.gateCtx, g.gateCancel = context.WithCancel(context.Background())
		}
	}
	g.retryWindow, g.retryMax = c.RetryWindow, c.RetryMax
	if g.retryWindow <= 0 {
		g.retryWindow = DefaultRetryWindow
	}
	if g.retryMax <= 0 {
		g.retryMax = DefaultRetryMax
	}
	g.cadence, g.cadenceWake = c.Cadence, make(chan struct{}, 1)
	g.spread, g.seed = c.LeaderSpread, c.LeaderSeed
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
	last, _ := memory.LastIndex()
	if c.Machine.Applied() > hard.GetCommit() || hard.GetCommit() > last {
		disk.Close()
		return nil, ErrJournalBehind
	}
	// Rebuild command identity and known reservations from the entire durable log,
	// including committed-but-unapplied and uncommitted entries before intake.
	g.replay = map[uint64]replayedEntry{}
	if err = g.rebuildKnown(); err != nil {
		disk.Close()
		return nil, err
	}
	g.loadProof(last)
	g.raw, err = raft.NewRawNode(&raft.Config{ID: c.ID, ElectionTick: electionTicks, HeartbeatTick: 1, Storage: snapshotSource{MemoryStorage: memory, g: g}, Applied: g.applied, MaxSizePerMsg: maxAppBytes, MaxCommittedSizePerReady: maxCommittedPerReady, MaxUncommittedEntriesSize: 64 << 20, MaxInflightMsgs: 32, MaxInflightBytes: maxInflightBytes, CheckQuorum: true, PreVote: true, ReadOnlyOption: raft.ReadOnlySafe, DisableProposalForwarding: true})
	if err != nil {
		disk.Close()
		return nil, err
	}
	if err = g.drive(); err != nil {
		disk.Close()
		return nil, err
	}
	if c.Domain != nil {
		if err = c.Domain.add(g); err != nil {
			disk.Close()
			return nil, err
		}
		g.domain = c.Domain
	}
	if c.TickInterval > 0 {
		go g.stageLoop()
		go g.run(c.TickInterval)
	}
	if g.cadence.Enabled() {
		g.cadenceWG.Add(1)
		go func() {
			defer g.cadenceWG.Done()
			g.cadenceLoop()
		}()
	}
	return g, nil
}

// run ticks the group. The tick takes mu for the Raft clock and nothing else: no journal write, apply or proposal
// runs under it, so it is on time while the stage works (Phases: TickLagMax).
func (g *Group) run(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case due := <-t.C:
			g.tick(due)
		case <-g.stop:
			return
		}
	}
}
func (g *Group) Close() error {
	g.closeOnce.Do(func() { close(g.stop) })
	if g.gateCancel != nil {
		g.gateCancel()
	}
	// A cut in progress writes snapshot files and compacts the journal; it must finish (or fail against
	// the stopped group) before the disk closes, or it writes after Close returned.
	g.cadenceWG.Wait()
	err := g.closeLocked()
	if g.stageDone != nil {
		<-g.stageDone // the stage runs no cycle once the group is closed
	}
	g.gateWG.Wait() // the senders report through g.mu, which closeLocked has released
	return err
}
func (g *Group) closeLocked() error {
	g.lockAll() // a cycle in flight finishes before the journal closes
	defer g.unlockAll()
	if g.closed {
		return nil
	}
	g.closed = true
	g.fail()
	return g.disk.Close()
}
func (g *Group) fail() {
	g.failed = true
	g.soloRead.Store(nil)
	for id, waiters := range g.pending {
		for _, ch := range waiters {
			ch <- proposalResult{err: ErrUnavailable}
		}
		delete(g.pending, id)
	}
	g.closeProposals()
	g.failReadsLocked(ErrUnavailable)
	g.notify()
}
func (g *Group) notify() { close(g.changed); g.changed = make(chan struct{}) }
func (g *Group) Tick() {
	g.tick(time.Time{})
}

// tick is Tick for the ticker goroutine, which passes the time the tick was due: how late Raft's clock runs is what
// decides whether a follower campaigns against a healthy leader.
func (g *Group) tick(due time.Time) {
	g.mu.Lock()
	if !due.IsZero() {
		if lag := int64(time.Since(due)); lag > g.phases.tickLagMax.Load() {
			g.phases.tickLagMax.Store(lag)
		}
	}
	if g.failed || g.closed {
		g.mu.Unlock()
		return
	}
	g.raw.Tick()
	g.expireReadsLocked()
	g.balanceLocked()
	if g.busy.Load() {
		g.heartbeatNowLocked()
	}
	g.wakeLocked()
	g.mu.Unlock()
	_ = g.settle() // a failure has failed the group
}
func (g *Group) Campaign() error {
	g.mu.Lock()
	if g.failed || g.closed {
		g.mu.Unlock()
		return ErrUnavailable
	}
	if err := g.raw.Campaign(); err != nil {
		g.mu.Unlock()
		return err
	}
	g.wakeLocked()
	g.mu.Unlock()
	return g.settle()
}
func (g *Group) Step(ctx context.Context, m *pb.Message) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	g.mu.Lock()
	err := g.stepLocked(m)
	g.mu.Unlock()
	if err != nil {
		return err
	}
	return g.settle()
}

// stepLocked is Step with g.mu held.
func (g *Group) stepLocked(m *pb.Message) (err error) {
	defer g.recoverBehind(&err)
	if g.failed || g.closed {
		return ErrUnavailable
	}
	if m == nil || m.GetTo() != g.id {
		return ErrInvalid
	}
	if m.GetType() == pb.MsgSnap {
		context, named := retryCapability(m.GetContext())
		if !named && digestBearing(m.GetSnapshot().GetData()) {
			return ErrUnavailable // a retry table kept by digest from a sender that never named the format (10.13-W2)
		}
		if g.gate != nil {
			token, advertised := gateToken(context)
			if !advertised {
				return ErrUnavailable // its sender runs no gate: nothing was ordered before this install
			}
			release, err := g.gate.AdmitSnapshot(token)
			if err != nil {
				return ErrUnavailable
			}
			defer release()
		}
	}
	answer := g.busy.Load() && m.GetType() == pb.MsgHeartbeat && g.heartbeatFromLeaderLocked(m)
	if err := g.raw.Step(m); err != nil {
		return err
	}
	if answer {
		g.answerHeartbeatNow(m)
	}
	g.wakeLocked()
	return nil
}
func (g *Group) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	s := g.raw.BasicStatus()
	last, _ := g.memory.LastIndex()
	return Status{Group: g.group, ID: g.id, Leader: s.Lead, Term: s.HardState.GetTerm(), Commit: s.HardState.GetCommit(), Applied: g.applied, LastIndex: last, ApplicationCursor: model.Cursor{Group: g.group, Index: model.Uint64(g.application)}, Revision: g.members.Revision, Failed: g.failed || g.closed, Members: cloneMembers(g.members)}
}

// publishMembers makes the configuration g.members holds the one CommittedMembers answers. g.mu is held (or
// the group is not shared yet).
func (g *Group) publishMembers() {
	m := cloneMembers(g.members)
	g.membersView.Store(&m)
	t := g.transportMembersLocked()
	g.transportView.Store(&t)
}

// CommittedMembers is the committed configuration of the group as of the last change this voter applied. It
// takes no lock: Status waits for g.mu, which is held across the journal fsync and the state machine's commit
// of the command in flight, and a gate that asks which members a group has before every command of another
// group (the protocol gates of control and storage) waited for that commit each time. The members are shared:
// the caller must not change them.
func (g *Group) CommittedMembers() Members { return *g.membersView.Load() }
func (g *Group) Propose(ctx context.Context, e Entry) (CommittedEntry, error) {
	return g.propose(ctx, e, nil)
}

// proposerLocked is the Proposer of member id as the group's configuration lists it, including a
// member that is retiring; nil when the group does not know the member. g.mu is held.
func (g *Group) proposerLocked(id uint64) *Proposer {
	for _, m := range g.members.Nodes {
		if m.ID == id {
			return &Proposer{Node: m.ID, Identity: m.NodeIdentity}
		}
	}
	for _, m := range g.retiring {
		if m.ID == id {
			return &Proposer{Node: m.ID, Identity: m.NodeIdentity}
		}
	}
	return nil
}

// proposalForwarder is the optional Transport capability that hands a follower's proposal to the
// leader (MTLS.ForwardPropose).
type proposalForwarder interface {
	ForwardPropose(context.Context, model.ID, Entry) (CommittedEntry, error)
}

// electionTicks is the raft ElectionTick of every group; a follower's randomized election timeout
// is between electionTicks and twice that many ticks.
const electionTicks = 10

// maxCommittedPerReady is raft's MaxCommittedSizePerReady: the committed entry bytes one Ready (so one cycle of the ready
// stage) applies, at least one entry. The messages Tick and Step produce, heartbeats first, leave with the next Ready, so
// what one cycle applies bounds how long a heartbeat waits for the stage: a full append (maxAppBytes) is applied in
// ~130 ms, a Ready of the 32 MiB this was before in seconds, against an election timeout of electionTicks ticks.
const maxCommittedPerReady = maxAppBytes

// leaderWaitFor is how long a follower that does not know the leader waits for one before it
// refuses a proposal: two election timeouts' worth of ticks, the longest a leaderless window of a
// healthy group lasts. A group that is ticked by its owner (tick 0) assumes the 20 ms tick of the
// tests and the product.
func leaderWaitFor(tick time.Duration) time.Duration {
	if tick <= 0 {
		tick = 20 * time.Millisecond
	}
	return 2 * electionTicks * tick
}

// propose orders e. from is the member whose transport credential authenticated a proposal a
// follower forwarded to this leader, nil for a proposal made on this node; either way the entry's
// own Proposer is replaced, so a caller or a forwarder cannot attribute a command to anyone else.
// Received internal requests are leader-only: a term race never adds a hop.
func (g *Group) propose(ctx context.Context, e Entry, from *Proposer) (CommittedEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	e.Proposer = from
	if !e.valid() {
		return CommittedEntry{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return CommittedEntry{}, ctx.Err()
	}
	_, forwards := g.transport.(proposalForwarder)
	var wait <-chan time.Time
	var leader uint64
	for done := false; !done; {
		g.mu.Lock()
		if g.failed || g.closed {
			g.mu.Unlock()
			return CommittedEntry{}, ErrUnavailable
		}
		leader = g.raw.BasicStatus().Lead
		if leader == g.id && from == nil {
			e.Proposer = g.proposerLocked(g.id)
		}
		changed := g.changed
		g.mu.Unlock()
		if leader != 0 || from != nil || !forwards {
			break
		}
		// This member does not know the leader yet: an election has just finished and the new
		// leader's first message has not reached it. ReadIndex waits for the same fact; a
		// proposal that failed here would be refused although the group is healthy. The wait is
		// one election round and no more, so a member cut off from every leader still answers
		// unavailable promptly.
		if wait == nil {
			timer := time.NewTimer(g.leaderWait)
			defer timer.Stop()
			wait = timer.C
		}
		select {
		case <-changed:
		case <-wait:
			done = true
		case <-ctx.Done():
			return CommittedEntry{}, ctx.Err()
		}
	}
	if leader != g.id {
		if forward, ok := g.transport.(proposalForwarder); ok && from == nil {
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
	// The checks that need the leader's view of the log and the tables, and the Raft proposal itself, are made by the
	// cycle that takes the command from the queue (proposeOneLocked), together with every command that queued meanwhile.
	req := &proposal{ctx: ctx, entry: e, done: make(chan proposalResult, 1)}
	if !g.enqueue(req) {
		return CommittedEntry{}, ErrUnavailable
	}
	if err := g.kick(); err != nil {
		return CommittedEntry{}, err
	}
	return g.awaitProposal(ctx, e.ID, req)
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

// refreshSoloRead publishes the cursor of a read served without g.mu when this group is a single
// voter that leads and has applied everything committed (g.mu held). Once published, the cursor stays while the
// group leads alone: what commits after that is the leader's own proposals, answered only once applied
// (advanceSoloRead), so a read at the cursor misses nothing acknowledged.
func (g *Group) refreshSoloRead() {
	if g.failed || g.closed || g.conf == nil {
		g.soloRead.Store(nil)
		return
	}
	s := g.raw.BasicStatus()
	voters := g.conf.GetVoters()
	if s.RaftState != raft.StateLeader || s.Lead != g.id || len(voters) != 1 || voters[0] != g.id || len(g.conf.GetVotersOutgoing()) != 0 || len(g.conf.GetLearnersNext()) != 0 {
		g.soloRead.Store(nil)
		return
	}
	if s.HardState.GetCommit() > g.applied {
		return // published or not: the commands being applied now are decided by advanceSoloRead, never by this
	}
	if old := g.soloRead.Load(); old != nil && old.Index == model.Uint64(g.application) {
		return
	}
	cursor := model.Cursor{Group: g.group, Index: model.Uint64(g.application)}
	g.soloRead.Store(&cursor)
}

// advanceSoloRead moves the cursor of the lock-free reads of a lone voter up to the command applyEntry
// has just applied (g.mu held). The waiters of a command are answered right after this, and a waiter
// that is not the goroutine running the cycle (a retried proposal, a proposal that joined an in-flight one)
// would be handed a receipt while the reads still answered the cut before the command. A group that does not
// serve lock-free reads (soloRead is nil: not a lone leader, a configuration change, or entries committed
// but not yet applied since the group opened) is left to refreshSoloRead, which decides that.
func (g *Group) advanceSoloRead() {
	if old := g.soloRead.Load(); old == nil || old.Index == model.Uint64(g.application) {
		return
	}
	cursor := model.Cursor{Group: g.group, Index: model.Uint64(g.application)}
	g.soloRead.Store(&cursor)
}
func (g *Group) ReadIndex(ctx context.Context) (model.Cursor, error) {
	if cursor := g.soloRead.Load(); cursor != nil {
		if ctx.Err() != nil {
			return model.Cursor{}, ErrStale // a caller that gave up gets what the waiting path gives it
		}
		return *cursor, nil
	}
	return g.readThroughRound(ctx)
}

// readThroughRound is ReadIndex's waiting path: the caller joins the group's next ReadIndex round (reads.go) and is
// answered by it, from whatever lead the group has.
func (g *Group) readThroughRound(ctx context.Context) (model.Cursor, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	began := time.Now()
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
		request := g.joinReadLocked()
		g.wakeLocked()
		g.mu.Unlock()
		if err := g.settle(); err != nil {
			return model.Cursor{}, err
		}
		select {
		case <-request.done:
			if request.result.err == ErrStale {
				g.phases.readGaveUp.Add(1)
				continue
			}
			if request.result.err != nil {
				return model.Cursor{}, request.result.err
			}
			sinceMax(&g.phases.readNS, &g.phases.readMaxNS, began)
			g.phases.readN.Add(1)
			return request.result.entry.ApplicationCursor, nil
		case <-ctx.Done():
			return model.Cursor{}, ErrStale // the round is shared and stays: other callers wait on it
		}
	}
}

// ReadIndexAtLeast is ReadIndex for a caller that holds a receipt: the cut it returns is at least min, the
// cursor a command was acknowledged at. A group that has not applied min yet is waited for, within one
// bounded wait (5 seconds, or ctx); a group that does not reach it in that time answers ErrStale, an
// explicit freshness error, never a cut below min.
func (g *Group) ReadIndexAtLeast(ctx context.Context, min model.Cursor) (model.Cursor, error) {
	if min.Group != g.group {
		return model.Cursor{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if cut := g.soloRead.Load(); cut != nil && cut.Index >= min.Index && ctx.Err() == nil {
		return *cut, nil
	}
	// g.mu is held across the journal fsync and the state machine's Apply, and neither the waiting path of
	// ReadIndex nor WaitApplied can stop waiting for it when ctx ends: the bound is kept here.
	type answer struct {
		cut model.Cursor
		err error
	}
	done := make(chan answer, 1)
	go func() {
		cut, err := g.readIndexAtLeast(ctx, min)
		done <- answer{cut, err}
	}()
	select {
	case a := <-done:
		return a.cut, a.err
	case <-ctx.Done():
		return model.Cursor{}, ErrStale
	}
}
func (g *Group) readIndexAtLeast(ctx context.Context, min model.Cursor) (model.Cursor, error) {
	return g.cutAtLeast(ctx, min, g.ReadIndex)
}

// cutAtLeast takes a cut with read and holds it to min: a cut below min (a ReadIndex round that was shared with
// callers that began before min was acknowledged, or one of a member behind) is never returned, the group is waited
// for to apply min and the cut taken again by a round that is put after the wait.
func (g *Group) cutAtLeast(ctx context.Context, min model.Cursor, read func(context.Context) (model.Cursor, error)) (model.Cursor, error) {
	cut, err := read(ctx)
	if err != nil || cut.Index >= min.Index {
		return cut, err
	}
	if err = g.WaitApplied(ctx, min); err != nil {
		return model.Cursor{}, err
	}
	// The fence is taken again after the wait: the cut of a read that began before the group applied min
	// proves nothing about leadership now.
	if cut, err = read(ctx); err != nil {
		return model.Cursor{}, err
	}
	if cut.Index < min.Index {
		return model.Cursor{}, ErrStale
	}
	return cut, nil
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

// decodeEntry decodes and validates a replicated command. An entry is decoded when it is
// remembered (persisted) and again when it is applied; the payload can be several hundred KiB, so
// the last decoded entry is kept and reused for the very same Raft data slice (identity, and Raft
// never mutates entry data). The cache holds the slice, so the address cannot be recycled.
func (g *Group) decodeEntry(data []byte) (Entry, error) {
	if len(data) > 0 && len(data) == len(g.decoded.data) && &data[0] == &g.decoded.data[0] {
		return g.decoded.entry, nil
	}
	if len(data) > 0 {
		if fresh, ok := g.fresh[&data[0]]; ok {
			return fresh, nil // proposed by this member in this cycle: the command is known, not to be read back from its bytes
		}
	}
	e, err := decodeEntry(data)
	if err != nil || !e.valid() {
		return Entry{}, ErrInvalid
	}
	g.decoded.data, g.decoded.entry = data, e
	return e, nil
}

// replayedEntry is an entry rebuildKnown decoded, with the Raft data slice it was decoded from.
type replayedEntry struct {
	data  []byte
	entry Entry
}

// appliedEntry is the command of an entry about to be applied: the one rebuildKnown decoded when this
// is the replay of the journal at Open (the same Raft data slice, so the same bytes), otherwise a
// decode of the data.
func (g *Group) appliedEntry(ent *pb.Entry) (Entry, error) {
	if r, ok := g.replay[ent.GetIndex()]; ok {
		delete(g.replay, ent.GetIndex())
		if data := ent.GetData(); len(data) > 0 && len(data) == len(r.data) && &data[0] == &r.data[0] {
			return r.entry, nil
		}
	}
	return g.decodeEntry(ent.GetData())
}
func (g *Group) remember(ent *pb.Entry, _ uint64) error {
	if ent.GetType() != pb.EntryNormal || len(ent.GetData()) == 0 {
		return nil
	}
	e, err := g.decodeEntry(ent.GetData())
	if err != nil {
		return err
	}
	g.noteEntry(ent, e)
	return nil
}

// noteEntry records the command e of entry ent in the tables of the commands in the log. It does no decoding: the cycle
// decodes the entries of a Ready before it takes mu (a batch of hundreds of entries of tens of KiB is the longest thing
// the group would otherwise do under it).
func (g *Group) noteEntry(ent *pb.Entry, e Entry) {
	if ent.GetIndex() > g.applied {
		g.replay[ent.GetIndex()] = replayedEntry{data: ent.GetData(), entry: e}
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
		return
	}
	if e.ReservationID != nil && e.Kind != Cancellation {
		if g.known[*e.ReservationID] == nil {
			g.known[*e.ReservationID] = map[uint64]struct{}{}
		}
		g.known[*e.ReservationID][ent.GetIndex()] = struct{}{}
	}
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
func (g *Group) awaitProposal(ctx context.Context, id model.ID, req *proposal) (CommittedEntry, error) {
	select {
	case result := <-req.done:
		return result.entry, result.err
	case <-ctx.Done():
		req.gone.Store(true)
		g.mu.Lock()
		g.removeWaiter(id, req.done)
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
