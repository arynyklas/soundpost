// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

type replicatedControl struct {
	store *Store
	group *replica.Group
	local *replica.Loopback
	// withdraw, ctx, cancel and done belong to withdrawLoop (attest.go): the group signals on
	// withdraw when it drops its redaction proof; close cancels ctx and waits for done.
	withdraw chan struct{}
	// installAt is the highest snapshot index this process installed; settled is true once
	// this process reconciled its own attestation record (attest.go).
	installAt atomic.Uint64
	settled   atomic.Bool
	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
}
type controlReplacement struct {
	Expected model.Revision     `json:"expected"`
	State    model.ControlState `json:"state"`
	Keys     map[string][]byte  `json:"keys"`
}
type controlSnapshot struct {
	State    model.ControlState `json:"state"`
	Keys     map[string][]byte  `json:"keys"`
	Metadata map[string][]byte  `json:"metadata"`
}

func replicaFault(err error) error {
	if err == nil {
		return nil
	}
	var fault *model.Fault
	if errors.As(err, &fault) {
		return err
	}
	if errors.Is(err, replica.ErrConflict) {
		return model.Fail(model.Conflict)
	}
	if errors.Is(err, replica.ErrStale) {
		// A fence that was waited for and not reached (no quorum, no leader in time) is retryable as it is; the
		// refusal of a command that names an old revision is not, and keeps the plain fault.
		f := model.Fail(model.Stale)
		f.Retryable = errors.Is(err, replica.ErrNoQuorum)
		return f
	}
	if errors.Is(err, replica.ErrInvalid) {
		return model.Fail(model.Invalid)
	}
	// A moment without a leader is the retryable unavailable; a group that failed closed or was closed is not.
	f := model.Fail(model.Unavailable)
	f.Retryable = errors.Is(err, replica.ErrNoLeader)
	return f
}

// EnableReplication installs the same Store.Update/View path, not a second
// control service. A multi-voter caller supplies the identical authenticated seed
// to every new node; independently bootstrapped authorities are never merged.
func (s *Store) EnableReplication(c replica.Config) (*replica.Group, error) {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	if s.repl != nil {
		return nil, model.Fail(model.Conflict)
	}
	m := &replicatedControl{store: s, withdraw: make(chan struct{}, 1)}
	if err := s.initializeConsensusNamespace(c.Directory); err != nil {
		return nil, err
	}
	c.Machine = m
	c.Validate = m.Validate
	c.SnapshotGuard = m.guardSnapshot
	if !c.Cadence.Enabled() {
		c.Cadence = DefaultJournalCadence
	}
	if c.Seed == nil {
		if len(c.Members.Nodes) != 1 {
			return nil, model.Fail(model.Invalid)
		}
		// The state is snapshotted into a seed only when a fresh journal is created from it (SeedFunc): a
		// journal that exists ignores it, and at the size of a busy installation building the seed and
		// decoding it to read the revision was most of what a restart did before the groups opened. The
		// revision the journal starts at is read from the keys of the file that hold it.
		_, revision, err := s.head()
		if err != nil {
			return nil, err
		}
		c.SeedFunc = m.Snapshot
		c.Application = uint64(revision)
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.done = make(chan struct{})
	group, err := replica.Open(c)
	if err != nil {
		m.cancel()
		return nil, err
	}
	m.group = group
	s.repl = m
	go m.withdrawLoop()
	s.registerDiag(group, c.Directory)
	return group, nil
}
func (s *Store) ReplicationSeed() ([]byte, uint64, error) {
	m := &replicatedControl{store: s}
	raw, err := m.Snapshot()
	if err != nil {
		return nil, 0, err
	}
	var snapshot controlSnapshot
	if model.StrictJSON(raw, &snapshot) != nil {
		return nil, 0, model.Fail(model.Corrupt)
	}
	return raw, uint64(snapshot.State.Revision), nil
}

// maxLostProposals bounds how often one writer that asked for it (retryLostProposals) reads, computes
// and proposes again after its proposal lost the application-index race to another writer.
const maxLostProposals = 64

type lostProposalRetryKey struct{}

// retryLostProposals marks ctx so replicatedUpdate runs a write again, on a fresh read of the state,
// when its proposal was refused because another command committed first (replica.ErrStale from the
// proposal itself, never from the read fence). Only a writer whose update function re-judges the
// state it is given asks for it: the function runs again against the new state, so the retry cannot
// apply a stale decision. Without it every proposal of a voter that does not lead (the proposal is
// forwarded) loses most races under saturating intake on every voter.
func retryLostProposals(ctx context.Context) context.Context {
	return context.WithValue(ctx, lostProposalRetryKey{}, true)
}

// unnamedError is what replicatedUpdateOnce answers when a transition that did not name some of the
// ledger's members (the admission books, the job and issue books) changed them anyway: replicatedUpdate
// then runs it again with them assembled, as every transition did before they had records of their own.
type unnamedError struct{ need memberScope }

func (e *unnamedError) Error() string {
	return "control: a writer that did not name the ledger changed it"
}

// replicatedUpdate runs fn as one control transition. members says which of the ledger's members fn
// reads or writes: the admission books (Reservations, AdmissionKeys, Quotas, Settlement) and the job and
// issue books (JobBooks, IssueBooks). They are assembled into the state fn is given and what fn leaves is
// written back record by record. A transition that does not name them gets the state without them, which
// is what keeps a command that has nothing to do with admission from reading the books of every batch
// ever admitted, and one that has nothing to do with the workers from reading their books. One that
// changes them anyway (a handler registered by a caller that does not know the layout) is run again on the
// state with them: fn re-judges the state it is given, as it does when a proposal is lost
// (retryLostProposals), so the second run is as good as the first and the cost of naming the ledger is
// paid only by the transition that needs it.
func (s *Store) replicatedUpdate(ctx context.Context, bump bool, force *bool, members memberScope, fn func(*State) error) error {
	attempts := 1
	if ctx.Value(lostProposalRetryKey{}) != nil {
		attempts = maxLostProposals
	}
	for attempt := 1; ; attempt++ {
		var lost bool
		err := s.replicatedUpdateOnce(ctx, bump, force, members, fn, &lost)
		var unnamed *unnamedError
		if errors.As(err, &unnamed) && members|unnamed.need != members {
			members |= unnamed.need
			attempt--
			continue
		}
		if !lost || attempt >= attempts || ctx.Err() != nil {
			return err
		}
	}
}

// replicatedUpdateOnce is one read-compute-propose round; lost reports that the proposal was refused
// as stale (another command committed since the read).
func (s *Store) replicatedUpdateOnce(ctx context.Context, bump bool, force *bool, members memberScope, fn func(*State) error, lost *bool) error {
	defer s.lockUpdates()()
	r := s.repl
	if _, err := r.group.ReadIndex(ctx); err != nil {
		return replicaFaultUnder(ctx, err)
	}
	var st State
	var oldRaw []byte // the encoding of the state read, kept only when the command is a patch
	var layout bool   // the file keeps its books in the ledger (ledgerLayout)
	var oldLedger, heldLedger ledgerMembers
	// window is the command whose records the log was reduced to when the transition read it ("": the whole log).
	var window string
	var layoutBaseOf string // the digest ledgerBase names for the state read (layout 2)
	// A command is a patch once every member declared the first protocol of it (SetLegacyStatePatchGate)
	// when the books are in the blob, as the previous release holds them and the patch names the digest it
	// computes. When they are in the ledger, the digest and the ledger commands need the protocol of that
	// layout (SetStatePatchGate): a contracted installation has no previous release among its members.
	// Otherwise the command is the whole-state replacement every release applies.
	ledgerPatch := s.StatePatch()
	patch := ledgerPatch || s.legacyStatePatch()
	if err := s.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		if err := readState(ctrl, &st); err != nil {
			return err
		}
		if layout = ledgerLayout(ctrl); layout {
			patch = ledgerPatch
			if members&scopeBooks == 0 && ctx.Value(lateErasureBooksKey{}) != nil && hasFinishedDeletion(&st) {
				members |= scopeBooks
			}
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			layoutBaseOf = layoutBase(ctrl, l.acc)
			if members != 0 {
				if patch {
					window = commandKeyOf(ctx) // a replacement carries the whole state, the whole log with it
				}
				m, err := l.membersOfKeyed(members, window)
				if err != nil {
					return err
				}
				attachScope(&st, m, members)
				if patch {
					// fn changes the maps it is given in place: what it started from is a second assembly.
					if oldLedger, err = l.membersOfKeyed(members, window); err != nil {
						return err
					}
				}
				writableCommands(&st, members)
			}
			if rest := scopeAll &^ members; !patch && rest != 0 {
				// a replacement carries the whole state, the rest of the ledger as it is
				if heldLedger, err = l.membersOf(rest); err != nil {
					return err
				}
			}
		}
		if patch {
			if layout {
				var err error
				if oldRaw, err = stateRaw(ctrl); err != nil {
					return err
				}
			} else {
				oldRaw = bytes.Clone(ctrl.Get(stateKey))
			}
		}
		return nil
	}); err != nil {
		return err
	}
	expected, priorAuthority, priorFloor := st.Revision, st.AuthorityRevision, installationFloor(&st)
	if err := fn(&st); err != nil {
		return err
	}
	var newLedger ledgerMembers
	if layout {
		if need := unnamedMembers(&st, members); need != 0 {
			return &unnamedError{need: need}
		}
		if members != 0 {
			newLedger = detachScope(&st, members).normalized()
		}
	}
	if expected == ^model.Revision(0) {
		return model.Fail(model.Unavailable)
	}
	st.Revision = expected + 1
	// The revision clock is stamped after fn like the revision itself: the age of the applied-command
	// log is read from it (retention.go, ExpireControlLog).
	noteRevisionTime(&st, s.clockNow().UnixNano())
	// Set after fn, never before: fn cannot forge, lower or suppress the field. A writer on the
	// non-authority allowlist leaves the value it found. A per-organization writer (updateOrgScoped)
	// that named its organization moves the installation's revision too (the previous release judges
	// against that scalar alone) and records that the floor this release judges against did not move,
	// plus the organization's own revision, when the commit is proposed as a state patch and verified
	// to have changed only what its class owns for it (settleOrgAuthority); every other case, a
	// replacement included, is an ordinary bump.
	var newRaw []byte // the encoding of st, when settleOrgAuthority made it
	var base string
	var ledgerOps []patchOp
	var err error
	switch {
	case oldRaw != nil && !layout:
		// The books are in the blob, as the previous release holds them: the digest is the one it computes.
		if base, err = patchBase(oldRaw); err != nil {
			return err
		}
	case oldRaw != nil:
		base = layoutBaseOf
		if members != 0 {
			ledgerOps = diffLedger(oldLedger.normalized(), newLedger)
		}
	case !layout:
	default:
		attachScope(&st, newLedger, members)
		attachScope(&st, heldLedger, scopeAll&^members)
	}
	switch scope, _ := ctx.Value(orgScopeKey{}).(*orgScope); {
	case bump || force != nil && *force:
		st.AuthorityRevision = st.Revision
	// The books of admission are no row an organization's retention or admin command owns: settleOrgAuthority
	// compares the blobs, which hold none of them, so a ledger the transition changed is judged here. The job
	// and issue books are rows of the organization (orgRetentionTables) that a retention transition owns:
	// their records are judged here by the key, as settleOrgAuthority judges them in a blob that holds them.
	case scope != nil && oldRaw != nil && scope.named && (len(ledgerOps) == 0 || booksOfOrg(ledgerOps, scope, oldLedger, window)):
		newRaw = settleOrgAuthority(&st, oldRaw, scope, priorFloor)
	case scope != nil:
		st.AuthorityRevision = st.Revision
	default:
		st.AuthorityRevision = priorAuthority
	}
	keys, err := s.replicaKeyFiles()
	if err != nil {
		return err
	}
	payload, err := s.controlPayload(oldRaw, newRaw, expected, &st, keys, base, ledgerOps)
	if err != nil {
		return err
	}
	_, err = r.group.Propose(ctx, replica.Entry{ID: model.NewID(), Kind: replica.Control, Payload: payload, ApplicationIndex: uint64(st.Revision)})
	// The leader refuses a proposal naming an old application index with the typed Stale fault
	// (Validate), a forwarding voter gets it back as replica.ErrStale: both are a lost race.
	var fault *model.Fault
	if errors.Is(err, replica.ErrStale) || errors.As(err, &fault) && fault.Code == model.Stale {
		*lost = true
	}
	return replicaFault(err)
}

// lateErasureBooksKey marks the context of an effect commit that does not name the books: an effect
// re-runs the erasure of every finished deletion over the state it changed (eraseLateEffect), the books
// of the jobs and issues included, so with such a deletion in the state the books are assembled for it.
type lateErasureBooksKey struct{}

// hasFinishedDeletion says whether some deletion operation of st has completed or failed.
func hasFinishedDeletion(st *State) bool {
	for _, op := range st.Deletions {
		if op.Phase == model.DeletePhaseComplete || op.Phase == model.DeletePhaseFailed {
			return true
		}
	}
	return false
}

// unnamedMembers is the members of the ledger that st holds although the transition did not name them
// (they are empty in the state a transition that does not name them is given).
func unnamedMembers(st *State, named memberScope) (need memberScope) {
	if named&scopeAdmission == 0 && (st.Reservations != nil || st.AdmissionKeys != nil || st.Quotas != nil || st.Settlement != nil) {
		need |= scopeAdmission
	}
	if named&scopeBooks == 0 && (st.JobBooks != nil || st.IssueBooks != nil || st.GroupingIssues != nil) {
		need |= scopeBooks
	}
	if named&scopeCommands == 0 && (len(st.Commands) != 0 || len(st.CommandOwners) != 0) {
		need |= scopeCommands
	}
	return need
}

// writableCommands gives a transition that names the applied-command log maps to write into: a record is
// written into an empty log as into any other.
func writableCommands(st *State, members memberScope) {
	if members&scopeCommands == 0 {
		return
	}
	if st.Commands == nil {
		st.Commands = map[string]model.ControlResult{}
	}
	if st.CommandOwners == nil {
		st.CommandOwners = map[string]string{}
	}
}

type commandKeyKey struct{}

// withCommandKey marks ctx so that a transition that names the applied-command log reads and writes the
// records of the command id only (a transition that applies one command: transactCommit).
func withCommandKey(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, commandKeyKey{}, id)
}

func commandKeyOf(ctx context.Context) string {
	id, _ := ctx.Value(commandKeyKey{}).(string)
	return id
}

// booksOfOrg says whether every op writes what the class of scope owns for the organization it named: a record
// of the command log that the transition adds (any class commits its command's record, and only adds: a record
// that is in the log when the transition starts is neither removed nor changed by it, an edit of the log of
// applied commands being no write of an organization), or a record of the job or issue books or a grouping issue
// of the organization, which the retention class owns. before is the ledger the transition started from, window
// the command the log was reduced to when the transition read it (a transition that sees one record cannot tell
// whether another is in the log: it adds that record and no other).
func booksOfOrg(ops []patchOp, scope *orgScope, before ledgerMembers, window string) bool {
	org := scope.org.String()
	for _, op := range ops {
		if len(op.Path) != 2 || !bookRoot(op.Path[0]) {
			return false
		}
		key := op.Path[1]
		if op.Path[0] == "Commands" || op.Path[0] == "CommandOwners" {
			_, held := before.Commands[key]
			if op.Path[0] == "CommandOwners" {
				_, held = before.CommandOwners[key]
			}
			if op.Op != opSet || held || window != "" && key != window {
				return false
			}
			continue
		}
		if scope.class != orgRetention || !keyInOrg(key, org) {
			return false
		}
	}
	return true
}

// RetryByDigest implements replica.DigestRetryMachine: every control command carries the whole
// next state, so the group keeps a digest and the receipt of an applied command, not its payload
// (the payload is the retry table's O(commands x state) otherwise).
func (m *replicatedControl) RetryByDigest(k replica.Kind) bool { return k == replica.Control }

var _ replica.DigestRetryMachine = (*replicatedControl)(nil)

func (m *replicatedControl) Applied() uint64 {
	var value uint64
	_ = m.store.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("replica_control"))
		if b != nil {
			raw := b.Get([]byte("physical"))
			if len(raw) == 8 {
				value = binary.BigEndian.Uint64(raw)
			}
		}
		return nil
	})
	return value
}

// The kinds of a control command, the index of Store.decodedByKind.
const (
	kindReplacement = iota
	kindPatch
	kindDelta
	kindScoped
)

func (m *replicatedControl) Apply(c replica.CommittedEntry) error {
	// The command is decoded once for the whole of the apply (a patch of a full round is 770 KiB of JSON).
	var decoded controlCommand
	haveCommand := false
	decode := func() (controlCommand, error) {
		if !haveCommand {
			cmd, err := decodeControlCommand(c.Entry.Payload)
			if err != nil {
				return controlCommand{}, err
			}
			decoded, haveCommand = cmd, true
		}
		return decoded, nil
	}
	applied := m.Applied()
	if c.Entry.Kind != replica.Noop && c.Index <= applied {
		rejected := false
		if err := m.store.db.View(func(tx *bolt.Tx) error {
			rejected = tx.Bucket([]byte("replica_control")).Get([]byte("rejected:"+c.Entry.ID.String())) != nil
			return nil
		}); err != nil {
			return err
		}
		if !rejected {
			cmd, err := decode()
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			switch {
			case cmd.delta != nil:
				err = m.verifyCurrentDelta(*cmd.delta)
			case cmd.scoped != nil:
				err = m.verifyCurrentScoped(*cmd.scoped, model.Revision(c.ApplicationCursor.Index))
			case cmd.patch != nil:
				err = m.verifyCurrentPatch(*cmd.patch)
			default:
				err = m.verifyCurrentState(cmd.replacement.State)
			}
			if err != nil {
				return err
			}
		}
	}
	if c.Index > applied && c.Entry.Kind != replica.Noop {
		cmd, err := decode()
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		// A delta, audit or scoped, carries no key files: only a replacement and a patch install them.
		var keys map[string][]byte
		switch {
		case cmd.replacement != nil:
			keys = cmd.replacement.Keys
		case cmd.patch != nil:
			keys = cmd.patch.Keys
		}
		if cmd.delta == nil && cmd.scoped == nil {
			if err := m.store.installReplicaKeys(keys); err != nil {
				return err
			}
		}
	}
	rejected, activated := false, false
	err := m.store.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("replica_control"))
		physical := readWatermark(meta.Get([]byte("physical")))
		if c.Index <= physical {
			rejected = meta.Get([]byte("rejected:"+c.Entry.ID.String())) != nil
			return nil
		}
		if c.Index != physical+1 && physical != 0 {
			return model.Fail(model.Corrupt)
		}
		b := tx.Bucket([]byte("control"))
		layout := ledgerLayout(b)
		// The bytes of the state the command is applied to are read only when the command cannot be applied
		// without them. A file of layout 2 keeps the revision outside its blob (state_layout.go), so a
		// command that only steps the revision (an admission round, a stale rejection, a no-op) never reads
		// the blob and never writes it; the state is decoded only when a command cannot be applied to its
		// bytes (stateRoot, patchRaw): a patch, an audit delta, a stale rejection and a no-op leave every
		// member they do not name as it is, and decoding and encoding tens of megabytes for them is what a
		// voter paid per command.
		var rawState []byte
		var root stateRoot
		haveRaw := false
		raw := func() error {
			if haveRaw {
				return nil
			}
			r, err := stateRaw(b)
			if err != nil {
				return err
			}
			rawState, root, haveRaw = r, scanStateRoot(r), true
			return nil
		}
		var current State
		loaded := false
		load := func() error {
			if !loaded {
				if err := raw(); err != nil {
					return err
				}
				if json.Unmarshal(rawState, &current) != nil {
					return model.Fail(model.Corrupt)
				}
				loaded = true
			}
			return nil
		}
		var installation0 model.ID
		var revision0 model.Revision
		if layout {
			var err error
			if installation0, revision0, err = stateHead(b); err != nil {
				return err
			}
		} else {
			if err := raw(); err != nil {
				return err
			}
			installation0, revision0 = root.installation, root.revision
			if !root.ok {
				if err := load(); err != nil {
					return err
				}
				installation0, revision0 = current.Installation, current.Revision
			}
		}
		revisionAfter := revision0
		owe := false
		var ledgerOps []patchOp
		var replaceLedger *ledgerMembers
		stepOnly := false
		fast, setClock := false, false // layout 2: the command only steps the revision (and maybe its clock)
		var stepClock []byte
		if c.Entry.Kind != replica.Noop {
			if c.Entry.Kind != replica.Control {
				return model.Fail(model.Corrupt)
			}
			cmd, derr := decode()
			if derr != nil {
				return model.Fail(model.Corrupt)
			}
			var installation model.ID
			var expected model.Revision
			switch {
			case cmd.delta != nil:
				installation, expected = cmd.delta.Installation, cmd.delta.Expected
			case cmd.scoped != nil:
				installation = cmd.scoped.Installation // it names no revision: the records it read are its precondition
			case cmd.patch != nil:
				installation, expected = cmd.patch.Installation, cmd.patch.Expected
			default:
				if cmd.replacement.State.Revision != cmd.replacement.Expected+1 {
					return model.Fail(model.Corrupt)
				}
				installation, expected = cmd.replacement.State.Installation, cmd.replacement.Expected
			}
			if installation != installation0 {
				return model.Fail(model.Corrupt)
			}
			var next []byte // the encoding of the state this command leaves
			settled := false
			stale := expected != revision0
			if cmd.scoped != nil {
				// The command is stale when a record it read is no longer the one it read, whatever else
				// was committed since (scoped_delta.go); every voter holds the same bytes and decides alike.
				if err := raw(); err != nil {
					return err
				}
				holds, e := cmd.scoped.holds(rawState, root)
				if e != nil {
					return e
				}
				stale = !holds
			}
			if stale {
				rejected = true
				revisionAfter = model.Revision(c.ApplicationCursor.Index)
				if err := meta.Put([]byte("rejected:"+c.Entry.ID.String()), []byte{1}); err != nil {
					return err
				}
				// The group drops its redaction proof on every node for a stale command: the index
				// is durable so a receipt can tell an attestation written before it (staleCutoff,
				// attest.go).
				if err := meta.Put(staleAppliedKey, watermarkBytes(c.Index)); err != nil {
					return err
				}
				if layout {
					fast = true
				} else if out, _, ok := patchRaw(rawState, root, []patchOp{revisionOp(revisionAfter)}); ok {
					next = out
				} else {
					if err := load(); err != nil {
						return err
					}
					current.Revision = revisionAfter
				}
			} else if cmd.scoped != nil {
				if revision0 == ^model.Revision(0) {
					return model.Fail(model.Corrupt)
				}
				revisionAfter = revision0 + 1
				settled = root.settled
				if out, ok := scopedRaw(rawState, root, *cmd.scoped, revisionAfter); ok {
					next = out
					owe = erasureCount(cmd.scoped.Audits) > 0
				} else {
					if err := load(); err != nil {
						return err
					}
					var e error
					if owe, e = applyScopedDelta(&current, *cmd.scoped, revisionAfter); e != nil {
						return e
					}
				}
			} else if cmd.delta != nil {
				owe = erasureCount(cmd.delta.Audits) > 0
				revisionAfter = cmd.delta.Expected + 1
				if err := raw(); err != nil {
					return err
				}
				settled = root.settled
				if out, ok := deltaRaw(rawState, root, *cmd.delta); ok {
					next = out
				} else {
					if err := load(); err != nil {
						return err
					}
					owe = applyAuditDelta(&current, *cmd.delta)
				}
			} else if cmd.patch != nil {
				p := *cmd.patch
				if p.Base != "" {
					// A voter that holds other bytes than the proposer read has to be resynchronised (a
					// snapshot install), not given a patch that only names what it changes.
					ok, e := baseMatches(tx, p.Base)
					if e != nil {
						return e
					}
					if !ok {
						return model.Fail(model.Corrupt)
					}
				}
				blobOps := p.Ops
				if layout {
					blobOps, ledgerOps = splitLedgerOps(p.Ops)
				}
				stepOnly = onlyStepOps(blobOps)
				if layout && stepOnly {
					var e error
					if revisionAfter, stepClock, setClock, e = stepOfOps(blobOps, p.Expected); e != nil {
						return e
					}
					fast = true
				} else {
					if err := raw(); err != nil {
						return err
					}
					if out, eff, ok := patchRaw(rawState, root, blobOps); ok && eff.revisionSet && eff.revision == p.Expected+1 {
						next = out
						owe = eff.erasures > 0
						settled = eff.settled
						revisionAfter = eff.revision
					} else {
						if err := load(); err != nil {
							return err
						}
						patched, perr := patchedState(rawState, &current, blobOps, p.Expected, p.Base == "")
						if perr != nil {
							return perr
						}
						owe = erasureCount(patched.Audits) > erasureCount(current.Audits)
						current = patched
					}
				}
			} else {
				// An erasing audit this commit adds means it frees the pages that held what was
				// erased: this file owes a scrub whatever any later record says another node did.
				if err := load(); err != nil {
					return err
				}
				owe = erasureCount(cmd.replacement.State.Audits) > erasureCount(current.Audits)
				current = cmd.replacement.State
				if layout {
					// The replacement carries the whole state: the ledger members go to the ledger, the blob
					// holds the rest.
					held := detachLedger(&current).normalized()
					replaceLedger = &held
				}
			}
			spliced := next != nil || fast
			if !spliced && !fast {
				// The decoded path: current is the state this command leaves.
				revisionAfter = current.Revision
				settled = current.Settlement != nil
				raw, e := json.Marshal(current)
				if e != nil {
					return e
				}
				next = raw
			}
			if !rejected && settled {
				m.store.settledSeen.Store(true)
			}
			var werr error
			switch {
			case fast:
				// Only the revision and the clock moved: the blob, and what a reader of the state without
				// the ledger decoded before it, are as they were.
				werr = putStep(b, revisionAfter, stepClock, setClock)
			case stepOnly:
				// The same for a file that keeps them in the blob (coreState).
				werr = putStateKeep(b, next)
			default:
				werr = putState(b, next)
			}
			if werr != nil {
				return werr
			}
			if layout && (replaceLedger != nil || len(ledgerOps) != 0) {
				l, e := openLedger(tx)
				if e != nil {
					return e
				}
				if replaceLedger != nil {
					e = l.replace(*replaceLedger)
				} else {
					e = l.applyLedgerOps(ledgerOps)
				}
				if e != nil {
					return e
				}
				if !rejected && l.hasWindows() {
					m.store.settledSeen.Store(true)
				}
			}
			// The command that contracts the installation (born so, or the operator's step) is the one that
			// takes the books out of the blob, on every voter at the same command.
			if !layout && !rejected && commandNamesContraction(&cmd) {
				if e := migrateLedger(tx); e != nil {
					return e
				}
				activated = true
			}
			if spliced {
				m.store.rawApplies.Add(1)
			} else {
				m.store.decodedApplies.Add(1)
				switch {
				case cmd.scoped != nil:
					m.store.decodedByKind[kindScoped].Add(1)
				case cmd.delta != nil:
					m.store.decodedByKind[kindDelta].Add(1)
				case cmd.patch != nil:
					m.store.decodedByKind[kindPatch].Add(1)
				default:
					m.store.decodedByKind[kindReplacement].Add(1)
				}
			}
			if owe {
				if e := oweLocalScrub(b); e != nil {
					return e
				}
			}
		}
		if uint64(revisionAfter) != uint64(c.ApplicationCursor.Index) {
			return model.Fail(model.Corrupt)
		}
		for name, value := range map[string]uint64{"physical": c.Index, "application": uint64(c.ApplicationCursor.Index), "term": c.Term} {
			if e := meta.Put([]byte(name), watermarkBytes(value)); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if activated {
		m.store.layoutLedger.Store(true)
	}
	if rejected {
		return replica.ErrConflict
	}
	return nil
}
func watermarkBytes(v uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], v)
	return raw[:]
}
func readWatermark(raw []byte) uint64 {
	if len(raw) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(raw)
}
func seedFile(name string) bool {
	return name == "bootstrap.token" || name == "envelope.key" || name == "envelope.active" || strings.HasPrefix(name, "envelope-") && strings.HasSuffix(name, ".key")
}
func (m *replicatedControl) Snapshot() ([]byte, error) {
	s := m.store
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	keys := map[string][]byte{}
	metadata := map[string][]byte{}
	var state []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		if state, err = snapshotState(tx); err != nil {
			return err
		}
		if b := tx.Bucket([]byte("replica_control")); b != nil {
			return b.ForEach(func(k, v []byte) error { metadata[string(k)] = bytes.Clone(v); return nil })
		}
		return nil
	}); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && seedFile(name) {
			raw, e := os.ReadFile(filepath.Join(s.dir, name))
			if e != nil {
				return nil, e
			}
			keys[name] = raw
		}
	}
	// The bytes of json.Marshal(controlSnapshot{State, Keys, Metadata}), with the state as snapshotState
	// wrote it (it is not decoded to be encoded again).
	keysRaw, err := json.Marshal(keys)
	if err != nil {
		return nil, err
	}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(state)+len(keysRaw)+len(metadataRaw)+64)
	out = append(out, `{"state":`...)
	out = append(out, state...)
	out = append(out, `,"keys":`...)
	out = append(out, keysRaw...)
	out = append(out, `,"metadata":`...)
	out = append(out, metadataRaw...)
	return append(out, '}'), nil
}

// Restore is the snapshot install of the replication layer: it replaces this node's control
// state with the leader's. bbolt writes the new tree to fresh pages and frees the old ones
// without zeroing them, so what the replaced state held (an erased payload this voter had
// applied before the leader erased it) stays in this file's free pages, while the installed
// audit log may already say that a scrub settled the debt: the leader's. The same transaction
// therefore owes this file a local scrub (oweInstalledScrub) that only ScrubErased clears,
// unless the install replaces nothing: the group's first open installs the seed OpenSeed has
// just written, the same decoded state (compared after canonical re-encoding, not byte for
// byte), over a file whose marker is settled.
func (m *replicatedControl) Restore(raw []byte, physical uint64) error {
	return m.restore(raw, physical, true)
}

// restore installs snapshot raw. owe is false only for OpenSeed, which fills a control.db it
// has just created: that file never held anything but the seed's own, already erased state,
// and carries the settled marker key from the start (the group's later install of that same
// state is exempt in oweInstalledScrub, which is what keeps the file unmarked once it opens).
func (m *replicatedControl) restore(raw []byte, physical uint64, owe bool) error {
	if isCompactControl(raw) {
		// Restore is asked to install only a state the machine is behind; a compact state is a name for
		// control.db itself, so a machine behind it has lost the state the name stands for.
		return compactStateRefusal("is behind")
	}
	var snapshot controlSnapshot
	if model.StrictJSON(raw, &snapshot) != nil || snapshot.State.Installation == (model.ID{}) {
		return model.Fail(model.Corrupt)
	}
	s := m.store
	keys, err := s.installKeys(snapshot.Keys)
	if err != nil {
		return err
	}
	whole := snapshot.State // the logical state, the ledger members still in it
	if err = s.db.Update(func(tx *bolt.Tx) error {
		if owe {
			// The installed state is compared with the file's own logical state, ledger included.
			if err := oweInstalledScrub(tx, whole); err != nil {
				return err
			}
		}
		b, err := tx.CreateBucketIfNotExists([]byte("replica_control"))
		if err != nil {
			return err
		}
		if err = putLogicalState(tx, whole); err != nil {
			return err
		}
		for name, value := range snapshot.Metadata {
			if err = b.Put([]byte(name), value); err != nil {
				return err
			}
		}
		if err = b.Put([]byte("application"), watermarkBytes(uint64(snapshot.State.Revision))); err != nil {
			return err
		}
		return finishControlRestore(tx, b, physical)
	}); err != nil {
		// The keys were installed for this state: an install that did not happen leaves none of them.
		return withCleanup(err, s.undoKeys(keys))
	}
	s.noteLayout()
	return nil
}

// ReconcileAdmissions uses the one installed owner's durable outcome proof and
// does not require a live source credential. It never refunds a reserved charge.
//
// The batches that can be missing a finalize are those whose reservation is still open (admission_open.go): an
// owner that answers for the reservations it is asked about (AdmissionOutcomesFor) is asked about those, so
// a pass costs what is open, a few hundred at any moment, and not what was ever admitted. An owner that
// answers only with every outcome it holds (AdmissionOutcomes) is read as before.
func (s *Store) ReconcileAdmissions(ctx context.Context) error {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	if owner == nil {
		return model.Fail(model.Unavailable)
	}
	proofs, err := s.ownerOutcomes(ctx, owner)
	if err != nil {
		return err
	}
	if len(proofs) == 0 {
		return nil
	}
	// One linearizable read decides which outcomes still need a commit: a reservation control
	// holds that has no cursor yet. An outcome whose reservation control no longer holds is fine
	// only when its cursor lies in a settled window (settle.go): its charge is folded already.
	var pending []model.FinalizeAdmission
	if err = s.viewBooks(ctx, func(books admissionBooks) error {
		for _, proof := range proofs {
			old, ok, err := books.reservation(proof.ReservationID.String())
			if err != nil {
				return err
			}
			if !ok {
				if _, settled, err := windowOf(books, proof.Cursor); err != nil {
					return err
				} else if settled {
					continue
				}
				return model.Fail(model.Corrupt)
			}
			if old.State == "cancelled" {
				return model.Fail(model.Corrupt)
			}
			if old.Cursor != nil {
				if *old.Cursor != proof.Cursor {
					return model.Fail(model.Conflict)
				}
				continue
			}
			pending = append(pending, proof)
		}
		return nil
	}); err != nil {
		return err
	}
	// The outcomes are committed reconcilePerCommand at a time: a restart after an overload finds a
	// batch of thousands of appended batches whose finalize never reached control, and one command
	// each is a restart that does not fit its startup budget.
	for len(pending) > 0 {
		chunk := pending[:min(len(pending), reconcilePerCommand)]
		pending = pending[len(chunk):]
		for _, proof := range chunk {
			if err = owner.VerifyFinalization(ctx, proof); err != nil {
				return err
			}
		}
		if err = s.admissionUpdate(ctx, writerReconcileAdmissions, func(_ *State, books admissionBooks) error {
			for _, proof := range chunk {
				if err := reconcileStep(books, proof); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// reconcilePerCommand is how many owner outcomes one reconciliation command marks consumed.
const reconcilePerCommand = 256

// reconcileStep marks the reservation of one durable outcome consumed at the outcome's cursor.
func reconcileStep(books admissionBooks, proof model.FinalizeAdmission) error {
	old, ok, err := books.reservation(proof.ReservationID.String())
	if err != nil {
		return err
	}
	if !ok || old.State == "cancelled" {
		return model.Fail(model.Corrupt)
	}
	if old.Cursor != nil && *old.Cursor != proof.Cursor {
		return model.Fail(model.Conflict)
	}
	old.State = "consumed"
	cursor := proof.Cursor
	old.Cursor = &cursor
	books.putReservation(old)
	return nil
}

// OpenSeed imports an operator-delivered private seed before auth initializes.
// Existing authorities must match its installation; they are never overwritten (an existing
// file is opened by Open, which gives it the scrub marker key if it has none). A file it
// creates holds only the seed's own, already erased state and gets the settled marker key.
func OpenSeed(dir string, raw []byte) (*Store, error) {
	var seed controlSnapshot
	if model.StrictJSON(raw, &seed) != nil || seed.State.Installation == (model.ID{}) {
		return nil, model.Fail(model.Corrupt)
	}
	if err := durablefs.MkdirAll(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "control.db")
	if _, err := os.Stat(path); err == nil {
		s, e := Open(dir)
		if e != nil {
			return nil, e
		}
		var actual model.ID
		e = s.db.View(func(tx *bolt.Tx) error {
			var st State
			if readState(tx.Bucket([]byte("control")), &st) != nil {
				return model.Fail(model.Corrupt)
			}
			actual = st.Installation
			return nil
		})
		if e != nil || actual != seed.State.Installation {
			s.Close()
			return nil, model.Fail(model.Conflict)
		}
		return s, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, durablefs.BoltOptions())
	if err != nil {
		return nil, err
	}
	s := &Store{db: &trackedDB{DB: db}, dir: dir}
	registerTracked(s.db)
	if err = durablefs.SyncFileAndDir(path); err != nil {
		db.Close()
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket([]byte("control"))
		if e != nil {
			return e
		}
		if e = putLogicalState(tx, seed.State); e != nil {
			return e
		}
		return writeLocalScrub(b, localScrub{})
	})
	if err == nil {
		err = (&replicatedControl{store: s}).restore(raw, 0, false)
	}
	if err != nil {
		// The file was created by this call and holds only the seed: a rejected seed must not
		// leave a settled key (and a state) behind for the next Open to trust, nor the seed's
		// envelope keys (restore removes the ones it wrote).
		db.Close()
		if rerr := durablefs.Remove(path); rerr != nil {
			return nil, errors.Join(err, rerr)
		}
		return nil, err
	}
	return s, nil
}
func (s *Store) ValidateReplicationSeed(raw []byte) error {
	var seed controlSnapshot
	if model.StrictJSON(raw, &seed) != nil {
		return model.Fail(model.Corrupt)
	}
	for name, key := range seed.Keys {
		path := filepath.Join(s.dir, name)
		if filepath.Base(name) != name {
			return model.Fail(model.Corrupt)
		}
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, key) {
			return model.Fail(model.Conflict)
		}
	}
	return nil
}

func (m *replicatedControl) Validate(ctx context.Context, command replica.Entry) error {
	if ctx.Err() != nil {
		return model.Fail(model.Cancelled)
	}
	if command.Kind != replica.Control {
		return model.Fail(model.Invalid)
	}
	cmd, err := decodeControlCommand(command.Payload)
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if cmd.scoped != nil {
		// It names no revision and is ordered at the next index: the records it read are its whole
		// precondition (scoped_delta.go). It is neither held for a writer that lost nor does its own
		// refusal make one a loser: an unrelated commit never refuses it.
		return m.store.db.View(func(tx *bolt.Tx) error { return validateScoped(tx, *cmd.scoped, command) })
	}
	var installation model.ID
	var expected, revision model.Revision
	if cmd.delta != nil {
		installation, expected, revision = cmd.delta.Installation, cmd.delta.Expected, cmd.delta.Expected+1
	} else if cmd.patch != nil {
		installation, expected, revision = cmd.patch.Installation, cmd.patch.Expected, cmd.patch.Expected+1
	} else {
		if cmd.replacement.State.Revision != cmd.replacement.Expected+1 {
			return model.Fail(model.Invalid)
		}
		installation, expected, revision = cmd.replacement.State.Installation, cmd.replacement.Expected, cmd.replacement.State.Revision
	}
	ledgerCommand := cmd.patch != nil && ledgerOnlyPatch(cmd.patch)
	if now := time.Now(); ledgerCommand && m.store.admissionYielding(now) {
		return model.Fail(model.Stale) // held for a writer that lost (admission_yield.go): the proposer tries again
	}
	err = m.store.db.View(func(tx *bolt.Tx) error {
		installation0, revision0, err := stateHead(tx.Bucket([]byte("control")))
		if err != nil {
			return err
		}
		if installation != installation0 || expected != revision0 || command.ApplicationIndex != uint64(revision) {
			return model.Fail(model.Stale)
		}
		if cmd.patch != nil {
			// A proposal names the bytes its ops were computed against, and the leader holds them or
			// refuses it before it is committed (every voter would refuse it at apply, patchedState).
			if cmd.patch.Base == "" {
				return model.Fail(model.Invalid)
			}
			ok, err := baseMatches(tx, cmd.patch.Base)
			if err != nil {
				return err
			}
			if !ok {
				return model.Fail(model.Stale)
			}
		}
		return nil
	})
	if !ledgerCommand && isStale(err) {
		m.store.noteWriterLost(time.Now())
	}
	return err
}
func (s *Store) replicaKeyFiles() (map[string][]byte, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	out := map[string][]byte{}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !seedFile(entry.Name()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		out[entry.Name()] = raw
	}
	return out, nil
}

// keyInstall is what one installKeys call changed in the directory, so that a failure later in the
// same install can put the directory back as the call found it.
type keyInstall struct {
	dir       string
	created   []string // key files the call created (they did not exist)
	active    bool     // the call replaced or created envelope.active
	activeHad bool     // envelope.active existed before, with the content activeOld
	activeOld []byte
}

// withCleanup is err with the failure of its cleanup attached; err itself when the cleanup worked.
func withCleanup(err, cleanup error) error {
	if cleanup == nil {
		return err
	}
	return errors.Join(err, cleanup)
}

// replaceActiveKey atomically replaces the envelope.active file at path with value.
func replaceActiveKey(dir, path string, value []byte) error {
	temporary := filepath.Join(dir, ".replica-envelope-active")
	if err := durablefs.Remove(temporary); err != nil {
		return err
	}
	if err := durablefs.Exclusive(temporary, value); err != nil {
		return withCleanup(err, durablefs.Remove(temporary))
	}
	if err := durablefs.Rename(temporary, path); err != nil {
		return withCleanup(err, durablefs.Remove(temporary))
	}
	return nil
}

// undo removes the key files the install created and puts envelope.active back; the caller holds keyMu.
func (k *keyInstall) undo() error {
	var errs []error
	for _, name := range k.created {
		errs = append(errs, durablefs.Remove(filepath.Join(k.dir, name)))
	}
	if k.active {
		path := filepath.Join(k.dir, "envelope.active")
		if k.activeHad {
			errs = append(errs, replaceActiveKey(k.dir, path, k.activeOld))
		} else {
			errs = append(errs, durablefs.Remove(path))
		}
	}
	return errors.Join(errs...)
}

func (s *Store) undoKeys(k *keyInstall) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return k.undo()
}

func (s *Store) installReplicaKeys(keys map[string][]byte) error {
	_, err := s.installKeys(keys)
	return err
}

// installKeys writes the key files of a snapshot or a replicated command that this directory does
// not hold yet and hands back what it changed. It writes all of them or none: every name is
// checked, and every file already there compared, before the first write, so a snapshot with one
// bad key writes nothing; a write that fails after others landed removes those.
func (s *Store) installKeys(keys map[string][]byte) (*keyInstall, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	for name := range keys {
		if !seedFile(name) || filepath.Base(name) != name {
			return nil, model.Fail(model.Corrupt)
		}
	}
	var missing []string
	for name, value := range keys {
		if name == "envelope.active" {
			continue
		}
		old, err := os.ReadFile(filepath.Join(s.dir, name))
		switch {
		case err == nil:
			if !bytes.Equal(old, value) {
				return nil, model.Fail(model.Conflict)
			}
		case os.IsNotExist(err):
			missing = append(missing, name)
		default:
			return nil, err
		}
	}
	active, hasActive := keys["envelope.active"]
	var activeOld []byte
	activeHad := false
	if hasActive {
		old, err := os.ReadFile(filepath.Join(s.dir, "envelope.active"))
		switch {
		case err == nil:
			activeOld, activeHad = old, true
		case !os.IsNotExist(err):
			return nil, err
		}
	}
	k := &keyInstall{dir: s.dir}
	for _, name := range missing {
		path := filepath.Join(s.dir, name)
		if err := durablefs.Exclusive(path, keys[name]); err != nil {
			if !os.IsExist(err) { // a file this call created (or half wrote) is its own to remove
				err = withCleanup(err, durablefs.Remove(path))
			}
			return nil, withCleanup(err, k.undo())
		}
		k.created = append(k.created, name)
	}
	if hasActive && !(activeHad && bytes.Equal(activeOld, active)) {
		k.active, k.activeHad, k.activeOld = true, activeHad, activeOld
		if err := replaceActiveKey(s.dir, filepath.Join(s.dir, "envelope.active"), active); err != nil {
			return nil, withCleanup(err, k.undo())
		}
	}
	return k, nil
}

func (s *Store) ReplicaGroup() *replica.Group {
	if s.repl == nil {
		return nil
	}
	return s.repl.group
}

// InitializeBearerHashKey is the only pre-consensus mutation after construction.
// It cannot create users, grants, sessions, source authority or feature state.
func (s *Store) InitializeBearerHashKey(ctx context.Context, sealed string, version uint8) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if sealed == "" || version != 1 {
		return model.Fail(model.Invalid)
	}
	initialize := func(st *State) (bool, error) {
		if st.BearerHashKeyVersion != 0 || st.BearerHashKey != "" {
			if st.BearerHashKeyVersion != 1 || st.BearerHashKey == "" {
				return false, model.Fail(model.Corrupt)
			}
			return false, nil
		}
		if st.Installation == (model.ID{}) || st.Revision != 0 || st.BootstrapHash == "" || st.DataInitialized || len(st.Users) != 0 || len(st.Sessions) != 0 || len(st.Orgs) != 0 || len(st.Commands) != 0 || len(st.Audits) != 0 || len(st.ServerTokens) != 0 || len(st.Sources) != 0 || len(st.SourceCredentials) != 0 || len(st.Reservations) != 0 {
			return false, model.Fail(model.Corrupt)
		}
		st.BearerHashKey = sealed
		st.BearerHashKeyVersion = version
		return true, nil
	}
	s.updateMu.Lock()
	if s.repl != nil {
		s.updateMu.Unlock()
		return s.Update(ctx, func(st *State) error { _, err := initialize(st); return err })
	}
	defer s.updateMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("control"))
		var st State
		if readState(bucket, &st) != nil {
			return model.Fail(model.Corrupt)
		}
		changed, err := initialize(&st)
		if err != nil || !changed {
			return err
		}
		st.Revision++
		raw, err := json.Marshal(st)
		if err != nil {
			return err
		}
		return putState(bucket, raw)
	})
}

// EnableSingle explicitly activates the real one-voter control group. Open does
// not activate it implicitly, especially not for an authenticated replica seed.
func (s *Store) EnableSingle(ctx context.Context, directory string) error {
	if s.repl != nil {
		return model.Fail(model.Conflict)
	}
	var id model.ID
	if err := s.View(ctx, func(st State) error { id = st.Installation; return nil }); err != nil {
		return err
	}
	local := replica.NewLoopback()
	group, err := s.EnableReplication(replica.Config{ID: 1, Group: id, Directory: directory, Transport: local, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}})
	if err != nil {
		local.Close()
		return err
	}
	s.repl.local = local
	if err = local.Register(group); err == nil {
		err = group.Campaign()
	}
	if err == nil {
		err = group.Ready(ctx)
	}
	if err != nil {
		s.repl.close()
	}
	return err
}
func (r *replicatedControl) close() error {
	if r.cancel != nil {
		r.cancel() // the attestation withdrawal loop stops before the group it talks to closes
		<-r.done
	}
	first := r.group.Close()
	if r.local != nil {
		if err := r.local.Close(); first == nil {
			first = err
		}
	}
	return first
}

func (s *Store) initializeConsensusNamespace(directory string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("control"))
		var state State
		if readState(bucket, &state) != nil {
			return model.Fail(model.Corrupt)
		}
		marker := bucket.Get([]byte("replica_format"))
		progress := tx.Bucket([]byte("replica_control"))
		if marker != nil {
			if !bytes.Equal(marker, []byte{1}) || progress == nil {
				return model.Fail(model.Corrupt)
			}
			for _, name := range []string{"physical", "application", "term"} {
				if len(progress.Get([]byte(name))) != 8 {
					return model.Fail(model.Corrupt)
				}
			}
			if readWatermark(progress.Get([]byte("application"))) != uint64(state.Revision) {
				return model.Fail(model.Corrupt)
			}
			return nil
		}
		if progress != nil {
			return model.Fail(model.Corrupt)
		}
		if _, err := os.Stat(filepath.Join(directory, "ready.wal")); err == nil {
			return model.Fail(model.Corrupt)
		} else if !os.IsNotExist(err) {
			return err
		}
		var err error
		progress, err = tx.CreateBucket([]byte("replica_control"))
		if err != nil {
			return err
		}
		for _, name := range []string{"physical", "term"} {
			if err = progress.Put([]byte(name), watermarkBytes(0)); err != nil {
				return err
			}
		}
		if err = progress.Put([]byte("application"), watermarkBytes(uint64(state.Revision))); err != nil {
			return err
		}
		return bucket.Put([]byte("replica_format"), []byte{1})
	})
}
func (m *replicatedControl) verifyCurrentState(expected State) error {
	return m.store.db.View(func(tx *bolt.Tx) error {
		var current State
		if err := loadLogical(tx, &current); err != nil {
			return err
		}
		if current.Installation != expected.Installation || current.Revision < expected.Revision {
			return model.Fail(model.Corrupt)
		}
		if current.Revision != expected.Revision {
			return nil
		}
		// The ledger does not tell an empty map from an absent one: both states are compared in its form.
		normalizeLedger(&expected)
		normalizeLedger(&current)
		left, err := model.CanonicalJSON(current)
		if err != nil {
			return err
		}
		right, err := model.CanonicalJSON(expected)
		if err != nil || !bytes.Equal(left, right) {
			return model.Fail(model.Corrupt)
		}
		return nil
	})
}

// VerifySnapshot checks a snapshot against the local state before the group restores it. A
// machine that is BEHIND the snapshot is exactly the voter a snapshot repairs (a leader that
// compacted its journal past a lagging voter sends one: Restore then installs it); it is
// refused only when it is for another installation. A machine at the snapshot's revision must
// hold exactly that state, and one ahead of it holds whatever came after.
func (m *replicatedControl) VerifySnapshot(raw []byte) error {
	if isCompactControl(raw) {
		return m.verifyCompact(raw)
	}
	var snapshot controlSnapshot
	if model.StrictJSON(raw, &snapshot) != nil {
		return model.Fail(model.Corrupt)
	}
	if m.Applied() == 0 {
		return nil
	}
	behind := false
	if err := m.store.db.View(func(tx *bolt.Tx) error {
		var current State
		if readState(tx.Bucket([]byte("control")), &current) != nil {
			return model.Fail(model.Corrupt)
		}
		behind = current.Installation == snapshot.State.Installation && current.Revision < snapshot.State.Revision
		return nil
	}); err != nil {
		return err
	}
	if behind {
		return nil
	}
	return m.verifyCurrentState(snapshot.State)
}

func finishControlRestore(tx *bolt.Tx, progress *bolt.Bucket, physical uint64) error {
	if len(progress.Get([]byte("term"))) != 8 {
		if err := progress.Put([]byte("term"), watermarkBytes(0)); err != nil {
			return err
		}
	}
	if err := tx.Bucket([]byte("control")).Put([]byte("replica_format"), []byte{1}); err != nil {
		return err
	}
	return progress.Put([]byte("physical"), watermarkBytes(physical))
}

// Replication validates already-authorized leaf commands again against the
// actual committed authority. Node certificates are not public write grants.
func replicaSource(st State, org, project, source model.ID, epoch model.Uint64, revision model.Revision, admission bool) error {
	src, ok := st.Sources[source.String()]
	if !ok || src.Org != org || src.Project != project || src.Retired || src.Revoked || int64(src.Expires) <= time.Now().UnixNano() {
		return model.Fail(model.Forbidden)
	}
	o, ok := st.Orgs[org.String()]
	if !ok {
		return model.Fail(model.Forbidden)
	}
	if _, ok = o.Projects[project.String()]; !ok {
		return model.Fail(model.Forbidden)
	}
	if admission {
		if src.Closing || !src.Policy.Enabled || src.Policy.Expires != 0 && int64(src.Policy.Expires) <= time.Now().UnixNano() || uint64(epoch) != o.Epoch || revision != src.Policy.Revision {
			return model.Fail(model.Stale)
		}
		var config struct {
			Project    model.ID `json:"project_id"`
			Enabled    bool     `json:"enabled"`
			Restricted bool     `json:"restricted"`
		}
		if json.Unmarshal(o.Settings["source_policy:"+source.String()], &config) != nil || config.Project != project || !config.Enabled || config.Restricted != (src.Policy.Class == "restricted_raw") {
			return model.Fail(model.Forbidden)
		}
	}
	return nil
}
func (s *Store) ValidateReplicatedBatch(ctx context.Context, b model.NormalizedBatch) error {
	return s.ViewAdmission(ctx, func(st State, rows auth.AdmissionReader) error {
		if err := replicaSource(st, b.Org, b.Project, b.Source, b.PolicyEpoch, b.PolicyRevision, true); err != nil {
			return err
		}
		r, ok, err := rows.Reservation(b.Reservation.ID.String())
		if err != nil {
			return err
		}
		if !ok || r.State != "reserved" || r.Hash != b.Hash || r.Batch != b.ID || r.Org != b.Org || r.Project != b.Project || r.Source != b.Source || r.Producer != b.Producer || r.Slot != b.RouteSlot {
			return model.Fail(model.Forbidden)
		}
		if !auth.SameReservation(r, b.Reservation) {
			return model.Fail(model.Forbidden)
		}
		src := st.Sources[b.Source.String()]
		policy, err := model.CanonicalJSON(src.Policy)
		if err != nil || model.HashCanonical(policy).String() != b.PolicyHash {
			return model.Fail(model.Stale)
		}
		return nil
	})
}
func (s *Store) ValidateReplicatedFragment(ctx context.Context, f model.ArtifactFragment) error {
	return s.View(ctx, func(st State) error {
		m := f.Manifest
		if err := replicaSource(st, m.Org, m.Project, m.Source, m.PolicyEpoch, m.PolicyRevision, true); err != nil {
			return err
		}
		r, ok := st.ArtifactReservations[m.ReservationID.String()]
		if !ok || r.Manifest != m || r.ManifestHash != model.BlobManifestHash(m) || r.State != "reserved" && r.State != "consumed" || r.Slot != model.BlobOwnerSlot(m.Org, m.Project, m.Root) {
			return model.Fail(model.Forbidden)
		}
		a, err := model.CanonicalJSON(r)
		if err != nil {
			return err
		}
		b, err := model.CanonicalJSON(f.Reservation)
		if err != nil || !bytes.Equal(a, b) {
			return model.Fail(model.Forbidden)
		}
		return nil
	})
}
func (s *Store) ValidateReplicatedGC(ctx context.Context, g model.ArtifactGC) error {
	return s.View(ctx, func(st State) error {
		r, ok := st.ArtifactReservations[g.Manifest.ReservationID.String()]
		if !ok || r.Manifest != g.Manifest || r.State != "cancelled" || r.GC == nil || r.GC.CommandID != g.CommandID || r.GC.ControlRevision != g.ControlRevision || g.ControlRevision == 0 || g.ControlRevision > st.Revision {
			return model.Fail(model.Forbidden)
		}
		for _, reference := range st.ArtifactIntents {
			if reference.ID == g.Manifest.Root && reference.Manifest.Org == g.Manifest.Org && reference.Manifest.Project == g.Manifest.Project {
				return model.Fail(model.Conflict)
			}
		}
		return nil
	})
}
func (s *Store) ValidateReplicatedFence(ctx context.Context, f model.SourceFence) error {
	return s.View(ctx, func(st State) error {
		actual, ok := st.SourceOperations[f.Operation.String()]
		if !ok || actual.Source != f.Source || actual.Org != f.Org || actual.Epoch != f.Epoch || actual.Phase != "fencing" {
			return model.Fail(model.Stale)
		}
		return nil
	})
}
func (s *Store) ValidateReplicatedCancellation(ctx context.Context, c model.CancelReservation) error {
	return s.viewBooks(ctx, func(books admissionBooks) error {
		r, ok, err := books.reservation(c.ReservationID.String())
		if err != nil {
			return err
		}
		if !ok || r.Hash != c.Hash || r.State != "reserved" {
			return model.Fail(model.Conflict)
		}
		return nil
	})
}
