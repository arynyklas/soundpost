// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/durablefs"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type Store struct {
	db         *trackedDB
	dir        string
	registryMu sync.RWMutex
	keyMu      sync.Mutex
	ownerProof AdmissionProofs
	handlers   map[CommandKind]Handler
	updateMu   sync.Mutex
	repl       *replicatedControl
	clock      func() time.Time // the leader's wall clock for RevisionClock; nil is time.Now
	// settledSeen is set once this store has seen a state with settled admission windows (settle.go):
	// ReserveAdmission then asks the owner about a key it has no row for before its first update
	// instead of after an aborted one. A hint only: the update decides on the state it reads.
	settledSeen atomic.Bool
	// layoutLedger says whether this file keeps the admission books in the ledger (ledgerLayout); it is
	// read by every admission before it decides how to commit, and set where the layout changes: Open,
	// the activation in Apply and a snapshot install.
	layoutLedger atomic.Bool
	// ruleLedger says whether this file keeps the rule books and the rule outbox in the ledger (D108, rule_ledger.go): set
	// where the layout changes (noteLayout, the activation in Apply).
	ruleLedger atomic.Bool
	// ruleMarker is the revision of the command that marked the installation, plus one (0: not read yet), kept by RuleLayout.
	ruleMarker atomic.Uint64
	// boundedGate says whether the bounded-state rules apply (bounded_rules.go); nil: they do.
	boundedGate atomic.Pointer[func() bool]
	// auditDeltaGate says whether the audit delta command may be proposed (audit_delta.go); nil: it may not.
	auditDeltaGate atomic.Pointer[func() bool]
	// auditDeltas and auditDeltaBytes count the delta commands AppendAudit proposed and their payload
	// bytes (read by tests and benchmarks through AuditDeltaStatsForTest).
	auditDeltas, auditDeltaBytes atomic.Uint64
	// scopedDeltas and scopedDeltaBytes count the scoped delta commands the record writers proposed
	// (scoped_delta.go) and their payload bytes (ScopedDeltaStats).
	scopedDeltas, scopedDeltaBytes atomic.Uint64
	// statePatchGate says whether a command may be proposed as a state patch (state_patch.go); nil:
	// it may not. statePatches and statePatchBytes count the patch commands proposed and their payload bytes.
	statePatchGate                atomic.Pointer[func() bool]
	statePatches, statePatchBytes atomic.Uint64
	// compactAdmissionGate says whether every member declared the protocol that applies the compact admission ops
	// (compact_admission.go, D104); nil: they are not proposed.
	compactAdmissionGate atomic.Pointer[func() bool]
	// compactReserves and compactFinalizes count the rsv and fin ops the admission rounds proposed (CompactAdmissionOps), and
	// compactSettles the chs ops (CompactSettleOps), compactRecords the rec ops (CompactRecordOps).
	compactReserves, compactFinalizes, compactSettles, compactRecords atomic.Uint64
	// sparseCommits counts the commands proposed by sparseUpdate (sparse.go).
	sparseCommits atomic.Uint64
	// sparseLockedDecodes counts the sparse commits that had to decode the state under the lock.
	sparseLockedDecodes atomic.Uint64
	// settleScanRows counts the reservation rows the planning of a settlement decoded (settle.go): the
	// books are scanned once per SettleAdmissions call, never by the commands that call commits.
	settleScanRows atomic.Uint64
	// legacyStatePatchGate says whether every member declared the first protocol of the patch: a patch
	// may then be proposed against a ledger that holds no record (SetLegacyStatePatchGate); nil: it may not.
	legacyStatePatchGate atomic.Pointer[func() bool]
	// admissionYieldUntil and admissionYieldNext are the leader's fairness toward the writers that are not
	// admission (admission_yield.go), as UnixNano; admissionYieldScale stretches its two durations (0: not
	// stretched), set by a test alone.
	admissionYieldUntil, admissionYieldNext, admissionYieldScale atomic.Int64
	// admissions is the group commit of admission transitions (admission_group.go); admissionRounds and
	// admissionRoundItems count the rounds proposed and the transitions they carried.
	admissions                           admissionQueue
	admissionRounds, admissionRoundItems atomic.Uint64
	// admissionStats times the rounds (roundOnce) for a diagnostic build's report: attempts, the ones lost to the
	// application-index race, the wait of the transitions in the queue and where an attempt spends its time.
	admissionStats roundStats
	// scopes makes the scope of a claim (BindAdmissionScopes); remoteDownUntil is when a voter whose call to the leader failed
	// judges its own transitions until (UnixNano); the counters are the calls made, their time, the ones that fell back and the
	// calls served as the leader (admission_remote.go).
	scopes                                                   atomic.Pointer[claimScopes]
	remoteDownUntil                                          atomic.Int64
	remoteCalls, remoteCallNS, remoteFallbacks, remoteServed atomic.Uint64
	// turn is the leader's turn for a writer that keeps losing; turnDownUntil is when a voter whose leader serves no such call
	// stops asking (UnixNano; admission_turn.go).
	turn          turnState
	turnDownUntil atomic.Int64
	// layoutSupportGate names the members of the control group whose running binary does not read
	// the contracted index layout (index_layout.go); nil: none is known to.
	layoutSupportGate atomic.Pointer[func() []string]
	// memberLayoutQuery is the live question to one member (index_layout.go); nil: none answers.
	memberLayoutQuery atomic.Pointer[func(context.Context, replica.Member) error]
	// memberRuleLedgerQuery is the live question to one member whether it reads the rule facts as records of the ledger (D108,
	// index_layout.go); asked once the installation carries the mark. nil: none answers.
	memberRuleLedgerQuery atomic.Pointer[func(context.Context, replica.Member) error]
	// rawApplies and decodedApplies count the committed commands this store applied to the bytes of
	// its state (stateRoot, patchRaw) and the ones it had to decode the state for (Apply).
	rawApplies, decodedApplies atomic.Uint64
	// decodedByKind splits decodedApplies by the kind of the command (kindReplacement, kindPatch,
	// kindDelta, kindScoped): statistics only, read by tests.
	decodedByKind [4]atomic.Uint64

	// updateHolds and updateHeldNS count the times updateMu was taken by a writer and how long it was held
	// (lockUpdates): what the writers cost the others that wait for it.
	updateHolds, updateHeldNS atomic.Uint64
}

// lockUpdates takes updateMu and returns the function that releases it and counts the hold.
func (s *Store) lockUpdates() func() {
	s.updateMu.Lock()
	taken := time.Now()
	return func() {
		s.updateHeldNS.Add(uint64(time.Since(taken)))
		s.updateHolds.Add(1)
		s.updateMu.Unlock()
	}
}

// SetClock replaces the wall clock the update funnel dates revisions with (RevisionClock), time.Now
// by default. A deployment has no reason to: it exists so that a long run can be simulated.
func (s *Store) SetClock(now func() time.Time) {
	s.updateMu.Lock()
	s.clock = now
	s.updateMu.Unlock()
}

// clockNow is the funnel's clock; the caller holds updateMu.
func (s *Store) clockNow() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

type User = model.ControlUser
type Session = model.ControlSession
type Team = model.ControlTeam
type Org = model.ControlOrg
type Audit = model.ControlAudit
type State = model.ControlState
type Command = model.ControlCommand
type Result = model.ControlResult

// openControlDB opens control.db with durablefs.BoltOptions (D91: no freelist in the commits, 455 KB, 111 pages, in each of the 57
// commits a second of the gate after its hour; read at open when the last close wrote it and rebuilt from the live tree when it did not).
// The warm-up of the live tree of a file that carries no freelist comes first (durablefs.WarmBoltTree: the 200,000 nodes of the gate's file
// are a pass of 26 s on a cold disk when bolt walks them one page fault at a time), then bolt.
func openControlDB(path string) (*bolt.DB, error) {
	durablefs.WarmBoltTree(path)
	return bolt.Open(path, 0600, durablefs.BoltOptions())
}

// Open opens (or creates) the control.db in dir. In the same write transaction it makes sure the
// file carries the node-local scrub marker (erase.go, localScrubKey): the key's presence says that
// a build with the marker has seen this file. A file without the key was written by an earlier
// build, which applied erasures without recording that this file still held their payload, and the
// replicated audit log is not a complete memory of them (a leader's scrubbed audit settles the
// leader's file, and an install from another lineage can drop an erasing audit): so every such
// file is marked owed, whatever its log names, once. A file that already has the key is never
// rewritten, and a created file gets the settled key at once so that a later Open does not mark
// it. Control writes accept only authorization-owned opaque scopes.
func Open(dir string) (*Store, error) {
	if e := durablefs.MkdirAll(dir); e != nil {
		return nil, e
	}
	path := filepath.Join(dir, "control.db")
	_, statErr := os.Stat(path)
	fresh := os.IsNotExist(statErr)
	if statErr != nil && !fresh {
		return nil, statErr
	}
	db, e := openControlDB(path)
	if e != nil {
		return nil, e
	}
	if e = durablefs.SyncFileAndDir(filepath.Join(dir, "control.db")); e != nil {
		db.Close()
		return nil, e
	}
	s := &Store{db: &trackedDB{DB: db}, dir: dir}
	registerTracked(s.db)
	e = db.Update(func(tx *bolt.Tx) error {
		if !fresh {
			b := tx.Bucket([]byte("control"))
			if b == nil || b.Get([]byte("state")) == nil {
				return model.Fail(model.Corrupt)
			}
			if e := markOpenedFile(b); e != nil {
				return e
			}
			return migrateLedger(tx)
		}
		b, e := tx.CreateBucketIfNotExists([]byte("control"))
		if e != nil {
			return e
		}
		if b.Get([]byte("state")) != nil {
			if e := markOpenedFile(b); e != nil {
				return e
			}
			return migrateLedger(tx)
		}
		token := Random()
		st := State{Installation: model.NewID(), BootstrapHash: Hash(token), Users: map[string]User{}, Sessions: map[string]Session{}, Orgs: map[string]Org{}, Commands: map[string]Result{}, OIDC: map[string]json.RawMessage{}}
		if e = durablefs.Exclusive(filepath.Join(dir, "bootstrap.token"), []byte(token)); e != nil {
			return e
		}
		v, e := json.Marshal(st)
		if e != nil {
			return e
		}
		if e = putState(b, v); e != nil {
			return e
		}
		if e = writeLocalScrub(b, localScrub{}); e != nil {
			return e
		}
		return ensureLedger(tx)
	})
	if e != nil {
		unregisterTracked(s.db)
		db.Close()
		return nil, e
	}
	s.noteSettled()
	s.noteLayout()
	return s, nil
}
func (s *Store) Close() error {
	if s.repl != nil {
		if err := s.repl.close(); err != nil {
			s.db.Close()
			return err
		}
	}
	// A graceful close writes the freelist the commits did not (durablefs.BoltOptions): the next start reads it instead of walking the tree.
	err := s.db.syncFreelist()
	if errors.Is(err, bolt.ErrDatabaseNotOpen) {
		err = nil // closed already
	}
	if x := s.db.Close(); err == nil {
		err = x
	}
	return err
}
func (s *Store) BootstrapToken() (string, error) {
	b, e := os.ReadFile(filepath.Join(s.dir, "bootstrap.token"))
	return string(b), e
}
func (s *Store) RemoveBootstrapFile() error {
	return durablefs.Remove(filepath.Join(s.dir, "bootstrap.token"))
}

// head is the installation and the revision of the committed state, read from the keys that hold them
// (the state is not decoded, and neither is the ledger): what a start needs to name its journal.
func (s *Store) head() (installation model.ID, revision model.Revision, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		if ctrl == nil {
			return model.Fail(model.Corrupt)
		}
		installation, revision, err = stateHead(ctrl)
		return err
	})
	return
}

// Revision is the committed revision of the control state, read linearizably (the read barrier of View) and without
// decoding the state: a caller that needs the revision to name it in a command (ExpectedRevision) needs no more.
func (s *Store) Revision(ctx context.Context) (model.Revision, error) {
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return 0, replicaFaultUnder(ctx, err)
		}
	}
	var revision model.Revision
	err := s.db.View(func(tx *bolt.Tx) error {
		ctrl := tx.Bucket([]byte("control"))
		if ctrl == nil {
			return model.Fail(model.Corrupt)
		}
		_, r, err := stateHead(ctrl)
		revision = r
		return err
	})
	return revision, err
}

// DecodeStats is how many times the control state was decoded since the store opened.
type DecodeStats struct {
	// Whole is the decodes of every member of the state for a shared reader (ViewShared, ViewCore and the
	// admission rounds read the decode every reader shares): a restart, or a commit that changed every member.
	Whole uint64
	// Members is the members of the state decoded for those readers: the ones a commit changed, the ones a
	// reader asked for that nobody had decoded (a book a shared reader opens), and all of them for a whole decode.
	Members uint64
	// Blobs is every decode of the whole blob made through readState, whoever asked: a reader of its own State
	// (View), a writer, the fallback of the shared decode. A reader of the shared decode makes none.
	Blobs uint64
}

// DecodeStats reports the decode counters of the store: what a steady load costs in decodes of the state.
func (s *Store) DecodeStats() DecodeStats {
	return DecodeStats{Whole: s.db.decodes.Load(), Members: s.db.memberDecodes.Load(), Blobs: s.db.blobDecodes.Load()}
}

// RevisionOf is the committed revision of c, a control store or a stand-in for one (a test double that counts or
// fails reads): a *Store gives it without decoding the state (Store.Revision), any other type through its own View.
func RevisionOf(ctx context.Context, c interface {
	View(context.Context, func(State) error) error
}) (model.Revision, error) {
	if s, ok := c.(*Store); ok {
		return s.Revision(ctx)
	}
	var revision model.Revision
	err := c.View(ctx, func(st State) error { revision = st.Revision; return nil })
	return revision, err
}

// Installation is the identity of the installation this file belongs to. It reads the committed file
// directly, without the read barrier of the replication group, so that it can be asked before the group
// is opened.
func (s *Store) Installation() (model.ID, error) {
	installation, _, err := s.head()
	return installation, err
}

// DataInitialized says whether the installation's data engine was initialized (ControlState.DataInitialized),
// read from the state blob like Installation: the open of the application asks it before any group exists.
func (s *Store) DataInitialized() (initialized bool, err error) {
	err = s.viewCore(context.Background(), func(st State) error { initialized = st.DataInitialized; return nil })
	return
}

// viewCore is View for a reader of the members the state blob holds (the organizations, the artifact
// intents, the deletions, the audit log): the read barrier and the transaction are View's, but no member
// of the ledger is assembled into the state (the admission books, the job and issue books, the grouping
// issues and the applied-command log come empty, in a file that keeps them in the ledger). A start reads
// the state several times before it serves, and the ledger of a busy installation is most of the file.
func (s *Store) viewCore(ctx context.Context, fn func(State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if err := s.readBarrier(ctx); err != nil {
		return err
	}
	return s.db.View(func(tx *bolt.Tx) error {
		var st State
		if readState(tx.Bucket([]byte("control")), &st) != nil {
			return model.Fail(model.Corrupt)
		}
		return fn(st)
	})
}

// View gives fn the committed state, with the admission books assembled into it (Reservations,
// AdmissionKeys, Quotas, Settlement) unless ctx came from WithoutBooks. The job and issue books (JobBooks,
// IssueBooks) are always assembled: a reader that asked not to carry the admission books may still look at
// them (the retention worker's projections, a cutover's checkpoints). The State is the reader's own.
func (s *Store) View(ctx context.Context, fn func(State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if err := s.readBarrier(ctx); err != nil {
		return err
	}
	books := model.WantsBooks(ctx)
	return s.db.View(func(tx *bolt.Tx) error {
		var st State
		if books {
			if e := loadLogical(tx, &st); e != nil {
				return e
			}
		} else {
			ctrl := tx.Bucket([]byte("control"))
			if readState(ctrl, &st) != nil {
				return model.Fail(model.Corrupt)
			}
			if ledgerLayout(ctrl) {
				l, err := openLedger(tx)
				if err != nil {
					return err
				}
				scope := scopeBooks
				if l.rules {
					scope |= scopeRules // the rule facts are the workers' books too, wherever the file keeps them
				}
				m, err := l.membersOf(scope)
				if err != nil {
					return err
				}
				attachScope(&st, m, scope)
			}
		}
		return fn(st)
	})
}

// ViewShared is View for a reader that only reads. Instead of a decode of its own it is given the
// decode of the committed state that every concurrent shared reader uses, through the read-only
// interface (model.ReadOnlyControl), which has no way to change it or to keep part of it: decoding
// the whole state once per read made a pass of the background workers cost O(projects squared). The
// decode is the one coreMembers keeps, member by member: a commit makes the next reader decode the members it
// changed that the read-only interface reads (the organizations, the sessions, the deletions), and the books
// (the rule books, the outbox, the incident and condition books) only when a reader asks for the book, so a
// reader on the append path of the data engine (ActiveDeletions, once per page chunk of a query) decodes
// nothing for the rule commits and outbox writes that went before it. The linearizable read barrier is the
// same as View's, and so is the snapshot: the state is the one of the bolt transaction the read runs in, so a
// reader sees one whole revision, never a mix. The admission ledger is not part of it. fn must not retain the
// ReadOnlyControl past its return. A caller that changes what it reads, or needs the State itself, uses View.
func (s *Store) ViewShared(ctx context.Context, fn func(model.ReadOnlyControl) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if err := s.readBarrier(ctx); err != nil {
		return err
	}
	return s.db.View(func(tx *bolt.Tx) error {
		st, err := s.coreMembers(tx, readOnlyMembers)
		if err != nil {
			return err
		}
		books := &sharedBooks{s: s, tx: tx}
		if ledgerLayout(tx.Bucket([]byte("control"))) {
			l, err := openLedger(tx)
			if err != nil {
				return err
			}
			books.ledger = ledgerBookSource{l}
			books.rules = l.rules
		}
		if err = fn(model.ReadOnlyOfWith(st, books)); err != nil {
			return err
		}
		return books.err
	})
}

// SharesViewOf reports whether c reads the control state through this store's own View. A type that
// embeds the store and overrides View (a test double that counts or fails reads) has ViewShared
// promoted unchanged, and a reader that preferred ViewShared would skip the override: auth.Service
// asks first and reads any other value through the View it was given.
func (s *Store) SharesViewOf(c auth.ControlStore) bool { return c == auth.ControlStore(s) }

// Update commits fn as one control transition. It is an authority transition: it moves
// AuthorityRevision. The writers that are known not to change authority go through updateAs.
func (s *Store) Update(ctx context.Context, fn func(*State) error) error {
	return s.update(ctx, true, scopeAll, fn)
}

// errReplayed is returned by the transition of Transact when the command was already applied
// (a first submission that raced another of the same id past the read-first check): the stored
// Result is the answer and nothing is committed, so no revision is spent and AuthorityRevision
// stays. replicatedUpdate returns a transition's error before it stamps or proposes anything.
var errReplayed = errors.New("command already applied")

func (s *Store) Transact(ctx context.Context, scope auth.Scope, cmd Command) (Result, error) {
	if !CommandKind(cmd.Kind).Valid() || cmd.CommandID == (model.ID{}) {
		return Result{}, model.Fail(model.Invalid)
	}
	if e := scope.ControlAuthorize(ctx, cmd.Kind); e != nil {
		return Result{}, e
	}
	var out Result
	correlationID := model.RequestCorrelationID(ctx, cmd.CommandID)
	// A retry of an applied CommandID is answered from a linearizable read: it changes no state,
	// so it must not propose a replacement, spend a revision or move AuthorityRevision. The
	// checks are the ones the update function makes (scope against the state, then the owner
	// binding); a first submission racing this read finds the other's result in the update.
	replayed := false
	if e := s.viewCommand(ctx, cmd.CommandID.String(), func(st *State, v Result, owner string, found bool) error {
		if !found {
			return nil
		}
		if err := scope.ValidateControlState(*st); err != nil {
			return err
		}
		if owner != scope.PrincipalID().String()+":"+scope.OrgID().String()+":"+cmd.Kind {
			return model.Fail(model.NotFound)
		}
		out, replayed = v, true
		return nil
	}); e != nil {
		return Result{}, e
	}
	if replayed {
		return out, nil
	}
	return s.transactCommit(ctx, scope, cmd, correlationID)
}

// transactCommit is the part of Transact after the read-first replay check: the one control
// transition that applies cmd.
func (s *Store) transactCommit(ctx context.Context, scope auth.Scope, cmd Command, correlationID model.ID) (Result, error) {
	var out Result
	legacy := false
	// A rule command of a file that keeps the rule facts in the ledger commits as the records of its own rule (rule_ledger.go).
	if CommandKind(cmd.Kind) == KindApplyRuleEvaluation {
		if res, handled, err := s.transactRule(ctx, scope, &cmd); handled {
			return res, err
		}
	}
	// A retention command carries the caller's view as a range ([AuthorityRevision, Revision], see
	// expectedRevisionOK), so a proposal that lost the application-index race to an unrelated write
	// is judged again against the new state instead of failing the caller: without this a deletion
	// Begin submitted through a voter that does not lead lost 75-88% of its proposals while intake
	// ran on every voter (10.05 review, F-10.05-1).
	if retentionKinds[CommandKind(cmd.Kind)] {
		ctx = retryLostProposals(ctx)
	}
	// apply is the transition of the command. checkpoint is called once every check that only reads
	// the state has passed and before the first write: a retention command of an organization is
	// committed through the per-organization writer (updateOrgScoped), which names the organization there.
	apply := func(st *State, checkpoint func()) error {
		if err := scope.ValidateControlState(*st); err != nil {
			return err
		}
		binding := scope.PrincipalID().String() + ":" + scope.OrgID().String() + ":" + cmd.Kind
		if v, ok := st.Commands[cmd.CommandID.String()]; ok {
			if st.CommandOwners[cmd.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			out = v
			return errReplayed
		}
		if !expectedRevisionOK(st, scope.OrgID(), cmd.Kind, cmd.ExpectedRevision) {
			legacy = retentionKinds[CommandKind(cmd.Kind)] && st.AuthorityRevision == 0 && st.Revision > 0
			return model.Fail(model.Conflict)
		}
		checkpoint()
		var effect Effect
		switch cmd.Kind {
		case "Audit":
			var a Audit
			if e := json.Unmarshal(cmd.Payload, &a); e != nil {
				return model.Fail(model.Invalid)
			}
			a.RequestID = correlationID
			a.Outcome = model.AuditAllowed
			a.Principal = scope.PrincipalID()
			a.Org = scope.OrgID().String()
			a.PolicyEpoch = scope.PolicyEpoch()
			st.Audits = append(st.Audits, a)
		default:
			handler := s.handler(CommandKind(cmd.Kind))
			if handler == nil {
				return model.Fail(model.Unsupported)
			}
			var err error
			effect, err = handler(scope, st, cmd)
			if err != nil {
				return err
			}
		}
		out = Result{AffectedIDs: append([]model.ID(nil), effect.AffectedIDs...), Phase: effect.Phase, Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		st.CommandOwners[cmd.CommandID.String()] = binding
		st.Commands[cmd.CommandID.String()] = out
		return nil
	}
	var e error
	if retentionKinds[CommandKind(cmd.Kind)] && scope.OrgID() != (model.ID{}) {
		// The deletion saga, holds and retention policies of one organization write rows it owns: when
		// that is all the commit changed, it moves the organization's own authority revision and leaves
		// the installation's alone (F-10.05-2), so another organization's views are not made stale by it.
		// Judged by what it changed in every member, the applied-command log included (booksOfOrg), it is
		// given the whole log rather than the records of its own command (withCommandKey): a record it
		// removes or edits is then a write the commit sees, and it moves the installation-wide revision.
		e = s.updateOrgScoped(ctx, orgRetention, func(st *State, name func(model.ID)) error {
			return apply(st, func() { name(scope.OrgID()) })
		})
	} else {
		ctx = withCommandKey(ctx, cmd.CommandID.String()) // applies one command: reads and writes its records and no other
		members := membersOfKind(cmd)
		if CommandKind(cmd.Kind) == KindApplyRuleEvaluation && s.ruleLedger.Load() {
			members |= scopeRules // the arms the plan leaves to the funnel (retirement, catalogue, late erasure) read and write the rule facts
		}
		if members&scopeBooks == 0 {
			// The handler commits an effect: when a finished deletion exists it re-runs the erasure over the books
			// too (eraseLateEffect), so it is given them then (replicatedUpdateOnce).
			ctx = context.WithValue(ctx, lateErasureBooksKey{}, true)
		}
		e = s.update(ctx, transactBumps(cmd.Kind), members, func(st *State) error { return apply(st, func() {}) })
	}
	if legacy {
		if f := (*model.Fault)(nil); errors.As(e, &f) && f.Code == model.Conflict {
			// A state written before AuthorityRevision existed: stamp it so the caller's retry
			// is judged against a real floor. The caller still gets this Conflict.
			if err := s.healLegacyAuthority(ctx); err != nil {
				return out, err
			}
		}
	}
	if errors.Is(e, errReplayed) {
		e = nil
	}
	return out, e
}
func Random() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func Hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
