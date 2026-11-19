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
	// boundedGate says whether the bounded-state rules apply (bounded_rules.go); nil: they do.
	boundedGate atomic.Pointer[func() bool]
	// auditDeltaGate says whether the audit delta command may be proposed (audit_delta.go); nil: it may not.
	auditDeltaGate atomic.Pointer[func() bool]
	// auditDeltas and auditDeltaBytes count the delta commands AppendAudit proposed and their payload
	// bytes (read by tests and benchmarks through AuditDeltaStatsForTest).
	auditDeltas, auditDeltaBytes atomic.Uint64
	// statePatchGate says whether a command may be proposed as a state patch (state_patch.go); nil:
	// it may not. statePatches and statePatchBytes count the patch commands proposed and their payload bytes.
	statePatchGate                atomic.Pointer[func() bool]
	statePatches, statePatchBytes atomic.Uint64
	// layoutSupportGate names the members of the control group whose running binary does not read
	// the contracted index layout (index_layout.go); nil: none is known to.
	layoutSupportGate atomic.Pointer[func() []string]
	// memberLayoutQuery is the live question to one member (index_layout.go); nil: none answers.
	memberLayoutQuery atomic.Pointer[func(context.Context, replica.Member) error]
	// rawApplies and decodedApplies count the committed commands this store applied to the bytes of
	// its state (stateRoot, patchRaw) and the ones it had to decode the state for (Apply).
	rawApplies, decodedApplies atomic.Uint64
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
	db, e := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if e != nil {
		return nil, e
	}
	if e = durablefs.SyncFileAndDir(filepath.Join(dir, "control.db")); e != nil {
		db.Close()
		return nil, e
	}
	s := &Store{db: &trackedDB{DB: db}, dir: dir}
	e = db.Update(func(tx *bolt.Tx) error {
		if !fresh {
			b := tx.Bucket([]byte("control"))
			if b == nil || b.Get([]byte("state")) == nil {
				return model.Fail(model.Corrupt)
			}
			return markOpenedFile(b)
		}
		b, e := tx.CreateBucketIfNotExists([]byte("control"))
		if e != nil {
			return e
		}
		if b.Get([]byte("state")) != nil {
			return markOpenedFile(b)
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
		return writeLocalScrub(b, localScrub{})
	})
	if e != nil {
		db.Close()
		return nil, e
	}
	return s, nil
}
func (s *Store) Close() error {
	if s.repl != nil {
		if err := s.repl.close(); err != nil {
			s.db.Close()
			return err
		}
	}
	return s.db.Close()
}
func (s *Store) BootstrapToken() (string, error) {
	b, e := os.ReadFile(filepath.Join(s.dir, "bootstrap.token"))
	return string(b), e
}
func (s *Store) RemoveBootstrapFile() error {
	return durablefs.Remove(filepath.Join(s.dir, "bootstrap.token"))
}
func (s *Store) View(ctx context.Context, fn func(State) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		var st State
		if e := json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &st); e != nil {
			return model.Fail(model.Corrupt)
		}
		return fn(st)
	})
}

// ViewShared is View for a reader that only reads. Instead of a decode of its own it is given the
// decode of the committed revision that every concurrent shared reader uses, through the read-only
// interface (model.ReadOnlyControl), which has no way to change it or to keep part of it: decoding
// the whole state once per read made a pass of the background workers cost O(projects squared).
// The linearizable read barrier is the same as View's, and so is the snapshot: the state is the
// one of the bolt transaction the read runs in, so a reader sees one whole revision, never a mix.
// fn must not retain the ReadOnlyControl past its return. A caller that changes what it reads, or
// needs the State itself, uses View.
func (s *Store) ViewShared(ctx context.Context, fn func(model.ReadOnlyControl) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s.repl != nil {
		if _, err := s.repl.group.ReadIndex(ctx); err != nil {
			return replicaFaultUnder(ctx, err)
		}
	}
	return s.db.View(func(tx *bolt.Tx) error {
		if d := s.db.decoded.Load(); d != nil && d.txid == tx.ID() {
			return fn(model.ReadOnlyOf(d.state))
		}
		st := new(State)
		if e := json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), st); e != nil {
			return model.Fail(model.Corrupt)
		}
		s.db.decodes.Add(1)
		s.db.publish(&decodedState{txid: tx.ID(), state: st})
		return fn(model.ReadOnlyOf(st))
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
	return s.update(ctx, true, fn)
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
	if e := s.View(ctx, func(st State) error {
		v, ok := st.Commands[cmd.CommandID.String()]
		if !ok {
			return nil
		}
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		if st.CommandOwners[cmd.CommandID.String()] != scope.PrincipalID().String()+":"+scope.OrgID().String()+":"+cmd.Kind {
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
		e = s.updateOrgScoped(ctx, orgRetention, func(st *State, name func(model.ID)) error {
			return apply(st, func() { name(scope.OrgID()) })
		})
	} else {
		e = s.update(ctx, transactBumps(cmd.Kind), func(st *State) error { return apply(st, func() {}) })
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
