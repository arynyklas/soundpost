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
	bolt "go.etcd.io/bbolt"
	"os"
	"path/filepath"
	"soundpost/internal/auth"
	"soundpost/internal/durablefs"
	"soundpost/internal/model"
	"sync"
	"time"
)

type Store struct {
	db         *bolt.DB
	dir        string
	registryMu sync.RWMutex
	keyMu      sync.Mutex
	ownerProof AdmissionProofs
	handlers   map[CommandKind]Handler
	updateMu   sync.Mutex
	repl       *replicatedControl
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
	s := &Store{db: db, dir: dir}
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
		if e = b.Put([]byte("state"), v); e != nil {
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
			return replicaFault(err)
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

// Update commits fn as one control transition. It is an authority transition: it moves
// AuthorityRevision. The writers that are known not to change authority go through updateAs.
func (s *Store) Update(ctx context.Context, fn func(*State) error) error {
	return s.update(ctx, true, fn)
}
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
	legacy := false
	e := s.update(ctx, transactBumps(cmd.Kind), func(st *State) error {
		if err := scope.ValidateControlState(*st); err != nil {
			return err
		}
		binding := scope.PrincipalID().String() + ":" + scope.OrgID().String() + ":" + cmd.Kind
		if v, ok := st.Commands[cmd.CommandID.String()]; ok {
			if st.CommandOwners[cmd.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			out = v
			return nil
		}
		if !expectedRevisionOK(st, cmd.Kind, cmd.ExpectedRevision) {
			legacy = retentionKinds[CommandKind(cmd.Kind)] && st.AuthorityRevision == 0 && st.Revision > 0
			return model.Fail(model.Conflict)
		}
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
	})
	if legacy {
		if f := (*model.Fault)(nil); errors.As(e, &f) && f.Code == model.Conflict {
			// A state written before AuthorityRevision existed: stamp it so the caller's retry
			// is judged against a real floor. The caller still gets this Conflict.
			if err := s.healLegacyAuthority(ctx); err != nil {
				return out, err
			}
		}
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
