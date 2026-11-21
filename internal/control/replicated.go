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
		return model.Fail(model.Stale)
	}
	if errors.Is(err, replica.ErrInvalid) {
		return model.Fail(model.Invalid)
	}
	return model.Fail(model.Unavailable)
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
		seed, err := m.Snapshot()
		if err != nil {
			return nil, err
		}
		c.Seed = seed
		var snapshot controlSnapshot
		if model.StrictJSON(seed, &snapshot) != nil {
			return nil, model.Fail(model.Corrupt)
		}
		c.Application = uint64(snapshot.State.Revision)
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

func (s *Store) replicatedUpdate(ctx context.Context, bump bool, force *bool, fn func(*State) error) error {
	attempts := 1
	if ctx.Value(lostProposalRetryKey{}) != nil {
		attempts = maxLostProposals
	}
	for attempt := 1; ; attempt++ {
		var lost bool
		err := s.replicatedUpdateOnce(ctx, bump, force, fn, &lost)
		if !lost || attempt >= attempts || ctx.Err() != nil {
			return err
		}
	}
}

// replicatedUpdateOnce is one read-compute-propose round; lost reports that the proposal was refused
// as stale (another command committed since the read).
func (s *Store) replicatedUpdateOnce(ctx context.Context, bump bool, force *bool, fn func(*State) error, lost *bool) error {
	s.updateMu.Lock()
	defer s.updateMu.Unlock()
	r := s.repl
	if _, err := r.group.ReadIndex(ctx); err != nil {
		return replicaFaultUnder(ctx, err)
	}
	var st State
	var oldRaw []byte // the encoding of the state read, kept only when the command is a patch
	patch := s.StatePatch()
	if err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("control")).Get([]byte("state"))
		if json.Unmarshal(raw, &st) != nil {
			return model.Fail(model.Corrupt)
		}
		if patch {
			oldRaw = bytes.Clone(raw)
		}
		return nil
	}); err != nil {
		return err
	}
	expected, priorAuthority, priorFloor := st.Revision, st.AuthorityRevision, installationFloor(&st)
	if err := fn(&st); err != nil {
		return err
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
	switch scope, _ := ctx.Value(orgScopeKey{}).(*orgScope); {
	case bump || force != nil && *force:
		st.AuthorityRevision = st.Revision
	case scope != nil && oldRaw != nil && scope.named:
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
	payload, err := s.controlPayload(oldRaw, newRaw, expected, &st, keys)
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
func (m *replicatedControl) Apply(c replica.CommittedEntry) error {
	if c.Entry.Kind != replica.Noop && c.Index <= m.Applied() {
		rejected := false
		if err := m.store.db.View(func(tx *bolt.Tx) error {
			rejected = tx.Bucket([]byte("replica_control")).Get([]byte("rejected:"+c.Entry.ID.String())) != nil
			return nil
		}); err != nil {
			return err
		}
		if !rejected {
			cmd, err := decodeControlCommand(c.Entry.Payload)
			if err != nil {
				return model.Fail(model.Corrupt)
			}
			switch {
			case cmd.delta != nil:
				err = m.verifyCurrentDelta(*cmd.delta)
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
	if c.Index > m.Applied() && c.Entry.Kind != replica.Noop {
		cmd, err := decodeControlCommand(c.Entry.Payload)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		// A delta carries no key files: only a replacement and a patch install them.
		var keys map[string][]byte
		switch {
		case cmd.replacement != nil:
			keys = cmd.replacement.Keys
		case cmd.patch != nil:
			keys = cmd.patch.Keys
		}
		if cmd.delta == nil {
			if err := m.store.installReplicaKeys(keys); err != nil {
				return err
			}
		}
	}
	rejected := false
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
		rawState := b.Get([]byte("state"))
		// The state is decoded only when a command cannot be applied to its bytes (stateRoot, patchRaw):
		// a patch, an audit delta, a stale rejection and a no-op leave every member they do not name as
		// it is, and decoding and encoding tens of megabytes for them is what a voter paid per command.
		root := scanStateRoot(rawState)
		var current State
		loaded := false
		load := func() error {
			if !loaded {
				if json.Unmarshal(rawState, &current) != nil {
					return model.Fail(model.Corrupt)
				}
				loaded = true
			}
			return nil
		}
		installation0, revision0 := root.installation, root.revision
		if !root.ok {
			if err := load(); err != nil {
				return err
			}
			installation0, revision0 = current.Installation, current.Revision
		}
		revisionAfter := revision0
		owe := false
		if c.Entry.Kind != replica.Noop {
			if c.Entry.Kind != replica.Control {
				return model.Fail(model.Corrupt)
			}
			cmd, derr := decodeControlCommand(c.Entry.Payload)
			if derr != nil {
				return model.Fail(model.Corrupt)
			}
			var installation model.ID
			var expected model.Revision
			if cmd.delta != nil {
				installation, expected = cmd.delta.Installation, cmd.delta.Expected
			} else if cmd.patch != nil {
				installation, expected = cmd.patch.Installation, cmd.patch.Expected
			} else {
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
			if expected != revision0 {
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
				if out, _, ok := patchRaw(rawState, root, []patchOp{revisionOp(revisionAfter)}); ok {
					next = out
				} else {
					if err := load(); err != nil {
						return err
					}
					current.Revision = revisionAfter
				}
			} else if cmd.delta != nil {
				owe = erasureCount(cmd.delta.Audits) > 0
				revisionAfter = cmd.delta.Expected + 1
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
					base, ok := "", false
					if root.ok {
						base, ok = patchBaseRoot(rawState, root)
					} else {
						var err error
						base, err = patchBase(rawState)
						ok = err == nil
					}
					if !ok || base != p.Base {
						return model.Fail(model.Corrupt)
					}
				}
				if out, eff, ok := patchRaw(rawState, root, p.Ops); ok && eff.revisionSet && eff.revision == p.Expected+1 {
					next = out
					owe = eff.erasures > 0
					settled = eff.settled
					revisionAfter = eff.revision
				} else {
					if err := load(); err != nil {
						return err
					}
					patched, perr := patchedState(rawState, &current, p)
					if perr != nil {
						return perr
					}
					owe = erasureCount(patched.Audits) > erasureCount(current.Audits)
					current = patched
				}
			} else {
				// An erasing audit this commit adds means it frees the pages that held what was
				// erased: this file owes a scrub whatever any later record says another node did.
				if err := load(); err != nil {
					return err
				}
				owe = erasureCount(cmd.replacement.State.Audits) > erasureCount(current.Audits)
				current = cmd.replacement.State
			}
			spliced := next != nil
			if !spliced {
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
			if e := putState(b, next); e != nil {
				return e
			}
			if spliced {
				m.store.rawApplies.Add(1)
			} else {
				m.store.decodedApplies.Add(1)
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
	out := controlSnapshot{Keys: map[string][]byte{}, Metadata: map[string][]byte{}}
	if err := s.db.View(func(tx *bolt.Tx) error {
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &out.State) != nil {
			return model.Fail(model.Corrupt)
		}
		if b := tx.Bucket([]byte("replica_control")); b != nil {
			return b.ForEach(func(k, v []byte) error { out.Metadata[string(k)] = bytes.Clone(v); return nil })
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
			out.Keys[name] = raw
		}
	}
	return json.Marshal(out)
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
	var snapshot controlSnapshot
	if model.StrictJSON(raw, &snapshot) != nil || snapshot.State.Installation == (model.ID{}) {
		return model.Fail(model.Corrupt)
	}
	s := m.store
	keys, err := s.installKeys(snapshot.Keys)
	if err != nil {
		return err
	}
	if err = s.db.Update(func(tx *bolt.Tx) error {
		if owe {
			if err := oweInstalledScrub(tx.Bucket([]byte("control")), snapshot.State); err != nil {
				return err
			}
		}
		b, err := tx.CreateBucketIfNotExists([]byte("replica_control"))
		if err != nil {
			return err
		}
		state, err := json.Marshal(snapshot.State)
		if err != nil {
			return err
		}
		if err = putState(tx.Bucket([]byte("control")), state); err != nil {
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
	return nil
}

// ReconcileAdmissions uses the one installed owner's durable outcome proof and
// does not require a live source credential. It never refunds a reserved charge.
func (s *Store) ReconcileAdmissions(ctx context.Context) error {
	s.registryMu.RLock()
	owner := s.ownerProof
	s.registryMu.RUnlock()
	if owner == nil {
		return model.Fail(model.Unavailable)
	}
	type outcomes interface {
		AdmissionOutcomes(context.Context) ([]model.FinalizeAdmission, error)
	}
	installed, ok := owner.(outcomes)
	if !ok {
		return model.Fail(model.Unavailable)
	}
	proofs, err := installed.AdmissionOutcomes(ctx)
	if err != nil {
		return err
	}
	// One linearizable read decides which outcomes still need a commit: a reservation control
	// holds that has no cursor yet. An outcome whose reservation control no longer holds is fine
	// only when its cursor lies in a settled window (settle.go): its charge is folded already.
	var pending []model.FinalizeAdmission
	if err = s.View(ctx, func(st State) error {
		for _, proof := range proofs {
			old, ok := st.Reservations[proof.ReservationID.String()]
			if !ok {
				if _, settled := st.Settlement.Window(proof.Cursor); settled {
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
	for _, proof := range pending {
		if err = owner.VerifyFinalization(ctx, proof); err != nil {
			return err
		}
		if err = s.updateAs(ctx, writerReconcileAdmissions, func(st *State) error {
			old, ok := st.Reservations[proof.ReservationID.String()]
			if !ok || old.State == "cancelled" {
				return model.Fail(model.Corrupt)
			}
			if old.Cursor != nil && *old.Cursor != proof.Cursor {
				return model.Fail(model.Conflict)
			}
			old.State = "consumed"
			cursor := proof.Cursor
			old.Cursor = &cursor
			st.Reservations[old.ID.String()] = old
			return nil
		}); err != nil {
			return err
		}
	}
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
			if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &st) != nil {
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
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: &trackedDB{DB: db}, dir: dir}
	if err = durablefs.SyncFileAndDir(path); err != nil {
		db.Close()
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucket([]byte("control"))
		if e != nil {
			return e
		}
		state, e := json.Marshal(seed.State)
		if e != nil {
			return e
		}
		if e = putState(b, state); e != nil {
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
	return m.store.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("control")).Get([]byte("state"))
		root := scanStateRoot(raw)
		installation0, revision0 := root.installation, root.revision
		if !root.ok {
			var current State
			if json.Unmarshal(raw, &current) != nil {
				return model.Fail(model.Corrupt)
			}
			installation0, revision0 = current.Installation, current.Revision
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
			base, ok := "", false
			if root.ok {
				base, ok = patchBaseRoot(raw, root)
			} else {
				var err error
				base, err = patchBase(raw)
				ok = err == nil
			}
			if !ok || base != cmd.patch.Base {
				return model.Fail(model.Stale)
			}
		}
		return nil
	})
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
		if bucket == nil || json.Unmarshal(bucket.Get([]byte("state")), &st) != nil {
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
		if bucket == nil || json.Unmarshal(bucket.Get([]byte("state")), &state) != nil {
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
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &current) != nil {
			return model.Fail(model.Corrupt)
		}
		if current.Installation != expected.Installation || current.Revision < expected.Revision {
			return model.Fail(model.Corrupt)
		}
		if current.Revision != expected.Revision {
			return nil
		}
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
		if json.Unmarshal(tx.Bucket([]byte("control")).Get([]byte("state")), &current) != nil {
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
	return s.View(ctx, func(st State) error {
		if err := replicaSource(st, b.Org, b.Project, b.Source, b.PolicyEpoch, b.PolicyRevision, true); err != nil {
			return err
		}
		r, ok := st.Reservations[b.Reservation.ID.String()]
		if !ok || r.State != "reserved" || r.Hash != b.Hash || r.Batch != b.ID || r.Org != b.Org || r.Project != b.Project || r.Source != b.Source || r.Producer != b.Producer || r.Slot != b.RouteSlot {
			return model.Fail(model.Forbidden)
		}
		a, err := model.CanonicalJSON(r)
		if err != nil {
			return model.Fail(model.Corrupt)
		}
		supplied, err := model.CanonicalJSON(b.Reservation)
		if err != nil || !bytes.Equal(a, supplied) {
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
	return s.View(ctx, func(st State) error {
		r, ok := st.Reservations[c.ReservationID.String()]
		if !ok || r.Hash != c.Hash || r.State != "reserved" {
			return model.Fail(model.Conflict)
		}
		return nil
	})
}
