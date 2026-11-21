// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
	bolt "go.etcd.io/bbolt"
)

// The control Raft journal redaction (RedactRetainedControlCommands) and the control.db scrub
// (ScrubErased) are per voter: each node rewrites and zeroes only its own files, and
// ResidualStores reports only the answering node. A receipt built from that alone would stop
// naming control_raft_journal and control_state while another voter (down, partitioned, lagging,
// or whose worker has not run) still holds the erased payload in its ready.wal, snapshot
// directories, pin archives or control.db free pages.
//
// This file adds the cluster view. A voter that proved its OWN journal and scrubbed its OWN file
// writes an attestation into the replicated control state, and ClusterResidualStores (the list
// the retention receipt carries) names the control stores until every node of the group's
// committed configuration has a valid one.
//
// Where it lives. One record per node, a resident of State.OIDC under attestKeyPrefix (the map
// is the control state's documented home for records that are not logins: elevation records and
// the restore stash live there, and no sweep touches a key with a colon that is not an elevation
// record). No model change is needed and the canonical encoding of a state without erasures is
// unchanged. The record is a closed DTO (residueAttestation, decoded strictly).
//
// What it says. Per fact (Journal: this node's raft journal, snapshots, retained commands and
// pins hold none of the payloads of the Erasures erasing audits committed so far; State: this
// node's control.db free pages were zeroed after them and the local scrub marker is settled)
// the number of erasing audits the proof covered and the applied index the proposer had when it
// wrote it. A fact covers every erasing audit up to its number, so it answers the receipt of any
// deletion whose erasing audit is among them (ClusterOperationResidual): a later erasure owes
// its own proof and re-owes only the deletions it adds, never an earlier one whose proof every
// node already holds. The retention worker reconciles the record against the node's local truth
// for the number it states (reconcileAttestation keeps a fact the node can still prove).
//
// What it must not outlive. An attestation is a statement about files, and some events make
// the statement false without adding an erasing audit: a snapshot install (the file is
// replaced, its marker owes, the leader's retry table is not covered by any local pass) and a
// stale control command committed after the pass (it carries the state it was built from, and
// the group drops its in-memory proof). The voter withdraws its own facts in those cases:
// replica.ProofWatcher tells the control machine when the proof is gone, and a goroutine of the
// store (withdrawLoop) reconciles the record with this node's own local truth at once, retrying
// until it commits; the retention worker reconciles it again on every pass.
//
// The window between the event and that commit is closed by the index, not by the commit. A
// stale command is committed at one replica index on every node, and every node stores it
// (staleAppliedKey, in the same transaction that rejects the command): a journal fact whose
// proposer had applied less than that index is not valid, so a receipt answered by any node that
// applied the stale command never trusts an attestation made before it, whether or not the
// withdrawal has committed. A snapshot install is local to the installing node and only that
// node learns of it (installAt): its own receipt never trusts its own earlier record; the other
// nodes cannot see the install before the withdrawal commits (see docs/privacy/retention.md).
//
// Who can write it. There is no CommandKind for it, so no client scope and no Transact reaches
// it (Transact refuses an unknown kind), and guardAttestations refuses any other writer (a
// Transact handler, Store.Update, UpdateReplayIndex) that adds or changes an attestation: only
// syncAttestation, which takes no node argument and names the node from the replica group's own
// identity, may. A write is accepted only for a node that is in the committed configuration and
// only for facts this node measures as true when the transition runs.

// attestKeyPrefix is the st.OIDC key prefix of attestation records: attestKeyPrefix + the
// decimal replica node ID.
const attestKeyPrefix = "control_attest:"

// attestedFact is one statement of an attestation.
type attestedFact struct {
	// Erasures is the number of erasing audits of the control log the proof covered.
	Erasures uint64 `json:"erasures"`
	// Applied is the replica applied index of the proposer when it wrote the record.
	Applied uint64 `json:"applied"`
}

// residueAttestation is the closed DTO of one node's record.
type residueAttestation struct {
	Node     uint64        `json:"node"`
	Identity string        `json:"identity"`
	Journal  *attestedFact `json:"journal,omitempty"`
	State    *attestedFact `json:"state,omitempty"`
}

func attestKey(node uint64) string { return attestKeyPrefix + strconv.FormatUint(node, 10) }

func memberByID(m replica.Members, id uint64) (replica.Member, bool) {
	for _, n := range m.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return replica.Member{}, false
}

// factHolds is the validity of one statement for a deletion whose erasing audit is the need-th:
// the proof covered at least that many erasing audits and no more than exist (a fact for erasures
// the state does not hold is not a fact), and its proposer had applied at least floor (the index
// of the last event that made an earlier proof false, see attestFloors).
func factHolds(f *attestedFact, need, total, floor uint64) bool {
	return f != nil && f.Erasures >= need && f.Erasures <= total && f.Applied != 0 && f.Applied >= floor
}

// clusterUnattested says, from the committed state and the committed configuration alone,
// which fact some node of the group (except skip, a node the caller judges from its own
// files) has not validly attested for the need-th erasing audit and everything before it. A
// node counts when it is in the configuration, voter or learner (a learner receives the
// payload by snapshot and keeps the same files); its record counts when it decodes strictly,
// names that node and its node identity (a node replaced under the same ID must attest again)
// and states the fact for at least that many erasures; a journal fact must also have been
// written by a proposer that applied the stale command committed at index stale (the last one
// this node applied, 0 for none). An unknown configuration (no node) is unattested.
func clusterUnattested(st State, members replica.Members, need, stale, skip uint64) (journal, state bool) {
	if len(members.Nodes) == 0 {
		return true, true
	}
	for _, n := range members.Nodes {
		if n.ID == skip {
			continue
		}
		var a residueAttestation
		raw, ok := st.OIDC[attestKey(n.ID)]
		if !ok || model.StrictJSON(raw, &a) != nil || a.Node != n.ID || a.Identity != n.NodeIdentity {
			return true, true
		}
		total := uint64(erasureCount(st.Audits))
		journal = journal || !factHolds(a.Journal, need, total, stale)
		state = state || !factHolds(a.State, need, total, 0)
	}
	return journal, state
}

var staleAppliedKey = []byte("stale_applied")

// staleCutoff is the replica index of the last stale control command this node applied (0 for
// none or an unreadable record: the caller then trusts no older index than the record carries,
// and a record that cannot be read is reported by the state read it follows).
func (s *Store) staleCutoff() uint64 {
	var at uint64
	_ = s.db.View(func(tx *bolt.Tx) error {
		at = readWatermark(tx.Bucket([]byte("replica_control")).Get(staleAppliedKey))
		return nil
	})
	return at
}

// attestFloors are the applied indexes below which this node does not trust a record it (or
// another node) wrote: a stale command drops every node's journal proof; a snapshot install
// replaces this node's own files, journal and control.db.
func (s *Store) attestFloors() (journal, state uint64) {
	journal = s.staleCutoff()
	if m := s.repl; m != nil {
		install := m.installAt.Load()
		if install > journal {
			journal = install
		}
		state = install
	}
	return journal, state
}

// erasureOrdinal is the position among the erasing audits of the last one that names op (0 when
// none does: the deletion erased nothing from the control state).
func erasureOrdinal(audits []model.ControlAudit, op model.ID) uint64 {
	var n, last uint64
	for _, a := range audits {
		if a.Action != controlErasedAction {
			continue
		}
		n++
		for _, id := range a.Targets {
			if id == op {
				last = n
			}
		}
	}
	return last
}

// journalOwedFor reports whether this node's journal is not proven free of the payloads of the
// first covered erasing audits: one of the deletions they name is unfinished, or no pass of this
// process covers that many, or the group reports residue (replica.Group.MachineResidue).
func (s *Store) journalOwedFor(st State, g *replica.Group, covered uint64) bool {
	var n uint64
	for _, a := range st.Audits {
		if a.Action != controlErasedAction {
			continue
		}
		if n++; n > covered {
			break
		}
		for _, id := range a.Targets {
			op, ok := st.Deletions[id.String()]
			if !ok || op.Phase != model.DeletePhaseComplete && op.Phase != model.DeletePhaseFailed {
				return true
			}
		}
	}
	residue, err := g.MachineResidue(covered)
	return err != nil || len(residue) != 0
}

// ClusterResidualStores is the residual list for the control store whatever the deletion: everything
// ResidualStores names for this node, plus control_raft_journal and control_state for as long as any
// node of the control group's committed configuration has not attested (AttestControlResidue)
// the matching fact for every erasure committed so far. Without a replication group the local
// list is the whole answer. It reads this node's committed state and never blocks on
// consensus. A state that cannot be read, or a configuration that is not known, names both.
// A deletion receipt asks ClusterOperationResidual instead, which answers for one operation.
func (s *Store) ClusterResidualStores() []string {
	local := s.ResidualStores()
	g := s.ReplicaGroup()
	if g == nil {
		return local
	}
	st, err := s.localState()
	if err != nil {
		return []string{ResidualControlJournal, ResidualControlState}
	}
	erasures := uint64(erasureCount(st.Audits))
	if erasures == 0 {
		return local
	}
	// The cutoff is read after the state: a stale command applied in between only raises it.
	journal, state := clusterUnattested(st, g.Status().Members, erasures, s.staleCutoff(), 0)
	var out []string
	for _, name := range []string{ResidualControlJournal, ResidualControlState} {
		have := false
		for _, l := range local {
			have = have || l == name
		}
		if have || name == ResidualControlJournal && journal || name == ResidualControlState && state {
			out = append(out, name)
		}
	}
	return out
}

// ClusterOperationResidual is the control store's part of the receipt of one deletion: it names
// control_raft_journal and control_state only for what the erasure of THAT operation still owes
// on some node of the control group. The operation's erasing audit is the need-th; a node has
// paid when it attested (or, for this node, proves now) the proof for at least need erasing
// audits, so a later deletion that is still being cleaned does not make an earlier receipt name
// stores it never wrote to. A deletion whose erasure dropped nothing from the control state owes
// nothing here. This node is judged from its own files (journalOwedFor, the scrub debt of the
// operation, and the local scrub marker unless its own record covers need and no install since),
// the others from their records (clusterUnattested): a record written before the last stale
// command, or one that does not cover need, does not count. Without a replication group the
// local list answers; a state that cannot be read names both.
func (s *Store) ClusterOperationResidual(op model.ID) []string {
	g := s.ReplicaGroup()
	if g == nil {
		return s.ResidualStores()
	}
	st, local, err := s.scrubState()
	if err != nil {
		return []string{ResidualControlJournal, ResidualControlState}
	}
	need := erasureOrdinal(st.Audits, op)
	if need == 0 {
		return nil
	}
	status := g.Status()
	self, ok := memberByID(status.Members, status.ID)
	if !ok {
		return []string{ResidualControlJournal, ResidualControlState}
	}
	journal, state := clusterUnattested(st, status.Members, need, s.staleCutoff(), self.ID)
	journal = journal || s.journalOwedFor(st, g, need)
	if _, debt := owedScrubs(st.Audits)[op]; debt {
		state = true
	} else if local.owed {
		var own residueAttestation
		raw, has := st.OIDC[attestKey(self.ID)]
		_, stateFloor := s.attestFloors()
		proven := has && model.StrictJSON(raw, &own) == nil && own.Node == self.ID && own.Identity == self.NodeIdentity &&
			factHolds(own.State, need, uint64(erasureCount(st.Audits)), stateFloor) && s.repl != nil && s.repl.settled.Load()
		state = state || !proven
	}
	var out []string
	if journal {
		out = append(out, ResidualControlJournal)
	}
	if state {
		out = append(out, ResidualControlState)
	}
	return out
}

// AttestControlResidue makes this node's attestation record say exactly what this node can
// prove right now: for every erasure committed so far it states the journal fact when
// ResidualStores does not name the control journal, the state fact when it does not name
// control.db, and withdraws a fact that no longer holds or no longer covers the current number
// of erasures. It commits nothing when the record already says that (the common case, so a
// worker that calls it every pass costs one local read), never states a fact this node does
// not measure as true when the transition runs, and never writes for another node. The
// retention worker calls it after ScrubErased and RedactRetainedControlCommands.
func (s *Store) AttestControlResidue(ctx context.Context) error {
	return s.syncAttestation(ctx, true)
}

// reconcileAttestation brings this node's record in st to the node's local truth, and drops
// the records of nodes that are not in the committed configuration. publish false only
// withdraws. It reports whether st changed. It reads this node's residue (ResidualStores) and
// the group's own identity; no argument names a node.
func (s *Store) reconcileAttestation(g *replica.Group, st *State, publish bool) (bool, error) {
	status := g.Status()
	self, ok := memberByID(status.Members, status.ID)
	if !ok {
		return false, model.Fail(model.NotFound) // not in the committed configuration: never attests
	}
	changed := false
	for key := range st.OIDC {
		if !strings.HasPrefix(key, attestKeyPrefix) {
			continue
		}
		if _, member := memberKeyID(status.Members, key); !member {
			delete(st.OIDC, key)
			changed = true
		}
	}
	key := attestKey(self.ID)
	raw, had := st.OIDC[key]
	var current residueAttestation
	if had && (model.StrictJSON(raw, &current) != nil || current.Node != self.ID || current.Identity != self.NodeIdentity) {
		current = residueAttestation{}
	}
	next := residueAttestation{Node: self.ID, Identity: self.NodeIdentity}
	if erasures := uint64(erasureCount(st.Audits)); erasures > 0 {
		local := s.ResidualStores()
		m := s.repl
		journalFloor, stateFloor := s.attestFloors()
		// hold is what the record says for one store: the fact the node proves now (published when
		// it has none that still holds), or, while a later erasure owes the node a proof it has not
		// made yet, the older fact that the node can still prove for the erasures it covers.
		hold := func(old *attestedFact, name string, floor uint64, stillProven func(covered uint64) bool) *attestedFact {
			named := false
			for _, l := range local {
				named = named || l == name
			}
			if !named {
				if old != nil && old.Erasures == erasures && old.Applied >= floor {
					return old
				}
				if !publish {
					return nil
				}
				return &attestedFact{Erasures: erasures, Applied: status.Applied}
			}
			if old != nil && old.Erasures < erasures && old.Applied >= floor && m != nil && m.settled.Load() && stillProven(old.Erasures) {
				return old
			}
			return nil
		}
		next.Journal = hold(current.Journal, ResidualControlJournal, journalFloor, func(covered uint64) bool {
			return !s.journalOwedFor(*st, g, covered)
		})
		next.State = hold(current.State, ResidualControlState, stateFloor, func(uint64) bool { return true })
	}
	if m := s.repl; m != nil {
		m.settled.Store(true)
	}
	if next.Journal == nil && next.State == nil {
		if had {
			delete(st.OIDC, key)
			changed = true
		}
		return changed, nil
	}
	encoded, err := json.Marshal(next)
	if err != nil {
		return false, err
	}
	if had && bytes.Equal(raw, encoded) {
		return changed, nil
	}
	if st.OIDC == nil {
		st.OIDC = map[string]json.RawMessage{}
	}
	st.OIDC[key] = encoded
	return true, nil
}

// memberKeyID reports whether key is the attestation key of a node of the configuration.
func memberKeyID(m replica.Members, key string) (uint64, bool) {
	for _, n := range m.Nodes {
		if attestKey(n.ID) == key {
			return n.ID, true
		}
	}
	return 0, false
}

// syncAttestation is the one writer of attestation records (see the file comment).
func (s *Store) syncAttestation(ctx context.Context, publish bool) error {
	g := s.ReplicaGroup()
	if g == nil {
		return nil
	}
	// The local precheck: nothing to say and nothing to withdraw commits nothing.
	local, err := s.localState()
	if err != nil {
		return err
	}
	changed, err := s.reconcileAttestation(g, &local, publish)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	err = s.updateAsGuarded(ctx, writerAttestControl, stateWithoutAttestations, func(st *State) error {
		changed, err := s.reconcileAttestation(g, st, publish)
		if err != nil {
			return err
		}
		if !changed {
			return errNothingToSettle
		}
		return nil
	})
	if errors.Is(err, errNothingToSettle) {
		return nil
	}
	return err
}

// stateWithoutAttestations is the canonical encoding of st with the attestation records
// removed: what updateAsGuarded compares to decide that an attestation write changed nothing
// that could matter to authority. OIDC is copied, never mutated.
func stateWithoutAttestations(st *State) ([]byte, error) {
	masked := *st
	masked.OIDC = make(map[string]json.RawMessage, len(st.OIDC))
	for k, v := range st.OIDC {
		if !strings.HasPrefix(k, attestKeyPrefix) {
			masked.OIDC[k] = v
		}
	}
	return json.Marshal(masked)
}

// guardAttestations wraps the transition of every writer but syncAttestation: it refuses (and
// so commits nothing) when the transition adds an attestation record or changes one. Deleting
// one is allowed: that can only make a receipt name more. It is what keeps a Transact handler,
// an exported Update or UpdateReplayIndex from forging evidence that a node is clean.
func guardAttestations(fn func(*State) error) func(*State) error {
	return func(st *State) error {
		before := map[string]string{}
		for k, v := range st.OIDC {
			if strings.HasPrefix(k, attestKeyPrefix) {
				before[k] = string(v)
			}
		}
		if err := fn(st); err != nil {
			return err
		}
		for k, v := range st.OIDC {
			if !strings.HasPrefix(k, attestKeyPrefix) {
				continue
			}
			if old, ok := before[k]; !ok || old != string(v) {
				return model.Fail(model.Forbidden)
			}
		}
		return nil
	}
}

// ProofWithdrawn implements replica.ProofWatcher. The group calls it with its lock held when
// it drops the in-memory proof of a redaction pass (a snapshot install, a stale control
// command), so it only records the install index and signals: withdrawLoop does the work. (A
// stale command's index is stored by Apply, durably, in the transaction that rejects it.)
func (m *replicatedControl) ProofWithdrawn(w replica.ProofWithdrawal) {
	if w.Install {
		for {
			old := m.installAt.Load()
			if old >= w.Index || m.installAt.CompareAndSwap(old, w.Index) {
				break
			}
		}
	}
	select {
	case m.withdraw <- struct{}{}:
	default: // one signal is pending already: the loop reconciles against the live truth
	}
}

var _ replica.ProofWatcher = (*replicatedControl)(nil)

// withdrawLoop withdraws this node's attestation facts that stopped holding. It runs for the
// life of the replication group and retries a commit that failed (no leader yet, a lost race)
// until it commits or the store closes.
func (m *replicatedControl) withdrawLoop() {
	defer close(m.done)
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.withdraw:
		}
		for backoff := 50 * time.Millisecond; ; {
			err := m.store.syncAttestation(m.ctx, false)
			var fault *model.Fault
			if err == nil || m.ctx.Err() != nil || errors.As(err, &fault) && fault.Code == model.NotFound {
				break
			}
			select {
			case <-m.ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}
}
