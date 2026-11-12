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

	"soundpost/internal/model"
	"soundpost/internal/replica"
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
// wrote it. A fact is valid only for exactly the current number of erasing audits: a later
// erasure supersedes every attestation by arithmetic, with no write by anybody.
//
// What it must not outlive. An attestation is a statement about files, and some events make
// the statement false without adding an erasing audit: a snapshot install (the file is
// replaced, its marker owes, the leader's retry table is not covered by any local pass) and a
// stale control command committed after the pass (it carries the state it was built from, and
// the group drops its in-memory proof). The voter withdraws its own facts in those cases:
// replica.ProofWatcher tells the control machine when the proof is gone, and a goroutine of the
// store (withdrawLoop) reconciles the record with this node's own local truth at once, retrying
// until it commits; the retention worker reconciles it again on every pass. The window between
// the event and the commit is the one the receipt cannot see (see docs/privacy/retention.md).
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

// factHolds is the validity of one statement for the current number of erasing audits.
func factHolds(f *attestedFact, erasures uint64) bool {
	return f != nil && f.Erasures == erasures && f.Applied != 0
}

// clusterUnattested says, from the committed state and the committed configuration alone,
// which fact some node of the group has not validly attested for the given number of erasing
// audits. A node counts when it is in the configuration, voter or learner (a learner receives
// the payload by snapshot and keeps the same files); its record counts when it decodes
// strictly, names that node and its node identity (a node replaced under the same ID must
// attest again) and states the fact for exactly this number of erasures. An unknown
// configuration (no node) is unattested.
func clusterUnattested(st State, members replica.Members, erasures uint64) (journal, state bool) {
	if len(members.Nodes) == 0 {
		return true, true
	}
	for _, n := range members.Nodes {
		var a residueAttestation
		raw, ok := st.OIDC[attestKey(n.ID)]
		if !ok || model.StrictJSON(raw, &a) != nil || a.Node != n.ID || a.Identity != n.NodeIdentity {
			return true, true
		}
		journal = journal || !factHolds(a.Journal, erasures)
		state = state || !factHolds(a.State, erasures)
	}
	return journal, state
}

// ClusterResidualStores is the residual list a deletion receipt carries for the control store:
// everything ResidualStores names for this node, plus control_raft_journal and control_state
// for as long as any node of the control group's committed configuration has not attested
// (AttestControlResidue) the matching fact for every erasure committed so far. Without a
// replication group the local list is the whole answer. It reads this node's committed state
// and never blocks on consensus. A state that cannot be read, or a configuration that is not
// known, names both.
//
// It is about erasures, not about one operation: a node attests the number of erasing audits
// its proof covered, which is what both proofs are measured in, so one attestation covers every
// deletion committed before it and a later erasure re-owes all of them. That can name the
// control stores for a deletion whose own erasure every node has already cleaned (a later
// deletion is still being cleaned); it never names fewer than the truth.
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
	journal, state := clusterUnattested(st, g.Status().Members, erasures)
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
		hold := func(old *attestedFact, name string) *attestedFact {
			for _, l := range local {
				if l == name {
					return nil
				}
			}
			if old != nil && old.Erasures == erasures {
				return old
			}
			if !publish {
				return nil
			}
			return &attestedFact{Erasures: erasures, Applied: status.Applied}
		}
		next.Journal = hold(current.Journal, ResidualControlJournal)
		next.State = hold(current.State, ResidualControlState)
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
// command), so it only signals: withdrawLoop does the work.
func (m *replicatedControl) ProofWithdrawn() {
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
