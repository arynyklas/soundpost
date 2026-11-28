// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"

	bolt "go.etcd.io/bbolt"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// SetLayoutSupportGate installs the function that names the members of the control group whose
// RUNNING binary does not read the contracted index layout (the sharded artifact ledger index and
// the per-replay pins without the per-project values the previous release reads, D70). Contracting
// (auth.Service.ContractIndexes) asks it. Passing nil removes it.
func (s *Store) SetLayoutSupportGate(lacking func() []string) {
	if lacking == nil {
		s.layoutSupportGate.Store(nil)
		return
	}
	s.layoutSupportGate.Store(&lacking)
}

// MembersLackingLayout names the members that do not support the contracted index layout; without
// a gate it answers with one entry, "unknown", so a caller that needs every member to support it
// refuses (fail closed).
func (s *Store) MembersLackingLayout() []string {
	gate := s.layoutSupportGate.Load()
	if gate == nil {
		return []string{"unknown"}
	}
	return (*gate)()
}

// LayoutIncompatiblePrefix starts the typed reason of a member whose running binary cannot read the
// installation's contracted layout; the node identity follows it.
const LayoutIncompatiblePrefix = "layout_incompatible:"

// LayoutIncompatible is the typed refusal that names a member that cannot read the contracted
// layout (model.Unsupported, SafeDetail "layout_incompatible:<identity>"), the way the contraction
// step names the members that do not support it.
func LayoutIncompatible(m replica.Member) error {
	return &model.Fault{Code: model.Unsupported, SafeDetail: LayoutIncompatiblePrefix + m.NodeIdentity, RequestID: model.NewID()}
}

// SetMemberLayoutQuery installs the live question to one member: nil when the RUNNING binary of the
// member answers that it reads the contracted index layout, an error for every other outcome (it does
// not implement the question, it is down, it does not answer in time). Passing nil removes it.
func (s *Store) SetMemberLayoutQuery(query func(context.Context, replica.Member) error) {
	if query == nil {
		s.memberLayoutQuery.Store(nil)
		return
	}
	s.memberLayoutQuery.Store(&query)
}

// SetMemberRuleLedgerQuery installs the live question to one member whether its RUNNING binary reads the rule books and the
// rule outbox as records of the ledger (D108): nil when it answers that it does, an error for every other outcome. It is asked
// of a member only once the installation carries the mark (model.RuleLedgerKey); without one nobody answers (fail closed).
// Passing nil removes it.
func (s *Store) SetMemberRuleLedgerQuery(query func(context.Context, replica.Member) error) {
	if query == nil {
		s.memberRuleLedgerQuery.Store(nil)
		return
	}
	s.memberRuleLedgerQuery.Store(&query)
}

// indexesContracted reports whether any organization of the installation is contracted
// (`soundpost upgrade contract-indexes` ran, or the organization was created after it). From that
// point a member whose binary does not read the contracted layout reports the ledgers and replays it
// reads in it corrupt. It looks for the marker key in the stored state of this node, without a quorum
// read and without decoding the state: a snapshot guard runs on every snapshot attempt of a lagging
// member, under whatever write load the group has. The marker only appears (never leaves), so a read
// that is a moment behind answers false at worst for a transition that has just committed; a stored
// state that cannot be read is an error (the guards refuse).
func (s *Store) indexesContracted(ctx context.Context) (bool, error) {
	contracted, _, err := s.layoutMarks(ctx)
	return contracted, err
}

// layoutMarks is indexesContracted and, beside it, whether the stored state carries the mark of the rule ledger (D108,
// model.RuleLedgerKey): from then on a member must also read the rule facts as records. It reads the state of this node the same way.
func (s *Store) layoutMarks(ctx context.Context) (contracted, rules bool, err error) {
	if err = ctx.Err(); err != nil {
		return false, false, err
	}
	err = s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket([]byte("control")).Get([]byte("state"))
		if raw == nil {
			return model.Fail(model.Corrupt)
		}
		contracted = bytes.Contains(raw, []byte(`"`+model.IndexesContractedKey+`"`))
		rules = contracted && bytes.Contains(raw, ruleLedgerMark)
		return nil
	})
	return contracted, rules, err
}

// memberReadsLayout asks the member the live question (and, when rules says the installation carries the mark of the rule
// ledger, the one about it); without a query nobody answers (fail closed).
func (s *Store) memberReadsLayout(ctx context.Context, m replica.Member, rules bool) bool {
	query := s.memberLayoutQuery.Load()
	if query == nil || (*query)(ctx, m) != nil {
		return false
	}
	if !rules {
		return true
	}
	query = s.memberRuleLedgerQuery.Load()
	return query != nil && (*query)(ctx, m) == nil
}

// CheckMemberLayout is the guard of a member joining the installation (a membership change, a
// snapshot): nil while no organization is contracted, and afterwards only for a member whose running
// binary answers the live question. Every other outcome, including a state that cannot be read, is a
// refusal; the one that names the member is LayoutIncompatible.
func (s *Store) CheckMemberLayout(ctx context.Context, m replica.Member) error {
	return s.checkMemberLayout(ctx, m, false)
}

// CheckLearnerLayout is the guard of `membership add-learner`: CheckMemberLayout, except that a
// learner nothing is running for yet (replica.ErrMemberNotRunning: the operator adds the member to the
// configuration, then starts it, and its binary cannot be asked before it runs) is admitted. A binary
// that is running and does not answer that it reads the layout (the previous release) is refused as
// before; so is a member that is up but whose answer cannot be had. What admitting an unstarted learner
// leaves to the other guards: promoting it to voter asks again (CheckMemberLayout), the leader sends it
// no snapshot of the contracted state unless it answers (guardSnapshot), and `membership status` names it
// while it does not (MembersIncompatible).
func (s *Store) CheckLearnerLayout(ctx context.Context, m replica.Member) error {
	return s.checkMemberLayout(ctx, m, true)
}

func (s *Store) checkMemberLayout(ctx context.Context, m replica.Member, notYetRunningIsAdmitted bool) error {
	contracted, rules, err := s.layoutMarks(ctx)
	if err != nil {
		return err
	}
	if !contracted {
		return nil
	}
	asks := []*atomic.Pointer[func(context.Context, replica.Member) error]{&s.memberLayoutQuery}
	if rules {
		// The installation keeps the rule facts in the ledger (D108): a binary that reads the contracted layout and not that one
		// (every build before the move, protocol 9) holds empty rule books and cannot verify the ledger digest; it is refused
		// as the previous release is after the contraction.
		asks = append(asks, &s.memberRuleLedgerQuery)
	}
	for _, ask := range asks {
		query := ask.Load()
		if query == nil {
			return LayoutIncompatible(m)
		}
		switch err = (*query)(ctx, m); {
		case err == nil:
		case notYetRunningIsAdmitted && errors.Is(err, replica.ErrMemberNotRunning):
			return nil
		default:
			return LayoutIncompatible(m)
		}
	}
	return nil
}

// MembersIncompatible names, as "layout_incompatible:<identity>" in the order of members, every one of
// them whose running binary cannot read the contracted layout (and, once the installation carries the mark of the rule
// ledger, the rule facts as records); none while no organization is contracted. A state that cannot be read answers
// nothing (a report, not a gate).
func (s *Store) MembersIncompatible(ctx context.Context, members []replica.Member) []string {
	contracted, rules, err := s.layoutMarks(ctx)
	if err != nil || !contracted {
		return nil
	}
	reads := make([]bool, len(members))
	var wg sync.WaitGroup
	for i, m := range members {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reads[i] = s.memberReadsLayout(ctx, m, rules)
		}()
	}
	wg.Wait()
	var out []string
	for i, m := range members {
		if !reads[i] {
			out = append(out, LayoutIncompatiblePrefix+m.NodeIdentity)
		}
	}
	return out
}

// guardSnapshot is the replica.Config.SnapshotGuard of the control group: a snapshot of a contracted
// state is not sent to a member that cannot read it (the previous release installs it, reports ready
// and then answers corrupt for the ledgers and replays it cannot read). The refusal names the member.
func (m *replicatedControl) guardSnapshot(ctx context.Context, to replica.Member) error {
	return m.store.CheckMemberLayout(ctx, to)
}

// IndexesContracted is indexesContracted for the storage engine, which keeps its own query-index layout
// in step with the installation's (storage.adoptRunsLayout): true once any organization is contracted.
func (s *Store) IndexesContracted(ctx context.Context) (bool, error) { return s.indexesContracted(ctx) }
