// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// ContractIndexesRequest is the closed body of POST /api/v1/admin/upgrade/contract-indexes.
// CommandID names the call in the audit rows; repeating a call (the same ID or another) once every
// organization is contracted changes nothing and answers the same success.
type ContractIndexesRequest struct {
	CommandID model.ID `json:"command_id"`
	Reason    string   `json:"reason"`
}

// ContractIndexesResult is the answer of a contraction. Organizations is how many organizations this
// call contracted; Changed is false when none needed it.
type ContractIndexesResult struct {
	Organizations model.Uint64   `json:"organizations"`
	Revision      model.Revision `json:"revision"`
	Changed       bool           `json:"changed"`
}

// IndexContractor contracts one organization's indexes (appcore: refledger.Contract and
// replays.ContractPins). It reports whether it changed the organization.
type IndexContractor func(*model.ControlOrg) (bool, error)

// SetIndexContractor installs the contraction ContractIndexes applies.
func (s *Service) SetIndexContractor(c IndexContractor) { s.indexContractor.Store(&c) }

// layoutSupport is implemented by a ControlStore that can say which members of the control group do
// not run a binary that reads the contracted layout (control.Store.MembersLackingLayout).
type layoutSupport interface {
	MembersLackingLayout() []string
}

// needsContraction reports whether the organization still carries the layout of the previous release or
// is not marked contracted.
func needsContraction(o model.ControlOrg) bool {
	if !o.IndexesContracted() {
		return true
	}
	for key := range o.Settings {
		if rest, ok := strings.CutPrefix(key, model.ReplayPinKeyPrefix); ok && !strings.Contains(rest, ":") {
			return true
		}
		if rest, ok := strings.CutPrefix(key, model.ArtifactLedgerIndexKeyPrefix); ok {
			if _, err := model.ParseID(strings.TrimPrefix(rest, "anchor:")); err == nil {
				return true
			}
		}
	}
	return false
}

var errContractedMeanwhile = errors.New("organization already contracted")

// ContractIndexes is the operator step that ends the expand phase of the sharded artifact ledger index and
// the per-replay pins (D70): until it runs, a write keeps the per-project values the previous release reads
// current, so any voter can be rolled back; afterwards those values are deleted and no longer written, writes
// are O(1) in the size of a project, and a rollback of a voter needs the backup taken before the step. It is
//
//   - restricted to a system administrator on a fresh session (like create_org);
//   - refused (unsupported, naming the members) unless the running binary of every member of the control
//     group answers the live layout question over the mesh (a member that does not answer, for any
//     reason, is named; no gate at all is a refusal);
//   - audited: one row per contracted organization;
//   - idempotent: when no organization needs it, it answers success and writes nothing.
//
// Each organization is one control transition, so a project that is large does not make the command
// large; a call that stops half way is finished by repeating it.
func (s *Service) ContractIndexes(ctx context.Context, c Credential, r ContractIndexesRequest) (ContractIndexesResult, error) {
	if c.service != s || !c.Fresh() {
		return ContractIndexesResult{}, model.Fail(model.Forbidden)
	}
	if _, e := s.Authenticate(ctx, c.token); e != nil {
		return ContractIndexesResult{}, e
	}
	if r.CommandID == (model.ID{}) || r.Reason == "" || len(r.Reason) > 512 {
		return ContractIndexesResult{}, model.Fail(model.Invalid)
	}
	contractor := s.indexContractor.Load()
	if contractor == nil {
		return ContractIndexesResult{}, &model.Fault{Code: model.Unsupported, SafeDetail: "index_contraction_unavailable", RequestID: model.NewID()}
	}
	authorize := func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		u := st.Users[c.user.String()]
		if u.Disabled {
			return model.Fail(model.Unauthenticated)
		}
		if !u.Admin {
			return model.Fail(model.Forbidden)
		}
		return nil
	}
	var pending []string
	var revision model.Revision
	if e := s.store.View(model.WithoutBooks(ctx), func(st model.ControlState) error {
		if err := authorize(st); err != nil {
			return err
		}
		revision = st.Revision
		for id, o := range st.Orgs {
			if needsContraction(o) {
				pending = append(pending, id)
			}
		}
		return nil
	}); e != nil {
		return ContractIndexesResult{}, e
	}
	if len(pending) == 0 {
		return ContractIndexesResult{Revision: revision}, nil
	}
	slices.Sort(pending)
	gate, ok := s.store.(layoutSupport)
	if !ok {
		return ContractIndexesResult{}, &model.Fault{Code: model.Unsupported, SafeDetail: "layout_support_unknown", RequestID: model.NewID()}
	}
	if lacking := gate.MembersLackingLayout(); len(lacking) > 0 {
		return ContractIndexesResult{}, &model.Fault{Code: model.Unsupported, SafeDetail: "layout_unsupported_by:" + strings.Join(lacking, ","), RequestID: model.NewID()}
	}
	out := ContractIndexesResult{}
	for _, id := range pending {
		audit := model.ControlAudit{ID: model.NewID(), Principal: c.user, Action: "contract_indexes", Reason: r.Reason, Time: s.now().UnixNano(), Org: id, RequestID: model.RequestCorrelationID(ctx, r.CommandID), Outcome: model.AuditAllowed}
		e := s.store.Update(ctx, func(st *model.ControlState) error {
			if err := authorize(*st); err != nil {
				return err
			}
			o, ok := st.Orgs[id]
			if !ok || !needsContraction(o) {
				return errContractedMeanwhile
			}
			if changed, err := (*contractor)(&o); err != nil {
				return err
			} else if !changed {
				return errContractedMeanwhile
			}
			st.Orgs[id] = o
			st.Audits = append(st.Audits, audit)
			out.Revision = st.Revision + 1
			return nil
		})
		switch {
		case errors.Is(e, errContractedMeanwhile):
			continue
		case e != nil:
			return ContractIndexesResult{}, e
		}
		out.Organizations++
		out.Changed = true
	}
	if !out.Changed {
		out.Revision = revision
	}
	return out, nil
}
