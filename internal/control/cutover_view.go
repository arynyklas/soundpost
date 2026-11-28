// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"sort"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// MaxShadowRows bounds the shadow decisions a view lists (newest first); the
// counts always cover all of them.
const MaxShadowRows = 50

// CutoverView is the read model of one project's notification ownership: what the
// cutover says about who owns normal notifications now, what the product decided
// while it only watched (shadow), and where the legacy history ends and the
// product's begins. It is a pure function of one committed control snapshot, holds
// no operator text and no evidence payload, and changes nothing.
type CutoverView struct {
	Org     model.ID `json:"org"`
	Project model.ID `json:"project"`
	// Cutover is nil when the project has no committed cutover: the product is its
	// only normal-notification owner and there is no history boundary.
	Cutover    *CutoverViewState `json:"cutover"`
	Accounting CutoverViewCounts `json:"accounting"`
	Shadow     ShadowView        `json:"shadow"`
	History    HistoryView       `json:"history"`
}

// CutoverViewState is the committed cutover record without its operator reasons.
type CutoverViewState struct {
	ID           model.ID           `json:"id"`
	Revision     model.Revision     `json:"revision"`
	Phase        string             `json:"phase"`
	Epoch        model.Uint64       `json:"epoch"`
	EnteredAt    model.UnixNano     `json:"entered_at_ns"`
	OldOwner     model.ID           `json:"old_owner"`
	NewOwner     model.ID           `json:"new_owner"`
	ActiveOwners []model.ID         `json:"active_owners"`
	Frontier     []CutoverFrontier  `json:"frontier"`
	Restore      CutoverViewRestore `json:"restore"`
	Timeline     []CutoverViewStep  `json:"timeline"`
}

// CutoverViewRestore says whether a disaster restore still has to be acknowledged
// before the product may send (Pending is the restore generation), and which
// generation the cutover has acknowledged.
type CutoverViewRestore struct {
	Pending      *model.ID `json:"pending,omitempty"`
	Acknowledged *model.ID `json:"acknowledged,omitempty"`
}

// CutoverViewStep is one committed transition: identities, instants and digests.
type CutoverViewStep struct {
	Revision model.Revision `json:"revision"`
	From     string         `json:"from"`
	To       string         `json:"to"`
	Epoch    model.Uint64   `json:"epoch"`
	At       model.UnixNano `json:"at_ns"`
	Command  model.ID       `json:"command"`
	// Principal is the operator that committed the step.
	Principal model.ID    `json:"principal"`
	Digest    model.Hash  `json:"digest"`
	Evidence  *model.Hash `json:"evidence_digest,omitempty"`
}

// CutoverViewCounts is the product's own delivery accounting: what is still to be
// sent, in flight, lapsed, and of unknown outcome.
type CutoverViewCounts struct {
	Pending       uint32     `json:"pending"`
	Claimed       uint32     `json:"claimed"`
	Lapsed        uint32     `json:"lapsed"`
	Unknown       uint32     `json:"unknown"`
	UnknownDigest model.Hash `json:"unknown_digest"`
}

// ShadowView is what the product decided while it was not the active owner: every
// external delivery decided outside new_active is recorded as suppressed with code
// shadow and sent nowhere. Each row carries the delivery's stable ID (its dedup
// identity), so a legacy decision stream can be compared decision by decision (see
// notify.CompareParity); the view does not import or hold that stream.
type ShadowView struct {
	// Observing is true while the committed phase is not new_active: new decisions
	// are shadow decisions.
	Observing bool `json:"observing"`
	// Decisions is how many shadow decisions the project holds, ByKind their split.
	Decisions uint32            `json:"decisions"`
	ByKind    map[string]uint32 `json:"by_kind"`
	// Recent are the newest MaxShadowRows of them.
	Recent []ShadowRow `json:"recent"`
}

// ShadowRow is one shadow decision at delivery granularity.
type ShadowRow struct {
	ID        model.ID       `json:"id"`
	Subject   string         `json:"subject"`
	Kind      string         `json:"kind"`
	Recipient *model.ID      `json:"recipient,omitempty"`
	DecidedAt model.UnixNano `json:"decided_ns"`
	Digest    model.Hash     `json:"digest"`
}

// HistoryView is the boundary between the legacy owner's history and the product's.
type HistoryView struct {
	// LegacyOwner is the old owner. Its history lives outside this product and
	// stays read-only: the product has no importer for it and deletes none of it.
	LegacyOwner   *model.ID `json:"legacy_owner,omitempty"`
	LegacyHistory string    `json:"legacy_history"`
	Importer      bool      `json:"importer"`
	// Spans say who owned normal notifications between the committed transitions,
	// oldest first. The last span is open (ToNS 0).
	Spans []HistorySpan `json:"spans"`
}

// The sides of a history span.
const (
	HistorySideLegacy   = "legacy"
	HistorySideProduct  = "product"
	HistorySideHandover = "handover"
)

// HistorySpan is one stretch of ownership.
type HistorySpan struct {
	// Owner is nil while no normal owner is active (a handover).
	Owner *model.ID      `json:"owner,omitempty"`
	Side  string         `json:"side"`
	Phase string         `json:"phase"`
	From  model.UnixNano `json:"from_ns"`
	To    model.UnixNano `json:"to_ns,omitempty"`
}

// CutoverViewOf derives the view of one project from a committed snapshot, under a
// scope that may read the project (the same check every control read makes). at is
// the instant lapsed claims are judged at.
func CutoverViewOf(st State, scope auth.Scope, project model.ID, at model.UnixNano) (CutoverView, error) {
	if err := ruleReadScope(scope, st, project); err != nil {
		return CutoverView{}, err
	}
	org := scope.OrgID()
	out := CutoverView{Org: org, Project: project, Shadow: ShadowView{ByKind: map[string]uint32{}, Recent: []ShadowRow{}}, History: HistoryView{LegacyHistory: "read_only", Spans: []HistorySpan{}}}
	counts, err := cutoverCountsOf(&st, org, project, at)
	if err != nil {
		return CutoverView{}, err
	}
	out.Accounting = CutoverViewCounts{Pending: counts.pending, Claimed: counts.claimed, Lapsed: counts.lapsed, Unknown: uint32(len(counts.unknown)), UnknownDigest: unknownDigest(counts.unknown)}
	rec, found, err := loadCutover(&st, cutoverKey(org, project))
	if err != nil {
		return CutoverView{}, err
	}
	if found {
		out.Cutover = cutoverViewState(&st, rec)
		out.Shadow.Observing = rec.Phase != CutoverNewActive
		old := rec.Old
		out.History.LegacyOwner = &old
		out.History.Spans = historySpans(rec)
	}
	recs, err := projectDeliveries(&st, org, project)
	if err != nil {
		return CutoverView{}, err
	}
	var shadow []DeliveryRecord
	for _, r := range recs {
		if r.Phase == DeliverySuppressed && r.Code == DeliveryCodeShadow {
			shadow = append(shadow, r)
			out.Shadow.ByKind[r.Kind]++
		}
	}
	out.Shadow.Decisions = uint32(len(shadow))
	sort.SliceStable(shadow, func(i, j int) bool {
		if shadow[i].SettledAt != shadow[j].SettledAt {
			return shadow[i].SettledAt > shadow[j].SettledAt
		}
		return shadow[i].ID.String() > shadow[j].ID.String()
	})
	for _, r := range shadow[:min(len(shadow), MaxShadowRows)] {
		out.Shadow.Recent = append(out.Shadow.Recent, ShadowRow{ID: r.ID, Subject: r.Subject, Kind: r.Kind, Recipient: r.Recipient, DecidedAt: r.SettledAt, Digest: r.Digest})
	}
	return out, nil
}

func cutoverViewState(st *State, rec CutoverRecord) *CutoverViewState {
	out := &CutoverViewState{ID: rec.ID, Revision: rec.Revision, Phase: rec.Phase, Epoch: rec.Epoch, EnteredAt: rec.EnteredAt, OldOwner: rec.Old, NewOwner: rec.New,
		ActiveOwners: rec.ActiveOwners(), Frontier: sortedFrontier(rec.Frontier), Timeline: make([]CutoverViewStep, 0, len(rec.Steps))}
	if out.ActiveOwners == nil {
		out.ActiveOwners = []model.ID{}
	}
	if out.Frontier == nil {
		out.Frontier = []CutoverFrontier{}
	}
	out.Restore.Acknowledged = rec.RestoreAck
	if m, pending := restorePending(st, rec, true); pending && m.Generation != (model.ID{}) {
		gen := m.Generation
		out.Restore.Pending = &gen
	}
	for _, s := range rec.Steps {
		out.Timeline = append(out.Timeline, CutoverViewStep{Revision: s.Revision, From: s.From, To: s.To, Epoch: s.Epoch, At: s.At, Command: s.Command, Principal: s.Principal, Digest: s.Digest, Evidence: s.Evidence})
	}
	return out
}

// historySpans turns the committed steps into stretches of ownership: from each
// transition to the next, owned by the owners active in the phase it entered.
func historySpans(rec CutoverRecord) []HistorySpan {
	spans := make([]HistorySpan, 0, len(rec.Steps))
	for i, s := range rec.Steps {
		span := HistorySpan{Side: HistorySideHandover, Phase: s.To, From: s.At}
		if owners := CutoverActiveOwners(s.To, rec.Old, rec.New); len(owners) == 1 {
			owner := owners[0]
			span.Owner = &owner
			span.Side = HistorySideProduct
			if owner == rec.Old {
				span.Side = HistorySideLegacy
			}
		}
		if i+1 < len(rec.Steps) {
			span.To = rec.Steps[i+1].At
		}
		spans = append(spans, span)
	}
	return spans
}
