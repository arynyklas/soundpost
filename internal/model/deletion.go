// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

// Deletion modes are the exact C11 vocabulary.
const (
	DeleteRetireOrg       = "retire_org"
	DeleteRetireProject   = "retire_project"
	DeleteHistoricalRange = "historical_range"
	DeleteEntity          = "entity"
)

// Deletion receipt phases separate immediate read suppression (fencing) from the
// completed all-group admission/effect fence (complete). Held and failed are
// explicit: neither is ever reported as success.
const (
	DeletePhaseFencing  = "fencing"
	DeletePhaseComplete = "complete"
	DeletePhaseHeld     = "held"
	DeletePhaseFailed   = "failed"
)

// DeleteSlots is the number of fixed data slots every deletion barrier must reach.
const DeleteSlots = 64

// DeletePredicate is the persistent tombstone content. The same value is the
// control operation record, the per-slot barrier payload and the restore ledger
// content, so every layer rejects exactly the same writes and hides exactly the
// same rows. It never carries telemetry values.
type DeletePredicate struct {
	Operation  ID       `json:"operation"`
	Org        ID       `json:"org"`
	Mode       string   `json:"mode"`
	Projects   []ID     `json:"projects,omitempty"` // retire_org: empty means every project of the org
	Signals    []Kind   `json:"signals,omitempty"`  // historical_range: required; entity: optional narrowing
	Start      UnixNano `json:"start_ns,omitempty"`
	End        UnixNano `json:"end_ns,omitempty"`
	Entities   []ID     `json:"entities,omitempty"` // replay/profile/artifact roots (128-bit random IDs never collide across kinds)
	Generation Uint64   `json:"generation"`         // org delete generation committed by Begin
}

// DeleteBarrier is one data slot's committed tombstone: writes ordered after
// Cursor in that slot are rejected when they match Predicate.
type DeleteBarrier struct {
	Predicate DeletePredicate `json:"predicate"`
	Cursor    Cursor          `json:"cursor"`
}

// Digest binds the exact tombstone content (restore ledgers carry only digests).
func (p DeletePredicate) Digest() Hash {
	raw, err := CanonicalJSON(p)
	if err != nil {
		return Hash{}
	}
	return HashCanonical(raw)
}

func containsID(ids []ID, id ID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func containsKind(kinds []Kind, k Kind) bool {
	for _, v := range kinds {
		if v == k {
			return true
		}
	}
	return false
}

// Validate is the single shape check shared by control, storage and restore.
func (p DeletePredicate) Validate() error {
	if p.Operation == (ID{}) || p.Org == (ID{}) || len(p.Projects) > 128 || len(p.Entities) > 128 || len(p.Signals) > 16 {
		return Fail(Invalid)
	}
	seen := map[ID]bool{}
	for _, id := range p.Projects {
		if id == (ID{}) || seen[id] {
			return Fail(Invalid)
		}
		seen[id] = true
	}
	seen = map[ID]bool{}
	for _, id := range p.Entities {
		if id == (ID{}) || seen[id] {
			return Fail(Invalid)
		}
		seen[id] = true
	}
	kinds := map[Kind]bool{}
	for _, k := range p.Signals {
		if !k.Valid() || kinds[k] {
			return Fail(Invalid)
		}
		kinds[k] = true
	}
	switch p.Mode {
	case DeleteRetireOrg:
		if len(p.Projects) != 0 || len(p.Signals) != 0 || len(p.Entities) != 0 || p.Start != 0 || p.End != 0 {
			return Fail(Invalid)
		}
	case DeleteRetireProject:
		if len(p.Projects) == 0 || len(p.Signals) != 0 || len(p.Entities) != 0 || p.Start != 0 || p.End != 0 {
			return Fail(Invalid)
		}
	case DeleteHistoricalRange:
		// An empty signal list is never "all signals": a mistyped request must not wipe a project.
		if len(p.Projects) == 0 || len(p.Signals) == 0 || len(p.Entities) != 0 || p.Start < 0 || p.End <= p.Start {
			return Fail(Invalid)
		}
	case DeleteEntity:
		if len(p.Projects) != 1 || len(p.Entities) == 0 || p.Start != 0 || p.End != 0 {
			return Fail(Invalid)
		}
		for _, k := range p.Signals {
			if k != Replay && k != Profile {
				return Fail(Invalid)
			}
		}
	default:
		return Fail(Invalid)
	}
	return nil
}

// SignalTime is the time a record is ordered and range-deleted by. It must stay
// identical to the storage row time (storage.signalTime): a predicate and the
// index have to agree on which instant a row belongs to.
func SignalTime(r Record) UnixNano {
	switch r.Kind {
	case Log:
		if r.Payload.Log != nil && r.Payload.Log.Timestamp != nil {
			return *r.Payload.Log.Timestamp
		}
	case SpanKind:
		if r.Payload.Span != nil {
			return r.Payload.Span.Start.Wall
		}
	case JobAttempt:
		if r.Payload.Job != nil {
			return r.Payload.Job.Observed
		}
	case Replay:
		if r.Payload.Replay != nil {
			return r.Payload.Replay.Clock.Wall
		}
	case Profile:
		if r.Payload.Profile != nil {
			return r.Payload.Profile.Start
		}
	case Loss:
		if r.Payload.Loss != nil {
			return r.Payload.Loss.Start
		}
	case Condition:
		if r.Payload.Condition != nil {
			return r.Payload.Condition.At
		}
	}
	return r.ObservedAt
}

// CoversProject reports whether the predicate's project selection includes
// project (retire_org selects every project of its org).
func (p DeletePredicate) CoversProject(org, project ID) bool {
	if org != p.Org {
		return false
	}
	if p.Mode == DeleteRetireOrg {
		return true
	}
	return containsID(p.Projects, project)
}

// RecordEntity returns the replay/profile root a record is an owned chunk of.
func RecordEntity(r Record) (ID, bool) {
	if r.Payload.Replay != nil && r.Kind == Replay {
		return r.Payload.Replay.Replay, true
	}
	if r.Payload.Profile != nil && r.Kind == Profile {
		return r.Payload.Profile.Profile, true
	}
	return ID{}, false
}

// CoversRecord reports whether a record of (org, project) is hidden/rejected.
// Referencing records (an error that links a deleted replay) are not owned
// chunks and are not covered: their link simply resolves to unavailable.
func (p DeletePredicate) CoversRecord(org, project ID, r Record) bool {
	if !p.CoversProject(org, project) {
		return false
	}
	switch p.Mode {
	case DeleteRetireOrg, DeleteRetireProject:
		return true
	case DeleteHistoricalRange:
		if !containsKind(p.Signals, r.Kind) {
			return false
		}
		at := SignalTime(r)
		return at >= p.Start && at < p.End
	case DeleteEntity:
		root, owned := RecordEntity(r)
		if !owned || !containsID(p.Entities, root) {
			return false
		}
		return len(p.Signals) == 0 || containsKind(p.Signals, r.Kind)
	}
	return false
}

// CoversBlob reports whether an artifact root is hidden/rejected. Signal ranges
// never cover artifacts; retirement and an entity naming the root do.
func (p DeletePredicate) CoversBlob(m BlobManifest) bool {
	if !p.CoversProject(m.Org, m.Project) {
		return false
	}
	switch p.Mode {
	case DeleteRetireOrg, DeleteRetireProject:
		return true
	case DeleteEntity:
		return containsID(p.Entities, m.Root)
	}
	return false
}

// RetiresProject reports whether the predicate permanently retires every row
// and artifact of the project (a whole page or index range can be denied
// without inspecting rows).
func (p DeletePredicate) RetiresProject(org, project ID) bool {
	return (p.Mode == DeleteRetireOrg || p.Mode == DeleteRetireProject) && p.CoversProject(org, project)
}

// DeletionAuthority is the independently durable checkpoint receipt of a
// completed deletion (C12). Zero means no off-host authority is configured.
type DeletionAuthority struct {
	Generation Uint64   `json:"generation"`
	Head       Hash     `json:"head"`
	At         UnixNano `json:"at_ns"`
}

// DeletionOperation is the control-group record of one deletion saga.
type DeletionOperation struct {
	Predicate         DeletePredicate    `json:"predicate"`
	Phase             string             `json:"phase"`
	Principal         ID                 `json:"principal"`
	Reason            string             `json:"reason"`
	RequestedAt       UnixNano           `json:"requested_at_ns"`
	BeginRevision     Revision           `json:"begin_revision"`
	Barriers          []Cursor           `json:"barriers,omitempty"` // one per data slot, recorded incrementally
	Holds             []ID               `json:"holds,omitempty"`    // blocking holds while held
	AuthorityRequired bool               `json:"authority_required"`
	Authority         *DeletionAuthority `json:"authority,omitempty"`
	PhysicalDeadline  UnixNano           `json:"physical_deadline_ns"`
	BackupDeadline    UnixNano           `json:"backup_deadline_ns"`
	CompletedAt       UnixNano           `json:"completed_at_ns,omitempty"`
	PhysicalAt        UnixNano           `json:"physical_at_ns,omitempty"` // local physical cleanup finished
	SafeReason        string             `json:"safe_reason,omitempty"`
}

// LegalHold blocks physical-erasure success for the data it covers. A zero
// ReleasedAt means the hold is active.
type LegalHold struct {
	ID         ID       `json:"id"`
	Org        ID       `json:"org"`
	Projects   []ID     `json:"projects,omitempty"` // empty: every project of the org
	Signals    []Kind   `json:"signals,omitempty"`  // empty: every signal
	Start      UnixNano `json:"start_ns,omitempty"`
	End        UnixNano `json:"end_ns,omitempty"` // zero End: unbounded in time
	Entities   []ID     `json:"entities,omitempty"`
	Reason     string   `json:"reason"`
	PlacedBy   ID       `json:"placed_by"`
	PlacedAt   UnixNano `json:"placed_at_ns"`
	ReleasedAt UnixNano `json:"released_at_ns,omitempty"`
	ReleasedBy *ID      `json:"released_by,omitempty"`
}

// Active reports whether the hold still blocks erasure.
func (h LegalHold) Active() bool { return h.ReleasedAt == 0 }

// Overlaps reports whether the hold could cover any row the predicate covers.
// It errs on the side of holding: any possible overlap blocks.
func (h LegalHold) Overlaps(p DeletePredicate) bool {
	if !h.Active() || h.Org != p.Org {
		return false
	}
	if len(h.Projects) != 0 && p.Mode != DeleteRetireOrg {
		shared := false
		for _, id := range p.Projects {
			if containsID(h.Projects, id) {
				shared = true
				break
			}
		}
		if !shared {
			return false
		}
	}
	switch p.Mode {
	case DeleteHistoricalRange:
		if len(h.Signals) != 0 {
			shared := false
			for _, k := range p.Signals {
				if containsKind(h.Signals, k) {
					shared = true
					break
				}
			}
			if !shared {
				return false
			}
		}
		if h.End != 0 && (h.End <= p.Start || h.Start >= p.End) {
			return false
		}
	case DeleteEntity:
		if len(h.Entities) != 0 {
			shared := false
			for _, id := range p.Entities {
				if containsID(h.Entities, id) {
					shared = true
					break
				}
			}
			if !shared {
				return false
			}
		}
	}
	return true
}

// CoversRecord reports whether an active hold keeps this record alive.
func (h LegalHold) CoversRecord(org, project ID, r Record) bool {
	if !h.Active() || h.Org != org {
		return false
	}
	if len(h.Projects) != 0 && !containsID(h.Projects, project) {
		return false
	}
	if len(h.Signals) != 0 && !containsKind(h.Signals, r.Kind) {
		return false
	}
	if h.End != 0 {
		at := SignalTime(r)
		if at < h.Start || at >= h.End {
			return false
		}
	}
	if len(h.Entities) != 0 {
		root, owned := RecordEntity(r)
		if !owned || !containsID(h.Entities, root) {
			return false
		}
	}
	return true
}

// CoversBlob reports whether an active hold keeps this artifact root alive.
func (h LegalHold) CoversBlob(m BlobManifest) bool {
	if !h.Active() || h.Org != m.Org {
		return false
	}
	if len(h.Projects) != 0 && !containsID(h.Projects, m.Project) {
		return false
	}
	if len(h.Signals) != 0 {
		return false // a signal-scoped hold does not name artifacts
	}
	if len(h.Entities) != 0 && !containsID(h.Entities, m.Root) {
		return false
	}
	return true
}

// EvidenceGap is a committed RecordEvidenceGap: lifecycle evidence in
// (After, Through] of a data group expired before it was processed. Affected
// intervals are incomplete/unknown, never recovered.
//
// DeclaredBy says who declared it and therefore how far it authorizes expiry:
// "worker" is the retention worker, which enumerated every entry of the
// interval (Count == Through-After); "admin" is an organization administrator's
// declaration, which is recorded and audited but never authorizes erasure
// because nothing enumerates the entries it names. Actor is the declaring
// principal (the installation for the worker). Both are set by control, never
// taken from a request.
type EvidenceGap struct {
	ID         ID       `json:"id"`
	Org        ID       `json:"org"`
	Project    ID       `json:"project"`
	Group      ID       `json:"group"`
	After      Uint64   `json:"after"`
	Through    Uint64   `json:"through"`
	Count      Uint64   `json:"count"`
	Start      UnixNano `json:"start_ns"`
	End        UnixNano `json:"end_ns"`
	Signals    []Kind   `json:"signals,omitempty"`
	Reason     string   `json:"reason"`
	RecordedAt UnixNano `json:"recorded_at_ns"`
	DeclaredBy string   `json:"declared_by,omitempty"`
	Actor      *ID      `json:"actor,omitempty"`
}

// RetentionPolicyVersion is one audited revision of a project's (or, with a
// zero Project, the organization's default) retention periods. A new version
// applies to batches admitted after Effective; receipts keep the deadlines they
// were issued, so a policy change never rewrites a receipt time.
type RetentionPolicyVersion struct {
	Org       ID              `json:"org"`
	Project   *ID             `json:"project,omitempty"`
	Version   Uint64          `json:"version"`
	Days      map[Kind]uint32 `json:"days"`
	RawDays   uint32          `json:"raw_days,omitempty"` // restricted_raw sources
	Artifacts uint32          `json:"artifact_days,omitempty"`
	Effective UnixNano        `json:"effective_ns"`
	Actor     ID              `json:"actor"`
	Reason    string          `json:"reason"`
	At        UnixNano        `json:"at_ns"`
}

// CoversOrigin is CoversRecord for a derived effect: the effect's origin is
// described by project, signal kind, event time and the replay/profile root it
// belongs to (nil when it has none), never by the record itself.
func (p DeletePredicate) CoversOrigin(org, project ID, kind Kind, at UnixNano, entity *ID) bool {
	if !p.CoversProject(org, project) {
		return false
	}
	switch p.Mode {
	case DeleteRetireOrg, DeleteRetireProject:
		return true
	case DeleteHistoricalRange:
		return containsKind(p.Signals, kind) && at >= p.Start && at < p.End
	case DeleteEntity:
		return entity != nil && containsID(p.Entities, *entity) && (len(p.Signals) == 0 || containsKind(p.Signals, kind))
	}
	return false
}
