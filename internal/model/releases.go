// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

// Release is the immutable build identity in one organization/project. Only
// DisplayLabel changes; History is authority-authored command receipt history.
type Release struct {
	ID             ID                     `json:"id"`
	Org            ID                     `json:"org"`
	Project        ID                     `json:"project"`
	BuildID        ID                     `json:"build_id"`
	Parents        []ID                   `json:"parents"`
	BuildTime      UnixNano               `json:"build_time_ns"`
	DebugArtifacts []ReleaseDebugArtifact `json:"debug_artifacts"`
	DisplayLabel   string                 `json:"display_label"`
	Revision       Revision               `json:"revision"`
	History        []ReleaseLabelRevision `json:"history,omitempty"`
}
type ReleaseDebugArtifact struct {
	ArtifactID ID     `json:"artifact_id"`
	DebugID    string `json:"debug_id"`
	SHA256     Hash   `json:"sha256"`
}
type ReleaseLabelRevision struct {
	ControlRevision Revision `json:"control_revision"`
	Revision        Revision `json:"revision"`
	DisplayLabel    string   `json:"display_label"`
}
type ReleaseCommand struct {
	Operation string             `json:"operation"`
	At        UnixNano           `json:"at_ns"`
	RequestID ID                 `json:"request_id"`
	Release   *Release           `json:"release,omitempty"`
	Migration *GroupingMigration `json:"migration,omitempty"`
}

// GroupingEvidence is the C07 immutable lifecycle projection. The 06.01
// migration operation never ingests evidence or mutates occurrence history.
type GroupingEvidence struct {
	OccurrenceID    ID                   `json:"occurrence_id"`
	RecordID        ID                   `json:"record_id"`
	Origin          Cursor               `json:"origin"`
	GroupingVersion uint16               `json:"grouping_version"`
	Fingerprint     Hash                 `json:"fingerprint"`
	EventTime       UnixNano             `json:"event_time_ns"`
	ArrivalTime     UnixNano             `json:"arrival_time_ns"`
	BuildID         *ID                  `json:"build_id,omitempty"`
	ReleaseID       *ID                  `json:"release_id,omitempty"`
	Ancestry        string               `json:"ancestry"`
	ProducerEpoch   *ID                  `json:"producer_epoch,omitempty"`
	Ordinal         Uint64               `json:"ordinal"`
	Freshness       string               `json:"freshness"`
	Denominator     *GroupingDenominator `json:"denominator,omitempty"`
}
type GroupingDenominator struct {
	Name     string   `json:"name"`
	Start    UnixNano `json:"start_ns"`
	End      UnixNano `json:"end_ns"`
	Count    Uint64   `json:"count"`
	Complete bool     `json:"complete"`
	Cursors  []Cursor `json:"cursors"`
}

// Occurrence-ledger window (06.02-W3). An issue's two ledgers (Occurrences and
// LateHistory) hold at most GroupingWindowMax evidence together. When a ledger
// would grow past it, the OLDEST evidence is folded into an exact
// GroupingCompaction aggregate and only the newest GroupingWindowKeep stay as
// full records, so a hot fingerprint never stalls the lifecycle on a count cap.
// The writer (internal/issues) and the verifier (internal/control) share these
// numbers and GroupingCompaction.Fold, which is the only way an aggregate grows.
const (
	// GroupingWindowMax is the largest evidence window one issue may store.
	GroupingWindowMax = 1024
	// GroupingWindowKeep is the window compaction leaves (never goes below).
	GroupingWindowKeep = 512
	// GroupingDedupTail is how many of the most recently folded occurrence IDs an
	// aggregate keeps so a redelivered occurrence is still recognized.
	GroupingDedupTail = 512
)

// GroupingCompactedRelease is one release named by folded evidence with the
// earliest event time at which any folded evidence named it.
type GroupingCompactedRelease struct {
	Release    ID       `json:"release_id"`
	FirstEvent UnixNano `json:"first_event_ns"`
}

// GroupingCompaction is the exact aggregate of the evidence folded out of one
// ledger of a GroupingIssue: how many items, their event-time and arrival-time
// bounds, the first event time per named release (so "releases observed at or
// before a boundary" stays exact) and the occurrence IDs of the most recently
// folded evidence (a dedup horizon, at most GroupingDedupTail). It holds IDs,
// times and counts only, never telemetry text. It changes only by Fold.
type GroupingCompaction struct {
	Count        Uint64                     `json:"count"`
	FirstEvent   UnixNano                   `json:"first_event_ns"`
	LastEvent    UnixNano                   `json:"last_event_ns"`
	FirstArrival UnixNano                   `json:"first_arrival_ns"`
	LastArrival  UnixNano                   `json:"last_arrival_ns"`
	Releases     []GroupingCompactedRelease `json:"releases,omitempty"`
	Recent       []ID                       `json:"recent,omitempty"`
}

// Clone returns a deep copy (nil stays nil).
func (c *GroupingCompaction) Clone() *GroupingCompaction {
	if c == nil {
		return nil
	}
	out := *c
	out.Releases = append([]GroupingCompactedRelease(nil), c.Releases...)
	out.Recent = append([]ID(nil), c.Recent...)
	return &out
}

// Fold returns the aggregate after folding evidence (in ledger order) into c;
// c is not modified and an empty list returns a copy of c. The result is
// deterministic: counts add, bounds take min/max, a release's first event is the
// minimum seen, new releases append in first-seen order, and Recent is the last
// GroupingDedupTail occurrence IDs of everything folded so far.
func (c *GroupingCompaction) Fold(evidence []GroupingEvidence) *GroupingCompaction {
	out := c.Clone()
	if len(evidence) == 0 {
		return out
	}
	if out == nil {
		out = &GroupingCompaction{}
	}
	position := make(map[ID]int, len(out.Releases))
	for i, r := range out.Releases {
		position[r.Release] = i
	}
	for _, e := range evidence {
		if out.Count == 0 || e.EventTime < out.FirstEvent {
			out.FirstEvent = e.EventTime
		}
		if out.Count == 0 || e.EventTime > out.LastEvent {
			out.LastEvent = e.EventTime
		}
		if out.Count == 0 || e.ArrivalTime < out.FirstArrival {
			out.FirstArrival = e.ArrivalTime
		}
		if out.Count == 0 || e.ArrivalTime > out.LastArrival {
			out.LastArrival = e.ArrivalTime
		}
		out.Count++
		if e.ReleaseID != nil {
			if at, ok := position[*e.ReleaseID]; ok {
				if e.EventTime < out.Releases[at].FirstEvent {
					out.Releases[at].FirstEvent = e.EventTime
				}
			} else {
				position[*e.ReleaseID] = len(out.Releases)
				out.Releases = append(out.Releases, GroupingCompactedRelease{Release: *e.ReleaseID, FirstEvent: e.EventTime})
			}
		}
		out.Recent = append(out.Recent, e.OccurrenceID)
	}
	if len(out.Recent) > GroupingDedupTail {
		out.Recent = append([]ID(nil), out.Recent[len(out.Recent)-GroupingDedupTail:]...)
	}
	return out
}

// ObservedBy reports whether any folded evidence named the release at or before
// the event-time boundary.
func (c *GroupingCompaction) ObservedBy(release ID, boundary UnixNano) bool {
	if c == nil {
		return false
	}
	for _, r := range c.Releases {
		if r.Release == release {
			return r.FirstEvent <= boundary
		}
	}
	return false
}

type GroupingIssue struct {
	ID              ID                 `json:"id"`
	Org             ID                 `json:"org"`
	Project         ID                 `json:"project"`
	GroupingVersion uint16             `json:"grouping_version"`
	Fingerprint     Hash               `json:"fingerprint"`
	Workflow        string             `json:"workflow"`
	Revision        Revision           `json:"revision"`
	Occurrences     []GroupingEvidence `json:"occurrences"`
	LateHistory     []GroupingEvidence `json:"late_history"`
	// Compacted and LateCompacted are the exact aggregates of the oldest
	// evidence folded out of Occurrences and LateHistory (see GroupingCompaction);
	// two fields, because the late count is reported separately and each ledger is
	// folded as a prefix of its own append order.
	Compacted          *GroupingCompaction `json:"compacted,omitempty"`
	LateCompacted      *GroupingCompaction `json:"late_compacted,omitempty"`
	ResolutionTime     *UnixNano           `json:"resolution_time_ns,omitempty"`
	ResolutionFrontier []ID                `json:"resolution_frontier"`
	ObservedReleases   []ID                `json:"observed_releases"`
	FixedDescendants   []ID                `json:"fixed_descendants"`
	MigrationLinks     []ID                `json:"migration_links"`
}
type GroupingMigration struct {
	ID              ID       `json:"id"`
	Org             ID       `json:"org"`
	Project         ID       `json:"project"`
	From            ID       `json:"from"`
	To              ID       `json:"to"`
	FromRevision    Revision `json:"from_revision"`
	GroupingVersion uint16   `json:"grouping_version"`
	Fingerprint     Hash     `json:"fingerprint"`
	Reason          string   `json:"reason"`
	At              UnixNano `json:"at_ns"`
}

// ReleaseScopeKey retains the scope independently of the fingerprint/build ID.
func ReleaseScopeKey(org, project, id ID) string {
	return org.String() + ":" + project.String() + ":" + id.String()
}
