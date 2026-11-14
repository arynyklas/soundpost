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
type GroupingIssue struct {
	ID                 ID                 `json:"id"`
	Org                ID                 `json:"org"`
	Project            ID                 `json:"project"`
	GroupingVersion    uint16             `json:"grouping_version"`
	Fingerprint        Hash               `json:"fingerprint"`
	Workflow           string             `json:"workflow"`
	Revision           Revision           `json:"revision"`
	Occurrences        []GroupingEvidence `json:"occurrences"`
	LateHistory        []GroupingEvidence `json:"late_history"`
	ResolutionTime     *UnixNano          `json:"resolution_time_ns,omitempty"`
	ResolutionFrontier []ID               `json:"resolution_frontier"`
	ObservedReleases   []ID               `json:"observed_releases"`
	FixedDescendants   []ID               `json:"fixed_descendants"`
	MigrationLinks     []ID               `json:"migration_links"`
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
