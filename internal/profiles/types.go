// Copyright 2026 Aryn Yklas; SPDX-License-Identifier: Apache-2.0
package profiles

import "soundpost/internal/model"

type Window struct {
	Start      model.UnixNano `json:"start_ns"`
	End        model.UnixNano `json:"end_ns"`
	MaxSamples uint32         `json:"max_samples"`
	Cursor     string         `json:"cursor,omitempty"`
	MinCursors []model.Cursor `json:"min_cursors,omitempty"`
}
type CapabilityRecord struct {
	ID    model.ID         `json:"id"`
	Value model.Capability `json:"value"`
}
type Reference struct {
	Project  model.ID `json:"project_id"`
	Build    model.ID `json:"build_id"`
	Kind     string   `json:"kind"`
	ID       model.ID `json:"id"`
	Relation string   `json:"relation"`
}
type ResolvedReference struct {
	Reference *Reference `json:"reference,omitempty"`
	Available bool       `json:"available"`
}

// ProfilePage owns its C04 values; no borrowed C05 buffers or service handles.
type ProfilePage struct {
	Project, Source model.ID
	Chunks          []model.ProfileChunk
	Capabilities    []CapabilityRecord
	Loss            []model.LossReport
	Links           []Reference
	Watermarks      []model.Cursor
	Complete        bool
}
type ProfileView struct {
	Profile      model.ID                   `json:"profile_id"`
	Process      model.ID                   `json:"process_id"`
	Project      model.ID                   `json:"project_id"`
	Method       string                     `json:"method"`
	Units        string                     `json:"units"`
	Clock        model.TraceClock           `json:"clock"`
	NativeDomain *model.ProfileNativeDomain `json:"native_domain,omitempty"`
	Frames       []model.ProfileFrame       `json:"frames"`
	Stacks       []model.ProfileStack       `json:"stacks"`
	Samples      []model.ProfileSample      `json:"samples"`
	Intervals    []model.ProfileInterval    `json:"intervals"`
	Capabilities []CapabilityRecord         `json:"capabilities"`
	Loss         []model.LossReport         `json:"loss"`
	LossCount    model.Uint64               `json:"loss_count"`
	NativeLoss   []model.ProfileNativeLoss  `json:"native_loss,omitempty"`
	Truncated    bool                       `json:"truncated"`
	BlockedNano  *model.Uint64              `json:"blocked_ns,omitempty"`
	RunnableNano *model.Uint64              `json:"runnable_ns,omitempty"`
	UnknownNano  *model.Uint64              `json:"unknown_ns,omitempty"`
	Links        []ResolvedReference        `json:"links"`
	Watermarks   []model.Cursor             `json:"watermarks"`
	Completeness string                     `json:"completeness"`
	Reasons      []string                   `json:"reasons"`
	NextCursor   string                     `json:"next_cursor,omitempty"`
}
