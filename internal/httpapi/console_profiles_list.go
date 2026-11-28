// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"errors"
	"io"
	"math"
	"slices"
	"strings"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/storage"
)

// This file is POST /api/v1/profiles/list (docs/operations/console-api.md section 5): the profiles of the requested
// projects inside a window, summarised per profile ID from the stored chunk metadata.
//
// A profile is a separate grant: the caller needs telemetry.read AND profiles.read on every requested project,
// else the one typed not_available answer and nothing is scanned. Only metadata is read (method, unit, time
// bounds, sequence, loss and truncation markers); frames, stacks and samples are never copied out. Every profile
// keeps its own unit. A profile whose capability is not supported, not stored or unreadable has coverage
// "unknown" with a closed reason, never a number and never "complete".

// Bounds of the profile scan; reaching one makes the answer incomplete with reason scan_capped.
const (
	maxProfileListRows     = 100_000
	maxProfileListBytes    = 256 << 20
	maxProfileListProfiles = 5_000
)

// Coverage values of a profile in the list.
const (
	CoverageComplete = "complete"
	CoveragePartial  = "partial"
	CoverageUnknown  = "unknown"
)

// Closed unsupported reasons the list itself states (a capability's own reason is forwarded only when it is a safe code).
const (
	ReasonCapabilityNotFound = "capability_not_found"
	ReasonUnitUnknown        = "unit_unknown"
	ReasonUnitMismatch       = "unit_mismatch"
	ReasonSourceMismatch     = "source_mismatch"
	reasonCapabilityPrefix   = "capability_"
)

// ProfileListBody is the POST /api/v1/profiles/list body; the window is required.
type ProfileListBody struct{ ListRequest }

// ProfileListItem is one profile of the list.
type ProfileListItem struct {
	ProjectID         model.ID    `json:"project_id"`
	ProfileID         model.ID    `json:"profile_id"`
	SourceID          *model.ID   `json:"source_id"`
	Method            string      `json:"method,omitempty"`
	Unit              string      `json:"unit"`
	FirstAt           model.Int64 `json:"first_at"`
	LastAt            model.Int64 `json:"last_at"`
	Coverage          string      `json:"coverage"`
	UnsupportedReason string      `json:"unsupported_reason,omitempty"`
}

type profileChunkMark struct {
	seq      uint64
	native   bool
	complete bool
	lossy    bool
}

type profileAgg struct {
	project, profile, source model.ID
	sourceMixed              bool
	method, unit             string
	unitMixed                bool
	capability               model.ID
	first, last              model.UnixNano
	marks                    []profileChunkMark
}

func validProfileListBody(b ProfileListBody) error {
	if err := b.validate(true); err != nil {
		return err
	}
	switch b.Sort {
	case "", "last_at", "first_at":
	default:
		return invalid("sort_invalid")
	}
	return nil
}

func (a *profileAgg) key(sort string) int64 {
	if sort == "first_at" {
		return int64(a.first)
	}
	return int64(a.last)
}

// unit is the unit the list states: the stored unit when every chunk agrees on a unit of the closed set.
func (a *profileAgg) unitOf() string {
	switch a.unit {
	case "samples", "nanoseconds", "events":
		if !a.unitMixed {
			return a.unit
		}
	}
	return "unknown"
}

// chunkCoverage is the coverage the stored chunks alone allow: partial when a native sequence is missing or does
// not start at 1 inside the window, the last native chunk is not complete, or any chunk reports loss or truncation.
func (a *profileAgg) chunkCoverage() string {
	slices.SortFunc(a.marks, func(x, y profileChunkMark) int {
		switch {
		case x.seq < y.seq:
			return -1
		case x.seq > y.seq:
			return 1
		}
		return 0
	})
	expected, nativeSeen, partial := uint64(1), false, false
	var lastNative *profileChunkMark
	for i := range a.marks {
		m := &a.marks[i]
		partial = partial || m.lossy
		if m.native {
			partial = partial || m.seq != expected
			expected, nativeSeen, lastNative = m.seq+1, true, m
		}
	}
	if nativeSeen && !lastNative.complete {
		partial = true
	}
	if partial {
		return CoveragePartial
	}
	return CoverageComplete
}

// Profiles answers one profile list under the caller's own authority.
func (l *ConsoleLists) Profiles(ctx context.Context, authority *auth.Service, credential auth.Credential, body ProfileListBody) (any, []auth.Scope, error) {
	if err := validProfileListBody(body); err != nil {
		return nil, nil, err
	}
	scope, err := authority.Authorize(ctx, credential, body.Org, body.Projects, auth.Read)
	if err != nil {
		return nil, nil, err
	}
	if err = body.allowsAll(scope); err != nil {
		return nil, nil, err
	}
	scopes := []auth.Scope{scope}
	gate, err := authority.Authorize(ctx, credential, body.Org, body.Projects, ProfilesRead)
	if err != nil && !faultIs(err, model.NotFound) {
		return nil, nil, err
	}
	if err != nil || body.allowsAll(gate) != nil {
		return newConsoleList[ProfileListItem](body.ListRequest, StateNotAvailable, ReasonGrantRequired, "profiles"), scopes, nil
	}
	scopes = append(scopes, gate)
	if l == nil || l.cfg.Scanner == nil {
		return newConsoleList[ProfileListItem](body.ListRequest, StateNotAvailable, ReasonListSourceNotWired, "profiles"), scopes, nil
	}
	digest, err := listDigest("profiles", withoutPaging(body.ListRequest))
	if err != nil {
		return nil, nil, err
	}
	var after *listPos
	if body.Cursor != "" {
		after = new(listPos)
		if err = openListCursor(ctx, l.cfg.Tickets, scope, "profiles", digest, body.Cursor, after); err != nil {
			return nil, nil, err
		}
	}
	aggs, partial, capped, err := l.scanProfiles(ctx, scope, body)
	if err != nil {
		return nil, nil, err
	}
	if q := strings.ToLower(strings.TrimSpace(body.Query)); q != "" {
		aggs = slices.DeleteFunc(aggs, func(a *profileAgg) bool {
			return !hexPrefix(q) || !strings.HasPrefix(a.profile.String(), q) && !(!a.sourceMixed && strings.HasPrefix(a.source.String(), q))
		})
	}
	slices.SortFunc(aggs, func(a, b *profileAgg) int {
		switch {
		case listLess(a.key(body.Sort), a.project.String(), a.profile.String(), b.key(body.Sort), b.project.String(), b.profile.String()):
			return -1
		case listLess(b.key(body.Sort), b.project.String(), b.profile.String(), a.key(body.Sort), a.project.String(), a.profile.String()):
			return 1
		}
		return 0
	})
	start := 0
	if after != nil {
		start = slices.IndexFunc(aggs, func(a *profileAgg) bool {
			return after.before(a.key(body.Sort), a.project.String(), a.profile.String())
		})
		if start < 0 {
			start = len(aggs)
		}
	}
	out := newConsoleList[ProfileListItem](body.ListRequest, StateReady, "", "profiles")
	end := min(start+body.pageLimit(), len(aggs))
	lookupPartial := false
	for _, a := range aggs[start:end] {
		item, p, err := l.profileItem(ctx, scope, a)
		if err != nil {
			return nil, nil, err
		}
		lookupPartial = lookupPartial || p
		out.Items = append(out.Items, item)
	}
	if out.More = end < len(aggs); out.More {
		last := aggs[end-1]
		if out.NextCursor, err = issueListCursor(ctx, l.cfg.Tickets, scope, "profiles", digest, listPos{Key: last.key(body.Sort), Project: last.project.String(), ID: last.profile.String()}); err != nil {
			return nil, nil, err
		}
	}
	switch {
	case capped:
		out.State, out.Reason = StateIncomplete, ReasonListScanCapped
	case partial || lookupPartial:
		out.State, out.Reason = StateIncomplete, ReasonShardsMissing
	case len(out.Items) == 0 && !out.More:
		out.State, out.Reason = StateEmpty, ReasonListNoItems
	}
	out.Sections = []ViewSection{{Name: "profiles", State: out.State, Reason: out.Reason}}
	return out, scopes, nil
}

// profileItem renders one profile, looking its capability up for the support state.
func (l *ConsoleLists) profileItem(ctx context.Context, scope auth.Scope, a *profileAgg) (ProfileListItem, bool, error) {
	item := ProfileListItem{ProjectID: a.project, ProfileID: a.profile, Method: a.method, Unit: a.unitOf(), FirstAt: model.Int64(a.first), LastAt: model.Int64(a.last), Coverage: CoverageUnknown}
	if !a.sourceMixed {
		item.SourceID = new(a.source)
	}
	switch {
	case a.sourceMixed:
		item.UnsupportedReason = ReasonSourceMismatch
		return item, false, nil
	case item.Unit == "unknown":
		item.UnsupportedReason = ReasonUnitUnknown
		if a.unitMixed {
			item.UnsupportedReason = ReasonUnitMismatch
		}
		return item, false, nil
	}
	capability, found, partial, err := l.capabilityOf(ctx, scope, a)
	if err != nil {
		return item, false, err
	}
	switch {
	case !found && partial:
		item.UnsupportedReason = ReasonShardsMissing
	case !found:
		item.UnsupportedReason = ReasonCapabilityNotFound
	case capability.Status != "supported":
		item.UnsupportedReason = capabilityReason(capability)
	default:
		item.Coverage = a.chunkCoverage()
	}
	return item, partial, nil
}

// capabilityReason is the reason a capability that is not supported states: its own safe code, else its status.
func capabilityReason(c model.Capability) string {
	if r := c.Reason; r != "" && len(r) <= 64 && strings.Trim(r, "abcdefghijklmnopqrstuvwxyz0123456789_.-") == "" {
		return r
	}
	return reasonCapabilityPrefix + c.Status
}

// capabilityOf reads the newest stored capability record the profile's chunks name, under the caller's scope.
func (l *ConsoleLists) capabilityOf(ctx context.Context, scope auth.Scope, a *profileAgg) (model.Capability, bool, bool, error) {
	rows, err := l.cfg.Scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: []model.ID{a.project}, Signal: model.CapabilityKind, Start: math.MinInt64, End: math.MaxInt64,
		Selectors: []storage.Matcher{
			{Target: storage.MatchField, Name: "id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: a.capability.String()}},
			{Target: storage.MatchField, Name: "source_id", Op: storage.MatchEqual, Literal: storage.Literal{Kind: storage.LiteralString, String: a.source.String()}},
		},
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldCapability},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return model.Capability{}, false, false, err
	}
	if rows == nil {
		return model.Capability{}, false, false, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	var best model.Capability
	var bestAt model.UnixNano
	found, partial := false, false
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return best, found, partial, nil
		}
		if err != nil {
			return model.Capability{}, false, false, err
		}
		partial = partial || page.Partial
		if len(page.Values) != page.Len() || len(page.Times) != page.Len() {
			return model.Capability{}, false, false, model.Fail(model.Corrupt)
		}
		for i, v := range page.Values {
			c := v.Capability
			if c == nil || c.Signal != model.Profile || page.IDs[i] != a.capability {
				continue
			}
			if !found || page.Times[i] >= bestAt {
				best, bestAt, found = *c, page.Times[i], true
			}
		}
	}
}

// scanProfiles reads the chunk metadata of the window and folds it per profile.
func (l *ConsoleLists) scanProfiles(ctx context.Context, scope auth.Scope, body ProfileListBody) (_ []*profileAgg, partial, capped bool, err error) {
	rows, err := l.cfg.Scanner.Scan(ctx, scope, storage.ScanRequest{
		Projects: body.Projects, Signal: model.Profile, Start: body.Window.Start, End: body.Window.End,
		Projection: []storage.Field{storage.FieldID, storage.FieldTime, storage.FieldProfile},
		Fence:      storage.ReadFence{AllowPartial: true},
	})
	if err != nil {
		return nil, false, false, err
	}
	if rows == nil {
		return nil, false, false, model.Fail(model.Corrupt)
	}
	defer rows.Close()
	type key struct{ project, profile model.ID }
	byKey := map[key]*profileAgg{}
	var order []*profileAgg
	scanned, bytes := 0, uint64(0)
	for {
		page, err := rows.Next(ctx)
		if errors.Is(err, io.EOF) {
			return order, partial, capped, nil
		}
		if err != nil {
			return nil, false, false, err
		}
		partial = partial || page.Partial
		if len(page.Values) != page.Len() || len(page.Projects) != page.Len() || len(page.Sources) != page.Len() {
			return nil, false, false, model.Fail(model.Corrupt)
		}
		if bytes += page.Bytes; bytes > maxProfileListBytes {
			return order, partial, true, nil
		}
		for i, v := range page.Values {
			c := v.Profile
			if c == nil {
				return nil, false, false, model.Fail(model.Corrupt)
			}
			if scanned++; scanned > maxProfileListRows {
				return order, partial, true, nil
			}
			k := key{page.Projects[i], c.Profile}
			a := byKey[k]
			if a == nil {
				if len(order) >= maxProfileListProfiles {
					return order, partial, true, nil
				}
				a = &profileAgg{project: k.project, profile: k.profile, source: page.Sources[i], method: c.Method, unit: c.Units, capability: c.Capability, first: c.Start, last: c.End}
				byKey[k] = a
				order = append(order, a)
			}
			a.first, a.last = min(a.first, c.Start), max(a.last, c.End)
			a.sourceMixed = a.sourceMixed || a.source != page.Sources[i]
			a.unitMixed = a.unitMixed || a.unit != c.Units
			a.marks = append(a.marks, profileChunkMark{seq: uint64(c.Sequence), native: c.NativeDomain != nil, complete: c.Complete,
				lossy: c.Loss > 0 || c.Truncated || len(c.NativeLoss) > 0})
		}
	}
}
