// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"unicode/utf8"
)

// ExternalLink is the link of an incident or an error issue to one issue of an
// external tracker (today only GitLab). It is a one-way link: Soundpost never reads
// the tracker's state back. Only identifiers, a URL and closed codes are kept.
//
// The state machine (ApplyExternal) is shared by the incident reducer and the issue
// lifecycle so that both entities create at most one tracker issue:
//
//	(none) --begin--> creating --end(linked)--> linked        (terminal)
//	                    |  ^
//	                    |  +-- begin again (lease expired, unknown or refused)
//	                    +--end(unknown|refused)--> unknown | refused
//	(none|unknown|refused|expired creating) --adopt--> linked
//
// "creating" is a durable lease: exactly one request holds it until Until, so two
// requests (on any node) can never both create. A request that finds the lease
// expired, or the link unknown, MUST look the tracker issue up by Marker before it
// creates anything.
type ExternalLink struct {
	Provider string   `json:"provider"`
	State    string   `json:"state"` // external states below
	Marker   string   `json:"marker"`
	Project  string   `json:"project,omitempty"` // tracker project path, e.g. "shop/storefront-web"
	IID      Uint64   `json:"iid,omitempty"`
	URL      string   `json:"url,omitempty"`
	Code     string   `json:"code,omitempty"` // closed code of unknown/refused
	Actor    ID       `json:"actor"`
	At       UnixNano `json:"at_ns"`
	Until    UnixNano `json:"until_ns,omitempty"` // lease expiry while creating
}

// States of an ExternalLink.
const (
	ExternalCreating = "creating"
	ExternalLinked   = "linked"
	ExternalUnknown  = "unknown"
	ExternalRefused  = "refused"
)

// ExternalOp kinds.
const (
	ExternalBegin = "begin"
	ExternalEnd   = "end"
	ExternalAdopt = "adopt"
)

// ExternalLease bounds how long a creating lease may be held.
const (
	ExternalMaxLease = UnixNano(5 * 60 * 1_000_000_000)
	MaxExternalLinks = 4
)

// ExternalOp is one transition request. Result is linked|unknown|refused for end
// and linked for adopt; begin carries Until.
type ExternalOp struct {
	Provider string   `json:"provider"`
	Kind     string   `json:"kind"`
	Marker   string   `json:"marker"`
	Project  string   `json:"project,omitempty"`
	Until    UnixNano `json:"until_ns,omitempty"`
	Result   string   `json:"result,omitempty"`
	IID      Uint64   `json:"iid,omitempty"`
	URL      string   `json:"url,omitempty"`
	Code     string   `json:"code,omitempty"`
}

// ExternalMarker is the deterministic marker of one entity's tracker issue. It is
// written into the tracker issue's description and searched for before any create.
func ExternalMarker(org ID, entityKind string, entity ID) string {
	h := sha256.New()
	h.Write([]byte("soundpost.external.v1\x00"))
	h.Write(org[:])
	h.Write([]byte(entityKind))
	h.Write([]byte{0})
	h.Write(entity[:])
	return "soundpost-ref-" + hex.EncodeToString(h.Sum(nil)[:16])
}

func externalFault(code Code, detail string) error {
	f := Fail(code)
	f.SafeDetail = detail
	return f
}

func externalToken(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || c == '/' || c == ':') {
			return false
		}
	}
	return true
}

// ValidExternalOp checks everything about an operation that needs no state.
func ValidExternalOp(op ExternalOp, at UnixNano) error {
	if !externalToken(op.Provider, 32) || !externalToken(op.Marker, 64) || op.Project != "" && !externalToken(op.Project, 200) || len(op.Code) > 64 || op.Code != "" && !externalToken(op.Code, 64) {
		return externalFault(Invalid, "external_invalid")
	}
	switch op.Kind {
	case ExternalBegin:
		if op.Project == "" || op.Until <= at || op.Until-at > ExternalMaxLease || op.Result != "" || op.IID != 0 || op.URL != "" || op.Code != "" {
			return externalFault(Invalid, "external_invalid")
		}
	case ExternalEnd, ExternalAdopt:
		switch op.Result {
		case ExternalLinked:
			u, err := url.Parse(op.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(op.URL) > 512 || !utf8.ValidString(op.URL) || op.IID == 0 || op.Project == "" || op.Code != "" {
				return externalFault(Invalid, "external_invalid")
			}
		case ExternalUnknown, ExternalRefused:
			if op.Kind == ExternalAdopt || op.Code == "" || op.IID != 0 || op.URL != "" {
				return externalFault(Invalid, "external_invalid")
			}
		default:
			return externalFault(Invalid, "external_invalid")
		}
		if op.Until != 0 {
			return externalFault(Invalid, "external_invalid")
		}
	default:
		return externalFault(Invalid, "external_invalid")
	}
	return nil
}

// ApplyExternal applies one transition to the links of an entity and returns the
// new list; links is never modified. Typed refusals (SafeDetail):
// external_already_linked, external_in_progress, external_not_creating,
// external_marker_mismatch, external_project_mismatch, external_full.
func ApplyExternal(links []ExternalLink, op ExternalOp, actor ID, at UnixNano) ([]ExternalLink, error) {
	if actor == (ID{}) || at <= 0 {
		return nil, externalFault(Invalid, "external_invalid")
	}
	if err := ValidExternalOp(op, at); err != nil {
		return nil, err
	}
	out := append([]ExternalLink(nil), links...)
	at0 := -1
	for i, l := range out {
		if l.Provider == op.Provider {
			at0 = i
			break
		}
	}
	if at0 < 0 {
		if len(out) >= MaxExternalLinks {
			return nil, externalFault(Quota, "external_full")
		}
		switch op.Kind {
		case ExternalBegin:
			return append(out, ExternalLink{Provider: op.Provider, State: ExternalCreating, Marker: op.Marker, Project: op.Project, Actor: actor, At: at, Until: op.Until}), nil
		case ExternalAdopt:
			return append(out, ExternalLink{Provider: op.Provider, State: ExternalLinked, Marker: op.Marker, Project: op.Project, IID: op.IID, URL: op.URL, Actor: actor, At: at}), nil
		}
		return nil, externalFault(Conflict, "external_not_creating")
	}
	cur := out[at0]
	if cur.State == ExternalLinked {
		return nil, externalFault(Conflict, "external_already_linked")
	}
	if cur.Marker != op.Marker {
		return nil, externalFault(Conflict, "external_marker_mismatch")
	}
	switch op.Kind {
	case ExternalBegin:
		if cur.State == ExternalCreating && cur.Until > at {
			return nil, externalFault(Conflict, "external_in_progress")
		}
		if cur.Project != op.Project {
			return nil, externalFault(Conflict, "external_project_mismatch")
		}
		out[at0] = ExternalLink{Provider: op.Provider, State: ExternalCreating, Marker: op.Marker, Project: op.Project, Actor: actor, At: at, Until: op.Until}
	case ExternalEnd:
		if cur.State != ExternalCreating {
			return nil, externalFault(Conflict, "external_not_creating")
		}
		if op.Project != "" && op.Project != cur.Project {
			return nil, externalFault(Conflict, "external_project_mismatch")
		}
		next := ExternalLink{Provider: op.Provider, State: op.Result, Marker: cur.Marker, Project: cur.Project, Actor: actor, At: at, Code: op.Code}
		if op.Result == ExternalLinked {
			next.IID, next.URL = op.IID, op.URL
		}
		out[at0] = next
	case ExternalAdopt:
		if cur.State == ExternalCreating && cur.Until > at {
			return nil, externalFault(Conflict, "external_in_progress")
		}
		out[at0] = ExternalLink{Provider: op.Provider, State: ExternalLinked, Marker: cur.Marker, Project: op.Project, IID: op.IID, URL: op.URL, Actor: actor, At: at}
	}
	return out, nil
}
