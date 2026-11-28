// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/rules"
)

// This file is the rule authoring surface (POST /api/v1/rules): list, save and
// retire the rules of one project, and declare an operator replay, through the
// rule catalogue (rules.Catalogue) over control state.
//
// A save is the audited command of the catalogue: its command ID is replayed
// idempotently, the reason is recorded, the expression is parsed and
// type-checked under the pinned profile and feature set before anything is
// committed (a definition that fails is never stored), and expected_revision is
// the catalogue revision the author read (0 = the rule must not exist yet), so a
// stale author loses with a conflict instead of overwriting. The pinned version
// is assigned by the server (one more than the previous). Saving, retiring and
// declaring a replay need organization administration of the project's
// organization: rules.write is reserved by decision D20 and the control store
// admits only administrators for rule facts. Listing needs the project's
// telemetry.read grant, as the rules are what the project's alerts evaluate.
//
// Nothing here evaluates a rule: the leader-only background workers do
// (docs/operations/background-workers.md), so a saved rule takes effect at the
// next pass and a retired one stops at it.

// Rule operations.
const (
	RuleList   = "list"
	RuleSave   = "save"
	RuleRetire = "retire"
	RuleReplay = "replay"
)

// RuleLabel is one configured output label of a recording rule.
type RuleLabel struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RuleSpec is the closed definition of a rule on the wire. Durations are whole
// seconds; the pinned profile and feature set are explicit (they fix the
// language semantics, exactly as a query request does).
type RuleSpec struct {
	Kind                string      `json:"kind"`
	Profile             string      `json:"profile"`
	FeatureSet          string      `json:"feature_set"`
	Expression          string      `json:"expression"`
	IntervalSeconds     uint32      `json:"interval_seconds"`
	ForSeconds          uint32      `json:"for_seconds,omitempty"`
	RecoveryHoldSeconds uint32      `json:"recovery_hold_seconds,omitempty"`
	MissingData         string      `json:"missing_data,omitempty"`
	Severity            string      `json:"severity,omitempty"`
	RecordName          string      `json:"record_name,omitempty"`
	Labels              []RuleLabel `json:"labels,omitempty"`
}

// RuleReplayRequest is an operator replay declaration: late evaluations of the
// rule's grid points in [from_ns, to_ns] may notify.
type RuleReplayRequest struct {
	FromNS model.Int64 `json:"from_ns"`
	ToNS   model.Int64 `json:"to_ns"`
}

// RuleRequest is the closed POST /api/v1/rules body. A list carries only the
// selectors; a save carries command_id, rule_id, expected_revision, reason and
// the rule; a retire the same without the rule; a replay rule_id, reason and
// the window (its identity is the window, so a repeated declaration commits once).
type RuleRequest struct {
	Org              model.ID           `json:"org"`
	Project          model.ID           `json:"project_id"`
	Operation        string             `json:"operation"`
	CommandID        model.ID           `json:"command_id,omitempty"`
	RuleID           model.ID           `json:"rule_id,omitempty"`
	ExpectedRevision *model.Uint64      `json:"expected_revision,omitempty"`
	Reason           string             `json:"reason,omitempty"`
	Rule             *RuleSpec          `json:"rule,omitempty"`
	Replay           *RuleReplayRequest `json:"replay,omitempty"`
}

// RuleView is one catalogue entry as the page shows it.
type RuleView struct {
	RuleID    model.ID     `json:"rule_id"`
	Revision  model.Uint64 `json:"revision"`
	Version   model.Uint64 `json:"version"`
	Retired   bool         `json:"retired"`
	CreatedNS model.Int64  `json:"created_ns"`
	UpdatedNS model.Int64  `json:"updated_ns"`
	Rule      RuleSpec     `json:"rule"`
}

// RuleProfile is a pinned engine profile and its feature sets, what a rule may
// pin.
type RuleProfile struct {
	ID          string   `json:"id"`
	FeatureSets []string `json:"feature_sets"`
}

// RuleListAnswer is the answer to a list. RecordingAvailable says whether the
// node has a recording source for the project (a recording rule can only be
// saved when it has).
type RuleListAnswer struct {
	Org                model.ID      `json:"org"`
	Project            model.ID      `json:"project_id"`
	CanAuthor          bool          `json:"can_author"`
	RecordingAvailable bool          `json:"recording_available"`
	Profiles           []RuleProfile `json:"profiles"`
	Rules              []RuleView    `json:"rules"`
}

// RuleWriteAnswer is the answer to a committed save or retire: the rule as
// committed.
type RuleWriteAnswer struct {
	State ActionState `json:"state"`
	Rule  RuleView    `json:"rule"`
}

// RuleReplayAnswer is the answer to a committed replay declaration.
type RuleReplayAnswer struct {
	State  ActionState `json:"state"`
	RuleID model.ID    `json:"rule_id"`
	FromNS model.Int64 `json:"from_ns"`
	ToNS   model.Int64 `json:"to_ns"`
}

// recordingBinding holds the node's recording source behind an atomic pointer.
type recordingBinding struct{ source rules.RecordingSource }

// UseRecordingSource names the node's recording source, which the rule routes
// check recording rules against at save. A node without one refuses to save a
// recording rule. It may be called at any time (the serving process calls it
// once, at start).
func (p *Policies) UseRecordingSource(source rules.RecordingSource) {
	if source == nil {
		p.recording.Store(nil)
		return
	}
	p.recording.Store(&recordingBinding{source: source})
}

func (p *Policies) ruleCatalogue(authority *auth.Service) (*rules.Catalogue, error) {
	store, ok := p.directory.(rules.CatalogueControl)
	if !ok {
		return nil, model.Fail(model.Unavailable)
	}
	registry, err := rules.DefaultRegistry()
	if err != nil {
		return nil, model.Fail(model.Unavailable)
	}
	options := []rules.CatalogueOption{rules.WithCatalogueClock(func() model.UnixNano { return model.UnixNano(authority.Now().UnixNano()) })}
	if b := p.recording.Load(); b != nil {
		options = append(options, rules.WithRecordingSource(b.source))
	}
	return rules.NewCatalogue(store, registry, options...)
}

// maxRuleSeconds is the longest duration a rule field may carry (30 days, the
// bound of a hold); it keeps the conversion to nanoseconds from overflowing.
const maxRuleSeconds = 30 * 24 * 3600

func ruleFromSpec(id, project model.ID, s RuleSpec) (rules.Rule, error) {
	if s.IntervalSeconds > maxRuleSeconds || s.ForSeconds > maxRuleSeconds || s.RecoveryHoldSeconds > maxRuleSeconds || len(s.Labels) > 64 {
		return rules.Rule{}, invalid("rule_request_invalid")
	}
	labels := make(model.Labels, 0, len(s.Labels))
	for _, l := range s.Labels {
		labels = append(labels, model.Label{Name: l.Name, Value: l.Value})
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Name < labels[j].Name })
	if len(labels) == 0 {
		labels = nil
	}
	return rules.Rule{
		ID: id, Project: project, Kind: rules.Kind(s.Kind), Profile: s.Profile, FeatureSet: s.FeatureSet, Expression: s.Expression,
		Interval: time.Duration(s.IntervalSeconds) * time.Second, For: time.Duration(s.ForSeconds) * time.Second, RecoveryHold: time.Duration(s.RecoveryHoldSeconds) * time.Second,
		MissingData: rules.MissingData(s.MissingData), Severity: s.Severity, RecordName: s.RecordName, Labels: labels,
	}, nil
}

func ruleView(d rules.Definition) RuleView {
	r := d.Rule
	spec := RuleSpec{
		Kind: string(r.Kind), Profile: r.Profile, FeatureSet: r.FeatureSet, Expression: r.Expression,
		IntervalSeconds: uint32(r.Interval / time.Second), ForSeconds: uint32(r.For / time.Second), RecoveryHoldSeconds: uint32(r.RecoveryHold / time.Second),
		MissingData: string(r.MissingData), Severity: r.Severity, RecordName: r.RecordName,
	}
	for _, l := range r.Labels {
		spec.Labels = append(spec.Labels, RuleLabel{Name: l.Name, Value: l.Value})
	}
	return RuleView{RuleID: r.ID, Revision: model.Uint64(d.Revision), Version: model.Uint64(r.Version), Retired: d.Retired, CreatedNS: model.Int64(d.CreatedNS), UpdatedNS: model.Int64(d.UpdatedNS), Rule: spec}
}

// recordingAvailable reports whether recording rules could be saved for the
// project right now.
func (p *Policies) recordingAvailable(ctx context.Context, project model.ID) bool {
	b := p.recording.Load()
	if b == nil {
		return false
	}
	target, err := b.source.Recording(ctx)
	return err == nil && target.Project == project && target.Policy.Enabled
}

func registerRuleRoutes(mux *http.ServeMux, authority *auth.Service, policies *Policies) {
	mux.HandleFunc("POST /api/v1/rules", func(w http.ResponseWriter, r *http.Request) {
		credential, err := artifactCredential(authority, w, r)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		var body RuleRequest
		if err = decode(w, r, &body); err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Org == (model.ID{}) || body.Project == (model.ID{}) || !validRuleShape(body) {
			queryReply(w, nil, invalid("rule_request_invalid"))
			return
		}
		catalogue, err := policies.ruleCatalogue(authority)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		if body.Operation == RuleList {
			scope, err := authority.AuthorizeWrite(r.Context(), credential, body.Org, body.Project, auth.Read)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			defs, err := catalogue.List(r.Context(), scope, body.Project)
			if err == nil {
				err = authority.Revalidate(r.Context(), scope)
			}
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			answer := RuleListAnswer{Org: body.Org, Project: body.Project, Profiles: []RuleProfile{}, Rules: make([]RuleView, 0, len(defs)), RecordingAvailable: policies.recordingAvailable(r.Context(), body.Project)}
			// Whether the caller may author is what the page needs to offer the form;
			// the save itself is authorized again against the committed state.
			if _, aerr := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, auth.OrgAdmin); aerr == nil {
				answer.CanAuthor = true
			}
			registry, rerr := rules.DefaultRegistry()
			if rerr != nil {
				queryReply(w, nil, model.Fail(model.Unavailable))
				return
			}
			for _, p := range registry.Profiles() {
				entry := RuleProfile{ID: p.ID, FeatureSets: []string{}}
				for _, f := range p.FeatureSets {
					entry.FeatureSets = append(entry.FeatureSets, f.ID)
				}
				answer.Profiles = append(answer.Profiles, entry)
			}
			for _, d := range defs {
				answer.Rules = append(answer.Rules, ruleView(d))
			}
			queryReply(w, answer, nil)
			return
		}
		scope, err := authority.Authorize(r.Context(), credential, body.Org, []model.ID{body.Project}, auth.OrgAdmin)
		if err != nil {
			queryReply(w, nil, err)
			return
		}
		switch body.Operation {
		case RuleSave:
			rule, err := ruleFromSpec(body.RuleID, body.Project, *body.Rule)
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			def, err := catalogue.Save(r.Context(), scope, rules.SaveCommand{Command: body.CommandID, Project: body.Project, Rule: rule, ExpectedRevision: model.Revision(*body.ExpectedRevision), Reason: body.Reason})
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			queryReply(w, RuleWriteAnswer{State: ActionCommitted, Rule: ruleView(def)}, nil)
		case RuleRetire:
			def, err := catalogue.Retire(r.Context(), scope, rules.RetireCommand{Command: body.CommandID, Project: body.Project, Rule: body.RuleID, ExpectedRevision: model.Revision(*body.ExpectedRevision), Reason: body.Reason})
			if err != nil {
				queryReply(w, nil, err)
				return
			}
			queryReply(w, RuleWriteAnswer{State: ActionCommitted, Rule: ruleView(def)}, nil)
		default:
			from, to := model.UnixNano(body.Replay.FromNS), model.UnixNano(body.Replay.ToNS)
			err := catalogue.DeclareReplay(r.Context(), scope, body.Project, body.RuleID, from, to, body.Reason)
			queryReply(w, RuleReplayAnswer{State: ActionCommitted, RuleID: body.RuleID, FromNS: body.Replay.FromNS, ToNS: body.Replay.ToNS}, err)
		}
	})
}

// validRuleShape checks the closed shape of each operation: exactly the fields
// the operation takes, none of the others.
func validRuleShape(b RuleRequest) bool {
	noWrite := b.CommandID == (model.ID{}) && b.RuleID == (model.ID{}) && b.ExpectedRevision == nil && b.Reason == "" && b.Rule == nil && b.Replay == nil
	switch b.Operation {
	case RuleList:
		return noWrite
	case RuleSave:
		return b.CommandID != (model.ID{}) && b.RuleID != (model.ID{}) && b.ExpectedRevision != nil && b.Reason != "" && b.Rule != nil && b.Replay == nil
	case RuleRetire:
		return b.CommandID != (model.ID{}) && b.RuleID != (model.ID{}) && b.ExpectedRevision != nil && b.Reason != "" && b.Rule == nil && b.Replay == nil
	case RuleReplay:
		return b.CommandID == (model.ID{}) && b.RuleID != (model.ID{}) && b.ExpectedRevision == nil && b.Reason != "" && b.Rule == nil && b.Replay != nil && b.Replay.FromNS >= 0 && b.Replay.ToNS >= b.Replay.FromNS
	}
	return false
}
