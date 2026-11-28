// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the audited, versioned write path of a project's settings page
// (POST /api/v1/policies, decision D20): an organization administrator or a
// member holding policy.write on the project changes the project's retention
// and notification policy, and an administrator also an organization
// notification destination. It is the admin command transition itself
// (adminCommand: revision compare-and-set, command-ID binding, audit, epoch
// bump, sealed write-only secret), not a second implementation; what this file
// adds is the narrow authorization and the one setting the admin vocabulary
// did not have, the per-project notification policy.

// PolicyKinds are the admin command kinds PolicyCommand accepts.
const (
	PolicyKindRetention    = "retention"
	PolicyKindNotification = "notification_policy"
	PolicyKindDestination  = "destination"
)

// NotificationPolicyConfig is the client-supplied notification policy of one
// project. Durations are nanoseconds. Its fields mirror notify.Config; the
// caller validates them with notify.Config.Validate before committing, because
// this package cannot import the notification engine.
type NotificationPolicyConfig struct {
	ProjectID       model.ID `json:"project_id"`
	MinOperations   uint32   `json:"min_operations"`
	MinFailures     uint32   `json:"min_failures"`
	RateBasisPoints uint32   `json:"rate_basis_points"`
	RegressionMin   uint32   `json:"regression_min"`
	CriticalCodes   []string `json:"critical_codes"`
	FirstReminder   int64    `json:"first_reminder_ns"`
	ReminderEvery   int64    `json:"reminder_every_ns"`
	MaxSuppression  int64    `json:"max_suppression_ns"`
	DefaultZone     string   `json:"default_zone"`
}

// NotificationPolicyRecord is the committed form: the config and the revision
// the notification worker adopts it as. Revision 1 is the approved default every
// project starts on, so the first written policy is revision 2.
type NotificationPolicyRecord struct {
	NotificationPolicyConfig
	Revision model.Revision `json:"revision"`
}

// NotificationPolicySettingKey is the organization setting key of a project's policy.
func NotificationPolicySettingKey(project model.ID) string {
	return PolicyKindNotification + ":" + project.String()
}

// ReadNotificationPolicy is the committed policy of a project in o, if one was written.
func ReadNotificationPolicy(o model.ControlOrg, project model.ID) (NotificationPolicyRecord, bool, error) {
	raw, ok := o.Settings[NotificationPolicySettingKey(project)]
	if !ok {
		return NotificationPolicyRecord{}, false, nil
	}
	var rec NotificationPolicyRecord
	if json.Unmarshal(raw, &rec) != nil || rec.ProjectID != project || rec.Revision < 2 {
		return NotificationPolicyRecord{}, false, model.Fail(model.Corrupt)
	}
	return rec, true, nil
}

func writeNotificationPolicy(o *model.ControlOrg, p AdminPayload) error {
	if p.Secret != "" || p.ID == (model.ID{}) {
		return model.Fail(model.Invalid)
	}
	if _, ok := o.Projects[p.ID.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	var cfg NotificationPolicyConfig
	if err := strictConfig(p.Config, &cfg); err != nil {
		return err
	}
	if cfg.ProjectID != p.ID {
		return model.Fail(model.Invalid)
	}
	next := model.Revision(2)
	prev, found, err := ReadNotificationPolicy(*o, p.ID)
	if err != nil {
		return err
	}
	if found {
		next = prev.Revision + 1
	}
	raw, err := json.Marshal(NotificationPolicyRecord{NotificationPolicyConfig: cfg, Revision: next})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	if o.Settings == nil {
		o.Settings = map[string]json.RawMessage{}
	}
	o.Settings[NotificationPolicySettingKey(p.ID)] = raw
	return nil
}

// policyWriter is the authority a PolicyCommand runs under: a scope for exactly
// one project, derived by Service.AuthorizeWrite for policy.write (or
// organization administration), which the transition re-validates against the
// state it commits to.
type policyWriter struct {
	scope   Scope
	project model.ID
}

// authorize re-checks the scope inside the write transaction: it is this
// credential's, for this organization and project, and its organization epoch is
// still the one it was derived at, so a grant revoked since is refused here and
// not only at derivation.
func (w *policyWriter) authorize(s *Service, st model.ControlState, c Credential, org model.ID) error {
	sc := w.scope
	if sc.service != s || sc.credential.user != c.user || sc.credential.token != c.token || sc.credential.machine != c.machine ||
		sc.org != org || len(sc.projects) != 1 || sc.projects[0] != w.project || (sc.action != PolicyWrite && sc.action != OrgAdmin) {
		return model.Fail(model.Forbidden)
	}
	if err := sc.ValidateControlState(st); err != nil {
		return err
	}
	if sc.action == OrgAdmin && !st.Orgs[org.String()].Admins[c.user.String()] {
		return model.Fail(model.NotFound)
	}
	return nil
}

// allows is the stateless kind check. A policy.write holder changes the
// retention and the notification policy of its own project and nothing else;
// a destination routes every project of the organization, so it takes an
// administrator.
func (w *policyWriter) allows(kind string, p AdminPayload) error {
	switch kind {
	case PolicyKindRetention:
		var cfg RetentionConfig
		if err := strictConfig(p.Config, &cfg); err != nil {
			return err
		}
		if cfg.ProjectID != w.project {
			return model.Fail(model.NotFound)
		}
	case PolicyKindNotification:
		if p.ID != w.project {
			return model.Fail(model.NotFound)
		}
	case PolicyKindDestination:
		if w.scope.action != OrgAdmin {
			return model.Fail(model.Forbidden)
		}
	default:
		return model.Fail(model.Invalid)
	}
	return nil
}

// PolicyCommand commits one project-settings change under scope (derived with
// AuthorizeWrite for PolicyWrite on project). r is the admin command (command ID,
// kind, payload), committed with the same audit and command-ID binding, with one
// difference: ExpectedRevision is the organization's policy epoch the caller read
// (ControlOrg.Epoch), not the global control revision. The kind must be one of
// the PolicyKind constants.
func (s *Service) PolicyCommand(ctx context.Context, c Credential, scope Scope, project model.ID, r AdminCommandRequest) (model.ControlResult, error) {
	if project == (model.ID{}) {
		return model.ControlResult{}, model.Fail(model.Invalid)
	}
	return s.adminCommand(ctx, c, r, &policyWriter{scope: scope, project: project})
}
