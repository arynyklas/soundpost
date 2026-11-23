// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"context"
	"encoding/json"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
)

// The human side of the issue lifecycle (resolve, ignore, unignore, reopen and
// the audited grouping migration): the same issues.Service the background
// producer drives, bound to the people's authority instead of the runner's. The
// scope is the caller's own (an issues.write grant, or an organization
// administrator), derived from the credential by the C11 route; this file mints
// nothing.
//
//	POST /api/v1/actions (entity_kind issue)
//	  -> httpapi.Actions.issueAct
//	  -> issues.Service.Act        scope, revision compare-and-set, command retry
//	  -> control.TransactIssues    one control transaction with the audit
//	  -> issueMigrator             the grouping migration, through the same door

// BindIssueActions installs the issue lifecycle on the C11 action surface. Until
// it runs every issue action answers not_available (nothing changed). It also
// binds the stored-error reader of the issue evidence view: the issue evidence
// lists occurrences by record, and the record behind one is read through the
// storage scan under the caller's own telemetry scope.
func (a *App) BindIssueActions() error {
	svc, err := a.NewIssueActions(releaseActionClock{})
	if err != nil {
		return err
	}
	a.Actions.BindIssues(svc)
	// The same lifecycle serves error issues to project readers (telemetry.read) and issues.write holders: the investigate issue
	// kind and the issue and occurrence evidence views read through it under the caller's own scope.
	if a.Investigator != nil {
		a.Investigator.WithIssues(svc)
	}
	if a.Evidence != nil {
		a.Evidence = a.Evidence.With(httpapi.WithErrorOccurrences(httpapi.NewStorageErrorSource(a.Storage)), httpapi.WithRegressionExplanations(svc), httpapi.WithIssueLifecycle(svc))
	}
	return nil
}

// NewIssueActions builds the issue lifecycle service of human actions over the
// control store. The deletion fence, the release graph, the policy.write proof
// and the migration are the node's own (the control store); clock stamps the
// audit and the migration.
func (a *App) NewIssueActions(clock issues.Clock) (*issues.Service, error) {
	store, err := issues.NewControlStore(a.Control)
	if err != nil {
		return nil, err
	}
	return issues.New(issues.Deps{Store: store, Authorizer: a.Auth, Graphs: humanReleaseGraphs{a}, Fence: humanIssueFence{a}, Policy: a.Control,
		Migrator: issueMigrator{a, clock}, Clock: clock, Regression: issues.RegressionPolicy{MinOccurrences: 1}, Contracted: a.orgContracted, RecordFormat: a.recordFormat})
}

// orgContracted reports whether the organization is contracted (model.IndexesContractedKey): the D93
// writes of an issue owner and external links wait for it, because the previous release cannot read them.
func (a *App) orgContracted(ctx context.Context, org model.ID) (bool, error) {
	contracted := false
	err := a.Control.View(ctx, func(st model.ControlState) error {
		contracted = st.Orgs[org.String()].IndexesContracted()
		return nil
	})
	return contracted, err
}

// humanIssueFence denies a project whose deletion saga is fencing: the lifecycle
// of its issues is neither read nor changed under a pending fence, and the denial
// is retryable, never a success.
type humanIssueFence struct{ app *App }

func (f humanIssueFence) Admit(ctx context.Context, scope auth.Scope, project model.ID) error {
	fenced, err := f.app.Control.ProjectFenced(ctx, scope.OrgID(), project)
	if err != nil {
		return err
	}
	if fenced {
		fault := model.Fail(model.Unavailable)
		fault.Retryable, fault.SafeDetail = true, "deletion_fencing"
		return fault
	}
	return nil
}

// humanReleaseGraphs serves the release graph to a person's resolve action (the
// fixed-descendant frontier). The scope must be admitted to the project's issue
// lifecycle in the very state the graph is read from.
type humanReleaseGraphs struct{ app *App }

func (g humanReleaseGraphs) Graph(ctx context.Context, scope auth.Scope, project model.ID) (releases.Graph, error) {
	if scope.IsSystem() || !scope.AllowsProject(project) {
		return nil, model.Fail(model.Forbidden)
	}
	if err := g.app.Control.AuthorizeIssueWrite(ctx, scope, project); err != nil {
		return nil, err
	}
	out := releases.Graph{}
	err := g.app.Control.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		org := scope.OrgID()
		for _, release := range st.Releases {
			if release.Org == org && release.Project == project {
				out[release.ID] = release
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// issueMigrator commits the audited grouping migration under the caller's own
// scope through control.TransactIssues, which admits an organization
// administrator, or a member holding both issues.write and policy.write on the
// project, and refuses the runner. The command ID is the action's, so a retry is
// answered with the first result.
type issueMigrator struct {
	app   *App
	clock issues.Clock
}

func (m issueMigrator) MigrateGrouping(ctx context.Context, scope auth.Scope, migration model.GroupingMigration, command model.ID) error {
	payload, err := json.Marshal(model.ReleaseCommand{Operation: "grouping_migration", At: m.clock.Now(), RequestID: model.RequestCorrelationID(ctx, command), Migration: &migration})
	if err != nil {
		return model.Fail(model.Invalid)
	}
	res, err := m.app.Control.TransactIssues(ctx, scope, control.Command{CommandID: command, Kind: string(control.KindApplyIssueEvidence), Payload: payload})
	if err != nil {
		return err
	}
	if len(res.AffectedIDs) != 3 {
		return model.Fail(model.Corrupt)
	}
	return nil
}
