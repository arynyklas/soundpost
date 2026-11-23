// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

// This file is the deploy marker store of the console (docs/operations/console-api.md, section 7):
// the time a release was deployed to an environment, as a fact somebody recorded. The build time of
// a release is never a deploy time. A marker is the organization setting
// deploy:<project>:<release>:<environment> and holds the first and the last time and a count.
//
// A marker is operational data, not authority: recording one does not move the organization's policy
// epoch (a pipeline that deploys all day must not end every console scope of the organization), and
// the transition is the one commit of an organization-scoped admin command (command-ID binding,
// audit, the same per-organization writer).

const (
	deployKeyPrefix = "deploy:"
	deployAction    = "releases.deploy"
	// MaxDeployMarkersPerProject bounds the markers one project keeps. At the bound a new
	// (release, environment) is refused (quota, deploy_markers_full); nothing is dropped.
	MaxDeployMarkersPerProject = 4096
	// DeployFutureSkew is how far past the server clock a recorded deploy time may be.
	DeployFutureSkew = 5 * time.Minute
	// MaxDeployListProjects bounds the projects of one list.
	MaxDeployListProjects = 16
)

// DeployMarkerFull is the closed detail of the quota refusal of a full project.
const DeployMarkerFull = "deploy_markers_full"

// Closed details of the refusals a deploy record can answer.
const (
	DeployEnvironmentUnknown = "deploy_environment_unknown"
	DeployTimeInvalid        = "deploy_time_invalid"
)

type deployRecordJSON struct {
	First int64  `json:"first"`
	Last  int64  `json:"last"`
	Count uint64 `json:"count"`
}

// DeployKey is the organization setting key of one marker.
func DeployKey(project, release, environment model.ID) string {
	return deployKeyPrefix + project.String() + ":" + release.String() + ":" + environment.String()
}

// DeployRecord is one deploy to record. DeployedAt zero means the server clock.
type DeployRecord struct {
	CommandID   model.ID
	Org         model.ID
	Project     model.ID
	Release     model.ID
	Environment model.ID
	DeployedAt  int64
}

// DeployItem is one marker as the console reads it.
type DeployItem struct {
	ProjectID model.ID     `json:"project_id"`
	ReleaseID model.ID     `json:"release_id"`
	Env       model.ID     `json:"environment"`
	First     model.Int64  `json:"first_deployed_at"`
	Last      model.Int64  `json:"last_deployed_at"`
	Count     model.Uint64 `json:"count"`
}

func detailFault(code model.Code, detail string) error {
	f := model.Fail(code)
	f.SafeDetail = detail
	return f
}

// parseDeployKey splits a marker key; ok is false for any other setting.
func parseDeployKey(key string) (project, release, environment model.ID, ok bool) {
	rest, found := strings.CutPrefix(key, deployKeyPrefix)
	if !found {
		return
	}
	parts := strings.Split(rest, ":")
	if len(parts) != 3 {
		return
	}
	var err error
	if project, err = model.ParseID(parts[0]); err != nil {
		return model.ID{}, model.ID{}, model.ID{}, false
	}
	if release, err = model.ParseID(parts[1]); err != nil {
		return model.ID{}, model.ID{}, model.ID{}, false
	}
	if environment, err = model.ParseID(parts[2]); err != nil {
		return model.ID{}, model.ID{}, model.ID{}, false
	}
	return project, release, environment, true
}

// environmentActive reports whether an ACTIVE source policy of the project lists the environment.
func (s *Service) environmentActive(st model.ControlState, org, project, environment model.ID) bool {
	now := s.now()
	for _, src := range st.Sources {
		if src.Org != org || src.Project != project || sourceState(src, now) != SourceActive {
			continue
		}
		if hasID(src.Policy.Resources.Environments, environment) {
			return true
		}
	}
	return false
}

// RecordDeploy records one deploy under an organization-administrator scope for the one project
// (Authorize with OrgAdmin: a person's session, or a server token that holds org.admin on the
// project). The release must exist and the environment must be listed by an active source policy of
// the project. The earliest time is kept; the count is the number of recordings. Both the scope and
// the organization administrator are checked against the very state the marker is written to.
func (s *Service) RecordDeploy(ctx context.Context, scope Scope, rec DeployRecord) (DeployItem, error) {
	if rec.CommandID == (model.ID{}) || rec.Org == (model.ID{}) || rec.Project == (model.ID{}) || rec.Release == (model.ID{}) || rec.Environment == (model.ID{}) || rec.DeployedAt < 0 {
		return DeployItem{}, model.Fail(model.Invalid)
	}
	at := rec.DeployedAt
	if at == 0 {
		at = s.now().UnixNano()
	} else if at > s.now().Add(DeployFutureSkew).UnixNano() {
		return DeployItem{}, detailFault(model.Invalid, DeployTimeInvalid)
	}
	c := scope.credential
	if scope.service != s || scope.org != rec.Org || len(scope.projects) != 1 || scope.projects[0] != rec.Project || scope.action != OrgAdmin || scope.sourceCredential != nil {
		return DeployItem{}, model.Fail(model.Forbidden)
	}
	digest := payloadDigest(deployAction, rec.Project.String(), rec.Release.String(), rec.Environment.String(), timeOrDefault(rec.DeployedAt))
	req := AdminCommandRequest{CommandID: rec.CommandID, OrgID: rec.Org, Kind: "deploy"}
	key := DeployKey(rec.Project, rec.Release, rec.Environment)
	var item DeployItem
	err := s.updateAdmin(ctx, req, func(st *model.ControlState) error {
		if err := scope.ValidateControlState(*st); err != nil {
			return err
		}
		if _, retired := st.RetiredOrgs[rec.Org.String()]; retired {
			return model.Fail(model.NotFound)
		}
		o, ok := st.Orgs[rec.Org.String()]
		if !ok || !o.Admins[c.user.String()] {
			return model.Fail(model.NotFound)
		}
		if _, live := o.Projects[rec.Project.String()]; !live {
			return model.Fail(model.NotFound)
		}
		binding := c.user.String() + ":" + rec.Org.String() + ":deploy"
		if old, replay := st.Commands[rec.CommandID.String()]; replay {
			if st.CommandOwners[rec.CommandID.String()] != binding {
				return model.Fail(model.NotFound)
			}
			if len(old.AffectedIDs) != 2 || old.AffectedIDs[1] != digest {
				return model.Fail(model.Conflict)
			}
			var err error
			item, err = deployItemOf(o, key)
			return err
		}
		if rel, ok := st.Releases[model.ReleaseScopeKey(rec.Org, rec.Project, rec.Release)]; !ok || rel.Org != rec.Org || rel.Project != rec.Project {
			return model.Fail(model.NotFound)
		}
		if !s.environmentActive(*st, rec.Org, rec.Project, rec.Environment) {
			return detailFault(model.Invalid, DeployEnvironmentUnknown)
		}
		if o.Settings == nil {
			o.Settings = map[string]json.RawMessage{}
		}
		marker := deployRecordJSON{First: at, Last: at, Count: 1}
		if raw, exists := o.Settings[key]; exists {
			var prior deployRecordJSON
			if json.Unmarshal(raw, &prior) != nil || prior.Count == 0 {
				return model.Fail(model.Corrupt)
			}
			marker = deployRecordJSON{First: min(prior.First, at), Last: max(prior.Last, at), Count: prior.Count + 1}
		} else if countDeployMarkers(o, rec.Project) >= MaxDeployMarkersPerProject {
			return detailFault(model.Quota, DeployMarkerFull)
		}
		raw, _ := json.Marshal(marker)
		o.Settings[key] = raw
		st.Orgs[rec.Org.String()] = o
		st.Audits = append(st.Audits, model.ControlAudit{ID: rec.CommandID, Principal: c.user, Action: deployAction, Reason: "deploy marker recorded", Time: s.now().UnixNano(), Org: rec.Org.String(), PolicyEpoch: o.Epoch, Targets: []model.ID{rec.Org, rec.Project, rec.Release, rec.Environment}, RequestID: model.RequestCorrelationID(ctx, rec.CommandID), Outcome: model.AuditAllowed})
		out := model.ControlResult{Revision: st.Revision + 1, Cursor: model.Cursor{Group: st.Installation, Index: model.Uint64(st.Revision + 1)}, AffectedIDs: []model.ID{rec.Release, digest}}
		if st.CommandOwners == nil {
			st.CommandOwners = map[string]string{}
		}
		if st.Commands == nil {
			st.Commands = map[string]model.ControlResult{}
		}
		st.CommandOwners[rec.CommandID.String()] = binding
		st.Commands[rec.CommandID.String()] = out
		item = DeployItem{ProjectID: rec.Project, ReleaseID: rec.Release, Env: rec.Environment, First: model.Int64(marker.First), Last: model.Int64(marker.Last), Count: model.Uint64(marker.Count)}
		return nil
	})
	return item, err
}

// timeOrDefault names the requested time in a command digest: a default (server clock) time is not
// part of the command's content.
func timeOrDefault(at int64) string {
	if at == 0 {
		return "server_clock"
	}
	return time.Unix(0, at).UTC().Format(time.RFC3339Nano)
}

func deployItemOf(o model.ControlOrg, key string) (DeployItem, error) {
	project, release, environment, ok := parseDeployKey(key)
	raw, present := o.Settings[key]
	var rec deployRecordJSON
	if !ok || !present || json.Unmarshal(raw, &rec) != nil || rec.Count == 0 {
		return DeployItem{}, model.Fail(model.Corrupt)
	}
	return DeployItem{ProjectID: project, ReleaseID: release, Env: environment, First: model.Int64(rec.First), Last: model.Int64(rec.Last), Count: model.Uint64(rec.Count)}, nil
}

func countDeployMarkers(o model.ControlOrg, project model.ID) int {
	prefix := deployKeyPrefix + project.String() + ":"
	n := 0
	for key := range o.Settings {
		if strings.HasPrefix(key, prefix) {
			n++
		}
	}
	return n
}

// ListDeploys lists the markers of the scope's projects (the scope is a reader's: telemetry.read,
// incidents.write or organization admin), for one release when release is set. A marker that cannot
// be read is damage and fails the read; a project outside the scope has no item.
func (s *Service) ListDeploys(ctx context.Context, scope Scope, projects []model.ID, release model.ID) ([]DeployItem, error) {
	if scope.service != s || scope.sourceCredential != nil || len(projects) == 0 || len(projects) > MaxDeployListProjects {
		return nil, model.Fail(model.Forbidden)
	}
	for _, p := range projects {
		if !scope.AllowsProject(p) {
			return nil, model.Fail(model.NotFound)
		}
	}
	var out []DeployItem
	err := s.store.View(ctx, func(st model.ControlState) error {
		if err := scope.ValidateControlState(st); err != nil {
			return err
		}
		o, ok := st.Orgs[scope.org.String()]
		if !ok {
			return model.Fail(model.NotFound)
		}
		for key := range o.Settings {
			project, rel, _, isMarker := parseDeployKey(key)
			if !isMarker || !hasID(projects, project) || release != (model.ID{}) && rel != release {
				continue
			}
			if _, live := o.Projects[project.String()]; !live {
				continue
			}
			item, err := deployItemOf(o, key)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(a, b DeployItem) int {
		if c := slices.Compare(a.ProjectID[:], b.ProjectID[:]); c != 0 {
			return c
		}
		if c := slices.Compare(a.ReleaseID[:], b.ReleaseID[:]); c != 0 {
			return c
		}
		return slices.Compare(a.Env[:], b.Env[:])
	})
	return out, nil
}
