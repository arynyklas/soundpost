// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"soundpost/internal/auth"
	"soundpost/internal/model"
	"strings"
	"unicode"
	"unicode/utf8"
)

// BindReleases installs one closed deterministic dispatcher per command kind on
// this Store only. Future C07 evidence apply extends applyIssueOperation rather
// than registering a second KindApplyIssueEvidence callback.
func (s *Store) BindReleases() error {
	if e := s.RegisterHandler(KindRegisterRelease, applyReleaseOperation); e != nil {
		return e
	}
	return s.RegisterHandler(KindApplyIssueEvidence, applyIssueOperation)
}
func decodeReleaseCommand(cmd Command) (model.ReleaseCommand, error) {
	var payload model.ReleaseCommand
	decoder := json.NewDecoder(bytes.NewReader(cmd.Payload))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&payload); e != nil {
		return payload, model.Fail(model.Invalid)
	}
	if e := decoder.Decode(new(any)); e != io.EOF {
		return payload, model.Fail(model.Invalid)
	}
	if payload.At <= 0 || payload.RequestID == (model.ID{}) {
		return payload, model.Fail(model.Invalid)
	}
	return payload, nil
}
func releaseScope(scope auth.Scope, st *State, org, project model.ID) error {
	if scope.Permission() != auth.OrgAdmin || scope.OrgID() != org || org == (model.ID{}) || project == (model.ID{}) {
		return model.Fail(model.NotFound)
	}
	authority, ok := st.Orgs[org.String()]
	if !ok || !authority.Admins[scope.PrincipalID().String()] {
		return model.Fail(model.NotFound)
	}
	if _, ok := authority.Projects[project.String()]; !ok {
		return model.Fail(model.NotFound)
	}
	if len(scope.ProjectIDs()) > 0 && !scope.AllowsProject(project) {
		return model.Fail(model.NotFound)
	}
	return nil
}
func applyReleaseOperation(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	payload, e := decodeReleaseCommand(cmd)
	if e != nil {
		return Effect{}, e
	}
	if payload.Operation != "register_release" || payload.Release == nil || payload.Migration != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	release := *payload.Release
	if e = releaseScope(scope, st, release.Org, release.Project); e != nil {
		return Effect{}, e
	}
	if release.ID == (model.ID{}) || release.BuildID == (model.ID{}) || release.BuildTime < 0 || len(release.Parents) > 64 || len(release.DebugArtifacts) > 1024 || !safeReleaseText(release.DisplayLabel, 256, true) || len(release.History) != 0 {
		return Effect{}, model.Fail(model.Invalid)
	}
	sort.Slice(release.Parents, func(i, j int) bool { return bytes.Compare(release.Parents[i][:], release.Parents[j][:]) < 0 })
	for i, parent := range release.Parents {
		if parent == (model.ID{}) || parent == release.ID || i > 0 && parent == release.Parents[i-1] {
			return Effect{}, model.Fail(model.Invalid)
		}
	}
	if len(release.Parents) == 0 {
		release.Parents = nil
	}
	sort.Slice(release.DebugArtifacts, func(i, j int) bool {
		return bytes.Compare(release.DebugArtifacts[i].ArtifactID[:], release.DebugArtifacts[j].ArtifactID[:]) < 0
	})
	for i, artifact := range release.DebugArtifacts {
		if artifact.ArtifactID == (model.ID{}) || artifact.SHA256 == (model.Hash{}) || !safeReleaseText(artifact.DebugID, 256, false) || i > 0 && artifact.ArtifactID == release.DebugArtifacts[i-1].ArtifactID {
			return Effect{}, model.Fail(model.Invalid)
		}
	}
	if len(release.DebugArtifacts) == 0 {
		release.DebugArtifacts = nil
	}
	key := model.ReleaseScopeKey(release.Org, release.Project, release.ID)
	prior, exists := st.Releases[key]
	if exists {
		if release.Revision != prior.Revision {
			return Effect{}, model.Fail(model.Conflict)
		}
		if release.BuildID != prior.BuildID || release.BuildTime != prior.BuildTime || !reflect.DeepEqual(release.Parents, prior.Parents) || !reflect.DeepEqual(release.DebugArtifacts, prior.DebugArtifacts) {
			return Effect{}, model.Fail(model.Conflict)
		}
		release.History = prior.History
	} else if release.Revision != 0 {
		return Effect{}, model.Fail(model.Conflict)
	}
	// Unknown parents are allowed. A later registration completing a cycle fails.
	pending := append([]model.ID(nil), release.Parents...)
	seen := map[model.ID]bool{}
	for len(pending) > 0 {
		id := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if id == release.ID {
			return Effect{}, model.Fail(model.Invalid)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if parent, ok := st.Releases[model.ReleaseScopeKey(release.Org, release.Project, id)]; ok {
			pending = append(pending, parent.Parents...)
		}
	}
	release.Revision++
	release.History = append(release.History, model.ReleaseLabelRevision{ControlRevision: st.Revision + 1, Revision: release.Revision, DisplayLabel: release.DisplayLabel})
	if st.Releases == nil {
		st.Releases = map[string]model.Release{}
	}
	st.Releases[key] = release
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: "releases.register", Reason: "immutable release registration or display label update", Time: int64(payload.At), Org: scope.OrgID().String(), PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{release.ID}, RequestID: payload.RequestID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{release.ID}, Phase: "registered"}, nil
}
func applyIssueOperation(scope auth.Scope, st *State, cmd Command) (Effect, error) {
	payload, e := decodeReleaseCommand(cmd)
	if e != nil {
		return Effect{}, e
	}
	if payload.Operation != "grouping_migration" || payload.Migration == nil || payload.Release != nil {
		return Effect{}, model.Fail(model.Invalid)
	}
	migration := *payload.Migration
	if e = releaseScope(scope, st, migration.Org, migration.Project); e != nil {
		return Effect{}, e
	}
	if migration.ID == (model.ID{}) || migration.From == (model.ID{}) || migration.To == (model.ID{}) || migration.From == migration.To || migration.GroupingVersion == 0 || migration.Fingerprint == (model.Hash{}) || migration.At <= 0 || !safeReleaseText(migration.Reason, 1024, false) || strings.TrimSpace(migration.Reason) == "" {
		return Effect{}, model.Fail(model.Invalid)
	}
	fromKey := model.ReleaseScopeKey(migration.Org, migration.Project, migration.From)
	toKey := model.ReleaseScopeKey(migration.Org, migration.Project, migration.To)
	migrationKey := model.ReleaseScopeKey(migration.Org, migration.Project, migration.ID)
	prior, ok := st.GroupingIssues[fromKey]
	if !ok || prior.Org != migration.Org || prior.Project != migration.Project || prior.ID != migration.From {
		return Effect{}, model.Fail(model.NotFound)
	}
	if prior.Revision != migration.FromRevision {
		return Effect{}, model.Fail(model.Conflict)
	}
	if prior.GroupingVersion == migration.GroupingVersion {
		return Effect{}, model.Fail(model.Invalid)
	}
	if _, exists := st.GroupingIssues[toKey]; exists {
		return Effect{}, model.Fail(model.Conflict)
	}
	if _, exists := st.GroupingMigrations[migrationKey]; exists {
		return Effect{}, model.Fail(model.Conflict)
	}
	prior.MigrationLinks = append(prior.MigrationLinks, migration.ID)
	prior.Revision++
	next := model.GroupingIssue{ID: migration.To, Org: migration.Org, Project: migration.Project, GroupingVersion: migration.GroupingVersion, Fingerprint: migration.Fingerprint, Workflow: "open", Revision: 1, MigrationLinks: []model.ID{migration.ID}}
	if st.GroupingMigrations == nil {
		st.GroupingMigrations = map[string]model.GroupingMigration{}
	}
	st.GroupingIssues[fromKey] = prior
	st.GroupingIssues[toKey] = next
	st.GroupingMigrations[migrationKey] = migration
	st.Audits = append(st.Audits, model.ControlAudit{ID: cmd.CommandID, Principal: scope.PrincipalID(), Action: "issues.grouping_migration", Reason: migration.Reason, Time: int64(payload.At), Org: scope.OrgID().String(), PolicyEpoch: scope.PolicyEpoch(), Targets: []model.ID{migration.From, migration.To, migration.ID}, RequestID: payload.RequestID, Outcome: model.AuditAllowed})
	return Effect{AffectedIDs: []model.ID{migration.From, migration.To, migration.ID}, Phase: "grouping_migrated"}, nil
}
func safeReleaseText(value string, max int, empty bool) bool {
	if (!empty && value == "") || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
