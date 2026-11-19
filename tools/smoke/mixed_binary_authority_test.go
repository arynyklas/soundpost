// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// The previous release (5475ef6) declares protocol 5 but does not know the per-organization authority
// revision: a voter of it judges a retention command against AuthorityRevision alone, so a verified commit of an
// organization has to move that scalar as well as the organization's own revision (internal/control
// authority_org.go). Real binaries, three voters, the previous release on voter 3 and the candidate on voters 1
// and 2, the group bootstrapped by the previous release and every member declared protocol 5 (the candidates
// propose state patches). The check of a retention command is made by the voter that receives it (the voter that
// leads is the previous release here, which the trace records), so the command is sent through the previous-release
// voter and through a candidate. The command is a hold placement (POST /api/v1/admin/holds), whose expected_revision is
// the control revision the caller read (the state_revision every voter reports), not a policy revision:
//
//	A  a hold whose view is older than a retention commit of the SAME organization is refused (409) by the
//	   previous-release voter and by the candidate;
//	B  the same after an admin command (membership) of the same organization;
//	C  a view that is stale only because ANOTHER organization committed a retention-class command: the candidate
//	   accepts it (no cross-organization false conflict on a new leader); the previous-release voter may refuse it,
//	   as it always did (the upgrade window), which is recorded and not required.
//
// Environment: as TestMixedBinaryPostContractGuard (SOUNDPOST_MIXED_OLD_BINARY, SOUNDPOST_MIXED_NEW_BINARY,
// SOUNDPOST_MIXED_EVIDENCE).
func TestMixedBinaryStaleSameOrgCommandsAreRefusedByThePreviousReleaseLeader(t *testing.T) {
	m := newFreshMixedRun(t, "stale-same-org")
	m.finishFresh(m.runStaleSameOrg())
}

// controlView is the control revision voter id applied last (its state_revision): the view of a retention command.
func (m *mixedRun) controlView(id uint64) (model.Revision, error) {
	f := m.observe(id)
	if f.StateErr != "" {
		return 0, errors.New("voter state: " + f.StateErr)
	}
	n, err := strconv.ParseUint(strings.Trim(f.Revision, `"`), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("state revision %q: %w", f.Revision, err)
	}
	return model.Revision(n), nil
}

// holdAt places a legal hold on project of org through voter id with a stated view; it returns the status.
func (m *mixedRun) holdAt(id uint64, s auth.Session, org, project model.ID, view model.Revision) (int, string, error) {
	status, raw, err := postRetryStale(m.sites[id], "/api/v1/admin/holds", map[string]any{"command_id": model.NewID().String(), "expected_revision": strconv.FormatUint(uint64(view), 10),
		"org_id": org.String(), "project_ids": []string{project.String()}, "reason": "mixed-binary authority"}, s.CSRF, "", &m.stale)
	return status, trunc(string(raw), 160), err
}

// expectHold runs one hold on a stated view; want 0 means any 2xx.
func (m *mixedRun) expectHold(what string, id uint64, s auth.Session, org, project model.ID, view model.Revision, want int) error {
	status, body, err := m.holdAt(id, s, org, project, view)
	m.say("  %s: hold on voter %d (%s) at view %d answered %d %s", what, id, m.release[id], view, status, body)
	if err != nil {
		return err
	}
	if (want == 0 && (status < 200 || status > 299)) || (want != 0 && status != want) {
		return m.violate("authority_check", fmt.Sprintf("%s: voter %d (%s) answered %d, want %d (%s)", what, id, m.release[id], status, want, body))
	}
	return nil
}

// settledView waits until the three voters hold one state and returns its revision.
func (m *mixedRun) settledView(label string) (model.Revision, error) {
	if err := m.settle(label); err != nil {
		return 0, err
	}
	return m.controlView(1)
}

// adminAtRevision is one admin command of org on the epoch of the organization read just before it.
func (m *mixedRun) adminAtRevision(id uint64, s auth.Session, org model.ID, kind string, p auth.AdminPayload) error {
	p.Reason = "mixed-binary authority"
	payload, _ := json.Marshal(p)
	var last string
	for range 8 {
		view, err := m.controlView(id)
		if err != nil {
			return err
		}
		req := auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: view, OrgID: org, Kind: kind, Payload: payload}
		if kind != "create_org" { // the console's own precondition: the epoch of the organization it read
			status, raw, err := postRetryStale(m.sites[id], "/api/v1/admin/read", auth.AdminReadRequest{OrgID: org, Kind: "organization"}, s.CSRF, "", &m.stale)
			if err = requireSmokeResponse("admin_read_organization", status, 200, raw, err); err != nil {
				return err
			}
			var read auth.AdminView
			if err = json.Unmarshal(raw, &read); err != nil {
				return err
			}
			epoch := model.Uint64(read.Epoch)
			req.ExpectedEpoch = &epoch
		}
		status, raw, err := postRetryStale(m.sites[id], "/api/v1/admin/commands", req, s.CSRF, "", &m.stale)
		if err != nil {
			return err
		}
		if status == 200 || status == 202 {
			return nil
		}
		last = fmt.Sprintf("status %d %s", status, trunc(string(raw), 200))
		if status != 409 {
			break
		}
	}
	return errors.New("admin " + kind + ": " + last)
}

func (m *mixedRun) runStaleSameOrg() error {
	cleanup, err := m.startGroup(func(id uint64) string {
		if id == 3 {
			return "old"
		}
		return "new"
	})
	defer cleanup()
	if err != nil {
		return err
	}
	sNew, err := m.login(1)
	if err != nil {
		return err
	}
	sOld, err := m.login(3)
	if err != nil {
		return err
	}
	org, project := m.fx.org, m.fx.project
	via := []struct {
		id uint64
		s  auth.Session
	}{{3, sOld}, {1, sNew}}

	// A: stale after a retention commit of the same organization.
	for _, v := range via {
		view, err := m.settledView(fmt.Sprintf("A before the commit that makes the view stale (checked on voter %d)", v.id))
		if err != nil {
			return err
		}
		if err = m.expectHold("A the retention commit that makes the view stale", 1, sNew, org, project, view, 0); err != nil { // a retention-class command of the organization
			return err
		}
		if err = m.settle("A after the retention commit"); err != nil {
			return err
		}
		if err = m.expectHold("A same-organization stale view", v.id, v.s, org, project, view, 409); err != nil {
			return err
		}
		fresh, err := m.controlView(v.id)
		if err != nil {
			return err
		}
		if err = m.expectHold("A a fresh view", v.id, v.s, org, project, fresh, 0); err != nil {
			return err
		}
	}

	// B: stale after an admin command of the same organization.
	for _, v := range via {
		view, err := m.settledView(fmt.Sprintf("B before the admin command (checked on voter %d)", v.id))
		if err != nil {
			return err
		}
		if err = m.adminAtRevision(1, sNew, org, "membership", auth.AdminPayload{UserID: m.fx.reader.User, Enabled: false}); err != nil {
			return err
		}
		if err = m.settle("B after the admin command"); err != nil {
			return err
		}
		if err = m.expectHold("B same-organization view stale after an admin command", v.id, v.s, org, project, view, 409); err != nil {
			return err
		}
	}

	// C: a view stale only for another organization.
	orgB, projB := model.NewID(), model.NewID()
	for _, step := range []struct {
		kind string
		p    auth.AdminPayload
	}{{"create_org", auth.AdminPayload{Name: "stale view other tenant"}}, {"membership", auth.AdminPayload{UserID: sNew.User, Enabled: true}}, {"org_admin", auth.AdminPayload{UserID: sNew.User, Enabled: true}}, {"create_project", auth.AdminPayload{ID: projB, Name: "b"}}} {
		if err = m.adminAtRevision(1, sNew, orgB, step.kind, step.p); err != nil {
			return err
		}
	}
	commitB := func() error {
		if _, err := m.settledView("C before the other organization's retention commit"); err != nil {
			return err
		}
		viewB, err := m.controlView(1)
		if err != nil {
			return err
		}
		if err = m.expectHold("C the other organization's retention commit", 1, sNew, orgB, projB, viewB, 0); err != nil {
			return err
		}
		return m.settle("C after the other organization's retention commit")
	}
	view, err := m.settledView("C view of the organization")
	if err != nil {
		return err
	}
	if err = commitB(); err != nil {
		return err
	}
	status, body, err := m.holdAt(3, sOld, org, project, view)
	if err != nil {
		return err
	}
	m.say("  C previous-release voter, view stale only for another organization: %d %s (409 is the upgrade-window false conflict, 2xx is fine)", status, body)
	if status >= 200 && status <= 299 { // it committed, which makes the view stale for this organization: take a new one
		if view, err = m.settledView("C a new view of the organization"); err != nil {
			return err
		}
		if err = commitB(); err != nil {
			return err
		}
	}
	if err = m.expectHold("C candidate, view stale only for another organization", 1, sNew, org, project, view, 0); err != nil {
		return err
	}
	return m.settle("C final")
}
