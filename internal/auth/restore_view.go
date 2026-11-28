// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/arynyklas/soundpost/internal/model"
)

// RestoreItem names one quarantined item exactly as a Reconciliation does, with a
// human label. It carries no credential, password, TOTP or secret: only the
// identifiers an administrator already needs to name the item and what to call it.
type RestoreItem struct {
	Kind    ReconcileKind `json:"kind"`
	Org     string        `json:"org,omitempty"`
	User    string        `json:"user,omitempty"`
	Project string        `json:"project,omitempty"`
	Source  string        `json:"source,omitempty"`
	ID      string        `json:"id,omitempty"`
	Key     string        `json:"key,omitempty"`
	Label   string        `json:"label"`
}

// RestoreView is everything a restored installation still holds inactive.
type RestoreView struct {
	Pending int           `json:"pending"`
	Items   []RestoreItem `json:"items"`
}

// RestorePending reports how many quarantined items still await reconciliation: exactly
// the items RestoreItems lists. It is a count only (zero for an installation that was
// never restored or has nothing left), so it can be shown to every signed-in account.
func (s *Service) RestorePending(ctx context.Context) (int, error) {
	pending := 0
	err := s.store.View(model.WithoutBooks(ctx), func(st model.ControlState) error {
		raw, ok := st.OIDC[restoreStashKey]
		if !ok {
			return nil
		}
		var stash restoreStash
		if json.Unmarshal(raw, &stash) != nil {
			return nil
		}
		pending = len(restoreItems(st, stash))
		return nil
	})
	return pending, err
}

// RestoreItems lists the quarantined items one instance administrator can
// reconcile. A restored account may not look (it cannot vouch for restored
// accounts either); neither may a non-administrator.
func (s *Service) RestoreItems(ctx context.Context, c Credential) (RestoreView, error) {
	if c.service != s || c.machine {
		return RestoreView{}, model.Fail(model.Forbidden)
	}
	if _, err := s.Authenticate(ctx, c.token); err != nil {
		return RestoreView{}, err
	}
	view := RestoreView{Items: []RestoreItem{}}
	err := s.store.View(model.WithoutBooks(ctx), func(st model.ControlState) error {
		if err := s.validateCredentialState(st, c); err != nil {
			return err
		}
		if !st.Users[c.user.String()].Admin {
			return model.Fail(model.Forbidden)
		}
		raw, ok := st.OIDC[restoreStashKey]
		if !ok {
			return nil
		}
		var stash restoreStash
		if json.Unmarshal(raw, &stash) != nil {
			return model.Fail(model.Corrupt)
		}
		for _, id := range stash.Users {
			if id == c.user {
				return model.Fail(model.Forbidden)
			}
		}
		view.Items = restoreItems(st, stash)
		view.Pending = len(view.Items)
		return nil
	})
	return view, err
}

func restoreItems(st model.ControlState, stash restoreStash) []RestoreItem {
	items := []RestoreItem{}
	login := func(id string) string {
		if u, ok := st.Users[id]; ok && u.Email != "" {
			return u.Email
		}
		return id
	}
	for _, id := range stash.Users {
		items = append(items, RestoreItem{Kind: ReconcileAccount, User: id.String(), Label: login(id.String())})
	}
	for _, id := range stash.Sources {
		items = append(items, RestoreItem{Kind: ReconcileSource, Source: id.String(), Label: "source " + id.String()})
	}
	orgIDs := make([]string, 0, len(stash.Orgs))
	for id := range stash.Orgs {
		orgIDs = append(orgIDs, id)
	}
	sort.Strings(orgIDs)
	sortedKeys := func(n int, each func(add func(string))) []string {
		keys := make([]string, 0, n)
		each(func(k string) { keys = append(keys, k) })
		sort.Strings(keys)
		return keys
	}
	for _, orgID := range orgIDs {
		q := stash.Orgs[orgID]
		orgName := st.Orgs[orgID].Name
		in := func(what string) string { return what + " in " + orgName }
		for _, user := range sortedKeys(len(q.Admins), func(add func(string)) {
			for k := range q.Admins {
				add(k)
			}
		}) {
			items = append(items, RestoreItem{Kind: ReconcileOrgAdmin, Org: orgID, User: user, Label: in("organization administrator " + login(user))})
		}
		for _, user := range sortedKeys(len(q.Members), func(add func(string)) {
			for k := range q.Members {
				add(k)
			}
		}) {
			items = append(items, RestoreItem{Kind: ReconcileMembership, Org: orgID, User: user, Label: in("membership of " + login(user))})
		}
		for _, key := range sortedKeys(len(q.Grants), func(add func(string)) {
			for k := range q.Grants {
				add(k)
			}
		}) {
			user, project, _ := strings.Cut(key, ":")
			items = append(items, RestoreItem{Kind: ReconcileGrant, Org: orgID, User: user, Project: project, Label: in("grant of " + login(user) + " on project " + st.Orgs[orgID].Projects[project])})
		}
		for _, team := range sortedKeys(len(q.Teams), func(add func(string)) {
			for k := range q.Teams {
				add(k)
			}
		}) {
			items = append(items, RestoreItem{Kind: ReconcileTeam, Org: orgID, ID: team, Label: in("team " + team)})
		}
		for _, key := range sortedKeys(len(q.Integrations), func(add func(string)) {
			for k := range q.Integrations {
				add(k)
			}
		}) {
			if strings.HasPrefix(key, "team:") {
				continue // reinstated with its team
			}
			items = append(items, RestoreItem{Kind: ReconcileIntegration, Org: orgID, Key: key, Label: in(key)})
		}
		for _, key := range sortedKeys(len(q.Readers), func(add func(string)) {
			for k := range q.Readers {
				add(k)
			}
		}) {
			for _, user := range q.Readers[key] {
				items = append(items, RestoreItem{Kind: ReconcileReader, Org: orgID, ID: strings.TrimPrefix(key, "source_policy:"), User: user.String(), Label: in("reader " + login(user.String()) + " of " + key)})
			}
		}
	}
	return items
}
