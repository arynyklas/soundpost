// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// The owner and the external links are members of the stored issue record: they survive its JSON round trip, are omitted when there
// are none (a record written before they existed is the same bytes), and the read-only view hands out copies of them.
func TestGroupingIssueOwnerAndExternalRoundTripAndAreOmittedWhenAbsent(t *testing.T) {
	org, project, id := model.ID{1}, model.ID{2}, model.ID{3}
	bare := model.GroupingIssue{ID: id, Org: org, Project: project, GroupingVersion: 1, Fingerprint: model.Hash{9}, Workflow: "open", Revision: 1}
	raw, err := json.Marshal(bare)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"owner"`) || strings.Contains(string(raw), `"external"`) {
		t.Fatalf("an issue with no owner and no link names them: %s", raw)
	}

	owner := model.ID{0xa1}
	full := bare
	full.Owner = &owner
	full.External = []model.ExternalLink{{Provider: "gitlab", State: model.ExternalLinked, Marker: "soundpost-ref-0123", Project: "shop/web", IID: 12, URL: "https://git.example.test/shop/web/-/issues/12", Actor: model.ID{0xb1}, At: 77}}
	raw, err = json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	var back model.GroupingIssue
	if err = json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Owner == nil || *back.Owner != owner || len(back.External) != 1 || back.External[0] != full.External[0] {
		t.Fatalf("round trip: %s -> %+v", raw, back)
	}
	// The link keeps its time under a key the erasure window rule reads (`*_ns`).
	if !strings.Contains(string(raw), `"at_ns":"77"`) {
		t.Fatalf("the link time is not under at_ns: %s", raw)
	}

	st := model.ControlState{GroupingIssues: map[string]model.GroupingIssue{model.ReleaseScopeKey(org, project, id): full}}
	entries := model.ReadOnlyOf(&st).ProjectIssues(org, project)
	if len(entries) != 1 || entries[0].Issue.Owner == nil || *entries[0].Issue.Owner != owner || len(entries[0].Issue.External) != 1 {
		t.Fatalf("the read-only view lost the owner or the links: %+v", entries)
	}
	*entries[0].Issue.Owner = model.ID{0xee}
	entries[0].Issue.External[0].URL = "https://changed.example.test"
	if got := st.GroupingIssues[model.ReleaseScopeKey(org, project, id)]; *got.Owner != owner || got.External[0].URL != "https://git.example.test/shop/web/-/issues/12" {
		t.Fatalf("the read-only view aliases the stored issue: %+v", got)
	}
}
