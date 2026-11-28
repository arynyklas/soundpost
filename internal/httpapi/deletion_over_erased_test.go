// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// [11.03-W1] A REAL range deletion over the real HTTP routes (real control store, 64-slot
// replicated storage engine, retention service) reports, in the JSON it answers and in the JSON
// the lifecycle poll answers, the opaque incident states it had to erase without a recorded
// window: "over_erased":[{"book":"incident","count":"1"}]. The state inside the range and the
// state after it are not counted; a retirement reports none.
func TestRealRangeDeletionReportsOverErasedInItsJSON(t *testing.T) {
	e := newFenceEnv(t)
	scope, err := e.auth.Authorize(e.ctx, e.ownerCr, e.org, nil, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	incident := func(extra string) {
		t.Helper()
		id := model.NewID()
		state := json.RawMessage(fmt.Sprintf(`{"incident_id":%q,"org_id":%q,"project_id":%q,"version":"1"%s}`, id.String(), e.org.String(), e.project.String(), extra))
		raw, err := json.Marshal(control.IncidentCommand{Project: e.project, Incident: id, Action: "open", Origin: "human", Actor: e.owner.User, At: 100, NewVersion: 1, State: state, Digest: model.Hash(sha256.Sum256(state))})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.store.Transact(e.ctx, scope, control.Command{CommandID: model.NewID(), ExpectedRevision: e.revision(), Kind: string(control.KindIncidentAction), Payload: raw}); err != nil {
			t.Fatal(err)
		}
	}
	// the first: its window meets the range; the second: all after it; the third: no window, so
	// erased fail-closed and counted
	incident(`,"at":"60"`)
	incident(`,"at":"1000"`)
	incident(`,"labels":{"a":"b"}`)

	const want = `"over_erased":[{"book":"incident","count":"1"}]`
	command := model.NewID()
	status, raw := e.do("POST", "/api/v1/admin/deletions", map[string]any{"command_id": command.String(), "expected_revision": strconv.FormatUint(uint64(e.revision()), 10), "mode": model.DeleteHistoricalRange,
		"org_id": e.org.String(), "project_ids": []string{e.project.String()}, "signals": []string{string(model.Metric)}, "start_ns": "40", "end_ns": "100", "reason": "range erasure"})
	if status != 202 || !strings.Contains(string(raw), want) {
		t.Fatalf("the begin response does not carry %s: %d %s", want, status, raw)
	}
	if err = e.svc.RunOnce(e.ctx); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/operations/" + command.String(), "/api/v1/lifecycle/operations/" + command.String() + "?org=" + e.org.String()} {
		status, raw = e.do("GET", path, nil)
		if status != 200 || !strings.Contains(string(raw), want) {
			t.Fatalf("poll %s does not carry %s: %d %s", path, want, status, raw)
		}
	}

	status, raw = e.do("POST", "/api/v1/admin/deletions", map[string]any{"command_id": model.NewID().String(), "expected_revision": strconv.FormatUint(uint64(e.revision()), 10), "mode": model.DeleteRetireProject,
		"org_id": e.org.String(), "project_ids": []string{e.bystand.String()}, "reason": "retirement"})
	if status != 202 || strings.Contains(string(raw), "over_erased") {
		t.Fatalf("a retirement must not carry over_erased: %d %s", status, raw)
	}
}
