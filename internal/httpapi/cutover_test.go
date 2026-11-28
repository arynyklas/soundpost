// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func (e *polEnv) postCutover(who person, body any) (int, []byte) {
	e.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/cutover", bytes.NewReader(raw))
	req.Header.Set("Cookie", "__Host-soundpost="+who.Session.Token)
	req.Header.Set("X-CSRF-Token", who.Session.CSRF)
	req.Header.Set("Origin", e.srv.URL)
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func cutoverBody(org, project model.ID) map[string]any {
	return map[string]any{"org": org.String(), "project_id": project.String()}
}

// The cutover view is the committed ownership cutover of a project as a read-only
// answer: the phase, owners and timeline without the operator's reasons, the legacy
// owner's read-only history boundary, and nothing at all for a project with no
// cutover. Only policy.write and administration read it; everyone else, another
// project and a malformed request are refused, and reading changes no state.
func TestCutoverViewIsReadOnlySanitizedAndScoped(t *testing.T) {
	e := newPolEnv(t)
	p1, p2 := model.NewID(), model.NewID()
	org := e.org("cutover view org", p1, p2)
	admin := e.user(org, "admin-cv@example.test")
	writer := e.user(org, "writer-cv@example.test")
	reader := e.user(org, "reader-cv@example.test")
	e.cmd(org, "org_admin", auth.AdminPayload{UserID: admin.ID, Enabled: true})
	e.grant(org, writer, p1, true, auth.PolicyWrite)
	e.grant(org, reader, p1, true, auth.Read)

	// No cutover yet: the product is the only owner; there is no boundary and no shadow.
	status, raw := e.postCutover(writer, cutoverBody(org, p1))
	var none control.CutoverView
	if err := json.Unmarshal(raw, &none); status != http.StatusOK || err != nil || none.Cutover != nil || none.Shadow.Decisions != 0 || none.Shadow.Observing || len(none.History.Spans) != 0 || none.History.Importer || none.History.LegacyHistory != "read_only" {
		t.Fatalf("a project without a cutover: %d %v %s", status, err, raw)
	}

	// The operator flow commits two transitions (the notify service does exactly this call).
	scope, err := e.app.Auth.Authorize(e.ctx, admin.Cred, org, []model.ID{p1}, auth.OrgAdmin)
	if err != nil {
		t.Fatal(err)
	}
	oldOwner, newOwner, source := model.ID{0x01, 0xc0}, model.ID{0x02, 0xc0}, model.NewID()
	frontier := []control.CutoverFrontier{{Source: source, Version: 1, Cursor: model.Cursor{Group: model.NewID(), Index: 7}}}
	t0 := model.UnixNano(time.Now().UnixNano())
	const reason = "OPERATOR-PRIVATE-REASON-5d41"
	first, err := e.app.Control.TransactCutover(e.ctx, scope, model.NewID(), control.CutoverTransition{Project: p1, Old: oldOwner, New: newOwner, Phase: control.CutoverShadow, At: t0, Reason: reason, Frontier: frontier})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.app.Control.TransactCutover(e.ctx, scope, model.NewID(), control.CutoverTransition{Project: p1, ExpectedRevision: first.Revision, Old: oldOwner, New: newOwner, Phase: control.CutoverQuiescingOld, At: t0 + model.UnixNano(time.Minute), Reason: reason, Frontier: frontier}); err != nil {
		t.Fatal(err)
	}
	var revisionBefore model.Revision
	_ = e.app.Control.View(e.ctx, func(st model.ControlState) error { revisionBefore = st.Revision; return nil })

	for name, who := range map[string]person{"administrator": admin, "policy.write holder": writer} {
		status, raw = e.postCutover(who, cutoverBody(org, p1))
		if status != http.StatusOK {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
		if strings.Contains(string(raw), reason) || strings.Contains(string(raw), `"reason"`) || strings.Contains(string(raw), `"evidence"`) {
			t.Fatalf("%s: the view carries operator text or evidence: %s", name, raw)
		}
		var v control.CutoverView
		if err = json.Unmarshal(raw, &v); err != nil || v.Org != org || v.Project != p1 || v.Cutover == nil {
			t.Fatalf("%s: %v %s", name, err, raw)
		}
		c := v.Cutover
		if c.Phase != control.CutoverQuiescingOld || c.OldOwner != oldOwner || c.NewOwner != newOwner || len(c.ActiveOwners) != 1 || c.ActiveOwners[0] != oldOwner || len(c.Frontier) != 1 || c.Frontier[0].Source != source || c.Frontier[0].Cursor.Index != 7 || c.Restore.Pending != nil {
			t.Fatalf("%s: cutover state %+v", name, c)
		}
		if len(c.Timeline) != 2 || c.Timeline[0].To != control.CutoverShadow || c.Timeline[1].From != control.CutoverShadow || c.Timeline[1].To != control.CutoverQuiescingOld || c.Timeline[1].Principal != admin.ID {
			t.Fatalf("%s: timeline %+v", name, c.Timeline)
		}
		if !v.Shadow.Observing || v.Shadow.Decisions != 0 || len(v.Shadow.Recent) != 0 {
			t.Fatalf("%s: shadow %+v", name, v.Shadow)
		}
		h := v.History
		if h.LegacyOwner == nil || *h.LegacyOwner != oldOwner || h.LegacyHistory != "read_only" || h.Importer || len(h.Spans) != 2 ||
			h.Spans[0].Side != control.HistorySideLegacy || h.Spans[0].Phase != control.CutoverShadow || h.Spans[0].To != h.Spans[1].From || h.Spans[1].To != 0 || h.Spans[1].Owner == nil || *h.Spans[1].Owner != oldOwner {
			t.Fatalf("%s: history %+v", name, h)
		}
	}
	var revisionAfter model.Revision
	_ = e.app.Control.View(e.ctx, func(st model.ControlState) error { revisionAfter = st.Revision; return nil })
	if revisionAfter != revisionBefore {
		t.Fatalf("reading the view changed control state: revision %d -> %d", revisionBefore, revisionAfter)
	}

	// Everyone else, another project and a malformed request.
	var baseline string
	for name, c := range map[string]func() (int, []byte){
		"read only":       func() (int, []byte) { return e.postCutover(reader, cutoverBody(org, p1)) },
		"other project":   func() (int, []byte) { return e.postCutover(writer, cutoverBody(org, p2)) },
		"missing project": func() (int, []byte) { return e.postCutover(writer, cutoverBody(org, model.NewID())) },
	} {
		status, raw = c()
		if status != http.StatusNotFound {
			t.Fatalf("%s: %d %s, want the one denial", name, status, raw)
		}
		if got := denial(t, status, raw); baseline == "" {
			baseline = got
		} else if got != baseline {
			t.Fatalf("%s is distinguishable from the other denials: %s vs %s", name, got, baseline)
		}
	}
	for name, body := range map[string]any{
		"no project":    map[string]any{"org": org.String()},
		"unknown field": map[string]any{"org": org.String(), "project_id": p1.String(), "operation": "write"},
	} {
		if status, raw = e.postCutover(writer, body); status != http.StatusBadRequest {
			t.Fatalf("%s: %d %s", name, status, raw)
		}
	}
}
