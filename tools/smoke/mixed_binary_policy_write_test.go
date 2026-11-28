// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// policySite is a voter's API as far as the policy write goes: a login, a policy read that answers the organization epoch 7 and
// a policy write that answers the scripted statuses in turn (the last one repeats).
type policySite struct {
	mu       sync.Mutex
	writes   []map[string]any
	statuses []int
	bodies   map[int]string
}

func (p *policySite) handler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v1/login":
		_, _ = w.Write([]byte(`{"csrf":"csrf"}`))
	case "/api/v1/policies":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["operation"] == "read" {
			_, _ = w.Write([]byte(`{"revision":"7"}`))
			return
		}
		p.mu.Lock()
		status := p.statuses[min(len(p.writes), len(p.statuses)-1)]
		p.writes = append(p.writes, body)
		p.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(p.bodies[status]))
	default:
		http.NotFound(w, r)
	}
}

// The mixed-binary save through a voter of the PREVIOUS release proposes once, as that release always did: a proposal that lost
// the application-index race for any other control commit of the group is answered `stale` (409, nothing committed) although the
// save's expected revision still holds. The candidate proposes again (control.UpdateOrgAuthority), so the same answer from a
// candidate is a product failure and stays one; a `conflict` is the caller's own view and stays one on both. The save through the
// previous release is repeated as the same command, on a fresh read, a bounded number of times.
func TestMixedBinaryPolicyWriteRepeatsOnlyAStaleThatThePreviousReleaseAnswers(t *testing.T) {
	stale, conflict := `{"code":"stale"}`, `{"code":"conflict"}`
	for _, c := range []struct {
		name      string
		release   string
		statuses  []int
		bodies    map[int]string
		wantErr   bool
		wantWrite int
	}{
		{"previous release, one lost race", "old", []int{409, 200}, map[int]string{409: stale, 200: `{}`}, false, 2},
		{"previous release, three lost races", "old", []int{409, 409, 409, 200}, map[int]string{409: stale, 200: `{}`}, false, 4},
		{"candidate, a lost race is a failure", "new", []int{409, 200}, map[int]string{409: stale, 200: `{}`}, true, 1},
		{"previous release, a conflict is a failure", "old", []int{409, 200}, map[int]string{409: conflict, 200: `{}`}, true, 1},
		{"previous release, losing every time is a failure", "old", []int{409}, map[int]string{409: stale}, true, 9},
		{"previous release, another status is a failure", "old", []int{500, 200}, map[int]string{500: `{"code":"unavailable"}`, 200: `{}`}, true, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			site := &policySite{statuses: c.statuses, bodies: c.bodies}
			srv := httptest.NewTLSServer(http.HandlerFunc(site.handler))
			defer srv.Close()
			trace, err := os.Create(filepath.Join(t.TempDir(), "trace.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer trace.Close()
			m := &mixedRun{t: t, trace: trace, fx: &installFixture{org: model.NewID(), project: model.NewID(), password: "pw"},
				sites: map[uint64]*installSite{1: {base: srv.URL, client: srv.Client()}}, release: map[uint64]string{1: c.release}}
			err = m.policyWrite(1)
			if (err != nil) != c.wantErr {
				t.Fatalf("policyWrite: %v, want error %t", err, c.wantErr)
			}
			if len(site.writes) != c.wantWrite {
				t.Fatalf("%d writes sent, want %d", len(site.writes), c.wantWrite)
			}
			for i, w := range site.writes {
				if w["command_id"] != site.writes[0]["command_id"] {
					t.Errorf("write %d is another command (%v, the first %v): a repeat of a refused save is the same command", i, w["command_id"], site.writes[0]["command_id"])
				}
				if w["expected_revision"] != "7" {
					t.Errorf("write %d: expected_revision %v, want the epoch just read, 7", i, w["expected_revision"])
				}
			}
		})
	}
}
