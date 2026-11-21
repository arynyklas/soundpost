// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
)

// TestAnIdleServeMovesNoControlRevision: a served node that is doing nothing commits nothing. The runner passes every second here (the product default
// is five); each pass used to commit one claim per project even when nothing was due, which moved the global control revision that create_org,
// create_user, release registration and every other command without an organization epoch compare. Measured on this test before the fix: one commit
// per project per pass (three projects, one-second passes: about three a second); after it none.
func TestAnIdleServeMovesNoControlRevision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	node := &jjServe{t: t, dir: filepath.Join(t.TempDir(), "data"), listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t))), interval: "1s"}
	node.start()
	t.Cleanup(func() {
		if node.cmd != nil && node.cmd.ProcessState == nil {
			_ = node.cmd.Process.Kill()
		}
	})
	admin := node.api(node.client())
	token, err := os.ReadFile(filepath.Join(node.dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	code, raw := admin.do("POST", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(token)), "Email": "owner@example.test", "Password": "idle serve admin password 2026"}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("bootstrap %d: %s", code, raw)
	}
	admin.csrf = session.CSRF
	org := model.NewID()
	jjCommand(admin, org, "create_org", auth.AdminPayload{Name: "idle serve"})
	for range 3 {
		jjCommand(admin, org, "create_project", auth.AdminPayload{ID: model.NewID(), Name: "idle serve project"})
	}

	revision := func() model.Revision {
		t.Helper()
		code, raw := admin.do("POST", "/api/v1/admin/read", map[string]any{"kind": "organizations"}, nil)
		var read struct {
			Revision model.Revision `json:"revision"`
		}
		if code != 200 || json.Unmarshal(raw, &read) != nil {
			t.Fatalf("admin read %d: %s", code, raw)
		}
		return read.Revision
	}
	// The first passes of a new leader term raise the project fences (real changes, a few commits at most): let several pass before watching.
	time.Sleep(6 * time.Second)
	const watch = 20 * time.Second
	start := revision()
	time.Sleep(watch)
	end := revision()
	t.Logf("IDLESERVE projects=3 interval=1s watched=%s revision %d -> %d (%d commits)", watch, start, end, end-start)
	if end != start {
		t.Fatalf("an idle served node committed %d control transitions in %s (revision %d -> %d)", end-start, watch, start, end)
	}
}
