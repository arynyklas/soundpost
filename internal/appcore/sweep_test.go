// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/appcore"
	"github.com/arynyklas/soundpost/internal/control"
)

// The serving process's background loop (RunFences) sweeps expired pending login
// and elevation records out of the replicated control state. Without it the
// unauthenticated OIDC start and every elevated read leave permanent records
// (m2 security review I-1, M-3): the sweep exists in internal/auth but nothing
// would ever call it.
func TestRunFencesSweepsExpiredElevationRecords(t *testing.T) {
	app, err := appcore.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	ctx := context.Background()
	const expired, live = "elevation:00000000000000000000000000000001", "elevation:00000000000000000000000000000002"
	farFuture := time.Now().Add(24 * time.Hour).Unix()
	if err = app.Control.Update(ctx, func(st *control.State) error {
		if st.OIDC == nil {
			st.OIDC = map[string]json.RawMessage{}
		}
		st.OIDC[expired] = json.RawMessage(`{"Expires":1}`)
		raw, _ := json.Marshal(map[string]int64{"Expires": farFuture})
		st.OIDC[live] = raw
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	run, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { app.RunFences(run); close(done) }()
	defer func() { cancel(); <-done }()

	present := func(key string) bool {
		var ok bool
		_ = app.Control.View(ctx, func(st control.State) error { _, ok = st.OIDC[key]; return nil })
		return ok
	}
	deadline := time.Now().Add(15 * time.Second)
	for present(expired) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if present(expired) {
		t.Fatal("RunFences never swept the expired elevation record")
	}
	if !present(live) {
		t.Fatal("the sweep removed an elevation record that has not expired")
	}
}
