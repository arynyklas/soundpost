// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"context"
	"github.com/arynyklas/soundpost/internal/control"
	"path/filepath"
	"testing"
	"time"
)

func activateHTTPControl(t *testing.T, store *control.Store, directory string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.EnableSingle(ctx, filepath.Join(directory, "raft-control")); err != nil {
		t.Fatal("real one-voter control activation failed", err)
	}
}
