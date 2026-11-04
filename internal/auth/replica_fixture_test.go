// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"path/filepath"
	"soundpost/internal/control"
	"testing"
	"time"
)

func activateAuthControl(t *testing.T, store *control.Store, directory string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.EnableSingle(ctx, filepath.Join(directory, "raft-control")); err != nil {
		t.Fatal("real one-voter control activation failed", err)
	}
}
