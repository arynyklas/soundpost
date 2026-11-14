// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// These tests use the real on-disk authority. Restarting it must not restore
// consumed bootstrap credentials or revoked project privileges.
func TestBootstrapTokenConsumedOnce(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, dir)
	if _, err = service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026"); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = control.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err = auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, dir)
	_, err = service.Bootstrap(ctx, token, "attacker@example.test", "another sufficiently long password")
	assertCode(t, err, model.Unauthenticated)
	if _, err = service.Login(ctx, "owner@example.test", "correct horse battery staple 2026", ""); err != nil {
		t.Fatalf("persisted account cannot log in: %v", err)
	}
}

func assertCode(t *testing.T, err error, code model.Code) {
	t.Helper()
	var fault *model.Fault
	if !errors.As(err, &fault) || fault.Code != code {
		t.Fatalf("got %v, want fault %s", err, code)
	}
}
