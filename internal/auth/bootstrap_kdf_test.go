// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// L1-R03 F6: the bootstrap route stays mounted for the life of the install and
// is unauthenticated, so it must refuse before any password work: a wrong token
// and a call after the install is bootstrapped run no KDF at all. A valid token
// still costs exactly one.
func TestBootstrapRefusesBeforeAnyPasswordWork(t *testing.T) {
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, t.TempDir())
	ctx := context.Background()
	token, err := store.BootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "bootstrap kdf password 2026"

	before := auth.KDFRuns()
	_, err = service.Bootstrap(ctx, "not the bootstrap token", "owner@example.test", secret)
	assertCode(t, err, model.Unauthenticated)
	if got := auth.KDFRuns() - before; got != 0 {
		t.Fatalf("a wrong bootstrap token ran the password KDF %d times, want 0", got)
	}
	// A wrong token with an unusable password is the same refusal: the token is
	// judged first, so the password length is no oracle for unauthenticated callers.
	before = auth.KDFRuns()
	_, err = service.Bootstrap(ctx, "not the bootstrap token", "owner@example.test", "short")
	assertCode(t, err, model.Unauthenticated)
	if got := auth.KDFRuns() - before; got != 0 {
		t.Fatalf("a wrong token with a short password ran the KDF %d times, want 0", got)
	}

	before = auth.KDFRuns()
	if _, err = service.Bootstrap(ctx, token, "owner@example.test", secret); err != nil {
		t.Fatal(err)
	}
	if got := auth.KDFRuns() - before; got != 1 {
		t.Fatalf("a valid bootstrap ran the password KDF %d times, want exactly 1", got)
	}

	// After bootstrap the same (now spent) token, and any other, is refused
	// without a KDF run.
	for _, again := range []string{token, "not the bootstrap token", ""} {
		before = auth.KDFRuns()
		_, err = service.Bootstrap(ctx, again, "second@example.test", secret)
		assertCode(t, err, model.Unauthenticated)
		if got := auth.KDFRuns() - before; got != 0 {
			t.Fatalf("a bootstrap call after bootstrap ran the password KDF %d times, want 0", got)
		}
	}
}

// L1-R03 F1: NewService derives the dummy digest (the one that stands in for an
// unknown or disabled address), so the first unknown-address login after a
// start costs exactly one KDF run like every other login. The digest is
// process-wide, so this test makes it cold first and no earlier test can have
// warmed it for it.
func TestFirstUnknownAddressLoginAfterNewServiceCostsOneKDF(t *testing.T) {
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	restore := auth.ColdDummyDigest()
	t.Cleanup(restore)
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, t.TempDir())
	before := auth.KDFRuns()
	_, err = service.Login(context.Background(), "never-seen@example.test", "wrong password entirely", "")
	assertCode(t, err, model.Unauthenticated)
	if got := auth.KDFRuns() - before; got != 1 {
		t.Fatalf("the first unknown-address login ran the KDF %d times, want exactly 1", got)
	}
}
