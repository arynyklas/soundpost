// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func TestMissingBearerHashKeyWithExistingAuthorityFailsClosed(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, directory)
	digest, err := service.BearerDigest(auth.ServerAPIBearer, "existing authority fixture")
	if err != nil {
		t.Fatal(err)
	}
	record := model.ControlServerToken{ID: model.NewID(), Principal: model.NewID(), Org: model.NewID(), Projects: []model.ID{model.NewID()}, Permissions: []string{string(auth.Read)}, Expires: time.Now().Add(time.Hour).Unix()}
	if err := store.Update(ctx, func(st *control.State) error {
		st.ServerTokens = map[string]model.ControlServerToken{digest: record}
		st.BearerHashKey = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	// Constructor must reject persisted missing initialized authority before any
	// reactivation can serve feature traffic; never regenerate an empty token set.
	_, err = auth.NewService(auth.AuthDependencies{Control: store})
	assertCode(t, err, model.Corrupt)
	if err := store.View(ctx, func(st control.State) error {
		if st.BearerHashKey != "" {
			t.Fatal("missing authority key was silently replaced")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInitializedBearerAuthorityDoesNotReplaceLostKeyWhenTokenSetIsEmpty(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	store, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	if _, err := auth.NewService(auth.AuthDependencies{Control: store}); err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, directory)
	if err := store.Update(ctx, func(st *control.State) error { st.BearerHashKey = ""; st.ServerTokens = nil; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	_, err = auth.NewService(auth.AuthDependencies{Control: store})
	assertCode(t, err, model.Corrupt)
	if err := store.View(ctx, func(st control.State) error {
		if st.BearerHashKey != "" || st.BearerHashKeyVersion != 1 {
			t.Fatal("initialized installation silently replaced its lost hash key")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
