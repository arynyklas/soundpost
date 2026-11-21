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

// installedControl is a control store directory holding an initialized installation (hash key sealed,
// marker at the supported value), closed again. rewrite changes the persisted state first.
func installedControl(t *testing.T, rewrite func(*model.ControlState)) string {
	t.Helper()
	directory := t.TempDir()
	store, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = auth.NewService(auth.AuthDependencies{Control: store}); err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, directory)
	if rewrite != nil {
		if err = store.Update(context.Background(), func(st *control.State) error { rewrite(st); return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	return directory
}

// A format marker that is not the one this build supports is a typed schema decision, never
// corruption: a newer marker was written by a newer build, an older one by a build that predates
// the format. Either way the constructor refuses before it touches the key (nothing is initialized,
// replaced or written) and the file keeps what it held.
func TestNewServiceRefusesAnUnsupportedSchemaMarkerWithATypedDecision(t *testing.T) {
	populated := func(st *model.ControlState) {
		id := model.NewID()
		st.Users = map[string]model.ControlUser{id.String(): {ID: id, Email: "schema@example.test"}}
	}
	for _, tc := range []struct {
		name    string
		rewrite func(*model.ControlState)
		marker  uint8
		key     bool
		newer   bool
	}{
		{"marker above the supported one", func(st *model.ControlState) { st.BearerHashKeyVersion = auth.SchemaMarker + 1 }, auth.SchemaMarker + 1, true, true},
		{"marker far above the supported one", func(st *model.ControlState) { st.BearerHashKeyVersion = 200 }, 200, true, true},
		{"marker below the supported one on an initialized installation", func(st *model.ControlState) { st.BearerHashKeyVersion = auth.SchemaMarker - 1 }, auth.SchemaMarker - 1, true, false},
		{"marker below the supported one with authority and no key (the pre-marker layout)", func(st *model.ControlState) {
			st.BearerHashKeyVersion, st.BearerHashKey = auth.SchemaMarker-1, ""
			populated(st)
		}, auth.SchemaMarker - 1, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := installedControl(t, tc.rewrite)
			store, err := control.Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			_, err = auth.NewService(auth.AuthDependencies{Control: store})
			var schema *auth.SchemaError
			if !errors.As(err, &schema) {
				t.Fatalf("got %v, want the typed schema decision", err)
			}
			if schema.Newer() != tc.newer || schema.Observed != tc.marker {
				t.Fatalf("decision observed=%d newer=%v, want observed=%d newer=%v", schema.Observed, schema.Newer(), tc.marker, tc.newer)
			}
			var fault *model.Fault
			if errors.As(err, &fault) {
				t.Fatalf("a schema decision must not be a typed fault (%s): the startup path would print it as corruption", fault.Code)
			}
			if err = store.View(context.Background(), func(st control.State) error {
				if st.BearerHashKeyVersion != tc.marker || (st.BearerHashKey != "") != tc.key {
					t.Fatalf("the refusal changed the file: marker %d, key present %v", st.BearerHashKeyVersion, st.BearerHashKey != "")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// The decision is about the marker, not about every inconsistent state: a marker the build supports
// over a lost key stays corrupt, and a pristine installation (marker unset, no key, no authority)
// is still initialized.
func TestSchemaMarkerDecisionLeavesCorruptionAndPristineRootsAlone(t *testing.T) {
	directory := installedControl(t, func(st *model.ControlState) { st.BearerHashKey = "" })
	store, err := control.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = auth.NewService(auth.AuthDependencies{Control: store})
	var schema *auth.SchemaError
	if errors.As(err, &schema) {
		t.Fatalf("a supported marker over a lost key is not a schema decision: %v", err)
	}
	assertCode(t, err, model.Corrupt)

	pristine, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer pristine.Close()
	if _, err = auth.NewService(auth.AuthDependencies{Control: pristine}); err != nil {
		t.Fatalf("a pristine root (marker 0, nothing stored) must initialize: %v", err)
	}
}
