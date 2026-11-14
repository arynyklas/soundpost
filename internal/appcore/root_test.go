// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore_test

import (
	"github.com/arynyklas/soundpost/internal/appcore"
	"os"
	"path/filepath"
	"testing"
)

func TestInitializedApplicationRefusesLostDataAuthority(t *testing.T) {
	dir := t.TempDir()
	app, e := appcore.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = app.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(dir, "data", "apply.db")); e != nil {
		t.Fatal(e)
	}
	if app, e = appcore.Open(dir); e == nil {
		app.Close()
		t.Fatal("initialized data authority was silently recreated")
	}
}
