// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/arynyklas/soundpost/internal/httpapi"
)

// A bundle whose index references an asset that is missing or empty (written with `: > a.js`, a build
// that stopped half way) is not a servable UI: every refusal is the one typed error, which `soundpost
// serve` prints as the startup reason ui_bundle_invalid instead of the generic line.
func TestUIRoutesRefuseEveryUnservableBundleWithTheTypedError(t *testing.T) {
	index := &fstest.MapFile{Data: []byte(`<div id="root"></div><script type="module" src="/assets/a.js"></script>`)}
	for name, bundle := range map[string]fs.FS{
		"no assets":              nil,
		"empty bundle":           fstest.MapFS{},
		"no application root":    fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<html></html>`)}},
		"no script":              fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(`<div id="root"></div>`)}},
		"referenced asset gone":  fstest.MapFS{"index.html": index},
		"referenced asset empty": fstest.MapFS{"index.html": index, "assets/a.js": &fstest.MapFile{}},
	} {
		if _, err := httpapi.UIRoutes(bundle); !errors.Is(err, httpapi.ErrUIBundle) {
			t.Errorf("%s: %v is not httpapi.ErrUIBundle", name, err)
		}
	}
	if _, err := httpapi.UIRoutes(fstest.MapFS{"index.html": index, "assets/a.js": &fstest.MapFile{Data: []byte("1")}}); err != nil {
		t.Fatalf("a servable bundle was refused: %v", err)
	}
}
