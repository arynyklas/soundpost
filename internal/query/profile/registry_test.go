// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package profile

import (
	"encoding/json"
	"testing"
	"testing/fstest"
)

func TestRegistryRejectsUnacceptedProfileAndPinDrift(t *testing.T) {
	files := fstest.MapFS{}
	for id, commit := range pins {
		b, e := json.Marshal(Profile{ID: id, Commit: commit, ManifestVersion: 1})
		if e != nil {
			t.Fatal(e)
		}
		files[id+".json"] = &fstest.MapFile{Data: b}
	}
	r, e := Load(files)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Resolve("promql-prometheus-3.1.0", "default"); e == nil {
		t.Fatal("unaccepted inventory resolved")
	}
	files["promql-prometheus-3.1.0.json"] = &fstest.MapFile{Data: []byte(`{"id":"promql-prometheus-3.1.0","commit":"different","manifest_version":1}`)}
	if _, e = Load(files); e == nil {
		t.Fatal("wrong source pin accepted")
	}
}
