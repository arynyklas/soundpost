// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sourcemap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRealGeneratedMapPosition(t *testing.T) {
	dir := os.Getenv("SOUNDPOST_SOURCEMAP_FIXTURE_DIR")
	if dir == "" {
		t.Skip("generate real Vite fixture and set SOUNDPOST_SOURCEMAP_FIXTURE_DIR; standalone smoke enforces this gate")
	}
	for _, entry := range []string{"simple", "indexed"} {
		data, e := os.ReadFile(filepath.Join(dir, entry+".position.json"))
		if e != nil {
			t.Fatal(e)
		}
		var want struct {
			GeneratedLine   uint32
			GeneratedColumn uint32
			SourceID        string
			Line            uint32
			Column          uint32
		}
		if e = json.Unmarshal(data, &want); e != nil {
			t.Fatal(e)
		}
		f, e := os.Open(filepath.Join(dir, entry+".mjs.map"))
		if e != nil {
			t.Fatal(e)
		}
		m, e := Decode(f, Limits{})
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		p, ok, e := m.Lookup(want.GeneratedLine, want.GeneratedColumn)
		if e != nil || !ok || p.SourceID != want.SourceID || p.Line != want.Line || p.Column != want.Column {
			t.Fatalf("real throw position: %+v want %+v mapped=%v err=%v", p, want, ok, e)
		}
	}
}
