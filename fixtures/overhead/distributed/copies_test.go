// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The estate generator, the cgroup scope rules and the host facts are the single-host harness's, copied byte for byte: the two gates
// must drive the same estate and judge the same host shape. A change to one needs the same change in the other (their tests live in
// fixtures/overhead/singlehost).
func TestSharedFilesAreTheSingleHostHarnessesFiles(t *testing.T) {
	for _, name := range []string{"workload.go", "cgroup.go", "hostfacts.go"} {
		mine, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		theirs, err := os.ReadFile(filepath.Join("..", "singlehost", name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mine, theirs) {
			t.Errorf("%s differs from fixtures/overhead/singlehost/%s", name, name)
		}
	}
}
