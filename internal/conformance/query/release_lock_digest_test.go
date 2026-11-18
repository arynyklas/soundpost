// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A content lock is a SHA-256 digest of 64 hex digits. An entry of another length is not a lock at
// all: the file is refused as unlocked, whatever it contains, rather than compared with a string
// that no file can match.
func TestAMalformedContentLockIsNoLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(`{"a":1}`))
	good := hex.EncodeToString(sum[:])
	var sink map[string]int
	if err := ReadLockedJSON(SourceLock{InventoryFiles: map[string]string{"cases/f.json": good}}, "cases/f.json", path, &sink); err != nil || sink["a"] != 1 {
		t.Fatalf("the file under its own digest was refused: %v", err)
	}
	for name, digest := range map[string]string{"one digit short": good[:63], "one digit long": good + "0", "empty": "", "a prefix": good[:8]} {
		err := ReadLockedJSON(SourceLock{InventoryFiles: map[string]string{"cases/f.json": digest}}, "cases/f.json", path, &sink)
		if err == nil || !strings.Contains(err.Error(), "missing content lock") {
			t.Errorf("%s: %v, want it to refuse the entry as no content lock", name, err)
		}
	}
	err := ReadLockedJSON(SourceLock{InventoryFiles: map[string]string{"cases/f.json": strings.Repeat("0", 64)}}, "cases/f.json", path, &sink)
	if err == nil || !strings.Contains(err.Error(), "locked content changed") {
		t.Errorf("another digest: %v, want locked content changed", err)
	}
}
