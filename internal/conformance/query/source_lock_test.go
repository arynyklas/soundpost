// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

func TestSourceLockRejectsMissingProfiles(t *testing.T) {
	if e := ValidateSourceLock(SourceLock{ManifestVersion: 1}); e == nil {
		t.Fatal("empty lock accepted; oracle would silently run zero profiles")
	}
}
