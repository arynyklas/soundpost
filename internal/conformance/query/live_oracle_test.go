//go:build integration

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import "testing"

// Required release command: go test -tags integration ./internal/conformance/query -run TestOracleSanity -count=1.
// Missing runtime/artifact fails; it never becomes a skipped integration success.
func TestOracleSanity(t *testing.T) { runSanityCases(t) }
