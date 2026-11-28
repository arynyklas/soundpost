// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

// Test-only handles on the evidence scope helpers: their contracts (no projects is invalid, the telemetry-read scope is nil for a
// non-administrator, both scopes are revalidated) are not reachable through a route, which always passes one project and checks
// the permission before it uses the read scope.
var (
	EvidenceScopeForTest = evidenceScope
	DetailScopeForTest   = detailScope
	RevalidateAllForTest = revalidateAll
)
