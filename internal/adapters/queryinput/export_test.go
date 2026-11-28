// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput

// Test-only exports for the external queryinput_test package (which cannot be
// in-package: the real-app fixture imports internal/appcore, which imports
// internal/httpapi, which imports this package).
var (
	SnappyDecode    = snappyDecode
	NewMetricRecord = newMetricRecord
	RecordCost      = recordCost
	RequestDigest   = requestDigest
	DeriveID        = deriveID
)

const FmtNormalize = fmtNormalize
