// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package model

// CanonicalSeriesID is project-local and independent of source or producer.
// Quota indexes retain the bounded identity, not another copy of every label.
func CanonicalSeriesID(project ID, r Record) (string, error) {
	if r.Kind != Metric {
		return "", Fail(Invalid)
	}
	key, e := OwnerKey(r)
	if e != nil {
		return "", e
	}
	return project.String() + ":" + HashCanonical(key).String(), nil
}
