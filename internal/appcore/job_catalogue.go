// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import "github.com/arynyklas/soundpost/internal/jobs"

// JobCatalogue is the job schedule-definition catalogue over this node's control
// state: what the authoring route (POST /api/v1/jobs/definitions) saves
// definitions into and what the background runner's observer stage reads. It
// keeps no state, so every call returns an equivalent value.
func (a *App) JobCatalogue() (*jobs.Catalogue, error) {
	return jobs.NewCatalogue(a.Control)
}
