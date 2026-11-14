// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import "github.com/arynyklas/soundpost/internal/auth"

// actionGrants are the project grants a human action needs (decision D19, see
// internal/auth/write.go). The first one names the scope the action runs under;
// every one must be held, or the caller must administer the organization.
//
//	incident actions            incidents.write
//	issue actions               issues.write
//	grouping migration          policy.write and issues.write (it rewrites a project policy)
//
// rules.write has no human action here: it is not in any list, so holding it
// authorizes nothing in this surface.
func actionGrants(req ActionRequest) []auth.Permission {
	if req.EntityKind != EntityIssue {
		return []auth.Permission{auth.IncidentsWrite}
	}
	if req.Kind == ActionGroupMigration {
		return []auth.Permission{auth.PolicyWrite, auth.IssuesWrite}
	}
	return []auth.Permission{auth.IssuesWrite}
}
