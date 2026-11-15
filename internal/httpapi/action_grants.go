// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi

import "github.com/arynyklas/soundpost/internal/auth"

// actionGrants are the project grants a human action needs (decision D20, see
// internal/auth/write.go). The first one names the scope the action runs under;
// every one must be held, or the caller must administer the organization.
//
//	incident actions            incidents.write
//	issue actions               issues.write
//	grouping migration          issues.write and policy.write (it rewrites a project policy)
//
// The grouping migration runs under the issues.write scope (the issue lifecycle
// takes no other) and the lifecycle re-proves policy.write before it migrates.
// rules.write has no human action here: it is not in any list, so holding it
// authorizes nothing in this surface.
func actionGrants(req ActionRequest) []auth.Permission {
	if req.EntityKind != EntityIssue {
		return []auth.Permission{auth.IncidentsWrite}
	}
	if req.Kind == ActionGroupMigration {
		return []auth.Permission{auth.IssuesWrite, auth.PolicyWrite}
	}
	return []auth.Permission{auth.IssuesWrite}
}
