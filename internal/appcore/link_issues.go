// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package appcore

import (
	"github.com/arynyklas/soundpost/internal/issues"
	"github.com/arynyklas/soundpost/internal/link"
)

// bindIssueLinks gives the C04 resolver the occurrence-to-issue index of the control group, so an error
// occurrence in a trace view can link to the issue that holds it.
func bindIssueLinks(control issues.Control, resolver *link.Resolver) error {
	index, err := issues.NewControlStore(control)
	if err != nil {
		return err
	}
	resolver.WithIssues(index)
	return nil
}
