// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package issues

import (
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/releases"
)

// RegressionDecision explains why one deduplicated occurrence did or did not
// qualify as a recurrence of a resolved issue. Every field derives from facts
// that are stored with the issue (resolution time, frontier, observed releases)
// and the immutable release graph, so the decision can be recomputed and
// audited; it is never a free-text guess.
type RegressionDecision struct {
	// Eligible reports that the occurrence qualifies on its own. Whether
	// enough qualifying occurrences accumulated to reopen is the service's
	// RegressionPolicy decision and is recorded in Explanation.
	Eligible bool
	// Reason is a stable human-readable explanation of Eligible.
	Reason string
	// Frontier is the release set the evidence was compared with: the
	// fixed-descendant frontier when one was recorded, otherwise the releases
	// observed at resolution.
	Frontier []model.ID
	// AncestryKnown is false when the evidence has no usable release ancestry
	// (unversioned, source-declared unknown, or a release the graph cannot
	// place against the frontier). Unknown ancestry is never guessed from
	// version text or time; it follows the explicit event-time boundary.
	AncestryKnown bool
}

const (
	reasonNotResolved   = "not resolved: no regression evaluation"
	reasonIgnored       = "ignored: workflow is explicit, no regression evaluation"
	reasonLate          = "evidence at or before the resolution boundary: late history, never a regression"
	reasonUnknown       = "ancestry unknown: event after the explicit resolution boundary"
	reasonFixMatch      = "release is the fix frontier or a descendant of it"
	reasonFixMiss       = "release is not the fix frontier or a descendant of it"
	reasonObservedMatch = "release is in or descends from the observed resolution frontier"
	reasonObservedMiss  = "release is not in or a descendant of the observed resolution frontier"
	reasonNoResolution  = "resolved issue has no resolution boundary"
)

// Regresses decides whether evidence qualifies as a regression of issue. It is
// a pure function of the issue's stored resolution facts, the evidence and the
// release graph (a partial order, never lexical or time order).
func Regresses(issue Issue, evidence Evidence, graph releases.Graph) RegressionDecision {
	known := evidenceAncestry(issue, evidence, graph)
	switch issue.Workflow {
	case "resolved":
	case "ignored":
		return RegressionDecision{Reason: reasonIgnored, AncestryKnown: known}
	default:
		return RegressionDecision{Reason: reasonNotResolved, AncestryKnown: known}
	}
	fixed := len(issue.FixedDescendants) > 0
	frontier := issue.ResolutionFrontier
	if fixed {
		frontier = issue.FixedDescendants
	}
	out := RegressionDecision{Frontier: append([]model.ID(nil), frontier...)}
	if issue.ResolutionTime == nil {
		out.Reason = reasonNoResolution
		return out
	}
	match := false
	if known && len(frontier) > 0 {
		allKnown := true
		for _, f := range frontier {
			switch releases.Relation(graph, *evidence.ReleaseID, f) {
			case releases.Same, releases.Descendant:
				match = true
			case releases.Unknown:
				allKnown = false
			}
		}
		out.AncestryKnown = match || allKnown
	}
	switch {
	case evidence.EventTime <= *issue.ResolutionTime:
		out.Reason = reasonLate
	case !out.AncestryKnown:
		out.Eligible, out.Reason = true, reasonUnknown
	case match && fixed:
		out.Eligible, out.Reason = true, reasonFixMatch
	case match:
		out.Eligible, out.Reason = true, reasonObservedMatch
	case fixed:
		out.Reason = reasonFixMiss
	default:
		out.Reason = reasonObservedMiss
	}
	return out
}

// evidenceAncestry reports whether the evidence itself carries ancestry the
// graph can use: the source claims known ancestry, names a release, and the
// graph holds that release in the issue's own org/project.
func evidenceAncestry(issue Issue, evidence Evidence, graph releases.Graph) bool {
	if evidence.Ancestry != "known" || evidence.ReleaseID == nil {
		return false
	}
	release, ok := graph[*evidence.ReleaseID]
	if !ok || release.ID != *evidence.ReleaseID {
		return false
	}
	return issue.Org == (model.ID{}) || release.Org == issue.Org && release.Project == issue.Project
}
