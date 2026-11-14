// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"time"
)

// SanitizedSummary deliberately has no inventory-derived string fields.
type SanitizedSummary struct {
	SchemaVersion              int
	TargetCount                int
	DiscrepancyCount           int
	CurrentEvidenceComplete    bool
	RetentionRecorded          bool
	RollbackRecorded           bool
	IndependentDeadmanRecorded bool
	CustomerAcceptance         bool
}

func PublicSummary(intake PrivateIntake) (SanitizedSummary, error) {
	now := time.Now().UTC()
	if intake.CollectedAt.IsZero() || intake.CollectedAt.After(now) || !nonempty(intake.GrantID) || len(intake.Targets) == 0 {
		return SanitizedSummary{}, errors.New("incomplete intake")
	}
	result := SanitizedSummary{SchemaVersion: 1, TargetCount: len(intake.Targets), CurrentEvidenceComplete: true, RetentionRecorded: true, RollbackRecorded: true, IndependentDeadmanRecorded: true}
	for _, t := range intake.Targets {
		if !t.CurrentEvidenceComplete || !nonempty(t.ObservedRef, t.ExpectedRef) || validateObservation(t, now, intake.MaxEvidenceAgeSeconds) != nil {
			return SanitizedSummary{}, errors.New("incomplete current evidence")
		}
		if t.ObservedRef != t.ExpectedRef {
			result.DiscrepancyCount++
		}
		if t.ObservedRef != t.Evidence.CurrentRef {
			result.DiscrepancyCount++
		}
		if t.Evidence.Build.Ref != t.Evidence.CurrentRef {
			result.DiscrepancyCount++
		}
	}
	return result, nil
}
