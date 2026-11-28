// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package queryinput_test

import (
	"math"
	"testing"

	. "github.com/arynyklas/soundpost/internal/adapters/queryinput"
	"github.com/arynyklas/soundpost/internal/model"
)

func conditionProfile() InputProfile {
	return InputProfile{
		Org: model.ID{9}, Project: model.ID{1}, Source: model.ID{2}, Producer: model.ID{3}, PolicyRevision: 1,
		Resource: model.Resource{Service: model.ID{4}, Environment: model.ID{5}, Build: model.ID{6}, Instance: "i", Labels: model.Labels{}},
		Limits:   DefaultLimits(), MinTimestamp: 1, MaxTimestamp: model.UnixNano(math.MaxInt64),
		Names: NamesStrict, OutOfOrder: OutOfOrderSort, Histograms: HistogramsPreserve, Exemplars: ExemplarsReject, Help: HelpReject,
	}
}

func conditionRecord(id byte, condition, epoch model.ID, sequence uint64, status string) model.Record {
	return model.Record{
		ID: model.ID{0xc0, id}, Kind: model.Condition, ObservedAt: 100, Resource: conditionProfile().Resource,
		Payload: model.Payload{Condition: &model.ConditionEvent{Condition: condition, Epoch: epoch, Sequence: model.Uint64(sequence), At: 100, Status: status, Severity: "info", Labels: model.Labels{}, Links: []model.ID{}}},
	}
}

func conditionBatch(t *testing.T, cfg InputProfile, recs ...model.Record) model.Batch {
	t.Helper()
	slot, err := model.OwnerSlot(cfg.Org, cfg.Project, cfg.Source, cfg.Producer, recs[0])
	if err != nil {
		t.Fatal(err)
	}
	return model.Batch{Version: 1, Project: cfg.Project, Source: cfg.Source, Producer: cfg.Producer, ID: model.ID{0xb0}, PolicyRevision: cfg.PolicyRevision, RouteSlot: slot, Records: recs}
}

// TestConditionNormalizationIdentity: one (condition, epoch, sequence) is one
// event. Repeats with identical content collapse whatever their record IDs, a
// replay with other content is a conflict, a reused record ID with other content
// is a conflict, and events without a sequence are never merged.
func TestConditionNormalizationIdentity(t *testing.T) {
	cfg := conditionProfile()
	cond, epoch := model.ID{7}, model.ID{8}

	same := conditionBatch(t, cfg, conditionRecord(1, cond, epoch, 5, "firing"), conditionRecord(2, cond, epoch, 5, "firing"))
	out, rep, err := Normalize(same, cfg)
	if err != nil || len(out.Records) != 1 || rep.Count(ReportExactDuplicateCollapsed) != 1 {
		t.Fatalf("identical repeats must collapse: records=%d err=%v report=%v", len(out.Records), err, rep.Counts)
	}

	replay := conditionBatch(t, cfg, conditionRecord(1, cond, epoch, 5, "firing"), conditionRecord(2, cond, epoch, 5, "recovered"))
	if _, _, err := Normalize(replay, cfg); reasonOf(err) != ReasonConflict {
		t.Fatalf("a replay of one event with other content must conflict: %v", err)
	}

	reused := conditionBatch(t, cfg, conditionRecord(1, cond, epoch, 5, "firing"), conditionRecord(1, cond, epoch, 6, "firing"))
	if _, _, err := Normalize(reused, cfg); reasonOf(err) != ReasonConflict {
		t.Fatalf("a reused record ID with other content must conflict: %v", err)
	}

	distinct := conditionBatch(t, cfg, conditionRecord(1, cond, epoch, 5, "firing"), conditionRecord(2, cond, epoch, 6, "recovered"), conditionRecord(3, cond, model.ID{9}, 5, "firing"))
	if out, _, err := Normalize(distinct, cfg); err != nil || len(out.Records) != 3 {
		t.Fatalf("different sequences and epochs are different events: records=%d err=%v", len(out.Records), err)
	}

	unsequenced := conditionBatch(t, cfg, conditionRecord(1, cond, epoch, 0, "firing"), conditionRecord(2, cond, epoch, 0, "recovered"))
	if out, _, err := Normalize(unsequenced, cfg); err != nil || len(out.Records) != 2 {
		t.Fatalf("events without a sequence are never merged: records=%d err=%v", len(out.Records), err)
	}

	early := conditionBatch(t, cfg, conditionRecord(1, cond, epoch, 5, "firing"))
	early.Records[0].ObservedAt = 0
	if _, _, err := Normalize(early, cfg); reasonOf(err) != ReasonTimestampRange {
		t.Fatalf("a condition below the timestamp bound must be refused: %v", err)
	}
}
