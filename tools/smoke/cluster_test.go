// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"errors"
	"os"
	"soundpost/internal/appcore"
	"soundpost/internal/model"
	"strings"
	"testing"
)

// Omitting enabled from the real protected grant command must fail this fixture
// before it can claim any multi-process value reconciliation.
func TestQuorumSeedProvisionHasActualScopedReadAuthority(t *testing.T) {
	fixture, err := provisionClusterSeed(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fixture.seed)
	if err != nil {
		t.Fatal(err)
	}
	var seed appcore.ClusterSeed
	if err = json.Unmarshal(raw, &seed); err != nil {
		t.Fatal(err)
	}
	var control struct {
		State model.ControlState `json:"state"`
	}
	if err = json.Unmarshal(seed.Control, &control); err != nil {
		t.Fatal(err)
	}
	var user model.ID
	for _, candidate := range control.State.Users {
		if candidate.Email == "quorum@example.test" {
			user = candidate.ID
		}
	}
	if user == (model.ID{}) {
		t.Fatal("actual bootstrap principal missing")
	}
	org := control.State.Orgs[fixture.org.String()]
	if !org.Members[user.String()] {
		t.Fatal("reader membership was not committed")
	}
	permissions := org.Grants[user.String()+":"+fixture.project.String()]
	if len(permissions) != 1 || permissions[0] != "telemetry.read" {
		t.Fatal("intended read grant was not committed")
	}
}

func TestQuorumChildFailurePreservesSafeBoundary(t *testing.T) {
	answer := clusterFailureAnswer(&smokeFailure{Stage: "quorum_verify_authorize", Code: "not_found"})
	failure := quorumAnswerFailure(answer)
	var detail *smokeFailure
	if !errors.As(failure, &detail) || detail.Stage != "quorum_verify_authorize" || detail.Code != "not_found" {
		t.Fatal("actual authority failure was masked")
	}
	for _, code := range []string{"value_mismatch", "missing_acknowledged_record"} {
		failure = quorumAnswerFailure(clusterAnswer{Stage: "quorum_verify_values", Code: code})
		if !errors.As(failure, &detail) || detail.Code != code {
			t.Fatal("value assertion failure was mislabeled")
		}
	}
	secret := "private-session-and-payload-must-never-be-echoed"
	failure = quorumAnswerFailure(clusterAnswer{Stage: secret, Code: secret})
	if strings.Contains(failure.Error(), secret) {
		t.Fatal("private child material escaped public diagnostics")
	}
	if !errors.As(failure, &detail) || detail.Stage != "quorum_verify_child" || detail.Code != "unavailable" {
		t.Fatal("untrusted stage/code was not bounded")
	}
}
