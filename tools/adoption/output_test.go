// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateOutputRejectsRepositoryAndOverwrite(t *testing.T) {
	targets, _ := fixture(t)
	root := targets.Targets[0].Repository
	if err := writePrivate(context.Background(), root, []string{root}, true, PrivateIntake{}); err == nil {
		t.Fatal("allowed private evidence in repository")
	}
	outside := t.TempDir()
	if err := writePrivate(context.Background(), outside, []string{root}, true, PrivateIntake{}); err != nil {
		t.Fatal(err)
	}
	if err := writePrivate(context.Background(), outside, []string{root}, true, PrivateIntake{}); err == nil {
		t.Fatal("overwrote private evidence")
	}
	if _, err := os.Stat(filepath.Join(outside, "intake.json")); err != nil {
		t.Fatal(err)
	}
}

func TestSyntheticLocalIntakeCommandSmoke(t *testing.T) {
	targets, grant := fixture(t)
	inputs := t.TempDir()
	private := t.TempDir()
	summary := filepath.Join(inputs, "public.json")
	targetPath := filepath.Join(inputs, "targets.json")
	grantPath := filepath.Join(inputs, "grant.json")
	if err := writeExclusive(targetPath, targets); err != nil {
		t.Fatal(err)
	}
	if err := writeExclusive(grantPath, grant); err != nil {
		t.Fatal(err)
	}
	args := []string{"intake", "--targets", targetPath, "--authorization", grantPath, "--private-output", private, "--public-summary", summary, "--private-directory-acl-confirmed"}
	if err := run(context.Background(), args); err != nil {
		t.Fatal(err)
	}
	var got SanitizedSummary
	if err := readInput(summary, &got); err != nil {
		t.Fatal(err)
	}
	if got.TargetCount != 1 || !got.CurrentEvidenceComplete || got.CustomerAcceptance {
		t.Fatal("synthetic smoke incorrectly represents acceptance")
	}
	var raw PrivateIntake
	if err := readInput(filepath.Join(private, "intake.json"), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Targets) != 1 || raw.Targets[0].ObservedRef != targets.Targets[0].ExpectedRef {
		t.Fatal("missing private evidence")
	}
	if err := run(context.Background(), args); err == nil {
		t.Fatal("overwrote previous evidence")
	}
}
