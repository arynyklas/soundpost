//go:build linux

// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

// 04.08 C16: plan 04.08 passes --endpoint-env SOUNDPOST_FIXTURE_API. A set variable
// names an external served node; it must not be rejected as a usage error (the
// verifier used to refuse it and only ever ran its own in-process node).

func writeNodeDescription(t *testing.T, mode os.FileMode) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"ca_file": "", "source_credential": "source-key", "reader_token": "reader-token",
		"org_id": model.NewID(), "project_id": model.NewID(), "source_id": model.NewID(), "producer_id": model.NewID(),
		"resource":        model.Resource{Service: model.NewID(), Environment: model.NewID(), Build: model.NewID(), Instance: "x", Labels: model.Labels{}},
		"policy_revision": model.Revision(1), "data_dir": t.TempDir(), "grant_dir": t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "node.json")
	if err = os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func nodeOptions() options {
	return options{workload: filepath.Join(os.TempDir(), "no-such-canary"), endpointEnv: "SOUNDPOST_FIXTURE_API", nodeEnv: "SOUNDPOST_FIXTURE_NODE", policyPath: "../policy.json", seconds: 1}
}

func TestEndpointEnvNamesAnExternalNodeInsteadOfBeingRejected(t *testing.T) {
	t.Setenv("SOUNDPOST_FIXTURE_API", "https://127.0.0.1:9")
	t.Setenv("SOUNDPOST_FIXTURE_NODE", writeNodeDescription(t, 0o600))
	_, code, err := runFixture(nodeOptions())
	if code == exitUsage {
		t.Fatalf("a set endpoint variable is rejected as a usage error: %v", err)
	}
}

func TestEndpointEnvWithoutANodeDescriptionIsAUsageErrorNamingIt(t *testing.T) {
	t.Setenv("SOUNDPOST_FIXTURE_API", "https://127.0.0.1:9")
	t.Setenv("SOUNDPOST_FIXTURE_NODE", "")
	_, code, err := runFixture(nodeOptions())
	if code != exitUsage || err == nil || !strings.Contains(err.Error(), "SOUNDPOST_FIXTURE_NODE") {
		t.Fatalf("an external endpoint without its description answered %d %v, want a usage error naming SOUNDPOST_FIXTURE_NODE", code, err)
	}
}

func TestExternalNodeDescriptionMustBePrivate(t *testing.T) {
	t.Setenv("SOUNDPOST_FIXTURE_API", "https://127.0.0.1:9")
	t.Setenv("SOUNDPOST_FIXTURE_NODE", writeNodeDescription(t, 0o644))
	_, code, err := runFixture(nodeOptions())
	if code != exitUsage || err == nil {
		t.Fatalf("a world-readable node description was accepted: %d %v", code, err)
	}
}
