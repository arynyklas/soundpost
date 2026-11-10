// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"soundpost/internal/appcore"
)

const installYAML = `
mode: distributed
replication_factor: 3
cluster:
  placement: simulated
  ca: /etc/soundpost/pki/ca.pem
  seed: file:/etc/soundpost/cluster.seed
  initial_leader: 1
  members_revision: 1
nodes:
  - {id: 1, identity: node-a, failure_domain: dom-a, peer_address: "https://soundpost-a:9444", peer_listen: "0.0.0.0:9444", disk: {id: d-a, volume: v-a, path: /var/lib/soundpost, capacity_bytes: 1000}, certificate: /etc/soundpost/pki/a.pem, private_key: file:/etc/soundpost/pki/a.key}
  - {id: 2, identity: node-b, failure_domain: dom-b, peer_address: "https://soundpost-b:9444", peer_listen: "0.0.0.0:9444", disk: {id: d-b, volume: v-b, path: /var/lib/soundpost, capacity_bytes: 1000}, certificate: /etc/soundpost/pki/b.pem, private_key: file:/etc/soundpost/pki/b.key}
  - {id: 3, identity: node-c, failure_domain: dom-c, peer_address: "https://soundpost-c:9444", peer_listen: "0.0.0.0:9444", disk: {id: d-c, volume: v-c, path: /var/lib/soundpost, capacity_bytes: 1000}, certificate: /etc/soundpost/pki/c.pem, private_key: file:/etc/soundpost/pki/c.key}
listen:
  address: 0.0.0.0:8443
  public_origins: ["https://soundpost.example.invalid"]
sources:
  - {id: backend, class: private}
quotas: {max_bytes_per_source: 1000, max_series_per_source: 10}
retention: {days: {metric: 30}}
backup: {mode: none}
`

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "install.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRenderWritesTheRealNodeFilesPrivately(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	var stdout bytes.Buffer
	if err := run([]string{"render", write(t, installYAML), "--out", out}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "simulated placement") {
		t.Fatalf("the qualification caveat must be printed:\n%s", stdout.String())
	}
	for id := 1; id <= 3; id++ {
		path := filepath.Join(out, "node-"+string(rune('0'+id))+".json")
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("node file %d: %v %v", id, err, info)
		}
		raw, _ := os.ReadFile(path)
		var node appcore.NodeConfig
		if err := json.Unmarshal(raw, &node); err != nil || node.NodeID != uint64(id) {
			t.Fatalf("node file %d is not this member's appcore.NodeConfig: %v", id, err)
		}
	}
}

func TestInvalidFilesProduceNoOutputAndNoEchoedValue(t *testing.T) {
	bad := strings.Replace(installYAML, "id: d-b", "id: d-a", 1)
	out := filepath.Join(t.TempDir(), "out")
	err := run([]string{"render", write(t, bad), "--out", out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "nodes[1].disk.id") {
		t.Fatalf("a shared disk device was rendered or mis-reported: %v", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("output directory created for an invalid installation")
	}
	if err := run([]string{"validate", filepath.Join(t.TempDir(), "missing.yaml")}, &bytes.Buffer{}); err == nil {
		t.Fatal("a missing file validated")
	}
	if err := run([]string{"frobnicate", "x"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown command accepted")
	}
}
