// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package delivery holds the Go side of the cross-language delivery goldens: the committed
// vector files are consumed by the TypeScript and Python SDK suites and must equal what the
// server's own canonical encoder and owner-routing function produce.
package delivery

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
)

func load(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type batchVectors struct {
	Version int `json:"version"`
	Vectors []struct {
		Batch     json.RawMessage `json:"batch"`
		Canonical string          `json:"canonical_utf8"`
		SHA256    string          `json:"sha256"`
	} `json:"vectors"`
}

// The SDKs' native canonical input must be byte-identical to the Go canonical form and hash.
func TestNativeAndProfileBatchGoldensMatchGoCanonicalForm(t *testing.T) {
	for _, file := range []string{"native-vectors.json", "native-profile-vectors.json"} {
		var vectors batchVectors
		load(t, file, &vectors)
		if vectors.Version != 1 || len(vectors.Vectors) == 0 {
			t.Fatalf("%s: unexpected shape", file)
		}
		for i, v := range vectors.Vectors {
			var batch model.Batch
			if err := model.StrictJSON(v.Batch, &batch); err != nil {
				t.Fatalf("%s[%d]: the Go decoder refuses the golden batch: %v", file, i, err)
			}
			canonical, err := model.CanonicalJSON(batch)
			if err != nil {
				t.Fatalf("%s[%d]: %v", file, i, err)
			}
			if string(canonical) != v.Canonical {
				t.Fatalf("%s[%d]: Go canonical form differs from the SDK golden\n go: %s\n sdk: %s", file, i, canonical, v.Canonical)
			}
			if got := model.HashCanonical(canonical).String(); got != v.SHA256 {
				t.Fatalf("%s[%d]: hash %s != golden %s", file, i, got, v.SHA256)
			}
		}
	}
}

// Every native batch golden uses the replay recorder version the server accepts.
func TestNativeVectorsUseTheSupportedRecorderVersion(t *testing.T) {
	var vectors batchVectors
	load(t, "native-vectors.json", &vectors)
	seen := 0
	for _, v := range vectors.Vectors {
		var batch model.Batch
		if err := model.StrictJSON(v.Batch, &batch); err != nil {
			t.Fatal(err)
		}
		for _, r := range batch.Records {
			if r.Kind != model.Replay {
				continue
			}
			seen++
			if r.Payload.Replay == nil {
				t.Fatal("replay_chunk golden without a replay payload")
			}
			if r.Payload.Replay.Recorder != "1" {
				t.Fatalf("replay golden recorder_version is %q, the supported version is \"1\"", r.Payload.Replay.Recorder)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no replay_chunk golden to check")
	}
}

type routingVectors struct {
	Version  int      `json:"version"`
	Org      model.ID `json:"org"`
	Project  model.ID `json:"project"`
	Source   model.ID `json:"source"`
	Producer model.ID `json:"producer"`
	Vectors  []struct {
		Record json.RawMessage `json:"record"`
		Owner  string          `json:"owner_utf8_hex"`
		Slot   uint16          `json:"slot"`
	} `json:"vectors"`
}

// The routing goldens (UTF-8 owner key bytes and slot) come from the server's owner function.
func TestRoutingGoldensMatchOwnerKeyAndSlot(t *testing.T) {
	var vectors routingVectors
	load(t, "routing-vectors.json", &vectors)
	if len(vectors.Vectors) == 0 {
		t.Fatal("no routing vectors")
	}
	for i, v := range vectors.Vectors {
		var record model.Record
		if err := json.Unmarshal(v.Record, &record); err != nil {
			t.Fatalf("routing[%d]: %v", i, err)
		}
		owner, err := model.OwnerKey(record)
		if err != nil {
			t.Fatalf("routing[%d]: %v", i, err)
		}
		// Capability and loss records route by their producer, not by payload content.
		if record.Kind == model.CapabilityKind || record.Kind == model.Loss {
			owner = []byte(vectors.Source.String() + vectors.Producer.String() + string(record.Kind))
		}
		if got := hex.EncodeToString(owner); got != v.Owner {
			t.Fatalf("routing[%d]: owner key %s != golden %s", i, got, v.Owner)
		}
		slot, err := model.OwnerSlot(vectors.Org, vectors.Project, vectors.Source, vectors.Producer, record)
		if err != nil || slot != v.Slot {
			t.Fatalf("routing[%d]: slot %d (%v) != golden %d", i, slot, err, v.Slot)
		}
	}
}
