// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package recorderfixtures_test

import (
	"bytes"
	"strings"
	"testing"

	recorderfixtures "github.com/arynyklas/soundpost/fixtures/replays/recorder"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replays"
)

// Every chunk the real recorder emitted is admitted by the closed Go validator
// (the strict decode plus replays.ValidateChunk is what (*Service).ValidateJSON and
// the ingest ReplayGate run), and the chain hash the recorder computed in the browser
// is the hash replays.ChunkHash computes over the decoded chunk.
func TestRecorderChunksPassTheClosedValidatorAndChainHashesAgree(t *testing.T) {
	for _, name := range recorderfixtures.Names {
		t.Run(name, func(t *testing.T) {
			s, err := recorderfixtures.Load(name)
			if err != nil {
				t.Fatal(err)
			}
			chunks, err := s.Chunks()
			if err != nil {
				t.Fatalf("the Go closed schema refused the recorder's own chunk: %v", err)
			}
			if len(chunks) < 4 {
				t.Fatalf("fixture has %d chunks", len(chunks))
			}
			var prev model.Hash
			var checkpoint model.Hash
			for i, c := range chunks {
				if err := replays.ValidateChunk(c); err != nil {
					t.Fatalf("chunk %d: %v", i+1, err)
				}
				if len(s.Wire[i]) > replays.MaxChunkBytes {
					t.Fatalf("chunk %d is %d bytes", i+1, len(s.Wire[i]))
				}
				if uint64(c.Sequence) != uint64(i+1) || c.Previous != prev {
					t.Fatalf("chunk %d: sequence %d previous %s, the hash chain is broken", i+1, c.Sequence, c.Previous)
				}
				if uint64(c.CheckpointSequence) == uint64(c.Sequence) {
					checkpoint = prev
					if c.Checkpoint != checkpoint {
						t.Fatalf("chunk %d: a checkpoint repeats the previous hash", i+1)
					}
				}
				if prev, err = replays.ChunkHash(c); err != nil {
					t.Fatal(err)
				}
				if uint64(c.CheckpointSequence) == uint64(c.Sequence) {
					checkpoint = prev
				} else if c.Checkpoint != checkpoint {
					t.Fatalf("chunk %d names checkpoint %s, want the hash of its checkpoint chunk %s", i+1, c.Checkpoint, checkpoint)
				}
			}
		})
	}
}

// The server allowlist stays closed. Chunks shaped like the recorder's former output (node rect and
// pres, wider tags) and every raw-content field are still refused; nothing was loosened to admit the recorder.
func TestGoSchemaStaysClosedAgainstOldRecorderShapes(t *testing.T) {
	s, err := recorderfixtures.Load("session")
	if err != nil {
		t.Fatal(err)
	}
	first := s.Wire[0]
	root := []byte(`{"id":"1","parent":"0","tag":"masked","class":"","text":""}`)
	if !bytes.Contains(first, root) {
		t.Fatal("test premise: the fixture's first node changed")
	}
	withNode := func(node string) []byte { return bytes.Replace(first, root, []byte(node), 1) }
	withField := func(field string) []byte { return bytes.Replace(first, []byte(`"gap":`), []byte(field+`,"gap":`), 1) }
	for name, wire := range map[string][]byte{
		"rect on a node":  withNode(`{"id":"1","parent":"0","tag":"masked","class":"","text":"","rect":{"x":0,"y":0,"w":8,"h":8}}`),
		"pres on a node":  withNode(`{"id":"1","parent":"0","tag":"masked","class":"","text":"","pres":"block"}`),
		"html on a chunk": withField(`"html":"<b>x</b>"`),
		"text on a chunk": withField(`"text":"typed"`),
		"attributes":      withField(`"attributes":{}`),
		"duplicate key":   withField(`"loss":"0"`),
	} {
		var c model.ReplayChunk
		if err := model.StrictJSON(wire, &c); err == nil {
			t.Errorf("%s: the strict decode accepted it", name)
		}
	}
	for name, wire := range map[string][]byte{
		"tag html":     withNode(`{"id":"1","parent":"0","tag":"html","class":"","text":""}`),
		"tag img":      withNode(`{"id":"1","parent":"0","tag":"img","class":"","text":""}`),
		"source class": withNode(`{"id":"1","parent":"0","tag":"div","class":"btn-primary","text":""}`),
		"typed text":   withNode(`{"id":"1","parent":"0","tag":"input","class":"","text":"hunter2"}`),
	} {
		var c model.ReplayChunk
		if err := model.StrictJSON(wire, &c); err != nil {
			t.Errorf("%s: decode: %v", name, err)
			continue
		}
		if err := replays.ValidateChunk(c); err == nil {
			t.Errorf("%s: ValidateChunk admitted it", name)
		}
	}
	for _, wire := range s.Wire {
		if strings.Contains(string(wire), "SECRET") {
			t.Fatal("raw page text in a fixture")
		}
	}
}
