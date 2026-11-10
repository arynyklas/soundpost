// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package replayvectors owns the shared cross-language replay chain vectors in
// chain-vectors.json. Every hash and every verdict in that file is produced by
// the real Go closed-format validator (internal/replays ValidateChunk plus
// model.StrictJSON, exactly what (*Service).ValidateJSON runs after its grant
// check) and the real replays.ChunkHash. The TypeScript viewer
// (packages/replay-viewer/test/stream.test.ts) asserts the same file, so the
// two languages cannot drift apart silently.
//
// Regenerate after an intentional protocol change:
//
//	SOUNDPOST_UPDATE_VECTORS=1 go test ./fixtures/sdk/replay -run TestChainVectors -count=1
package replayvectors

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"soundpost/internal/model"
	"soundpost/internal/replays"
)

const vectorFile = "chain-vectors.json"

// Verdicts are the closed outcomes of Go admission for one wire chunk.
const (
	verdictValid       = "valid"
	verdictInvalid     = "invalid"
	verdictUnsupported = "unsupported"
	verdictTooLarge    = "too_large"
)

type goResult struct {
	Verdict        string  `json:"verdict"`
	Hash           *string `json:"hash"`
	CanonicalBytes *int    `json:"canonical_bytes"`
}

// synth describes a chunk too large to embed: take the base chunk and replace its nodes
// with Nodes generated nodes. Shape "masked": node 1 is a plain div root, nodes 2..N are
// children of 1 with tag/class "masked" and text "[masked]". Shape "plain": nodes 1..N are
// root divs with empty class and text. The wire is the compact JSON of the result.
type synth struct {
	Base  string `json:"base"`
	Nodes int    `json:"nodes"`
	Shape string `json:"shape"`
}

type vectorChunk struct {
	Wire  string   `json:"wire,omitempty"`
	Synth *synth   `json:"synth,omitempty"`
	Go    goResult `json:"go"`
}

type step struct {
	Chunk  string `json:"chunk"`
	Expect string `json:"expect"`
	Reason string `json:"reason,omitempty"`
}

type scenario struct {
	Name          string   `json:"name"`
	Steps         []step   `json:"steps"`
	FinalApplied  []string `json:"final_applied"`
	FinalContinue bool     `json:"final_continuous"`
}

type vectors struct {
	Version  int                    `json:"version"`
	Source   string                 `json:"source"`
	MaxBytes int                    `json:"max_chunk_bytes"`
	Chunks   map[string]vectorChunk `json:"chunks"`
	Cases    []scenario             `json:"scenarios"`
}

func id(b byte) model.ID {
	var v model.ID
	for i := range v {
		v[i] = b
	}
	return v
}

func hash(t *testing.T, c model.ReplayChunk) model.Hash {
	t.Helper()
	h, err := replays.ChunkHash(c)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func base() model.ReplayChunk {
	return model.ReplayChunk{
		Replay: id(0x11), Session: id(0x22), Recorder: "1",
		Clock: model.TraceClock{
			Wall: 1_700_000_000_000_000_000, Mono: 5_000_000_000, Uncertainty: 1000,
			Domain: model.ClockDomain{Host: id(0x33), Boot: id(0x44), Runtime: id(0x55)},
		},
		PolicyRevision: 7,
	}
}

func canon(t *testing.T, c model.ReplayChunk) string {
	t.Helper()
	raw, err := model.CanonicalJSON(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func tree(texts ...string) []model.MaskedNode {
	nodes := []model.MaskedNode{{ID: 1, Parent: 0, Tag: "div"}, {ID: 2, Parent: 1, Tag: "p"}}
	for i, tx := range texts {
		nodes = append(nodes, model.MaskedNode{ID: model.Uint64(3 + i), Parent: 2, Tag: "span", Text: tx})
	}
	return nodes
}

// classify runs the Go admission path for one wire chunk without a grant.
func classify(raw []byte) goResult {
	if len(raw) > replays.MaxChunkBytes {
		return goResult{Verdict: verdictTooLarge}
	}
	var c model.ReplayChunk
	if err := model.StrictJSON(raw, &c); err != nil {
		return goResult{Verdict: verdictInvalid}
	}
	if err := replays.ValidateChunk(c); err != nil {
		var f *model.Fault
		if errors.As(err, &f) {
			switch f.Code {
			case model.TooLarge:
				return goResult{Verdict: verdictTooLarge}
			case model.Unsupported:
				return goResult{Verdict: verdictUnsupported}
			}
		}
		return goResult{Verdict: verdictInvalid}
	}
	h, err := replays.ChunkHash(c)
	if err != nil {
		return goResult{Verdict: verdictInvalid}
	}
	canonical, _ := model.CanonicalJSON(c)
	hex, n := h.String(), len(canonical)
	return goResult{Verdict: verdictValid, Hash: &hex, CanonicalBytes: &n}
}

func build(t *testing.T) vectors {
	t.Helper()
	wires := map[string]string{}
	add := func(name string, c model.ReplayChunk) model.Hash {
		wires[name] = canon(t, c)
		return hash(t, c)
	}

	c1 := base()
	c1.Sequence, c1.CheckpointSequence = 1, 1
	c1.Nodes = tree("[masked]")
	c1.Events = []model.MaskedEvent{{At: 1, Kind: "checkpoint", Node: 0}}
	h1 := add("c1", c1)

	d2 := base()
	d2.Sequence, d2.Previous, d2.CheckpointSequence, d2.Checkpoint = 2, h1, 1, h1
	d2.Clock.Mono = 5_100_000_000
	d2.Nodes = []model.MaskedNode{}
	d2.Events = []model.MaskedEvent{{At: 100, Kind: "pointer", Node: 2, X: 64, Y: -8}}
	h2 := add("d2", d2)

	d3 := base()
	d3.Sequence, d3.Previous, d3.CheckpointSequence, d3.Checkpoint = 3, h2, 1, h1
	d3.Nodes = []model.MaskedNode{{ID: 3, Parent: 2, Tag: "span", Text: "[masked]"}, {ID: 4, Parent: 2, Tag: "button", Text: "[masked]"}}
	d3.Events = []model.MaskedEvent{{At: 200, Kind: "mutation", Node: 2}, {At: 210, Kind: "scroll", Node: 0, X: 0, Y: 480}}
	h3 := add("d3", d3)

	d4 := base()
	d4.Sequence, d4.Previous, d4.CheckpointSequence, d4.Checkpoint = 4, h3, 1, h1
	d4.Nodes = []model.MaskedNode{}
	d4.Events = []model.MaskedEvent{{At: 300, Kind: "resize", Node: 0, X: 1280, Y: 720}}
	h4 := add("d4", d4)

	// c5 follows the intact chain 1..4: a checkpoint names the previous hash as its checkpoint hash.
	c5 := base()
	c5.Sequence, c5.Previous, c5.CheckpointSequence, c5.Checkpoint = 5, h4, 5, h4
	c5.Nodes = []model.MaskedNode{{ID: 1, Parent: 0, Tag: "section"}, {ID: 2, Parent: 1, Tag: "canvas", Class: "masked"}}
	c5.Events = []model.MaskedEvent{{At: 400, Kind: "checkpoint", Node: 0}}
	h5 := add("c5", c5)

	d6 := base()
	d6.Sequence, d6.Previous, d6.CheckpointSequence, d6.Checkpoint = 6, h5, 5, h5
	d6.Nodes = []model.MaskedNode{}
	d6.Events = []model.MaskedEvent{{At: 500, Kind: "pointer", Node: 2, X: 8, Y: 8}}
	h6 := add("d6", d6)

	// d7 is never sent in the gap scenarios; only its hash exists so c8 and d8 are well formed.
	d7 := base()
	d7.Sequence, d7.Previous, d7.CheckpointSequence, d7.Checkpoint = 7, h6, 5, h5
	d7.Nodes = []model.MaskedNode{}
	d7.Events = []model.MaskedEvent{{At: 600, Kind: "pointer", Node: 2, X: 16, Y: 16}}
	h7 := add("d7", d7)

	c8 := base()
	c8.Sequence, c8.Previous, c8.CheckpointSequence, c8.Checkpoint = 8, h7, 8, h7
	c8.Nodes = []model.MaskedNode{{ID: 1, Parent: 0, Tag: "div"}, {ID: 2, Parent: 1, Tag: "input", Text: "[masked]"}}
	c8.Events = []model.MaskedEvent{{At: 700, Kind: "checkpoint", Node: 0}}
	h8 := add("c8", c8)

	d9 := base()
	d9.Sequence, d9.Previous, d9.CheckpointSequence, d9.Checkpoint = 9, h8, 8, h8
	d9.Nodes = []model.MaskedNode{}
	d9.Events = []model.MaskedEvent{{At: 800, Kind: "pointer", Node: 2, X: 24, Y: 24}}
	add("d9", d9)

	// A recorder-declared gap checkpoint whose predecessor hash chains correctly.
	g6 := base()
	g6.Sequence, g6.Previous, g6.CheckpointSequence, g6.Checkpoint = 6, h5, 6, h5
	g6.Gap, g6.Loss = true, 3
	g6.Nodes = []model.MaskedNode{{ID: 1, Parent: 0, Tag: "div"}}
	g6.Events = []model.MaskedEvent{{At: 450, Kind: "checkpoint", Node: 0}, {At: 450, Kind: "gap", Node: 0}}
	add("g6", g6)

	// Altered previous hash: a delta 3 whose previous_hash is another chunk's hash.
	bad3 := d3
	bad3.Previous = h1
	add("d3_altered_previous", bad3)

	// A delta that names the wrong checkpoint hash (dependency mismatch).
	dep3 := d3
	dep3.Checkpoint = h2
	add("d3_wrong_checkpoint", dep3)

	// A different chunk claiming sequence 2 (equivocation / conflict).
	alt2 := d2
	alt2.Events = []model.MaskedEvent{{At: 100, Kind: "pointer", Node: 2, X: 96, Y: 96}}
	add("d2_conflicting", alt2)

	// A checkpoint at sequence 2 whose previous hash contradicts the present chunk 1.
	c2bad := base()
	c2bad.Sequence, c2bad.Previous, c2bad.CheckpointSequence, c2bad.Checkpoint = 2, h5, 2, h5
	c2bad.Nodes = []model.MaskedNode{{ID: 1, Parent: 0, Tag: "div"}}
	c2bad.Events = []model.MaskedEvent{{At: 120, Kind: "checkpoint", Node: 0}}
	add("c2_contradicts_predecessor", c2bad)

	// A chunk of another session claiming the same replay root.
	foreign := d2
	foreign.Session = id(0x66)
	add("d2_foreign_session", foreign)

	// Nodes null on the wire is Go-valid; its hash covers "nodes":null.
	nulls := d4
	nulls.Nodes = nil
	add("d4_null_nodes", nulls)

	// Unknown and native-delivery version strings.
	v2 := c1
	v2.Recorder = "2"
	add("c1_version_2", v2)
	native := c1
	native.Recorder = "soundpost1"
	add("c1_version_soundpost1", native)

	// Exact integers above 2^53 survive: loss is max uint64, mono is 2^53+1.
	big := c1
	big.Loss, big.Clock.Mono = model.Uint64(1<<64-1), 9_007_199_254_740_993
	add("c1_big_counters", big)

	// Oversized: canonical form above 128 KiB with only closed vocabulary.
	huge := c1
	huge.Nodes = []model.MaskedNode{{ID: 1, Parent: 0, Tag: "div"}}
	for i := 2; i <= 3000; i++ {
		huge.Nodes = append(huge.Nodes, model.MaskedNode{ID: model.Uint64(i), Parent: 1, Tag: "masked", Class: "masked", Text: "[masked]"})
	}
	wires["c1_oversized"] = canon(t, huge)

	many := c1
	many.Nodes = nil
	for i := 1; i <= 4097; i++ {
		many.Nodes = append(many.Nodes, model.MaskedNode{ID: model.Uint64(i), Tag: "div"})
	}
	wires["c1_too_many_nodes"] = canon(t, many)

	// Truncated: the checkpoint cut mid-document.
	wires["c1_truncated"] = wires["c1"][:len(wires["c1"])-37]

	// Raw-channel and field-level violations built by string surgery on the canonical wire.
	c1w := wires["c1"]
	wires["c1_unknown_field_html"] = strings.Replace(c1w, `{"capture_policy_revision"`, `{"html":"<b>x</b>","capture_policy_revision"`, 1)
	wires["c1_node_rect"] = strings.Replace(c1w, `{"class":"","id":"1","parent":"0","tag":"div","text":""}`, `{"class":"","id":"1","parent":"0","rect":{"h":8,"w":8,"x":0,"y":0},"tag":"div","text":""}`, 1)
	wires["c1_node_pres"] = strings.Replace(c1w, `{"class":"","id":"1","parent":"0","tag":"div","text":""}`, `{"class":"","id":"1","parent":"0","pres":"block","tag":"div","text":""}`, 1)
	wires["c1_tag_img"] = strings.Replace(c1w, `"tag":"p"`, `"tag":"img"`, 1)
	wires["c1_tag_html"] = strings.Replace(c1w, `"tag":"p"`, `"tag":"html"`, 1)
	wires["c1_text_secret"] = strings.Replace(c1w, `"text":"[masked]"`, `"text":"hunter2"`, 1)
	wires["c1_class_secret"] = strings.Replace(c1w, `"class":""`, `"class":"btn-primary"`, 1)
	wires["c1_sequence_leading_zero"] = strings.Replace(c1w, `"sequence":"1"`, `"sequence":"01"`, 1)
	wires["c1_sequence_number"] = strings.Replace(c1w, `"sequence":"1"`, `"sequence":1`, 1)
	wires["c1_sequence_zero"] = strings.Replace(c1w, `"sequence":"1"`, `"sequence":"0"`, 1)
	wires["c1_sequence_too_big"] = strings.Replace(c1w, `"sequence":"1"`, `"sequence":"65537"`, 1)
	wires["c1_duplicate_key"] = strings.Replace(c1w, `"gap":false`, `"gap":false,"gap":true`, 1)
	wires["c1_previous_uppercase_hash"] = strings.Replace(c1w, `"previous_hash":"`+strings.Repeat("0", 64)+`"`, `"previous_hash":"`+strings.Repeat("0", 63)+`A"`, 1)
	wires["c1_zero_replay_id"] = strings.Replace(c1w, `"replay_id":"`+id(0x11).String()+`"`, `"replay_id":"`+strings.Repeat("0", 32)+`"`, 1)
	wires["c1_event_x_out_of_range"] = strings.Replace(c1w, `"x":0`, `"x":16777217`, 1)
	wires["c1_bom_prefix"] = "\ufeff" + c1w
	wires["c1_negative_zero_coordinate"] = strings.Replace(c1w, `"x":0`, `"x":-0`, 1)
	wires["c1_trailing_garbage"] = c1w + ` {}`
	wires["c1_pretty_reordered"] = prettyReordered(t, c1w)
	h1hex := *classify([]byte(wires["c1"])).Hash
	for _, s := range surgeries(h1hex) {
		if !strings.Contains(wires[s.from], s.old) {
			t.Fatalf("%s: %q not in %s", s.name, s.old, s.from)
		}
		wires[s.name] = strings.Replace(wires[s.from], s.old, s.new, 1)
	}

	out := vectors{
		Version:  1,
		Source:   "internal/replays ChunkHash + ValidateChunk + model.StrictJSON; regenerate with SOUNDPOST_UPDATE_VECTORS=1 go test ./fixtures/sdk/replay -run TestChainVectors",
		MaxBytes: replays.MaxChunkBytes,
		Chunks:   map[string]vectorChunk{},
		Cases:    scenarios(),
	}
	synthetic := map[string]*synth{
		"c1_oversized":      {Base: "c1", Nodes: 3000, Shape: "masked"},
		"c1_too_many_nodes": {Base: "c1", Nodes: 4097, Shape: "plain"},
	}
	for name, w := range wires {
		vc := vectorChunk{Go: classify([]byte(w))}
		if s, ok := synthetic[name]; ok {
			vc.Synth = s
		} else {
			vc.Wire = w
		}
		out.Chunks[name] = vc
	}
	return out
}

// prettyReordered re-emits a wire chunk indented with reversed top-level key order so a
// consumer cannot depend on key order or whitespace of the bytes it hashes.
func prettyReordered(t *testing.T, raw string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	var b bytes.Buffer
	b.WriteString("{\n")
	for i, k := range keys {
		kb, _ := json.Marshal(k)
		b.WriteString("  ")
		b.Write(kb)
		b.WriteString(": ")
		var tmp any
		_ = json.Unmarshal(m[k], &tmp)
		vb, _ := json.Marshal(tmp)
		b.Write(vb)
		if i+1 < len(keys) {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// scenarios are the viewer-side expectations derived from the plan() rules of
// internal/replays/chain.go: continuity is proven by an unbroken hash chain from a
// verified checkpoint; everything else is a gap that lasts until the next accepted
// checkpoint. Chunk hashes and verdicts above come from Go; the decisions below are
// the specified consumer behavior asserted by the viewer.
func scenarios() []scenario {
	return []scenario{
		{Name: "intact chain", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d3", "apply", ""}, {"d4", "apply", ""}, {"c5", "checkpoint", ""}, {"d6", "apply", ""}}, FinalApplied: []string{"1", "2", "3", "4", "5", "6"}, FinalContinue: true},
		{Name: "delta before any checkpoint", Steps: []step{{"d2", "gap", "no_checkpoint"}, {"d3", "gap", "no_checkpoint"}}, FinalApplied: []string{}, FinalContinue: false},
		{Name: "missing chunk then valid checkpoint resumes with a visible gap", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d4", "gap", "missing_chunk"}, {"c5", "checkpoint", "missing_chunk"}, {"d6", "apply", ""}}, FinalApplied: []string{"1", "2", "5", "6"}, FinalContinue: true},
		{Name: "checkpoint after a long hole", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"c8", "checkpoint", "missing_chunk"}, {"d9", "apply", ""}}, FinalApplied: []string{"1", "2", "8", "9"}, FinalContinue: true},
		{Name: "deltas after a gap never apply before the next checkpoint", Steps: []step{{"c1", "checkpoint", ""}, {"d3", "gap", "missing_chunk"}, {"d4", "gap", "no_checkpoint"}}, FinalApplied: []string{"1"}, FinalContinue: false},
		{Name: "duplicate delivery never double-applies", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d2", "reject", "duplicate"}, {"d3", "apply", ""}, {"c1", "reject", "stale"}}, FinalApplied: []string{"1", "2", "3"}, FinalContinue: true},
		{Name: "altered previous hash rejects and breaks the chain", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d3_altered_previous", "reject", "hash_mismatch"}, {"d3", "gap", "no_checkpoint"}}, FinalApplied: []string{"1", "2"}, FinalContinue: false},
		{Name: "wrong checkpoint dependency rejects", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d3_wrong_checkpoint", "reject", "dependency_mismatch"}}, FinalApplied: []string{"1", "2"}, FinalContinue: false},
		{Name: "conflicting chunk at an applied sequence breaks the chain", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d2_conflicting", "reject", "conflict"}, {"d3", "gap", "no_checkpoint"}}, FinalApplied: []string{"1", "2"}, FinalContinue: false},
		{Name: "a checkpoint contradicting its present predecessor is not a recovery point", Steps: []step{{"c1", "checkpoint", ""}, {"c2_contradicts_predecessor", "reject", "hash_mismatch"}, {"d2", "gap", "no_checkpoint"}}, FinalApplied: []string{"1"}, FinalContinue: false},
		{Name: "foreign session chunk is rejected and breaks the chain", Steps: []step{{"c1", "checkpoint", ""}, {"d2_foreign_session", "reject", "identity_mismatch"}, {"d2", "gap", "no_checkpoint"}}, FinalApplied: []string{"1"}, FinalContinue: false},
		{Name: "recorder-declared gap checkpoint resumes with a visible gap", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"c5", "checkpoint", "missing_chunk"}, {"g6", "checkpoint", "recorder_gap"}}, FinalApplied: []string{"1", "2", "5", "6"}, FinalContinue: true},
		{Name: "null nodes hash exactly as Go hashes them", Steps: []step{{"c1", "checkpoint", ""}, {"d2", "apply", ""}, {"d3", "apply", ""}, {"d4_null_nodes", "apply", ""}}, FinalApplied: []string{"1", "2", "3", "4"}, FinalContinue: true},
	}
}

func TestChainVectors(t *testing.T) {
	got, err := json.MarshalIndent(build(t), "", " ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("SOUNDPOST_UPDATE_VECTORS") == "1" {
		if err := os.WriteFile(vectorFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatalf("%v (run with SOUNDPOST_UPDATE_VECTORS=1 to create it)", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), got) {
		t.Fatal("chain-vectors.json differs from what the real Go validator and ChunkHash produce; regenerate it with SOUNDPOST_UPDATE_VECTORS=1")
	}
}

// TestVectorVerdicts pins the verdicts the TypeScript viewer must reproduce, so a Go
// protocol change cannot pass while the vector still says otherwise.
func TestVectorVerdicts(t *testing.T) {
	v := build(t)
	want := map[string]string{
		"c1": verdictValid, "d2": verdictValid, "d3": verdictValid, "d4": verdictValid, "c5": verdictValid, "c8": verdictValid, "d9": verdictValid,
		"g6": verdictValid, "d3_altered_previous": verdictValid, "d3_wrong_checkpoint": verdictValid, "d2_conflicting": verdictValid,
		"c2_contradicts_predecessor": verdictValid, "d2_foreign_session": verdictValid, "d4_null_nodes": verdictValid, "c1_pretty_reordered": verdictValid,
		"c1_version_2": verdictUnsupported, "c1_version_soundpost1": verdictUnsupported,
		"c1_oversized": verdictTooLarge, "c1_too_many_nodes": verdictTooLarge,
		"c1_truncated": verdictInvalid, "c1_unknown_field_html": verdictInvalid, "c1_node_rect": verdictInvalid, "c1_node_pres": verdictInvalid,
		"c1_tag_img": verdictInvalid, "c1_tag_html": verdictInvalid, "c1_text_secret": verdictInvalid, "c1_class_secret": verdictInvalid,
		"c1_sequence_leading_zero": verdictInvalid, "c1_sequence_number": verdictInvalid, "c1_sequence_zero": verdictInvalid, "c1_sequence_too_big": verdictInvalid,
		"c1_duplicate_key": verdictInvalid, "c1_previous_uppercase_hash": verdictInvalid, "c1_zero_replay_id": verdictInvalid, "c1_event_x_out_of_range": verdictInvalid,
		"c1_bom_prefix": verdictInvalid, "c1_trailing_garbage": verdictInvalid,
		"c1_big_counters": verdictValid, "c1_negative_zero_coordinate": verdictValid,
	}
	for name, verdict := range want {
		c, ok := v.Chunks[name]
		if !ok {
			t.Fatalf("missing vector chunk %s", name)
		}
		if c.Go.Verdict != verdict {
			t.Errorf("%s: Go verdict %s, want %s", name, c.Go.Verdict, verdict)
		}
	}
	for _, s := range surgeries(*v.Chunks["c1"].Go.Hash) {
		if got := v.Chunks[s.name].Go.Verdict; got != s.want {
			t.Errorf("%s: Go verdict %s, want %s", s.name, got, s.want)
		}
	}
	// The pretty, key-reordered wire of c1 must hash exactly like the canonical c1.
	if v.Chunks["c1_pretty_reordered"].Go.Hash == nil || *v.Chunks["c1_pretty_reordered"].Go.Hash != *v.Chunks["c1"].Go.Hash {
		t.Error("wire order or whitespace changed the chunk hash")
	}
	// "-0" is a Go-valid int32 coordinate and canonicalizes to 0, so it hashes exactly like c1.
	if v.Chunks["c1_negative_zero_coordinate"].Go.Hash == nil || *v.Chunks["c1_negative_zero_coordinate"].Go.Hash != *v.Chunks["c1"].Go.Hash {
		t.Error("negative-zero coordinate changed the chunk hash")
	}
}

// surgery derives one wire chunk from another by replacing the first occurrence of old with new and
// names the verdict Go must give it. Each case isolates exactly one closed-format rule, including both
// sides of every numeric boundary, so a consumer that drops or shifts a rule is caught.
type surgery struct{ name, from, old, new, want string }

func surgeries(h1 string) []surgery {
	zero, ones := strings.Repeat("0", 64), strings.Repeat("1", 64)
	return []surgery{
		// Chain-field rules.
		{"c1_seq1_nonzero_previous", "c1", `"checkpoint_hash":"` + zero + `"`, `"checkpoint_hash":"` + ones + `"`, verdictInvalid},
		{"c1_checkpoint_hash_differs_from_previous", "c1", `"previous_hash":"` + zero + `"`, `"previous_hash":"` + ones + `"`, verdictInvalid},
		{"d2_zero_previous", "d2", `"previous_hash":"` + h1 + `"`, `"previous_hash":"` + zero + `"`, verdictInvalid},
		{"d2_zero_checkpoint_hash", "d2", `"checkpoint_hash":"` + h1 + `"`, `"checkpoint_hash":"` + zero + `"`, verdictInvalid},
		{"d2_checkpoint_after_sequence", "d2", `"checkpoint_sequence":"1"`, `"checkpoint_sequence":"3"`, verdictInvalid},
		{"d2_checkpoint_sequence_zero", "d2", `"checkpoint_sequence":"1"`, `"checkpoint_sequence":"0"`, verdictInvalid},
		{"d2_sequence_max", "d2", `"sequence":"2"`, `"sequence":"65536"`, verdictValid},
		{"c1_policy_revision_zero", "c1", `"capture_policy_revision":"7"`, `"capture_policy_revision":"0"`, verdictInvalid},
		// Clock rules.
		{"c1_wall_zero", "c1", `"wall_ns":"1700000000000000000"`, `"wall_ns":"0"`, verdictInvalid},
		{"c1_wall_negative", "c1", `"wall_ns":"1700000000000000000"`, `"wall_ns":"-1"`, verdictInvalid},
		{"c1_domain_host_zero", "c1", `"host":"` + id(0x33).String() + `"`, `"host":"` + strings.Repeat("0", 32) + `"`, verdictInvalid},
		{"c1_clock_unknown_field", "c1", `"uncertainty_ns":"1000"`, `"uncertainty_ns":"1000","zone":"x"`, verdictInvalid},
		{"c1_loss_overflow", "c1", `"loss":"0"`, `"loss":"18446744073709551616"`, verdictInvalid},
		{"c1_gap_string", "c1", `"gap":false`, `"gap":"false"`, verdictInvalid},
		{"c1_version_empty", "c1", `"recorder_version":"1"`, `"recorder_version":""`, verdictUnsupported},
		{"c1_events_null", "c1", `"events":[{"at_ns":"1","kind":"checkpoint","node":"0","x":0,"y":0}]`, `"events":null`, verdictValid},
		// Node rules and boundaries.
		{"c1_node_id_zero", "c1", `"id":"1","parent":"0"`, `"id":"0","parent":"0"`, verdictInvalid},
		{"c1_node_id_max", "c1", `"id":"1","parent":"0"`, `"id":"2147483648","parent":"0"`, verdictValid},
		{"c1_node_id_over_max", "c1", `"id":"1","parent":"0"`, `"id":"2147483649","parent":"0"`, verdictInvalid},
		{"c1_node_parent_max", "c1", `"id":"1","parent":"0"`, `"id":"1","parent":"2147483648"`, verdictValid},
		{"c1_node_parent_over_max", "c1", `"id":"1","parent":"0"`, `"id":"1","parent":"2147483649"`, verdictInvalid},
		{"c1_node_parent_self", "c1", `"id":"1","parent":"0"`, `"id":"1","parent":"1"`, verdictInvalid},
		{"c1_node_duplicate_id", "c1", `"id":"2","parent":"1"`, `"id":"1","parent":"1"`, verdictInvalid},
		{"c1_node_unknown_field", "c1", `"class":"","id":"2"`, `"alt":"x","class":"","id":"2"`, verdictInvalid},
		// Event rules and boundaries.
		{"c1_event_kind_unknown", "c1", `"kind":"checkpoint"`, `"kind":"click"`, verdictInvalid},
		{"c1_event_node_max", "c1", `"node":"0","x":0`, `"node":"2147483648","x":0`, verdictValid},
		{"c1_event_node_over_max", "c1", `"node":"0","x":0`, `"node":"2147483649","x":0`, verdictInvalid},
		{"c1_event_x_max", "c1", `"x":0`, `"x":16777216`, verdictValid},
		{"c1_event_x_min", "c1", `"x":0`, `"x":-16777216`, verdictValid},
		{"c1_event_x_under_min", "c1", `"x":0`, `"x":-16777217`, verdictInvalid},
		{"c1_event_y_max", "c1", `"y":0`, `"y":16777216`, verdictValid},
		{"c1_event_y_over_max", "c1", `"y":0`, `"y":16777217`, verdictInvalid},
		{"c1_event_x_fraction", "c1", `"x":0`, `"x":1.5`, verdictInvalid},
		{"c1_event_x_exponent", "c1", `"x":0`, `"x":1e2`, verdictInvalid},
		{"c1_event_x_string", "c1", `"x":0`, `"x":"0"`, verdictInvalid},
		{"c1_event_at_number", "c1", `"at_ns":"1"`, `"at_ns":1`, verdictInvalid},
	}
}
