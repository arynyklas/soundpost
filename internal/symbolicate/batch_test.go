// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package symbolicate

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/arynyklas/soundpost/internal/model"
	"strings"
	"testing"
	"time"
)

// lineMap is a source map whose generated line n (1-based) maps to source line n
// of a.ts, so every position has its own distinct answer.
func lineMap(lines int) []byte {
	var b strings.Builder
	b.WriteString(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"AAAA`)
	for i := 1; i < lines; i++ {
		b.WriteString(";AACA")
	}
	b.WriteString(`"}`)
	return []byte(b.String())
}

func batchInput(raw []byte, lines ...uint32) workerInput {
	in := workerInput{Version: 1, Map: raw, MapHash: model.HashCanonical(raw)}
	for _, l := range lines {
		in.Positions = append(in.Positions, workerPosition{Line: l})
	}
	return in
}

func TestResolveBatchAnswersEveryPositionLikeASingleRun(t *testing.T) {
	raw := lineMap(200)
	var lines []uint32
	for l := uint32(1); l <= 64; l++ {
		lines = append(lines, l*3)
	}
	got := resolveBatch(batchInput(raw, lines...))
	if len(got) != len(lines) {
		t.Fatalf("answers=%d positions=%d", len(got), len(lines))
	}
	for i, l := range lines {
		single := resolveBatch(batchInput(raw, l))[0]
		if got[i].Reason != Resolved || got[i].Position == nil || got[i].Position.Line != l || *got[i].Position != *single.Position {
			t.Fatalf("position %d (line %d): batch %+v single %+v", i, l, got[i], single)
		}
	}
	// Past the last mapped line is a per-position answer, not a batch failure.
	mixed := resolveBatch(batchInput(raw, 5, 0, 1000, 7))
	if mixed[0].Reason != Resolved || mixed[1].Reason != InvalidMap || mixed[2].Reason != Resolved && mixed[2].Reason != Unmapped || mixed[3].Reason != Resolved {
		t.Fatalf("a bad position must stay local: %+v", mixed)
	}
	if mixed[3].Position == nil || mixed[3].Position.Line != 7 {
		t.Fatalf("answers are not in input order: %+v", mixed)
	}
}

func TestResolveBatchMapLevelFailuresAnswerEveryPosition(t *testing.T) {
	raw := lineMap(10)
	in := batchInput(raw, 1, 2, 3)
	in.MapHash = model.HashCanonical([]byte("other"))
	for i, o := range resolveBatch(in) {
		if o.Reason != CorruptArtifact || o.Position != nil {
			t.Fatalf("position %d: %+v", i, o)
		}
	}
	for i, o := range resolveBatch(batchInput([]byte(`{"version":3,"sources":["a.ts"],"names":[],"mappings":"!"}`), 1, 2)) {
		if o.Reason != InvalidMap || o.Position != nil {
			t.Fatalf("position %d: %+v", i, o)
		}
	}
	if got := resolveBatch(workerInput{Version: 1, Map: raw, MapHash: model.HashCanonical(raw)}); len(got) != 1 || got[0].Reason != InvalidMap {
		t.Fatalf("empty batch: %+v", got)
	}
	over := batchInput(raw)
	over.Positions = make([]workerPosition, MaxResolvedFrames+1)
	for i := range over.Positions {
		over.Positions[i].Line = 1
	}
	if got := resolveBatch(over); len(got) != 1 || got[0].Reason != InvalidMap {
		t.Fatalf("oversized batch must be refused: %d answers", len(got))
	}
}

func TestResolveBatchSourceContextPerPosition(t *testing.T) {
	raw := lineMap(5)
	sources := []byte(`{"sources":["a.ts"],"sourcesContent":["one\ntwo\nthree\nfour\nfive"]}`)
	in := batchInput(raw, 1, 3, 5)
	in.IncludeSources = true
	in.Sources = sources
	in.SourcesHash = model.HashCanonical(sources)
	got := resolveBatch(in)
	for i, want := range []string{"one", "three", "five"} {
		if got[i].SourceContext == nil || *got[i].SourceContext != want {
			t.Fatalf("position %d: %+v want %q", i, got[i], want)
		}
	}
	in.Sources = []byte(`{"sources":`)
	in.SourcesHash = model.HashCanonical(in.Sources)
	for i, o := range resolveBatch(in) {
		if o.Reason != CorruptArtifact || o.SourceContext != nil {
			t.Fatalf("corrupt sources must fail every resolved position: %d %+v", i, o)
		}
	}
}

// One worker reply holds an answer per position; the largest legal reply must
// still fit the parent's closed-reply limit, or deep stacks would be refused.
func TestWorkerReplyFitsOutputLimitAtMaxPositions(t *testing.T) {
	big := strings.Repeat("x", 4096)
	ctx := strings.Repeat("c", 4096)
	out := make([]workerOutput, MaxResolvedFrames)
	for i := range out {
		out[i] = workerOutput{Reason: Resolved, Position: &CodeIdentity{Source: big, Function: strings.Repeat("f", 256), Line: 1 << 30, Column: 1 << 30}, SourceContext: &ctx}
	}
	raw, e := json.Marshal(out)
	if e != nil || len(raw) > MaxOutputBytes {
		t.Fatalf("reply %d bytes > MaxOutputBytes %d (err %v)", len(raw), MaxOutputBytes, e)
	}
	var back []workerOutput
	if e := decodeClosed(bytes.NewReader(raw), &back, MaxOutputBytes); e != nil || len(back) != len(out) {
		t.Fatalf("decode: %v (%d)", e, len(back))
	}
	for _, o := range back {
		if !validOutput(o, true) {
			t.Fatalf("a maximal legal answer was refused: %+v", o)
		}
	}
}

// With a real sandbox (SOUNDPOST_SYMBOLICATE_TEST_CONFIG) a deep stack in one
// bundle must answer every position from one launch inside the 5 s wall; the
// per-position cost against N single launches is logged for the report.
func TestActualBatchedDeepStack(t *testing.T) {
	c := sandboxConfig(t)
	s, e := New(&unusedReader{}, unusedGenerations{}, c)
	if e != nil {
		t.Fatal(e)
	}
	raw := lineMap(1000)
	for _, n := range []int{16, 64} {
		lines := make([]uint32, n)
		for i := range lines {
			lines[i] = uint32(i*7 + 1)
		}
		start := time.Now()
		got := s.run(context.Background(), batchInput(raw, lines...))
		batch := time.Since(start)
		if len(got) != n {
			t.Fatalf("n=%d: %d answers", n, len(got))
		}
		for i, o := range got {
			if o.Reason != Resolved || o.Position == nil || o.Position.Line != lines[i] {
				t.Fatalf("n=%d position %d: %+v", n, i, o)
			}
		}
		start = time.Now()
		for _, l := range lines {
			if o := s.runOne(context.Background(), batchInput(raw, l)); o.Reason != Resolved {
				t.Fatalf("n=%d single line %d: %+v", n, l, o)
			}
		}
		t.Log(fmt.Sprintf("DEEPSTACK n=%d mode=%s batched=%s sequential_single_launches=%s", n, c.Mode, batch.Round(time.Millisecond), time.Since(start).Round(time.Millisecond)))
		if batch >= ProcessTimeout {
			t.Fatalf("n=%d: batched run took %s", n, batch)
		}
	}
}
