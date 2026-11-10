// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package replays

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"soundpost/internal/model"
	"soundpost/internal/storage"
	"strconv"
	"strings"
	"testing"
	"time"
)

const canary = "CANARY-secret-page-text-7f3a"

// storedRows counts every replay row in the project as an authorized reader sees it.
func (f *fx) storedRows(t tenant) int {
	f.t.Helper()
	// Sessions lapse when a test moves the clock by days: log the owner in again.
	login, err := f.auth.Login(f.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		f.t.Fatal(err)
	}
	if f.cred, err = f.auth.Authenticate(f.ctx, login.Token); err != nil {
		f.t.Fatal(err)
	}
	scope, _ := f.reader(t, t.project)
	it, err := f.engine.Scan(f.ctx, scope, storage.ScanRequest{Projects: []model.ID{t.project}, Signal: model.Replay, Start: math.MinInt64, End: math.MaxInt64})
	if err != nil {
		f.t.Fatal(err)
	}
	defer it.Close()
	n := 0
	for {
		p, err := it.Next(f.ctx)
		if errors.Is(err, io.EOF) {
			return n
		}
		if err != nil {
			f.t.Fatal(err)
		}
		n += p.Len()
	}
}

// gated is the production admission order for a wire chunk: closed-format
// validation first, durable append only for what passes.
func (f *fx) gated(t tenant, raw []byte) error {
	g := f.grant(t)
	c, err := f.svc.ValidateJSON(g, raw)
	if err != nil {
		return err
	}
	return f.rawAppend(t, c, true)
}

func wire(t *testing.T, c model.ReplayChunk, edit func(map[string]any)) []byte {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReplayRejectsRawChannelsBeforeStorage(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	good := r.cp()
	node := func(m map[string]any) map[string]any { return m["nodes"].([]any)[0].(map[string]any) }
	event := func(m map[string]any) map[string]any { return m["events"].([]any)[0].(map[string]any) }
	cases := map[string]func(map[string]any){}
	// Every raw-content channel as an unknown field at every level of the closed format.
	for _, key := range []string{"html", "inner_html", "outer_html", "text", "text_content", "attributes", "attrs", "css", "style", "stylesheet", "url", "href", "src", "canvas", "canvas_data", "body", "request_body", "response_body", "value", "title"} {
		key := key
		cases["top-level "+key] = func(m map[string]any) { m[key] = canary }
		cases["node "+key] = func(m map[string]any) { node(m)[key] = canary }
		cases["event "+key] = func(m map[string]any) { event(m)[key] = canary }
	}
	// And through the known fields.
	cases["node text"] = func(m map[string]any) { node(m)["text"] = "<b>" + canary + "</b>" }
	cases["node text whitespace variant"] = func(m map[string]any) { node(m)["text"] = " [masked]" }
	cases["node class"] = func(m map[string]any) { node(m)["class"] = canary }
	cases["node tag"] = func(m map[string]any) { node(m)["tag"] = "script" }
	cases["node tag with content"] = func(m map[string]any) { node(m)["tag"] = "div " + canary }
	cases["event kind"] = func(m map[string]any) { event(m)["kind"] = "keypress" }
	cases["event kind with content"] = func(m map[string]any) { event(m)["kind"] = canary }
	cases["recorder version"] = func(m map[string]any) { m["recorder_version"] = canary }
	cases["recorder version of a future recorder"] = func(m map[string]any) { m["recorder_version"] = "9" }
	cases["duplicate node ids"] = func(m map[string]any) {
		m["nodes"] = append(m["nodes"].([]any), m["nodes"].([]any)[0])
	}
	cases["node parent loop"] = func(m map[string]any) { node(m)["parent"] = node(m)["id"] }
	cases["zero node id"] = func(m map[string]any) { node(m)["id"] = "0" }
	cases["oversized node id"] = func(m map[string]any) { node(m)["id"] = "18446744073709551615" }
	cases["event coordinate overflow"] = func(m map[string]any) { event(m)["x"] = 1 << 30 }
	cases["sequence zero"] = func(m map[string]any) { m["sequence"] = "0" }
	cases["sequence beyond the replay bound"] = func(m map[string]any) { m["sequence"] = "70000" }
	cases["checkpoint beyond sequence"] = func(m map[string]any) { m["checkpoint_sequence"] = "5" }
	cases["first chunk with a previous hash"] = func(m map[string]any) { m["previous_hash"] = strings.Repeat("ab", 32) }
	cases["zero replay id"] = func(m map[string]any) { m["replay_id"] = strings.Repeat("0", 32) }
	cases["zero policy revision"] = func(m map[string]any) { m["capture_policy_revision"] = "0" }
	cases["clock without a domain"] = func(m map[string]any) {
		m["clock"].(map[string]any)["domain"] = map[string]any{"host": strings.Repeat("0", 32), "boot": strings.Repeat("0", 32), "runtime": strings.Repeat("0", 32)}
	}
	cases["too many nodes"] = func(m map[string]any) {
		n := m["nodes"].([]any)
		for i := 0; i < 4200; i++ {
			c := map[string]any{}
			for k, v := range n[0].(map[string]any) {
				c[k] = v
			}
			c["id"] = strconv.Itoa(i + 10)
			n = append(n, c)
		}
		m["nodes"] = n
	}
	for name, edit := range cases {
		raw := wire(t, good, edit)
		// The gate itself must refuse: the model's own record validation behind
		// it must never be what keeps raw content out.
		_, err := f.svc.ValidateJSON(f.grant(f.main), raw)
		if err == nil {
			t.Errorf("%s: passed the closed-format gate", name)
			continue
		}
		if gerr := f.gated(f.main, raw); gerr == nil {
			t.Errorf("%s: admitted", name)
			continue
		}
		var fault *model.Fault
		if !errors.As(err, &fault) {
			t.Errorf("%s: not a closed fault: %v", name, err)
			continue
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(fault.SafeDetail, "script") || strings.Contains(fault.SafeDetail, "<") {
			t.Errorf("%s: error echoes input: %v", name, err)
		}
	}
	if n := f.storedRows(f.main); n != 0 {
		t.Fatalf("%d rejected chunks reached durable storage", n)
	}
	// Control: the same chunk, unedited, is admitted and is the only row.
	if err := f.gated(f.main, wire(t, good, func(map[string]any) {})); err != nil {
		t.Fatalf("valid chunk rejected: %v", err)
	}
	if n := f.storedRows(f.main); n != 1 {
		t.Fatalf("stored rows %d, want 1", n)
	}
	// Duplicate JSON keys are rejected before decoding into the closed type.
	dup := strings.Replace(string(wire(t, r.delta(), func(map[string]any) {})), `"loss"`, `"loss":"0","loss"`, 1)
	if err := f.gated(f.main, []byte(dup)); err == nil {
		t.Fatal("duplicate keys admitted")
	}
	if _, err := f.svc.ValidateJSON(f.grant(f.main), make([]byte, MaxChunkBytes+1)); code(err) != model.TooLarge {
		t.Fatalf("oversized wire chunk: %v", err)
	}
}

func TestReplayValidateIsStatelessClosedFormat(t *testing.T) {
	f := newFx(t)
	r := newRecorder(f.wall())
	cp, d := r.cp(), r.delta()
	g := f.grant(f.main)
	if err := f.svc.Validate(g, cp); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Validate(g, d); err != nil {
		t.Fatal(err)
	}
	// A delta must name a checkpoint; a checkpoint repeats its previous hash.
	bad := d
	bad.Checkpoint = model.Hash{}
	if code(f.svc.Validate(g, bad)) != model.Invalid {
		t.Fatal("delta without a checkpoint hash accepted")
	}
	bad = r.cp()
	bad.Checkpoint = model.Hash{}
	if code(f.svc.Validate(g, bad)) != model.Invalid {
		t.Fatal("checkpoint whose checkpoint hash differs from its previous hash accepted")
	}
	// The replay bound is a rule of its own: a chain-consistent delta beyond it is refused.
	far := d
	far.Sequence = MaxSequence + 1
	if code(f.svc.Validate(g, far)) != model.Invalid {
		t.Fatal("sequence beyond the replay bound accepted")
	}
	far.Sequence = MaxSequence
	if err := f.svc.Validate(g, far); err != nil {
		t.Fatalf("the last allowed sequence refused: %v", err)
	}
	// A chunk bigger than the closed ceiling is rejected whole.
	big := r.cp()
	for i := 0; i < 4096; i++ {
		big.Nodes = append(big.Nodes, model.MaskedNode{ID: model.Uint64(i + 10), Tag: "masked", Class: "masked", Text: "[masked]"})
	}
	big.Events = nil
	for i := 0; i < 4096; i++ {
		big.Events = append(big.Events, model.MaskedEvent{At: model.MonoNano(i), Kind: "mutation", Node: model.Uint64(i + 10), X: 1 << 20, Y: 1 << 20})
	}
	if code(f.svc.Validate(g, big)) != model.TooLarge {
		t.Fatal("chunk above 128 KiB accepted")
	}
	// A grant past its deadline validates nothing.
	f.clock.Add(int64(10 * time.Second))
	if err := f.svc.Validate(g, cp); code(err) != model.Stale {
		t.Fatalf("stale grant: %v", err)
	}
	if _, err := New(nil, f.auth, f.store); err == nil {
		t.Fatal("service built without a scanner")
	}
	if _, err := New(f.scan, nil, f.store); err == nil {
		t.Fatal("service built without an authorizer")
	}
	if _, err := New(f.scan, f.auth, nil); err == nil {
		t.Fatal("service built without control state")
	}
}
