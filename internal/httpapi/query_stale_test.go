// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query"
	"testing"
)

// 05.09#6: the page-level Stale state has a producer in the shipped storage. A caller that names a minimum read position no shard has reached
// (a replica behind the read fence) and allows partial results is answered `stale` with the data each shard holds at its own cut, not
// `partial` with that shard's data dropped: the shard is present, only older than the caller required. A caller that forbids partial results
// is still refused (409 stale) and sees no value.
func TestQueryThatAllowsPartialResultsReadsAShardBehindTheMinimumAsStaleWithItsData(t *testing.T) {
	e := newQueryEnv(t, queryLimits())
	ids := sharedIDs{model.NewID(), model.NewID(), model.NewID()}
	p := model.NewID()
	org := e.org("stale org", p)
	alice := e.user(org, "alice@example.test")
	e.grant(org, alice, p, true, auth.Read)
	s := e.metricSource(org, p, ids)
	e.metricPoint(s, "up", model.Labels{{Name: "job", Value: "api"}}, sampleTime, 1, nil)

	read := func(body queryBody) (int, []byte) {
		status, raw, _ := e.post(alice, "/api/v1/query", body)
		return status, raw
	}
	// The control: a read with no minimum is complete and names the position each shard was read through.
	status, raw := read(e.request(org, []model.ID{p}, "up", sampleTime+1_000_000))
	if status != 200 {
		t.Fatalf("control read: %d %s", status, raw)
	}
	control := decodeResult(t, raw).Projects[0]
	if control.Completeness != "complete" || len(control.Watermarks) == 0 || control.Value == nil || len(control.Value.Vector) != 1 {
		t.Fatalf("control read: %+v", control)
	}
	// A position one beyond what every shard has reached: no shard is at it.
	ahead := make([]queryBody, len(control.Watermarks))
	for i, w := range control.Watermarks {
		ahead[i] = queryBody{"group": w.Group.String(), "index": decimal(int64(w.Index) + 1_000_000)}
	}
	body := e.request(org, []model.ID{p}, "up", sampleTime+1_000_000)
	body["min_cursors"] = ahead

	// Without the opt-in the whole query is refused and no value leaves.
	if status, raw = read(body); status != 409 {
		t.Fatalf("a minimum no shard reached, partial results forbidden: %d %s", status, raw)
	} else if code, _ := faultBody(t, raw); code != "stale" {
		t.Fatalf("refusal code %q: %s", code, raw)
	}

	// With it the project is stale and still carries the value the shards hold; it is neither complete nor partial.
	body["allow_partial"] = true
	status, raw = read(body)
	if status != 200 {
		t.Fatalf("a minimum no shard reached, partial results allowed: %d %s", status, raw)
	}
	got := decodeResult(t, raw).Projects[0]
	if got.Completeness != query.CompletenessStale {
		t.Fatalf("completeness %q, want stale: %s", got.Completeness, raw)
	}
	if got.Value == nil || len(got.Value.Vector) != 1 || got.Failure != nil {
		t.Fatalf("a stale project keeps the data its shards hold: %s", raw)
	}
	if len(got.Watermarks) != len(control.Watermarks) {
		t.Fatalf("every shard answered, so every shard keeps its watermark: %d of %d", len(got.Watermarks), len(control.Watermarks))
	}

	// A stale answer is never cached as complete: the same query without the minimum is computed afresh and complete.
	if status, raw = read(e.request(org, []model.ID{p}, "up", sampleTime+1_000_000)); status != 200 || decodeResult(t, raw).Projects[0].Completeness != "complete" {
		t.Fatalf("the read after a stale one: %d %s", status, raw)
	}
}
