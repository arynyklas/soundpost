// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"io"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/profile"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// Expectations are the obligation rule text (logql-loki-3.5.2/shard-capability-domain
// and iterator-entry-merge), written by hand: four recognized names enable their
// capabilities independently, duplicates repeat enablement, unknown strings are
// ignored.
func TestReleaseLogQLShardAggregationSwitchSemantics(t *testing.T) {
	cases := []struct {
		name  string
		names []string
		want  []string
	}{
		{"empty", nil, []string{}},
		{"each alone first", []string{"first_over_time"}, []string{"shard-first_over_time"}},
		{"each alone last", []string{"last_over_time"}, []string{"shard-last_over_time"}},
		{"each alone quantile", []string{"quantile_over_time"}, []string{"shard-quantile_over_time"}},
		{"each alone approx", []string{"approx_topk"}, []string{"approx_topk"}},
		{"all four independently, canonical order", []string{"approx_topk", "quantile_over_time", "last_over_time", "first_over_time"},
			[]string{"shard-first_over_time", "shard-last_over_time", "shard-quantile_over_time", "approx_topk"}},
		{"duplicates repeat enablement", []string{"first_over_time", "first_over_time", "approx_topk", "first_over_time"},
			[]string{"shard-first_over_time", "approx_topk"}},
		{"unknown strings ignored", []string{"sum_over_time", "", " first_over_time", "FIRST_OVER_TIME", "first_over_time ", "shard-first_over_time", "shard-approx_topk", "rate"}, []string{}},
		{"unknown does not disturb known", []string{"nonsense", "last_over_time", "", "approx_topk", "x"}, []string{"shard-last_over_time", "approx_topk"}},
	}
	for _, c := range cases {
		if got := ShardAggregationGates(c.names); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v -> %v, want %v", c.name, c.names, got, c.want)
		}
	}
}

// Every combination of the four names is a registered feature set of the pinned
// profile (the closure the language ledger enumerates), so the switch can never
// select a profile the registry does not know.
func TestReleaseLogQLShardAggregationSwitchSelectsRegisteredFeatureSets(t *testing.T) {
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	for mask := range 1 << len(shardCapabilities) {
		var names []string
		for i, capability := range shardCapabilities {
			if mask&(1<<i) != 0 {
				names = append(names, capability, capability, "ignored-"+capability)
			}
		}
		gates := ShardAggregationGates(names)
		want := append([]string(nil), gates...)
		sort.Strings(want)
		found := ""
		for _, set := range base.FeatureSets {
			have := append([]string(nil), set.Enabled...)
			sort.Strings(have)
			if reflect.DeepEqual(have, want) || (len(have) == 0 && len(want) == 0) {
				found = set.ID
				break
			}
		}
		if found == "" {
			t.Fatalf("combination %v (%v) has no registered feature set", names, gates)
		}
		if _, err = registry.Resolve(base.ID, found); err != nil {
			t.Fatalf("combination %v: %v", names, err)
		}
	}
}

func profileWithGates(t *testing.T, gates []string) profile.Profile {
	t.Helper()
	registry, err := profile.Load(os.DirFS("../../../profiles/query"))
	if err != nil {
		t.Fatal(err)
	}
	base := testProfile(t)
	want := append([]string(nil), gates...)
	sort.Strings(want)
	for _, set := range base.FeatureSets {
		have := append([]string(nil), set.Enabled...)
		sort.Strings(have)
		if reflect.DeepEqual(have, want) || (len(have) == 0 && len(want) == 0) {
			p, err := registry.Resolve(base.ID, set.ID)
			if err != nil {
				t.Fatal(err)
			}
			return p
		}
	}
	t.Fatalf("no registered feature set for %v", gates)
	return profile.Profile{}
}

// approx_topk is enabled by its own name only: the switch with duplicates and
// unknown strings around it behaves as the single name, and the other three
// names never imply it.
func TestReleaseLogQLShardAggregationSwitchDrivesApproxTopK(t *testing.T) {
	query := `approx_topk(1,` + relAPI + `)`
	build := func(names ...string) error {
		p := profileWithGates(t, ShardAggregationGates(names))
		typed, err := parseCheck(t, query, p)
		if err != nil {
			return err
		}
		_, err = BuildPlan(typed, value.Evaluation{Instant: true, Time: 2e9}, p)
		return err
	}
	for _, names := range [][]string{{"approx_topk"}, {"approx_topk", "approx_topk", "bogus"}, {"bogus", "first_over_time", "approx_topk"}} {
		if err := build(names...); err != nil {
			t.Errorf("%v refused approx_topk: %v", names, err)
		}
	}
	for _, names := range [][]string{nil, {"first_over_time", "last_over_time", "quantile_over_time"}, {"Approx_TopK", "approx_topk "}, {"shard-approx_topk"}} {
		if err := build(names...); err == nil {
			t.Errorf("%v enabled approx_topk", names)
		}
	}
}

// Replica collapse is an upstream behavior the owned engine deliberately does not
// perform (rule iterator-entry-merge: normalization must distinguish owned
// multiplicity from upstream replica merging and cannot globally deduplicate): the
// same stream, time and line arriving from two shard inputs is two entries, in both
// directions, and a single-input run keeps its encounter order.
func TestReleaseLogQLMergeLogsNeverCollapsesReplicasAcrossInputs(t *testing.T) {
	for _, order := range []LogOrder{Forward, Backward} {
		a := value.NewBoundedAccount(32 << 20)
		left := &releaseRows{rows: []PipelineResult{releaseRow(1, 1000, "same", "a"), releaseRow(2, 2000, "same", "a")}}
		right := &releaseRows{rows: []PipelineResult{releaseRow(3, 1000, "same", "a"), releaseRow(4, 1000, "other", "a")}}
		merged, err := MergeLogs(context.Background(), []EntryIterator{left, right}, order, 10, a)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		for {
			r, e := merged.Next(context.Background())
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			for n := model.Uint64(0); n < r.Entry.Multiplicity; n++ {
				lines = append(lines, r.Entry.Line)
			}
		}
		merged.Close()
		count := map[string]int{}
		for _, l := range lines {
			count[l]++
		}
		if len(lines) != 4 || count["same"] != 3 || count["other"] != 1 {
			t.Fatalf("order %v: replicas collapsed or invented: %v", order, lines)
		}
	}
}
