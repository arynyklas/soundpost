// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package query

import (
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/logql"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The OCI oracle feeds the engine one iterator below every merge and never shards, so
// the fixture rows of the release campaign cannot observe the shard string switch, what a
// sharded evaluation does with an entry that two shard inputs both deliver, or what the
// querier-side merge iterators collapse (07.05#10, 02.12-W2). The probe
// conformance/query/author/logql-shard-probe drives the pinned Loki 3.5.2 sources directly
// over inputs authored in conformance/query/cases/logql-shard-replica-probe.json; its
// observations are content-locked in evidence/native-logql-shard-replica-observations.json.
// The tests below replay them without a container runtime.

type shardEntry struct {
	TS   string `json:"ts"`
	Host string `json:"host"`
	Line string `json:"line"`
}
type shardSample struct {
	TS    string  `json:"ts"`
	Host  string  `json:"host"`
	Value float64 `json:"value"`
	Hash  string  `json:"hash"`
}
type shardCases struct {
	Gating struct {
		Queries []struct {
			ID    string `json:"id"`
			Kind  string `json:"kind"`
			Query string `json:"query"`
		} `json:"queries"`
		Lists []struct {
			ID    string   `json:"id"`
			Names []string `json:"names"`
		} `json:"lists"`
	} `json:"gating"`
	Fixtures []struct {
		ID     string         `json:"id"`
		Inputs [][]shardEntry `json:"inputs"`
	} `json:"fixtures"`
	SampleFixtures []struct {
		ID     string          `json:"id"`
		Inputs [][]shardSample `json:"inputs"`
	} `json:"sample_fixtures"`
	Frontend []struct {
		ID        string `json:"id"`
		Fixture   string `json:"fixture"`
		Direction string `json:"direction"`
		Limit     int    `json:"limit"`
	} `json:"frontend"`
	Merges []struct {
		ID        string `json:"id"`
		Fixture   string `json:"fixture"`
		Direction string `json:"direction"`
		Mode      string `json:"mode"`
	} `json:"merges"`
	SampleMerges []struct {
		ID      string `json:"id"`
		Fixture string `json:"fixture"`
		Mode    string `json:"mode"`
	} `json:"sample_merges"`
}
type shardObsEntry struct {
	TS     string `json:"ts"`
	Labels string `json:"labels"`
	Line   string `json:"line"`
}
type shardObsSample struct {
	TS     string `json:"ts"`
	Labels string `json:"labels"`
	Sample string `json:"sample_hash"`
	Bits   string `json:"value_bits"`
}
type shardEvidence struct {
	Provenance string `json:"provenance"`
	Gating     []struct {
		List        string `json:"list"`
		Query       string `json:"query"`
		Noop        bool   `json:"noop"`
		Downstreams int    `json:"downstreams"`
		Error       string `json:"error"`
		Evaluated   *bool  `json:"evaluated"`
	} `json:"gating"`
	Frontend []struct {
		ID    string          `json:"id"`
		Error string          `json:"error"`
		Flat  []shardObsEntry `json:"flat"`
	} `json:"frontend"`
	Merges []struct {
		ID      string          `json:"id"`
		Error   string          `json:"error"`
		Entries []shardObsEntry `json:"entries"`
	} `json:"merges"`
	SampleMerges []struct {
		ID      string           `json:"id"`
		Error   string           `json:"error"`
		Samples []shardObsSample `json:"samples"`
	} `json:"sample_merges"`
}

func readShardProbe(t *testing.T) (shardCases, shardEvidence, map[string][][]shardEntry, map[string][][]shardSample) {
	t.Helper()
	var lock SourceLock
	if err := ReadJSON("../../../conformance/query/source-lock.json", &lock); err != nil {
		t.Fatal(err)
	}
	var in shardCases
	raw, err := readLocked(lock, "cases/logql-shard-replica-probe.json", "../../../conformance/query/cases/logql-shard-replica-probe.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	raw, err = readLocked(lock, "evidence/native-logql-shard-replica-observations.json", "../../../conformance/query/evidence/native-logql-shard-replica-observations.json")
	if err != nil {
		t.Fatal(err)
	}
	var ev shardEvidence
	if err = json.Unmarshal(raw, &ev); err != nil {
		t.Fatal(err)
	}
	// This reference was built natively from the pinned source archive, never run as the
	// digest-locked OCI image: the recorded file says so.
	if !strings.Contains(ev.Provenance, "a native build of the pinned source archive") || !strings.Contains(ev.Provenance, "not the digest-locked OCI image") {
		t.Fatalf("the recorded observations do not state that the reference was a native build of the pinned source archive: %q", ev.Provenance)
	}
	logs := map[string][][]shardEntry{}
	for _, f := range in.Fixtures {
		logs[f.ID] = f.Inputs
	}
	samples := map[string][][]shardSample{}
	for _, f := range in.SampleFixtures {
		samples[f.ID] = f.Inputs
	}
	// The observations are bound to the authored rows one to one, in order: a row that was
	// not observed, or an observation of no authored row, fails here.
	if len(ev.Gating) != len(in.Gating.Lists)*len(in.Gating.Queries) || len(ev.Frontend) != len(in.Frontend) ||
		len(ev.Merges) != len(in.Merges) || len(ev.SampleMerges) != len(in.SampleMerges) {
		t.Fatalf("observations %d/%d/%d/%d do not match the authored rows", len(ev.Gating), len(ev.Frontend), len(ev.Merges), len(ev.SampleMerges))
	}
	for i, o := range ev.Frontend {
		if o.ID != in.Frontend[i].ID || o.Error != "" {
			t.Fatalf("frontend observation %d is %q (error %q), authored %q", i, o.ID, o.Error, in.Frontend[i].ID)
		}
	}
	for i, o := range ev.Merges {
		if o.ID != in.Merges[i].ID || o.Error != "" {
			t.Fatalf("merge observation %d is %q (error %q), authored %q", i, o.ID, o.Error, in.Merges[i].ID)
		}
	}
	for i, o := range ev.SampleMerges {
		if o.ID != in.SampleMerges[i].ID || o.Error != "" {
			t.Fatalf("sample merge observation %d is %q (error %q), authored %q", i, o.ID, o.Error, in.SampleMerges[i].ID)
		}
	}
	return in, ev, logs, samples
}

// TestOwnedMatchesRecordedNativeShardAggregationSwitch: for every string list of 40 and
// every mappable query, the capability the pinned shard mapper enabled is exactly the
// capability the owned ShardAggregationGates enables: the four names independently,
// a repeated name once, and every other string (another spelling or case, surrounding
// space, a shard- prefix, a comma-joined pair, the empty string, an unrelated name)
// nothing and without effect on its neighbours. approx_topk evaluates only when its own
// name is listed; the pinned mapper refuses it otherwise.
func TestOwnedMatchesRecordedNativeShardAggregationSwitch(t *testing.T) {
	in, ev, _, _ := readShardProbe(t)
	gateOf := map[string]string{"first_over_time": "shard-first_over_time", "last_over_time": "shard-last_over_time",
		"quantile_over_time": "shard-quantile_over_time", "approx_topk": "approx_topk"}
	kinds := map[string]string{}
	for _, q := range in.Gating.Queries {
		kinds[q.ID] = q.Kind
	}
	names := map[string][]string{}
	for _, l := range in.Gating.Lists {
		names[l.ID] = l.Names
	}
	enabledRows, refusedRows := 0, 0
	for _, o := range ev.Gating {
		o := o
		t.Run(o.List+"/"+o.Query, func(t *testing.T) {
			owned := map[string]bool{}
			for _, g := range logql.ShardAggregationGates(names[o.List]) {
				owned[g] = true
			}
			kind := kinds[o.Query]
			switch kind {
			case "always":
				if o.Error != "" || o.Noop || o.Downstreams != 2 {
					t.Fatalf("the unconditionally shardable control was not sharded: %+v", o)
				}
			case "approx_topk":
				evaluated := o.Evaluated != nil && *o.Evaluated
				if evaluated != owned[gateOf[kind]] {
					t.Fatalf("pinned mapper evaluated approx_topk=%v with %q; owned switch enables it=%v", evaluated, names[o.List], owned[gateOf[kind]])
				}
				if !evaluated && !strings.Contains(o.Error, "approx_topk is not enabled") {
					t.Fatalf("pinned mapper refused approx_topk with %q, not the not-enabled refusal", o.Error)
				}
			default:
				sharded := o.Error == "" && !o.Noop && o.Downstreams == 2
				if refused := o.Error == "" && o.Noop && o.Downstreams <= 1; !sharded && !refused {
					t.Fatalf("observation is neither sharded nor a no-op: %+v", o)
				}
				if sharded != owned[gateOf[kind]] {
					t.Fatalf("pinned mapper sharded %s=%v with %q; owned switch enables it=%v", kind, sharded, names[o.List], owned[gateOf[kind]])
				}
			}
			if kind != "always" {
				if owned[gateOf[kind]] {
					enabledRows++
				} else {
					refusedRows++
				}
			}
		})
	}
	// The probe is not vacuous: of the 160 rows of the four capabilities, 49 enable one and 111 refuse it.
	if enabledRows != 49 || refusedRows != 111 {
		t.Fatalf("%d enabled and %d refused rows, recorded 49 and 111", enabledRows, refusedRows)
	}
}

type replayEntry struct{ ts, host, line string }

func (e replayEntry) labels() string { return `{app="api", host=` + strconv.Quote(e.host) + `}` }

func replayInputs(in [][]shardEntry) [][]replayEntry {
	out := make([][]replayEntry, len(in))
	for i, input := range in {
		for _, e := range input {
			out[i] = append(out[i], replayEntry{e.TS, e.Host, e.Line})
		}
	}
	return out
}

// shardRows is one input of the owned merge. Record identity follows arrival, as the
// owned engine treats equal text as distinct records.
type shardRows struct {
	rows []logql.PipelineResult
	at   int
}

func (i *shardRows) Next(context.Context) (logql.PipelineResult, error) {
	if i.at == len(i.rows) {
		return logql.PipelineResult{}, io.EOF
	}
	r := i.rows[i.at]
	i.at++
	return r, nil
}
func (i *shardRows) Watermarks() []model.Cursor { return nil }
func (i *shardRows) Partial() bool              { return false }
func (i *shardRows) Close() error               { return nil }

// ownedMerge runs the owned MergeLogs over the inputs and returns its entries, every
// multiplicity expanded, in the order the merge produced them.
func ownedMerge(t *testing.T, inputs [][]replayEntry, direction string, limit uint64) []shardObsEntry {
	t.Helper()
	order := logql.Forward
	if direction == "backward" {
		order = logql.Backward
	}
	var iterators []logql.EntryIterator
	arrival := uint64(0)
	for _, input := range inputs {
		rows := &shardRows{}
		for _, e := range input {
			ts, err := strconv.ParseInt(e.ts, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			arrival++
			var id model.ID
			id[0], id[1] = byte(arrival>>8), byte(arrival)
			labels := model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: e.host}}
			rows.rows = append(rows.rows, logql.PipelineResult{Retained: true, Entry: logql.LogEntry{ID: id, Timestamp: model.UnixNano(ts), Multiplicity: 1, Line: e.line}, Labels: labels, OriginalStreamLabels: labels})
		}
		iterators = append(iterators, rows)
	}
	account := value.NewBoundedAccount(32 << 20)
	merged, err := logql.MergeLogs(context.Background(), iterators, order, limit, account)
	if err != nil {
		t.Fatal(err)
	}
	defer merged.Close()
	var out []shardObsEntry
	for {
		r, err := merged.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		for n := model.Uint64(0); n < r.Entry.Multiplicity; n++ {
			out = append(out, shardObsEntry{TS: strconv.FormatInt(int64(r.Entry.Timestamp), 10), Labels: `{app="api", host=` + strconv.Quote(r.Labels[1].Value) + `}`, Line: r.Entry.Line})
		}
		account.Release(r.Bytes)
	}
}

// ownedEngine runs the owned query path (the one the release rows and the campaign use) over
// every delivered entry as one stored row each, and returns its entries in answer order with
// every multiplicity expanded. The pinned frontend reads its merged streams back without
// their hash, so equal-time entries of different streams order by label text there, as they
// do on this path; MergeLogs, the owned counterpart of the querier-side iterators, orders
// them by the original stream hash.
func ownedEngine(t *testing.T, inputs [][]replayEntry, direction string, limit uint64) []shardObsEntry {
	t.Helper()
	c := LogQLCase{
		ID: "shard-replica", Phase: "logql-metric", Profiles: []string{"logql-loki-3.5.2"}, Kind: "range", Query: `{app="api"}`,
		Start: 0, End: 60e9, Step: 1e9, Direction: direction, Limit: model.Uint64(limit),
		Configuration:  map[string]string{"count_min_sketch_heap_size": "10000", "instant_log_lookback_ns": "30000000000"},
		ConfigIdentity: "resolved-profile-manifest-default",
	}
	arrival := uint64(0)
	for _, input := range inputs {
		for _, e := range input {
			ts, err := strconv.ParseInt(e.ts, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			arrival++
			var id model.ID
			id[0], id[1] = byte(arrival>>8), byte(arrival)
			c.Entries = append(c.Entries, LogQLEntry{Timestamp: model.UnixNano(ts), ID: id, Multiplicity: 1, Line: e.line,
				StreamLabels: model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: e.host}}})
		}
	}
	p, err := resolveLogQLProfile("../../../profiles/query", nil)
	if err != nil {
		t.Fatal(err)
	}
	o, err := observeOwnedLogQL(context.Background(), c, p)
	if err != nil {
		t.Fatal(err)
	}
	var out []shardObsEntry
	for _, v := range o.Values {
		n := uint64(1)
		if v.Multiplicity != "" {
			if n, err = strconv.ParseUint(v.Multiplicity, 10, 64); err != nil {
				t.Fatal(err)
			}
		}
		for ; n > 0; n-- {
			out = append(out, shardObsEntry{TS: v.Timestamp, Labels: `{app="api", host=` + strconv.Quote(v.Labels[1].Value) + `}`, Line: v.Line})
		}
	}
	return out
}

// groups folds an ordered entry list into its (timestamp, stream) groups, in order of
// first appearance, with the lines of each group sorted. Entries of one stream and
// timestamp have no order of their own in the pinned sharded evaluation (the
// accumulator sorts them with an unstable sort); everything else is ordered.
type entryGroup struct {
	ts, labels string
	lines      []string
}

func groups(entries []shardObsEntry) []entryGroup {
	var out []entryGroup
	for _, e := range entries {
		if n := len(out); n == 0 || out[n-1].ts != e.TS || out[n-1].labels != e.Labels {
			out = append(out, entryGroup{ts: e.TS, labels: e.Labels})
		}
		g := &out[len(out)-1]
		g.lines = append(g.lines, e.Line)
	}
	for i := range out {
		sort.Strings(out[i].lines)
	}
	return out
}

func sameGroups(a, b []entryGroup) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ts != b[i].ts || a[i].labels != b[i].labels || strings.Join(a[i].lines, "\x00") != strings.Join(b[i].lines, "\x00") {
			return false
		}
	}
	return true
}

func distinctKeys(entries []shardObsEntry) int {
	seen := map[shardObsEntry]bool{}
	for _, e := range entries {
		seen[e] = true
	}
	return len(seen)
}

func replayObserved(in [][]replayEntry, first bool) []shardObsEntry {
	var out []shardObsEntry
	for i, input := range in {
		if first && i > 0 {
			break
		}
		for _, e := range input {
			out = append(out, shardObsEntry{TS: e.ts, Labels: e.labels(), Line: e.line})
		}
	}
	return out
}

// TestOwnedMatchesRecordedNativeShardedReplicaInputs: the real sharded evaluation of the
// pinned engine (ShardMapper + DownstreamEngine over two or three shard inputs) never
// collapses an entry that several shard inputs deliver: it keeps every copy, as the owned
// query path does with the same entries as stored rows (rule iterator-entry-merge: equal
// text never identifies a record). With no limit the owned answer reproduces the pinned
// one group by group (a group is one stream and timestamp), ties between streams included (label text order on both sides:
// the fixture cross-stream-hash-order has the original stream hash order opposite to the
// label order); under a limit it returns the same number of entries, all of them delivered
// (which of several entries tied at one timestamp in different streams survives the cut
// is the pinned accumulator's choice, not a language rule).
func TestOwnedMatchesRecordedNativeShardedReplicaInputs(t *testing.T) {
	in, ev, logs, _ := readShardProbe(t)
	replicas := 0
	for i, c := range in.Frontend {
		c, o := c, ev.Frontend[i]
		t.Run(strings.TrimPrefix(c.ID, "frontend/"), func(t *testing.T) {
			inputs := replayInputs(logs[c.Fixture])
			all := replayObserved(inputs, false)
			owned := ownedEngine(t, inputs, c.Direction, uint64(c.Limit))
			want := len(all)
			if c.Limit < want {
				want = c.Limit
			}
			if len(o.Flat) != want || len(owned) != want {
				t.Fatalf("pinned engine returned %d entries, owned %d, want %d of the %d delivered", len(o.Flat), len(owned), want, len(all))
			}
			if c.Limit >= len(all) {
				if !sameGroups(groups(o.Flat), groups(owned)) {
					t.Fatalf("owned differs from the pinned sharded answer\npinned %v\nowned  %v", o.Flat, owned)
				}
				if len(o.Flat) > distinctKeys(o.Flat) {
					replicas++
				}
				return
			}
			delivered := map[shardObsEntry]int{}
			for _, e := range all {
				delivered[e]++
			}
			for _, side := range [][]shardObsEntry{o.Flat, owned} {
				left := map[shardObsEntry]int{}
				for k, n := range delivered {
					left[k] = n
				}
				for _, e := range side {
					if left[e]--; left[e] < 0 {
						t.Fatalf("entry %+v returned more often than delivered", e)
					}
				}
			}
		})
	}
	// Not vacuous: most fixtures deliver an entry more than once and the pinned engine
	// returned every copy.
	if replicas < 10 {
		t.Fatalf("only %d unlimited rows returned an entry more than once", replicas)
	}
}

// declaredEntryMergeCollapse pins, per fixture, the entries one querier-side merge of the
// pinned engine returns for the entries the owned engine keeps: {merge of every input
// (owned, pinned), merge of the first input only (owned, pinned)}. They differ where the
// pinned merge treats equal (timestamp, stream, line) as one entry. The owned engine does
// not: the locked rule of iterator-entry-merge says normalization must distinguish owned
// multiplicity from upstream replica merging and cannot globally deduplicate input.
var declaredEntryMergeCollapse = map[string][4]int{
	"replica":                 {6, 3, 3, 3},
	"replica-inner-dup":       {6, 2, 3, 2},
	"disjoint":                {2, 2, 1, 1},
	"partial-overlap":         {4, 3, 2, 2},
	"same-ts-opposite-order":  {4, 2, 2, 2},
	"cross-stream-replica":    {4, 2, 2, 2},
	"same-line-other-stream":  {2, 2, 1, 1},
	"triple-replica":          {3, 1, 1, 1},
	"inner-dup-first-only":    {3, 2, 2, 1},
	"cross-stream-hash-order": {4, 2, 2, 2},
}

// TestRecordedNativeEntryMergeCollapseIsDeclaredAgainstOwned is the explicit declaration
// of the one place where the pinned entry merge and the owned engine differ. It replays
// every merge observation: the pinned sort iterator (the frontend's merge) equals the
// owned merge; the pinned merge iterator returns exactly one entry per distinct
// (timestamp, stream, line) of its input, whether the copies came from several inputs or
// from one, where the owned merge keeps every entry; and the entries the merge does
// return are those of the owned answer, in its order. A fixture that stops diverging, a
// new divergence, or a changed collapse rule fails the pinned table.
func TestRecordedNativeEntryMergeCollapseIsDeclaredAgainstOwned(t *testing.T) {
	in, ev, logs, _ := readShardProbe(t)
	seen := map[string]map[string]int{}
	for i, c := range in.Merges {
		c, o := c, ev.Merges[i]
		t.Run(strings.TrimPrefix(c.ID, "merge/"), func(t *testing.T) {
			inputs := replayInputs(logs[c.Fixture])
			first := c.Mode == "merge-first"
			all := replayObserved(inputs, first)
			ownedInputs := inputs
			if first {
				ownedInputs = inputs[:1]
			}
			owned := ownedMerge(t, ownedInputs, c.Direction, uint64(len(all))+1)
			if len(owned) != len(all) {
				t.Fatalf("owned merge returned %d of %d entries", len(owned), len(all))
			}
			if seen[c.Fixture] == nil {
				seen[c.Fixture] = map[string]int{}
			}
			switch c.Mode {
			case "sort-all":
				if !sameGroups(groups(o.Entries), groups(owned)) {
					t.Fatalf("pinned sort iterator differs from the owned merge\npinned %v\nowned  %v", o.Entries, owned)
				}
			default:
				if len(o.Entries) != distinctKeys(replayObserved(ownedInputs, false)) {
					t.Fatalf("pinned merge returned %d entries for %d distinct (timestamp, stream, line)", len(o.Entries), distinctKeys(all))
				}
				// every group of the pinned answer is a group of the owned answer, in order,
				// holding each distinct line of it once
				pinned, ownedGroups := groups(o.Entries), groups(owned)
				if len(pinned) != len(ownedGroups) {
					t.Fatalf("pinned groups %v, owned groups %v", pinned, ownedGroups)
				}
				for j := range pinned {
					var distinct []string
					for k, line := range ownedGroups[j].lines {
						if k == 0 || line != ownedGroups[j].lines[k-1] {
							distinct = append(distinct, line)
						}
					}
					if pinned[j].ts != ownedGroups[j].ts || pinned[j].labels != ownedGroups[j].labels || strings.Join(pinned[j].lines, "\x00") != strings.Join(distinct, "\x00") {
						t.Fatalf("pinned group %v is not the distinct lines of owned group %v", pinned[j], ownedGroups[j])
					}
				}
			}
			if c.Direction == "forward" {
				seen[c.Fixture][c.Mode+"/owned"], seen[c.Fixture][c.Mode+"/pinned"] = len(owned), len(o.Entries)
			}
		})
	}
	diverging := 0
	for fixture, want := range declaredEntryMergeCollapse {
		got := seen[fixture]
		have := [4]int{got["merge-all/owned"], got["merge-all/pinned"], got["merge-first/owned"], got["merge-first/pinned"]}
		if have != want {
			t.Errorf("fixture %s: merge counts %v, declared %v", fixture, have, want)
		}
		if have[0] > have[1] || have[2] > have[3] {
			diverging++
		}
	}
	if len(seen) != len(declaredEntryMergeCollapse) {
		t.Errorf("%d fixtures observed, %d declared", len(seen), len(declaredEntryMergeCollapse))
	}
	if diverging != 8 {
		t.Errorf("%d fixtures show a collapse, declared 8", diverging)
	}
}

// declaredSampleMerge pins, per fixture, the samples that the pinned sort iterator,
// the merge of every input and the merge of the first input return. A nonzero sample hash
// equal across the inputs at one timestamp and stream is one sample; a zero hash, equal
// values with different hashes, and the same hash in another stream are not; two samples
// of one input with one hash survive the merge of one input.
var declaredSampleMerge = map[string][3]int{
	"replica-hash":           {4, 2, 2},
	"replica-zero-hash":      {4, 4, 2},
	"same-value-other-hash":  {2, 2, 1},
	"same-hash-other-value":  {2, 1, 1},
	"inner-dup-hash":         {4, 2, 2},
	"cross-stream-same-hash": {2, 2, 1},
	"partial-overlap-hash":   {4, 3, 2},
}

// TestRecordedNativeSampleMergeCollapseIsDeclaredAgainstOwned: the pinned sample merge
// suppresses a sample by its hash (iterator-sample-merge: value equality alone is not
// identity; zero disables the criterion). The owned engine has no hash to suppress by: its
// rows are counted by multiplicity (the campaign rows of iterator-sample-merge observed
// the same counts through one iterator) and a replica is a further row. The declaration
// pins the pinned engine's counts; the sort iterator, which does not deduplicate, keeps
// every sample.
func TestRecordedNativeSampleMergeCollapseIsDeclaredAgainstOwned(t *testing.T) {
	in, ev, _, samples := readShardProbe(t)
	counts := map[string]map[string]int{}
	for i, c := range in.SampleMerges {
		o := ev.SampleMerges[i]
		if counts[c.Fixture] == nil {
			counts[c.Fixture] = map[string]int{}
		}
		counts[c.Fixture][c.Mode] = len(o.Samples)
		total := 0
		for j, input := range samples[c.Fixture] {
			if c.Mode == "merge-first" && j > 0 {
				break
			}
			total += len(input)
		}
		if c.Mode == "sort-all" && len(o.Samples) != total {
			t.Errorf("%s: the sort iterator returned %d of %d samples", c.ID, len(o.Samples), total)
		}
		if c.Mode != "sort-all" && len(o.Samples) > total {
			t.Errorf("%s: the merge invented samples: %d of %d", c.ID, len(o.Samples), total)
		}
	}
	for fixture, want := range declaredSampleMerge {
		got := [3]int{counts[fixture]["sort-all"], counts[fixture]["merge-all"], counts[fixture]["merge-first"]}
		if got != want {
			t.Errorf("fixture %s: sample counts %v, declared %v", fixture, got, want)
		}
	}
	if len(counts) != len(declaredSampleMerge) {
		t.Errorf("%d sample fixtures observed, %d declared", len(counts), len(declaredSampleMerge))
	}
	// the rule, from the observations: equal values never collapse, equal nonzero hashes do
	if counts["same-value-other-hash"]["merge-all"] != counts["same-value-other-hash"]["sort-all"] ||
		counts["replica-zero-hash"]["merge-all"] != counts["replica-zero-hash"]["sort-all"] ||
		counts["same-hash-other-value"]["merge-all"] >= counts["same-hash-other-value"]["sort-all"] ||
		counts["replica-hash"]["merge-all"] >= counts["replica-hash"]["sort-all"] {
		t.Errorf("the observations do not show the hash rule: %v", counts)
	}
}

// TestShardReplicaProbeIsBoundToItsObligations: the replay tests are the bound Go tests of
// the three obligations the probe closes, and the probe's inputs and observations are
// content-locked. Unbinding a test, dropping it from the observed list, or editing either
// locked file fails here and in the release gate (a bound test without a pass event is an
// unobserved test, an unresolved obligation).
func TestShardReplicaProbeIsBoundToItsObligations(t *testing.T) {
	var acceptance struct {
		Bindings []struct {
			ObligationID string   `json:"obligation_id"`
			GoTests      []string `json:"go_tests"`
		} `json:"production_bindings"`
	}
	raw, err := os.ReadFile("../../../conformance/query/acceptance.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &acceptance); err != nil {
		t.Fatal(err)
	}
	bound := map[string][]string{}
	for _, b := range acceptance.Bindings {
		bound[b.ObligationID] = b.GoTests
	}
	observed, err := os.ReadFile("../../../conformance/query/author/observed-tests.d/logql.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"logql-loki-3.5.2/shard-capability-domain": {"TestOwnedMatchesRecordedNativeShardAggregationSwitch"},
		"logql-loki-3.5.2/iterator-entry-merge":    {"TestOwnedMatchesRecordedNativeShardedReplicaInputs", "TestRecordedNativeEntryMergeCollapseIsDeclaredAgainstOwned"},
		"logql-loki-3.5.2/iterator-sample-merge":   {"TestRecordedNativeSampleMergeCollapseIsDeclaredAgainstOwned"},
	}
	for obligation, tests := range want {
		for _, name := range tests {
			found := false
			for _, b := range bound[obligation] {
				found = found || b == name
			}
			if !found {
				t.Errorf("%s is not bound to %s", name, obligation)
			}
			if !strings.Contains(string(observed), "./internal/conformance/query "+name+"\n") {
				t.Errorf("%s is not in the observed test list", name)
			}
		}
	}
	// A bound test that is no longer declared is a removed test: the pass event of a stale
	// evidence stream must not keep it alive.
	declared := map[string]bool{}
	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), "_test.go") {
			continue
		}
		parsed, perr := parser.ParseFile(token.NewFileSet(), f.Name(), nil, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, decl := range parsed.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
				declared[fn.Name.Name] = true
			}
		}
	}
	for _, tests := range want {
		for _, name := range tests {
			if !declared[name] {
				t.Errorf("bound test %s is not declared in this package", name)
			}
		}
	}
	var lock SourceLock
	if err = ReadJSON("../../../conformance/query/source-lock.json", &lock); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"cases/logql-shard-replica-probe.json", "evidence/native-logql-shard-replica-observations.json"} {
		if len(lock.InventoryFiles[key]) != 64 {
			t.Errorf("%s is not content-locked", key)
		}
	}
}
