// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package logql

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/query/scan"
	"github.com/arynyklas/soundpost/internal/query/value"
)

// The expectations below are rows of the recorded observations of the pinned Loki 3.5.2 reference
// (conformance/query/evidence/native-logql-interval-observations.json, cases
// logql-interval-multiplicity/...; a native build of the pinned source archive, D63). The full replay
// is TestOwnedMatchesRecordedNativeLogQLIntervalObservations in internal/conformance/query.

const intervalS = int64(1_000_000_000)

func hostRow(id byte, at int64, host string, mult uint64, line string) scan.LogRow {
	return scan.LogRow{ID: model.ID{id}, Project: model.ID{1}, Source: model.ID{2}, Timestamp: model.UnixNano(at), Multiplicity: model.Uint64(mult),
		Record: model.LogRecord{Line: line, StreamLabels: model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: host}}}}
}

// logsOf renders the rows of a result as "<ns>|<host>|<line>|<multiplicity>".
func logsOf(r value.Result) []string {
	var out []string
	for _, l := range r.Logs {
		host := ""
		for _, x := range l.Labels {
			if x.Name == "host" {
				host = x.Value
			}
		}
		out = append(out, fmt.Sprintf("%d|%s|%s|%d", l.Timestamp, host, l.Line, l.Multiplicity))
	}
	return out
}

func evalRaw(t *testing.T, rows []scan.LogRow, start, end int64, order LogOrder, limit uint64, interval int64) []string {
	t.Helper()
	return evalRawQuery(t, `{app="api"}`, rows, start, end, order, limit, interval)
}

func evalRawQuery(t *testing.T, query string, rows []scan.LogRow, start, end int64, order LogOrder, limit uint64, interval int64) []string {
	t.Helper()
	src := &metricSource{rows: rows}
	plan := metricPlan(t, query, value.Evaluation{Start: model.UnixNano(start), End: model.UnixNano(end)})
	a := value.NewBoundedAccount(32 << 20)
	r, err := EvaluateLogsInterval(context.Background(), plan, src, order, limit, interval, a)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Release(value.ResultBytes(r))
	return logsOf(r)
}

// The tied entry a limit keeps follows the hash of the ORIGINAL stream labels, the order of the
// answer follows the labels the query shows (observed rows relabelled/forward/i0/l3 and l100,
// relabelled/backward/i0/l100, relabelled/forward/i500000000/l3 of the recorded Loki observations).
// Stream a is shown as host "z" by the label_format, so it sorts after b and c.
func TestEvaluateLogsTiedEntriesKeepTheOriginalHashAndShowTheQueryLabels(t *testing.T) {
	rows := []scan.LogRow{
		hostRow(1, 1*intervalS, "c", 2, "x"), hostRow(2, 1*intervalS, "a", 3, "x"), hostRow(3, 1*intervalS, "b", 1, "y"),
		hostRow(4, 2*intervalS, "b", 4, "z"), hostRow(5, 2*intervalS, "a", 1, "z"), hostRow(6, 2*intervalS, "c", 2, "w"),
		hostRow(7, 3*intervalS, "a", 2, "x"), hostRow(8, 3*intervalS, "b", 2, "x"), hostRow(9, 4*intervalS, "c", 3, "v"),
	}
	const query = `{app="api"} | label_format host="{{ if eq .host \"a\" }}z{{ else }}{{ .host }}{{ end }}"`
	for _, tc := range []struct {
		name     string
		order    LogOrder
		limit    uint64
		interval int64
		want     []string
	}{
		{"forward limit 3", Forward, 3, 0, []string{"1000000000|c|x|2", "1000000000|z|x|1"}},
		{"forward all", Forward, 100, 0, []string{
			"1000000000|b|y|1", "1000000000|c|x|2", "1000000000|z|x|3", "2000000000|b|z|4", "2000000000|c|w|2", "2000000000|z|z|1",
			"3000000000|b|x|2", "3000000000|z|x|2", "4000000000|c|v|3"}},
		{"backward all", Backward, 100, 0, []string{
			"4000000000|c|v|3", "3000000000|b|x|2", "3000000000|z|x|2", "2000000000|b|z|4", "2000000000|c|w|2", "2000000000|z|z|1",
			"1000000000|b|y|1", "1000000000|c|x|2", "1000000000|z|x|3"}},
		{"forward 500ms limit 3", Forward, 3, intervalS / 2, []string{"1000000000|c|x|1", "2000000000|c|w|1", "3000000000|z|x|1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalRawQuery(t, query, rows, 0, 60*intervalS, tc.order, tc.limit, tc.interval)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// Loki's readStreams skips an entry that is closer than `interval` to the last output entry only
// while `lastEntry.Unix() >= 0`: after an output entry before 1970 every following entry is
// output, with its whole multiplicity (each copy is its own entry). An entry at or after the epoch
// is thinned again, so its copies are cut to one.
func TestEvaluateLogsIntervalAfterAPreEpochEntryFollowsThePinnedEngine(t *testing.T) {
	rows := []scan.LogRow{
		hostRow(1, -4*intervalS, "a", 3, "e1"), hostRow(2, -3*intervalS, "a", 2, "e2"), hostRow(3, -3*intervalS, "a", 2, "e3"),
		hostRow(4, -2*intervalS, "a", 4, "e4"), hostRow(5, -1*intervalS, "a", 2, "e5"), hostRow(6, -1, "a", 3, "e6"),
		hostRow(7, 0, "a", 2, "e7"), hostRow(8, 1*intervalS, "a", 2, "e8"), hostRow(9, 2*intervalS, "a", 2, "e9"),
	}
	for _, tc := range []struct {
		name     string
		order    LogOrder
		limit    uint64
		interval int64
		want     []string
	}{
		// epoch/forward/i1000000000/l100: every entry before 1970 is kept with its copies, those after thinned.
		{"forward 1s", Forward, 100, intervalS, []string{
			"-4000000000|a|e1|3", "-3000000000|a|e2|2", "-3000000000|a|e3|2", "-2000000000|a|e4|4", "-1000000000|a|e5|2", "-1|a|e6|3",
			"0|a|e7|1", "1000000000|a|e8|1", "2000000000|a|e9|1"}},
		// epoch/backward/i1000000000/l100: e6 (1 ns before the epoch) is thinned against e7 at 0, e5 is output, then nothing is thinned.
		{"backward 1s", Backward, 100, intervalS, []string{
			"2000000000|a|e9|1", "1000000000|a|e8|1", "0|a|e7|1", "-1000000000|a|e5|2", "-2000000000|a|e4|4",
			"-3000000000|a|e2|2", "-3000000000|a|e3|2", "-4000000000|a|e1|3"}},
		// epoch/forward/i500000000/l3: the three copies of the first row are the first three entries.
		{"forward 500ms limit 3", Forward, 3, intervalS / 2, []string{"-4000000000|a|e1|3"}},
		// epoch/forward/i500000000/l5: three copies of e1, then two of e2.
		{"forward 500ms limit 5", Forward, 5, intervalS / 2, []string{"-4000000000|a|e1|3", "-3000000000|a|e2|2"}},
		// epoch/backward/i1/l5: e6 (3 copies, 1 ns before the epoch) is output after e7 at 0 and the limit cuts it to the 2 copies left.
		{"backward 1ns limit 5", Backward, 5, 1, []string{"2000000000|a|e9|1", "1000000000|a|e8|1", "0|a|e7|1", "-1|a|e6|2"}},
		// epoch/backward/i1000000001/l5: e5 and e6 are thinned against e7; e4 (4 copies) is output and cut to the 3 left.
		{"backward 1s+1ns limit 5", Backward, 5, intervalS + 1, []string{"2000000000|a|e9|1", "0|a|e7|1", "-2000000000|a|e4|3"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalRaw(t, rows, -6*intervalS, 54*intervalS, tc.order, tc.limit, tc.interval)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

// Among entries with equal timestamps of different streams the pinned engine's source merge picks
// by ascending hash of the original stream labels, so that is the entry a limit or an interval
// keeps; only the grouped result it returns is sorted by label string, and so is the answer.
// Here hash({app="api",host="c"}) < hash(host=a) < hash(host=b).
func TestEvaluateLogsLimitAndIntervalKeepTheTiedEntryOfTheLowestStreamHash(t *testing.T) {
	hash := func(host string) uint64 {
		return metricXXH64(metricStreamHashBytes(nil, model.Labels{{Name: "app", Value: "api"}, {Name: "host", Value: host}}))
	}
	if !(hash("c") < hash("a") && hash("a") < hash("b")) {
		t.Fatalf("the fixture needs hash(c) < hash(a) < hash(b): %x %x %x", hash("c"), hash("a"), hash("b"))
	}
	rows := []scan.LogRow{
		hostRow(1, 1*intervalS, "c", 2, "x"), hostRow(2, 1*intervalS, "a", 3, "x"), hostRow(3, 1*intervalS, "b", 1, "y"),
		hostRow(4, 2*intervalS, "b", 4, "z"), hostRow(5, 2*intervalS, "a", 1, "z"), hostRow(6, 2*intervalS, "c", 2, "w"),
		hostRow(7, 3*intervalS, "a", 2, "x"), hostRow(8, 3*intervalS, "b", 2, "x"), hostRow(9, 4*intervalS, "c", 3, "v"),
	}
	for _, tc := range []struct {
		name     string
		order    LogOrder
		limit    uint64
		interval int64
		want     []string
	}{
		// ties-streams/forward/i0/l1: the first entry is the one of stream c.
		{"limit 1", Forward, 1, 0, []string{"1000000000|c|x|1"}},
		// .../i0/l2: both entries of stream c.
		{"limit 2", Forward, 2, 0, []string{"1000000000|c|x|2"}},
		// .../i0/l3: stream c (2), then one of stream a; the answer is in label order.
		{"limit 3", Forward, 3, 0, []string{"1000000000|a|x|1", "1000000000|c|x|2"}},
		// .../i0/l5: c (2) then a (3).
		{"limit 5", Forward, 5, 0, []string{"1000000000|a|x|3", "1000000000|c|x|2"}},
		// .../i500000000/l100: the entry kept at each timestamp is the lowest hash's, one copy of it.
		{"interval 500ms", Forward, 100, intervalS / 2, []string{"1000000000|c|x|1", "2000000000|c|w|1", "3000000000|a|x|1", "4000000000|c|v|1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := evalRaw(t, rows, 0, 60*intervalS, tc.order, tc.limit, tc.interval)
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}
