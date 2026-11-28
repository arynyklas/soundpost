// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package qual

import (
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/nativeperf"
)

// A runtime that served `requests` loopback HTTP requests, each held server-side for 50 ms, inside a 3.2 s window: its
// event-loop thread (TID 4242) was idle for about requests*50 ms of it, and the round trips it observed add up to a
// little more than that (the loop also does work). These are hand-made intervals, not scheduler evidence.
func waitTruth(requests int) RuntimeWaitTruth {
	return RuntimeWaitTruth{
		Kind: WaitKindHTTP,
		TID:  4242, StartNs: 10_000_000_000, EndNs: 13_200_000_000,
		Requests: requests, ServerDelayNs: 50_000_000, WaitTotalNs: uint64(requests) * 56_000_000,
	}
}

func loopIntervals(kind nativeperf.IntervalKind, tid uint32, requests int, each uint64) []nativeperf.Interval {
	var out []nativeperf.Interval
	start := uint64(10_000_000_000)
	for range requests {
		out = append(out, nativeperf.Interval{Kind: kind, Task: nativeperf.TaskKey{TID: tid}, Start: model.MonoNano(start), End: model.MonoNano(start + each)})
		start += 60_000_000
	}
	return out
}

func TestCompareRuntimeWaitAcceptsTheBlockedTimeTheRuntimeRecorded(t *testing.T) {
	for _, each := range []uint64{50_000_000, 52_000_000, 56_000_000} {
		got := CompareRuntimeWait(waitTruth(53), loopIntervals(nativeperf.IntervalBlocked, 4242, 53, each))
		if got.Verdict != VerdictPass {
			t.Errorf("blocked %d ns per request: %s (%s)", each, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitRejectsCollectorsThatMisreportTheWait(t *testing.T) {
	truth := waitTruth(53)
	for name, native := range map[string][]nativeperf.Interval{
		"every wait reported as run-queue delay (blocked never reported)": loopIntervals(nativeperf.IntervalRunnable, 4242, 53, 50_000_000),
		"waits cut to 30%":  loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 15_000_000),
		"waits inflated 2x": loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 110_000_000),
	} {
		got := CompareRuntimeWait(truth, native)
		if got.Verdict != VerdictFail {
			t.Errorf("%s: %s (%s), want fail", name, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitIsUnknownWithoutEvidence(t *testing.T) {
	truth := waitTruth(53)
	good := loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 52_000_000)
	for name, c := range map[string]struct {
		truth  RuntimeWaitTruth
		native []nativeperf.Interval
	}{
		"no interval of the loop thread at all":             {truth, loopIntervals(nativeperf.IntervalBlocked, 9999, 53, 52_000_000)},
		"too few requests":                                  {waitTruth(5), loopIntervals(nativeperf.IntervalBlocked, 4242, 5, 52_000_000)},
		"no server delay recorded":                          {RuntimeWaitTruth{TID: 4242, StartNs: truth.StartNs, EndNs: truth.EndNs, Requests: 53, WaitTotalNs: truth.WaitTotalNs}, good},
		"empty window":                                      {RuntimeWaitTruth{TID: 4242, Requests: 53, ServerDelayNs: 50_000_000, WaitTotalNs: truth.WaitTotalNs}, good},
		"an unknown split inside the window":                {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Task: nativeperf.TaskKey{TID: 4242}, Start: 10_100_000_000, End: 10_200_000_000})},
		"a censored interval inside the window":             {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalCensored, Task: nativeperf.TaskKey{TID: 4242}, Start: 12_000_000_000, End: 12_500_000_000})},
		"a correction of the loop thread inside the window": {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Task: nativeperf.TaskKey{TID: 4242}, Start: 11_000_000_000, End: 11_100_000_000})},
		"a domain-wide correction inside the window":        {truth, append(append([]nativeperf.Interval(nil), good...), nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Start: 11_000_000_000, End: 11_100_000_000})},
	} {
		got := CompareRuntimeWait(c.truth, c.native)
		if got.Verdict != VerdictUnknown {
			t.Errorf("%s: %s (%s), want unknown", name, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitIgnoresOtherThreadsAndCorrectionsAndTimeOutsideTheWindow(t *testing.T) {
	truth := waitTruth(53)
	native := loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 52_000_000)
	// a helper thread of the runtime that slept the whole window must not add to the loop thread's wait
	native = append(native, nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4243}, Start: 10_000_000_000, End: 13_200_000_000})
	// blocked time before and after the window (startup, shutdown) is not part of the measured phase
	native = append(native, nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4242}, Start: 5_000_000_000, End: 9_900_000_000},
		nativeperf.Interval{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4242}, Start: 13_300_000_000, End: 19_000_000_000})
	// a coverage correction outside the window, or of another thread, is not this window's evidence
	native = append(native,
		nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Task: nativeperf.TaskKey{TID: 4242}, Start: 5_000_000_000, End: 9_000_000_000},
		nativeperf.Interval{Kind: nativeperf.IntervalUnknown, Correction: true, Task: nativeperf.TaskKey{TID: 4243}, Start: 10_000_000_000, End: 13_200_000_000})
	got := CompareRuntimeWait(truth, native)
	if got.Verdict != VerdictPass {
		t.Fatalf("%s (%s)", got.Verdict, got.Reason)
	}
	if got.NativeNs != 53*52_000_000 {
		t.Errorf("native blocked %d ns, want the loop thread's own %d ns inside the window", got.NativeNs, 53*52_000_000)
	}
}

func TestCompareRuntimeWaitBoundaryIsTheApprovedTolerance(t *testing.T) {
	truth := waitTruth(53) // lower bound 53*50 ms*0.75 = 1.9875 s, upper bound 53*56 ms*1.25 = 3.71 s
	lower := uint64(float64(53*50_000_000) * (1 - BlockedTolerance))
	upper := uint64(float64(truth.WaitTotalNs) * (1 + BlockedTolerance))
	one := func(total uint64) []nativeperf.Interval {
		return []nativeperf.Interval{{Kind: nativeperf.IntervalBlocked, Task: nativeperf.TaskKey{TID: 4242}, Start: 10_000_000_000, End: model.MonoNano(10_000_000_000 + total)}}
	}
	for _, c := range []struct {
		ns   uint64
		want string
	}{{lower + 1_000, VerdictPass}, {lower - 1_000_000, VerdictFail}, {upper - 1_000, VerdictPass}, {upper + 1_000_000, VerdictFail}} {
		wide := truth
		wide.EndNs = 20_000_000_000 // keep the whole interval inside the window so only the totals decide
		if got := CompareRuntimeWait(wide, one(c.ns)); got.Verdict != c.want {
			t.Errorf("%d ns: %s (%s), want %s", c.ns, got.Verdict, got.Reason, c.want)
		}
	}
}

// The fixtures announce the start of their wait phase on stdout ("wait_begin <ns>", the same monotonic clock as the
// scheduler events) so the harness can release the loop thread's intervals of the CPU phase at the source instead of
// returning them to its consumer.
func TestParseWaitBegin(t *testing.T) {
	for name, tc := range map[string]struct {
		out  string
		want uint64
		ok   bool
	}{
		"announced":       {"wait_begin 10000000000\n", 10_000_000_000, true},
		"among lines":     {"noise\nwait_begin 42\ndone\n", 42, true},
		"before the line": {"", 0, false},
		"partial line":    {"wait_begin 4", 0, false},
		"not a number":    {"wait_begin x\n", 0, false},
		"zero":            {"wait_begin 0\n", 0, false},
	} {
		if got, ok := ParseWaitBegin(tc.out); got != tc.want || ok != tc.ok {
			t.Errorf("%s: %d %v", name, got, ok)
		}
	}
}

// KeepWaitWindow is the interval filter of a runtime column: corrections always, the loop thread's intervals only from
// the announced wait phase on, nothing before the announcement.
func TestKeepWaitWindowDropsTheCPUPhaseAtTheSource(t *testing.T) {
	out := ""
	keep := KeepWaitWindow(4242, func() string { return out })
	iv := func(tid uint32, end int64, corr bool) nativeperf.Interval {
		return nativeperf.Interval{Task: nativeperf.TaskKey{TID: tid}, Start: model.MonoNano(end - 10), End: model.MonoNano(end), Correction: corr}
	}
	if keep(iv(4242, 5_000, false)) {
		t.Fatal("an interval before the wait phase was announced was kept")
	}
	if !keep(iv(4242, 5_000, true)) {
		t.Fatal("a coverage correction must always be kept")
	}
	out = "wait_begin 10000\n"
	for name, tc := range map[string]struct {
		iv   nativeperf.Interval
		want bool
	}{
		"loop thread inside the window":  {iv(4242, 20_000, false), true},
		"loop thread spanning the start": {iv(4242, 10_005, false), true},
		"loop thread before the window":  {iv(4242, 9_999, false), false},
		"other thread inside the window": {iv(7, 20_000, false), false},
		"correction before the window":   {iv(0, 1, true), true},
	} {
		if keep(tc.iv) != tc.want {
			t.Errorf("%s: want %v", name, tc.want)
		}
	}
}

// A runtime that ran `requests` simple queries of `select pg_sleep(0.2)` against a real PostgreSQL server, one after
// the other on one connection, inside a 3 s window: its event-loop thread (TID 4242) sat in a socket read for about
// requests*200 ms of it. The server measured its own hold of every statement (clock_timestamp() - statement_timestamp()
// after the sleep, in the same statement), and the client saw each round trip a little longer than that.
func dbTruth(requests int) RuntimeWaitTruth {
	return RuntimeWaitTruth{
		Kind: WaitKindDatabase,
		TID:  4242, StartNs: 10_000_000_000, EndNs: 13_000_000_000,
		Requests: requests, ServerDelayNs: 200_000_000,
		ServerReportedNs: uint64(requests) * 200_400_000, WaitTotalNs: uint64(requests) * 203_000_000,
	}
}

// dbIntervals are the loop thread's intervals of one query each, `each` ns long, one every 210 ms.
func dbIntervals(kind nativeperf.IntervalKind, tid uint32, requests int, each uint64) []nativeperf.Interval {
	var out []nativeperf.Interval
	start := uint64(10_000_000_000)
	for range requests {
		out = append(out, nativeperf.Interval{Kind: kind, Task: nativeperf.TaskKey{TID: tid}, Start: model.MonoNano(start), End: model.MonoNano(start + each)})
		start += 210_000_000
	}
	return out
}

func TestCompareRuntimeWaitAcceptsTheBlockedTimeOfADatabaseWait(t *testing.T) {
	for _, each := range []uint64{200_400_000, 202_000_000, 205_000_000} {
		got := CompareRuntimeWait(dbTruth(12), dbIntervals(nativeperf.IntervalBlocked, 4242, 12, each))
		if got.Verdict != VerdictPass {
			t.Errorf("blocked %d ns per query: %s (%s)", each, got.Verdict, got.Reason)
		}
	}
}

func TestCompareRuntimeWaitRejectsCollectorsThatMisreportADatabaseWait(t *testing.T) {
	truth := dbTruth(12)
	for name, native := range map[string][]nativeperf.Interval{
		"every query wait reported as run-queue delay": dbIntervals(nativeperf.IntervalRunnable, 4242, 12, 200_400_000),
		"query waits cut to 30%":                       dbIntervals(nativeperf.IntervalBlocked, 4242, 12, 60_000_000),
		"query waits inflated 2x":                      dbIntervals(nativeperf.IntervalBlocked, 4242, 12, 420_000_000),
	} {
		if got := CompareRuntimeWait(truth, native); got.Verdict != VerdictFail {
			t.Errorf("%s: %s (%s), want fail", name, got.Verdict, got.Reason)
		}
	}
}

// The lower bound of a database wait is what the database itself reported holding each statement (it is measured by
// the server, not assumed from the sleep that was asked for): a server that held its statements 230 ms each puts the
// loop's idle time at 230 ms each, so 170 ms each is below the tolerance although it is above the 200 ms that were asked.
func TestCompareRuntimeWaitDatabaseLowerBoundIsWhatTheServerReported(t *testing.T) {
	truth := dbTruth(12)
	truth.ServerReportedNs, truth.WaitTotalNs = 12*230_000_000, 12*233_000_000
	truth.EndNs = 14_000_000_000
	if got := CompareRuntimeWait(truth, dbIntervals(nativeperf.IntervalBlocked, 4242, 12, 170_000_000)); got.Verdict != VerdictFail {
		t.Errorf("170 ms blocked per statement the server held 230 ms: %s (%s), want fail", got.Verdict, got.Reason)
	}
	if got := CompareRuntimeWait(truth, dbIntervals(nativeperf.IntervalBlocked, 4242, 12, 230_000_000)); got.Verdict != VerdictPass {
		t.Errorf("230 ms blocked per statement the server held 230 ms: %s (%s), want pass", got.Verdict, got.Reason)
	}
}

func TestCompareRuntimeWaitDatabaseIsUnknownWithoutTheServersAccount(t *testing.T) {
	good := dbIntervals(nativeperf.IntervalBlocked, 4242, 12, 202_000_000)
	for name, mutate := range map[string]func(*RuntimeWaitTruth){
		"fewer queries than a database wait needs":   func(w *RuntimeWaitTruth) { w.Requests = MinDatabaseWaitRequests - 1 },
		"the server reported no hold at all":         func(w *RuntimeWaitTruth) { w.ServerReportedNs = 0 },
		"the server held each statement for 40 ms":   func(w *RuntimeWaitTruth) { w.ServerReportedNs = uint64(w.Requests) * 40_000_000 },
		"round trips shorter than the server's hold": func(w *RuntimeWaitTruth) { w.WaitTotalNs = w.ServerReportedNs - 1 },
		"a database wait with no kind recorded":      func(w *RuntimeWaitTruth) { w.Kind = "" },
	} {
		truth := dbTruth(12)
		mutate(&truth)
		if got := CompareRuntimeWait(truth, good); got.Verdict != VerdictUnknown {
			t.Errorf("%s: %s (%s), want unknown", name, got.Verdict, got.Reason)
		}
	}
}

// A wait of a kind nothing knows is not judged by the rules of another one, however many requests it claims.
func TestCompareRuntimeWaitIsUnknownForAnUnknownKind(t *testing.T) {
	good := loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 52_000_000)
	for _, kind := range []string{"", "file_read", "Loopback_HTTP"} {
		truth := waitTruth(53)
		truth.Kind = kind
		if got := CompareRuntimeWait(truth, good); got.Verdict != VerdictUnknown {
			t.Errorf("kind %q: %s (%s), want unknown", kind, got.Verdict, got.Reason)
		}
	}
}

// A database query holds the loop for 200 ms, so a dozen of them are as much evidence as the 20 loopback requests of
// 50 ms a loopback HTTP wait needs: the minimum is per kind.
func TestCompareRuntimeWaitMinimumRequestsIsPerKind(t *testing.T) {
	http := waitTruth(12)
	if got := CompareRuntimeWait(http, loopIntervals(nativeperf.IntervalBlocked, 4242, 12, 52_000_000)); got.Verdict != VerdictUnknown {
		t.Errorf("12 loopback HTTP requests: %s (%s), want unknown", got.Verdict, got.Reason)
	}
	if got := CompareRuntimeWait(dbTruth(12), dbIntervals(nativeperf.IntervalBlocked, 4242, 12, 202_000_000)); got.Verdict != VerdictPass {
		t.Errorf("12 database queries: %s (%s), want pass", got.Verdict, got.Reason)
	}
}

// The server's own account is meaningless for a loopback HTTP wait (nothing independent measured it) and must not be
// accepted in its place: a request-count and tolerance bound decide, as before.
func TestCompareRuntimeWaitHTTPIgnoresAServerAccount(t *testing.T) {
	truth := waitTruth(53)
	truth.ServerReportedNs = 53 * 500_000_000 // would put the lower bound far above what the loop was idle for
	if got := CompareRuntimeWait(truth, loopIntervals(nativeperf.IntervalBlocked, 4242, 53, 52_000_000)); got.Verdict != VerdictPass {
		t.Errorf("%s (%s), want pass", got.Verdict, got.Reason)
	}
}
