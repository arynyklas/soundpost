// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/replica"
)

// startupReopens is how many times each state is closed and reopened; every reopen
// is timed. A reopen elects the single voter again, which appends a few journal
// entries per group (the suffix), negligible next to N.
const startupReopens = 5

// metricRetention gives every batch a metric retention deadline far enough away
// that nothing the benchmark writes is ever retention-expired.
var metricRetention = []model.SignalDeadline{{Kind: model.Metric, RetainUntil: model.UnixNano(1 << 62)}}

// startupSizes are the committed-batch counts measured by BenchmarkEngineStartup.
// SOUNDPOST_STARTUP_BENCH_N (comma separated) overrides them.
func startupSizes(b *testing.B) []int {
	raw := os.Getenv("SOUNDPOST_STARTUP_BENCH_N")
	if raw == "" {
		return []int{100, 500, 1000, 2500, 5000}
	}
	var out []int
	for _, field := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || n <= 0 {
			b.Fatalf("SOUNDPOST_STARTUP_BENCH_N: bad size %q", field)
		}
		out = append(out, n)
	}
	return out
}

// runAsTest runs body with a real *testing.T. The shared fixtures (typedFixture,
// newEraseEnv, openTestEngine) take *testing.T and their data directories and
// cleanups end with that T, so setup and the timed reopens both run inside it.
func runAsTest(b *testing.B, body func(t *testing.T)) {
	b.Helper()
	ran := testing.RunTests(func(string, string) (bool, error) { return true, nil }, []testing.InternalTest{{Name: "StartupSetup", F: body}})
	if !ran {
		b.Fatal("startup measurement failed")
	}
}

func treeBytes(root string, accept func(rel string) bool) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if rel, rerr := filepath.Rel(root, path); rerr == nil && accept(filepath.ToSlash(rel)) {
			if info, ierr := d.Info(); ierr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// startupSample is one timed reopen: Open, EnableReplication (opens the 64 Raft
// groups, replays their journals and restores snapshots), then registering and
// campaigning every group.
type startupSample struct{ open, enable, campaign time.Duration }

func (s startupSample) total() time.Duration { return s.open + s.enable + s.campaign }

func medianOf(samples []startupSample, pick func(startupSample) time.Duration) time.Duration {
	values := make([]time.Duration, len(samples))
	for i, s := range samples {
		values[i] = pick(s)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[len(values)/2]
}

func millis(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// timedReopen reopens x.dir exactly as openTestEngine does, timing each step, then
// checks that the reopened engine holds want commands and closes it again. It
// returns the sample and the number of Raft journal entries held in memory.
func timedReopen(b *testing.B, t *testing.T, x *eraseEnv, want uint64) (startupSample, uint64) {
	t.Helper()
	b.StartTimer()
	t0 := time.Now()
	engine, err := Open(x.dir, x.a)
	if err != nil {
		b.StopTimer()
		t.Fatal(err)
	}
	t1 := time.Now()
	transport := replica.NewLoopback()
	groups, err := engine.EnableReplication(replica.Config{ID: 1, Directory: filepath.Join(x.dir, "raft"), Transport: transport, Members: replica.Members{Revision: 1, Nodes: []replica.Member{{ID: 1, Address: "https://single.invalid", NodeIdentity: "single", FailureDomain: "local-disk"}}}}, nil, x.store)
	if err != nil {
		b.StopTimer()
		engine.Close()
		transport.Close()
		t.Fatal(err)
	}
	t2 := time.Now()
	for _, group := range groups {
		if err = transport.Register(group); err == nil {
			err = group.Campaign()
		}
		if err != nil {
			b.StopTimer()
			engine.Close()
			transport.Close()
			t.Fatal(err)
		}
	}
	t3 := time.Now()
	b.StopTimer()

	var total, kept uint64
	for slot := range uint16(64) {
		total += engine.indexes[slot]
		first, last := groups[slot].JournalRange()
		kept += last - first + 1
	}
	if total != want {
		t.Fatalf("reopened engine holds %d commands, wrote %d", total, want)
	}
	if err = engine.Close(); err != nil {
		t.Fatal(err)
	}
	transport.Close()
	return startupSample{open: t1.Sub(t0), enable: t2.Sub(t1), campaign: t3.Sub(t2)}, kept
}

// BenchmarkEngineStartup times how long a single-voter replicated engine takes to
// reopen (Open, EnableReplication, then registering and campaigning its 64 groups)
// when its data holds N committed batches, in three states of the same data:
//
//	full    Raft journals untouched
//	trunc   after Engine.CreateSnapshots + Engine.CompactJournals, so every journal
//	        begins at its snapshot
//	flush   the same after Engine.Flush, so the data also sits in cold segment files
//	        that Open must hash
//
// The N batches are built once through the real Append path (this setup is not
// timed and dominates the run: the control-store fixture grows quadratically with
// N). Each state is then reopened startupReopens times. One output line per N
// reports, for each state, the median and fastest total reopen, the median of each
// step, and the size of the journals and snapshots that were reopened. Run with
// -benchtime 1x; ns/op is the sum of every timed reopen.
func BenchmarkEngineStartup(b *testing.B) {
	for _, n := range startupSizes(b) {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			type result struct {
				name                 string
				samples              []startupSample
				kept                 uint64
				journalMB, snapshotM float64
			}
			var results []result
			var setup time.Duration
			var engineMB float64
			for range b.N {
				b.StopTimer()
				results = nil
				runAsTest(b, func(t *testing.T) {
					began := time.Now()
					x := newEraseEnv(t)
					for i := range n {
						// One series with a distinct timestamp per batch (an equal series
						// and time is a duplicate the engine does not store); a new series
						// per batch would exhaust the fixture's 1000-series quota.
						x.appendRecords(model.NewID(), metricRetention, x.metric("startup_series", model.UnixNano(50+i)))
					}
					if err := x.e.Close(); err != nil {
						t.Fatal(err)
					}
					setup += time.Since(began)

					for _, state := range []struct {
						name    string
						prepare func(*Engine) error
					}{
						{"full", nil},
						{"trunc", func(e *Engine) error {
							if _, err := e.CreateSnapshots(context.Background()); err != nil {
								return err
							}
							return e.CompactJournals(context.Background())
						}},
						{"flush", func(e *Engine) error { return e.Flush(context.Background()) }},
					} {
						if state.prepare != nil {
							e, err := openTestEngine(t, x.dir, x.a, x.store)
							if err == nil {
								err = state.prepare(e)
							}
							if err != nil {
								t.Fatalf("%s: %v", state.name, err)
							}
							if err = e.Close(); err != nil {
								t.Fatal(err)
							}
						}
						r := result{name: state.name}
						for range startupReopens {
							sample, kept := timedReopen(b, t, x, uint64(n))
							r.samples = append(r.samples, sample)
							r.kept = kept
						}
						r.journalMB = float64(treeBytes(filepath.Join(x.dir, "raft"), func(rel string) bool { return strings.HasSuffix(rel, "ready.wal") })) / 1e6
						r.snapshotM = float64(treeBytes(filepath.Join(x.dir, "raft"), func(rel string) bool { return strings.Contains(rel, "/snapshots/") })) / 1e6
						results = append(results, r)
					}
					engineMB = float64(treeBytes(x.dir, func(rel string) bool { return !strings.HasPrefix(rel, "raft/") })) / 1e6
				})
			}
			b.ReportMetric(float64(setup)/float64(b.N)/float64(time.Millisecond), "setup-ms")
			b.ReportMetric(float64(n), "commands")
			b.ReportMetric(engineMB, "engine-MB")
			for _, r := range results {
				fastest := r.samples[0].total()
				for _, s := range r.samples {
					fastest = min(fastest, s.total())
				}
				b.ReportMetric(millis(medianOf(r.samples, startupSample.total)), r.name+"-reopen-ms")
				b.ReportMetric(millis(fastest), r.name+"-fastest-ms")
				b.ReportMetric(millis(medianOf(r.samples, func(s startupSample) time.Duration { return s.open })), r.name+"-open-ms")
				b.ReportMetric(millis(medianOf(r.samples, func(s startupSample) time.Duration { return s.enable })), r.name+"-enable-ms")
				b.ReportMetric(millis(medianOf(r.samples, func(s startupSample) time.Duration { return s.campaign })), r.name+"-campaign-ms")
				b.ReportMetric(float64(r.kept), r.name+"-journal-entries")
				b.ReportMetric(r.journalMB, r.name+"-journal-MB")
				b.ReportMetric(r.snapshotM, r.name+"-snapshot-MB")
			}
		})
	}
}
