// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// [07.03#9 / 10.16-W2] The carried-series set (what stale markers are computed
// against) survives a restart: it lives in a private state directory of the
// node, advances only after the cycle's batches have their receipts, is keyed by
// the target's identity and is bounded. docs/operations/scraping.md, "Restart",
// states the rule; these tests pin it.

// restartBody renders an OpenMetrics exposition of gauges named by "name value".
func restartBody(series ...string) string {
	var b strings.Builder
	for _, s := range series {
		name, value, _ := strings.Cut(s, " ")
		b.WriteString("# TYPE " + name + " gauge\n" + name + "{job=\"api\"} " + value + "\n")
	}
	b.WriteString("# EOF\n")
	return b.String()
}

// restartRig is one node (the real ingest of the fixture), one exporter and one
// state directory; process() starts a new "process" over them: a fresh Scraper
// over a freshly opened store, with nothing in memory.
type restartRig struct {
	t    *testing.T
	f    *scrapeFixture
	srv  *httptest.Server
	hits atomic.Int64
	mu   sync.Mutex
	body string
	code int
	log  *admitLog
	dir  string
}

func newRestartRig(t *testing.T, body string) *restartRig {
	t.Helper()
	r := &restartRig{t: t, f: newScrapeFixture(t), body: body, code: http.StatusOK, dir: filepath.Join(t.TempDir(), "scrape-state")}
	r.srv, _ = scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.hits.Add(1)
		r.mu.Lock()
		body, code := r.body, r.code
		r.mu.Unlock()
		if code != http.StatusOK {
			http.Error(w, "exporter down", code)
			return
		}
		scrapeOM(w, body)
	}))
	r.log = &admitLog{f: r.f}
	return r
}

func (r *restartRig) set(body string) { r.mu.Lock(); r.body = body; r.mu.Unlock() }
func (r *restartRig) status(code int) { r.mu.Lock(); r.code = code; r.mu.Unlock() }

type restartProc struct {
	s      *Scraper
	store  *ScrapeStateStore
	target ScrapeTarget
}

// process starts a new process. admit nil admits through the rig's real ingest.
func (r *restartRig) process(admit AdmitFunc, mutate ...func(*ScrapeTarget)) *restartProc {
	r.t.Helper()
	store, err := OpenScrapeStateStore(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	target := r.f.target(r.srv.URL)
	target.Clock = nil
	target.Stale = StalePolicy{OnDisappear: true}
	for _, m := range mutate {
		m(&target)
	}
	if admit == nil {
		admit = r.log.admit
	}
	return &restartProc{store: store, target: target, s: &Scraper{
		Target: target, State: store, Attempts: 1, Admit: admit,
		Grant: func(context.Context) (policy.SourceGrant, error) { return r.f.grant, nil },
	}}
}

// persisted reads what the process's store holds for its target.
func (r *restartRig) persisted(p *restartProc) []string {
	r.t.Helper()
	series, _, err := p.store.load(p.target.Alias, scrapeStateIdentity(r.f.org, p.target), 2*p.target.Profile.Limits.MaxSeries)
	if err != nil {
		r.t.Fatalf("reading the persisted state: %v", err)
	}
	names := scrapeSeen(r.t, series)
	sort.Strings(names)
	return names
}

func (r *restartRig) stateFile(p *restartProc) string {
	r.t.Helper()
	path, err := p.store.path(p.target.Alias)
	if err != nil {
		r.t.Fatal(err)
	}
	return path
}

func (r *restartRig) once(p *restartProc) ScrapeResult {
	r.t.Helper()
	res, err := p.s.Once(r.f.ctx)
	if err != nil {
		r.t.Fatalf("cycle: %v", err)
	}
	return res
}

func series(names ...string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = n + "{job=api}"
	}
	sort.Strings(out)
	return out
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A series that vanished while the process was down gets its stale marker on the
// FIRST cycle after the restart: exactly one marker, admitted once, never
// repeated by the cycles after it.
func TestScrapeStaleMarkersSurviveARestart(t *testing.T) {
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	before := r.process(nil)
	if res := r.once(before); res.Samples != 2 || res.StaleMarkers != 0 {
		t.Fatalf("first process cycle: %+v", res)
	}
	if got := r.persisted(before); !eqStrings(got, series("host_gone", "host_load")) {
		t.Fatalf("the state on disk before the process dies: %v", got)
	}

	// The node restarts; host_gone vanished and host_new appeared while it was down.
	r.set(restartBody("host_load 2", "host_new 5"))
	after := r.process(nil)
	res := r.once(after)
	if res.Health.Status != ScrapeOK || res.Samples != 2 {
		t.Fatalf("first cycle after the restart: %+v", res)
	}
	if res.StaleMarkers != 1 || len(r.log.staleFor("host_gone")) != 1 {
		t.Fatalf("the first cycle after the restart did not mark the vanished series: %d markers, %d admitted for host_gone", res.StaleMarkers, len(r.log.staleFor("host_gone")))
	}
	for i := range 2 {
		if res = r.once(after); res.StaleMarkers != 0 || len(r.log.staleFor("host_gone")) != 1 {
			t.Fatalf("cycle %d after the restart repeated the marker: markers=%d admitted=%d", i+2, res.StaleMarkers, len(r.log.staleFor("host_gone")))
		}
	}

	// The restarted scraper carries normally: host_new disappearing is marked once.
	r.set(restartBody("host_load 3"))
	if res = r.once(after); res.StaleMarkers != 1 || len(r.log.staleFor("host_new")) != 1 {
		t.Fatalf("marker for a series first seen after the restart: markers=%d admitted=%d", res.StaleMarkers, len(r.log.staleFor("host_new")))
	}
	if res = r.once(after); res.StaleMarkers != 0 || len(r.log.staleFor("host_new")) != 1 {
		t.Fatalf("the marker was repeated: %d", res.StaleMarkers)
	}

	// A second restart with nothing vanished marks nothing: both markers stay single.
	third := r.process(nil)
	if res = r.once(third); res.StaleMarkers != 0 || len(r.log.staleFor("host_gone")) != 1 || len(r.log.staleFor("host_new")) != 1 {
		t.Fatalf("second restart: markers=%d host_gone=%d host_new=%d", res.StaleMarkers, len(r.log.staleFor("host_gone")), len(r.log.staleFor("host_new")))
	}
	if got := r.persisted(third); !eqStrings(got, series("host_load")) {
		t.Fatalf("persisted set after the second restart: %v", got)
	}
}

// OnFailure marks the carried series too: after a restart it must see the
// restored set, so an exporter that is down on the first cycle marks everything
// the previous process had seen.
func TestScrapeOnFailureSeesTheRestoredSet(t *testing.T) {
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	withFailure := func(tg *ScrapeTarget) { tg.Stale = StalePolicy{OnDisappear: true, OnFailure: true} }
	if res := r.once(r.process(nil, withFailure)); res.Samples != 2 {
		t.Fatalf("first process cycle: %+v", res)
	}
	r.status(http.StatusInternalServerError)
	after := r.process(nil, withFailure)
	res := r.once(after)
	if res.Health.Status != ScrapeBadStatus || res.StaleMarkers != 2 {
		t.Fatalf("the failed first cycle after the restart: status %s, %d markers (want both restored series marked)", res.Health.Status, res.StaleMarkers)
	}
	for _, name := range []string{"host_load", "host_gone"} {
		if n := len(r.log.staleFor(name)); n != 1 {
			t.Errorf("%s: %d markers admitted, want 1", name, n)
		}
	}
	// the markers consumed the set: the recovery cycle marks nothing
	r.status(http.StatusOK)
	if res = r.once(after); res.StaleMarkers != 0 || res.Samples != 2 {
		t.Fatalf("recovery cycle: %+v", res)
	}
}

// The persisted state advances only after the receipts: while a cycle's batches
// are in flight the file still holds what the previous cycle committed (plus the
// series the cycle may admit, so a crash cannot skip a marker); only after every
// receipt does it become exactly the cycle's own set.
func TestScrapeStatePersistsOnlyAfterReceipts(t *testing.T) {
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	p := r.process(nil)
	r.once(p)

	r.set(restartBody("host_load 2", "host_new 5"))
	var inFlight []string
	p.s.Admit = func(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
		if inFlight == nil {
			inFlight = r.persisted(p)
		}
		return r.log.admit(ctx, g, b)
	}
	res := r.once(p)
	if res.StaleMarkers != 1 {
		t.Fatalf("cycle: %+v", res)
	}
	if want := series("host_gone", "host_load", "host_new"); !eqStrings(inFlight, want) {
		t.Fatalf("state while the batches were in flight: %v, want %v (the old set and the new one: nothing may be forgotten before the receipts)", inFlight, want)
	}
	if got, want := r.persisted(p), series("host_load", "host_new"); !eqStrings(got, want) {
		t.Fatalf("state after every receipt: %v, want %v", got, want)
	}
}

// A lost ACK or a crash between admission and the state write never loses a
// marker. The rule: before the cycle's first batch is submitted the file holds
// (previous set ∪ the cycle's set); after the last receipt it holds the cycle's
// set. A restart therefore carries a superset of what could have been admitted:
// a marker is never skipped, and a marker whose batch had in fact been admitted
// is produced again at the first cycle after the restart (a later scrape time,
// so a distinct batch identity: the same series, the same stale value).
func TestScrapeLostAckNeverLosesAStaleMarker(t *testing.T) {
	// cycle 1 sees {host_load, host_gone}; cycle 2 sees {host_load, host_new}
	// (host_gone vanished, host_new is first seen); the process dies; after the
	// restart the exporter shows {host_load} only (host_new vanished right after
	// the cycle whose state was never committed).
	cases := []struct {
		name     string
		prepare  func(r *restartRig, p *restartProc)
		wantGone int // markers for host_gone admitted over the whole run
	}{
		{"the node admitted the stale batch and its ACK was lost", func(r *restartRig, p *restartProc) {
			p.s.Admit = func(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
				receipt, err := r.log.admit(ctx, g, b)
				if err == nil && b.Records[0].Payload.Metric.SampleKind == "stale" {
					return model.Receipt{}, model.Fail(model.Unavailable) // durable at the node, never acknowledged
				}
				return receipt, err
			}
		}, 2},
		{"the node never saw the batches", func(r *restartRig, p *restartProc) {
			p.s.Admit = func(context.Context, policy.SourceGrant, model.Batch) (model.Receipt, error) {
				return model.Receipt{}, model.Fail(model.Unavailable)
			}
		}, 1},
		{"every receipt arrived and the process died before the state write", func(r *restartRig, p *restartProc) {
			p.store.beforeWrite = func(set []SeriesRef) error {
				// the write that would commit the cycle's own set
				if got := scrapeSeen(r.t, set); eqStrings(sortedCopy(got), series("host_load", "host_new")) {
					return errors.New("disk gone")
				}
				return nil
			}
		}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
			p := r.process(nil)
			r.once(p)
			r.set(restartBody("host_load 2", "host_new 5"))
			tc.prepare(r, p)
			if _, err := p.s.Once(r.f.ctx); err == nil {
				t.Fatal("the cycle reported success")
			}
			// the process dies here: nothing but the state directory survives
			r.set(restartBody("host_load 3"))
			after := r.process(nil)
			res := r.once(after)
			if res.StaleMarkers != 2 {
				t.Fatalf("first cycle after the restart: %d markers, want host_gone and host_new", res.StaleMarkers)
			}
			if n := len(r.log.staleFor("host_gone")); n != tc.wantGone {
				t.Fatalf("markers admitted for host_gone: %d, want %d (never 0, at most one duplicate)", n, tc.wantGone)
			}
			if n := len(r.log.staleFor("host_new")); n != 1 {
				t.Fatalf("markers admitted for host_new: %d, want 1 (a series first seen in the uncommitted cycle must not be forgotten)", n)
			}
			if res = r.once(after); res.StaleMarkers != 0 {
				t.Fatalf("the marker was repeated after the restart cycle: %d", res.StaleMarkers)
			}
			if got := r.persisted(after); !eqStrings(got, series("host_load")) {
				t.Fatalf("committed set: %v", got)
			}
			// a duplicate is the same series with the same stale value at a later time
			gone := r.log.staleFor("host_gone")
			for _, d := range gone[1:] {
				if d.Bits != gone[0].Bits || d.Labels != gone[0].Labels || d.At <= gone[0].At {
					t.Fatalf("the duplicate marker differs from the original: %+v vs %+v", d, gone[0])
				}
			}
		})
	}
}

// A state file that cannot be trusted is an error, never "nothing seen": that
// would hide the gap. The cycle fails closed, typed, before the exporter is
// contacted or anything is admitted, and the file is left for the operator.
func TestScrapeCorruptStateIsATypedErrorNotNothingSeen(t *testing.T) {
	corruptions := map[string]func(t *testing.T, path string, raw []byte){
		"garbage":   func(t *testing.T, path string, _ []byte) { write(t, path, []byte("\x00\xffnot json")) },
		"truncated": func(t *testing.T, path string, raw []byte) { write(t, path, raw[:len(raw)/2]) },
		"flipped series": func(t *testing.T, path string, raw []byte) {
			write(t, path, []byte(strings.Replace(string(raw), "host_gone", "host_gonf", 1)))
		},
		"another version": func(t *testing.T, path string, _ []byte) {
			// a well-formed, correctly checksummed document of a version this build does not know
			raw, err := encodeScrapeState(scrapeStateDoc{Version: 2, Alias: "host-exporter", Identity: strings.Repeat("0", 64)})
			if err != nil {
				t.Fatal(err)
			}
			write(t, path, raw)
		},
		"empty": func(t *testing.T, path string, _ []byte) { write(t, path, nil) },
	}
	for name, corrupt := range corruptions {
		t.Run(name, func(t *testing.T) {
			r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
			before := r.process(nil)
			r.once(before)
			path := r.stateFile(before)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			corrupt(t, path, raw)
			damaged, _ := os.ReadFile(path)
			if strings.Contains(name, "flipped") || strings.Contains(name, "version") {
				if string(damaged) == string(raw) {
					t.Fatal("the corruption did not change the file")
				}
			}

			r.set(restartBody("host_load 2"))
			hits, admitted := r.hits.Load(), len(r.log.recs)
			after := r.process(nil)
			res, err := after.s.Once(r.f.ctx)
			var se *ScrapeStateError
			if !errors.As(err, &se) || se.Reason != ScrapeStateCorrupt {
				t.Fatalf("a damaged state file: err=%v res=%+v, want a typed %s error", err, res.Health, ScrapeStateCorrupt)
			}
			if r.hits.Load() != hits || len(r.log.recs) != admitted {
				t.Fatalf("the exporter was contacted (%d requests) or batches admitted (%d) with untrusted state", r.hits.Load()-hits, len(r.log.recs)-admitted)
			}
			if after2, _ := os.ReadFile(path); string(after2) != string(damaged) {
				t.Fatal("the damaged file was overwritten: the operator lost the evidence")
			}
			// it stays an error cycle after cycle ...
			if _, err = after.s.Once(r.f.ctx); !errors.As(err, &se) {
				t.Fatalf("second cycle over the damaged file: %v", err)
			}
			// ... and clears as soon as the operator removed the file (a fresh target)
			if err = os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if res = r.once(after); res.Samples != 1 || res.StaleMarkers != 0 {
				t.Fatalf("cycle after the operator removed the file: %+v", res)
			}
		})
	}
}

func write(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A state file belongs to the alias it is named for; a file copied under
// another alias is corrupt, not inherited.
func TestScrapeStateOfAnotherAliasIsCorruptNotInherited(t *testing.T) {
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	a := r.process(nil)
	r.once(a)
	b := r.process(nil, func(tg *ScrapeTarget) { tg.Alias = "copied-exporter" })
	raw, err := os.ReadFile(r.stateFile(a))
	if err != nil {
		t.Fatal(err)
	}
	write(t, r.stateFile(b), raw)
	var se *ScrapeStateError
	if _, err = b.s.Once(r.f.ctx); !errors.As(err, &se) || se.Reason != ScrapeStateCorrupt {
		t.Fatalf("state copied under another alias: %v", err)
	}
}

// The state of one target is not inherited by another target, nor by the same
// alias after its configuration changed: the series belong to the old identity.
func TestScrapeStateIsNotInheritedByAnotherTarget(t *testing.T) {
	variants := map[string]func(r *restartRig) func(*ScrapeTarget){
		"another alias": func(*restartRig) func(*ScrapeTarget) {
			return func(tg *ScrapeTarget) { tg.Alias = "other-exporter" }
		},
		"another URL": func(r *restartRig) func(*ScrapeTarget) {
			other, _ := scrapeServe(r.t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				scrapeOM(w, restartBody("host_load 2"))
			}))
			return func(tg *ScrapeTarget) { tg.URL = other.URL }
		},
		"another producer": func(*restartRig) func(*ScrapeTarget) {
			return func(tg *ScrapeTarget) { tg.Profile.Producer = model.ID{0xaa, 9} }
		},
		"another stale policy": func(*restartRig) func(*ScrapeTarget) {
			return func(tg *ScrapeTarget) { tg.Stale = StalePolicy{OnDisappear: true, OnFailure: true} }
		},
	}
	for name, variant := range variants {
		t.Run(name, func(t *testing.T) {
			r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
			r.once(r.process(nil))
			r.set(restartBody("host_load 2"))
			other := r.process(nil, variant(r))
			res := r.once(other)
			if res.StaleMarkers != 0 || len(r.log.staleFor("host_gone")) != 0 {
				t.Fatalf("another target inherited the series of the first one: %d markers, %d admitted for host_gone", res.StaleMarkers, len(r.log.staleFor("host_gone")))
			}
		})
	}
	// The control: the same identity does inherit.
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	r.once(r.process(nil))
	r.set(restartBody("host_load 2"))
	if res := r.once(r.process(nil)); res.StaleMarkers != 1 {
		t.Fatalf("control: the same target did not inherit its own state (%d markers)", res.StaleMarkers)
	}
}

// Every field that makes a target another target is bound into the identity the
// state is keyed by; what only tunes the schedule or the policy revision is not.
func TestScrapeStateIdentityBindsTheTarget(t *testing.T) {
	f := newScrapeFixture(t)
	base := f.target("http://exporter.example.test/metrics")
	base.Stale = StalePolicy{OnDisappear: true}
	base.Profile.Resource.Labels = model.Labels{{Name: "zone", Value: "a"}}
	org := f.org
	want := scrapeStateIdentity(org, base)
	if scrapeStateIdentity(org, base) != want {
		t.Fatal("the identity is not deterministic")
	}
	differs := map[string]func(tg *ScrapeTarget, org *model.ID){
		"org":         func(_ *ScrapeTarget, o *model.ID) { *o = model.ID{9} },
		"alias":       func(tg *ScrapeTarget, _ *model.ID) { tg.Alias = "x" + tg.Alias },
		"url":         func(tg *ScrapeTarget, _ *model.ID) { tg.URL += "?a=1" },
		"project":     func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Project = model.ID{9} },
		"source":      func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Source = model.ID{9} },
		"producer":    func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Producer = model.ID{9} },
		"service":     func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Resource.Service = model.ID{9} },
		"environment": func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Resource.Environment = model.ID{9} },
		"build":       func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Resource.Build = model.ID{9} },
		"instance":    func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Resource.Instance = "inst-9" },
		"label value": func(tg *ScrapeTarget, _ *model.ID) {
			tg.Profile.Resource.Labels = model.Labels{{Name: "zone", Value: "b"}}
		},
		"label name": func(tg *ScrapeTarget, _ *model.ID) {
			tg.Profile.Resource.Labels = model.Labels{{Name: "zon", Value: "ea"}}
		},
		"no labels":  func(tg *ScrapeTarget, _ *model.ID) { tg.Profile.Resource.Labels = nil },
		"on failure": func(tg *ScrapeTarget, _ *model.ID) { tg.Stale.OnFailure = true },
		"on disappear": func(tg *ScrapeTarget, _ *model.ID) {
			tg.Stale.OnDisappear = false
			tg.Stale.OnFailure = true
		},
	}
	seen := map[[32]byte]string{want: "base"}
	for name, mutate := range differs {
		tg, o := base, org
		tg.Profile.Resource.Labels = append(model.Labels(nil), base.Profile.Resource.Labels...)
		mutate(&tg, &o)
		got := scrapeStateIdentity(o, tg)
		if prev, dup := seen[got]; dup {
			t.Errorf("changing %s gives the identity of %s: its state would be inherited", name, prev)
		}
		seen[got] = name
	}
	same := map[string]func(tg *ScrapeTarget){
		"policy revision": func(tg *ScrapeTarget) { tg.Profile.PolicyRevision = 7 },
		"interval":        func(tg *ScrapeTarget) { tg.Interval *= 2 },
		"timeout":         func(tg *ScrapeTarget) { tg.Timeout /= 2 },
		"max bytes":       func(tg *ScrapeTarget) { tg.MaxBytes /= 2 },
	}
	for name, mutate := range same {
		tg := base
		mutate(&tg)
		if scrapeStateIdentity(org, tg) != want {
			t.Errorf("changing %s changes the identity: a schedule or policy-revision change must keep the carried series", name)
		}
	}
}

// The carried set is bounded by the target's own series limit: at most twice
// MaxSeries (the previous committed set plus one cycle's own set). A set that
// would exceed it is refused as typed health, before anything is admitted;
// the file never grows past the bound.
func TestScrapeStateIsBounded(t *testing.T) {
	r := newRestartRig(t, restartBody("s_a 1", "s_b 1", "s_c 1"))
	small := func(tg *ScrapeTarget) { tg.Profile.Limits.MaxSeries = 3 } // bound: 6 carried series
	fail := atomic.Bool{}
	p := r.process(func(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
		if fail.Load() {
			return model.Receipt{}, model.Fail(model.Unavailable)
		}
		return r.log.admit(ctx, g, b)
	}, small)
	r.once(p)

	// two refused cycles with other series: 3 + 3 carried, the bound
	fail.Store(true)
	r.set(restartBody("s_d 1", "s_e 1", "s_f 1"))
	if _, err := p.s.Once(r.f.ctx); err == nil {
		t.Fatal("a refused cycle reported success")
	}
	if got := r.persisted(p); len(got) != 6 {
		t.Fatalf("persisted after the refused cycle: %v", got)
	}

	// a third distinct set would carry 9 series: refused, typed, nothing admitted
	fail.Store(false)
	r.set(restartBody("s_g 1", "s_h 1", "s_i 1"))
	admitted := len(r.log.recs)
	_, err := p.s.Once(r.f.ctx)
	var se *ScrapeStateError
	if !errors.As(err, &se) || se.Reason != ScrapeStateTooLarge {
		t.Fatalf("a cycle over the bound: %v, want a typed %s error", err, ScrapeStateTooLarge)
	}
	if len(r.log.recs) != admitted {
		t.Fatalf("a cycle over the bound admitted %d records", len(r.log.recs)-admitted)
	}
	if got := r.persisted(p); len(got) != 6 {
		t.Fatalf("the state grew past the bound: %d series", len(got))
	}

	// the exporter returns to a set the carried one covers: the node recovers by itself
	r.set(restartBody("s_a 1", "s_d 1", "s_e 1"))
	if res := r.once(p); res.Samples != 3 {
		t.Fatalf("recovery: %+v", res)
	}
	if got := r.persisted(p); len(got) != 3 {
		t.Fatalf("committed set after the recovery: %v", got)
	}

	// a file over the bound (written by a node that allowed more) is refused at load, typed
	big := r.process(nil, func(tg *ScrapeTarget) { tg.Profile.Limits.MaxSeries = 4 })
	var many []SeriesRef
	for i := range 9 {
		many = append(many, SeriesRef{Name: "m_" + string(rune('a'+i))})
	}
	if err := big.store.save(big.target.Alias, scrapeStateIdentity(r.f.org, big.target), many, 100); err != nil {
		t.Fatal(err)
	}
	if _, err := big.s.Once(r.f.ctx); !errors.As(err, &se) || se.Reason != ScrapeStateTooLarge {
		t.Fatalf("a state file over the bound: %v, want %s", err, ScrapeStateTooLarge)
	}
}

// Writes are rare: the file is rewritten only when the carried set changes, not
// every interval.
func TestScrapeStateIsRewrittenOnlyWhenTheSetChanges(t *testing.T) {
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	p := r.process(nil)
	for range 4 {
		r.once(p)
	}
	if p.store.writes != 1 {
		t.Fatalf("%d writes for four cycles over an unchanged series set, want 1", p.store.writes)
	}
	r.set(restartBody("host_load 1"))
	r.once(p) // host_gone vanishes: the file already held previous ∪ own, so only the commit writes
	if p.store.writes != 2 {
		t.Fatalf("%d writes after the set changed, want 2", p.store.writes)
	}
	r.once(p)
	if p.store.writes != 2 {
		t.Fatalf("%d writes after a further unchanged cycle, want 2", p.store.writes)
	}
}

// A target that produces no stale markers has nothing to carry: nothing is written.
func TestScrapeStateIsNotWrittenWithoutAStalePolicy(t *testing.T) {
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	p := r.process(nil, func(tg *ScrapeTarget) { tg.Stale = StalePolicy{} })
	r.once(p)
	r.set(restartBody("host_load 2"))
	r.once(p)
	if _, err := os.Stat(r.stateFile(p)); !errors.Is(err, os.ErrNotExist) || p.store.writes != 0 {
		t.Fatalf("a target without a stale policy wrote state: %v, %d writes", err, p.store.writes)
	}
}

// The state directory is a private subdirectory: 0700, files 0600, no temporary left behind.
func TestScrapeStateFilesArePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	r := newRestartRig(t, restartBody("host_load 1", "host_gone 7"))
	p := r.process(nil)
	r.once(p)
	r.set(restartBody("host_load 2"))
	r.once(p)
	if info, err := os.Stat(r.dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("state directory: %v %v", info, err)
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("state directory entries: %v %v", entries, err)
	}
	if info, _ := entries[0].Info(); info.Mode().Perm() != 0o600 || entries[0].Name() != "host-exporter.scrape-state.json" {
		t.Fatalf("state file %s mode %v", entries[0].Name(), info.Mode())
	}
	if _, err := OpenScrapeStateStore("relative/state"); err == nil {
		t.Fatal("a relative state directory was accepted")
	}
}
