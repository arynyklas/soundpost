// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// admitLog forwards to the REAL ingest admission of the node and remembers what
// was durably admitted; fail makes Admit refuse before reaching the node.
type admitLog struct {
	f    *scrapeFixture
	mu   sync.Mutex
	fail atomic.Bool
	recs []scrapeRec
}

func (a *admitLog) admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error) {
	if a.fail.Load() {
		return model.Receipt{}, model.Fail(model.Unavailable)
	}
	r, err := a.f.app.Ingest.Admit(ctx, g, b)
	if err != nil {
		return r, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, rec := range scrapeFlatten(a.f.t, []model.Batch{b}) {
		a.recs = append(a.recs, rec)
	}
	return r, nil
}

func (a *admitLog) staleFor(name string) []scrapeRec {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []scrapeRec
	for _, r := range a.recs {
		if r.Kind == "stale" && r.Name == name {
			out = append(out, r)
		}
	}
	return out
}

func (a *admitLog) samplesFor(name string) []scrapeRec {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []scrapeRec
	for _, r := range a.recs {
		if r.Kind != "stale" && r.Name == name {
			out = append(out, r)
		}
	}
	return out
}

// The series a cycle carries (what the next stale markers are computed against)
// advances only after every batch of the cycle has its receipt.
func TestScrapeSchedulerCarriesSeriesOnlyAfterReceipts(t *testing.T) {
	f := newScrapeFixture(t)
	var mu sync.Mutex
	body := "# TYPE host_load gauge\nhost_load{job=\"api\"} 1\n# TYPE host_gone gauge\nhost_gone{job=\"api\"} 7\n# EOF\n"
	srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		scrapeOM(w, body)
	}))
	setBody := func(b string) { mu.Lock(); body = b; mu.Unlock() }
	log := &admitLog{f: f}
	target := f.target(srv.URL)
	target.Clock = nil
	target.Stale = StalePolicy{OnDisappear: true}
	s := &Scraper{Target: target, Grant: func(context.Context) (policy.SourceGrant, error) { return f.grant, nil }, Admit: log.admit, Attempts: 1}

	res, err := s.Once(f.ctx)
	if err != nil || res.Health.Status != ScrapeOK || res.Samples != 2 || res.StaleMarkers != 0 {
		t.Fatalf("cycle 1: %+v %v", res, err)
	}
	if got := scrapeSeen(t, s.Last().Seen); len(got) != 2 {
		t.Fatalf("seen after cycle 1: %v", got)
	}

	// host_gone disappears while the node refuses the batches: the cycle fails
	// and the scraper still remembers host_gone
	setBody("# TYPE host_load gauge\nhost_load{job=\"api\"} 2\n# EOF\n")
	log.fail.Store(true)
	res, err = s.Once(f.ctx)
	if err == nil {
		t.Fatal("a cycle whose batches were refused reported success")
	}
	if res.StaleMarkers != 1 || s.AdmitFailures() != 1 || len(log.staleFor("host_gone")) != 0 {
		t.Fatalf("cycle 2: markers %d failures %d admitted-stale %d", res.StaleMarkers, s.AdmitFailures(), len(log.staleFor("host_gone")))
	}

	// the node is back: the marker is produced again and admitted exactly once
	log.fail.Store(false)
	res, err = s.Once(f.ctx)
	if err != nil || res.StaleMarkers != 1 {
		t.Fatalf("cycle 3: %+v %v", res, err)
	}
	if got := log.staleFor("host_gone"); len(got) != 1 {
		t.Fatalf("stale markers admitted for host_gone: %d, want exactly 1", len(got))
	}
	if got := scrapeSeen(t, s.Last().Seen); len(got) != 1 {
		t.Fatalf("seen after cycle 3: %v", got)
	}
	// and then it is forgotten: no marker is repeated
	res, err = s.Once(f.ctx)
	if err != nil || res.StaleMarkers != 0 || len(log.staleFor("host_gone")) != 1 {
		t.Fatalf("cycle 4: err=%v markers=%d stale-admitted=%d health=%+v", err, res.StaleMarkers, len(log.staleFor("host_gone")), res.Health)
	}
	if n := len(log.samplesFor("host_load")); n != 3 {
		t.Fatalf("host_load samples admitted %d, want 3 (cycles 1, 3 and 4; cycle 2 was refused)", n)
	}
}

func TestScrapeSchedulerRunsOnTheIntervalAndStopsOnCancel(t *testing.T) {
	f := newScrapeFixture(t)
	var requests atomic.Int64
	srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := requests.Add(1)
		scrapeOM(w, fmt.Sprintf("# TYPE host_requests counter\nhost_requests_total{job=\"api\"} %d\n# EOF\n", n))
	}))
	log := &admitLog{f: f}
	target := f.target(srv.URL)
	target.Clock = nil
	target.Interval = time.Second
	s := &Scraper{Target: target, Grant: func(context.Context) (policy.SourceGrant, error) { return f.grant, nil }, Admit: log.admit}
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	var cycles atomic.Int64
	go func() {
		s.Run(ctx, func(res ScrapeResult, err error) {
			if err != nil || res.Health.Status != ScrapeOK {
				t.Errorf("cycle failed: %+v %v", res.Health, err)
			}
			cycles.Add(1)
		})
		close(done)
	}()
	time.Sleep(2300 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
	if n := cycles.Load(); n < 3 || n > 4 {
		t.Fatalf("cycles %d in 2.3s at a 1s interval, want 3 (at 0, 1 and 2s)", n)
	}
	got := log.samplesFor("host_requests_total")
	if int64(len(got)) != cycles.Load() {
		t.Fatalf("admitted %d samples for %d cycles", len(got), cycles.Load())
	}
	for i, r := range got {
		if r.Bits != scrapeFloat(float64(i+1)) {
			t.Fatalf("sample %d is %#x: the exporter counter was not carried exactly", i, r.Bits)
		}
	}
}

func TestScraperWiringIsRequired(t *testing.T) {
	f := newScrapeFixture(t)
	if _, err := (&Scraper{Target: f.target("http://127.0.0.1:1")}).Once(f.ctx); err == nil {
		t.Fatal("a scraper without grant/admission ran")
	}
}

// Two scrapes of an unchanged exporter have identical bodies. Their batches
// must still be distinct admissions: reusing one batch identifier for different
// observed times would be a conflict at the receipt ledger.
func TestScrapeIdenticalBodiesAtDifferentTimesAreDistinctAdmissions(t *testing.T) {
	f := newScrapeFixture(t)
	srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrapeOM(w, "# TYPE host_load gauge\nhost_load{job=\"api\"} 1\n# EOF\n")
	}))
	first := f.target(srv.URL)
	first.Clock = scrapeClockAt(time.Now().Add(-2 * time.Second))
	second := f.target(srv.URL)
	second.Clock = scrapeClockAt(time.Now().Add(-1 * time.Second))
	a, err := FetchScrape(f.ctx, f.grant, first)
	a = scrapeMustOK(t, a, err)
	b, err := FetchScrape(f.ctx, f.grant, second)
	b = scrapeMustOK(t, b, err)
	if len(a.Batches) != 1 || len(b.Batches) != 1 {
		t.Fatalf("batches %d/%d", len(a.Batches), len(b.Batches))
	}
	if a.Batches[0].ID == b.Batches[0].ID {
		t.Fatal("identical bodies at different times share a batch identifier")
	}
	if a.Batches[0].Records[0].ID == b.Batches[0].Records[0].ID {
		t.Fatal("identical bodies at different times share a record identifier")
	}
	for i, res := range []ScrapeResult{a, b} {
		if _, err := f.app.Ingest.Admit(f.ctx, f.grant, res.Batches[0]); err != nil {
			t.Fatalf("scrape %d was refused by real admission: %v", i+1, err)
		}
	}
	// a retry of the very same scrape is still idempotent
	if _, err := f.app.Ingest.Admit(f.ctx, f.grant, a.Batches[0]); err != nil {
		t.Fatalf("retry of the same scrape: %v", err)
	}
}
