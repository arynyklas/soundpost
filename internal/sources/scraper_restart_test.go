// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/arynyklas/soundpost/internal/policy"
)

// [10.16-W2 / 07.03-W2] The carried-series set is in memory only. A restart
// therefore forgets what the previous process had seen: a series that vanished
// while the node was down never receives a stale marker (its last sample ages
// out of the query lookback, as after any scrape gap), the new process neither
// invents nor repeats a marker, and from its first healthy cycle on it carries
// and marks exactly like an uninterrupted scraper. The documented limit lives in
// docs/operations/scraping.md, "Restart".
func TestScrapeRestartForgetsCarriedSeriesWithoutInventingMarkers(t *testing.T) {
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
	newScraper := func() *Scraper {
		target := f.target(srv.URL)
		target.Clock = nil
		target.Stale = StalePolicy{OnDisappear: true}
		return &Scraper{Target: target, Grant: func(context.Context) (policy.SourceGrant, error) { return f.grant, nil }, Admit: log.admit, Attempts: 1}
	}

	before := newScraper()
	if res, err := before.Once(f.ctx); err != nil || res.Samples != 2 || res.StaleMarkers != 0 {
		t.Fatalf("first process cycle: %+v %v", res, err)
	}

	// The node restarts and host_gone vanished while it was down.
	setBody("# TYPE host_load gauge\nhost_load{job=\"api\"} 2\n# TYPE host_new gauge\nhost_new{job=\"api\"} 5\n# EOF\n")
	after := newScraper()
	res, err := after.Once(f.ctx)
	if err != nil || res.Health.Status != ScrapeOK || res.Samples != 2 {
		t.Fatalf("first cycle after restart: %+v %v", res, err)
	}
	if res.StaleMarkers != 0 || len(log.staleFor("host_gone")) != 0 {
		t.Fatalf("restart invented a marker: %d markers, %d admitted for host_gone", res.StaleMarkers, len(log.staleFor("host_gone")))
	}
	if got := scrapeSeen(t, after.Last().Seen); len(got) != 2 {
		t.Fatalf("seen after the restart cycle: %v", got)
	}

	// The restarted scraper carries normally: host_new disappearing is marked once.
	setBody("# TYPE host_load gauge\nhost_load{job=\"api\"} 3\n# EOF\n")
	res, err = after.Once(f.ctx)
	if err != nil || res.StaleMarkers != 1 || len(log.staleFor("host_new")) != 1 {
		t.Fatalf("second cycle after restart: err=%v markers=%d admitted-for-host_new=%d", err, res.StaleMarkers, len(log.staleFor("host_new")))
	}
	if res, err = after.Once(f.ctx); err != nil || res.StaleMarkers != 0 || len(log.staleFor("host_new")) != 1 {
		t.Fatalf("third cycle after restart repeated a marker: err=%v markers=%d", err, res.StaleMarkers)
	}
	if len(log.staleFor("host_gone")) != 0 {
		t.Fatal("a marker for the series that vanished during the restart appeared later")
	}
}
