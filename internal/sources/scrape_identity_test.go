// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func scrapeIdentities(res ScrapeResult) (batches, records []model.ID) {
	for _, b := range res.Batches {
		batches = append(batches, b.ID)
		for _, r := range b.Records {
			records = append(records, r.ID)
		}
	}
	return batches, records
}

// The decoder itself binds the scrape time into the batch and record
// identifiers (there is no re-keying in the scraper): two scrapes of an exporter
// whose text did not change are distinct admissions with their own observed
// times, and a retry of one scrape reproduces its identifiers exactly.
func TestScrapeOfUnchangedExporterGetsDistinctIdentifiers(t *testing.T) {
	f := newScrapeFixture(t)
	srv, _ := scrapeServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scrapeOM(w, "# TYPE reqs counter\nreqs_total{job=\"api\"} 7\n# TYPE temp gauge\ntemp{job=\"worker\"} 1.5\n# EOF\n")
	}))
	at := func(d time.Duration) ScrapeTarget {
		tg := f.target(srv.URL)
		tg.Clock = scrapeClockAt(scrapeT0.Add(d))
		return tg
	}
	first := f.fetchOK(t, at(0))
	retry := f.fetchOK(t, at(0))
	later := f.fetchOK(t, at(15*time.Second))

	b1, r1 := scrapeIdentities(first)
	bRetry, rRetry := scrapeIdentities(retry)
	b2, r2 := scrapeIdentities(later)
	if len(b1) == 0 || len(r1) != 2 {
		t.Fatalf("fixture scrape: %d batches, %d records", len(b1), len(r1))
	}
	if !reflect.DeepEqual(b1, bRetry) || !reflect.DeepEqual(r1, rRetry) {
		t.Fatal("a retry of one scrape changed its identifiers")
	}
	if len(b2) != len(b1) || len(r2) != len(r1) {
		t.Fatalf("shape %d/%d batches, %d/%d records", len(b1), len(b2), len(r1), len(r2))
	}
	for i := range b1 {
		if b1[i] == b2[i] {
			t.Errorf("batch %d: scrapes 15s apart share batch id %s", i, b1[i])
		}
	}
	for i := range r1 {
		if r1[i] == r2[i] {
			t.Errorf("record %d: scrapes 15s apart share record id %s", i, r1[i])
		}
	}
	for _, b := range later.Batches {
		for _, r := range b.Records {
			if r.ObservedAt != model.UnixNano(scrapeT0.Add(15*time.Second).UnixNano()) {
				t.Fatalf("observed time %d is not the scrape time", r.ObservedAt)
			}
		}
	}
}
