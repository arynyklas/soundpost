// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"soundpost/internal/model"
	"soundpost/internal/policy"
)

// GrantFunc resolves a fresh source grant. Grants are short-lived (they expire
// seconds after they are resolved), so a scrape cycle resolves one per attempt.
type GrantFunc func(ctx context.Context) (policy.SourceGrant, error)

// AdmitFunc admits one batch through C03 under the grant and returns the
// durable receipt (in production ingest.Service.Admit).
type AdmitFunc func(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error)

// Scraper schedules one locally approved scrape target. Acquisition runs where
// a policy grant can be resolved (it needs the installation's authority, so it
// runs inside the node, not in a remote agent); source health is exposed
// through Last and never as a fabricated zero.
//
// The set of series carried to the next cycle (what stale markers are computed
// against) advances only after every batch of the cycle has its receipt, the
// same discipline as the log checkpoint: a cycle whose admission failed does
// not forget what it marked or admitted.
type Scraper struct {
	Target ScrapeTarget // Previous is owned by the Scraper
	Grant  GrantFunc
	Admit  AdmitFunc
	// Attempts bounds the admission retries of one batch within a cycle; the
	// batch identifiers are deterministic, so a retry is idempotent. Zero is 3.
	Attempts int

	mu       sync.Mutex
	previous []SeriesRef
	last     ScrapeResult
	failures uint64
}

// Last returns the result of the most recent cycle (zero before the first).
func (s *Scraper) Last() ScrapeResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// AdmitFailures counts cycles whose batches could not be admitted.
func (s *Scraper) AdmitFailures() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failures
}

// Once runs one scrape cycle: fetch, admit every batch, then carry the series.
// A runtime scrape failure (timeout, refused, ...) is not an error: it is the
// result's Health with unknown Coverage; err reports configuration faults and
// admission failures.
func (s *Scraper) Once(ctx context.Context) (ScrapeResult, error) {
	if s.Grant == nil || s.Admit == nil {
		return ScrapeResult{}, scrapeInvalid("scraper wiring")
	}
	s.mu.Lock()
	target := s.Target
	target.Previous = append([]SeriesRef(nil), s.previous...)
	s.mu.Unlock()
	grant, err := s.Grant(ctx)
	if err != nil {
		return ScrapeResult{}, err
	}
	res, err := FetchScrape(ctx, grant, target)
	if err != nil {
		return res, err
	}
	for _, b := range res.Batches {
		if err := s.admit(ctx, b); err != nil {
			s.mu.Lock()
			s.last, s.failures = res, s.failures+1
			s.mu.Unlock()
			return res, fmt.Errorf("sources: scrape %s: admit: %w", res.Target, err)
		}
	}
	s.mu.Lock()
	s.previous, s.last = res.Seen, res
	s.mu.Unlock()
	return res, nil
}

func (s *Scraper) admit(ctx context.Context, b model.Batch) error {
	attempts := s.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	var err error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(i) * 100 * time.Millisecond):
			}
		}
		var grant policy.SourceGrant
		if grant, err = s.Grant(ctx); err != nil {
			continue
		}
		if _, err = s.Admit(ctx, grant, b); err == nil {
			return nil
		}
	}
	return err
}

// Run scrapes at the target's Interval until ctx ends. A failed cycle is
// reported to onCycle (which may be nil) and does not stop the schedule.
func (s *Scraper) Run(ctx context.Context, onCycle func(ScrapeResult, error)) {
	t := time.NewTicker(s.Target.Interval)
	defer t.Stop()
	for {
		res, err := s.Once(ctx)
		if onCycle != nil {
			onCycle(res, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
