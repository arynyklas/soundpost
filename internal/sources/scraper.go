// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package sources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
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
// not forget what it marked or admitted, so the next cycle compares against the
// previous set together with the failed cycle's own (series it may have
// admitted are marked when they vanish, and a marker whose receipt was lost is
// produced again).
//
// With a State store (and a stale policy that consumes the set) the carried set
// also survives a restart: it is restored on the first cycle, written before the
// first batch is submitted as (previous ∪ the cycle's own set) and replaced by
// the cycle's own set after the last receipt. See scrape_state.go for the exact
// rule and its guarantees. A state file that cannot be trusted fails the cycle
// typed (ScrapeStateError) before the exporter is contacted.
type Scraper struct {
	Target ScrapeTarget // Previous is owned by the Scraper
	Grant  GrantFunc
	Admit  AdmitFunc
	// Attempts bounds the admission retries of one batch within a cycle; the
	// batch identifiers are deterministic, so a retry is idempotent. Zero is 3.
	Attempts int
	// Revision, when set, supplies the source policy revision of the grant the
	// last Grant call resolved; the cycle's batches are stamped with it. Zero
	// keeps the target's configured revision.
	Revision func() model.Revision
	// State, when set, persists the carried-series set across restarts. It is
	// used only by a target whose stale policy consumes the set.
	State *ScrapeStateStore

	mu       sync.Mutex
	previous []SeriesRef
	last     ScrapeResult
	failures uint64

	// The persisted state, touched only by Once (which is not reentrant).
	restored bool
	identity [32]byte
	stored   [32]byte // digest of the series set the state file holds, when storedOK
	storedOK bool     // false: the file may hold something else (another identity's state)
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
// result's Health with unknown Coverage; err reports configuration faults,
// admission failures and failures of the persisted state (ScrapeStateError).
func (s *Scraper) Once(ctx context.Context) (ScrapeResult, error) {
	if s.Grant == nil || s.Admit == nil {
		return ScrapeResult{}, scrapeInvalid("scraper wiring")
	}
	grant, err := s.Grant(ctx)
	if err != nil {
		return ScrapeResult{}, err
	}
	// carry: the stale policy consumes the carried set at all. persist: it also
	// survives a restart. bound: the carried set is at most the previous committed
	// set plus one cycle's own set, each at most the decoder's series limit.
	carry := s.Target.Stale.OnDisappear || s.Target.Stale.OnFailure
	persist := carry && s.State != nil
	bound := 2 * s.Target.Profile.Limits.MaxSeries
	if carry && bound <= 0 {
		return ScrapeResult{}, scrapeInvalid("scrape series limit")
	}
	if persist && !s.restored {
		if err := s.restore(grant, bound); err != nil {
			return ScrapeResult{}, err
		}
	}
	s.mu.Lock()
	target := s.Target
	target.Previous = append([]SeriesRef(nil), s.previous...)
	s.mu.Unlock()
	if s.Revision != nil {
		if rev := s.Revision(); rev != 0 {
			target.Profile.PolicyRevision = rev
		}
	}
	res, err := FetchScrape(ctx, grant, target)
	if err != nil {
		return res, err
	}

	// Before anything is submitted, what a crash must still carry: the previous set
	// and this cycle's own set.
	var union []SeriesRef
	if carry {
		union = scrapeUnion(target.Previous, res.Seen)
		if len(union) > bound {
			s.mu.Lock()
			s.last = res
			s.mu.Unlock()
			return res, scrapeStateFail(ScrapeStateTooLarge)
		}
	}
	if persist {
		if err := s.write(union, bound); err != nil {
			s.mu.Lock()
			s.last = res
			s.mu.Unlock()
			return res, err
		}
	}
	for _, b := range res.Batches {
		if err := s.admit(ctx, b); err != nil {
			s.mu.Lock()
			s.last, s.failures = res, s.failures+1
			if carry {
				s.previous = union
			}
			s.mu.Unlock()
			return res, fmt.Errorf("sources: scrape %s: admit: %w", res.Target, err)
		}
	}
	s.mu.Lock()
	s.previous, s.last = res.Seen, res
	s.mu.Unlock()
	// Every batch has its receipt: the cycle's own set is now the committed one.
	if persist {
		if err := s.write(res.Seen, bound); err != nil {
			return res, err
		}
	}
	return res, nil
}

// restore loads the persisted carried set of the target. A state file that
// cannot be trusted is an error and is retried on every cycle (it clears when the
// operator removes the file); another target configuration's state is not inherited.
func (s *Scraper) restore(grant policy.SourceGrant, bound int) error {
	scope, err := grant.Scope()
	if err != nil {
		return err
	}
	id := scrapeStateIdentity(scope.OrgID(), s.Target)
	series, inSync, err := s.State.load(s.Target.Alias, id, bound)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.previous = series
	s.mu.Unlock()
	s.identity, s.stored, s.storedOK, s.restored = id, scrapeSetDigest(series), inSync, true
	return nil
}

// write makes the state file hold series (sorted, deduplicated), unless it
// already does.
func (s *Scraper) write(series []SeriesRef, bound int) error {
	digest := scrapeSetDigest(series)
	if s.storedOK && digest == s.stored {
		return nil
	}
	if err := s.State.save(s.Target.Alias, s.identity, series, bound); err != nil {
		return err
	}
	s.stored, s.storedOK = digest, true
	return nil
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
