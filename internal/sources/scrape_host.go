// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/model"
	"github.com/arynyklas/soundpost/internal/policy"
)

// SourceAuthenticator turns the raw source credential an operator provisioned
// into a credential (in production *auth.Service, the call the HTTP ingest
// route makes).
type SourceAuthenticator interface {
	AuthenticateSource(ctx context.Context, raw, origin string, browser bool) (auth.SourceCredential, error)
}

// ScrapeIngest resolves a grant and admits a batch (in production
// *ingest.Service: ResolveSource and Admit are exactly what the HTTP ingest
// route calls, so a scraped batch passes the same policy, quota and receipt path).
type ScrapeIngest interface {
	ResolveSource(ctx context.Context, c auth.SourceCredential, b model.Batch) (policy.SourceGrant, error)
	Admit(ctx context.Context, g policy.SourceGrant, b model.Batch) (model.Receipt, error)
}

// ScrapeHostDeps is what the node supplies to host scrapers.
type ScrapeHostDeps struct {
	Auth    SourceAuthenticator
	Ingest  ScrapeIngest
	Secrets SecretReader
	// Policies reads the live source policy (in production *auth.Service). It
	// is required only by targets that follow the live policy revision.
	Policies SourcePolicyReader
	// State, when set, persists each target's carried-series set.
	State *ScrapeStateStore
}

// SourcePolicyReader answers the live authority of a source, including its
// current policy revision.
type SourcePolicyReader interface {
	SourceAuthority(ctx context.Context, c auth.SourceCredential, admission bool) (model.SourceAuthority, error)
}

// ScrapeReason is the closed set of per-target reasons a cycle did not
// complete. Empty means the last cycle scraped and admitted. A scrape outcome
// (timeout, bad_status, egress_denied, ...) is the ScrapeStatus itself.
type ScrapeReason string

const (
	ScrapeReasonNone ScrapeReason = ""
	// ScrapeReasonCredentialUnavailable: the source credential secret could not be read.
	ScrapeReasonCredentialUnavailable ScrapeReason = "credential_unavailable"
	// ScrapeReasonGrantDenied: the source credential is unknown, revoked or expired, or does not cover the configured project and source.
	ScrapeReasonGrantDenied ScrapeReason = "grant_denied"
	// ScrapeReasonPolicyStale: the source policy revision differs from the configured one.
	ScrapeReasonPolicyStale ScrapeReason = "policy_stale"
	// ScrapeReasonGrantUnavailable: the installation could not answer (not a verdict on the credential).
	ScrapeReasonGrantUnavailable ScrapeReason = "grant_unavailable"
	// ScrapeReasonAdmitFailed: a batch of the cycle was refused or could not be made durable.
	ScrapeReasonAdmitFailed ScrapeReason = "admit_failed"
	// ScrapeReasonInvalid: the target or grant failed validation before any request.
	ScrapeReasonInvalid ScrapeReason = "invalid"
	// ScrapeReasonCancelled: the host is stopping.
	ScrapeReasonCancelled ScrapeReason = "cancelled"
	// ScrapeReasonStateCorrupt: the persisted stale-marker state of the target cannot be trusted.
	ScrapeReasonStateCorrupt ScrapeReason = "state_corrupt"
	// ScrapeReasonStateUnavailable: the persisted stale-marker state could not be read or written.
	ScrapeReasonStateUnavailable ScrapeReason = "state_unavailable"
	// ScrapeReasonStateTooLarge: the carried series would exceed the persisted bound.
	ScrapeReasonStateTooLarge ScrapeReason = "state_too_large"
)

// scrapeGrantError carries the typed reason of a failed grant resolution
// through Scraper.Once untouched; its text is static.
type scrapeGrantError struct{ reason ScrapeReason }

func (e *scrapeGrantError) Error() string { return "sources: scrape grant " + string(e.reason) }

// ScrapeTargetStatus is the readable health of one target. It carries no URL,
// secret, header, body or transport error text.
type ScrapeTargetStatus struct {
	Alias string
	// Cycles counts completed attempts (successful or not).
	Cycles uint64
	// Reason is empty when the last cycle scraped and admitted.
	Reason ScrapeReason
	// Last is the last result of the scraper; zero before the first healthy cycle.
	Last ScrapeResult
	// AdmitFailures is Scraper.AdmitFailures.
	AdmitFailures uint64
	// Project is the configured project the target admits into; the status
	// route maps it to the owning organization and never returns it.
	Project model.ID
	// LastAttempt is when the last cycle ended; zero before the first.
	LastAttempt time.Time
}

// OK reports whether the last cycle scraped and admitted every batch with a
// healthy scrape.
func (s ScrapeTargetStatus) OK() bool {
	return s.Cycles > 0 && s.Reason == ScrapeReasonNone && s.Last.Health.Status == ScrapeOK
}

// ScrapeHost runs one Scraper per configured target until Close or the
// context given to StartScrapeHost ends.
type ScrapeHost struct {
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	targets []*scrapeHosted
}

type scrapeHosted struct {
	scraper *Scraper
	alias   string
	cycles  uint64
	project model.ID
	// lastAttempt is when the last cycle ended, whatever its outcome (a grant or
	// secret failure produces no ScrapeResult time).
	lastAttempt time.Time
	reason      ScrapeReason
	// revision is the live policy revision of the last grant (follow mode).
	revision atomic.Uint64
}

// StartScrapeHost starts one scrape schedule per spec under ctx. It validates
// the specs again (so a hand-built spec is held to the same rules as a loaded
// one) and starts nothing when any is invalid.
func StartScrapeHost(ctx context.Context, deps ScrapeHostDeps, specs []ScrapeTargetSpec) (*ScrapeHost, error) {
	return startScrapeHost(ctx, deps, specs, nil)
}

func startScrapeHost(ctx context.Context, deps ScrapeHostDeps, specs []ScrapeTargetSpec, adjust func(*ScrapeTarget)) (*ScrapeHost, error) {
	if deps.Auth == nil || deps.Ingest == nil || deps.Secrets == nil {
		return nil, scrapeInvalid("scrape host wiring")
	}
	seen := map[string]bool{}
	for i := range specs {
		if adjust != nil {
			adjust(&specs[i].Target)
		}
		if _, err := specs[i].Target.validate(); err != nil || seen[specs[i].Target.Alias] || !ValidSecretRef(specs[i].CredentialSecret) {
			return nil, scrapeInvalid("scrape target")
		}
		if specs[i].FollowPolicy && (deps.Policies == nil || specs[i].PolicyRevision != 0) {
			return nil, scrapeInvalid("scrape policy revision")
		}
		seen[specs[i].Target.Alias] = true
	}
	runCtx, cancel := context.WithCancel(ctx)
	h := &ScrapeHost{cancel: cancel}
	for _, spec := range specs {
		t := &scrapeHosted{alias: spec.Target.Alias, project: spec.Project, scraper: &Scraper{
			Target: spec.Target,
			Admit:  deps.Ingest.Admit,
			State:  deps.State,
		}}
		t.scraper.Grant = scrapeGrantFunc(deps, spec, &t.revision)
		if spec.FollowPolicy {
			t.scraper.Revision = func() model.Revision { return model.Revision(t.revision.Load()) }
		}
		h.targets = append(h.targets, t)
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			t.scraper.Run(runCtx, func(res ScrapeResult, err error) { h.record(t, res, err) })
		}()
	}
	return h, nil
}

// scrapeGrantFunc resolves a fresh grant for every call: it reads the source
// credential from the secret store, authenticates it and resolves the grant for
// the configured project, source and policy revision through the same
// ingest.Service.ResolveSource the HTTP route uses. Nothing is kept between
// calls (a grant lives a few seconds, and a credential may be revoked at any time).
func scrapeGrantFunc(deps ScrapeHostDeps, spec ScrapeTargetSpec, live *atomic.Uint64) GrantFunc {
	return func(ctx context.Context) (policy.SourceGrant, error) {
		raw, err := deps.Secrets.ReadSecret(ctx, spec.CredentialSecret)
		if err != nil || len(raw) == 0 {
			scrapeZero(raw)
			if ctx.Err() != nil {
				return policy.SourceGrant{}, &scrapeGrantError{ScrapeReasonCancelled}
			}
			return policy.SourceGrant{}, &scrapeGrantError{ScrapeReasonCredentialUnavailable}
		}
		token := string(raw)
		scrapeZero(raw)
		cred, err := deps.Auth.AuthenticateSource(ctx, token, "", false)
		if err != nil {
			return policy.SourceGrant{}, &scrapeGrantError{scrapeGrantReason(ctx, err)}
		}
		rev := spec.PolicyRevision
		if spec.FollowPolicy {
			// The revision is read from the live policy at this attempt; a policy
			// change between this read and the resolve is a typed policy_stale
			// for this one attempt and the next attempt follows it.
			src, err := deps.Policies.SourceAuthority(ctx, cred, true)
			if err != nil {
				return policy.SourceGrant{}, &scrapeGrantError{scrapeGrantReason(ctx, err)}
			}
			rev = src.Policy.Revision
			live.Store(uint64(rev))
		}
		g, err := deps.Ingest.ResolveSource(ctx, cred, model.Batch{Project: spec.Project, Source: spec.Source, PolicyRevision: rev})
		if err != nil {
			return policy.SourceGrant{}, &scrapeGrantError{scrapeGrantReason(ctx, err)}
		}
		return g, nil
	}
}

func scrapeGrantReason(ctx context.Context, err error) ScrapeReason {
	if ctx.Err() != nil {
		return ScrapeReasonCancelled
	}
	var f *model.Fault
	if errors.As(err, &f) {
		switch f.Code {
		case model.Forbidden, model.Unauthenticated, model.NotFound:
			return ScrapeReasonGrantDenied
		case model.Stale:
			return ScrapeReasonPolicyStale
		}
	}
	return ScrapeReasonGrantUnavailable
}

func (h *ScrapeHost) record(t *scrapeHosted, res ScrapeResult, err error) {
	reason := ScrapeReasonNone
	var ge *scrapeGrantError
	var se *ScrapeStateError
	switch {
	case err == nil:
		if res.Health.Status != ScrapeOK {
			reason = ScrapeReason(res.Health.Status)
		}
	case errors.As(err, &ge):
		reason = ge.reason
	case errors.As(err, &se): // the persisted stale-marker state, before or after the fetch
		reason = ScrapeReason(se.Reason)
	case res.Target != "": // the fetch produced batches that could not be admitted
		reason = ScrapeReasonAdmitFailed
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		reason = ScrapeReasonCancelled
	default:
		var f *model.Fault
		if errors.As(err, &f) && f.Code == model.Cancelled {
			reason = ScrapeReasonCancelled
		} else {
			reason = ScrapeReasonInvalid
		}
	}
	h.mu.Lock()
	t.cycles++
	t.reason = reason
	t.lastAttempt = time.Now()
	h.mu.Unlock()
}

// Status returns the health of every target in alias order.
func (h *ScrapeHost) Status() []ScrapeTargetStatus {
	h.mu.Lock()
	out := make([]ScrapeTargetStatus, 0, len(h.targets))
	for _, t := range h.targets {
		out = append(out, ScrapeTargetStatus{Alias: t.alias, Project: t.project, Cycles: t.cycles, Reason: t.reason, LastAttempt: t.lastAttempt})
	}
	h.mu.Unlock()
	for i := range out {
		out[i].Last = h.targets[i].scraper.Last()
		out[i].AdmitFailures = h.targets[i].scraper.AdmitFailures()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// Close stops every scrape schedule and waits until none is running. It is
// idempotent.
func (h *ScrapeHost) Close() {
	h.cancel()
	h.wg.Wait()
}
