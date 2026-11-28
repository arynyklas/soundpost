// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

func (f *sweepFixture) newOrg(t *testing.T) model.ID {
	t.Helper()
	c, err := f.service.Authenticate(f.ctx, f.session.Token)
	if err != nil {
		t.Fatal(err)
	}
	org := model.NewID()
	var rev model.Revision
	_ = f.store.View(f.ctx, func(st control.State) error { rev = st.Revision; return nil })
	payload, _ := json.Marshal(auth.AdminPayload{Name: "org", Reason: "throttle test"})
	if _, err = f.service.AdminCommand(f.ctx, c, auth.AdminCommandRequest{CommandID: model.NewID(), ExpectedRevision: rev, OrgID: org, Kind: "create_org", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	return org
}

func isRateLimited(err error) *auth.RateLimitedError {
	var rl *auth.RateLimitedError
	if errors.As(err, &rl) {
		return rl
	}
	return nil
}

// 09.06x-W2: elevation start is throttled per credential, separately from
// login: the eleventh start inside the window is a typed rate limit, another
// credential is unaffected, and the block ends with the window.
func TestElevationStartIsThrottledPerCredential(t *testing.T) {
	f := newSweepFixture(t)
	org := f.newOrg(t)
	for i := range 10 {
		if _, err := f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org}); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	_, err := f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org})
	if rl := isRateLimited(err); rl == nil || rl.RetryAfter <= 0 || rl.RetryAfter > 5*time.Minute {
		t.Fatalf("the eleventh start was not rate limited with a bounded wait: %v", err)
	}
	other, err := f.service.Login(f.ctx, "owner@example.test", "correct horse battery staple 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Elevate(f.ctx, other, "investigate selected organization", []model.ID{org}); err != nil {
		t.Fatalf("another credential was throttled with the first: %v", err)
	}
	*f.now = f.now.Add(5*time.Minute + time.Second)
	_, err = f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org})
	if isRateLimited(err) != nil {
		t.Fatalf("the start block outlived its window: %v", err)
	}
}

// 09.06x-W2: guessing elevation IDs is throttled per credential; reads of a
// real elevation never count against the limit.
func TestElevationReadMissesAreThrottledPerCredential(t *testing.T) {
	f := newSweepFixture(t)
	org := f.newOrg(t)
	el, err := f.service.Elevate(f.ctx, f.session, "investigate selected organization", []model.ID{org})
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.service.Authenticate(f.ctx, f.session.Token)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 100 {
		if _, err = f.service.ResolveElevation(f.ctx, c, el.ID()); err != nil {
			t.Fatalf("valid read %d counted against the limit: %v", i, err)
		}
	}
	for range 30 {
		_, err = f.service.ResolveElevation(f.ctx, c, model.NewID())
		assertCode(t, err, model.NotFound)
	}
	_, err = f.service.ResolveElevation(f.ctx, c, model.NewID())
	if rl := isRateLimited(err); rl == nil || rl.RetryAfter <= 0 {
		t.Fatalf("the 31st guess was not rate limited: %v", err)
	}
	// While blocked even the real elevation is refused: the check runs first.
	if _, err = f.service.ResolveElevation(f.ctx, c, el.ID()); isRateLimited(err) == nil {
		t.Fatalf("a blocked credential still resolved: %v", err)
	}
	*f.now = f.now.Add(5*time.Minute + time.Second)
	if _, err = f.service.ResolveElevation(f.ctx, c, model.NewID()); isRateLimited(err) != nil {
		t.Fatalf("the read block outlived its window: %v", err)
	}
}

// 09.04x-W1: N goroutines start a login at cap-1 live pending records. Exactly
// one is admitted, the rest get the typed retryable unavailable, and the cap is
// never exceeded. Run under -race.
func TestConcurrentOIDCStartAtCapMinusOneAdmitsExactlyOne(t *testing.T) {
	f := newSweepFixture(t)
	const limit = 8
	t.Cleanup(auth.SetPendingOIDCCap(limit))
	base, _ := f.oidcRecords(t)
	for i := range limit - 1 {
		if _, err := f.service.OIDCStart(f.ctx, f.cfg, "binding"); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
	}
	const workers = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = f.service.OIDCStart(f.ctx, f.cfg, "binding")
		}()
	}
	close(start)
	wg.Wait()
	admitted := 0
	for i, err := range errs {
		if err == nil {
			admitted++
			continue
		}
		var fault *model.Fault
		if !errors.As(err, &fault) || fault.Code != model.Unavailable || !fault.Retryable {
			t.Fatalf("goroutine %d: want retryable unavailable, got %v", i, err)
		}
	}
	if admitted != 1 {
		t.Fatalf("%d starts admitted at cap-1, want exactly 1", admitted)
	}
	if p, _ := f.oidcRecords(t); p-base != limit {
		t.Fatalf("%d live pending records, want exactly the cap %d", p-base, limit)
	}
}

// 09.04x-W2: expired sessions are collected at the instant Authenticate refuses
// them; live sessions stay.
func TestSweepRemovesExpiredSessionsKeepsLiveOnes(t *testing.T) {
	f := newSweepFixture(t)
	second, err := f.service.Login(f.ctx, "owner@example.test", "correct horse battery staple 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	sessions := func() (n int) {
		_ = f.store.View(f.ctx, func(st control.State) error { n = len(st.Sessions); return nil })
		return
	}
	if sessions() != 2 {
		t.Fatalf("setup: %d sessions", sessions())
	}
	expiry := time.Unix(int64(f.session.Expires), 0)
	*f.now = expiry.Add(-time.Second)
	if n, err := f.service.SweepExpired(f.ctx); err != nil || n != 0 || sessions() != 2 {
		t.Fatalf("swept live sessions: %d %v left %d", n, err, sessions())
	}
	*f.now = expiry
	if n, err := f.service.SweepExpired(f.ctx); err != nil || n != 2 || sessions() != 0 {
		t.Fatalf("swept %d err %v left %d at exact expiry, want both removed", n, err, sessions())
	}
	_, err = f.service.Authenticate(f.ctx, second.Token)
	assertCode(t, err, model.Unauthenticated)
}
