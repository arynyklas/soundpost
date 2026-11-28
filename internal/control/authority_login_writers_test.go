// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package control_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
)

// totpCode is RFC 6238 (SHA-1, 6 digits, 30 s step) for the base32 secret BeginTOTP returns.
func totpCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 15
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff%1000000)
}

// A login that presents a TOTP code or a recovery code consumes it (User.LastTOTP raised, a
// recovery hash removed) in the same commit as its session. That is the SessionCreate writer's
// case for factor consumption: it keeps AuthorityRevision (no access decision reads either field),
// while the code really is spent and cannot be replayed.
func TestTOTPAndRecoveryLoginsKeepAuthority(t *testing.T) {
	const email, password = "owner@example.test", "a long test password 2026"
	f := newFenceFx(t)
	enroll, err := f.svc.Login(f.ctx, email, password, "")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := f.svc.BeginTOTP(f.ctx, enroll.Token)
	if err != nil {
		t.Fatal(err)
	}
	step := f.now.Unix() / 30
	recovery, err := f.svc.ConfirmTOTP(f.ctx, enroll.Token, totpCode(t, secret, step))
	if err != nil {
		t.Fatal(err)
	}
	user := func() (u model.ControlUser) {
		if err := f.store.View(f.ctx, func(st control.State) error { u = st.Users[f.user.String()]; return nil }); err != nil {
			t.Fatal(err)
		}
		return u
	}
	if u := user(); u.LastTOTP != step || len(u.Recovery) != len(recovery) || len(recovery) < 2 {
		t.Fatalf("setup: enrolment left LastTOTP %d (want %d), %d recovery hashes for %d codes", u.LastTOTP, step, len(u.Recovery), len(recovery))
	}
	keeps := func(label, code string) {
		t.Helper()
		rev0, auth0 := f.revisions()
		if _, err := f.svc.Login(f.ctx, email, password, code); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		rev1, auth1 := f.revisions()
		if rev1 != rev0+1 || auth1 != auth0 {
			t.Fatalf("%s: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", label, rev0, rev1, auth0, auth1)
		}
	}
	refused := func(label, code string) {
		t.Helper()
		rev0, auth0 := f.revisions()
		if _, err := f.svc.Login(f.ctx, email, password, code); err == nil {
			t.Fatalf("%s: a spent code logged in again", label)
		}
		if rev1, auth1 := f.revisions(); rev1 != rev0 || auth1 != auth0 {
			t.Fatalf("%s: a refused login committed: revision %d -> %d, authority %d -> %d", label, rev0, rev1, auth0, auth1)
		}
	}

	before := user()
	keeps("recovery code", recovery[0])
	after := user()
	if len(after.Recovery) != len(before.Recovery)-1 || slices.Equal(after.Recovery, before.Recovery) {
		t.Fatalf("the recovery code was not spent: %d -> %d hashes", len(before.Recovery), len(after.Recovery))
	}
	refused("recovery code replayed", recovery[0])

	next := totpCode(t, secret, step+1)
	keeps("TOTP step", next)
	if got := user().LastTOTP; got != step+1 {
		t.Fatalf("the TOTP step was not spent: LastTOTP %d, want %d", got, step+1)
	}
	refused("TOTP step replayed", next)
}

// Elevate stores an elevation record, which is an access grant (ResolveElevation rebuilds the
// cross-organization read scope of an administrator's session from it): it MUST bump
// AuthorityRevision, and this pins it. The per-read elevated_read audit of ElevatedScope only
// appends an audit row and keeps the revision.
func TestElevateBumpsElevatedReadAuditDoesNot(t *testing.T) {
	f := newFenceFx(t)
	session, err := f.svc.Login(f.ctx, "owner@example.test", "a long test password 2026", "")
	if err != nil {
		t.Fatal(err)
	}
	rev0, auth0 := f.revisions()
	elevation, err := f.svc.Elevate(f.ctx, session, "authority classification test", []model.ID{f.org})
	if err != nil {
		t.Fatal(err)
	}
	rev1, auth1 := f.revisions()
	if rev1 != rev0+1 || auth1 != rev1 || auth1 == auth0 {
		t.Fatalf("Elevate: revision %d -> %d, authority %d -> %d (want a bump: the elevation record is an access grant)", rev0, rev1, auth0, auth1)
	}
	audits := func() (n int, last model.ControlAudit) {
		if err := f.store.View(f.ctx, func(st control.State) error {
			n = len(st.Audits)
			if n > 0 {
				last = st.Audits[n-1]
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	n0, _ := audits()
	if _, err = f.svc.ElevatedScope(f.ctx, elevation, f.org, nil, auth.Read); err != nil {
		t.Fatal(err)
	}
	rev2, auth2 := f.revisions()
	n1, last := audits()
	if rev2 != rev1+1 || auth2 != auth1 {
		t.Fatalf("ElevatedScope: revision %d -> %d, authority %d -> %d (want the revision to move, authority not)", rev1, rev2, auth1, auth2)
	}
	if n1 != n0+1 || last.Action != "elevated_read" {
		t.Fatalf("ElevatedScope left %d -> %d audit rows, last %q: the audit must still be committed", n0, n1, last.Action)
	}
}
