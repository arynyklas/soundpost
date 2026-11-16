// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"github.com/arynyklas/soundpost/internal/model"
	"golang.org/x/crypto/argon2"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ControlStore interface {
	View(context.Context, func(model.ControlState) error) error
	Update(context.Context, func(*model.ControlState) error) error
	InitializeBearerHashKey(context.Context, string, uint8) error
	RemoveBootstrapFile() error
	Seal(string) (string, error)
	OpenSecret(string) (string, error)
}
type AuthDependencies struct {
	Control ControlStore
	Now     func() time.Time
}
type Service struct {
	store         ControlStore
	now           func() time.Time
	bearerHashKey [32]byte
	sourceBarrier SourceBarrier
	throttle      *loginThrottle
}
type Session struct {
	Token   string      `json:"-"`
	CSRF    string      `json:"csrf"`
	User    model.ID    `json:"user"`
	Expires model.Int64 `json:"expires"`
}
type Credential struct {
	service *Service
	user    model.ID
	token   string
	fresh   int64
	admin   bool
	// system marks the runner's in-process credential (AuthorizeSystem). Only
	// that function sets it; it has no token and Authenticate never returns one.
	system  bool
	machine bool
}

func NewService(d AuthDependencies) (*Service, error) {
	if d.Control == nil {
		return nil, model.Fail(model.Invalid)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	key, err := initializeBearerHashKey(d.Control)
	if err != nil {
		return nil, err
	}
	s := &Service{store: d.Control, now: d.Now, bearerHashKey: key, throttle: newLoginThrottle(d.Now)}
	// The dummy digest stands in for unknown and disabled addresses. It is derived here, once per
	// process and before any request is served, so the first unknown-address login costs one KDF
	// run like every other login instead of two.
	dummyDigest()
	return s, nil
}

// kdfRuns counts password-KDF evaluations so tests can assert equal work
// without timing.
var kdfRuns atomic.Int64

func password(p string, salt string) string {
	kdfRuns.Add(1)
	return base64.RawStdEncoding.EncodeToString(argon2.IDKey([]byte(p), []byte(salt), 3, 64*1024, 2, 32))
}
func hashPassword(p string) (string, error) {
	if len(p) < 16 || len(p) > 1024 {
		return "", model.Fail(model.Invalid)
	}
	salt := randomToken()
	return salt + ":" + password(p, salt), nil
}
func checkPassword(encoded, p string) bool {
	a, b, ok := strings.Cut(encoded, ":")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(b), []byte(password(p, a))) == 1
}

// bootstrapTokenRefusal is nil only while the install is unbootstrapped and token is its
// one-time token; every other case (already bootstrapped, wrong token) is the same
// Unauthenticated.
func bootstrapTokenRefusal(st model.ControlState, token string) error {
	if st.BootstrapHash == "" || subtle.ConstantTimeCompare([]byte(st.BootstrapHash), []byte(hashToken(token))) != 1 {
		return model.Fail(model.Unauthenticated)
	}
	return nil
}
func (s *Service) Bootstrap(ctx context.Context, token, email, p string) (Session, error) {
	// This route is unauthenticated and stays mounted for the life of the install, so it
	// refuses before any password work: a linearizable read of the token comes first and the
	// 64 MiB KDF runs only for the holder of a valid one. The transition below checks again,
	// because the state may change between the read and the write.
	if e := s.store.View(ctx, func(st model.ControlState) error { return bootstrapTokenRefusal(st, token) }); e != nil {
		return Session{}, e
	}
	h, e := hashPassword(p)
	if e != nil {
		return Session{}, e
	}
	id := model.NewID()
	out := s.newSession(id)
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		if e := bootstrapTokenRefusal(*st, token); e != nil {
			return e
		}
		if !validEmail(email) {
			return model.Fail(model.Invalid)
		}
		st.Users[id.String()] = model.ControlUser{ID: id, Email: email, Password: h, Admin: true}
		st.BootstrapHash = ""
		st.Sessions[hashToken(out.Token)] = model.ControlSession{User: id, CSRF: out.CSRF, Expires: int64(out.Expires), Reauthenticated: s.now().Unix()}
		return nil
	})
	if e != nil {
		return Session{}, e
	}
	if e = s.store.RemoveBootstrapFile(); e != nil {
		return Session{}, model.Fail(model.Unavailable)
	}
	return out, nil
}
func validEmail(v string) bool {
	return len(v) < 255 && strings.Contains(v, "@") && strings.TrimSpace(v) == v
}
func (s *Service) newSession(id model.ID) Session {
	return Session{Token: randomToken(), CSRF: randomToken(), User: id, Expires: model.Int64(s.now().Add(12 * time.Hour).Unix())}
}

// sessionCreator is implemented by *control.Store: an update that does not move the control
// AuthorityRevision when it only adds a session. A ControlStore without it falls back to
// Update. Only session-creating logins (password, SSO callback) use it; Bootstrap (creates the
// admin user), Logout and every credential change keep the always-bumping Update.
type sessionCreator interface {
	UpdateSessionCreate(context.Context, func(*model.ControlState) error) error
}

func (s *Service) updateSession(ctx context.Context, fn func(*model.ControlState) error) error {
	if u, ok := s.store.(sessionCreator); ok {
		return u.UpdateSessionCreate(ctx, fn)
	}
	return s.store.Update(ctx, fn)
}
func (s *Service) Login(ctx context.Context, email, p, code string) (Session, error) {
	if e := s.throttle.check(ctx, email); e != nil {
		return Session{}, e
	}
	out, e := s.login(ctx, email, p, code)
	var f *model.Fault
	if e == nil {
		s.throttle.success(email)
	} else if errors.As(e, &f) && f.Code == model.Unauthenticated {
		s.throttle.failure(ctx, email)
	}
	return out, e
}

// dummyDigest is verified for addresses that do not exist (or are disabled) so
// a missing account costs the same KDF work as a wrong password.
var dummyDigest = sync.OnceValue(deriveDummyDigest)

func deriveDummyDigest() string {
	return "soundpost-dummy-salt:" + password("soundpost dummy password", "soundpost-dummy-salt")
}

// loginStaleBudget bounds how long one login waits for its control write to stop being stale.
const loginStaleBudget = 15 * time.Second

// loginStaleRetries counts the repeats retryStale made after a typed stale answer, so tests can
// assert that a login did not need the bounded wait.
var loginStaleRetries atomic.Int64

// retryStale repeats fn, pausing briefly between attempts, for as long as it fails with the typed
// retryable Stale fault and ctx is alive. The last Stale is returned when ctx ends; every other
// result is returned at once.
func retryStale(ctx context.Context, fn func() error) error {
	for {
		err := fn()
		var fault *model.Fault
		if err == nil || ctx.Err() != nil || !errors.As(err, &fault) || fault.Code != model.Stale {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(25 * time.Millisecond):
			loginStaleRetries.Add(1)
		}
	}
}

func (s *Service) login(ctx context.Context, email, p, code string) (Session, error) {
	out := s.newSession(model.ID{})
	// One attempt is two steps. The password check is a KDF of about 100 ms, so it runs against a
	// linearizable read of the account BEFORE the control write: a replicated write carries the
	// revision it was computed from, and any other control commit during the check (every node runs
	// background writers) makes it lose the race for its index (typed `stale`). Inside the write only
	// cheap steps remain: the account must still be the record the password was verified against
	// (same id, enabled, same password hash), a TOTP or recovery code is consumed (it must commit
	// with the session), and the session is added.
	var checkedDigest string
	var checkedOK, checked bool
	attempt := func(wait context.Context) error {
		var key string
		var seen model.ControlUser
		known := false
		if err := s.store.View(wait, func(st model.ControlState) error {
			for k, u := range st.Users {
				if u.Email == email && !u.Disabled {
					key, seen, known = k, u, true
					break
				}
			}
			return nil
		}); err != nil {
			return err
		}
		// A missing or disabled account costs the same single KDF as a wrong password.
		digest := dummyDigest()
		if known {
			digest = seen.Password
		}
		// The KDF result is kept across the retries of this one login: a repeated attempt against
		// the same password hash never pays it again, so the bounded wait is bounded CPU too.
		if !checked || checkedDigest != digest {
			checkedOK, checkedDigest, checked = checkPassword(digest, p), digest, true
		}
		if !checkedOK || !known {
			return model.Fail(model.Unauthenticated)
		}
		return s.updateSession(wait, func(st *model.ControlState) error {
			u, ok := st.Users[key]
			if !ok || u.Disabled || u.Email != email || u.Password != seen.Password {
				// The account changed after the password was verified: verify it again.
				return model.Fail(model.Stale)
			}
			if u.TOTP != "" {
				sealed := u.TOTP
				secret, err := s.store.OpenSecret(sealed)
				if err != nil {
					return model.Fail(model.Unavailable)
				}
				u.TOTP = secret
				if !consumeFactor(&u, code, s.now()) {
					return model.Fail(model.Unauthenticated)
				}
				u.TOTP = sealed
				st.Users[key] = u
			}
			out.User = u.ID
			st.Sessions[hashToken(out.Token)] = model.ControlSession{User: u.ID, CSRF: out.CSRF, Expires: int64(out.Expires), Reauthenticated: s.now().Unix()}
			return nil
		})
	}
	// The session token and CSRF value were drawn above, and a refused attempt committed nothing, so
	// repeating the attempt against a fresher state is safe. A write that is stale because the node
	// is still catching up with the cluster (a restart is the common case) or lost the race for its
	// index to another control write is therefore waited out for loginStaleBudget instead of being
	// answered to the caller.
	wait, cancel := context.WithTimeout(ctx, loginStaleBudget)
	defer cancel()
	e := retryStale(wait, func() error { return attempt(wait) })
	return out, e
}
func (s *Service) Authenticate(ctx context.Context, token string) (Credential, error) {
	var out Credential
	e := s.store.View(ctx, func(st model.ControlState) error {
		if tokenRecord, ok := st.ServerTokens[s.serverTokenDigest(token)]; ok {
			user, exists := st.Users[tokenRecord.Principal.String()]
			if !exists || user.Disabled || tokenRecord.Revoked || tokenRecord.Expires <= s.now().Unix() {
				return model.Fail(model.Unauthenticated)
			}
			out = Credential{service: s, user: tokenRecord.Principal, token: token, machine: true}
			return nil
		}
		v, ok := st.Sessions[hashToken(token)]
		u := st.Users[v.User.String()]
		if !ok || v.Expires <= s.now().Unix() || u.ID == (model.ID{}) || u.Disabled {
			return model.Fail(model.Unauthenticated)
		}
		out = Credential{service: s, user: u.ID, token: token, fresh: v.Reauthenticated, admin: u.Admin}
		return nil
	})
	return out, e
}
func (s *Service) Session(ctx context.Context, token string) (Session, error) {
	var out Session
	e := s.store.View(ctx, func(st model.ControlState) error {
		v, ok := st.Sessions[hashToken(token)]
		if !ok || v.Expires <= s.now().Unix() || st.Users[v.User.String()].ID == (model.ID{}) || st.Users[v.User.String()].Disabled {
			return model.Fail(model.Unauthenticated)
		}
		out = Session{Token: token, CSRF: v.CSRF, User: v.User, Expires: model.Int64(v.Expires)}
		return nil
	})
	return out, e
}
func (s *Service) CheckCSRF(ctx context.Context, token, csrf string) error {
	v, e := s.Session(ctx, token)
	if e != nil {
		return e
	}
	if subtle.ConstantTimeCompare([]byte(v.CSRF), []byte(csrf)) != 1 {
		return model.Fail(model.Forbidden)
	}
	return nil
}
func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.Update(ctx, func(st *model.ControlState) error { delete(st.Sessions, hashToken(token)); return nil })
}
func (s *Service) Reauthenticate(ctx context.Context, token, p, code string) (Session, error) {
	c, e := s.Authenticate(ctx, token)
	if e != nil {
		return Session{}, e
	}
	var email string
	e = s.store.View(ctx, func(st model.ControlState) error { email = st.Users[c.user.String()].Email; return nil })
	if e != nil {
		return Session{}, e
	}
	out, e := s.Login(ctx, email, p, code)
	if e != nil {
		return Session{}, e
	}
	if e = s.Logout(ctx, token); e != nil {
		return Session{}, e
	}
	return out, nil
}
func (c Credential) Fresh() bool {
	return c.service != nil && !c.machine && c.fresh > c.service.now().Add(-5*time.Minute).Unix()
}
