// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"golang.org/x/crypto/argon2"
	"soundpost/internal/model"
	"strings"
	"time"
)

type ControlStore interface {
	View(context.Context, func(model.ControlState) error) error
	Update(context.Context, func(*model.ControlState) error) error
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
}
type Session struct {
	Token   string   `json:"-"`
	CSRF    string   `json:"csrf"`
	User    model.ID `json:"user"`
	Expires int64    `json:"expires,string"`
}
type Credential struct {
	service *Service
	user    model.ID
	token   string
	fresh   int64
	admin   bool
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
	return &Service{store: d.Control, now: d.Now, bearerHashKey: key}, nil
}
func password(p string, salt string) string {
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
func (s *Service) Bootstrap(ctx context.Context, token, email, p string) (Session, error) {
	h, e := hashPassword(p)
	if e != nil {
		return Session{}, e
	}
	id := model.NewID()
	out := s.newSession(id)
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		if st.BootstrapHash == "" || subtle.ConstantTimeCompare([]byte(st.BootstrapHash), []byte(hashToken(token))) != 1 {
			return model.Fail(model.Unauthenticated)
		}
		if !validEmail(email) {
			return model.Fail(model.Invalid)
		}
		st.Users[id.String()] = model.ControlUser{ID: id, Email: email, Password: h, Admin: true}
		st.BootstrapHash = ""
		st.Sessions[hashToken(out.Token)] = model.ControlSession{User: id, CSRF: out.CSRF, Expires: out.Expires, Reauthenticated: s.now().Unix()}
		return nil
	})
	if e != nil {
		return Session{}, e
	}
	_ = s.store.RemoveBootstrapFile()
	return out, nil
}
func validEmail(v string) bool {
	return len(v) < 255 && strings.Contains(v, "@") && strings.TrimSpace(v) == v
}
func (s *Service) newSession(id model.ID) Session {
	return Session{Token: randomToken(), CSRF: randomToken(), User: id, Expires: s.now().Add(12 * time.Hour).Unix()}
}
func (s *Service) Login(ctx context.Context, email, p, code string) (Session, error) {
	out := s.newSession(model.ID{})
	e := s.store.Update(ctx, func(st *model.ControlState) error {
		for k, u := range st.Users {
			if u.Email != email || u.Disabled {
				continue
			}
			if !checkPassword(u.Password, p) {
				return model.Fail(model.Unauthenticated)
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
				st.Users[k] = u
			}
			out.User = u.ID
			st.Sessions[hashToken(out.Token)] = model.ControlSession{User: u.ID, CSRF: out.CSRF, Expires: out.Expires, Reauthenticated: s.now().Unix()}
			return nil
		}
		return model.Fail(model.Unauthenticated)
	})
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
		out = Session{Token: token, CSRF: v.CSRF, User: v.User, Expires: v.Expires}
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
