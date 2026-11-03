// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"soundpost/internal/model"
	"time"
)

func totp(secret string, step int64) string {
	k, e := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if e != nil {
		return ""
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(step))
	h := hmac.New(sha1.New, k)
	h.Write(b[:])
	v := h.Sum(nil)
	o := v[len(v)-1] & 15
	n := binary.BigEndian.Uint32(v[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1000000)
}
func consumeFactor(u *model.ControlUser, code string, now time.Time) bool {
	step := now.Unix() / 30
	for d := int64(-1); d <= 1; d++ {
		n := step + d
		if n > u.LastTOTP && subtle.ConstantTimeCompare([]byte(totp(u.TOTP, n)), []byte(code)) == 1 {
			u.LastTOTP = n
			return true
		}
	}
	hash := hashToken(code)
	for i, v := range u.Recovery {
		if subtle.ConstantTimeCompare([]byte(v), []byte(hash)) == 1 {
			u.Recovery = append(u.Recovery[:i], u.Recovery[i+1:]...)
			return true
		}
	}
	return false
}
func (s *Service) BeginTOTP(ctx context.Context, token string) (string, error) {
	c, e := s.Authenticate(ctx, token)
	if e != nil {
		return "", e
	}
	if !c.Fresh() {
		return "", model.Fail(model.Forbidden)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(randomToken())[:20])
	sealed, err := s.store.Seal(secret)
	if err != nil {
		return "", model.Fail(model.Unavailable)
	}
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		u := st.Users[c.user.String()]
		u.PendingTOTP = sealed
		st.Users[c.user.String()] = u
		return nil
	})
	return secret, e
}
func (s *Service) ConfirmTOTP(ctx context.Context, token, code string) ([]string, error) {
	c, e := s.Authenticate(ctx, token)
	if e != nil {
		return nil, e
	}
	if !c.Fresh() {
		return nil, model.Fail(model.Forbidden)
	}
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		codes[i] = randomToken()
		hashes[i] = hashToken(codes[i])
	}
	e = s.store.Update(ctx, func(st *model.ControlState) error {
		if err := s.validateCredentialState(*st, c); err != nil {
			return err
		}
		u := st.Users[c.user.String()]
		secret, err := s.store.OpenSecret(u.PendingTOTP)
		if err != nil {
			return model.Fail(model.Unauthenticated)
		}
		if u.PendingTOTP == "" || totp(secret, s.now().Unix()/30) != code {
			return model.Fail(model.Unauthenticated)
		}
		u.TOTP = u.PendingTOTP
		u.PendingTOTP = ""
		u.LastTOTP = s.now().Unix() / 30
		u.Recovery = hashes
		st.Users[c.user.String()] = u
		return nil
	})
	if e != nil {
		return nil, e
	}
	return codes, nil
}
