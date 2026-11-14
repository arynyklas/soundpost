// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/model"
	"testing"
	"time"
)

func fixtureTOTP(secret string, now time.Time) string {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[19] & 15
	number := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", number%1000000)
}
func TestTOTPAndRecoveryCodesAreOneUse(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1800000000, 0)
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	activateAuthControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	session, err := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := service.BeginTOTP(ctx, session.Token)
	if err != nil {
		t.Fatal(err)
	}
	codes, err := service.ConfirmTOTP(ctx, session.Token, fixtureTOTP(secret, now))
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatal("expected ten recovery codes")
	}
	_, err = service.Login(ctx, "owner@example.test", "correct horse battery staple 2026", fixtureTOTP(secret, now))
	assertCode(t, err, model.Unauthenticated)
	now = now.Add(30 * time.Second)
	code := fixtureTOTP(secret, now)
	if _, err = service.Login(ctx, "owner@example.test", "correct horse battery staple 2026", code); err != nil {
		t.Fatal(err)
	}
	_, err = service.Login(ctx, "owner@example.test", "correct horse battery staple 2026", code)
	assertCode(t, err, model.Unauthenticated)
	if _, err = service.Login(ctx, "owner@example.test", "correct horse battery staple 2026", codes[0]); err != nil {
		t.Fatal(err)
	}
	_, err = service.Login(ctx, "owner@example.test", "correct horse battery staple 2026", codes[0])
	assertCode(t, err, model.Unauthenticated)
	if err = store.View(ctx, func(st control.State) error {
		u := st.Users[session.User.String()]
		if u.TOTP == secret || u.TOTP == "" || len(u.Recovery) != 9 {
			t.Fatal("MFA secret/recovery durable state is incorrect")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
