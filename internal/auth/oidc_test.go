// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package auth_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/model"
	"testing"
	"time"
)

func TestOIDCIssuerStateNonceAndPKCE(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	var issuer, nonce, challenge, forgery string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "test", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
			w.WriteHeader(401)
			return
		}
		claimIssuer, claimNonce := issuer, nonce
		if forgery == "issuer" {
			claimIssuer = "https://foreign.example.test"
		}
		if forgery == "nonce" {
			claimNonce = "forged"
		}
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test"})
		payload, _ := json.Marshal(map[string]any{"iss": claimIssuer, "sub": "explicit-subject", "aud": "client", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(), "nonce": claimNonce})
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		hash := sha256.Sum256([]byte(input))
		signature, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture", "token_type": "Bearer", "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	issuer = server.URL
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, server.Client())
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	token, _ := store.BootstrapToken()
	session, e := service.Bootstrap(ctx, token, "owner@example.test", "correct horse battery staple 2026")
	if e != nil {
		t.Fatal(e)
	}
	cfg := auth.OIDCConfig{Issuer: issuer, ClientID: "client", RedirectURL: "https://soundpost.example.test/api/v1/oidc/callback", Subjects: map[string]model.ID{"explicit-subject": session.User}}
	for _, mode := range []string{"issuer", "nonce", "valid"} {
		forgery = mode
		start, err := service.OIDCStart(ctx, cfg, "browser-binding")
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(start)
		if err != nil {
			t.Fatal(err)
		}
		nonce = u.Query().Get("nonce")
		challenge = u.Query().Get("code_challenge")
		state := u.Query().Get("state")
		if nonce == "" || challenge == "" || u.Query().Get("code_challenge_method") != "S256" {
			t.Fatal("missing nonce/PKCE")
		}
		_, err = service.OIDCCallback(ctx, cfg, "browser-binding", state, "fixture-code")
		if mode == "valid" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			assertCode(t, err, model.Unauthenticated)
		}
		_, err = service.OIDCCallback(ctx, cfg, "browser-binding", state, "fixture-code")
		assertCode(t, err, model.Unauthenticated)
	}
}
