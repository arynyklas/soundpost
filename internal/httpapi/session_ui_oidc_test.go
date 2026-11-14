// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"golang.org/x/oauth2"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSessionUIOIDCNegotiation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, nonce, challenge, claimIssuer string
	providerMux := http.NewServeMux()
	providerMux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	providerMux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "ui", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": "AQAB"}}})
	})
	providerMux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		nonce = q.Get("nonce")
		challenge = q.Get("code_challenge")
		if q.Get("code_challenge_method") != "S256" || nonce == "" {
			http.Error(w, "invalid", 400)
			return
		}
		target, _ := url.Parse(q.Get("redirect_uri"))
		v := target.Query()
		v.Set("code", "real-fixture-code")
		v.Set("state", q.Get("state"))
		target.RawQuery = v.Encode()
		http.Redirect(w, r, target.String(), 303)
	})
	providerMux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "real-fixture-code" || oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) != challenge {
			http.Error(w, "invalid", 401)
			return
		}
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "ui"})
		claims, _ := json.Marshal(map[string]any{"iss": claimIssuer, "sub": "mapped", "aud": "ui-client", "nonce": nonce, "exp": time.Now().Add(time.Minute).Unix()})
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
		digest := sha256.Sum256([]byte(input))
		signature, e := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if e != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "fixture", "token_type": "Bearer", "id_token": input + "." + base64.RawURLEncoding.EncodeToString(signature)})
	})
	provider := httptest.NewTLSServer(providerMux)
	defer provider.Close()
	issuer = provider.URL
	store, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	activateHTTPControl(t, store, t.TempDir())
	token, _ := store.BootstrapToken()
	owner, err := service.Bootstrap(context.Background(), token, "oidc-ui@example.test", "generic UI fixture password 2026")
	if err != nil {
		t.Fatal(err)
	}
	cfg := auth.OIDCConfig{Issuer: issuer, ClientID: "ui-client", Subjects: map[string]model.ID{"mapped": owner.User}}
	var client *http.Client
	server := httptest.NewUnstartedServer(nil)
	cfg.RedirectURL = "https://" + server.Listener.Addr().String() + "/api/v1/oidc/callback"
	handler := httpapi.NewServer("", service, &cfg).Handler
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), oauth2.HTTPClient, client)))
	})
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(provider.Certificate())
	roots.AddCert(server.Certificate())
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	for _, accept := range []string{"application/json", "text/html", "text/html;q=0", "application/json; note=\"text/html\"", ""} {
		for _, valid := range []bool{true, false} {
			client.Jar, _ = cookiejar.New(nil)
			claimIssuer = issuer
			if !valid {
				claimIssuer = "https://wrong.example.test"
			}
			req, _ := http.NewRequest("POST", server.URL+"/api/v1/oidc/start", bytes.NewBufferString(`{}`))
			req.Header.Set("Origin", server.URL)
			resp, e := client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			var start struct {
				URL string `json:"url"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&start)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("start %d", resp.StatusCode)
			}
			resp, e = client.Get(start.URL)
			if e != nil {
				t.Fatal(e)
			}
			callback := resp.Header.Get("Location")
			resp.Body.Close()
			if callback == "" {
				t.Fatal("provider redirect missing")
			}
			req, _ = http.NewRequest("GET", callback, nil)
			req.Header.Set("Accept", accept)
			resp, e = client.Do(req)
			if e != nil {
				t.Fatal(e)
			}
			resp.Body.Close()
			if accept == "text/html" {
				target := "/"
				if !valid {
					target = "/?auth=failed"
				}
				if resp.StatusCode != 303 || resp.Header.Get("Location") != target {
					t.Fatalf("HTML callback %d %q", resp.StatusCode, resp.Header.Get("Location"))
				}
			} else {
				expected := 401
				if valid {
					expected = 200
				}
				if resp.StatusCode != expected {
					t.Fatalf("JSON callback %q %d", accept, resp.StatusCode)
				}
			}
			check, e := client.Get(server.URL + "/api/v1/session")
			if e != nil {
				t.Fatal(e)
			}
			check.Body.Close()
			expected := 401
			if valid {
				expected = 200
			}
			if check.StatusCode != expected {
				t.Fatalf("session %d", check.StatusCode)
			}
		}
	}
}
