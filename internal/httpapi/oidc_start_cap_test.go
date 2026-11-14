// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/arynyklas/soundpost/internal/auth"
	"github.com/arynyklas/soundpost/internal/control"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fullOIDCStore reports auth.MaxPendingOIDC live pending logins in every read and
// counts writes, so the route's refusal can be observed without 1024 real starts.
type fullOIDCStore struct {
	*control.Store
	updates atomic.Int64
	full    atomic.Bool
}

func (s *fullOIDCStore) View(ctx context.Context, fn func(model.ControlState) error) error {
	return s.Store.View(ctx, func(st model.ControlState) error {
		if s.full.Load() {
			oidc := map[string]json.RawMessage{}
			for k, v := range st.OIDC {
				oidc[k] = v
			}
			for i := 0; i < auth.MaxPendingOIDC; i++ {
				state := "fixture-state-" + strconv.Itoa(i)
				sum := sha256.Sum256([]byte(state))
				raw, _ := json.Marshal(map[string]any{"State": state, "Expires": time.Now().Add(time.Hour).Unix()})
				oidc[hex.EncodeToString(sum[:])] = raw
			}
			st.OIDC = oidc
		}
		return fn(st)
	})
}
func (s *fullOIDCStore) Update(ctx context.Context, fn func(*model.ControlState) error) error {
	s.updates.Add(1)
	return s.Store.Update(ctx, fn)
}

func TestOIDCStartRefusedAtCapWithoutFetchOrWrite(t *testing.T) {
	var fetches atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fetches.Add(1); http.Error(w, "no", 500) }))
	defer provider.Close()
	inner, err := control.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()
	store := &fullOIDCStore{Store: inner}
	service, err := auth.NewService(auth.AuthDependencies{Control: store})
	if err != nil {
		t.Fatal(err)
	}
	store.full.Store(true)
	cfg := auth.OIDCConfig{Issuer: provider.URL, ClientID: "c", RedirectURL: "https://soundpost.example.test/api/v1/oidc/callback"}
	server := httptest.NewTLSServer(httpapi.NewServer("", service, &cfg).Handler)
	defer server.Close()
	updates := store.updates.Load()
	req, _ := http.NewRequest("POST", server.URL+"/api/v1/oidc/start", bytes.NewBufferString(`{}`))
	req.Header.Set("Origin", server.URL)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var fault model.Fault
	_ = json.NewDecoder(resp.Body).Decode(&fault)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") == "" || fault.Code != model.Unavailable || !fault.Retryable {
		t.Fatalf("status %d retry-after %q fault %+v", resp.StatusCode, resp.Header.Get("Retry-After"), fault)
	}
	if fetches.Load() != 0 || store.updates.Load() != updates {
		t.Fatalf("fetches %d, state writes %d at cap", fetches.Load(), store.updates.Load()-updates)
	}
}
