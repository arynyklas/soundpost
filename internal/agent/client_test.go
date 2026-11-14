// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/model"
)

func testBatch() model.Batch {
	res, id := testIDs()
	bits := model.FloatBits(0x3ff0000000000000)
	rec := model.Record{ID: model.NewID(), Kind: model.Metric, ObservedAt: 1, Resource: res, Payload: model.Payload{Metric: &model.MetricPoint{Name: "m", Labels: model.Labels{}, SampleKind: "float", Value: &bits, Unit: "1", Type: "gauge"}}}
	slot, _ := model.OwnerSlot(id.Org, id.Project, id.Source, model.ID{7}, rec)
	return model.Batch{Version: 1, Project: id.Project, Source: id.Source, Producer: model.ID{7}, ID: model.NewID(), PolicyRevision: 1, RouteSlot: slot, Records: []model.Record{rec}}
}

func clientFor(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := NewClient(srv.URL, writeCA(t, srv), []byte(testToken), 0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func faultBody(code model.Code, retryable bool) string {
	raw, _ := json.Marshal(map[string]any{"code": code, "retryable": retryable, "detail": "SERVER-DETAIL-CANARY", "request_id": model.NewID()})
	return string(raw)
}

func TestClientMapsRefusalsToTypedContentFreeFaults(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		body      string
		code      model.Code
		retryable bool
	}{
		{"quota", 429, faultBody(model.Quota, true), model.Quota, true},
		{"unauthenticated", 401, faultBody(model.Unauthenticated, false), model.Unauthenticated, false},
		{"forbidden", 403, faultBody(model.Forbidden, false), model.Forbidden, false},
		{"invalid is permanent", 422, faultBody(model.Invalid, false), model.Invalid, false},
		{"conflict", 409, faultBody(model.Conflict, false), model.Conflict, false},
		{"unavailable without body", 503, "", model.Unavailable, true},
		{"unknown code collapses", 500, `{"code":"made_up","retryable":false}`, model.Unavailable, true},
		{"html error page", 502, "<html>proxy error</html>", model.Unavailable, true},
	}
	for _, tc := range cases {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		_, err := clientFor(t, srv).Admit(context.Background(), testBatch())
		srv.Close()
		var f *model.Fault
		if !errors.As(err, &f) || f.Code != tc.code || f.Retryable != tc.retryable {
			t.Fatalf("%s: got %v, want %s retryable=%v", tc.name, err, tc.code, tc.retryable)
		}
		if strings.Contains(err.Error(), "CANARY") || strings.Contains(err.Error(), "proxy") {
			t.Fatalf("%s: server text relayed: %v", tc.name, err)
		}
	}
}

func TestClientReceiptMustMatchTheBatch(t *testing.T) {
	b := testBatch()
	good := model.Receipt{Version: 1, BatchID: b.ID, Cursor: model.Cursor{Group: model.ID{1}, Index: 5}}
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"matching receipt": {mustJSON(t, good), true},
		"other batch":      {mustJSON(t, model.Receipt{Version: 1, BatchID: model.ID{9}, Cursor: good.Cursor}), false},
		"zero version":     {mustJSON(t, model.Receipt{BatchID: b.ID, Cursor: good.Cursor}), false},
		"not json":         {"ok", false},
		"unknown field":    {`{"version":1,"batch_id":"` + b.ID.String() + `","surprise":1}`, false},
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(tc.body)) }))
		r, err := clientFor(t, srv).Admit(context.Background(), b)
		srv.Close()
		if (err == nil) != tc.ok {
			t.Fatalf("%s: receipt %+v err %v", name, r, err)
		}
		if err != nil {
			var f *model.Fault
			if !errors.As(err, &f) || f.Code != model.Corrupt {
				t.Fatalf("%s: got %v, want corrupt", name, err)
			}
		}
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestClientTransportFailureLeaksNeitherAddressNorToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	c := clientFor(t, srv)
	addr := strings.TrimPrefix(srv.URL, "https://")
	srv.Close() // connection refused from now on
	_, err := c.Admit(context.Background(), testBatch())
	var f *model.Fault
	if !errors.As(err, &f) || f.Code != model.Unavailable || !f.Retryable || f.SafeDetail != "transport" {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), addr) || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), testToken) {
		t.Fatalf("transport error leaks the destination or credential: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Admit(ctx, testBatch())
	if !errors.As(err, &f) || f.Retryable {
		t.Fatalf("a cancelled submission must not be retryable: %v", err)
	}
}

// The bearer credential must never follow a redirect to another origin.
func TestClientNeverFollowsRedirects(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/ingest/v1/batches", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	_, err := clientFor(t, srv).Admit(context.Background(), testBatch())
	if err == nil {
		t.Fatal("a redirect was treated as success")
	}
	if elsewhere.Load() != 0 {
		t.Fatalf("the redirect target received %d requests carrying the credential", elsewhere.Load())
	}
}

func TestClientRefusesAnUntrustedServerCertificate(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an untrusted server received a request")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	srv.StartTLS()
	defer srv.Close()
	// httptest servers share one built-in certificate; the trust root here is
	// that one, while the server presents a different self-signed certificate
	trusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer trusted.Close()
	c, err := NewClient(srv.URL, writeCA(t, trusted), []byte(testToken), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Admit(context.Background(), testBatch()); err == nil {
		t.Fatal("a certificate outside the configured trust root was accepted")
	}
}

func TestReadCredentialRefusesLooseOrMalformedFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, mode)
		return p
	}
	tok, err := ReadCredential(write("ok", testToken+"\n", 0600))
	if err != nil || string(tok) != testToken {
		t.Fatalf("%q %v", tok, err)
	}
	for name, p := range map[string]string{
		"empty":      write("empty", "\n", 0600),
		"two tokens": write("two", "a b\n", 0600),
		"multi line": write("multi", "a\nb\n", 0600),
		"missing":    filepath.Join(dir, "nope"),
		"huge":       write("huge", strings.Repeat("x", 5000), 0600),
		"nul":        write("nul", "ab\x00c", 0600),
	} {
		if _, err := ReadCredential(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := ReadCredential(write("loose", testToken, 0644)); err == nil {
			t.Error("a group/world readable credential file was accepted")
		}
		if _, err := ReadCredential(write("group", testToken, 0640)); err == nil {
			t.Error("a group readable credential file was accepted")
		}
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "other"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
