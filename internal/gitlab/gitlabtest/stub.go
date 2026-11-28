// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0

// Package gitlabtest is a local stand-in for a GitLab instance, for the tests of
// the GitLab integration. NO real GitLab instance is involved.
//
// The stub listens on the host's own non-loopback IPv4 address, which a test
// allows with an egress allow-list prefix exactly as an administrator would, so the
// production dialer and egress rules run unchanged (no test seam is involved).
package gitlabtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// Issue is one issue the stub holds.
type Issue struct {
	IID         int
	Title       string
	Description string
	Labels      string
}

// Behaviour is how the stub answers; the zero value is a healthy GitLab.
type Behaviour struct {
	// PostStatus, when set, answers every issue creation with this status without
	// creating anything.
	PostStatus int
	// CreateThenFail creates the issue and then answers this status.
	CreateThenFail int
	// PostDelay holds an issue creation back.
	PostDelay time.Duration
}

// Server is the stub.
type Server struct {
	// URL is the base URL of the stub (https, the host's own address).
	URL string
	// Pool trusts the stub's certificate.
	Pool *x509.CertPool
	// Allow is the egress allow-list prefix that admits the stub's address.
	Allow netip.Prefix

	mu     sync.Mutex
	issues []*Issue
	posts  int
	tokens []string
	b      Behaviour
}

// LocalAddress is a usable non-loopback, non-link-local IPv4 address of this host.
// The test is skipped when there is none.
func LocalAddress(t testing.TB) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP.To4())
		if ok && ip.IsValid() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() {
			return ip
		}
	}
	t.Skip("this host has no non-loopback IPv4 address for the stub GitLab")
	return netip.Addr{}
}

func selfSigned(t testing.TB, ip netip.Addr) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "stub gitlab"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{ip.AsSlice()}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// New starts the stub; it serves the project "shop/web" (issues, notes) and
// GET /personal_access_tokens/self, and stops with the test.
func New(t testing.TB) *Server {
	t.Helper()
	ip := LocalAddress(t)
	cert, pool := selfSigned(t, ip)
	s := &Server{Pool: pool, Allow: netip.PrefixFrom(ip, 32)}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(s.serve))
	_ = srv.Listener.Close()
	srv.Listener = listener
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	s.URL = "https://" + listener.Addr().String()
	return s
}

// Set changes how the stub answers.
func (s *Server) Set(f func(*Behaviour)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.b)
}

// Posts is the number of issue creations the stub received.
func (s *Server) Posts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts
}

// Issues is a copy of the issues the stub holds.
func (s *Server) Issues() []Issue {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Issue, len(s.issues))
	for i, it := range s.issues {
		out[i] = *it
	}
	return out
}

// Tokens are the PRIVATE-TOKEN header values of every request received.
func (s *Server) Tokens() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.tokens...)
}

func (s *Server) webURL(it *Issue) string {
	return fmt.Sprintf("%s/shop/web/-/issues/%d", s.URL, it.IID)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.tokens = append(s.tokens, r.Header.Get("PRIVATE-TOKEN"))
	s.mu.Unlock()
	path := r.URL.EscapedPath()
	const issues = "/api/v4/projects/shop%2Fweb/issues"
	switch {
	case r.Method == "GET" && path == "/api/v4/personal_access_tokens/self":
		_, _ = w.Write([]byte(`{"active":true,"revoked":false,"scopes":["api"],"expires_at":"2027-03-04"}`))
	case r.Method == "GET" && path == issues:
		s.mu.Lock()
		var out []map[string]any
		for _, it := range s.issues {
			if strings.Contains(it.Description, r.URL.Query().Get("search")) {
				out = append(out, map[string]any{"iid": it.IID, "web_url": s.webURL(it), "description": it.Description})
			}
		}
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(out)
	case r.Method == "POST" && path == issues:
		s.mu.Lock()
		s.posts++
		b := s.b
		s.mu.Unlock()
		time.Sleep(b.PostDelay)
		if b.PostStatus != 0 {
			w.WriteHeader(b.PostStatus)
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		s.mu.Lock()
		it := &Issue{IID: len(s.issues) + 1, Title: in["title"], Description: in["description"], Labels: in["labels"]}
		s.issues = append(s.issues, it)
		s.mu.Unlock()
		if b.CreateThenFail != 0 {
			w.WriteHeader(b.CreateThenFail)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"iid": it.IID, "web_url": s.webURL(it), "description": it.Description})
	default:
		http.NotFound(w, r)
	}
}
