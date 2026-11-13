// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"soundpost/internal/auth"
	"soundpost/internal/model"
	"soundpost/internal/notify/providers"
)

func privateAddress(t *testing.T) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipnet.IP); ok && ip.Unmap().Is4() && ip.Unmap().IsPrivate() && !ip.IsLoopback() {
				return ip.Unmap()
			}
		}
	}
	t.Skip("no private (RFC 1918) IPv4 interface: the egress policy forbids loopback receivers")
	return netip.Addr{}
}

type webhookPost struct {
	header http.Header
	body   []byte
}

// webhookReceiver is a TLS receiver on a private interface; caPath holds its CA.
func webhookReceiver(t *testing.T, ip netip.Addr, caPath string) (url string, posts func() []webhookPost) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "soundpost serve test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "receiver"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.IP(ip.AsSlice())}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []webhookPost
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, webhookPost{header: r.Header.Clone(), body: body})
		mu.Unlock()
		w.Header().Set("Soundpost-Receipt-ID", "receiver-receipt-1")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return "https://" + listener.Addr().String() + "/hook", func() []webhookPost {
		mu.Lock()
		defer mu.Unlock()
		return append([]webhookPost(nil), got...)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// api is a minimal HTTPS client of the served process.
type api struct {
	t      *testing.T
	base   string
	client *http.Client
	csrf   string
}

func (a *api) do(method, path string, body any, headers map[string]string) (int, []byte) {
	a.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, a.base+path, reader)
	if err != nil {
		a.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", a.base)
	if a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (a *api) command(org model.ID, kind string, payload auth.AdminPayload) {
	a.t.Helper()
	payload.Reason = "serve acceptance"
	body, _ := json.Marshal(payload)
	// The runner commits to the same control state, so the revision read may be stale.
	for attempt := 0; ; attempt++ {
		code, raw := a.do("POST", "/api/v1/admin/read", map[string]any{"kind": "organizations"}, nil)
		var read struct {
			Revision model.Revision `json:"revision"`
		}
		if code != 200 || json.Unmarshal(raw, &read) != nil {
			a.t.Fatalf("admin read %d: %s", code, raw)
		}
		code, raw = a.do("POST", "/api/v1/admin/commands", map[string]any{"command_id": model.NewID(), "expected_revision": read.Revision, "org_id": org, "kind": kind, "payload": json.RawMessage(body)}, nil)
		if code == 409 && attempt < 8 {
			continue
		}
		if code >= 300 {
			a.t.Fatalf("%s: %d %s", kind, code, raw)
		}
		return
	}
}

// The acceptance of owner decision D1 on the real serve path: a served process
// (re-executed real main) with no human logged in turns an ingested error into an
// issue, opens an incident, and delivers a signed webhook notification to a TLS receiver
// on a private interface, then audits the incident as system:runner.
func TestServeDeliversANotificationAfterAnIncidentOpensWithNoHumanLoggedIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes and signals")
	}
	ip := privateAddress(t)
	work := t.TempDir()
	caPath := filepath.Join(work, "receiver-ca.pem")
	hookURL, posts := webhookReceiver(t, ip, caPath)
	dir := filepath.Join(work, "data")
	port := freePort(t)
	listen := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	cmd, lines, errOut := serveChild(t, "--data-dir", dir, "--listen", listen, "--worker-interval", "100ms",
		"--public-origin", "https://soundpost.example.test", "--notify-egress-allow", netip.PrefixFrom(ip, 32).String(), "--notify-ca-file", caPath)
	defer cmd.Process.Kill()
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range lines {
		}
	}()

	// The served node's own generated certificate is the trust anchor of the client.
	var client *http.Client
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		pemBytes, err := os.ReadFile(filepath.Join(dir, "server.crt"))
		if err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pemBytes) {
				jar, _ := cookiejar.New(nil)
				client = &http.Client{Jar: jar, Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
				if resp, err := client.Get("https://" + listen + "/readyz"); err == nil {
					resp.Body.Close()
					if resp.StatusCode == 200 {
						break
					}
				}
			}
		}
		client = nil
		time.Sleep(200 * time.Millisecond)
	}
	if client == nil {
		t.Fatalf("serve never became ready; stderr:\n%s", errOut.String())
	}
	a := &api{t: t, base: "https://" + listen, client: client}

	// Provision as the bootstrap administrator, then sign out: nobody is logged in after this.
	token, err := os.ReadFile(filepath.Join(dir, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	password := "serve acceptance password 2026"
	code, raw := a.do("POST", "/api/v1/bootstrap", map[string]string{"Token": strings.TrimSpace(string(token)), "Email": "owner@example.test", "Password": password}, nil)
	var session struct {
		CSRF string `json:"csrf"`
	}
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("bootstrap %d: %s", code, raw)
	}
	a.csrf = session.CSRF
	org, project, source, dest := model.NewID(), model.NewID(), model.NewID(), model.NewID()
	a.command(org, "create_org", auth.AdminPayload{Name: "serve acceptance"})
	a.command(org, "create_project", auth.AdminPayload{ID: project, Name: "serve acceptance project"})
	secret := "serve acceptance webhook secret 0123456789"
	destination, _ := json.Marshal(auth.DestinationConfig{Type: "webhook", Endpoint: hookURL, Enabled: true})
	a.command(org, "destination", auth.AdminPayload{ID: dest, Config: destination, Secret: secret})
	service, environment, build := model.NewID(), model.NewID(), model.NewID()
	resource := model.Resource{Service: service, Environment: environment, Build: build, Instance: "opaque-instance", Labels: model.Labels{}}
	policy := model.SourcePolicy{Revision: 1, Enabled: true, Class: "structured", Kinds: []model.Kind{model.ErrorKind},
		Resources:     model.ResourceRegistry{Services: []model.ID{service}, Environments: []model.ID{environment}, Builds: []model.ID{build}, Instances: []string{"opaque-instance"}},
		RetentionDays: map[model.Kind]uint32{model.ErrorKind: 30}, MaxBytes: 64 << 20, MaxSeries: 100}
	code, raw = a.do("POST", "/api/v1/sources", auth.SourceOnboarding{CommandID: model.NewID(), Org: org, Project: project, Source: source, Origins: []string{},
		Expires: model.UnixNano(time.Now().Add(time.Hour).UnixNano()), Policy: policy, Reason: "serve acceptance"}, nil)
	var onboarded auth.SourceOnboarded
	if code != 200 || json.Unmarshal(raw, &onboarded) != nil || onboarded.Credential == "" {
		t.Fatalf("source onboarding %d: %s", code, raw)
	}
	if code, raw = a.do("POST", "/api/v1/logout", nil, nil); code >= 300 {
		t.Fatalf("logout %d: %s", code, raw)
	}
	a.csrf = ""
	if code, _ = a.do("GET", "/api/v1/session", nil, nil); code != 401 {
		t.Fatalf("a session is still open (%d)", code)
	}

	// The only actor from here on is the source credential of an SDK: it ingests one error.
	producer := model.NewID()
	record := model.Record{ID: model.NewID(), Kind: model.ErrorKind, ObservedAt: model.UnixNano(time.Now().UnixNano()), Resource: resource,
		Payload: model.Payload{Error: &model.ErrorOccurrence{Occurrence: model.NewID(), Class: "PaymentFailed", Mechanism: "manual", Build: build, Fatal: true, Frames: []model.Frame{}}}}
	batch := model.Batch{Version: 1, Project: project, Source: source, Producer: producer, ID: model.NewID(), PolicyRevision: 1, Records: []model.Record{record}}
	if batch.RouteSlot, err = model.OwnerSlot(org, project, source, producer, record); err != nil {
		t.Fatal(err)
	}
	// A new source becomes usable once its onboarding fence drains (a few hundred ms).
	for deadline = time.Now().Add(30 * time.Second); ; time.Sleep(250 * time.Millisecond) {
		code, raw = a.do("POST", "/ingest/v1/batches", batch, map[string]string{"Authorization": "Bearer " + onboarded.Credential, "Origin": ""})
		if code == 200 {
			break
		}
		if code != 403 || time.Now().After(deadline) {
			t.Fatalf("ingest %d: %s", code, raw)
		}
	}

	var post webhookPost
	for deadline = time.Now().Add(90 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if got := posts(); len(got) > 0 {
			post = got[0]
			break
		}
	}
	if post.body == nil {
		t.Fatalf("no notification reached the receiver; stderr:\n%s", errOut.String())
	}
	ts, _ := strconv.ParseInt(post.header.Get(providers.HeaderTimestamp), 10, 64)
	if want := providers.Sign([]byte(secret), ts, post.header.Get(providers.HeaderDeliveryID), post.body); post.header.Get(providers.HeaderSignature) != want {
		t.Fatal("the delivery's signature does not verify with the destination secret")
	}
	var body struct {
		Org    model.ID `json:"org_id"`
		Entity struct {
			Kind string `json:"kind"`
		} `json:"entity"`
	}
	if err = json.Unmarshal(post.body, &body); err != nil || body.Org != org || body.Entity.Kind != "incident" {
		t.Fatalf("the notification is not about an incident of the organization: %s (%v)", post.body, err)
	}

	// The incident and the delivery are audited as system:runner (a new sign-in only reads the audit).
	code, raw = a.do("POST", "/api/v1/login", map[string]string{"Email": "owner@example.test", "Password": password}, nil)
	if code != 200 || json.Unmarshal(raw, &session) != nil {
		t.Fatalf("login %d: %s", code, raw)
	}
	a.csrf = session.CSRF
	code, raw = a.do("POST", "/api/v1/admin/read", map[string]any{"kind": "audit", "org_id": org}, nil)
	if code != 200 {
		t.Fatalf("audit read %d: %s", code, raw)
	}
	var audit struct {
		Audits []struct {
			Principal model.ID `json:"principal"`
			Action    string   `json:"action"`
		} `json:"audits"`
	}
	if err = json.Unmarshal(raw, &audit); err != nil {
		t.Fatalf("audit %s: %v", raw, err)
	}
	seen := map[string]bool{}
	for _, e := range audit.Audits {
		if auth.IsSystemPrincipal(e.Principal) && e.Principal == auth.SystemPrincipal(org) {
			seen[e.Action] = true
		}
	}
	if !seen["incidents.open"] {
		t.Fatalf("no incident open audited as %s: %v", auth.SystemRunner, audit.Audits)
	}
	hasDelivery := false
	for action := range seen {
		hasDelivery = hasDelivery || strings.HasPrefix(action, "notify.delivery.")
	}
	if !hasDelivery {
		t.Fatalf("no delivery transition audited as %s: %v", auth.SystemRunner, seen)
	}
	if err = cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-drained:
	case <-time.After(30 * time.Second):
		t.Fatalf("serve did not stop after SIGINT; stderr:\n%s", errOut.String())
	}
	if err = cmd.Wait(); err != nil {
		t.Fatalf("serve did not exit cleanly: %v\n%s", err, errOut.String())
	}
}
