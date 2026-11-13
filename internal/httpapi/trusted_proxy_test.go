// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package httpapi_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"soundpost/internal/auth"
	"soundpost/internal/control"
	"soundpost/internal/httpapi"
)

func TestClientAddrReadsForwardedForOnlyFromTrustedPeers(t *testing.T) {
	proxies, err := httpapi.ParseTrustedProxies("10.0.0.0/8, 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ remote, xff, want string }{
		"untrusted peer, spoofed header": {"203.0.113.7:4000", "1.2.3.4", "203.0.113.7"},
		"trusted peer, one hop":          {"10.1.2.3:4000", "198.51.100.5", "198.51.100.5"},
		"trusted peer, rightmost wins":   {"10.1.2.3:4000", "6.6.6.6, 198.51.100.5", "198.51.100.5"},
		"trusted chain skipped":          {"10.1.2.3:4000", "198.51.100.5, 10.9.9.9, 192.0.2.1", "198.51.100.5"},
		"trusted peer, no header":        {"10.1.2.3:4000", "", "10.1.2.3"},
		"trusted peer, garbage hop":      {"10.1.2.3:4000", "198.51.100.5, nonsense", "10.1.2.3"},
		"exact host entry":               {"192.0.2.1:1", "198.51.100.8:5555", "198.51.100.8"},
		"only trusted hops":              {"10.1.2.3:4000", "10.4.4.4", "10.1.2.3"},
		"v4-mapped trusted peer":         {"[::ffff:10.1.2.3]:4000", "198.51.100.5", "198.51.100.5"},
		"neighbour of the trusted host":  {"192.0.2.2:1", "198.51.100.8", "192.0.2.2"},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := proxies.ClientAddr(r); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if _, err = httpapi.ParseTrustedProxies("10.0.0.0/8,banana"); err == nil {
		t.Fatal("a malformed entry was accepted")
	}
	var none httpapi.TrustedProxies
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.1.2.3:1"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := none.ClientAddr(r); got != "10.1.2.3" {
		t.Fatalf("an empty set trusted a header: %q", got)
	}
}

// loginRig serves the real login route and posts failing logins from distinct email addresses,
// so only the per-source limit (50) can refuse them.
func loginRig(t *testing.T, proxies httpapi.TrustedProxies) func(i int, forwardedFor string) int {
	t.Helper()
	store, e := control.Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	service, e := auth.NewService(auth.AuthDependencies{Control: store})
	if e != nil {
		t.Fatal(e)
	}
	activateHTTPControl(t, store, t.TempDir())
	server := httptest.NewTLSServer(httpapi.NewServerBehind(proxies, "", service, nil).Handler)
	t.Cleanup(server.Close)
	client := server.Client()
	return func(i int, forwardedFor string) int {
		b, _ := json.Marshal(map[string]string{"Email": fmt.Sprintf("user%03d@example.test", i), "Password": "wrong password entirely"})
		req, _ := http.NewRequest("POST", server.URL+"/api/v1/login", bytes.NewReader(b))
		req.Header.Set("Origin", server.URL)
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
}

func TestLoginThrottleIgnoresForwardedForFromAnUntrustedPeer(t *testing.T) {
	post := loginRig(t, nil)
	limited := 0
	for i := range 55 { // each attempt claims to come from a different client
		if post(i, fmt.Sprintf("198.51.100.%d", i+1)) == http.StatusTooManyRequests {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("a spoofed X-Forwarded-For from an untrusted peer evaded the throttle")
	}
}

func TestLoginThrottleKeysOnTheForwardedClientBehindATrustedProxy(t *testing.T) {
	proxies, err := httpapi.ParseTrustedProxies("127.0.0.0/8,::1/128")
	if err != nil {
		t.Fatal(err)
	}
	post := loginRig(t, proxies)
	for i := range 52 {
		post(i, "198.51.100.1")
	}
	if got := post(60, "198.51.100.1"); got != http.StatusTooManyRequests {
		t.Fatalf("the abusive client behind the proxy was not throttled: %d", got)
	}
	if got := post(61, "198.51.100.2"); got == http.StatusTooManyRequests {
		t.Fatal("another client behind the same proxy was throttled with it")
	}
	// A client that pads the header on its left gains nothing: the rightmost untrusted hop is
	// the one the proxy saw.
	if got := post(62, "198.51.100.3, 198.51.100.1"); got != http.StatusTooManyRequests {
		t.Fatalf("a client forged a leftward hop: %d", got)
	}
}
