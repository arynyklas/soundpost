// Copyright 2026 Aryn Yklas
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/arynyklas/soundpost/internal/health"
	"github.com/arynyklas/soundpost/internal/httpapi"
	"github.com/arynyklas/soundpost/internal/model"
)

const readyCanary = "SOUNDPOST_READY_CLI_CANARY"

// readyServer serves the real /readyz route over TLS and returns its URL and a PEM file that
// trusts exactly its certificate.
func readyServer(t *testing.T, decide httpapi.ReadyFunc) (url, caPath string) {
	t.Helper()
	mux := http.NewServeMux()
	httpapi.RegisterHealthRoutes(mux, decide)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server.URL, writeCA(t, server)
}

func writeCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func ready(version string) httpapi.ReadyFunc {
	return func(context.Context) (health.Readiness, error) {
		c := model.Cursor{Group: model.NewID(), Index: 12}
		return health.Readiness{Ready: true, Version: version, Applied: &c}, nil
	}
}

func unready(r health.Reason) httpapi.ReadyFunc {
	return func(context.Context) (health.Readiness, error) { return health.Unready(r), nil }
}

func readyJSON(t *testing.T, args ...string) (health.Readiness, error) {
	t.Helper()
	var out bytes.Buffer
	err := runReady(append([]string{"--json"}, args...), &out)
	var got health.Readiness
	if jsonErr := json.Unmarshal(out.Bytes(), &got); jsonErr != nil {
		t.Fatalf("stdout is not one JSON answer: %q (%v)", out.String(), jsonErr)
	}
	return got, err
}

// Exit status 0 only for a verified 200 ready=true answer from a server we trust; its
// version and applied cursor reach stdout.
func TestReadyExitsZeroOnlyForAReadyServer(t *testing.T) {
	url, ca := readyServer(t, ready("7.7.7"))
	got, err := readyJSON(t, "--url", url, "--ca-cert", ca)
	if err != nil || !got.Ready || got.Version != "7.7.7" || got.Applied == nil || got.Applied.Index != 12 {
		t.Fatalf("ready server: %+v %v", got, err)
	}
	var text bytes.Buffer
	if err = runReady([]string{"--url", url, "--ca-cert", ca}, &text); err != nil || !strings.HasPrefix(text.String(), "ready version=7.7.7") {
		t.Fatalf("text mode: %q %v", text.String(), err)
	}

	url, ca = readyServer(t, unready(health.ReasonNoQuorum))
	got, err = readyJSON(t, "--url", url, "--ca-cert", ca)
	if !errors.Is(err, errNotReady) || got.Ready || got.Reason != health.ReasonNoQuorum {
		t.Fatalf("unready server must fail with its reason: %+v %v", got, err)
	}
	text.Reset()
	if err = runReady([]string{"--url", url, "--ca-cert", ca}, &text); !errors.Is(err, errNotReady) || text.String() != "not ready: no_quorum\n" {
		t.Fatalf("text mode unready: %q %v", text.String(), err)
	}
}

// Not being able to ask is not "ready" either, and never succeeds by disabling verification.
func TestReadyTreatsEveryFailureToAskAsNotReady(t *testing.T) {
	url, ca := readyServer(t, ready("1"))
	// httptest servers all share one built-in certificate, so a genuinely different CA is made
	// the way an installation makes its own.
	otherDir := filepath.Join(t.TempDir(), "other")
	if err := preparePrivate(otherDir, ""); err != nil {
		t.Fatal(err)
	}
	otherCA, _, err := localTLS(otherDir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	closed := httptest.NewTLSServer(http.NotFoundHandler())
	closedURL, closedCA := closed.URL, writeCA(t, closed)
	closed.Close()

	// A plain HTTP server that says ready: the answer must never be believed, nor even asked for.
	asked := false
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = true
		_, _ = w.Write([]byte(`{"ready":true,"version":"1"}`))
	}))
	defer plain.Close()
	if got, err := readyJSON(t, "--url", plain.URL); !errors.Is(err, errNotReady) || got.Ready || got.Reason != health.ReasonUnreachable || asked {
		t.Fatalf("plain http: %+v %v asked=%v", got, err, asked)
	}

	notPEM := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"server certificate is not trusted (system roots)": {"--url", url},
		"a different CA":              {"--url", url, "--ca-cert", otherCA},
		"nothing listening":           {"--url", closedURL, "--ca-cert", closedCA},
		"plain http is refused":       {"--url", strings.Replace(url, "https://", "http://", 1), "--ca-cert", ca},
		"credentials in the URL":      {"--url", strings.Replace(url, "https://", "https://user:"+readyCanary+"@", 1), "--ca-cert", ca},
		"a path in the URL":           {"--url", url + "/elsewhere", "--ca-cert", ca},
		"missing CA file":             {"--url", url, "--ca-cert", filepath.Join(t.TempDir(), "absent.pem")},
		"CA file without a cert":      {"--url", url, "--ca-cert", notPEM},
		"data-dir without server.crt": {"--url", url, "--data-dir", t.TempDir()},
	} {
		got, err := readyJSON(t, args...)
		if !errors.Is(err, errNotReady) || got.Ready || got.Reason != health.ReasonUnreachable {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
}

// The answer must be internally consistent: the status code and the body have to agree and the
// body has to be the closed shape. Anything else is distrusted rather than believed.
func TestReadyDistrustsInconsistentAnswers(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"200 with ready=false": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ready":false,"reason":"no_quorum"}`)) },
		"503 with ready=true": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
			w.Write([]byte(`{"ready":true,"version":"1"}`))
		},
		"unknown extra field": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"ready":true,"version":"1","token":"` + readyCanary + `"}`))
		},
		"not JSON": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>ok</html>")) },
		"off-list reason": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
			w.Write([]byte(`{"ready":false,"reason":"` + readyCanary + `"}`))
		},
		"redirect to a ready one": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ok" {
				_, _ = w.Write([]byte(`{"ready":true,"version":"1"}`))
				return
			}
			http.Redirect(w, r, "/ok", http.StatusFound)
		},
	} {
		server := httptest.NewTLSServer(handler)
		ca := writeCA(t, server)
		var out bytes.Buffer
		err := runReady([]string{"--json", "--url", server.URL, "--ca-cert", ca}, &out)
		server.Close()
		if !errors.Is(err, errNotReady) || strings.Contains(out.String(), readyCanary) {
			t.Fatalf("%s: %q %v", name, out.String(), err)
		}
		var got health.Readiness
		if json.Unmarshal(out.Bytes(), &got) != nil || got.Ready || !got.Reason.Valid() {
			t.Fatalf("%s: answer %q is not a closed unready answer", name, out.String())
		}
	}
}

func TestReadyRejectsAmbiguousArguments(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"--ca-cert", "a", "--data-dir", "b"}, {"extra"}, {"--timeout", "0s"}, {"--timeout", "2h"}, {"--nope"}} {
		if err := runReady(args, &out); err == nil || errors.Is(err, errNotReady) {
			t.Fatalf("%v accepted: %v", args, err)
		}
	}
}

// --data-dir only names the installation's own public certificate as the trust root.
func TestReadyDataDirLocatesTheInstallationCertificate(t *testing.T) {
	url, ca := readyServer(t, ready("2"))
	dir := t.TempDir()
	raw, err := os.ReadFile(ca)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "server.crt"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readyJSON(t, "--url", url, "--data-dir", dir); err != nil || !got.Ready {
		t.Fatalf("%+v %v", got, err)
	}
}

// Before storage opens a serving process answers; it does not refuse the connection and it
// never claims readiness. The startup gate file holds storage closed deterministically, with
// its own reason, until the operator's sentinel exists.
func TestStartupWindowAnswersNotReadyUntilGateOpens(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := preparePrivate(dir, ""); err != nil {
		t.Fatal(err)
	}
	cert, key, err := localTLS(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	early, err := startEarly("127.0.0.1:0", cert, key)
	if err != nil {
		t.Fatal(err)
	}
	defer early.server.Close()
	base := "https://" + early.addr
	ask := func() health.Readiness { return probeReady(base, cert, 3*time.Second) }

	if got := ask(); got.Ready || got.Reason != health.ReasonStarting {
		t.Fatalf("closed gate: %+v", got)
	}
	sentinel := filepath.Join(t.TempDir(), "mounted")
	held := make(chan error, 1)
	go func() { held <- early.waitStartupHold(context.Background(), sentinel) }()
	deadline := time.Now().Add(5 * time.Second)
	for ask().Reason != health.ReasonStartupHold {
		if time.Now().After(deadline) {
			t.Fatal("the held gate never reported startup_hold")
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case err = <-held:
		t.Fatalf("waitStartupHold returned before the sentinel existed: %v", err)
	default:
	}
	if err = os.WriteFile(sentinel, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-held:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waitStartupHold did not return after the sentinel appeared")
	}
	if got := ask(); got.Ready || got.Reason != health.ReasonStarting {
		t.Fatalf("after the hold, before storage: %+v", got)
	}
	mux := http.NewServeMux()
	httpapi.RegisterHealthRoutes(mux, ready("3"))
	early.gate.Open(mux)
	if got := ask(); !got.Ready || got.Version != "3" {
		t.Fatalf("opened: %+v", got)
	}
}

func TestStartupHoldIsInterruptible(t *testing.T) {
	gate := &earlyServer{gate: httpapi.NewGate(health.ReasonStarting)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- gate.waitStartupHold(ctx, filepath.Join(t.TempDir(), "never")) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled hold kept waiting")
	}
	if (&earlyServer{gate: httpapi.NewGate(health.ReasonStarting)}).waitStartupHold(context.Background(), "") != nil {
		t.Fatal("no hold file configured must not wait")
	}
}

// A directory the process can chmod is tightened to 0700; a key it must not chmod is refused.
func TestPreparePrivateEnforcesModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	root := t.TempDir()
	created := filepath.Join(root, "new", "data")
	if err := preparePrivate(created, ""); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(created); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("created data directory mode %v %v", info.Mode().Perm(), err)
	}
	for _, mode := range []os.FileMode{0o755, 0o750, 0o705, 0o770, 0o777} {
		open := filepath.Join(root, "open"+mode.String())
		if err := os.Mkdir(open, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, mode); err != nil {
			t.Fatal(err)
		}
		if err := preparePrivate(open, ""); err != nil {
			t.Fatalf("data dir %v: %v", mode, err)
		}
		if info, err := os.Stat(open); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("data dir %v was not tightened to 0700: %v %v", mode, info.Mode().Perm(), err)
		}
	}
	key := filepath.Join(root, "server.key")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := preparePrivate(created, key); err != nil {
		t.Fatalf("0600 key refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		if err := os.Chmod(key, mode); err != nil {
			t.Fatal(err)
		}
		if err := preparePrivate(created, key); !errors.Is(err, errInsecureMode) {
			t.Fatalf("key %v accepted: %v", mode, err)
		}
	}
	if err := preparePrivate(created, filepath.Join(root, "absent.key")); err == nil {
		t.Fatal("a missing key was accepted")
	}
}

func TestFailureLinesAreSafe(t *testing.T) {
	if got := failureLine([]string{"soundpost", "serve"}, errInsecureMode); strings.Contains(got, "/") || !strings.Contains(got, "0700") {
		t.Fatalf("insecure mode line: %q", got)
	}
	if got := failureLine([]string{"soundpost", "ready"}, errNotReady); got != "soundpost: not ready" {
		t.Fatalf("ready line: %q", got)
	}
	if got := failureLine([]string{"soundpost", "serve"}, errors.New("open /srv/"+readyCanary)); strings.Contains(got, readyCanary) {
		t.Fatalf("generic line leaks: %q", got)
	}
}
